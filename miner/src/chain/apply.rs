//! Blocks: the rules one is held to, and how the chain takes it.
//!
//! # The rules
//!
//! Of a block whose parent is known, beyond its header's
//! ([`super::headers`]):
//!
//! 4. The body is the one the header commits to, well formed (its
//!    positions in range and distinct, its operations within their
//!    caps), and the block no larger than a block may be.
//! 5. Everything it spends is unspent. What a reveal or a sweep spends
//!    holds no coins and is of the age for it: a commit can be revealed
//!    from so many blocks after it was made until [`MAX_REVEAL`] after,
//!    and swept only once that is past. A name revealed is not
//!    registered; a name updated is.
//! 6. The outputs it makes sum to what it spends and its subsidy.
//! 7. After it the state's root is the header's.
//! 8. Its proof is accepted ([`super::verify`]).
//!
//! Rules 5 to 8 are of the state before the block, so they are checked
//! when the block joins the chain, not when it arrives.
//!
//! # A commit's age is checked here
//!
//! Which outputs are commits the state does not say, and the table that
//! does is an index a node may lack entries of
//! ([`crate::store::commits`]); that the output a reveal spends is the
//! commit of its name is for the proof to show. But an output's record
//! holds the height it was made at, under the state's root, so its age
//! is known to every node, whatever it was told: the window is checked
//! from that, by every node, for every block it applies.
//!
//! # Branches
//!
//! A block is kept whatever branch it extends, once its header's rules
//! and rule 4 hold. If its branch then has more work than the chain's,
//! the chain goes over to it: the blocks above the fork are undone, the
//! newest first, and the branch's applied, the oldest first, as one step
//! of the store ([`crate::store::state::State::session`]). A branch with
//! a block that breaks a rule leaves the chain as it was; that block and
//! those after it are then marked invalid.
//!
//! [`MAX_REVEAL`]: crate::name::MAX_REVEAL

use crate::block::{BlockRef, BodyRef, HEADER_SIZE, Header};
use crate::error::Error;
use crate::hash::Digest;
use crate::name::{BlockNameOp, Key, Record as NameRecord, commit_leaf, expired, in_window};
use crate::pow_air::Work;
use crate::store::backend::Backend;
use crate::store::blocks::Blocks;
use crate::store::outputs::Record;
use crate::store::pagefile::ReadPages;
use crate::store::state::{BlockEdit, Session};
use crate::u256::U256;

use super::Chain;
use super::headers::{Known, Status, check};
use super::verify::{BlockStatement, ProofVerifier};

/// What became of a block applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// It was kept already, with its body.
    Known,
    /// Kept, on a branch with no more work than the chain's.
    Side,
    /// It is the chain's new last block.
    Extended,
    /// The chain went over to its branch: the height the branches part
    /// above, and how many blocks were undone.
    Reorganized { fork_height: u32, unwound: u32 },
}

/// Whether an error is the block's own fault, for good: such a block is
/// remembered as invalid. Not so: a parent not known yet, a time ahead
/// of the clock (later it may not be), a body that is not the header's
/// (the header may be good, with its own body), a body not kept, the
/// store failing.
pub(crate) fn condemns(e: &Error) -> bool {
    !matches!(
        e,
        Error::UnknownParent
            | Error::TimestampTooNew { .. }
            | Error::BadBodyCommitment
            | Error::MissingBody
            | Error::NoUndoRecord
            | Error::SetAside
            | Error::KnownInvalid
            | Error::WrongGenesis
            | Error::Cancelled
            | Error::Io(_)
    )
}

/// A block's body as the store takes it.
struct Edit {
    spends: Vec<u64>,
    outputs: Vec<Record>,
    names: Vec<(Key, NameRecord, bool)>,
    commits: Vec<Digest>,
    commits_spent: Vec<u64>,
    /// The amounts of the outputs made, added up.
    created: u128,
}

impl<B: Backend + 'static, V: ProofVerifier + Sync> Chain<B, V> {
    /// Checks `block` and, if its header's rules and its body's form
    /// hold, keeps it; if its branch then has the most work, makes it
    /// the chain's last block, going over to its branch if it is another.
    /// `now` is the caller's clock, in seconds.
    ///
    /// A block that breaks a rule is remembered as invalid, by id, so it
    /// is not checked again; one whose branch leaves the chain below
    /// what can be undone is set aside.
    pub fn apply_block(&self, block: &BlockRef<'_>, now: u64) -> Result<Applied, Error> {
        let id = block.header().hash();
        // The blocks to mark if the branch fails: from the one that
        // failed on. The block itself if nothing else is said.
        let mut failed: Vec<Digest> = vec![id];
        let result = self.whole()?.session(|session| self.apply_in(session, block, now, &mut failed));
        let status = match &result {
            Err(Error::NoUndoRecord) => Some(Status::Aside),
            Err(e) if condemns(e) => Some(Status::Invalid),
            _ => None,
        };
        if let Some(status) = status {
            self.write_blocks(|txn, blocks| {
                for bad in &failed {
                    // The block itself was not kept: its header is, now.
                    let header = match self.known_in(txn, blocks, bad)? {
                        Some(known) => known.header,
                        None if *bad == id => *block.header(),
                        None => continue,
                    };
                    blocks.put_entry(txn, &Known { header, work: U256::ZERO, status }.entry())?;
                    blocks.drop_kept(txn, header.height, bad)?;
                }
                Ok(())
            })?;
        }
        result
    }

    fn apply_in(
        &self,
        session: &mut Session<'_, B>,
        block: &BlockRef<'_>,
        now: u64,
        failed: &mut Vec<Digest>,
    ) -> Result<Applied, Error> {
        let (header, body) = (block.header(), block.body());
        let id = header.hash();
        let tip_height = session.tip().0;
        let (txn, blocks) = session.blocks();
        let known = self.known_in(txn, blocks, &id)?;
        if let Some(k) = known.filter(|k| !k.header_only()) {
            return match k.status {
                Status::Aside => Err(Error::SetAside),
                Status::Invalid => Err(Error::KnownInvalid),
                _ => Ok(Applied::Known),
            };
        }
        let parent = self.known_in(txn, blocks, &header.prev_hash)?.ok_or(Error::UnknownParent)?;
        // A header kept alone had its work checked then, unless only
        // by what it claims.
        let median = self.times_in(txn, blocks, &parent.header)?.median();
        let first = self.anchor_in(txn, blocks, &parent.header)?;
        let target = self.target_from(&parent.header, first.as_ref());
        let work_ok = known.is_some_and(|k| k.status == Status::HeaderOnly) || self.full_pow(header, &target);
        let work = check(&self.params, header, &parent, median, &target, now, work_ok)?;
        self.check_body(header, &body)?;

        blocks.put_entry(txn, &Known { header: *header, work, status: Status::HeaderValid }.entry())?;
        blocks.put_body(txn, header.height, &id, body.as_bytes())?;
        let tip = self.tip_in(txn, blocks, tip_height)?;
        if work <= tip.work {
            return Ok(Applied::Side);
        }

        // The branch from the chain to the block, oldest first.
        let mut branch = vec![*header];
        let mut at = parent.header;
        while !self.is_main_in(txn, blocks, &at)? {
            branch.push(at);
            at = self
                .known_in(txn, blocks, &at.prev_hash)?
                .ok_or_else(|| corrupt("a branch's parent is missing"))?
                .header;
        }
        branch.reverse();
        let fork_height = at.height;
        let unwound = tip_height - fork_height;
        for height in (fork_height + 1..=tip_height).rev() {
            self.disconnect(session, height)?;
        }
        for (i, h) in branch.iter().enumerate() {
            let connected = if i + 1 == branch.len() {
                self.connect(session, h, &body)
            } else {
                let (txn, blocks) = session.blocks();
                match blocks.body(txn, h.height, &h.hash())? {
                    Some(bytes) => BodyRef::from_bytes(&bytes).and_then(|body| self.connect(session, h, &body)),
                    None => Err(Error::MissingBody),
                }
            };
            if let Err(e) = connected {
                // It and what follows it on the branch can never connect.
                *failed = branch[i..].iter().map(Header::hash).collect();
                return Err(e);
            }
        }
        Ok(if unwound == 0 { Applied::Extended } else { Applied::Reorganized { fork_height, unwound } })
    }

    /// Rule 4. The commitment first: the other failures condemn the
    /// header, and hold only of the body it commits to.
    pub(super) fn check_body(&self, header: &Header, body: &BodyRef<'_>) -> Result<(), Error> {
        if header.body_commitment != body.commitment() {
            return Err(Error::BadBodyCommitment);
        }
        let size = HEADER_SIZE + body.size();
        if size > self.params.max_block_size {
            return Err(Error::TooLarge(size));
        }
        Ok(())
    }

    /// The work a block's proof proves of its parent: what the header
    /// claims, its mix checked by the header's own rules. Genesis claims
    /// none, so its is computed from the seed text, once.
    pub fn parent_work(&self, parent: &Header) -> Work {
        match parent.height {
            0 => *self.genesis_work.get_or_init(|| Work::computed(&self.seed, parent)),
            _ => Work::of_header(&self.seed, parent),
        }
    }

    /// A body at `height` as the store takes it, checked as far as the
    /// state as the session has it says: the ages of the commits it
    /// spends, and the names it registers and replaces.
    fn edit(&self, session: &Session<'_, B>, body: &BodyRef<'_>, height: u32) -> Result<Edit, Error> {
        let mut spends: Vec<u64> = body.spent_positions().collect();
        spends.sort_unstable();
        let mut created = 0u128;
        let mut outputs: Vec<Record> = Vec::with_capacity(body.outputs().len() + body.commits());
        for o in body.outputs() {
            created += o.amount as u128;
            outputs.push(Record { commitment: o.commitment, memo: o.memo, amount: o.amount, height });
        }
        // What a reveal or a sweep spends: unspent, empty of coins, and
        // of the age for it.
        let spent_commit = |position: u64, sweep: bool| -> Result<(), Error> {
            let made = match session.output(position)? {
                Some((record, true)) if record.amount == 0 => record.height,
                Some((_, true)) => return Err(Error::NotACommit(position)),
                _ => return Err(Error::NoSuchOutput(position)),
            };
            let of_age = if sweep { expired(height, made) } else { in_window(height, made, self.params.min_reveal) };
            match of_age {
                true => Ok(()),
                false => Err(Error::CommitAge(made)),
            }
        };
        let (mut commits, mut commits_spent) = (Vec::new(), Vec::new());
        let mut names: Vec<(Key, NameRecord, bool)> = Vec::new();
        for op in body.ops() {
            match op {
                BlockNameOp::Commit { commit, memo } => {
                    outputs.push(Record { commitment: commit_leaf(&commit, height), memo, amount: 0, height });
                    commits.push(commit);
                }
                BlockNameOp::Reveal { record, commit } => {
                    spent_commit(commit, false)?;
                    commits_spent.push(commit);
                    let key = record.key();
                    if names.iter().any(|n| n.0 == key) || session.name(key)?.is_some() {
                        return Err(Error::NameTaken);
                    }
                    names.push((key, record, false));
                }
                BlockNameOp::Update(record) => {
                    let key = record.key();
                    // One the block itself registered or replaced is
                    // replaced again: the last record stands.
                    match names.iter_mut().find(|n| n.0 == key) {
                        Some(put) => put.1 = record,
                        None => names.push((key, record, true)),
                    }
                }
            }
        }
        for position in body.sweeps() {
            spent_commit(position, true)?;
            commits_spent.push(position);
        }
        names.sort_unstable_by_key(|n| n.0);
        commits_spent.sort_unstable();
        Ok(Edit { spends, outputs, names, commits, commits_spent, created })
    }

    /// Joins the block of `header` and `body` to the chain, whose last
    /// block is its parent: rules 5 to 8.
    fn connect(&self, session: &mut Session<'_, B>, header: &Header, body: &BodyRef<'_>) -> Result<(), Error> {
        let id = header.hash();
        let (prev_state_root, first_output_position) = (session.root(), session.next());
        let edit = self.edit(session, body, header.height)?;
        let (new_state_root, spent) = session.apply(&BlockEdit {
            height: header.height,
            block: id,
            spends: &edit.spends,
            outputs: &edit.outputs,
            names: &edit.names,
            commits: &edit.commits,
            commits_spent: &edit.commits_spent,
            state_root: Some(header.state_root),
        })?;
        // The supply, outside the proof and before it: what was spent is
        // what the state held, and what is made must be that and the
        // subsidy.
        let subsidy = self.params.subsidy(header.height);
        if edit.created != spent + subsidy as u128 {
            return Err(Error::Supply);
        }
        let (txn, blocks) = session.blocks();
        let parent =
            self.known_in(txn, blocks, &header.prev_hash)?.ok_or_else(|| corrupt("a block's parent is missing"))?;
        let statement = BlockStatement {
            height: header.height,
            prev_state_root,
            new_state_root,
            first_output_position,
            subsidy,
            body: *body,
            parent_work: self.parent_work(&parent.header),
            parent_hash: header.prev_hash,
        };
        if !self.verifier.verify(&statement, body.proof()) {
            return Err(Error::BadProof);
        }
        let known = self.known_in(txn, blocks, &id)?.ok_or_else(|| corrupt("a block joined is not kept"))?;
        blocks.put_entry(txn, &Known { status: Status::Valid, ..known }.entry())?;
        blocks.set_at(txn, header.height, Some(id))?;
        // It is planned no more: it is the chain.
        blocks.drop_planned(txn, 0, header.height.saturating_add(1))?;
        // The blocks no going over can reach keep their headers alone,
        // genesis excepted.
        if let Some(old) = header.height.checked_sub(self.keep as u32).filter(|old| *old > 0) {
            blocks.drop_kept_between(txn, 1, old + 1)?;
        }
        Ok(())
    }

    /// Takes the chain's last block, at `height`, off it.
    /// [`Error::NoUndoRecord`] if it is older than can be undone.
    fn disconnect(&self, session: &mut Session<'_, B>, height: u32) -> Result<(), Error> {
        let (at, tip) = session.undo()?;
        let (txn, blocks) = session.blocks();
        debug_assert_eq!(at + 1, height);
        // The state's own id of the block before is none at genesis.
        if at > 0 && blocks.at(txn, at)? != Some(tip) {
            return Err(corrupt("the state and the chain are of different blocks"));
        }
        blocks.set_at(txn, height, None)
    }

    /// The state's root after a block of `body` on the chain's last: what
    /// a miner writes in the header it then mines. Nothing is changed.
    pub fn state_root_after(&self, body: &BodyRef<'_>) -> Result<Digest, Error> {
        let mut root = None;
        let tried: Result<(), Error> = self.whole()?.session(|session| {
            let height = session.tip().0 + 1;
            let edit = self.edit(session, body, height)?;
            let (after, _) = session.apply(&BlockEdit {
                height,
                block: [crate::poseidon2::Fp::ZERO; 8],
                spends: &edit.spends,
                outputs: &edit.outputs,
                names: &edit.names,
                commits: &edit.commits,
                commits_spent: &edit.commits_spent,
                state_root: None,
            })?;
            root = Some(after);
            // Given up: the state is as it was.
            Err(Error::Cancelled)
        });
        match (root, tried) {
            (Some(root), _) => Ok(root),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => unreachable!("the session is given up"),
        }
    }
}

impl<B: Backend + 'static, V> Chain<B, V> {
    /// The body of the block of id `id`, if it is kept.
    pub fn body(&self, id: &Digest) -> Result<Option<Vec<u8>>, Error> {
        let store = self.store();
        let snap = store.view()?;
        let (pages, blocks): (_, &Blocks) = (snap.pages(), snap.blocks());
        let Some(known) = self.known_in(pages, blocks, id)? else { return Ok(None) };
        Ok(blocks.body(pages, known.header.height, id)?)
    }

    /// The work of the chain as far as its last block.
    pub fn tip_work(&self) -> Result<U256, Error> {
        let store = self.store();
        let snap = store.view()?;
        Ok(self.tip_known(snap.pages(), snap.blocks(), snap.tip().0)?.work)
    }

    fn tip_known(&self, pages: &impl ReadPages, blocks: &Blocks, height: u32) -> Result<Known, Error> {
        let id = blocks.at(pages, height)?.ok_or_else(|| corrupt("the tip is not in the chain"))?;
        self.known_in(pages, blocks, &id)?.ok_or_else(|| corrupt("the tip has no header"))
    }
}

fn corrupt(what: &'static str) -> Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what).into()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::block::{Block, BlockOutput, Body};
    use crate::chain::headers::tests::{NOW, easy, seed, table};
    use crate::chain::params::{COIN, ChainParams};
    use crate::chain::verify::AcceptAllProofs;
    use crate::name::{MAX_REVEAL, commit_hash};
    use crate::poseidon2::Fp;
    use crate::pow::hashimoto;
    use crate::store::testing::MemBackend;

    /// What a block pays in the first era.
    const PAY: u64 = 1500 * COIN;

    /// Refuses a proof that says it is bad: a rule only the proof holds
    /// a block to, for a branch to break.
    #[derive(Clone, Copy)]
    struct Marked;

    impl ProofVerifier for Marked {
        fn verify(&self, _: &BlockStatement<'_>, proof: &[u8]) -> bool {
            proof != b"bad"
        }
    }

    fn open_with<V>(params: ChainParams, keep: usize, verifier: V) -> Chain<MemBackend, V> {
        let chain = Chain::open(MemBackend::new(), keep, params, seed(), verifier).unwrap();
        chain.set_dataset(table());
        chain
    }

    fn open(params: ChainParams) -> Chain<MemBackend, AcceptAllProofs> {
        open_with(params, 8, AcceptAllProofs)
    }

    fn d(x: u32) -> Digest {
        [Fp::new(x); 8]
    }

    fn out(tag: u32, amount: u64) -> BlockOutput {
        BlockOutput { commitment: d(tag), memo: [Fp::new(tag); 5], amount }
    }

    /// A body that spends `inputs` and makes `outputs`.
    fn body(inputs: &[u64], outputs: &[BlockOutput]) -> Body {
        Body { inputs: inputs.to_vec(), outputs: outputs.to_vec(), ..Body::default() }
    }

    /// The header's work found, from the table.
    fn seal(mut header: Header, target: &crate::difficulty::Target) -> Header {
        loop {
            header.mix = hashimoto(&*table(), &header.pow_hash(), &header.nonce).mix;
            if header.quick_pow_check(target) {
                return header;
            }
            header.nonce[0] = header.nonce[0].wrapping_add(1);
        }
    }

    /// The block of `body` after `chain`'s last, with the state root
    /// `root` or, with none given, the one the body gives.
    fn block_with<V: ProofVerifier + Sync>(chain: &Chain<MemBackend, V>, body: &Body, root: Option<Digest>) -> Vec<u8> {
        let parent = chain.tip().unwrap();
        let bytes = body.to_bytes();
        let state_root = root.unwrap_or_else(|| chain.state_root_after(&BodyRef::from_bytes(&bytes).unwrap()).unwrap());
        let header = Header {
            prev_hash: parent.hash(),
            height: parent.height + 1,
            timestamp: parent.timestamp + 600,
            body_commitment: body.commitment(),
            state_root,
            aux: [0; 32],
            mix: d(0),
            nonce: [0; 32],
        };
        let header = seal(header, &chain.expected_target(&parent).unwrap());
        Block { header, body: body.clone() }.to_bytes()
    }

    fn block<V: ProofVerifier + Sync>(chain: &Chain<MemBackend, V>, body: &Body) -> Vec<u8> {
        block_with(chain, body, None)
    }

    fn apply<V: ProofVerifier + Sync>(chain: &Chain<MemBackend, V>, bytes: &[u8]) -> Result<Applied, Error> {
        chain.apply_block(&BlockRef::from_bytes(bytes).unwrap(), NOW)
    }

    fn header_of(bytes: &[u8]) -> Header {
        *BlockRef::from_bytes(bytes).unwrap().header()
    }

    /// Makes the block of `body` and applies it: it must extend.
    fn extend<V: ProofVerifier + Sync>(chain: &Chain<MemBackend, V>, body: &Body) -> Vec<u8> {
        let bytes = block(chain, body);
        assert_eq!(apply(chain, &bytes), Ok(Applied::Extended));
        bytes
    }

    /// The block after `chain`'s last making one output told apart by
    /// `tag`, not applied: as a miner hands one over. With `sound`
    /// false its state root is not what its body gives.
    pub(crate) fn next_block<V: ProofVerifier + Sync>(chain: &Chain<MemBackend, V>, tag: u32, sound: bool) -> Vec<u8> {
        let body = body(&[], &[out(tag, PAY)]);
        block_with(chain, &body, if sound { None } else { Some(d(tag)) })
    }

    /// Extends `chain` by `n` blocks, each making one output: `tag`
    /// tells one run of blocks from another on the same parent. The
    /// blocks, whole.
    pub(crate) fn grow<V: ProofVerifier + Sync>(chain: &Chain<MemBackend, V>, n: usize, tag: u32) -> Vec<Vec<u8>> {
        (0..n).map(|i| extend(chain, &body(&[], &[out(tag * 100_000 + i as u32, PAY)]))).collect()
    }

    fn status<V>(chain: &Chain<MemBackend, V>, bytes: &[u8]) -> Option<Status> {
        chain.known(&header_of(bytes).hash()).unwrap().map(|k| k.status)
    }

    /// Blocks join the chain, each paying what it may and spending what
    /// is there; one that breaks a rule is refused, remembered, and
    /// changes nothing.
    #[test]
    fn blocks_extend_the_chain() {
        let chain = open(easy());
        let genesis = chain.tip().unwrap();
        let b1 = extend(&chain, &body(&[], &[out(1, 1000 * COIN), out(2, 500 * COIN)]));
        let b2 = extend(&chain, &body(&[0], &[out(3, 2500 * COIN)]));
        assert_eq!(apply(&chain, &b2), Ok(Applied::Known));
        assert_eq!(chain.tip().unwrap(), header_of(&b2));
        assert_eq!(chain.header_at(1).unwrap(), Some(header_of(&b1)));
        assert_eq!((status(&chain, &b1), status(&chain, &b2)), (Some(Status::Valid), Some(Status::Valid)));
        assert_eq!(chain.state().root(), header_of(&b2).state_root);
        let kept = chain.body(&header_of(&b2).hash()).unwrap().unwrap();
        assert_eq!(kept, b2[HEADER_SIZE..]);
        assert_eq!(chain.tip_work().unwrap(), chain.best_header().unwrap().work);
        let mut headers = [genesis; 4];
        assert_eq!(chain.headers_after(&[genesis.hash()], &mut headers).unwrap(), 2);
        assert_eq!(headers[..2], [header_of(&b1), header_of(&b2)]);
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert!(!snap.is_unspent(0).unwrap() && snap.is_unspent(1).unwrap() && snap.is_unspent(2).unwrap());
        assert_eq!(snap.output(2).unwrap().unwrap().0.height, 2);
        drop(snap);
        drop(state);

        let tip = (chain.tip().unwrap(), chain.state().root());
        let refused = |bytes: &[u8], want: Error, remembered: bool| {
            assert_eq!(apply(&chain, bytes), Err(want));
            assert_eq!((chain.tip().unwrap(), chain.state().root()), tip, "nothing has changed");
            match remembered {
                true => {
                    assert_eq!(status(&chain, bytes), Some(Status::Invalid));
                    assert_eq!(apply(&chain, bytes), Err(Error::KnownInvalid));
                    assert_eq!(chain.body(&header_of(bytes).hash()).unwrap(), None);
                }
                false => assert_eq!(status(&chain, bytes), None),
            }
        };
        // More coins than it spends and is paid; and fewer.
        refused(&block(&chain, &body(&[1], &[out(4, 2000 * COIN + 1)])), Error::Supply, true);
        refused(&block(&chain, &body(&[], &[out(5, PAY - 1)])), Error::Supply, true);
        // An output spent already, and one never made.
        refused(&block_with(&chain, &body(&[0], &[out(6, PAY)]), Some(d(1))), Error::NoSuchOutput(0), true);
        refused(&block_with(&chain, &body(&[9], &[out(7, PAY)]), Some(d(1))), Error::NoSuchOutput(9), true);
        // Another state than the header says.
        refused(&block_with(&chain, &body(&[], &[out(8, PAY)]), Some(d(1))), Error::StateRoot, true);
        // A body that is not the header's: the header is not condemned.
        let good = block(&chain, &body(&[], &[out(9, PAY)]));
        let mut other = good[..HEADER_SIZE].to_vec();
        other.extend(body(&[], &[out(10, PAY)]).to_bytes());
        refused(&other, Error::BadBodyCommitment, false);
        // A time ahead of the clock: it may do later.
        let early = header_of(&good).timestamp - 7200 - 1;
        let limit = early + 7200;
        let too_new = Error::TimestampTooNew { limit, got: limit + 1 };
        assert_eq!(chain.apply_block(&BlockRef::from_bytes(&good).unwrap(), early), Err(too_new));
        assert_eq!(status(&chain, &good), None);
        // A block larger than a block may be, on a network of small ones.
        let small = open(ChainParams { max_block_size: HEADER_SIZE + 100, ..easy() });
        let big = block(&small, &body(&[], &[out(1, PAY - 1), out(2, 1)]));
        assert_eq!(apply(&small, &big), Err(Error::TooLarge(big.len())));
        assert_eq!(status(&small, &big), Some(Status::Invalid));
        // A parent not known, and one found invalid.
        let elsewhere = open(easy());
        extend(&elsewhere, &body(&[], &[out(77, PAY)]));
        let orphan = block(&elsewhere, &body(&[], &[out(1, PAY)]));
        assert_eq!(apply(&chain, &orphan), Err(Error::UnknownParent));
        assert_eq!(apply(&chain, &good), Ok(Applied::Extended));
    }

    /// The chain goes over to a branch with more work, as one step, and
    /// back; the headers of a branch say which bodies to fetch until
    /// they have come.
    #[test]
    fn the_chain_goes_over_to_more_work() {
        let (ours, theirs) = (open(easy()), open(easy()));
        let a: Vec<Vec<u8>> = (0..3).map(|i| extend(&ours, &body(&[], &[out(10 + i, PAY)]))).collect();
        let mut b: Vec<Vec<u8>> = vec![extend(&theirs, &body(&[], &[out(20, PAY - 7), out(21, 7)]))];
        b.push(extend(&theirs, &body(&[1], &[out(22, PAY + 7)])));
        b.push(extend(&theirs, &body(&[0, 2], &[out(23, 3 * PAY)])));
        b.push(extend(&theirs, &body(&[], &[out(24, PAY)])));
        let ours_before = ours.state().root();

        // Their headers first: the branch is the best, and to be fetched.
        let headers: Vec<Header> = b.iter().map(|x| header_of(x)).collect();
        assert_eq!(ours.accept_headers(&headers, NOW, false), (4, None));
        assert_eq!(ours.best_header().unwrap().header, headers[3]);
        let mut fetch = [headers[0]; 8];
        assert_eq!(ours.missing_bodies(&mut fetch).unwrap(), 4);
        assert_eq!(fetch[..4], headers[..]);
        // Their blocks: kept beside the chain while it has as much work.
        for x in &b[..3] {
            assert_eq!(apply(&ours, x), Ok(Applied::Side));
            assert_eq!(status(&ours, x), Some(Status::HeaderValid));
        }
        assert_eq!((ours.tip().unwrap(), ours.state().root()), (header_of(&a[2]), ours_before));
        assert_eq!(ours.missing_bodies(&mut fetch).unwrap(), 1);
        assert_eq!(apply(&ours, &b[3]), Ok(Applied::Reorganized { fork_height: 0, unwound: 3 }));
        assert_eq!(ours.tip().unwrap(), theirs.tip().unwrap());
        assert_eq!(ours.state().root(), theirs.state().root());
        assert_eq!(ours.missing_bodies(&mut fetch).unwrap(), 0);
        for (i, x) in b.iter().enumerate() {
            assert_eq!(ours.header_at(i as u32 + 1).unwrap(), Some(header_of(x)));
            assert_eq!(status(&ours, x), Some(Status::Valid));
        }
        // The blocks left were part of the chain once, and are kept.
        assert!(a.iter().all(|x| status(&ours, x) == Some(Status::Valid)));
        assert!(ours.body(&header_of(&a[1]).hash()).unwrap().is_some());
        let state = ours.state();
        let snap = state.snapshot().unwrap();
        assert_eq!(snap.output(3).unwrap().unwrap().0.commitment, d(23));
        drop(snap);
        drop(state);

        // And back, when the first branch has grown: built by a node
        // that never left it.
        let stayed = open(easy());
        a.iter().for_each(|x| assert_eq!(apply(&stayed, x), Ok(Applied::Extended)));
        let a4 = extend(&stayed, &body(&[0], &[out(14, 2 * PAY)]));
        let a5 = extend(&stayed, &body(&[], &[out(15, PAY)]));
        assert_eq!(apply(&ours, &a4), Ok(Applied::Side));
        assert_eq!(apply(&ours, &a5), Ok(Applied::Reorganized { fork_height: 0, unwound: 4 }));
        assert_eq!((ours.tip().unwrap(), ours.state().root()), (stayed.tip().unwrap(), stayed.state().root()));
        assert_eq!(ours.header_at(5).unwrap(), Some(header_of(&a5)));
        // From a fork above genesis: one block undone.
        let fork = extend(&stayed, &body(&[], &[out(31, PAY)]));
        let other = block(&ours, &body(&[], &[out(32, PAY)]));
        assert_eq!(apply(&ours, &other), Ok(Applied::Extended));
        assert_eq!(apply(&ours, &fork), Ok(Applied::Side));
        let longer = extend(&stayed, &body(&[], &[out(33, PAY)]));
        assert_eq!(apply(&ours, &longer), Ok(Applied::Reorganized { fork_height: 5, unwound: 1 }));
        assert_eq!(ours.state().root(), stayed.state().root());
    }

    /// A branch with a block that breaks a rule leaves the chain where
    /// it was; the block and those after it are invalid from then on.
    #[test]
    fn a_branch_with_a_bad_block_is_not_taken() {
        let ours = open_with(easy(), 8, Marked);
        let theirs = open(easy());
        let a: Vec<Vec<u8>> = (0..2).map(|i| extend(&ours, &body(&[], &[out(10 + i, PAY)]))).collect();
        let b1 = extend(&theirs, &body(&[], &[out(20, PAY)]));
        // The second says of its own proof that it is bad; they take it.
        let b2 = extend(&theirs, &Body { proof: b"bad".to_vec(), ..body(&[0], &[out(21, 2 * PAY)]) });
        let b3 = extend(&theirs, &body(&[], &[out(22, PAY)]));
        let b4 = extend(&theirs, &body(&[], &[out(23, PAY)]));
        let before = (ours.tip().unwrap(), ours.state().root(), ours.state().file().space().0);
        assert_eq!(apply(&ours, &b1), Ok(Applied::Side));
        assert_eq!(apply(&ours, &b2), Ok(Applied::Side));
        // With the third the branch has more work, and is tried.
        assert_eq!(apply(&ours, &b3), Err(Error::BadProof));
        assert_eq!((ours.tip().unwrap(), ours.state().root()), (before.0, before.1));
        assert_eq!(ours.header_at(2).unwrap(), Some(header_of(&a[1])));
        assert_eq!(status(&ours, &b1), Some(Status::HeaderValid));
        assert_eq!((status(&ours, &b2), status(&ours, &b3)), (Some(Status::Invalid), Some(Status::Invalid)));
        assert_eq!(ours.body(&header_of(&b2).hash()).unwrap(), None);
        assert_eq!(apply(&ours, &b3), Err(Error::KnownInvalid));
        assert_eq!(apply(&ours, &b4), Err(Error::InvalidParent));
        assert_eq!(status(&ours, &b4), Some(Status::Invalid));
        // The chain goes on.
        extend(&ours, &body(&[1], &[out(12, 2 * PAY)]));
    }

    /// Names: a commit is revealed in its window and not before, swept
    /// once the window is past and not before, and what a reveal or a
    /// sweep spends is no output with coins in it.
    #[test]
    fn commits_are_revealed_and_swept_at_their_age() {
        let params = ChainParams { min_reveal: 2, ..easy() };
        let chain = open_with(params, 400, AcceptAllProofs);
        let pay = body(&[], &[out(1, PAY)]);
        let record = |name: &[u8], owner: u32| NameRecord::new(name, d(owner), d(owner + 1), d(owner + 2)).unwrap();
        let commit_of = |r: &NameRecord, salt: u32| commit_hash(&r.name.hash(), &d(salt), &r.owner);
        let (alice, bob) = (record(b"alice", 100), record(b"bob", 200));
        let commit =
            |r: &NameRecord, salt: u32| BlockNameOp::Commit { commit: commit_of(r, salt), memo: [Fp::new(salt); 5] };
        let with = |ops: Vec<BlockNameOp>, sweeps: Vec<u64>| Body { ops, sweeps, ..pay.clone() };
        let refused = |b: &Body, want: Error| {
            let bytes = block_with(&chain, b, Some(d(1)));
            assert_eq!(apply(&chain, &bytes), Err(want));
            assert_eq!(status(&chain, &bytes), Some(Status::Invalid));
        };

        // Block 1 commits to a name: an output at 1, after its own.
        extend(&chain, &with(vec![commit(&alice, 7)], vec![]));
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert_eq!(snap.commits().position_of(snap.pages(), &commit_of(&alice, 7)).unwrap(), Some(1));
        assert_eq!(snap.output(1).unwrap().unwrap().0.commitment, commit_leaf(&commit_of(&alice, 7), 1));
        drop(snap);
        drop(state);
        let reveal = |r: &NameRecord, at: u64| BlockNameOp::Reveal { record: *r, commit: at };
        // Too soon: a block after, where two must pass.
        refused(&with(vec![reveal(&alice, 1)], vec![]), Error::CommitAge(1));
        // An output with coins in it is no commit, revealed or swept.
        refused(&with(vec![reveal(&alice, 0)], vec![]), Error::NotACommit(0));
        refused(&with(vec![], vec![0]), Error::NotACommit(0));
        // Swept before its window is past.
        refused(&with(vec![], vec![1]), Error::CommitAge(1));
        // One commit a block: two are too many. Block 2 commits to
        // another name, at 3.
        let two = with(vec![commit(&alice, 9), commit(&bob, 8)], vec![]).to_bytes();
        assert!(matches!(BodyRef::from_bytes(&two), Err(Error::TooManyOps { .. })));
        extend(&chain, &with(vec![commit(&bob, 8)], vec![]));
        // In the window: the name is registered, the commit spent.
        extend(&chain, &with(vec![reveal(&alice, 1)], vec![]));
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert_eq!(snap.name(alice.key()).unwrap(), Some(alice));
        assert!(!snap.is_unspent(1).unwrap());
        assert_eq!(snap.commits().count, 1);
        drop(snap);
        drop(state);
        // Revealed again, by a commit spent or by another: refused.
        refused(&with(vec![reveal(&alice, 1)], vec![]), Error::NoSuchOutput(1));
        refused(&with(vec![reveal(&alice, 3)], vec![]), Error::NameTaken);
        // Replaced, twice in one block: the last record stands. A name
        // not registered is not replaced.
        let (second, third) = (NameRecord { owner: d(300), ..alice }, NameRecord { owner: d(400), ..alice });
        extend(&chain, &with(vec![BlockNameOp::Update(second), BlockNameOp::Update(third)], vec![]));
        assert_eq!(chain.state().snapshot().unwrap().name(alice.key()).unwrap(), Some(third));
        refused(&with(vec![BlockNameOp::Update(bob)], vec![]), Error::NoSuchName);

        // The second commit is never revealed. At the last block of its
        // window it can be, and cannot be swept; a block later it is
        // the other way about.
        while chain.tip().unwrap().height < MAX_REVEAL + 1 {
            extend(&chain, &pay);
        }
        refused(&with(vec![], vec![3]), Error::CommitAge(2));
        let at_the_end = block(&chain, &with(vec![reveal(&bob, 3)], vec![]));
        extend(&chain, &pay);
        assert_eq!(chain.tip().unwrap().height, 2 + MAX_REVEAL);
        refused(&with(vec![reveal(&bob, 3)], vec![]), Error::CommitAge(2));
        extend(&chain, &with(vec![], vec![3]));
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert!(!snap.is_unspent(3).unwrap());
        assert_eq!((snap.commits().count, snap.name(bob.key()).unwrap()), (0, None));
        drop(snap);
        drop(state);
        // The reveal at the window's end was a good block of its own
        // branch: kept beside the chain.
        assert_eq!(apply(&chain, &at_the_end), Ok(Applied::Side));
    }

    /// Bodies are kept for the blocks that can be undone and no longer,
    /// and a branch that leaves the chain below them is set aside.
    #[test]
    fn what_cannot_be_undone_is_not_kept() {
        let (ours, theirs) = (open_with(easy(), 3, AcceptAllProofs), open(easy()));
        let a: Vec<Vec<u8>> = (0..6).map(|i| extend(&ours, &body(&[], &[out(10 + i, PAY)]))).collect();
        for (i, x) in a.iter().enumerate() {
            let kept = ours.body(&header_of(x).hash()).unwrap().is_some();
            assert_eq!(kept, i >= 3, "the body of block {}", i + 1);
            assert_eq!(status(&ours, x), Some(Status::Valid));
        }
        assert!(ours.header_at(1).unwrap().is_some());
        // A branch from genesis, with more work.
        let b: Vec<Vec<u8>> = (0..7).map(|i| extend(&theirs, &body(&[], &[out(20 + i, PAY)]))).collect();
        for x in &b[..6] {
            assert_eq!(apply(&ours, x), Ok(Applied::Side));
        }
        let before = (ours.tip().unwrap(), ours.state().root());
        assert_eq!(apply(&ours, &b[6]), Err(Error::NoUndoRecord));
        assert_eq!((ours.tip().unwrap(), ours.state().root()), before);
        assert_eq!(status(&ours, &b[6]), Some(Status::Aside));
        assert_eq!(apply(&ours, &b[6]), Err(Error::SetAside));
        // The chain goes on, and a fork within reach is still taken.
        let a7 = extend(&ours, &body(&[], &[out(16, PAY)]));
        let stayed = open(easy());
        a.iter().for_each(|x| assert_eq!(apply(&stayed, x), Ok(Applied::Extended)));
        let c7 = extend(&stayed, &body(&[], &[out(40, PAY)]));
        let c8 = extend(&stayed, &body(&[], &[out(41, PAY)]));
        assert_eq!(apply(&ours, &c7), Ok(Applied::Side));
        assert_eq!(apply(&ours, &c8), Ok(Applied::Reorganized { fork_height: 6, unwound: 1 }));
        assert_eq!(ours.state().root(), stayed.state().root());
        assert_eq!(status(&ours, &a7), Some(Status::Valid));
    }
}
