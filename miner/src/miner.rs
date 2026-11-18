//! Making blocks: the block after the chain's last is built, proven,
//! and its proof of work found.
//!
//! [`mine`] makes one block and hands it back whole; whoever runs it
//! gives the block to the node, which applies it and tells its peers
//! (`net::node::Hand`). Nothing here knows of the network.
//!
//! A block made here pays its reward to one key, with the fees of the
//! transactions it carries: those chosen for it from the pool
//! ([`choose`]), no more of them than the miner is to prove.
//!
//! Where a block's proof builds on the proof of the block before it
//! (every network but the dev network, whose proofs stand alone), that
//! proof and what it speaks to are taken from the chain: the proof is
//! in the block before's body, which is kept, and what it speaks to is
//! made again from that body and the header before it ([`before`]).
//!
//! The steps, each given up if `cancel` says so (the chain has another
//! last block, or the node is stopping):
//!
//! 1. The reward's transaction, and the witnesses of it and of the
//!    transactions chosen, against the state as it is.
//! 2. The block's proof: what takes the time, where proofs are large.
//! 3. The header, and a nonce whose hash meets the target: on every
//!    thread there is, each trying its own nonces.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::aggregate::{AggregateVerifier, Statement};
use crate::block::{Block, Body, BodyRef, HEADER_SIZE, Header};
use crate::block_air::{ROWS_PER_OUTPUT, SegmentWitness, item_rows_of, pack_with};
use crate::block_proof::{body_from_segments, join_signed};
use crate::chain::Chain;
use crate::chain::verify::BlockStatement;
use crate::difficulty::Target;
use crate::error::Error;
use crate::hash::Digest;
use crate::mempool::{Mempool, PROOF_BYTES, RESERVE_PERCENT};
use crate::name::NameOp;
use crate::name_air::{NameWitness, SWEEP_ROWS, op_rows_bound};
use crate::output::{INPUT_SIZE, Output, Sig};
use crate::pow::{ItemSource, LazyDataset, Nonce, hashimoto, nonce_from_u64};
use crate::store::backend::Backend;
use crate::store::outputs::Record;
use crate::transaction::{Transaction, UnsignedTransaction};

/// Signatures a block made here checks at the most, unless told
/// otherwise: one for each input of its transactions (a policy input
/// may be several). Two segments of signatures, some hundred
/// transactions: what a machine with nothing but its processor proves
/// in about the time it proves a block of nothing twice over. The
/// block's size allows a hundred times as many, which is for those who
/// prove on many machines (`POOL_SCALING.md`).
pub const MAX_SIGNATURES: usize = 256;

/// Whether to make blocks now, or to wait for a chain ahead of ours to
/// come in ([`HoldOff::ask`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Now {
    /// Make blocks.
    Mine,
    /// Wait: `first` when this is the first time of asking that it is
    /// so, of this chain ahead.
    Wait { first: bool },
    /// Make blocks though a chain ahead is known of: its blocks have
    /// not come in the time allowed. `first` as above.
    MineAnyway { first: bool },
}

/// When a node that knows of a chain ahead of its own stops making
/// blocks, and for how long.
///
/// A block made on a chain about to be replaced is work thrown away,
/// so a node well behind waits. But a node that waits for ever for
/// blocks that do not come makes none: so it waits only so long for
/// the blocks of any one chain ahead (by its last header), and then
/// goes on making its own until a chain ahead with another last header
/// is known of. Waiting wrongly costs the network a miner; making
/// blocks wrongly costs the miner its own work, and no one else
/// anything.
pub struct HoldOff {
    /// How long the blocks of a chain ahead are waited for.
    limit: Duration,
    /// The chain ahead being waited for, by its last header, and since
    /// when.
    waiting: Option<(Digest, Instant)>,
    /// The chain ahead that was waited for long enough.
    given_up: Option<Digest>,
}

impl HoldOff {
    /// For a network whose blocks are `block_time` seconds apart: three
    /// blocks' time is waited, ten seconds at the least.
    pub fn new(block_time: u64) -> HoldOff {
        HoldOff { limit: Duration::from_secs((3 * block_time).max(10)), waiting: None, given_up: None }
    }

    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// What to do at `now`, where the best chain known of that is two
    /// blocks or more ahead of ours ends in the header `ahead`: none,
    /// if there is none.
    pub fn ask(&mut self, ahead: Option<Digest>, now: Instant) -> Now {
        let Some(ahead) = ahead else {
            (self.waiting, self.given_up) = (None, None);
            return Now::Mine;
        };
        if self.given_up == Some(ahead) {
            return Now::MineAnyway { first: false };
        }
        match self.waiting {
            Some((chain, since)) if chain == ahead => {
                if now.duration_since(since) < self.limit {
                    return Now::Wait { first: false };
                }
                (self.waiting, self.given_up) = (None, Some(ahead));
                Now::MineAnyway { first: true }
            }
            _ => {
                self.waiting = Some((ahead, now));
                Now::Wait { first: true }
            }
        }
    }
}

/// Fills what is missing of `table`, on every thread there is, and says
/// how far it has got: `progress` is called with each twentieth of the
/// table that has come to be there (5, 10, ... 95 in a hundred), as
/// that is seen, the table being looked at every `look`. A table
/// filled faster than it is looked at passes some of them by.
pub fn fill_table(table: &LazyDataset<'_>, look: Duration, progress: &(dyn Fn(u32) + Sync)) {
    let twentieths = || (table.filled() * 20 / table.pairs()) as u32;
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            table.fill();
            done.store(true, Ordering::Release);
        });
        let mut said = twentieths();
        while !done.load(Ordering::Acquire) {
            std::thread::sleep(look);
            let now = twentieths();
            if now > said && now < 20 {
                said = now;
                progress(5 * now);
            }
        }
    });
}

/// What came of trying to make a block.
#[derive(Debug)]
pub enum Mined {
    /// The block, whole: with how long proving it took, and how many
    /// hashes finding its nonce took and how long.
    Block { block: Vec<u8>, header: Header, proved: Duration, hashes: u64, solved: Duration },
    /// Given up: `cancel` said so.
    Cancelled,
    /// A transaction chosen for the block no longer applies: the state
    /// has changed since it was chosen, and the pool has not yet been
    /// looked over. To be tried again, with what is chosen then.
    Stale,
    /// The chain has had its last block: there is none to make.
    Finished,
}

/// The transactions of the pool for the block after `chain`'s last,
/// and the commits of names past their time that it is to sweep.
///
/// The longest waiting first, a tenth of the block, and then the best
/// paying ([`Mempool::select`]), while the block checks no more than
/// `max_signatures` signatures, its transactions are one segment's, its
/// name operations fit their segment, and it is no larger than a block
/// may be. `with_pool` gives the pool, held while they are chosen: the
/// state is taken first, as by everyone that takes both.
pub fn choose<B: Backend + 'static>(
    chain: &Chain<B, AggregateVerifier>,
    with_pool: &dyn Fn(&mut dyn FnMut(&Mempool)),
    max_signatures: usize,
) -> Result<(Vec<Transaction>, Vec<u64>), Error> {
    let params = *chain.params();
    let proofs = *chain.verifier().params();
    let state = chain.whole()?;
    let snap = state.snapshot()?;
    let height = snap.tip().0 + 1;
    let sweeps = Mempool::sweeps(&snap, height);
    let mut chosen: Vec<Transaction> = Vec::new();
    if max_signatures == 0 {
        return Ok((chosen, sweeps));
    }
    with_pool(&mut |pool: &Mempool| {
        // (What is chosen so far, decoded once: the choosing asks of
        // all of it each time one more is tried.)
        let mut so_far: Vec<Transaction> = Vec::new();
        let reserve = max_signatures * INPUT_SIZE * RESERVE_PERCENT / 100;
        let taken = pool.select(&snap, height, params.min_reveal, reserve, |trying| {
            so_far.truncate(trying.len() - 1);
            so_far.push(trying[trying.len() - 1].to_transaction());
            if so_far.iter().map(Transaction::weight).sum::<usize>() > max_signatures {
                return false;
            }
            let ops = || so_far.iter().flat_map(|tx| tx.ops.iter());
            if sweeps.len() * SWEEP_ROWS + ops().map(op_rows_bound).sum::<usize>() >= proofs.name_rows() {
                return false;
            }
            let spends: usize = so_far.iter().map(|tx| tx.inputs.len() + tx.policy_inputs.len()).sum();
            let makes = 1 + so_far.iter().map(|tx| tx.outputs.len()).sum::<usize>();
            let names =
                ops().map(|op| op.block_op().size()).sum::<usize>() + sweeps.len() * crate::codec::POSITION_BYTES;
            if HEADER_SIZE + Body::size_of(spends, makes, names, PROOF_BYTES) > params.max_block_size {
                return false;
            }
            // One segment, with the reward's transaction before them.
            let rows = |t: usize| match t {
                0 => (vec![ROWS_PER_OUTPUT], false),
                t => item_rows_of(&so_far[t - 1]),
            };
            let made = |t: usize| match t {
                0 => 0..1,
                t => {
                    let tx = &so_far[t - 1];
                    let before = tx.inputs.len() + tx.policy_inputs.len();
                    before..before + tx.outputs.len()
                }
            };
            pack_with(so_far.len() + 1, rows, made, proofs.segment_rows()).len() <= 1
        });
        chosen = taken.iter().map(|tx| tx.to_transaction()).collect();
    });
    Ok((chosen, sweeps))
}

/// What the block after `chain`'s last is to pay whoever makes it, if
/// it carries the transactions `pooled`: its height, and what it may
/// make with their fees. None if the chain has had its last block.
pub fn reward_due<B: Backend + 'static, V>(
    chain: &Chain<B, V>,
    pooled: &[Transaction],
) -> Result<Option<(u32, u64)>, Error> {
    let height = chain.tip()?.height + 1;
    let subsidy = chain.params().subsidy(height);
    let fees: u64 = pooled.iter().map(|tx| tx.balance().clamp(0, u64::MAX as i128) as u64).sum();
    Ok((subsidy > 0).then_some((height, subsidy.saturating_add(fees))))
}

/// [`mine_with`], of a block that carries nothing but its reward, paid
/// to the key of hash `reward`.
pub fn mine<B: Backend + 'static, S: ItemSource + Sync>(
    chain: &Chain<B, AggregateVerifier>,
    dataset: &S,
    reward: &Digest,
    unix: u64,
    start: u64,
    proved: &dyn Fn(Duration),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<Mined, Error> {
    let Some((_, due)) = reward_due(chain, &[])? else { return Ok(Mined::Finished) };
    mine_with(chain, dataset, &Output::to_key_hash(reward, due), unix, start, &[], &[], proved, cancel)
}

/// Makes the block after `chain`'s last, of the transactions `pooled`
/// and sweeping the commits at `sweeps` ([`choose`]), paying its reward
/// and their fees ([`reward_due`]) by the output `paid`, which is the
/// maker's own. `unix` is the time by the calendar, in seconds,
/// and `start` where the nonces tried begin (any number: so that two
/// miners do not try the same). `proved` is called when the block's
/// proof is made, with how long that took: from then the nonce is
/// looked for. `cancel` is asked now and then whether to give up.
///
/// `dataset` is the table of the proof of work for that block's
/// height: whole, or one that fills as it is read
/// ([`crate::pow::LazyDataset`]).
#[allow(clippy::too_many_arguments)]
pub fn mine_with<B: Backend + 'static, S: ItemSource + Sync>(
    chain: &Chain<B, AggregateVerifier>,
    dataset: &S,
    paid: &Output,
    unix: u64,
    start: u64,
    pooled: &[Transaction],
    sweeps: &[u64],
    proved: &dyn Fn(Duration),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<Mined, Error> {
    let params = *chain.params();
    let tip = chain.tip()?;
    let height = tip.height + 1;
    let subsidy = params.subsidy(height);
    if subsidy == 0 {
        return Ok(Mined::Finished);
    }
    // The reward: a transaction that spends nothing, signed by nobody.
    // It pays what the block may make and what its transactions leave:
    // an output made for another block's is not this block's.
    let fees: u64 = pooled.iter().map(|tx| tx.balance().clamp(0, u64::MAX as i128) as u64).sum();
    if paid.amount != subsidy.saturating_add(fees) {
        return Ok(Mined::Stale);
    }
    let tx = UnsignedTransaction::new(vec![], vec![*paid])
        .sign(|_, _, _| Err::<Sig, ()>(()))
        .expect("a transaction without inputs needs no signature");
    let mut txs = vec![tx];
    txs.extend(pooled.iter().cloned());
    let rows = chain.verifier().params().segment_rows();
    let state = chain.whole()?;
    let (mut segments, prev_state_root, first_output_position) = {
        let snap = state.snapshot()?;
        // (The state of the block being built on, or it has moved on.)
        // (The state before the first block is of no block.)
        let (at, id) = snap.tip();
        if at != tip.height || (at > 0 && id != tip.hash()) {
            return Ok(Mined::Cancelled);
        }
        let segments = match SegmentWitness::collect_by_rows(&snap, &txs, rows, height) {
            Ok(segments) => segments,
            // What a transaction of the pool spends is not there.
            Err(Error::NoSuchOutput(_)) if !pooled.is_empty() => return Ok(Mined::Stale),
            Err(e) => return Err(e),
        };
        (segments, snap.root(), snap.outputs().next)
    };
    let names = if pooled.is_empty() && sweeps.is_empty() {
        let first = &segments[0];
        NameWitness {
            min_reveal: params.min_reveal,
            root_in: first.root_in,
            pos_in: first.pos_in,
            height,
            ops: vec![],
            signed: Default::default(),
        }
        .with_segments(&segments)
    } else {
        // The name operations and the sweeps, on the state as the
        // transactions leave it; and one set of the block's signatures,
        // for every segment to look its own up in.
        let mut spends: Vec<u64> = segments.iter().flat_map(|s| s.positions()).collect();
        spends.sort_unstable();
        let made: Vec<Record> = segments
            .iter()
            .flat_map(|s| s.block_outputs())
            .map(|o| Record { commitment: o.commitment, memo: o.memo, amount: o.amount, height })
            .collect();
        let ops: Vec<NameOp> = txs.iter().flat_map(|tx| tx.ops.iter().cloned()).collect();
        let mut names = match NameWitness::collect(&state, height, params.min_reveal, &spends, &made, &ops, sweeps) {
            Ok(names) => names,
            Err(Error::Io(kind)) => return Err(Error::Io(kind)),
            // A name taken, a commit out of its window: the pool has
            // not yet been looked over.
            Err(_) => return Ok(Mined::Stale),
        };
        join_signed(&mut segments, &mut names);
        names
    };
    drop(state);
    // What the proof of the block before speaks to, and that proof:
    // where this block's proof is to build on it.
    let before = match chain.verifier().needs_plan() && height > 1 {
        true => Some(before(chain, &tip, first_output_position)?),
        false => None,
    };
    // (A proof before that this build does not take is not built on:
    // the block's own could not be made, and is not tried.)
    if let Some((statement, body)) = &before
        && chain.verifier().verify_chain_proof(tip.height, statement, proof_of(body)).is_err()
    {
        return Err(Error::BadProof);
    }
    let mut body = body_from_segments(&segments, &names, vec![]);
    let unproven = body.to_bytes();
    let unproven = BodyRef::from_bytes(&unproven)?;
    let state_root = match chain.state_root_after(&unproven) {
        Ok(root) => root,
        // The chain has gone on meanwhile: what this block was made of
        // is no longer what the chain holds, and that is no fault.
        Err(_) if chain.tip()?.hash() != tip.hash() => return Ok(Mined::Stale),
        Err(e) => return Err(e),
    };
    let statement = Statement::from_block(&BlockStatement {
        height,
        prev_state_root,
        new_state_root: state_root,
        first_output_position,
        subsidy,
        body: unproven,
        parent_work: chain.parent_work(&tip),
        parent_hash: tip.hash(),
    });
    let jobs = crate::parallel::threads();
    let began = Instant::now();
    let on = before.as_ref().map(|(statement, body)| (tip.height, statement, proof_of(body), &tip));
    let Some(proof) = chain.verifier().prove_block(height, &statement, &segments, &names, on, jobs, &|_| {}, cancel)
    else {
        return Ok(Mined::Cancelled);
    };
    // The chain may have another last block by now, heard of while the
    // last of the proof was made: then this block is for nothing.
    if cancel() {
        return Ok(Mined::Cancelled);
    }
    body.proof = proof;
    let took = began.elapsed();
    // The proof is made: what is left is to find the nonce.
    proved(took);
    let header = Header {
        prev_hash: tip.hash(),
        height,
        timestamp: unix.max(chain.earliest_timestamp(&tip)?),
        body_commitment: body.commitment(),
        state_root,
        aux: [0; 32],
        mix: tip.mix,
        nonce: [0; 32],
    };
    let target = chain.expected_target(&tip)?;
    let began = Instant::now();
    let Some((nonce, mix, hashes)) = solve(dataset, &header.pow_hash(), &target, start, cancel) else {
        return Ok(Mined::Cancelled);
    };
    let header = Header { nonce, mix, ..header };
    let solved = began.elapsed();
    Ok(Mined::Block { block: Block { header, body }.to_bytes(), header, proved: took, hashes, solved })
}

/// Whether the proof of `chain`'s last block is one this build takes:
/// true where there is none to hold (the first block, a network whose
/// proofs stand alone).
///
/// A block's proof builds on the proof of the block before, and says
/// so in a program that is the network's rules: its circuits, and the
/// numbers in them. A chain made by a build of other rules has proofs
/// this build's blocks cannot build on, and it would not take that
/// chain's blocks from a peer either. Such a chain is not to be gone on
/// with: whoever starts a node on one is told, before anything is made.
pub fn last_proof_holds<B: Backend + 'static>(chain: &Chain<B, AggregateVerifier>) -> Result<bool, Error> {
    let tip = chain.tip()?;
    if !chain.verifier().needs_plan() || tip.height == 0 {
        return Ok(true);
    }
    let end = chain.whole()?.snapshot()?.outputs().next;
    let (statement, body) = before(chain, &tip, end)?;
    Ok(chain.verifier().verify_chain_proof(tip.height, &statement, proof_of(&body)).is_ok())
}

/// Debugging only: how many outputs and spends of those asked for a
/// block of `max_block_size` holds, with its reward and room for a
/// proof: both less in the same measure, where they do not fit.
#[cfg(feature = "dev")]
pub fn fill_plan(max_block_size: usize, outputs: usize, spends: usize) -> (usize, usize) {
    use crate::output::BLOCK_OUTPUT_SIZE;
    let space = max_block_size.saturating_sub(HEADER_SIZE + Body::size_of(0, 1, 0, PROOF_BYTES));
    let asked = spends * crate::codec::POSITION_BYTES + outputs * BLOCK_OUTPUT_SIZE;
    match asked > space {
        true => (outputs * space / asked, spends * space / asked),
        false => (outputs, spends),
    }
}

/// Debugging only: makes the block after `chain`'s last without proving
/// it, where proofs go unchecked: of `outputs` outputs nobody is paid
/// by (each of one unit), and `spends` spends, chosen at random, of the
/// outputs the chain began with (`filled`: how many, and how far
/// apart), with a stand-in the size of a proof. `paid` is the reward:
/// what the block may make, less a unit for each of the outputs.
/// `said` is told what the block is and how long building it took.
#[cfg(feature = "dev")]
#[allow(clippy::too_many_arguments)]
pub fn mine_filled<B: Backend + 'static, S: ItemSource + Sync>(
    chain: &Chain<B, AggregateVerifier>,
    dataset: &S,
    paid: &Output,
    unix: u64,
    start: u64,
    outputs: usize,
    spends: usize,
    filled: Option<(u64, u64)>,
    said: &dyn Fn(&str),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<Mined, Error> {
    use crate::block::BlockOutput;
    use crate::poseidon2::{Fp, P};
    let began = Instant::now();
    let reads_before = crate::store::backend::asked()[0];
    let params = *chain.params();
    let tip = chain.tip()?;
    let height = tip.height + 1;
    let subsidy = params.subsidy(height);
    if subsidy == 0 {
        return Ok(Mined::Finished);
    }
    if paid.amount.checked_add(outputs as u64) != Some(subsidy) {
        return Ok(Mined::Stale);
    }
    // (splitmix64, from the system's own randomness.)
    let mut seed = [0u8; 8];
    crate::random::fill(&mut seed)?;
    let mut x = u64::from_le_bytes(seed);
    let mut next = || {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    // What it spends: outputs the chain began with that are still
    // unspent, each once.
    let mut picked: Vec<u64> = Vec::with_capacity(spends);
    if let Some((n, spacing)) = filled.filter(|(n, _)| *n > 0) {
        let state = chain.whole()?;
        let snap = state.snapshot()?;
        let (at, id) = snap.tip();
        if at != tip.height || (at > 0 && id != tip.hash()) {
            return Ok(Mined::Cancelled);
        }
        let mut seen = std::collections::HashSet::with_capacity(spends);
        for _ in 0..4 * spends {
            if picked.len() == spends {
                break;
            }
            let position = (next() % n) * spacing;
            if seen.insert(position) && snap.is_unspent(position)? {
                picked.push(position);
            }
        }
    }
    picked.sort_unstable();
    let mut made = vec![paid.block_output()];
    made.extend((0..outputs).map(|_| BlockOutput {
        commitment: core::array::from_fn(|_| Fp::new((next() % P as u64) as u32)),
        memo: core::array::from_fn(|_| Fp::new((next() % P as u64) as u32)),
        amount: 1,
    }));
    let spent = picked.len();
    let body = Body { inputs: picked, outputs: made, proof: vec![0u8; PROOF_BYTES], ..Default::default() };
    let bytes = body.to_bytes();
    let state_root = match chain.state_root_after(&BodyRef::from_bytes(&bytes)?) {
        Ok(root) => root,
        // The chain has gone on meanwhile, and spent what was chosen.
        Err(_) if chain.tip()?.hash() != tip.hash() => return Ok(Mined::Stale),
        Err(e) => return Err(e),
    };
    if cancel() {
        return Ok(Mined::Cancelled);
    }
    let took = began.elapsed();
    let reads = crate::store::backend::asked()[0];
    said(&format!(
        "debug fill: block {height}: {outputs} outputs, {spent} spends, {} bytes, built in {:.2}s ({} reads of the \
         disk in {:.1}s)",
        HEADER_SIZE + bytes.len(),
        took.as_secs_f64(),
        reads.0 - reads_before.0,
        (reads.1 - reads_before.1).as_secs_f64()
    ));
    let header = Header {
        prev_hash: tip.hash(),
        height,
        timestamp: unix.max(chain.earliest_timestamp(&tip)?),
        body_commitment: body.commitment(),
        state_root,
        aux: [0; 32],
        mix: tip.mix,
        nonce: [0; 32],
    };
    let target = chain.expected_target(&tip)?;
    let began = Instant::now();
    let Some((nonce, mix, hashes)) = solve(dataset, &header.pow_hash(), &target, start, cancel) else {
        return Ok(Mined::Cancelled);
    };
    let header = Header { nonce, mix, ..header };
    let solved = began.elapsed();
    Ok(Mined::Block { block: Block { header, body }.to_bytes(), header, proved: took, hashes, solved })
}

/// The last blocks of a chain made long without a table whose work is
/// done ([`extend_empty`]): more than a node joining it checks in full.
#[cfg(feature = "dev")]
pub const WORKED: u32 = 16;

/// Debugging only: makes `chain`, whose blocks' proofs go unchecked,
/// `blocks` blocks long, of blocks that are empty but for what each
/// pays (to nobody) and carry no proof: a chain as long as one that has
/// run for years, made in minutes, for trying how a node takes its
/// headers. Their times are `spacing` seconds apart from the first
/// block's, which on a dev network is far more than its blocks are
/// meant to be: so each asks for the least work there is. `unix` is
/// the time now, which no block's time may be ahead of; `progress` is
/// told, now and then, how long the chain is.
///
/// With a table (`dataset`) every block's work is done. Without one a
/// block's work is tens of milliseconds a try, from the seed's text,
/// and a year of blocks most of a day: so only the last [`WORKED`] have
/// their work done, and the rest claim work they have not, in a header
/// that is otherwise what it should be; the chain is told to take
/// their word while they are made ([`Chain::debug_trust_work`]). To a
/// node that takes them as headers, leaving their work to a proof, and
/// checks in full only the last few, they are what any chain's are.
#[cfg(feature = "dev")]
#[allow(clippy::too_many_arguments)]
pub fn extend_empty<B: Backend + 'static>(
    chain: &Chain<B, AggregateVerifier>,
    seed: &crate::pow::SeedText<'_>,
    dataset: Option<&crate::pow::Dataset<'_>>,
    blocks: u32,
    spacing: u64,
    unix: u64,
    progress: &dyn Fn(u32),
) -> Result<(), Error> {
    use crate::block::BlockOutput;
    use crate::poseidon2::Fp;
    let params = *chain.params();
    loop {
        let tip = chain.tip()?;
        let height = tip.height + 1;
        if height > blocks || params.subsidy(height) == 0 {
            return Ok(());
        }
        // (An output like no other: its commitment is its height.)
        let paid = BlockOutput {
            commitment: core::array::from_fn(|i| Fp::new(if i == 0 { height } else { 0x0e0e_0e0e })),
            memo: [Fp::ZERO; 5],
            amount: params.subsidy(height),
        };
        let body = Body { outputs: vec![paid], ..Default::default() };
        let bytes = body.to_bytes();
        let state_root = chain.state_root_after(&BodyRef::from_bytes(&bytes)?)?;
        let timestamp = (params.genesis_timestamp + height as u64 * spacing).max(chain.earliest_timestamp(&tip)?);
        let header = Header {
            prev_hash: tip.hash(),
            height,
            timestamp: timestamp.min(unix),
            body_commitment: body.commitment(),
            state_root,
            aux: [0; 32],
            mix: tip.mix,
            nonce: [0; 32],
        };
        let target = chain.expected_target(&tip)?;
        let worked = dataset.is_some() || height + WORKED > blocks;
        chain.debug_trust_work(!worked);
        let found = match (dataset, worked) {
            (Some(table), _) => solve(table, &header.pow_hash(), &target, height as u64, &|| false),
            (None, true) => solve(&seed.at(height as u64), &header.pow_hash(), &target, height as u64, &|| false),
            // The first nonce whose claim, of a mix of nothing, meets
            // the target.
            (None, false) => {
                let mut claimed = Header { mix: [Fp::ZERO; 8], ..header };
                let mut tried = 0u64;
                loop {
                    claimed.nonce = crate::pow::nonce_from_u64(tried);
                    if claimed.quick_pow_check(&target) {
                        break Some((claimed.nonce, claimed.mix, tried));
                    }
                    tried += 1;
                }
            }
        };
        let Some((nonce, mix, _)) = found else {
            chain.debug_trust_work(false);
            return Ok(());
        };
        let block = Block { header: Header { nonce, mix, ..header }, body }.to_bytes();
        let applied = chain.apply_block(&crate::block::BlockRef::from_bytes(&block)?, unix);
        chain.debug_trust_work(false);
        applied?;
        if height.is_multiple_of(5000) {
            progress(height);
        }
    }
}

/// The proof in a body kept by the chain.
fn proof_of(body: &[u8]) -> &[u8] {
    BodyRef::from_bytes(body).map_or(&[], |b| b.proof())
}

/// What the proof of the chain's last block `tip` speaks to, and that
/// block's body, in which its proof is: for the proof of the block
/// after it to build on. `end` is the position the next output takes,
/// the state being as `tip` left it.
///
/// Nothing of this is kept as such, and nothing need be. The body is
/// kept. The state's root before the block is in the header before it.
/// Where its outputs begin is where they end, less how many it made:
/// so that a node that took its state whole, and has no state of
/// before its last block, can still say.
fn before<B: Backend + 'static>(
    chain: &Chain<B, AggregateVerifier>,
    tip: &Header,
    end: u64,
) -> Result<(Statement, Vec<u8>), Error> {
    let missing = |what: &'static str| -> Error { std::io::Error::new(std::io::ErrorKind::InvalidData, what).into() };
    let body = chain.body(&tip.hash())?.ok_or_else(|| missing("the last block's body is not kept"))?;
    let view = BodyRef::from_bytes(&body)?;
    let parent = chain.header_at(tip.height - 1)?.ok_or_else(|| missing("the header before the last is not kept"))?;
    let made = (view.outputs().len() + view.commits()) as u64;
    let first = end.checked_sub(made).ok_or_else(|| missing("the last block made more outputs than there are"))?;
    let statement = Statement::from_block(&BlockStatement {
        height: tip.height,
        prev_state_root: parent.state_root,
        new_state_root: tip.state_root,
        first_output_position: first,
        subsidy: chain.params().subsidy(tip.height),
        body: view,
        parent_work: chain.parent_work(&parent),
        parent_hash: tip.prev_hash,
    });
    Ok((statement, body))
}

/// A nonce whose hash with `header_hash` meets `target`, with the mix
/// that goes in the header beside it, and how many were tried: on
/// every thread there is, the nonces from `start` dealt out among
/// them. None if `cancel` said to give up first.
pub fn solve<S: ItemSource + Sync>(
    dataset: &S,
    header_hash: &Digest,
    target: &Target,
    start: u64,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Option<(Nonce, Digest, u64)> {
    let threads = crate::parallel::threads() as u64;
    let (done, tried) = (AtomicBool::new(false), AtomicU64::new(0));
    let found = Mutex::new(None);
    std::thread::scope(|scope| {
        for t in 0..threads {
            let (done, tried, found) = (&done, &tried, &found);
            scope.spawn(move || {
                let (mut n, mut mine) = (start.wrapping_add(t), 0u64);
                while !done.load(Ordering::Relaxed) {
                    let nonce = nonce_from_u64(n);
                    let out = hashimoto(dataset, header_hash, &nonce);
                    mine += 1;
                    if target.is_met_by(&out.result) && !done.swap(true, Ordering::Relaxed) {
                        *found.lock().unwrap_or_else(|e| e.into_inner()) = Some((nonce, out.mix));
                    }
                    // (One of them asks, and not at every hash.)
                    if t == 0 && mine.is_multiple_of(64) && cancel() {
                        done.store(true, Ordering::Relaxed);
                    }
                    n = n.wrapping_add(threads);
                }
                tried.fetch_add(mine, Ordering::Relaxed);
            });
        }
    });
    let (nonce, mix) = found.into_inner().unwrap_or_else(|e| e.into_inner())?;
    Some((nonce, mix, tried.into_inner()))
}

#[cfg(test)]
mod hold_off {
    use super::*;
    use crate::poseidon2::Fp;

    /// A table is filled whole, and how far it has got is said in
    /// twentieths, each once and in order, none of them the last.
    #[test]
    fn a_table_is_filled_and_says_how_far_it_has_got() {
        let seed = crate::pow::SeedText::new(crate::pow::PowParams {
            log_dataset_items: 12,
            max_log_dataset_items: 12,
            ..crate::pow::PowParams::MAINNET
        });
        let table = LazyDataset::new(&seed, 12).unwrap();
        let said = Mutex::new(Vec::new());
        fill_table(&table, Duration::from_micros(200), &|percent| said.lock().unwrap().push(percent));
        assert!(table.is_complete());
        let said = said.into_inner().unwrap();
        assert!(said.windows(2).all(|w| w[0] < w[1]), "{said:?}");
        assert!(said.iter().all(|p| p % 5 == 0 && (5..=95).contains(p)), "{said:?}");
        // Whole already: nothing to fill, nothing to say.
        fill_table(&table, Duration::from_micros(200), &|_| panic!("nothing was to be said"));
    }

    /// A chain ahead is waited for so long, and no longer; another
    /// chain ahead is waited for afresh; and with none ahead, blocks
    /// are made.
    #[test]
    fn a_chain_ahead_is_waited_for_so_long_and_no_longer() {
        let chain = |n: u32| -> Digest { [Fp::new(n); 8] };
        let mut hold = HoldOff::new(600);
        assert_eq!(hold.limit(), Duration::from_secs(1800));
        assert_eq!(HoldOff::new(1).limit(), Duration::from_secs(10));
        let t = Instant::now();
        let at = |seconds: u64| t + Duration::from_secs(seconds);
        assert_eq!(hold.ask(None, at(0)), Now::Mine);
        // A chain ahead: waited for, until the time allowed is up.
        assert_eq!(hold.ask(Some(chain(1)), at(10)), Now::Wait { first: true });
        assert_eq!(hold.ask(Some(chain(1)), at(1000)), Now::Wait { first: false });
        assert_eq!(hold.ask(Some(chain(1)), at(1809)), Now::Wait { first: false });
        assert_eq!(hold.ask(Some(chain(1)), at(1810)), Now::MineAnyway { first: true });
        // From then on blocks are made, however long it stays ahead.
        assert_eq!(hold.ask(Some(chain(1)), at(1811)), Now::MineAnyway { first: false });
        assert_eq!(hold.ask(Some(chain(1)), at(99_999)), Now::MineAnyway { first: false });
        // It grows (another last header): that is news, and waited for.
        assert_eq!(hold.ask(Some(chain(2)), at(100_000)), Now::Wait { first: true });
        assert_eq!(hold.ask(Some(chain(2)), at(100_500)), Now::Wait { first: false });
        // Its blocks come: nothing is ahead, and blocks are made.
        assert_eq!(hold.ask(None, at(100_600)), Now::Mine);
        // The same chain ahead again later is waited for again.
        assert_eq!(hold.ask(Some(chain(2)), at(100_700)), Now::Wait { first: true });
        // A chain ahead that keeps growing is waited for each time it
        // does, the time allowed counted from when it last did.
        assert_eq!(hold.ask(Some(chain(3)), at(102_000)), Now::Wait { first: true });
        assert_eq!(hold.ask(Some(chain(3)), at(103_700)), Now::Wait { first: false });
        assert_eq!(hold.ask(Some(chain(3)), at(103_800)), Now::MineAnyway { first: true });
    }
}

#[cfg(all(test, feature = "dev"))]
mod tests {
    use super::*;
    use crate::aggregate::{AggregatorParams, Genesis};
    use crate::block::BlockRef;
    use crate::chain::apply::Applied;
    use crate::chain::params::ChainParams;
    use crate::poseidon2::Fp;
    use crate::pow::{Dataset, SeedText};
    use crate::store::testing::MemBackend;

    /// 2026-06-01, after the dev network's genesis.
    const NOW: u64 = 1_780_000_000;

    fn dev() -> (Chain<MemBackend, AggregateVerifier>, Dataset<'static>) {
        network(ChainParams::DEV, AggregatorParams::DEV)
    }

    fn network(
        params: ChainParams,
        proofs: AggregatorParams,
    ) -> (Chain<MemBackend, AggregateVerifier>, Dataset<'static>) {
        let seed = SeedText::new(params.pow);
        let genesis = Genesis::of(&params.genesis().header, &seed);
        let verifier = AggregateVerifier::new(proofs, params.emission, genesis);
        let chain = Chain::open(MemBackend::new(), 64, params, seed, verifier).unwrap();
        (chain, Dataset::built_in(&seed).expect("the dev network's table is built in"))
    }

    /// Blocks made here are blocks the chain takes: proof, work, state
    /// root and reward as the rules have them, one after another.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
    fn a_block_made_here_joins_the_chain() {
        let (chain, dataset) = dev();
        let reward: Digest = core::array::from_fn(|i| Fp::new(1000 + i as u32));
        for height in 1..=3u32 {
            let made = mine(&chain, &dataset, &reward, NOW, height as u64 * 1_000_003, &|_| {}, &|| false).unwrap();
            let Mined::Block { block, header, hashes, .. } = made else { panic!("{made:?}") };
            assert!(header.height == height && hashes >= 1);
            let view = BlockRef::from_bytes(&block).unwrap();
            assert_eq!(chain.apply_block(&view, NOW), Ok(Applied::Extended));
            let tip = chain.tip().unwrap();
            assert_eq!((tip.height, tip), (height, *view.header()));
            // What it made: one output, of the reward, to the key.
            let paid = Output::to_key_hash(&reward, chain.params().subsidy(height));
            let outputs: Vec<_> = view.body().outputs().collect();
            assert_eq!(outputs.len(), 1);
            assert_eq!((outputs[0].commitment, outputs[0].amount), (paid.commitment, paid.amount));
        }
    }

    /// On the recursive dev network a block's proof builds on the proof
    /// of the block before, which is taken from the chain: the first
    /// block's on none, and each after it on the last.
    #[test]
    #[ignore = "proves proofs of proofs, block on block; run with --release"]
    fn blocks_of_a_recursive_network_build_on_the_proof_before() {
        let (chain, dataset) = network(ChainParams::DEV_RECURSIVE, AggregatorParams::DEV_RECURSIVE);
        let reward: Digest = core::array::from_fn(|i| Fp::new(1000 + i as u32));
        for height in 1..=3u32 {
            let began = Instant::now();
            let made = mine(&chain, &dataset, &reward, NOW, height as u64 * 1_000_003, &|_| {}, &|| false).unwrap();
            let Mined::Block { block, header, proved, .. } = made else { panic!("{made:?}") };
            println!("block {height}: {} bytes, proved in {proved:?}, made in {:?}", block.len(), began.elapsed());
            let view = BlockRef::from_bytes(&block).unwrap();
            // The chain checks the proof, the one before in it.
            assert_eq!(chain.apply_block(&view, NOW), Ok(Applied::Extended));
            assert_eq!(chain.tip().unwrap(), header);
        }
        // What is made again of the last block is what its proof was
        // made to: the chain's own check of the proof with it holds.
        let tip = chain.tip().unwrap();
        let end = chain.whole().unwrap().snapshot().unwrap().outputs().next;
        let (statement, body) = before(&chain, &tip, end).unwrap();
        assert_eq!(chain.verifier().verify_chain_proof(tip.height, &statement, proof_of(&body)), Ok(()));
    }

    /// A block made here carries what was chosen for it from the pool,
    /// and pays their fees with its reward: a block the chain takes.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
    fn a_block_carries_the_pools_transactions() {
        let (chain, dataset) = dev();
        let mut key = crate::xmss::SecretKey::generate(&[5; 32]);
        let reward = crate::output::pubkey_hash(&key.public_key());
        let paid_now = |chain: &Chain<MemBackend, AggregateVerifier>, pooled: &[Transaction]| {
            Output::to_key_hash(&reward, reward_due(chain, pooled).unwrap().unwrap().1)
        };
        // The first block pays the key; the second carries a spend of
        // that, all but a fee, back to it.
        let made = mine(&chain, &dataset, &reward, NOW, 3, &|_| {}, &|| false).unwrap();
        let Mined::Block { block, .. } = made else { panic!("{made:?}") };
        assert_eq!(chain.apply_block(&BlockRef::from_bytes(&block).unwrap(), NOW), Ok(Applied::Extended));
        let (paid, fee) = (chain.params().subsidy(1), 1_000_000);
        let mut pool = Mempool::new(1 << 20);
        let position = {
            let state = chain.whole().unwrap();
            let snap = state.snapshot().unwrap();
            let theirs = crate::output::commitment(&key.public_key(), paid);
            let position = (0..64).find(|p| snap.output(*p).unwrap().is_some_and(|(r, _)| r.commitment == theirs));
            let mut tx = UnsignedTransaction::new(
                vec![(key.public_key(), paid)],
                vec![Output::new(&key.public_key(), paid - fee)],
            )
            .sign(|_, _, m| key.sign(m))
            .unwrap();
            tx.set_positions(&[position.unwrap()]);
            pool.insert(&tx.to_bytes(), &snap, 2, NOW).unwrap();
            position.unwrap()
        };
        // Nothing is chosen for a miner that is to prove no signatures.
        assert!(choose(&chain, &|f| f(&pool), 0).unwrap().0.is_empty());
        let (pooled, sweeps) = choose(&chain, &|f| f(&pool), MAX_SIGNATURES).unwrap();
        assert_eq!((pooled.len(), sweeps.len()), (1, 0));
        let made =
            mine_with(&chain, &dataset, &paid_now(&chain, &pooled), NOW, 7, &pooled, &sweeps, &|_| {}, &|| false)
                .unwrap();
        let Mined::Block { block, .. } = made else { panic!("{made:?}") };
        let view = BlockRef::from_bytes(&block).unwrap();
        assert_eq!(chain.apply_block(&view, NOW), Ok(Applied::Extended));
        // It spends that output, and makes two: the reward with the
        // fee, and what the transaction paid.
        let spent: Vec<u64> = view.body().inputs().collect();
        assert_eq!(spent, [position]);
        let mut amounts: Vec<u64> = view.body().outputs().map(|o| o.amount).collect();
        amounts.sort_unstable();
        let mut wanted = [chain.params().subsidy(2) + fee, paid - fee];
        wanted.sort_unstable();
        assert_eq!(amounts, wanted);
        // The same transaction again, its output spent: the block is
        // not made, and nothing is wrong.
        let again =
            mine_with(&chain, &dataset, &paid_now(&chain, &pooled), NOW, 9, &pooled, &sweeps, &|_| {}, &|| false)
                .unwrap();
        assert!(matches!(again, Mined::Stale), "{again:?}");
    }

    /// Told to give up, it does: while proving, or while looking for
    /// the nonce.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
    fn it_gives_up_when_told() {
        let (chain, dataset) = dev();
        let reward: Digest = core::array::from_fn(|i| Fp::new(1000 + i as u32));
        assert!(matches!(mine(&chain, &dataset, &reward, NOW, 0, &|_| {}, &|| true).unwrap(), Mined::Cancelled));
        // A target nothing meets: until told.
        let asked = AtomicU64::new(0);
        let cancel = || asked.fetch_add(1, Ordering::Relaxed) >= 3;
        let never = Target([0; 32]);
        assert!(solve(&dataset, &reward, &never, 7, &cancel).is_none());
        assert!(chain.tip().unwrap().height == 0);
    }
}
