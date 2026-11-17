//! Making blocks: the block after the chain's last is built, proven,
//! and its proof of work found.
//!
//! [`mine`] makes one block and hands it back whole; whoever runs it
//! gives the block to the node, which applies it and tells its peers
//! (`net::node::Hand`). Nothing here knows of the network.
//!
//! A block made here pays its reward to one key, and carries nothing
//! else: there is no pool of transactions yet.
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
//! 1. The reward's transaction, and its witness against the state as
//!    it is.
//! 2. The block's proof: what takes the time, where proofs are large.
//! 3. The header, and a nonce whose hash meets the target: on every
//!    thread there is, each trying its own nonces.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::aggregate::{AggregateVerifier, Statement};
use crate::block::{Block, Body, BodyRef, Header};
use crate::block_air::SegmentWitness;
use crate::chain::Chain;
use crate::chain::verify::BlockStatement;
use crate::difficulty::Target;
use crate::error::Error;
use crate::hash::Digest;
use crate::name_air::NameWitness;
use crate::output::{Output, Sig};
use crate::pow::{ItemSource, LazyDataset, Nonce, hashimoto, nonce_from_u64};
use crate::store::backend::Backend;
use crate::transaction::UnsignedTransaction;

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
    /// The chain has had its last block: there is none to make.
    Finished,
}

/// Makes the block after `chain`'s last, paying its reward to the key
/// of hash `reward`. `unix` is the time by the calendar, in seconds,
/// and `start` where the nonces tried begin (any number: so that two
/// miners do not try the same). `proved` is called when the block's
/// proof is made, with how long that took: from then the nonce is
/// looked for. `cancel` is asked now and then whether to give up.
///
/// `dataset` is the table of the proof of work for that block's
/// height: whole, or one that fills as it is read
/// ([`crate::pow::LazyDataset`]).
pub fn mine<B: Backend + 'static, S: ItemSource + Sync>(
    chain: &Chain<B, AggregateVerifier>,
    dataset: &S,
    reward: &Digest,
    unix: u64,
    start: u64,
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
    let paid = Output::to_key_hash(reward, subsidy);
    let tx = UnsignedTransaction::new(vec![], vec![paid])
        .sign(|_, _, _| Err::<Sig, ()>(()))
        .expect("a transaction without inputs needs no signature");
    let rows = chain.verifier().params().segment_rows();
    let (segments, prev_state_root, first_output_position) = {
        let state = chain.whole()?;
        let snap = state.snapshot()?;
        // (The state of the block being built on, or it has moved on.)
        // (The state before the first block is of no block.)
        let (at, id) = snap.tip();
        if at != tip.height || (at > 0 && id != tip.hash()) {
            return Ok(Mined::Cancelled);
        }
        let segments = SegmentWitness::collect_by_rows(&snap, &[tx], rows, height)?;
        (segments, snap.root(), snap.outputs().next)
    };
    // What the proof of the block before speaks to, and that proof:
    // where this block's proof is to build on it.
    let before = match chain.verifier().needs_plan() && height > 1 {
        true => Some(before(chain, &tip, first_output_position)?),
        false => None,
    };
    let first = &segments[0];
    let names = NameWitness {
        min_reveal: params.min_reveal,
        root_in: first.root_in,
        pos_in: first.pos_in,
        height,
        ops: vec![],
    }
    .with_segments(&segments);
    let mut body = Body {
        inputs: vec![],
        outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
        proof: vec![],
        ..Default::default()
    };
    let unproven = body.to_bytes();
    let unproven = BodyRef::from_bytes(&unproven)?;
    let state_root = chain.state_root_after(&unproven)?;
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
