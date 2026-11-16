//! Making blocks: the block after the chain's last is built, proven,
//! and its proof of work found.
//!
//! [`mine`] makes one block and hands it back whole; whoever runs it
//! gives the block to the node, which applies it and tells its peers
//! (`net::node::Hand`). Nothing here knows of the network.
//!
//! A block made here pays its reward to one key, and carries nothing
//! else: there is no pool of transactions yet. And only for a network
//! whose block proofs are checked directly (the dev network): a proof
//! that builds on the proof of the block before it needs that proof
//! kept, which the chain does not do yet.
//!
//! The steps, each given up if `cancel` says so (the chain has another
//! last block, or the node is stopping):
//!
//! 1. The reward's transaction, and its witness against the state as
//!    it is.
//! 2. The block's proof.
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
use crate::pow::{Dataset, Nonce, hashimoto, nonce_from_u64};
use crate::store::backend::Backend;
use crate::transaction::UnsignedTransaction;

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
/// miners do not try the same). `cancel` is asked now and then whether
/// to give up.
pub fn mine<B: Backend + 'static>(
    chain: &Chain<B, AggregateVerifier>,
    dataset: &Dataset<'_>,
    reward: &Digest,
    unix: u64,
    start: u64,
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
        let segments = SegmentWitness::collect_by_rows(&snap, &[tx], rows, height)?;
        (segments, snap.root(), snap.outputs().next)
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
    let Some(proof) = chain.verifier().prove_block(height, &statement, &segments, &names, None, jobs, &|_| {}, cancel)
    else {
        return Ok(Mined::Cancelled);
    };
    body.proof = proof;
    let proved = began.elapsed();
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
    Ok(Mined::Block { block: Block { header, body }.to_bytes(), header, proved, hashes, solved })
}

/// A nonce whose hash with `header_hash` meets `target`, with the mix
/// that goes in the header beside it, and how many were tried: on
/// every thread there is, the nonces from `start` dealt out among
/// them. None if `cancel` said to give up first.
pub fn solve(
    dataset: &Dataset<'_>,
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

#[cfg(all(test, feature = "dev"))]
mod tests {
    use super::*;
    use crate::aggregate::{AggregatorParams, Genesis};
    use crate::block::BlockRef;
    use crate::chain::apply::Applied;
    use crate::chain::params::ChainParams;
    use crate::poseidon2::Fp;
    use crate::pow::SeedText;
    use crate::store::testing::MemBackend;

    /// 2026-06-01, after the dev network's genesis.
    const NOW: u64 = 1_780_000_000;

    fn dev() -> (Chain<MemBackend, AggregateVerifier>, Dataset<'static>) {
        let params = ChainParams::DEV;
        let seed = SeedText::new(params.pow);
        let genesis = Genesis::of(&params.genesis().header, &seed);
        let verifier = AggregateVerifier::new(AggregatorParams::DEV, params.emission, genesis);
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
            let made = mine(&chain, &dataset, &reward, NOW, height as u64 * 1_000_003, &|| false).unwrap();
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

    /// Told to give up, it does: while proving, or while looking for
    /// the nonce.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
    fn it_gives_up_when_told() {
        let (chain, dataset) = dev();
        let reward: Digest = core::array::from_fn(|i| Fp::new(1000 + i as u32));
        assert!(matches!(mine(&chain, &dataset, &reward, NOW, 0, &|| true).unwrap(), Mined::Cancelled));
        // A target nothing meets: until told.
        let asked = AtomicU64::new(0);
        let cancel = || asked.fetch_add(1, Ordering::Relaxed) >= 3;
        let never = Target([0; 32]);
        assert!(solve(&dataset, &reward, &never, 7, &cancel).is_none());
        assert!(chain.tip().unwrap().height == 0);
    }
}
