//! The tests of the tree of proofs and of the chain's proof: the
//! original's, with their witnesses gathered from the store
//! ([`crate::block_air`]'s test set).

use super::*;
use crate::block::{Body, BodyRef};
use crate::block_air::circuit_tests::TestSet;
use crate::block_proof::{prove_name_padded, prove_segment_padded};
use crate::error::Error;
use crate::output::{Key, Output as TxOutput, Sig};
use crate::pow::SeedText;
use crate::pow_air::Work;
use crate::transaction::{Transaction, UnsignedTransaction};
use crate::xmss::PublicKey;

/// A configuration at an eighth of the rate, for the size tests.
const EIGHTH: StarkConfig = StarkConfig { log_blowup: 3, num_queries: 28, pow_bits: 16, zk: false, commit_bits: 0 };

/// The seed text of `pow`.
fn test_seed(pow: PowParams) -> SeedText<'static> {
    SeedText::new(pow)
}

/// A header for tests on `prev_hash` at `height` with `state_root`, its mix
/// hashimoto's under `pow` (its target not met: the chain proof checks the
/// mix, not the target), and its work.
fn test_header(prev_hash: Digest, height: u32, state_root: Digest, pow: PowParams) -> (Header, Work) {
    let mut header = Header {
        prev_hash,
        height,
        timestamp: 1_793_000_000 + 600 * height as u64,
        body_commitment: core::array::from_fn(|k| Fp::new(100 * height + k as u32)),
        state_root,
        aux: [height as u8; 32],
        mix: [Fp::ZERO; DIGEST],
        nonce: [7u8.wrapping_add(height as u8); 32],
    };
    let work = Work::computed(&test_seed(pow), &header);
    header.mix = work.mix;
    (header, work)
}

/// The test chains' genesis: a header at height 0, its `mix` empty.
fn test_genesis_header() -> Header {
    Header { mix: [Fp::ZERO; DIGEST], ..test_header([Fp::ZERO; DIGEST], 0, [Fp::ZERO; DIGEST], PowParams::DEV).0 }
}

/// The test genesis's work under `pow`: its true mix.
fn test_work(pow: PowParams) -> Work {
    Work::computed(&test_seed(pow), &test_genesis_header())
}

fn key(tag: u8) -> Key {
    let mut s = [0u8; 32];
    s[0] = tag;
    Key::generate(&s)
}

/// Reward-only transactions: tiny segments (one output each).
fn reward(pk: &PublicKey, amount: u64) -> Transaction {
    UnsignedTransaction::new(vec![], vec![TxOutput::new(pk, amount)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap()
}

/// Small parameters: 128-row segments hold one output-only transaction,
/// nodes take two children.
const SMALL: AggregatorParams = AggregatorParams {
    segment: StarkConfig { log_blowup: 1, num_queries: 4, pow_bits: 3, zk: false, commit_bits: 110 },
    segment_log_n: 7,
    name_log_n: 11,
    max_segments: 16,
    fan_in: 2,
    outer: StarkConfig { log_blowup: 2, num_queries: 4, pow_bits: 5, zk: false, commit_bits: 112 },
    wrap: StarkConfig { log_blowup: 3, num_queries: 4, pow_bits: 4, zk: true, commit_bits: 112 },
    direct: false,
    pow: PowParams::DEV,
    min_reveal: crate::name::MIN_REVEAL,
};

struct Setup {
    segments: Vec<SegmentWitness>,
    names: NameWitness,
    statement: Statement,
    proofs: Vec<SegmentProof>,
    name_proof: NameProof,
    work_proof: WorkProof,
}

/// The genesis of the network whose aggregator `params` are.
fn network_genesis(params: AggregatorParams) -> Genesis {
    use crate::chain::params::ChainParams;
    let net = if params == AggregatorParams::MAINNET { ChainParams::MAINNET } else { ChainParams::DEV_RECURSIVE };
    assert_eq!(net.pow, params.pow);
    Genesis::of(&net.genesis().header, &test_seed(net.pow))
}

/// The test chains' genesis under `pow`.
fn genesis_for(pow: PowParams) -> Genesis {
    Genesis { hash: test_genesis_header().hash(), work: test_work(pow) }
}

/// The test blocks' parent work, proven at SMALL (once).
fn small_work_proof() -> WorkProof {
    static PROOF: std::sync::OnceLock<WorkProof> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| SMALL.prove_work(&test_work(SMALL.pow))).clone()
}

/// An empty name segment witness after `segments`, at `height`.
fn empty_names(segments: &[SegmentWitness], height: u32) -> NameWitness {
    let first = &segments[0];
    NameWitness {
        min_reveal: crate::name::MIN_REVEAL,
        root_in: first.root_in,
        pos_in: first.pos_in,
        height,
        ops: vec![],
        signed: Default::default(),
    }
    .with_segments(segments)
}

fn setup(name: &str, amounts: &[u64], subsidy: u64) -> Setup {
    let miner = key(9).public_key();
    let s = setup_txs(name, &amounts.iter().map(|a| reward(&miner, *a)).collect::<Vec<_>>(), subsidy);
    assert_eq!(s.segments.len(), amounts.len());
    s
}

/// `txs` packed into SMALL segments, proven.
fn setup_txs(_name: &str, txs: &[Transaction], subsidy: u64) -> Setup {
    let utxo = TestSet::new();
    let prev_root = utxo.root();
    let segments = utxo.collect_by_rows(txs, SMALL.segment_rows(), 1).unwrap();
    let new_root = utxo.root();
    let body = Body {
        inputs: vec![],
        outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
        proof: vec![],
        ..Default::default()
    };
    let statement = Statement::from_block(&BlockStatement {
        height: 1,
        prev_state_root: prev_root,
        new_state_root: new_root,
        first_output_position: 0,
        subsidy,
        body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
        parent_work: test_work(SMALL.pow),
        parent_hash: test_genesis_header().hash(),
    });
    let proofs: Vec<SegmentProof> =
        segments.iter().map(|w| prove_segment_padded(&SMALL.segment, w, SMALL.segment_log_n)).collect();
    let names = empty_names(&segments, 1);
    let name_proof = prove_name_padded(&SMALL.segment, &names, SMALL.name_log_n);
    Setup { segments, names, statement, proofs, name_proof, work_proof: small_work_proof() }
}

fn seg_children(proofs: &[SegmentProof]) -> Vec<Child<'_>> {
    proofs.iter().map(Child::Segment).collect()
}

/// One reward transaction with three outputs: in 128-row segments it
/// spans three.
fn spanning_setup(name: &str) -> Setup {
    let miner = key(9).public_key();
    let outs = [10, 20, 25].map(|a| TxOutput::new(&miner, a)).to_vec();
    let tx = UnsignedTransaction::new(vec![], outs).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
    setup_txs(name, &[tx], 55)
}

#[test]
#[cfg_attr(debug_assertions, ignore = "proves proofs of proofs; run with --release")]
fn nodes_chain_open_transactions() {
    let s = spanning_setup("span");
    assert_eq!(s.proofs.len(), 3);
    let (p0, p1, p2) = (&s.proofs[0].public, &s.proofs[1].public, &s.proofs[2].public);
    assert!(p0.carry_out.open && p1.carry_out.open && !p2.carry_out.open);
    assert_eq!((p0.carry_out, p1.carry_out), (p1.carry_in, p2.carry_in));
    // A node over the first two segments chains them and exports the
    // open transaction.
    let c = compile_node(&SMALL, &seg_children(&s.proofs[..2]), Output::Record);
    let exec = VmAir::execute(&c.prog, &c.inputs).expect("node accepts chained open transactions");
    let record = combine_records(&[*p0, *p1]);
    assert!(record.carry_out.open && !record.carry_in.open);
    assert_eq!(exec.output_digest, Some(node_output(&record, &tree_digest(&[None, None]))));
    // Out of order, the carries do not chain (nor do the roots).
    let c = compile_node(&SMALL, &seg_children(&[s.proofs[1].clone(), s.proofs[0].clone()]), Output::Record);
    assert!(matches!(VmAir::execute(&c.prog, &c.inputs), Err(Error::VmAssertion(_))));
    // A block that ends with the transaction still open is rejected by
    // the root, though everything else about it is consistent.
    let short = Statement {
        new_state_root: p1.root_out,
        outputs_state: p1.osp_out,
        end_output_position: p1.pos_out,
        subsidy: 30,
        ..s.statement.clone()
    };
    let c = compile_node(
        &SMALL,
        &seg_children(&s.proofs[..2]),
        Output::Statement(&short, &s.name_proof, &s.work_proof, None),
    );
    assert!(matches!(VmAir::execute(&c.prog, &c.inputs), Err(Error::VmAssertion(_))));
}

#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn proving_can_be_cancelled() {
    let s = setup("cancel", &[30, 25], 55);
    let shape = plan(&SMALL, 2);
    let quiet = |_: Progress| {};
    // At once: no segment is proven.
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let now = || {
        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    };
    assert!(prove_block_cancellable(&SMALL, &shape, &s.statement, &s.segments, &s.names, 2, &quiet, &now).is_none());
    assert!(calls.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    // Part way: after the segments, during the node's phases.
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let later = || calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 6;
    assert!(prove_block_cancellable(&SMALL, &shape, &s.statement, &s.segments, &s.names, 2, &quiet, &later).is_none());
    // Never: a proof as from `prove_block_with`.
    let proof =
        prove_block_cancellable(&SMALL, &shape, &s.statement, &s.segments, &s.names, 2, &quiet, &|| false).unwrap();
    assert_eq!(
        AggregateVerifier::new(SMALL, &[(10, 55)], genesis_for(SMALL.pow)).verify_statement(&s.statement, &proof),
        Ok(())
    );
}

#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn chain_proofs_cover_history() {
    let utxo = TestSet::new();
    let miner = key(9).public_key();
    // Two consecutive blocks on one UTXO set, 55 each, each on its
    // parent's hash and work.
    let block = |txs: Vec<Transaction>, height: u32, parent: (Digest, Work)| {
        let prev_root = utxo.root();
        let first = utxo.next_position();
        let segments = utxo.collect_by_rows(&txs, SMALL.segment_rows(), height).unwrap();
        let body = Body {
            inputs: vec![],
            outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
            proof: vec![],
            ..Default::default()
        };
        let statement = Statement::from_block(&BlockStatement {
            height,
            prev_state_root: prev_root,
            new_state_root: utxo.root(),
            first_output_position: first,
            subsidy: 55,
            body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
            parent_work: parent.1,
            parent_hash: parent.0,
        });
        let names = empty_names(&segments, height);
        (segments, statement, names)
    };
    let genesis = genesis_for(SMALL.pow);
    let (seg1, st1, nm1) = block(vec![reward(&miner, 30), reward(&miner, 25)], 1, (genesis.hash, genesis.work));
    // Block 1's header, the parent of block 2.
    let (h1, work1) = test_header(genesis.hash, 1, st1.new_state_root, SMALL.pow);
    let (seg2, st2, nm2) = block(vec![reward(&miner, 55)], 2, (h1.hash(), work1));

    let mut cache = PlanCache::new();
    let tree = crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&SMALL, &mut cache));
    let emission = [(10u32, 55u64)];
    let t = std::time::Instant::now();
    let setup = chain_setup(&SMALL, &emission, &genesis_for(SMALL.pow), &tree.root(), tree.height(), &mut cache);
    println!("chain setup in {:?}: 2^{}/2^{}", t.elapsed(), setup.log_n, setup.hash_log_n);
    let wrap_of = |segs: &[SegmentWitness], st: &Statement, nm: &NameWitness| {
        let shape = plan_with(&SMALL, segs.len(), &mut PlanCache::new());
        let proof = prove_wrap(&SMALL, &shape, st, segs, nm, 2, &|_| {}, &|| false).unwrap();
        (shape.wrap.unwrap(), proof, plan_index(segs.len(), false))
    };
    let (w1, p1, i1) = wrap_of(&seg1, &st1, &nm1);
    let (w2, p2, i2) = wrap_of(&seg2, &st2, &nm2);
    let witness = |height, st, wrap, proof, index, prev| ChainWitness {
        height,
        statement: st,
        wrap,
        wrap_proof: proof,
        path: tree.open(index),
        index,
        prev,
    };
    let t = std::time::Instant::now();
    let c1 = prove_chain(&SMALL, &emission, &setup, &witness(1, &st1, w1, &p1, i1, None), &|| false).unwrap();
    println!("base proof in {:?}", t.elapsed());
    assert_eq!(verify_chain(&SMALL, &setup, 1, &st1, &c1), Ok(()));
    let prev = PrevChain { height: 1, statement: &st1, proof: &c1, header: &h1 };
    let t = std::time::Instant::now();
    let c2 = prove_chain(&SMALL, &emission, &setup, &witness(2, &st2, w2, &p2, i2, Some(prev)), &|| false).unwrap();
    println!("step proof in {:?}, {} bytes", t.elapsed(), c2.to_bytes().len());
    assert_eq!(verify_chain(&SMALL, &setup, 2, &st2, &c2), Ok(()));
    // Wrong height, statement or proof.
    assert!(verify_chain(&SMALL, &setup, 3, &st2, &c2).is_err());
    assert!(verify_chain(&SMALL, &setup, 2, &st1, &c2).is_err());
    assert!(verify_chain(&SMALL, &setup, 2, &st2, &c1).is_err());
    let mut other = st2.clone();
    other.end_output_position += 1;
    assert!(verify_chain(&SMALL, &setup, 2, &other, &c2).is_err());
    // Every structural field of the chain proof (zero knowledge: its
    // wrap), at its boundary values: the proof a peer sends with a block.
    let t = std::time::Instant::now();
    let (fields, panicked, accepted) = crate::codec::sweep_fields(&c2.to_bytes(), |b| {
        stark::Proof::from_bytes(b).ok().map(|p| p != c2 && verify_chain(&SMALL, &setup, 2, &st2, &p).is_ok())
    });
    println!("{fields} fields swept in {:?}", t.elapsed());
    assert!(panicked.is_empty() && accepted.is_empty(), "panicked {panicked:?}, accepted {accepted:?}");
    // The schedule is enforced: with block 2 due 7, its 55 is refused.
    let strict = [(1u32, 55u64), (9, 7)];
    let bad = std::panic::catch_unwind(|| {
        let prev = PrevChain { height: 1, statement: &st1, proof: &c1, header: &h1 };
        let w = witness(2, &st2, w2, &p2, i2, Some(prev));
        compile_chain(&SMALL, &strict, &setup.genesis, &setup.plan_root, &setup.base, &setup.step, &w, None)
    });
    if let Ok(c) = bad {
        assert!(VmAir::execute(&c.prog, &c.inputs).is_err());
    }
    // A wrap that is not in the plan is refused.
    let mut fake = w2;
    fake.tree[0] += Fp::ONE;
    let prev = PrevChain { height: 1, statement: &st1, proof: &c1, header: &h1 };
    let w = witness(2, &st2, fake, &p2, i2, Some(prev));
    let c = compile_chain(&SMALL, &emission, &setup.genesis, &setup.plan_root, &setup.base, &setup.step, &w, None);
    assert!(VmAir::execute(&c.prog, &c.inputs).is_err());
    // The step stands for one header chain: block 2's proof verifies
    // only with block 1's hash as its parent, and is made only on a
    // parent header with that hash, linked to genesis, at height 1, on
    // block 1's state.
    let mut other = st2.clone();
    other.parent_hash[0] += Fp::ONE;
    assert!(verify_chain(&SMALL, &setup, 2, &other, &c2).is_err());
    let parents = [
        ("block 1's header", h1),
        ("another timestamp", Header { timestamp: h1.timestamp + 1, ..h1 }),
        ("another body", Header { body_commitment: [Fp::ONE; DIGEST], ..h1 }),
        ("another aux", Header { aux: [9; 32], ..h1 }),
    ];
    for (i, (what, h)) in parents.iter().enumerate() {
        let prev = PrevChain { height: 1, statement: &st1, proof: &c1, header: h };
        let w = witness(2, &st2, w2, &p2, i2, Some(prev));
        let c = compile_chain(&SMALL, &emission, &setup.genesis, &setup.plan_root, &setup.base, &setup.step, &w, None);
        assert_eq!(VmAir::execute(&c.prog, &c.inputs).is_err(), i > 0, "{what}");
    }
    // A parent on another chain: its own hash and work, so the root
    // proved its work, but its prev_hash is not genesis's.
    let (stray, stray_work) = test_header([Fp::ONE; DIGEST], 1, st1.new_state_root, SMALL.pow);
    let st_stray = Statement { parent_hash: stray.hash(), parent_work: stray_work, ..st2.clone() };
    let prev = PrevChain { height: 1, statement: &st1, proof: &c1, header: &stray };
    let w = ChainWitness { statement: &st_stray, ..witness(2, &st2, w2, &p2, i2, Some(prev)) };
    let c = compile_chain(&SMALL, &emission, &setup.genesis, &setup.plan_root, &setup.base, &setup.step, &w, None);
    assert!(VmAir::execute(&c.prog, &c.inputs).is_err(), "a parent not on genesis");
    // Block 1 must be on genesis: its statement with another parent.
    let st_orphan = Statement { parent_hash: [Fp::ONE; DIGEST], ..st1.clone() };
    let w = ChainWitness { statement: &st_orphan, ..witness(1, &st1, w1, &p1, i1, None) };
    let c = compile_chain(&SMALL, &emission, &setup.genesis, &setup.plan_root, &setup.base, &setup.step, &w, None);
    assert!(VmAir::execute(&c.prog, &c.inputs).is_err(), "block 1 not on genesis");
}

/// How long the recursive dev parameters take: chain setup, then
/// blocks of one, two and five segments proven on the previous one.
#[test]
#[ignore = "timing; run with --release --nocapture"]
fn dev_block_timing() {
    let p = AggregatorParams::DEV_RECURSIVE;
    const EMISSION: &[(u32, u64)] = &[(1000, 55)];
    let v = AggregateVerifier::new(p, EMISSION, genesis_for(p.pow));
    let t = std::time::Instant::now();
    v.plan_tree();
    let _ = v.setup();
    println!("plan and chain setup: {:?}", t.elapsed());
    let utxo = TestSet::new();
    let miner = key(9).public_key();
    let mut prev: Option<(u32, Statement, Vec<u8>, Header)> = None;
    for (height, n) in [(1u32, 1usize), (2, 2), (3, 5)] {
        let (parent_hash, parent_work) = match &prev {
            Some((_, _, _, h)) => (h.hash(), Work::of_header(&test_seed(SMALL.pow), h)),
            None => (v.genesis.hash, v.genesis.work),
        };
        let amounts: Vec<u64> = (0..n as u64).map(|i| if i == 0 { 55 - (n as u64 - 1) } else { 1 }).collect();
        let txs: Vec<Transaction> = amounts.iter().map(|a| reward(&miner, *a)).collect();
        let prev_root = utxo.root();
        let first = utxo.next_position();
        let segments = utxo.collect_by_rows(&txs, 128, height).unwrap();
        let body = Body {
            inputs: vec![],
            outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
            proof: vec![],
            ..Default::default()
        };
        let statement = Statement::from_block(&BlockStatement {
            height,
            prev_state_root: prev_root,
            new_state_root: utxo.root(),
            first_output_position: first,
            subsidy: 55,
            body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
            parent_work,
            parent_hash,
        });
        let names = empty_names(&segments, height);
        let t = std::time::Instant::now();
        let proof = v
            .prove_block(
                height,
                &statement,
                &segments,
                &names,
                prev.as_ref().map(|(h, s, p, hd)| (*h, s, &p[..], hd)),
                2,
                &|p| println!("  {p:?}"),
                &|| false,
            )
            .unwrap();
        let proved = t.elapsed();
        let t = std::time::Instant::now();
        assert_eq!(v.verify_chain_proof(height, &statement, &proof), Ok(()));
        println!(
            "block {height}, {} segments: proved in {proved:?}, {} KB, verified in {:?}",
            segments.len(),
            proof.len() / 1000,
            t.elapsed()
        );
        let (header, _) = test_header(parent_hash, height, statement.new_state_root, p.pow);
        prev = Some((height, statement, proof, header));
    }
}

/// Every zero-knowledge configuration in use blinds more rows than its
/// openings can reveal of a column (`stark::tests::zero_knowledge_tables`
/// counts them on a real proof).
#[test]
#[cfg_attr(debug_assertions, ignore = "proves proofs of proofs; run with --release")]
fn zero_knowledge_configurations_blind_enough() {
    for (name, c) in [("mainnet wrap", AggregatorParams::MAINNET.wrap), ("small wrap", SMALL.wrap)] {
        assert!(c.zk, "{name}");
        assert!(4 * 2 + 2 * c.num_queries <= c.blind_rows(), "{name}");
    }
    for c in [AggregatorParams::MAINNET.segment, AggregatorParams::MAINNET.outer] {
        assert!(!c.zk, "only the published wrap proof needs zero knowledge");
    }
}

#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn deep_tree_roundtrip() {
    // Nine segments at fan-in two: a full subtree of eight and one
    // segment, with an open transaction crossing two boundaries.
    let miner = key(9).public_key();
    let mut txs: Vec<Transaction> = (0..6).map(|i| reward(&miner, 1 + i)).collect();
    let outs = [5, 6, 7].map(|a| TxOutput::new(&miner, a)).to_vec();
    txs.push(UnsignedTransaction::new(vec![], outs).sign(|_, _, _| Err::<Sig, ()>(())).unwrap());
    let s = setup_txs("deep", &txs, 21 + 18);
    assert_eq!(s.segments.len(), 9);
    let shape = plan(&SMALL, 9);
    assert_eq!(shape.children.iter().map(|c| c.segments).collect::<Vec<_>>(), vec![8, 1]);
    let t = std::time::Instant::now();
    let proof = prove_block(&SMALL, &s.statement, &s.segments, &s.names);
    println!("9 segments, 4 levels: {} bytes in {:?}", proof.len(), t.elapsed());
    let v = AggregateVerifier::new(SMALL, &[(10, 55)], genesis_for(SMALL.pow));
    assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
    let mut poor = s.statement.clone();
    poor.subsidy -= 1;
    assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
}

#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn spanning_transaction_roundtrip() {
    let s = spanning_setup("span-roundtrip");
    let proof = prove_block(&SMALL, &s.statement, &s.segments, &s.names);
    let v = AggregateVerifier::new(SMALL, &[(10, 55)], genesis_for(SMALL.pow));
    assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
}

#[test]
#[cfg_attr(debug_assertions, ignore = "proves proofs of proofs; run with --release")]
fn root_program_accepts_and_rejects() {
    let s = setup("program", &[30, 25], 55);
    // Each segment proof verifies natively.
    for sp in &s.proofs {
        let tr = &mut crate::block_proof::transcript();
        assert_eq!(stark::verify(&SMALL.segment, &BlockAir, &sp.public.to_values(), &sp.proof, tr), Ok(()));
    }
    let tr = &mut crate::block_proof::name_transcript();
    assert_eq!(
        stark::verify(&SMALL.segment, &NameAir::MAINNET, &s.name_proof.public.to_values(), &s.name_proof.proof, tr),
        Ok(())
    );
    let c = compile_node(
        &SMALL,
        &seg_children(&s.proofs),
        Output::Statement(&s.statement, &s.name_proof, &s.work_proof, None),
    );
    let exec = match VmAir::execute(&c.prog, &c.inputs) {
        Ok(e) => e,
        Err(Error::VmAssertion(i)) => panic!("root rejected at {i}: {:?}", c.prog.instrs[i]),
        Err(e) => panic!("{e:?}"),
    };
    assert_eq!(exec.output_digest, Some(s.statement.output(&SMALL.work_shape(), &root_tree_digest(&[None, None]))));
    println!(
        "root over 2 segments of 2^{}: {} instructions, {} inputs",
        SMALL.segment_log_n,
        c.prog.instrs.len(),
        c.inputs.len()
    );
    let shape = plan(&SMALL, 2);
    assert_eq!(shape.digest, c.prog.digest(SMALL.outer.log_blowup));
    assert!(shape.children.iter().all(|c| c.is_segment()));
    assert_ne!(plan(&SMALL, 1).digest, shape.digest);

    let rejects_with = |st: &Statement, proofs: &[SegmentProof], name: &NameProof| {
        let c = compile_node(&SMALL, &seg_children(proofs), Output::Statement(st, name, &s.work_proof, None));
        matches!(VmAir::execute(&c.prog, &c.inputs), Err(Error::VmAssertion(_)))
    };
    let rejects = |st: &Statement, proofs: &[SegmentProof]| rejects_with(st, proofs, &s.name_proof);
    // The name segment must continue from the segments: a different
    // height, a count beyond the cap, a different end state.
    let mut other = s.name_proof.clone();
    other.public.height = 2;
    assert!(rejects_with(&s.statement, &s.proofs, &other));
    let mut capped = s.name_proof.clone();
    capped.public.counts[0] = crate::name::MAX_COMMITS as u32 + 1;
    assert!(rejects_with(&s.statement, &s.proofs, &capped));
    let mut forged = s.name_proof.clone();
    forged.public.root_in = s.proofs[0].public.root_in;
    assert!(rejects_with(&s.statement, &s.proofs, &forged));
    // Unbalanced.
    let mut poor = s.statement.clone();
    poor.subsidy = 54;
    assert!(rejects(&poor, &s.proofs));
    let mut rich = s.statement.clone();
    rich.subsidy = 56;
    assert!(rejects(&rich, &s.proofs));
    // A balance that only holds modulo 2^16 in the low limb.
    let mut wrapped = s.statement.clone();
    wrapped.subsidy = 55 + (1 << 16);
    assert!(rejects(&wrapped, &s.proofs));
    // Broken chain: segments swapped.
    let swapped = vec![s.proofs[1].clone(), s.proofs[0].clone()];
    assert!(rejects(&s.statement, &swapped));
    // Wrong end state.
    let mut moved = s.statement.clone();
    moved.end_output_position = 3;
    assert!(rejects(&moved, &s.proofs));
    let mut other_root = s.statement.clone();
    other_root.new_state_root[0] += Fp::ONE;
    assert!(rejects(&other_root, &s.proofs));
    // A segment proof for different public values.
    let mut forged = s.proofs.clone();
    forged[1].public.sum_out[0] += 1;
    let mut richer = s.statement.clone();
    richer.subsidy = 56;
    assert!(rejects(&richer, &forged));
    // Segment proofs swapped under their public values.
    let mut cross = s.proofs.clone();
    cross[1].proof = s.proofs[0].proof.clone();
    assert!(rejects(&s.statement, &cross));
}

#[test]
#[cfg_attr(debug_assertions, ignore = "proves proofs of proofs; run with --release")]
fn inner_node_program_outputs_record() {
    let s = setup("record", &[30, 25], 55);
    let c = compile_node(&SMALL, &seg_children(&s.proofs), Output::Record);
    let exec = VmAir::execute(&c.prog, &c.inputs).expect("valid node");
    let records: Vec<SegmentPublic> = s.proofs.iter().map(|p| p.public).collect();
    assert_eq!(exec.output_digest, Some(node_output(&combine_records(&records), &tree_digest(&[None, None]))));
}

#[test]
#[ignore = "plans mainnet trees; run with --release"]
fn mainnet_plans() {
    fn show(s: &Shape) -> String {
        if s.is_segment() {
            return "s".into();
        }
        let kids: Vec<String> = s.children.iter().map(show).collect();
        format!("2^{}/2^{}[{}]", s.log_n, s.hash_log_n, kids.join(" "))
    }
    let eighth = AggregatorParams { segment: EIGHTH, ..AggregatorParams::MAINNET };
    for (name, params) in [("mainnet", AggregatorParams::MAINNET), ("segments at rate 1/8", eighth)] {
        println!("{name}:");
        for k in [1, 2, 4, 5, 8, 12, 16] {
            println!("{k:2} segments: {}", show(&plan(&params, k)));
        }
        let mut cache = PlanCache::new();
        for k in [1000, 9999, 1 << 14, 1001, 12345, 3, 77] {
            let t = std::time::Instant::now();
            let fresh = plan(&params, k);
            let alone = t.elapsed();
            let t = std::time::Instant::now();
            let s = plan_with(&params, k, &mut cache);
            assert_eq!(s.wrap, fresh.wrap);
            println!(
                "{k} segments: root 2^{}/2^{}, planned in {alone:?}, {:?} after the counts before ({} types)",
                s.log_n,
                s.hash_log_n,
                t.elapsed(),
                cache.len()
            );
        }
    }
}

#[test]
fn tree_plans() {
    assert_eq!(split(10, 4), vec![4, 4, 2]);
    assert_eq!(split(5, 4), vec![4, 1]);
    assert_eq!(split(16, 4), vec![4, 4, 4, 4]);
    assert_eq!(split(17, 4), vec![16, 1]);
    assert_eq!(split(63, 4), vec![16, 16, 16, 15]);
    assert_eq!(split(3, 2), vec![2, 1]);
    for k in 5..300 {
        let g = split(k, 4);
        assert!(g.len() >= 2 && g.len() <= 4 && g.iter().sum::<usize>() == k && g.iter().all(|&n| n < k));
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "proves proofs of proofs; run with --release")]
fn aggregator_size() {
    for (name, params) in [
        ("mainnet", AggregatorParams::MAINNET),
        ("segments at rate 1/8, 28 queries", AggregatorParams { segment: EIGHTH, ..AggregatorParams::MAINNET }),
        ("2^13 segments", AggregatorParams { segment_log_n: 13, ..AggregatorParams::MAINNET }),
    ] {
        let dummy = dummy_proof(&[(&BlockAir, params.segment_log_n)], &params.segment, SEGMENT_PUBLIC);
        let public = SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap();
        let seg = SegmentProof { public, proof: dummy };
        let zero = Statement::zero(&params.work_shape());
        let (nm, wk) = (dummy_name(&params), dummy_work(&params));
        let c = compile_node(&params, &[Child::Segment(&seg)], Output::Statement(&zero, &nm, &wk, None));
        let mut hist = std::collections::BTreeMap::new();
        for ins in &c.prog.instrs {
            let name = format!("{ins:?}");
            *hist.entry(name.split([' ', '{']).next().unwrap().to_string()).or_insert(0usize) += 1;
        }
        println!("  {hist:?}");
        let rows = c.prog.num_rows();
        println!(
            "{name}: one segment = {} instructions, {} inputs, {} machine rows (2^{}), segment proof {} bytes",
            c.prog.instrs.len(),
            c.inputs.len(),
            rows,
            rows.next_power_of_two().trailing_zeros(),
            seg.proof.to_bytes().len()
        );
    }
    // A node verifying one node proof of the mainnet root's height, with
    // the outer proofs at rate 1/4 and at rate 1/8.
    for (name, outer) in [("rate 1/4, 42 queries", AggregatorParams::MAINNET.outer), ("rate 1/8, 28 queries", EIGHTH)] {
        let params = AggregatorParams { outer, ..AggregatorParams::MAINNET };
        let seg = SegmentProof {
            public: SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap(),
            proof: dummy_proof(&[(&BlockAir, params.segment_log_n)], &params.segment, SEGMENT_PUBLIC),
        };
        let zero = Statement::zero(&params.work_shape());
        let (nm, wk) = (dummy_name(&params), dummy_work(&params));
        let leaf = compile_node(&params, &[Child::Segment(&seg)], Output::Statement(&zero, &nm, &wk, None)).prog;
        let np = NodeProof {
            record: seg.public,
            digest: [Fp::ZERO; DIGEST],
            tree: [Fp::ZERO; DIGEST],
            proof: dummy_proof(
                &[
                    (&VmAir, leaf.height().trailing_zeros() as usize),
                    (&HashTableAir, VmAir::hash_height(&leaf).trailing_zeros() as usize),
                ],
                &params.outer,
                VM_PUBLIC,
            ),
        };
        let c = compile_node(&params, &[Child::Node(&np)], Output::Record);
        println!(
            "mainnet node child, {name}: 2^{} rows = {} instructions, {} inputs, node proof {} bytes",
            leaf.height().trailing_zeros(),
            c.prog.instrs.len(),
            c.inputs.len(),
            np.proof.to_bytes().len()
        );
    }
}

/// A block with a spend: its root takes the top of the signature
/// tree, whose one segment says the spend's entry, and the block's
/// proof verifies as a block with signatures and as nothing else.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_spend_rests_on_the_signature_tree() {
    let utxo = TestSet::new();
    let miner = key(9).public_key();
    let mut owner = Key::generate_with_height(&[7; 32], 2);
    utxo.add_output(&TxOutput::new(&owner.public_key(), 70).block_output(), 0).unwrap();
    let mut spend = UnsignedTransaction::new(vec![(owner.public_key(), 70)], vec![TxOutput::new(&miner, 70)])
        .sign(|_, _, m| owner.sign(m))
        .unwrap();
    spend.set_positions(&[0]);
    let entry = crate::sig_air::entry(&owner.public_key(), &spend.txid(), spend.inputs[0].signature.index);
    // (Alone in its block: two segments, as many as a root is over.)
    let txs = [spend];
    let (prev_root, first) = (utxo.root(), utxo.next_position());
    let segments = utxo.collect_by_rows(&txs, SMALL.segment_rows(), 1).unwrap();
    let new_root = utxo.root();
    assert!(has_signatures(&segments));
    let signed = segments[0].signed.clone();
    assert_eq!((signed.segments.len(), signed.set.find(&entry)), (1, Some(0)));
    let body = Body {
        inputs: segments.iter().flat_map(|s| s.positions()).collect(),
        outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
        proof: vec![],
        ..Default::default()
    };
    let statement = Statement::from_block(&BlockStatement {
        height: 1,
        prev_state_root: prev_root,
        new_state_root: new_root,
        first_output_position: first,
        subsidy: 0,
        body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
        parent_work: test_work(SMALL.pow),
        parent_hash: test_genesis_header().hash(),
    });
    let names = empty_names(&segments, 1);
    let mut cache = PlanCache::new();
    let shape = plan_for(&SMALL, &segments, &mut cache);
    let plan = shape.sig.expect("a block with signatures has a root that takes their tree");
    let bare = plan_with(&SMALL, segments.len(), &mut cache);
    assert!(bare.sig.is_none());
    assert_ne!((shape.digest, shape.wrap.unwrap().digest), (bare.digest, bare.wrap.unwrap().digest));
    // The tree's programs: one a level, each of its own, of one shape.
    for (i, d) in plan.digests.iter().enumerate() {
        assert!(plan.digests[..i].iter().all(|other| other != d), "level {}", i + 1);
    }
    let steps = Mutex::new(Vec::new());
    let proof = prove_block_with(&SMALL, &shape, &statement, &segments, &names, 2, &|p| {
        steps.lock().unwrap().push(format!("{p:?}"))
    });
    let steps = steps.into_inner().unwrap();
    assert_eq!(steps.iter().filter(|s| s.starts_with("Signatures")).count(), 1, "{steps:?}");
    assert_eq!(steps.iter().filter(|s| s.starts_with("SignatureNode")).count(), 1, "{steps:?}");
    let wraps = |_: usize, signed: bool| if signed { shape.wrap.unwrap() } else { bare.wrap.unwrap() };
    assert_eq!(verify_block(&SMALL, &wraps, &statement, &proof), Ok(()));
    // Said to be a block without signatures, it is checked against the
    // other root's wrap, and is not that.
    let mut unsigned = proof.clone();
    unsigned[3] &= 0x7f;
    assert_eq!(verify_block(&SMALL, &wraps, &statement, &unsigned), Err(AggregateError::Rejected));
    // The top of the tree is what the set's root is, and no other
    // tree's top serves: of the same segment twice, say.
    let sig = crate::block_proof::prove_signatures(
        &SMALL.segment,
        &signed.segments[0],
        Some(crate::signed::SEGMENT_LOG_ROWS),
    );
    let nothing = crate::block_proof::prove_signatures(&SMALL.segment, &[], Some(crate::signed::SEGMENT_LOG_ROWS));
    let node = |children: [&crate::block_proof::SigProof; 4]| {
        prove_sig_node(&SMALL, &plan, 1, &SigChildren::Segments(children), &|| false).unwrap()
    };
    let top = node([&sig, &nothing, &nothing, &nothing]);
    assert_eq!(top.top, signed.set.root());
    assert_eq!(
        top.root,
        crate::signed::node_root(&[
            crate::signed::segment_root(&sig.entries),
            crate::signed::segment_root(&nothing.entries),
            crate::signed::segment_root(&nothing.entries),
            crate::signed::segment_root(&nothing.entries),
        ])
    );
    let twice = node([&sig, &sig, &nothing, &nothing]);
    assert_ne!(twice.top, top.top);
    // The root's program, given the other top: the segments were proven
    // against another set, and the program does not run.
    let proofs: Vec<SegmentProof> =
        segments.iter().map(|w| prove_segment_padded(&SMALL.segment, w, SMALL.segment_log_n)).collect();
    let name_proof = prove_name_padded(&SMALL.segment, &names, SMALL.name_log_n);
    let work_proof = small_work_proof();
    assert!(proofs.len() <= SMALL.fan_in, "the root is over the segments themselves");
    let runs = |top: &SigNodeProof, plan: &SigPlan| {
        let output = Output::Statement(&statement, &name_proof, &work_proof, Some((top, plan)));
        let c = compile_node(&SMALL, &seg_children(&proofs), output);
        VmAir::generate_trace(&c.prog, &c.inputs).is_ok()
    };
    assert!(runs(&top, &plan));
    assert!(!runs(&twice, &plan));
    // Nor a top of a program that is none of the tree's.
    let mut other = plan;
    other.digests[0][0] += Fp::ONE;
    assert!(!runs(&top, &other));
}

/// More signature segments than one node holds: a second level over
/// two nodes of the first and two of nothing, whose top is the root of
/// the set of all the segments.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_signature_tree_of_two_levels() {
    let mut owner = Key::generate_with_height(&[8; 32], 3);
    // Five segments, of a signature each: as a miner might have them
    // that proved each transaction's as it came.
    let segments: Vec<Vec<crate::signed::Signing>> = (0..5u32)
        .map(|i| {
            let message: Digest = core::array::from_fn(|k| Fp::new(1000 * i + k as u32));
            vec![(owner.public_key(), message, owner.sign(&message).unwrap())]
        })
        .collect();
    let entries: Vec<_> = segments.iter().map(|s| Signed::entries(s)).collect();
    let signed = Signed { set: crate::signed::SignedSet::new(&entries), segments };
    let plan = sig_plan(&SMALL, &mut PlanCache::new());
    let steps = Mutex::new(Vec::new());
    let top =
        prove_sig_tree(&SMALL, &plan, &signed, &|p| steps.lock().unwrap().push(format!("{p:?}")), &|| false).unwrap();
    let steps = steps.into_inner().unwrap();
    assert_eq!(steps.iter().filter(|s| s.starts_with("Signatures")).count(), 5, "{steps:?}");
    assert_eq!(steps.iter().filter(|s| s.starts_with("SignatureNode { level: 1")).count(), 2, "{steps:?}");
    assert_eq!(steps.iter().filter(|s| s.starts_with("SignatureNode { level: 2")).count(), 1, "{steps:?}");
    assert_eq!(top.digest, plan.digests[1]);
    assert_eq!(top.top, signed.set.root());
    // Every entry's path ends at what the tree's top says.
    for (s, group) in signed.segments.iter().enumerate() {
        let (pk, message, sig) = &group[0];
        let entry = crate::sig_air::entry(pk, message, sig.index);
        assert_eq!(signed.set.path((s * crate::sig_air::SLOTS) as u32).root(&entry), top.top);
    }
    // The proof is of the second level's program, with that output.
    let public = VmAir::public_values(&top.digest, &sig_output(&top.root, &top.top));
    let specs = VmAir::specs(&top.digest);
    assert!(stark::verify_tables(&SMALL.outer, &specs, &public, &top.proof, &mut outer_transcript()).is_ok());
    let other = VmAir::public_values(&top.digest, &sig_output(&top.root, &top.root));
    assert!(stark::verify_tables(&SMALL.outer, &specs, &other, &top.proof, &mut outer_transcript()).is_err());
}

#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn aggregate_proof_roundtrip() {
    let s = setup("roundtrip", &[30, 25], 55);
    let t = std::time::Instant::now();
    let proof = prove_block(&SMALL, &s.statement, &s.segments, &s.names);
    println!("aggregate of 2 segments: {} bytes in {:?}", proof.len(), t.elapsed());
    let v = AggregateVerifier::new(SMALL, &[(10, 55)], genesis_for(SMALL.pow));
    let t = std::time::Instant::now();
    assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
    println!("verify: {:?}", t.elapsed());
    let mut poor = s.statement.clone();
    poor.subsidy = 54;
    assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
    let mut bad = proof.clone();
    bad[0] = 3;
    assert_eq!(v.verify_statement(&s.statement, &bad), Err(AggregateError::Rejected));
    bad[0] = 0;
    assert_eq!(v.verify_statement(&s.statement, &bad), Err(AggregateError::BadSegmentCount(0)));
    assert_eq!(v.verify_statement(&s.statement, &proof[..100]), Err(AggregateError::Malformed));
}

#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn aggregate_tree_roundtrip() {
    // Three segments with fan-in two: leaves of 2 and 1 segments, then
    // the root verifies one node proof and one segment proof.
    let s = setup("tree", &[30, 25, 10], 65);
    let shape = plan(&SMALL, 3);
    assert_eq!(shape.children.len(), 2);
    assert_eq!(shape.children[0].segments, 2);
    assert!(!shape.children[0].is_segment());
    assert!(shape.children[1].is_segment());
    let t = std::time::Instant::now();
    let proof = prove_block(&SMALL, &s.statement, &s.segments, &s.names);
    println!("tree aggregate of 3 segments: {} bytes in {:?}", proof.len(), t.elapsed());
    let v = AggregateVerifier::new(SMALL, &[(10, 55)], genesis_for(SMALL.pow));
    assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
    let mut poor = s.statement.clone();
    poor.subsidy = 64;
    assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
}

#[test]
#[ignore = "proves a mainnet segment and a node over it; run with --release"]
fn mainnet_node_timing() {
    let s = setup("node-timing", &[30], 30);
    let params = AggregatorParams::MAINNET;
    let seg = prove_segment_padded(&params.segment, &s.segments[0], params.segment_log_n);
    let c = compile_node(&params, &[Child::Segment(&seg)], Output::Record);
    let out = node_output(&combine_records(&[seg.public]), &tree_digest(&[None]));
    for _ in 0..2 {
        let t = std::time::Instant::now();
        let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
        let pre = c.prog.preprocess(&params.outer);
        eprintln!("  trace + program: {:?}", t.elapsed());
        let public = VmAir::public_values(&pre.root(), &out);
        let tables = VmAir::tables(&trace, &hashes, &pre);
        let proof = stark::prove_tables(&params.outer, &tables, &public, &mut outer_transcript());
        println!(
            "node 2^{} + 2^{} hashes: {:?}, {} bytes",
            trace.height().trailing_zeros(),
            hashes.height().trailing_zeros(),
            t.elapsed(),
            proof.to_bytes().len()
        );
    }
}

/// Mainnet-sized output-only block of `segments` full segments under
/// `params`: the witnesses and the statement.
fn full_segments(
    _name: &str,
    params: &AggregatorParams,
    segments: usize,
) -> (Vec<SegmentWitness>, Statement, NameWitness) {
    let miner = key(9).public_key();
    let per = rewards_per_segment(&params);
    let txs: Vec<Transaction> = (0..segments * per).map(|i| reward(&miner, 1 + i as u64)).collect();
    let subsidy: u64 = (1..=txs.len() as u64).sum();
    let utxo = TestSet::new();
    let prev_root = utxo.root();
    let w = utxo.collect_by_rows(&txs, params.segment_rows(), 1).unwrap();
    let new_root = utxo.root();
    assert_eq!(w.len(), segments);
    let body = Body {
        inputs: vec![],
        outputs: w.iter().flat_map(|s| s.block_outputs()).collect(),
        proof: vec![],
        ..Default::default()
    };
    let statement = Statement::from_block(&BlockStatement {
        height: 1,
        prev_state_root: prev_root,
        new_state_root: new_root,
        first_output_position: 0,
        subsidy,
        body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
        parent_work: test_work(params.pow),
        parent_hash: test_genesis_header().hash(),
    });
    let names = NameWitness {
        min_reveal: crate::name::MIN_REVEAL,
        root_in: new_root,
        pos_in: statement.end_output_position,
        height: 1,
        ops: vec![],
        signed: Default::default(),
    };
    (w, statement, names)
}

/// As many reward transactions as a segment is packed with: each its
/// rows, and room kept for putting the segment's outputs in the tree.
fn rewards_per_segment(params: &AggregatorParams) -> usize {
    let each = crate::block_air::tx_rows(&reward(&key(9).public_key(), 1));
    let fits = |n: usize| n * each + crate::block_air::flush_rows_bound(n) < params.segment_rows();
    (1..).take_while(|n| fits(*n)).last().expect("a segment holds a reward")
}

/// A block of `n` transactions that each spend two outputs and make
/// two, and a reward: for measuring what a block with signatures costs.
fn spending_block(params: &AggregatorParams, n: usize) -> (Vec<SegmentWitness>, Statement, NameWitness) {
    let utxo = TestSet::new();
    let miner = key(9).public_key();
    // Keys of 32 leaves: each signs for sixteen transactions.
    let mut keys: Vec<Key> = (0..n.div_ceil(16)).map(|i| Key::generate_with_height(&[i as u8 + 1; 32], 5)).collect();
    for i in 0..2 * n {
        let owner = keys[i / 32].public_key();
        utxo.add_output(&TxOutput::new(&owner, 10).block_output(), 0).unwrap();
    }
    let mut txs: Vec<Transaction> = (0..n)
        .map(|t| {
            let k = &mut keys[t / 16];
            let pk = k.public_key();
            let outs = vec![TxOutput::new(&miner, 12), TxOutput::new(&miner, 8)];
            let mut tx = UnsignedTransaction::new(vec![(pk, 10), (pk, 10)], outs).sign(|_, _, m| k.sign(m)).unwrap();
            tx.set_positions(&[2 * t as u64, 2 * t as u64 + 1]);
            tx
        })
        .collect();
    txs.push(reward(&miner, 50));
    let (prev_root, first) = (utxo.root(), utxo.next_position());
    let segments = utxo.collect_by_rows(&txs, params.segment_rows(), 1).unwrap();
    let new_root = utxo.root();
    let body = Body {
        inputs: segments.iter().flat_map(|s| s.positions()).collect(),
        outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
        proof: vec![],
        ..Default::default()
    };
    let statement = Statement::from_block(&BlockStatement {
        height: 1,
        prev_state_root: prev_root,
        new_state_root: new_root,
        first_output_position: first,
        subsidy: 50,
        body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
        parent_work: test_work(params.pow),
        parent_hash: test_genesis_header().hash(),
    });
    let names = NameWitness {
        min_reveal: crate::name::MIN_REVEAL,
        root_in: new_root,
        pos_in: statement.end_output_position,
        height: 1,
        ops: vec![],
        signed: segments[0].signed.clone(),
    };
    (segments, statement, names)
}

/// The plans built into the binary are mainnet's and the recursive dev
/// network's: their roots are their constants', so a miner starts
/// without planning.
#[test]
fn plans_are_built_in() {
    let mut built = vec![(AggregatorParams::MAINNET, MAINNET_CHAIN, "mainnet_chain_constants")];
    if cfg!(feature = "dev") {
        built.push((AggregatorParams::DEV_RECURSIVE, DEV_RECURSIVE_CHAIN, "dev_recursive_chain_constants"));
    }
    for (params, c, name) in built {
        let c = c.unwrap_or_else(|| panic!("no constants: run {name}"));
        let v = AggregateVerifier::new(params, crate::chain::params::MAINNET_EMISSION, network_genesis(params));
        assert!(v.plan_is_built_in(), "the built-in plan is stale: run {name}");
        assert_eq!(v.plan_tree().root(), c.setup(v.genesis).plan_root);
        assert_eq!(v.plan_tree().height(), c.plan_depth);
    }
}

/// Computes the chain-proof constants and plan leaves of `params` (with
/// mainnet's emission) and checks the source has them; prints the
/// constants and rewrites the leaves' file when it does not.
fn check_chain_constants(
    params: AggregatorParams,
    name: &str,
    built: Option<ChainSetupConst>,
    plan: &[u8],
    file: &str,
) {
    let mut cache = PlanCache::new();
    let tree = crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&params, &mut cache));
    let s = chain_setup(
        &params,
        crate::chain::params::MAINNET_EMISSION,
        &network_genesis(params),
        &tree.root(),
        tree.height(),
        &mut cache,
    );
    let u = |d: &Digest| d.map(|x| x.to_canonical());
    let c = ChainSetupConst {
        plan_root: u(&s.plan_root),
        plan_depth: s.plan_depth,
        base: u(&s.base),
        step: u(&s.step),
        log_n: s.log_n,
        hash_log_n: s.hash_log_n,
    };
    // The plan leaves built into the binary: rewritten when they differ.
    let mut bytes = Vec::with_capacity(32 * tree.len());
    for i in 0..tree.len() {
        bytes.extend_from_slice(&crate::poseidon2::digest_to_bytes(&tree.leaf(i)));
    }
    if bytes != plan {
        let path = format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"));
        std::fs::write(&path, &bytes).unwrap();
        println!("wrote {path}: rebuild");
    }
    println!("pub const {name}: Option<ChainSetupConst> = Some({c:?});");
    assert_eq!(built, Some(c), "update {name} to the line printed above");
    assert!(bytes == plan, "src/{file} was rewritten; rebuild");
}

/// Mainnet's chain-proof constants ([`MAINNET_CHAIN`]) and plan leaves
/// ([`MAINNET_PLAN`]).
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn mainnet_chain_constants() {
    check_chain_constants(AggregatorParams::MAINNET, "MAINNET_CHAIN", MAINNET_CHAIN, MAINNET_PLAN, "mainnet_plan.bin");
}

/// The recursive dev network's ([`DEV_RECURSIVE_CHAIN`],
/// [`DEV_RECURSIVE_PLAN`]).
#[test]
#[cfg(feature = "dev")]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn dev_recursive_chain_constants() {
    check_chain_constants(
        AggregatorParams::DEV_RECURSIVE,
        "DEV_RECURSIVE_CHAIN",
        DEV_RECURSIVE_CHAIN,
        DEV_RECURSIVE_PLAN,
        "dev_recursive_plan.bin",
    );
}

/// Chain proofs at mainnet parameters (with the plan cut to 16 segment
/// counts, which only shortens a Merkle path): two one-segment blocks,
/// their wraps, the base proof and a step.
#[test]
#[ignore = "proves mainnet blocks and chain proofs; run with --release"]
fn mainnet_chain_timing() {
    let params = AggregatorParams { max_segments: 16, ..AggregatorParams::MAINNET };
    let miner = key(9).public_key();
    let per = rewards_per_segment(&params);
    let utxo = TestSet::new();
    let subsidy: u64 = (1..=per as u64).sum();
    let block = |height: u32, parent: (Digest, Work)| {
        let txs: Vec<Transaction> = (0..per).map(|i| reward(&miner, 1 + i as u64)).collect();
        let prev_root = utxo.root();
        let first = utxo.next_position();
        let w = utxo.collect_by_rows(&txs, params.segment_rows(), height).unwrap();
        let body = Body {
            inputs: vec![],
            outputs: w.iter().flat_map(|s| s.block_outputs()).collect(),
            proof: vec![],
            ..Default::default()
        };
        let st = Statement::from_block(&BlockStatement {
            height,
            prev_state_root: prev_root,
            new_state_root: utxo.root(),
            first_output_position: first,
            subsidy,
            body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
            parent_work: parent.1,
            parent_hash: parent.0,
        });
        let nm = NameWitness {
            min_reveal: crate::name::MIN_REVEAL,
            root_in: st.new_state_root,
            pos_in: st.end_output_position,
            height,
            ops: vec![],
            signed: Default::default(),
        };
        (w, st, nm)
    };
    let genesis = genesis_for(params.pow);
    let (seg1, st1, nm1) = block(1, (genesis.hash, genesis.work));
    let (h1, work1) = test_header(genesis.hash, 1, st1.new_state_root, params.pow);
    let (seg2, st2, nm2) = block(2, (h1.hash(), work1));
    let mut cache = PlanCache::new();
    let t = std::time::Instant::now();
    let tree = crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&params, &mut cache));
    let emission = [(10u32, subsidy)];
    let setup = chain_setup(&params, &emission, &genesis_for(params.pow), &tree.root(), tree.height(), &mut cache);
    println!("plan and chain setup in {:?}: chain proofs 2^{} + 2^{} rows", t.elapsed(), setup.log_n, setup.hash_log_n);
    let wrap_of = |segs: &[SegmentWitness], st: &Statement, nm: &NameWitness, cache: &mut PlanCache| {
        let shape = plan_with(&params, segs.len(), cache);
        let t = std::time::Instant::now();
        let proof = prove_wrap(&params, &shape, st, segs, nm, 2, &|_| {}, &|| false).unwrap();
        println!("block proven to its wrap in {:?}", t.elapsed());
        (shape.wrap.unwrap(), proof)
    };
    let (w1, p1) = wrap_of(&seg1, &st1, &nm1, &mut cache);
    let (w2, p2) = wrap_of(&seg2, &st2, &nm2, &mut cache);
    let t = std::time::Instant::now();
    let base = ChainWitness {
        height: 1,
        statement: &st1,
        wrap: w1,
        wrap_proof: &p1,
        path: tree.open(0),
        index: 0,
        prev: None,
    };
    let c1 = prove_chain(&params, &emission, &setup, &base, &|| false).unwrap();
    println!("base chain proof in {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let step = ChainWitness {
        height: 2,
        statement: &st2,
        wrap: w2,
        wrap_proof: &p2,
        path: tree.open(0),
        index: 0,
        prev: Some(PrevChain { height: 1, statement: &st1, proof: &c1, header: &h1 }),
    };
    let c2 = prove_chain(&params, &emission, &setup, &step, &|| false).unwrap();
    println!("step chain proof in {:?}, {} bytes", t.elapsed(), c2.to_bytes().len());
    let t = std::time::Instant::now();
    assert_eq!(verify_chain(&params, &setup, 2, &st2, &c2), Ok(()));
    println!("verified in {:?}; wrap proof was {} bytes", t.elapsed(), p2.to_bytes().len());
}

/// Writes a real mainnet chain proof for the fam node's verifier
/// (`chainproof.bin`, under `target/fam`): block 2's, under mainnet's
/// built-in setup, as its 16 public values (little-endian words) and
/// then its bytes.
#[test]
#[ignore = "proves two mainnet blocks; run with --release"]
fn write_fam_chain_proof() {
    use crate::chain::params::{ChainParams, MAINNET_EMISSION};
    let params = AggregatorParams::MAINNET;
    let genesis = network_genesis(params);
    let verifier = AggregateVerifier::new(params, MAINNET_EMISSION, genesis);
    let setup = *verifier.setup();
    let tree = verifier.plan_tree();
    let miner = key(9).public_key();
    let utxo = TestSet::new();
    let block = |height: u32, parent: (Digest, Work)| {
        let subsidy = ChainParams::MAINNET.subsidy(height);
        let txs = vec![reward(&miner, subsidy)];
        let prev_root = utxo.root();
        let first = utxo.next_position();
        let w = utxo.collect_by_rows(&txs, params.segment_rows(), height).unwrap();
        let body = Body {
            inputs: vec![],
            outputs: w.iter().flat_map(|s| s.block_outputs()).collect(),
            proof: vec![],
            ..Default::default()
        };
        let st = Statement::from_block(&BlockStatement {
            height,
            prev_state_root: prev_root,
            new_state_root: utxo.root(),
            first_output_position: first,
            subsidy,
            body: BodyRef::from_bytes(&body.to_bytes()).unwrap(),
            parent_work: parent.1,
            parent_hash: parent.0,
        });
        let nm = NameWitness {
            min_reveal: crate::name::MIN_REVEAL,
            root_in: st.new_state_root,
            pos_in: st.end_output_position,
            height,
            ops: vec![],
            signed: Default::default(),
        };
        (w, st, nm)
    };
    let (seg1, st1, nm1) = block(1, (genesis.hash, genesis.work));
    let (h1, work1) = test_header(genesis.hash, 1, st1.new_state_root, params.pow);
    let (seg2, st2, nm2) = block(2, (h1.hash(), work1));
    let mut cache = PlanCache::new();
    let wrap_of = |segs: &[SegmentWitness], st: &Statement, nm: &NameWitness, cache: &mut PlanCache| {
        let shape = plan_with(&params, segs.len(), cache);
        let proof = prove_wrap(&params, &shape, st, segs, nm, 2, &|_| {}, &|| false).unwrap();
        (shape.wrap.unwrap(), proof)
    };
    let (w1, p1) = wrap_of(&seg1, &st1, &nm1, &mut cache);
    let (w2, p2) = wrap_of(&seg2, &st2, &nm2, &mut cache);
    let emission = MAINNET_EMISSION;
    let base = ChainWitness {
        height: 1,
        statement: &st1,
        wrap: w1,
        wrap_proof: &p1,
        path: tree.open(0),
        index: 0,
        prev: None,
    };
    let c1 = prove_chain(&params, emission, &setup, &base, &|| false).unwrap();
    let prev = Some(PrevChain { height: 1, statement: &st1, proof: &c1, header: &h1 });
    let step =
        ChainWitness { height: 2, statement: &st2, wrap: w2, wrap_proof: &p2, path: tree.open(0), index: 0, prev };
    let c2 = prove_chain(&params, emission, &setup, &step, &|| false).unwrap();
    assert_eq!(verify_chain(&params, &setup, 1, &st1, &c1), Ok(()));
    assert_eq!(verify_chain(&params, &setup, 2, &st2, &c2), Ok(()));
    let bytes = c2.to_bytes();
    assert_eq!(verifier.verify_chain_proof(2, &st2, &bytes), Ok(()));
    let public =
        VmAir::public_values(&setup.step, &chain_output(&SMALL.work_shape(), 2, &st2, &setup.step, &setup.plan_root));
    let mut out: Vec<u8> = public.iter().flat_map(|x| x.to_canonical().to_le_bytes()).collect();
    out.extend_from_slice(&bytes);
    // The fam node is kept elsewhere: the file is left under target/fam
    // (or TABMINER_FAM_DIR) for it to take.
    let dir = std::env::var("TABMINER_FAM_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/fam"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("chainproof.bin");
    std::fs::write(&path, &out).unwrap();
    println!("wrote {} bytes: a proof of {} bytes", out.len(), bytes.len());
}

/// The main network's parameters: table heights over the segment
/// counts, and blocks of one and sixteen full segments proven and
/// verified, with the time, the memory and the proof's size. What it
/// measures can be asked for otherwise ([`security_blocks`]).
#[test]
#[ignore = "proves mainnet blocks; run with --release"]
fn security_configs() {
    security_blocks("mainnet", &[1, 16]);
}

/// The same under the candidate with about twice the queries.
#[test]
#[ignore = "proves mainnet blocks with twice the queries; run with --release"]
fn security_configs_with_twice_the_queries() {
    security_blocks("proven", &[1, 16]);
}

/// The same under what the parameters were, for comparison.
#[test]
#[ignore = "proves mainnet blocks under earlier parameter sets; run with --release"]
fn security_configs_of_before() {
    security_blocks("plain,112,old", &[1, 16]);
}

/// Blocks of full segments proven and verified under the parameter
/// sets `names`, of `sizes` segments each. Set from outside: `SEC` for
/// other sets by name, `BLOCKS=<k>` for one size, `SEGLOG=<n>` for
/// segments of `2^n` rows, `SPENDS=<n>` for a block of `n` transactions
/// with signatures in place of the blocks of rewards, `STAGES=1` for
/// the memory held at each stage.
fn security_blocks(names: &str, sizes: &[usize]) {
    let m = AggregatorParams::MAINNET;
    let cfg = |q: usize, pow: usize| StarkConfig { num_queries: q, pow_bits: pow, commit_bits: 0, ..m.segment };
    let wrap = |q: usize, pow: usize| StarkConfig { num_queries: q, pow_bits: pow, commit_bits: 0, ..m.wrap };
    let all = [
        ("mainnet", m),
        // Mainnet without the commit-phase grinding: its cost by difference.
        ("plain", AggregatorParams { segment: cfg(54, 16), outer: cfg(54, 16), wrap: wrap(22, 16), ..m }),
        ("112", AggregatorParams { segment: cfg(50, 16), outer: cfg(50, 16), wrap: wrap(20, 16), ..m }),
        ("old", AggregatorParams { segment: cfg(42, 16), outer: cfg(42, 16), wrap: wrap(16, 20), ..m }),
        // What 120 bits proven would take in queries (in the Johnson
        // regime a query is worth half of what it is conjectured to
        // be), all else as mainnet: about twice as many.
        (
            "proven",
            AggregatorParams {
                segment: StarkConfig { num_queries: 113, ..m.segment },
                outer: StarkConfig { num_queries: 113, ..m.outer },
                wrap: StarkConfig { num_queries: 45, ..m.wrap },
                ..m
            },
        ),
    ];
    let pick = std::env::var("SEC").unwrap_or_else(|_| names.to_string());
    for (name, params) in all {
        if !pick.split(',').any(|x| x == name) {
            continue;
        }
        // (`SEGLOG=<n>` for segments of `2^n` rows in place of the network's.)
        let params = match std::env::var("SEGLOG").ok().and_then(|n| n.parse().ok()) {
            Some(segment_log_n) => AggregatorParams { segment_log_n, ..params },
            None => params,
        };
        println!("  segments of 2^{} rows", params.segment_log_n);
        let bits = |c: &StarkConfig| c.num_queries * c.log_blowup + c.pow_bits;
        println!(
            "== {name}: segments/nodes {}+{} ({} bits), wrap {}x{}+{} ({} bits)",
            params.outer.num_queries,
            params.outer.pow_bits,
            bits(&params.outer),
            params.wrap.num_queries,
            params.wrap.log_blowup,
            params.wrap.pow_bits,
            bits(&params.wrap)
        );
        let mut cache = PlanCache::new();
        for k in [1, 16, 64, 1 << 14] {
            let s = plan_with(&params, k, &mut cache);
            let w = s.wrap.unwrap();
            println!("  {k} segments: root 2^{}/2^{}, wrap 2^{}/2^{}", s.log_n, s.hash_log_n, w.log_n, w.hash_log_n);
        }
        let sizes: Vec<usize> = match std::env::var("BLOCKS").ok().and_then(|b| b.parse().ok()) {
            Some(k) => vec![k],
            None => sizes.to_vec(),
        };
        for k in sizes {
            // (`SPENDS=<n>` for a block of `n` transactions of two inputs
            // and two outputs each, in place of the blocks of rewards.)
            let spends: Option<usize> = std::env::var("SPENDS").ok().and_then(|n| n.parse().ok());
            let (segments, statement, names) = match spends {
                Some(n) => spending_block(&params, n),
                None => full_segments(name, &params, k),
            };
            let k = segments.len();
            let shape = plan_for(&params, &segments, &mut cache);
            if spends.is_some() {
                let signed = &segments[0].signed;
                let signatures: usize = signed.segments.iter().map(Vec::len).sum();
                println!(
                    "  {} transactions: {k} segments, {signatures} signatures in {} signature segments",
                    spends.unwrap_or(0),
                    signed.segments.len()
                );
            }
            // The most memory the process holds at once, from here.
            let _ = std::fs::write("/proc/self/clear_refs", "5");
            let t = std::time::Instant::now();
            let times = Mutex::new(Vec::new());
            let proof = prove_block_with(&params, &shape, &statement, &segments, &names, 2, &|p| {
                // The most memory held since the stage before this one
                // was done: which stage it is that takes the most.
                if std::env::var_os("STAGES").is_some() {
                    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                    let peak = status.lines().find(|l| l.starts_with("VmHWM:")).map(str::to_string).unwrap_or_default();
                    let now = status.lines().find(|l| l.starts_with("VmRSS:")).map(str::to_string).unwrap_or_default();
                    let mb =
                        |l: &str| l.split_whitespace().nth(1).and_then(|n| n.parse::<u64>().ok()).unwrap_or(0) / 1024;
                    println!("    up to {p:?}: most {} MB, held after {} MB", mb(&peak), mb(&now));
                    let _ = std::fs::write("/proc/self/clear_refs", "5");
                }
                times.lock().unwrap().push(format!("{p:?}"));
            });
            let elapsed = t.elapsed();
            let peak = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| {
                let line = s.lines().find(|l| l.starts_with("VmHWM:"))?.to_string();
                line.split_whitespace().nth(1)?.parse::<u64>().ok()
            });
            println!("  block of {k}: most memory while proving {} MB", peak.map_or(0, |kb| kb / 1024));
            let wrap_line = times.lock().unwrap().iter().rev().find(|l| l.starts_with("Wrap")).cloned();
            let t = std::time::Instant::now();
            let w = shape.wrap.unwrap();
            let ok = verify_block(&params, &|_, _| w, &statement, &proof);
            if spends.is_some() {
                println!("  block of {k}: proven in {elapsed:.1?}, {} bytes, verified {ok:?}", proof.len());
                break;
            }
            println!(
                "  block of {k}: proven in {elapsed:.1?}, {} bytes, verified {:?} in {:.1?}; {}",
                proof.len(),
                ok,
                t.elapsed(),
                wrap_line.unwrap_or_default()
            );
        }
    }
}

/// The numbers the soundness analysis needs, per table of each proof.
#[test]
#[ignore = "prints the parameters of the soundness analysis"]
fn soundness_parameters() {
    use crate::block_air::{BlockAir, NUM_PUBLIC as BLOCK_PUBLIC};
    use crate::stark::{DynAir, evaluate, shape};
    fn table(name: &str, air: &dyn DynAir, num_public: usize) {
        let public = vec![Fp::ZERO; num_public];
        let (constraints, terms) = shape(air, &public);
        let zeros = vec![Fp::ZERO; air.air_width()];
        let pre = vec![Fp::ZERO; air.air_preprocessed_width()];
        let (_, t) = evaluate(air, &zeros, &zeros, (&pre, &pre), &public, (Fp::ZERO, Fp::ZERO, Fp::ZERO));
        let max_len = t.iter().map(|t| t.values.len()).max().unwrap_or(0);
        let lens: usize = t.iter().map(|t| t.values.len()).sum();
        println!(
            "{name}: width {} pre {} degree {} constraints {constraints} terms {terms} (tuple lengths sum {lens}, max {max_len}) group {}",
            air.air_width(),
            air.air_preprocessed_width(),
            air.air_degree(),
            air.air_lookup_group()
        );
    }
    table("segment BlockAir", &BlockAir, BLOCK_PUBLIC);
    table("name segment NameAir", &NameAir::MAINNET, NAME_PUBLIC);
    table("signature segment SigAir", &SigAir, SIG_PUBLIC);
    table("machine VmAir", &VmAir, crate::vm_air::NUM_PUBLIC);
    table("hash HashTableAir", &crate::hash_table::HashTableAir, crate::vm_air::NUM_PUBLIC);
    let m = AggregatorParams::MAINNET;
    let mut cache = PlanCache::new();
    for k in [1, 4, 16, 64, 1 << 14] {
        for signed in [false, true] {
            let s = plan_signed(&m, k, signed, &mut cache);
            let w = s.wrap.unwrap();
            let inner = s.children.iter().filter(|c| !c.is_segment()).map(|c| (c.log_n, c.hash_log_n)).max();
            println!(
                "{k} segments, signatures {signed}: root 2^{}/2^{}, wrap 2^{}/2^{}, tallest node under the root {inner:?}",
                s.log_n, s.hash_log_n, w.log_n, w.hash_log_n
            );
        }
    }
    let sig = sig_plan(&m, &mut cache);
    println!("signature nodes: 2^{}/2^{}; signature segments 2^{SEGMENT_LOG_ROWS}", sig.log_n, sig.hash_log_n);
    let chain = MAINNET_CHAIN.unwrap();
    println!("chain step: 2^{}/2^{}", chain.log_n, chain.hash_log_n);
    // The grinding of the largest proof of each kind.
    let full = plan(&m, 16);
    let wrap = full.wrap.unwrap();
    let hash = crate::hash_table::HashTableAir;
    type Kind<'a> = (&'a str, StarkConfig, Vec<(&'a dyn DynAir, usize)>, usize);
    let kinds: [Kind<'_>; 5] = [
        ("segment", m.segment, vec![(&BlockAir, m.segment_log_n)], BLOCK_PUBLIC),
        ("name segment", m.segment, vec![(&NameAir::MAINNET, m.name_log_n)], NAME_PUBLIC),
        ("signature segment", m.segment, vec![(&SigAir, SEGMENT_LOG_ROWS)], SIG_PUBLIC),
        ("node", m.outer, vec![(&VmAir, full.log_n), (&hash, full.hash_log_n)], crate::vm_air::NUM_PUBLIC),
        ("wrap", m.wrap, vec![(&VmAir, wrap.log_n), (&hash, wrap.hash_log_n)], crate::vm_air::NUM_PUBLIC),
    ];
    for (name, config, tables, num_public) in kinds {
        let g = crate::stark::grinding_of(&config, &tables, &vec![Fp::ZERO; num_public]);
        let mut sizes: Vec<usize> = tables.iter().map(|t| t.1 + config.log_blowup).collect();
        sizes.dedup();
        let fri = config.fri();
        let mut log_m = sizes[0];
        let folds: Vec<usize> = crate::fri::round_log_arities(&fri, &sizes)
            .iter()
            .map(|&la| {
                let b = crate::fri::fold_grinding(&fri, la, log_m);
                log_m -= la;
                b
            })
            .collect();
        println!("{name} grinding: {g:?}, folds {folds:?}");
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "proves proofs of proofs; run with --release")]
fn wrap_program_accepts_and_rejects() {
    let s = setup("wrap", &[30, 25], 55);
    let shape = plan(&SMALL, 2);
    let root = prove_node(
        &SMALL,
        &shape,
        &s.proofs,
        Output::Statement(&s.statement, &s.name_proof, &s.work_proof, None),
        &|_| {},
        &|| false,
    )
    .unwrap();
    let wrap = shape.wrap.unwrap();
    let c = compile_wrap(&SMALL, &root, &s.statement, Some((wrap.log_n, wrap.hash_log_n)));
    let exec = VmAir::execute(&c.prog, &c.inputs).expect("wrap accepts the root proof");
    assert_eq!(wrap.tree, wrap_tree(&shape.digest, &root_tree_digest(&[None, None])));
    assert_eq!(exec.output_digest, Some(s.statement.output(&SMALL.work_shape(), &wrap.tree)));
    assert_eq!(c.prog.digest(SMALL.wrap.log_blowup), wrap.digest);
    let rejects = |c: Compiler| matches!(VmAir::execute(&c.prog, &c.inputs), Err(Error::VmAssertion(_)));
    // Another statement, another root program, another tree, a
    // corrupted proof.
    let mut poor = s.statement.clone();
    poor.subsidy = 54;
    assert!(rejects(compile_wrap(&SMALL, &root, &poor, None)));
    let mut other = root.clone();
    other.digest[0] += Fp::ONE;
    assert!(rejects(compile_wrap(&SMALL, &other, &s.statement, None)));
    let mut other = root.clone();
    other.tree[0] += Fp::ONE;
    assert!(rejects(compile_wrap(&SMALL, &other, &s.statement, None)));
    let mut bad = root.clone();
    bad.proof.openings[1][0].trace_row[3] += Fp::ONE;
    assert!(rejects(compile_wrap(&SMALL, &bad, &s.statement, None)));
    // Proof-of-work witnesses before the batching challenge and the
    // first fold are checked too.
    let hash = crate::hash_table::HashTableAir;
    let g = crate::stark::grinding_of(
        &SMALL.outer,
        &[(&VmAir, shape.log_n), (&hash, shape.hash_log_n)],
        &[Fp::ZERO; crate::vm_air::NUM_PUBLIC],
    );
    assert!(g.beta > 0, "{g:?}");
    let mut bad = root.clone();
    bad.proof.grinding[3] += Fp::ONE;
    assert!(rejects(compile_wrap(&SMALL, &bad, &s.statement, None)));
    let mut bad = root.clone();
    bad.proof.fri.fold_witnesses[0] += Fp::ONE;
    assert!(rejects(compile_wrap(&SMALL, &bad, &s.statement, None)));
}

#[test]
#[ignore = "proves a mainnet root and wraps it; run with --release"]
fn mainnet_wrap_timing() {
    let mut s = setup("wrap-timing", &[30], 30);
    let params = AggregatorParams::MAINNET;
    // The parent's work under the main network's proof of work: its
    // table and its text are not the small network's.
    s.statement.parent_work = test_work(params.pow);
    let seg = prove_segment_padded(&params.segment, &s.segments[0], params.segment_log_n);
    let name = prove_name_padded(&params.segment, &s.names, params.name_log_n);
    let shape = plan(&params, 1);
    let root = prove_node(
        &params,
        &shape,
        &[seg],
        Output::Statement(&s.statement, &name, &params.prove_work(&s.statement.parent_work), None),
        &|_| {},
        &|| false,
    )
    .unwrap();
    let configs: Vec<StarkConfig> = match std::env::var("WRAP") {
        Ok(v) => {
            let n: Vec<usize> = v.split(',').map(|x| x.parse().unwrap()).collect();
            vec![StarkConfig {
                log_blowup: n[0],
                num_queries: n[1],
                pow_bits: n[2],
                zk: n.get(3) == Some(&1),
                commit_bits: 0,
            }]
        }
        Err(_) => vec![
            StarkConfig { log_blowup: 4, num_queries: 21, pow_bits: 16, zk: false, commit_bits: 0 },
            StarkConfig { log_blowup: 5, num_queries: 17, pow_bits: 16, zk: false, commit_bits: 0 },
            StarkConfig { log_blowup: 6, num_queries: 14, pow_bits: 16, zk: false, commit_bits: 0 },
        ],
    };
    for wrap in configs {
        let mut c = compile_wrap(&params, &root, &s.statement, None);
        c.prog.reserve(wrap.blind_rows());
        let t = std::time::Instant::now();
        let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
        let pre = c.prog.preprocess(&wrap);
        let public =
            VmAir::public_values(&pre.root(), &s.statement.output(&params.work_shape(), &shape.wrap.unwrap().tree));
        let tables = VmAir::tables(&trace, &hashes, &pre);
        let proof = stark::prove_tables(&wrap, &tables, &public, &mut outer_transcript());
        let elapsed = t.elapsed();
        let t = std::time::Instant::now();
        let ok = stark::verify_tables(&wrap, &VmAir::specs(&pre.root()), &public, &proof, &mut outer_transcript());
        println!(
            "wrap at rate 1/{}, {} queries: 2^{} + 2^{} hashes, {} instructions; proven in {elapsed:?}, {} bytes; verify {:?} {:?}",
            1 << wrap.log_blowup,
            wrap.num_queries,
            trace.height().trailing_zeros(),
            hashes.height().trailing_zeros(),
            c.prog.instrs.len(),
            proof.to_bytes().len(),
            ok,
            t.elapsed()
        );
        assert!(ok.is_ok(), "the wrap verifies");
    }
}

#[test]
#[ignore = "proves mainnet-sized segments and nodes; run with --release"]
fn mainnet_rate_timing() {
    let s = setup("rates", &[30], 30);
    let quarter = AggregatorParams::MAINNET.outer;
    let eighth = EIGHTH;
    for (name, segment, outer) in [
        ("segments 1/4, nodes 1/4", quarter, quarter),
        ("segments 1/8, nodes 1/4", eighth, quarter),
        ("segments 1/8, nodes 1/8", eighth, eighth),
    ] {
        let params = AggregatorParams { segment, outer, ..AggregatorParams::MAINNET };
        let t = std::time::Instant::now();
        let seg = prove_segment_padded(&params.segment, &s.segments[0], params.segment_log_n);
        let seg_time = t.elapsed();
        let c = compile_node(&params, &[Child::Segment(&seg)], Output::Record);
        let t = std::time::Instant::now();
        let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
        let pre = c.prog.preprocess(&params.outer);
        let out = node_output(&combine_records(&[seg.public]), &tree_digest(&[None]));
        let public = VmAir::public_values(&pre.root(), &out);
        let tables = VmAir::tables(&trace, &hashes, &pre);
        let proof = stark::prove_tables(&params.outer, &tables, &public, &mut outer_transcript());
        let node_time = t.elapsed();
        println!(
            "{name}: segment 2^{} in {seg_time:?} ({} bytes); node over it 2^{} + 2^{} hashes in {node_time:?} ({} bytes)",
            params.segment_log_n,
            seg.proof.to_bytes().len(),
            c.prog.height().trailing_zeros(),
            hashes.height().trailing_zeros(),
            proof.to_bytes().len()
        );
    }
}

/// The table a header's work is done in is the table of its height:
/// the flags that say which are held to it, at every height around the
/// epochs' edges, and nothing else passes for flags.
#[test]
fn a_works_table_is_its_heights() {
    // Epochs of a hundred blocks, the table doubling twice.
    let pow = PowParams { log_dataset_items: 8, max_log_dataset_items: 10, epoch_blocks: 100, ..PowParams::DEV };
    let holds = |height: u32, flags: [u32; 2]| {
        let mut c = Compiler::new();
        let h = c.scalar_inputs(&[Fp::new(height)]);
        let f = c.scalar_inputs(&flags.map(Fp::new));
        table_of_height(&mut c, &pow, h, f);
        VmAir::execute(&c.prog, &c.inputs).is_ok()
    };
    // What the proof of work itself says the flags of a height are.
    let shape = crate::pow_air::WorkShape { windows: 1 << 12, parents: pow.parents, log_pairs: 7, growth: 2 };
    let of_height = |height: u32| -> [u32; 2] {
        let work = Work {
            pow_hash: [Fp::ZERO; DIGEST],
            nonce: [0; 32],
            mix: [Fp::ZERO; DIGEST],
            log_items: pow.log_items_at(height as u64),
        };
        let values = work.to_values(&shape);
        core::array::from_fn(|j| values[crate::pow_air::PUB_TABLE + j].to_canonical())
    };
    assert_eq!(
        (of_height(0), of_height(99), of_height(100), of_height(200), of_height(5000)),
        ([0, 0], [0, 0], [1, 0], [1, 1], [1, 1])
    );
    let heights = [0, 1, 50, 99, 100, 101, 199, 200, 201, 299, 300, 1000, 1 << 20, (1 << 30) - 1];
    for height in heights {
        let right = of_height(height);
        for flags in [[0, 0], [1, 0], [1, 1]] {
            assert_eq!(holds(height, flags), flags == right, "height {height}, flags {flags:?}");
        }
        // Not flags at all: one set after one that is not, and values
        // that are no bits.
        for flags in [[0, 1], [2, 0], [1, 2], [0, 2], [crate::poseidon2::P - 1, 0]] {
            assert!(!holds(height, flags), "height {height}, flags {flags:?}");
        }
    }
    // A table that does not grow has no flags, and nothing to hold.
    let mut c = Compiler::new();
    let h = c.scalar_inputs(&[Fp::new(7)]);
    table_of_height(&mut c, &PowParams::DEV, h, h);
    assert!(VmAir::execute(&c.prog, &c.inputs).is_ok());
}

/// A chain whose blocks each carry one proof, of themselves and of
/// every block before, and whose only verifier is that proof's: the
/// chain takes the proven blocks and refuses a proof that is another
/// block's, one changed anywhere, and one on a body that is not its
/// own.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn the_chain_connects_only_proven_blocks() {
    use crate::block::{Block, BlockRef};
    use crate::chain::Chain;
    use crate::chain::apply::Applied;
    use crate::chain::params::ChainParams;
    use crate::pow::{Dataset, hashimoto};
    use crate::store::testing::MemBackend;
    const EMISSION: &[(u32, u64)] = &[(10, 55)];
    // The aggregator's proof of work (the work segment proves parents'
    // under it), with the built-in text, and every target met.
    let params = ChainParams {
        pow: SMALL.pow,
        genesis_timestamp: 1_700_000_000,
        genesis_nonce: [0u8; 32],
        genesis_target: ChainParams::MAINNET.max_target,
        max_block_size: 16 << 20,
        emission: EMISSION,
        min_reveal: SMALL.min_reveal,
        ..ChainParams::MAINNET
    };
    let seed = SeedText::new(params.pow);
    let table = Dataset::generate(&seed, 10);
    let genesis = Genesis::of(&params.genesis().header, &seed);
    let verifier = AggregateVerifier::new(SMALL, EMISSION, genesis);
    let chain = Chain::open(MemBackend::new(), 8, params, seed, verifier).unwrap();
    let miner = key(9).public_key();
    let now = params.genesis_timestamp + 100_000;
    // The body of the block on the tip paying `amount`, its statement,
    // its state root after, and its proof on `prev`.
    let build = |amount: u64, prev: Option<(u32, &Statement, &[u8])>| {
        let tip = chain.tip().unwrap();
        let height = tip.height + 1;
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        let (prev_root, first) = (snap.root(), snap.outputs().next);
        let txs = vec![reward(&miner, amount)];
        let segments = SegmentWitness::collect_by_rows(&snap, &txs, SMALL.segment_rows(), height).unwrap();
        drop(snap);
        drop(state);
        let names = empty_names(&segments, height);
        let mut body = Body {
            inputs: vec![],
            outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
            proof: vec![],
            ..Default::default()
        };
        let bytes = body.to_bytes();
        let view = BodyRef::from_bytes(&bytes).unwrap();
        let new_root = chain.state_root_after(&view).unwrap();
        let statement = Statement::from_block(&BlockStatement {
            height,
            prev_state_root: prev_root,
            new_state_root: new_root,
            first_output_position: first,
            subsidy: 55,
            body: view,
            parent_work: chain.parent_work(&tip),
            parent_hash: tip.hash(),
        });
        let prev = prev.map(|(h, st, proof)| (h, st, proof, &tip));
        body.proof =
            chain.verifier().prove_block(height, &statement, &segments, &names, prev, 2, &|_| {}, &|| false).unwrap();
        (height, body, statement, new_root)
    };
    // The block of `body` on the tip, sealed.
    let mine = |body: &Body, state_root: Digest| {
        let tip = chain.tip().unwrap();
        let mut header = Header {
            prev_hash: tip.hash(),
            height: tip.height + 1,
            timestamp: tip.timestamp + 600,
            body_commitment: body.commitment(),
            state_root,
            aux: [0; 32],
            mix: [Fp::ZERO; DIGEST],
            nonce: [0; 32],
        };
        header.mix = hashimoto(&table, &header.pow_hash(), &header.nonce).mix;
        Block { header, body: body.clone() }.to_bytes()
    };
    let apply = |block: &[u8]| chain.apply_block(&BlockRef::from_bytes(block).unwrap(), now);

    let (h1, body1, st1, root1) = build(55, None);
    assert_eq!(apply(&mine(&body1, root1)), Ok(Applied::Extended));
    assert_eq!(chain.tip().unwrap().height, 1);
    let (_, body2, _, root2) = build(55, Some((h1, &st1, &body1.proof)));
    // Block 1's proof on block 2's body: another statement.
    let stale = Body { proof: body1.proof.clone(), ..body2.clone() };
    assert_eq!(apply(&mine(&stale, root2)), Err(Error::BadProof));
    // Block 2's proof with one byte changed, anywhere.
    for at in [0, body2.proof.len() / 2, body2.proof.len() - 1] {
        let mut tampered = body2.clone();
        tampered.proof[at] ^= 1;
        assert_eq!(apply(&mine(&tampered, root2)), Err(Error::BadProof), "byte {at}");
    }
    // Block 2's proof on a body paying the reward elsewhere: the
    // outputs, and so the statement, differ. The state's root is that
    // body's own, so that it is the proof that refuses it.
    let mut moved = body2.clone();
    moved.outputs[0] = TxOutput::new(&key(8).public_key(), 55).block_output();
    let moved_root = chain.state_root_after(&BodyRef::from_bytes(&moved.to_bytes()).unwrap()).unwrap();
    assert_eq!(apply(&mine(&moved, moved_root)), Err(Error::BadProof));
    assert_eq!(chain.tip().unwrap().height, 1);
    // The real one connects.
    assert_eq!(apply(&mine(&body2, root2)), Ok(Applied::Extended));
    assert_eq!(chain.tip().unwrap().height, 2);
    assert_eq!(chain.state().root(), root2);
}

/// A network's chain and its aggregator are of one network: the same
/// proof of work, the same wait before a reveal. They are kept apart so
/// that the chain's rules do not depend on how its proofs are made.
#[test]
fn a_networks_chain_and_aggregator_agree() {
    use crate::chain::params::ChainParams;
    for (chain, aggregator) in [
        (ChainParams::MAINNET, AggregatorParams::MAINNET),
        (ChainParams::DEV, AggregatorParams::DEV),
        (ChainParams::DEV_RECURSIVE, AggregatorParams::DEV_RECURSIVE),
    ] {
        assert_eq!(chain.pow, aggregator.pow);
        assert_eq!(chain.min_reveal, aggregator.min_reveal);
    }
    assert!(
        AggregatorParams::DEV.direct && !AggregatorParams::MAINNET.direct && !AggregatorParams::DEV_RECURSIVE.direct
    );
    assert_eq!(AggregatorParams::MAINNET.name_log_n, crate::name_air::NAME_LOG_ROWS);
}
