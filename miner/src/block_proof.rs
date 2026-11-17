//! Block validity proofs: segments proven in parallel and aggregated.
//!
//! A block's proof is a list of transaction segment proofs (see
//! [`crate::block_air`]) and one name segment proof (see
//! [`crate::name_air`]), each with its public boundary values, and the
//! proofs of the block's signature segments ([`crate::sig_air`]), whose
//! entries make the signed set every transaction segment is proven
//! against ([`crate::signed`]). The
//! verifier checks that the segments chain, that the chain starts at the
//! block's previous root, the initial sponge states and first output
//! position, that the name segment continues from where the last segment
//! ends and ends at the new root and the block's end position, that the
//! sponge states are those of the block's own input, output, operation and
//! sweep lists, that the summed input amounts plus the subsidy equal the
//! summed output amounts as integers, and that every STARK proof verifies.
//!
//! This module's checks are native; [`crate::aggregate`] does the same in
//! a recursive proof, which is what blocks carry.
//!
//! Encoding: `u32 count`, then per segment its public values followed by a
//! length-prefixed STARK proof, then the name segment's the same way,
//! then `u32 count` and each signature segment's entries and proof.

use crate::block::Body;
use crate::block_air::{
    BlockAir, Carry, LIMBS, NUM_PUBLIC, SegmentPublic, SegmentWitness, initial_inputs_state, initial_names_state,
    initial_outputs_state, inputs_state, names_state, outputs_state, sweeps_state,
};
use crate::chain::verify::{BlockStatement, ProofVerifier};
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::error::Error;
use crate::hash::Digest;
use crate::name::{NameOp, OpKind, count_ops};
use crate::name_air::{NAME_LOG_ROWS, NUM_PUBLIC as NAME_PUBLIC, NameAir, NamePublic, NameWitness};
use crate::poseidon2::Fp;
use crate::sig_air::{NUM_PUBLIC as SIG_PUBLIC, SLOTS, SigAir};
use crate::signed::{Signed, SignedSet, Signing};
use crate::stark::{self, StarkConfig};
use crate::store::backend::Backend;
use crate::store::outputs::Record;
use crate::store::state::State;
use crate::transaction::Transaction;

/// Transcript domain separator for segment proofs.
pub(crate) const DOM_SEGMENT_PROOF: u32 = 0x30;
/// Transcript domain separator for name segment proofs.
pub(crate) const DOM_NAME_PROOF: u32 = 0x34;
/// Transcript domain separator for signature segment proofs.
pub(crate) const DOM_SIG_PROOF: u32 = 0x35;

pub(crate) fn transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_SEGMENT_PROOF));
    c
}

pub(crate) fn sig_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_SIG_PROOF));
    c
}

pub(crate) fn name_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_NAME_PROOF));
    c
}

/// A proven name segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameProof {
    pub public: NamePublic,
    pub proof: stark::Proof,
}

/// Proves a block's name segment padded to `2^log_n` rows.
pub fn prove_name_padded(config: &StarkConfig, witness: &NameWitness, log_n: usize) -> NameProof {
    let (trace, public) = NameAir::generate_trace_padded(witness, log_n);
    let air = NameAir { min_reveal: witness.min_reveal };
    let proof = stark::prove(config, &air, &trace, &public.to_values(), &mut name_transcript());
    NameProof { public, proof }
}

/// [`prove_name_padded`], given up once `cancel` says so: asked when
/// the trace is made, and then as the proof goes.
pub fn try_prove_name_padded(
    config: &StarkConfig,
    witness: &NameWitness,
    log_n: usize,
    cancel: stark::Cancel<'_>,
) -> Option<NameProof> {
    let (trace, public) = NameAir::generate_trace_padded(witness, log_n);
    if cancel() {
        return None;
    }
    let air = NameAir { min_reveal: witness.min_reveal };
    let tables = [stark::TableInput { air: &air, trace: &trace, pre: None }];
    let proof =
        stark::try_prove_tables(config, &tables, &public.to_values(), &mut name_transcript(), Some(cancel)).ok()?;
    Some(NameProof { public, proof })
}

/// A proven signature segment: the entries it says, and its proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigProof {
    pub entries: [Digest; SLOTS],
    pub proof: stark::Proof,
}

impl SigProof {
    /// The entries as the proof's public values.
    pub fn values(&self) -> Vec<Fp> {
        self.entries.iter().flatten().copied().collect()
    }
}

/// Proves one signature segment, of `2^log_n` rows or, with none
/// given, of as few as hold its signatures. Refuses a signature that
/// does not verify.
pub fn prove_signatures(config: &StarkConfig, signings: &[Signing], log_n: Option<usize>) -> SigProof {
    let log_n = log_n.unwrap_or_else(|| crate::sig_air::log_rows(signings));
    let trace = SigAir::generate_trace(signings, log_n);
    let entries = Signed::entries(signings);
    let values: Vec<Fp> = entries.iter().flatten().copied().collect();
    let proof = stark::prove(config, &SigAir, &trace, &values, &mut sig_transcript());
    SigProof { entries, proof }
}

/// [`prove_signatures`], given up once `cancel` says so: asked when
/// the trace is made, and then as the proof goes.
pub fn try_prove_signatures(
    config: &StarkConfig,
    signings: &[Signing],
    log_n: Option<usize>,
    cancel: stark::Cancel<'_>,
) -> Option<SigProof> {
    let log_n = log_n.unwrap_or_else(|| crate::sig_air::log_rows(signings));
    let trace = SigAir::generate_trace(signings, log_n);
    if cancel() {
        return None;
    }
    let entries = Signed::entries(signings);
    let values: Vec<Fp> = entries.iter().flatten().copied().collect();
    let tables = [stark::TableInput { air: &SigAir, trace: &trace, pre: None }];
    let proof = stark::try_prove_tables(config, &tables, &values, &mut sig_transcript(), Some(cancel)).ok()?;
    Some(SigProof { entries, proof })
}

/// A proven segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentProof {
    pub public: SegmentPublic,
    pub proof: stark::Proof,
}

/// Proves one segment at its natural height.
pub fn prove_segment(config: &StarkConfig, witness: &SegmentWitness) -> SegmentProof {
    let (trace, public) = BlockAir::generate_trace(witness);
    let proof = stark::prove(config, &BlockAir, &trace, &public.to_values(), &mut transcript());
    SegmentProof { public, proof }
}

/// Proves one segment padded to `2^log_n` rows, the shape the aggregator
/// expects.
pub fn prove_segment_padded(config: &StarkConfig, witness: &SegmentWitness, log_n: usize) -> SegmentProof {
    let (trace, public) = BlockAir::generate_trace_padded(witness, log_n);
    let proof = stark::prove(config, &BlockAir, &trace, &public.to_values(), &mut transcript());
    SegmentProof { public, proof }
}

/// [`prove_segment_padded`], given up once `cancel` says so: asked
/// when the trace is made, and then as the proof goes.
pub fn try_prove_segment_padded(
    config: &StarkConfig,
    witness: &SegmentWitness,
    log_n: usize,
    cancel: stark::Cancel<'_>,
) -> Option<SegmentProof> {
    let (trace, public) = BlockAir::generate_trace_padded(witness, log_n);
    if cancel() {
        return None;
    }
    let tables = [stark::TableInput { air: &BlockAir, trace: &trace, pre: None }];
    let proof = stark::try_prove_tables(config, &tables, &public.to_values(), &mut transcript(), Some(cancel)).ok()?;
    Some(SegmentProof { public, proof })
}

/// Proves every segment, the name segment and the signature segments
/// (each at its natural height), one thread each, and encodes the lot.
pub fn prove_block(config: &StarkConfig, segments: &[SegmentWitness], name: &NameWitness) -> Vec<u8> {
    let signed: &[Vec<Signing>] = segments.first().map_or(&[], |w| &w.signed.segments);
    let (proofs, name_proof, sigs) = std::thread::scope(|s| {
        let handles: Vec<_> = segments.iter().map(|w| s.spawn(move || prove_segment(config, w))).collect();
        let sig_handles: Vec<_> = signed.iter().map(|g| s.spawn(move || prove_signatures(config, g, None))).collect();
        let np = s.spawn(move || {
            let (trace, public) = NameAir::generate_trace(name);
            let air = NameAir { min_reveal: name.min_reveal };
            let proof = stark::prove(config, &air, &trace, &public.to_values(), &mut name_transcript());
            NameProof { public, proof }
        });
        let proofs: Vec<SegmentProof> =
            handles.into_iter().map(|h| h.join().expect("segment prover panicked")).collect();
        let sigs: Vec<SigProof> =
            sig_handles.into_iter().map(|h| h.join().expect("signature segment prover panicked")).collect();
        (proofs, np.join().expect("name segment prover panicked"), sigs)
    });
    encode(&proofs, &name_proof, &sigs)
}

pub fn encode(proofs: &[SegmentProof], name: &NameProof, sigs: &[SigProof]) -> Vec<u8> {
    let mut w = Writer::with_capacity((proofs.len() + 1) << 18);
    w.u32(proofs.len() as u32);
    for sp in proofs {
        w.fps(&sp.public.to_values());
        let bytes = sp.proof.to_bytes();
        w.u32(bytes.len() as u32);
        w.0.extend_from_slice(&bytes);
    }
    w.fps(&name.public.to_values());
    let bytes = name.proof.to_bytes();
    w.u32(bytes.len() as u32);
    w.0.extend_from_slice(&bytes);
    w.u32(sigs.len() as u32);
    for sig in sigs {
        w.fps(&sig.values());
        let bytes = sig.proof.to_bytes();
        w.u32(bytes.len() as u32);
        w.0.extend_from_slice(&bytes);
    }
    w.finish()
}

pub fn decode(bytes: &[u8]) -> Option<(Vec<SegmentProof>, NameProof, Vec<SigProof>)> {
    let mut r = Reader(bytes);
    let n = r.len(NUM_PUBLIC * 4)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut values = Vec::with_capacity(NUM_PUBLIC);
        for _ in 0..NUM_PUBLIC {
            values.push(r.fp()?);
        }
        let public = SegmentPublic::from_values(&values)?;
        let len = r.len(1)?;
        let proof = stark::Proof::from_bytes(r.take(len)?).ok()?;
        out.push(SegmentProof { public, proof });
    }
    let mut values = Vec::with_capacity(NAME_PUBLIC);
    for _ in 0..NAME_PUBLIC {
        values.push(r.fp()?);
    }
    let public = NamePublic::from_values(&values)?;
    let len = r.len(1)?;
    let proof = stark::Proof::from_bytes(r.take(len)?).ok()?;
    let name = NameProof { public, proof };
    let n = r.len(SIG_PUBLIC * 4)?;
    if n > crate::signed::MAX_SEGMENTS {
        return None;
    }
    let mut sigs = Vec::with_capacity(n);
    for _ in 0..n {
        let mut entries = [crate::signed::NO_ENTRY; SLOTS];
        for x in entries.iter_mut().flatten() {
            *x = r.fp()?;
        }
        let len = r.len(1)?;
        let proof = stark::Proof::from_bytes(r.take(len)?).ok()?;
        sigs.push(SigProof { entries, proof });
    }
    if !r.is_empty() {
        return None;
    }
    Some((out, name, sigs))
}

/// Assembles a block body from the segments, the name witness and the
/// encoded proof.
pub fn body_from_segments(segments: &[SegmentWitness], name: &NameWitness, proof: Vec<u8>) -> Body {
    Body {
        inputs: segments.iter().flat_map(|s| s.positions()).collect(),
        outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
        ops: name.block_ops(),
        sweeps: name.sweeps(),
        proof,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    Malformed,
    NoSegments,
    /// Segment `index` does not start where the previous one ended (or, for
    /// the first, where the block starts).
    BrokenChain {
        index: usize,
    },
    /// The last segment does not end at the block's root, lists or position.
    WrongEnd,
    /// The name segment does not continue from the last segment, or does
    /// not end at the block's root, position, operation and sweep lists,
    /// height or caps.
    WrongNames,
    Unbalanced,
    SegmentRejected {
        index: usize,
    },
    NameSegmentRejected,
    /// The segments are not all proven against the set the signature
    /// segments' entries make.
    WrongSignedSet,
    SignatureSegmentRejected {
        index: usize,
    },
}

/// Checks the aggregate's chaining and balance against the statement,
/// without verifying the STARK proofs.
pub fn check_chaining(
    s: &BlockStatement<'_>,
    proofs: &[SegmentProof],
    name: &NameProof,
    sigs: &[SigProof],
) -> Result<(), AggregateError> {
    let first = proofs.first().ok_or(AggregateError::NoSegments)?;
    // Every segment's signatures are looked up in one set: the one the
    // signature segments' entries make.
    let entries: Vec<[Digest; SLOTS]> = sigs.iter().map(|sig| sig.entries).collect();
    let signed = SignedSet::new(&entries).root();
    if proofs.iter().any(|p| p.public.signed != signed) || name.public.signed != signed {
        return Err(AggregateError::WrongSignedSet);
    }
    if first.public.root_in != s.prev_state_root
        || first.public.isp_in != initial_inputs_state()
        || first.public.osp_in != initial_outputs_state()
        || first.public.nsp_in != initial_names_state()
        || first.public.pos_in != s.first_output_position
        || first.public.carry_in != Carry::CLOSED
    {
        return Err(AggregateError::BrokenChain { index: 0 });
    }
    for (i, pair) in proofs.windows(2).enumerate() {
        let (a, b) = (&pair[0].public, &pair[1].public);
        if a.root_out != b.root_in
            || a.isp_out != b.isp_in
            || a.osp_out != b.osp_in
            || a.nsp_out != b.nsp_in
            || a.pos_out != b.pos_in
            || a.carry_out != b.carry_in
        {
            return Err(AggregateError::BrokenChain { index: i + 1 });
        }
    }
    let last = &proofs.last().unwrap().public;
    let after_outputs = s.first_output_position + s.body.outputs().len() as u64;
    if last.isp_out != inputs_state(s.body.inputs())
        || last.osp_out != outputs_state(s.body.outputs())
        || last.nsp_out != names_state(s.body.ops().map(|op| op.digest()))
        || last.pos_out != after_outputs
        || last.carry_out != Carry::CLOSED
    {
        return Err(AggregateError::WrongEnd);
    }
    let nm = &name.public;
    let kinds = s.body.ops().map(|o| o.kind()).chain(s.body.sweeps().map(|_| OpKind::Sweep));
    let counts = count_ops(kinds).map_err(|_| AggregateError::WrongNames)?;
    if nm.root_in != last.root_out
        || nm.root_out != s.new_state_root
        || nm.pos_in != last.pos_out
        || nm.pos_out != after_outputs + s.body.commits() as u64
        || nm.nsp != last.nsp_out
        || nm.ssp != sweeps_state(s.body.sweeps())
        || nm.height != s.height
        || nm.counts.iter().zip(&counts).any(|(a, b)| *a as usize != *b)
    {
        return Err(AggregateError::WrongNames);
    }
    // Checked: the limbs are untrusted until the proofs are verified, and
    // enough segments of large ones would overflow a u128.
    let sum = |f: fn(&SegmentPublic) -> u128| proofs.iter().try_fold(0u128, |a, p| a.checked_add(f(&p.public)));
    let total_in = sum(|p| SegmentPublic::total(&p.sum_in)).and_then(|t| t.checked_add(s.subsidy as u128));
    let total_out = sum(|p| SegmentPublic::total(&p.sum_out));
    if total_in.is_none() || total_in != total_out {
        return Err(AggregateError::Unbalanced);
    }
    Ok(())
}

/// Full verification of an encoded block proof against a statement.
pub fn verify_block(
    config: &StarkConfig,
    names: &NameAir,
    s: &BlockStatement<'_>,
    proof: &[u8],
) -> Result<(), AggregateError> {
    let (proofs, name, sigs) = decode(proof).ok_or(AggregateError::Malformed)?;
    check_chaining(s, &proofs, &name, &sigs)?;
    for (i, sig) in sigs.iter().enumerate() {
        if stark::verify(config, &SigAir, &sig.values(), &sig.proof, &mut sig_transcript()).is_err() {
            return Err(AggregateError::SignatureSegmentRejected { index: i });
        }
    }
    for (i, sp) in proofs.iter().enumerate() {
        if stark::verify(config, &BlockAir, &sp.public.to_values(), &sp.proof, &mut transcript()).is_err() {
            return Err(AggregateError::SegmentRejected { index: i });
        }
    }
    if stark::verify(config, names, &name.public.to_values(), &name.proof, &mut name_transcript()).is_err() {
        return Err(AggregateError::NameSegmentRejected);
    }
    Ok(())
}

/// The rows every name segment is padded to on mainnet.
pub const NAME_ROWS_LOG: usize = NAME_LOG_ROWS;

/// Verifies block proofs with the STARK verifier.
#[derive(Clone, Copy, Debug)]
pub struct StarkVerifier {
    pub config: StarkConfig,
    /// The name circuit, for the chain's reveal window.
    pub names: NameAir,
}

impl ProofVerifier for StarkVerifier {
    fn verify(&self, s: &BlockStatement<'_>, proof: &[u8]) -> bool {
        verify_block(&self.config, &self.names, s, proof).is_ok()
    }
}

/// The body of the block of `txs` and `sweeps` at `height` on `state`,
/// with its proof: what a miner then seals in a header. The
/// transactions are packed into segments of at most `max_rows` rows
/// ([`crate::block_air::pack`]), their witnesses and the name section's
/// gathered from the state as it is, and every segment proven. The
/// state is not changed.
///
/// An error if the block cannot be: an input that is not there to
/// spend, a name taken, a commit outside its window.
pub fn prove_body<B: Backend + 'static>(
    state: &State<B>,
    config: &StarkConfig,
    min_reveal: u32,
    height: u32,
    txs: &[Transaction],
    sweeps: &[u64],
    max_rows: usize,
) -> Result<Body, Error> {
    let segments = SegmentWitness::collect_by_rows(&state.snapshot()?, txs, max_rows, height)?;
    let mut spends: Vec<u64> = segments.iter().flat_map(|s| s.positions()).collect();
    spends.sort_unstable();
    let made: Vec<Record> = segments
        .iter()
        .flat_map(|s| s.block_outputs())
        .map(|o| Record { commitment: o.commitment, memo: o.memo, amount: o.amount, height })
        .collect();
    let ops: Vec<NameOp> = txs.iter().flat_map(|tx| tx.ops.iter().cloned()).collect();
    let mut segments = segments;
    let mut name = NameWitness::collect(state, height, min_reveal, &spends, &made, &ops, sweeps)?;
    join_signed(&mut segments, &mut name);
    let proof = prove_block(config, &segments, &name);
    Ok(body_from_segments(&segments, &name, proof))
}

/// Makes one signed set of a block's signatures: its transaction
/// segments' and its name segment's, in that order, for every one of
/// them to look its own up in.
pub fn join_signed(segments: &mut [SegmentWitness], name: &mut NameWitness) {
    let mut signings = SegmentWitness::signings(segments);
    signings.extend(name.signings());
    let signed = std::sync::Arc::new(Signed::pack(signings));
    for segment in segments.iter_mut() {
        segment.signed = signed.clone();
    }
    name.signed = signed;
}

/// Limb count re-export for callers computing totals.
pub const AMOUNT_LIMBS: usize = LIMBS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockRef, BodyRef, Header};
    use crate::chain::Chain;
    use crate::chain::apply::Applied;
    use crate::chain::headers::tests::{NOW, easy, seed, table};
    use crate::chain::params::{COIN, ChainParams};
    use crate::hash::Digest;
    use crate::name::{Record as NameRecord, commit_hash};
    use crate::output::{Key, Output, Sig, pubkey_hash};
    use crate::pow::hashimoto;
    use crate::store::sparse::EMPTY;
    use crate::store::testing::MemBackend;
    use crate::transaction::UnsignedTransaction;

    const STARK: StarkConfig = StarkConfig { log_blowup: 1, num_queries: 12, pow_bits: 0, zk: false, commit_bits: 0 };
    const PAY: u64 = 1500 * COIN;

    type Proven = Chain<MemBackend, StarkVerifier>;

    fn params() -> ChainParams {
        ChainParams { min_reveal: 2, ..easy() }
    }

    fn open() -> Proven {
        let verifier = StarkVerifier { config: STARK, names: NameAir::of(params().min_reveal) };
        let chain = Chain::open(MemBackend::new(), 8, params(), seed(), verifier).unwrap();
        chain.set_dataset(table());
        chain
    }

    fn key(tag: u8) -> Key {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s)
    }

    fn d(x: u32) -> Digest {
        [Fp::new(x); 8]
    }

    /// A transaction that makes the block's coins: no inputs.
    fn reward(to: &Key, amount: u64) -> Transaction {
        UnsignedTransaction::new(vec![], vec![Output::new(&to.public_key(), amount)])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap()
    }

    /// The block of `body` after the chain's last, sealed.
    fn sealed(chain: &Proven, body: &Body) -> Vec<u8> {
        let parent = chain.tip().unwrap();
        let bytes = body.to_bytes();
        let mut header = Header {
            prev_hash: parent.hash(),
            height: parent.height + 1,
            timestamp: parent.timestamp + 600,
            body_commitment: body.commitment(),
            state_root: chain.state_root_after(&BodyRef::from_bytes(&bytes).unwrap()).unwrap(),
            aux: [0; 32],
            mix: EMPTY,
            nonce: [0; 32],
        };
        header.mix = hashimoto(&*table(), &header.pow_hash(), &header.nonce).mix;
        Block { header, body: body.clone() }.to_bytes()
    }

    /// Proves the block of `txs` after the chain's last.
    fn proven(chain: &Proven, txs: &[Transaction], max_rows: usize) -> Body {
        let height = chain.tip().unwrap().height + 1;
        prove_body(&chain.state(), &STARK, params().min_reveal, height, txs, &[], max_rows).unwrap()
    }

    fn apply(chain: &Proven, block: &[u8]) -> Result<Applied, Error> {
        chain.apply_block(&BlockRef::from_bytes(block).unwrap(), NOW)
    }

    #[test]
    fn verifier_rejects_garbage() {
        let v = StarkVerifier { config: STARK, names: NameAir::MAINNET };
        let bytes = Body::default().to_bytes();
        let st = BlockStatement {
            height: 1,
            prev_state_root: EMPTY,
            new_state_root: EMPTY,
            first_output_position: 0,
            subsidy: 50,
            body: BodyRef::from_bytes(&bytes).unwrap(),
            parent_work: crate::pow_air::Work { pow_hash: d(1), nonce: [0; 32], mix: d(2), log_items: 10 },
            parent_hash: d(3),
        };
        assert!(!v.verify(&st, &[]));
        assert!(!v.verify(&st, &[1, 2, 3]));
        let empty = NameWitness {
            root_in: EMPTY,
            pos_in: 0,
            height: 1,
            min_reveal: crate::name::MIN_REVEAL,
            ops: vec![],
            signed: Default::default(),
        };
        let name = prove_name_padded(&STARK, &empty, 4);
        assert_eq!(
            verify_block(&STARK, &NameAir::MAINNET, &st, &encode(&[], &name, &[])),
            Err(AggregateError::NoSegments)
        );
    }

    /// A chain whose blocks carry proofs, checked by the circuits'
    /// verifier and nothing else: coins made and spent, a name committed
    /// to, revealed and updated, a transaction split between segments.
    /// A block with a proof that is not its own is refused, and changes
    /// nothing.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
    fn a_chain_of_proven_blocks() {
        let chain = open();
        let (mut a, mut b, miner) = (key(1), key(2), key(3));
        let (mut owner, heir) = (key(4), key(5));
        // Block 1: the first coins, to a.
        let b1 = sealed(&chain, &proven(&chain, &[reward(&a, PAY)], 1 << 13));
        assert_eq!(apply(&chain, &b1), Ok(Applied::Extended));

        // Block 2: a pays b, and commits to a name; the miner is paid.
        let alice = NameRecord::new(b"alice", pubkey_hash(&owner.public_key()), d(11), d(12)).unwrap();
        let salt = d(77);
        let commit = commit_hash(&alice.name.hash(), &salt, &alice.owner);
        let mut pay = UnsignedTransaction::with_ops(
            vec![(a.public_key(), PAY)],
            vec![Output::new(&b.public_key(), PAY - 5), Output::new(&miner.public_key(), 5)],
            vec![NameOp::Commit { commit, memo: [Fp::new(9); 5] }],
        )
        .sign_with(&mut a)
        .unwrap();
        pay.set_positions(&[0]);
        let txs = [pay, reward(&miner, PAY)];
        let body2 = proven(&chain, &txs, 1 << 13);
        // A proof that is not this block's: a byte of it changed, and
        // the first block's whole.
        let before = (chain.tip().unwrap(), chain.state().root());
        let mut flipped = body2.clone();
        let at = flipped.proof.len() / 2;
        flipped.proof[at] ^= 1;
        assert_eq!(apply(&chain, &sealed(&chain, &flipped)), Err(Error::BadProof));
        let other = Body { proof: BlockRef::from_bytes(&b1).unwrap().body().proof().to_vec(), ..body2.clone() };
        assert_eq!(apply(&chain, &sealed(&chain, &other)), Err(Error::BadProof));
        let none = Body { proof: vec![], ..body2.clone() };
        assert_eq!(apply(&chain, &sealed(&chain, &none)), Err(Error::BadProof));
        assert_eq!((chain.tip().unwrap(), chain.state().root()), before);
        assert_eq!(apply(&chain, &sealed(&chain, &body2)), Ok(Applied::Extended));
        // Outputs 1 and 2 are the payment's, 3 the miner's, 4 the commit.
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert_eq!(snap.commits().position_of(snap.pages(), &commit).unwrap(), Some(4));
        assert!(!snap.is_unspent(0).unwrap() && snap.is_unspent(4).unwrap());
        drop(snap);
        drop(state);

        // Block 3: coins alone. The commit waits two blocks.
        let b3 = sealed(&chain, &proven(&chain, &[reward(&miner, PAY)], 1 << 13));
        assert_eq!(apply(&chain, &b3), Ok(Applied::Extended));
        // Block 4: b pays on and reveals the name, in segments small
        // enough that the transaction is split between two.
        let mut reveal = UnsignedTransaction::with_ops(
            vec![(b.public_key(), PAY - 5)],
            // Ten outputs: with the input, more rows than a segment has.
            (0..10).map(|i| Output::new(&a.public_key(), if i == 0 { PAY - 14 } else { 1 })).collect(),
            vec![NameOp::Reveal { record: alice, salt, commit: 4 }],
        )
        .sign_with(&mut b)
        .unwrap();
        reveal.set_positions(&[1]);
        let body4 = proven(&chain, &[reveal, reward(&miner, PAY)], 1 << 9);
        let (segments, _, sigs) = decode(&body4.proof).unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(segments.len() >= 2, "{} segments", segments.len());
        assert_eq!(apply(&chain, &sealed(&chain, &body4)), Ok(Applied::Extended));
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert_eq!(snap.name(alice.key()).unwrap(), Some(alice));
        assert!(!snap.is_unspent(4).unwrap());
        drop(snap);
        drop(state);

        // Block 5: the name's owner hands it on.
        let handed = NameRecord::new(b"alice", pubkey_hash(&heir.public_key()), d(13), d(14)).unwrap();
        let update = UnsignedTransaction::with_ops(vec![], vec![], vec![NameOp::update(handed, &mut owner).unwrap()])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();
        let body5 = proven(&chain, &[update, reward(&miner, PAY)], 1 << 13);
        assert_eq!(apply(&chain, &sealed(&chain, &body5)), Ok(Applied::Extended));
        assert_eq!(chain.state().snapshot().unwrap().name(alice.key()).unwrap(), Some(handed));
        assert_eq!(chain.tip().unwrap().height, 5);

        // What cannot be a block is not proven: a spend of what is
        // spent, a name revealed again.
        let mut again = UnsignedTransaction::new(vec![(a.public_key(), PAY)], vec![Output::new(&b.public_key(), PAY)])
            .sign_with(&mut key(1))
            .unwrap();
        again.set_positions(&[0]);
        let refused = prove_body(&chain.state(), &STARK, 2, 6, &[again], &[], 1 << 13);
        assert_eq!(refused.err(), Some(Error::NoSuchOutput(0)));
    }

    /// A block's spends rest on its signature segments. Without them,
    /// with entries that are not what was proven, with the segments of
    /// another block, or with a signature that does not verify, there
    /// is no block.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
    fn a_spend_rests_on_a_proven_signature() {
        let chain = open();
        let (mut a, b, miner) = (key(1), key(2), key(3));
        let b1 = sealed(&chain, &proven(&chain, &[reward(&a, PAY)], 1 << 13));
        assert_eq!(apply(&chain, &b1), Ok(Applied::Extended));
        let spend = |a: &mut Key, to: &Key| {
            let mut tx =
                UnsignedTransaction::new(vec![(a.public_key(), PAY)], vec![Output::new(&to.public_key(), PAY)])
                    .sign_with(a)
                    .unwrap();
            tx.set_positions(&[0]);
            tx
        };
        let pay = spend(&mut a, &b);
        let good = proven(&chain, &[pay.clone(), reward(&miner, PAY)], 1 << 13);
        let (segments, name, sigs) = decode(&good.proof).unwrap();
        assert_eq!(sigs.len(), 1);
        let entry = crate::sig_air::entry(&a.public_key(), &pay.txid(), pay.inputs[0].signature.index);
        assert_eq!(sigs[0].entries[0], entry);
        assert!(sigs[0].entries[1..].iter().all(|e| *e == crate::signed::NO_ENTRY));
        assert!(segments.iter().all(|p| p.public.signed == SignedSet::new(&[sigs[0].entries]).root()));
        let with = |sigs: &[SigProof]| Body { proof: encode(&segments, &name, sigs), ..good.clone() };
        let refused = |body: &Body| assert_eq!(apply(&chain, &sealed(&chain, body)), Err(Error::BadProof));
        // No signature segment: the set is of nothing, and the segments
        // were proven against another.
        refused(&with(&[]));
        // The entry said is not the one proven; nor is another slot's.
        let mut other = sigs.clone();
        other[0].entries[0][0] += Fp::ONE;
        refused(&with(&other));
        let mut more = sigs.clone();
        more[0].entries[1] = d(5);
        refused(&with(&more));
        // The same segment twice: another set.
        refused(&with(&[sigs[0].clone(), sigs[0].clone()]));
        // A signature of another message by the same key, proven, says
        // another entry: the spend is not in its set.
        let elsewhere = spend(&mut a, &miner);
        let theirs = proven(&chain, &[elsewhere, reward(&miner, PAY)], 1 << 13);
        let (_, _, their_sigs) = decode(&theirs.proof).unwrap();
        refused(&with(&their_sigs));
        // A signature that does not verify is proven by nobody.
        let mut forged = spend(&mut a, &b);
        forged.inputs[0].signature.randomizer[0] += Fp::ONE;
        let made = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_body(&chain.state(), &STARK, 2, 2, &[forged, reward(&miner, PAY)], &[], 1 << 13)
        }));
        assert!(made.is_err());
        // The block as it was made is taken.
        assert_eq!(apply(&chain, &sealed(&chain, &good)), Ok(Applied::Extended));
    }

    /// The proof's container is read back as written, and bytes that
    /// are not one are refused without a panic.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn fuzz_the_container_decoder() {
        use crate::poseidon2_air::Poseidon2Air;
        let config = StarkConfig { log_blowup: 2, num_queries: 4, pow_bits: 0, zk: false, commit_bits: 0 };
        let trace = Poseidon2Air::generate_trace(&[[Fp::ZERO; crate::poseidon2::WIDTH]]);
        let proof = stark::prove(&config, &Poseidon2Air, &trace, &[], &mut Challenger::new());
        let public = SegmentPublic::from_values(&[Fp::ZERO; NUM_PUBLIC]).unwrap();
        let name_public = NamePublic::from_values(&[Fp::ZERO; NAME_PUBLIC]).unwrap();
        let sp = SegmentProof { public, proof: proof.clone() };
        let np = NameProof { public: name_public, proof };
        let sig = SigProof { entries: [d(7); SLOTS], proof: sp.proof.clone() };
        let samples =
            [encode(&[sp.clone()], &np, &[]), encode(&[sp.clone(), sp.clone()], &np, &[sig.clone(), sig.clone()])];
        crate::test_util::fuzz_decoder("block_proof::decode", &samples, 5_000, |b| {
            decode(b).map(|(s, n, g)| Some(encode(&s, &n, &g)))
        });
    }
}
