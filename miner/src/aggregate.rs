//! A block's proof as one proof: its segments gathered by a tree of
//! proofs of proofs, and the statement the root speaks to.
//!
//! [`crate::block_proof`] checks a block's segment proofs one by one,
//! which is what a network of quick blocks does. A block of the main
//! network carries one proof instead: nodes of the tree verify segment
//! proofs (and other nodes) inside the machine of [`crate::vm_air`], the
//! root also verifies the name section's proof and the proof of its
//! parent's work, and what the root says is the block's [`Statement`].
//!
//! This is the part of that with no proof in it: the parameters, the
//! statement and its encoding, and the digests that say which programs a
//! tree was made of. The programs themselves, and the chain's proof over
//! them, are not here yet.
//!
//! # The statement
//!
//! Everything a block's proof is about, as scalars: the state roots
//! before and after, the sponges of what the body lists, the positions
//! its outputs take, its subsidy and height, its parent's hash and its
//! parent's work. The parent's work comes last: how many values it has
//! depends on how many sizes the network's table of work takes
//! ([`crate::pow_air::WorkShape::num_public`]), so the statement's length
//! is the network's ([`AggregatorParams::statement_len`]) and every
//! place before the work is fixed.

use std::sync::Mutex;

use crate::block_air::{
    LIMBS, SegmentPublic, inputs_state, limbs16, limbs16_wide, names_state, outputs_state, position_limbs, sweeps_state,
};
use crate::chain::verify::BlockStatement;
use crate::hash::Digest;
use crate::name_air;
use crate::poseidon2::{DIGEST, Fp, WIDTH};
use crate::pow::{PowParams, SeedText};
use crate::pow_air::{Work, WorkSetup, WorkShape};
use crate::stark::{Proof, StarkConfig};

/// Consensus parameters of the aggregator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregatorParams {
    /// STARK configuration of the segment proofs.
    pub segment: StarkConfig,
    /// Every segment trace has exactly `2^segment_log_n` rows.
    pub segment_log_n: usize,
    /// Every name segment trace has exactly `2^name_log_n` rows; it is
    /// proven at the segment configuration.
    pub name_log_n: usize,
    /// Largest segment count a block may use.
    pub max_segments: usize,
    /// Largest number of children a node verifies.
    pub fan_in: usize,
    /// STARK configuration of the node (machine) proofs.
    pub outer: StarkConfig,
    /// STARK configuration of the wrap proof, the one a block carries.
    pub wrap: StarkConfig,
    /// Blocks carry their segment and name proofs, checked one by one at
    /// the segment configuration: no nodes, wrap or chain proof, so no
    /// plan either (`--network dev`, for rapid blocks). A proof then says
    /// nothing of the blocks before.
    pub direct: bool,
    /// The proof of work, whose parent's the root's work segment proves
    /// (at the segment configuration).
    pub pow: PowParams,
    /// Blocks a name's commit waits before its reveal
    /// ([`crate::name::MIN_REVEAL`] on mainnet), proven in the name
    /// segments.
    pub min_reveal: u32,
}

impl AggregatorParams {
    /// 120 bits of conjectured security for every proof: each
    /// Fiat-Shamir round has an error below 2^-121.
    pub const MAINNET: AggregatorParams = AggregatorParams {
        segment: StarkConfig { log_blowup: 2, num_queries: 54, pow_bits: 16, zk: false, commit_bits: 121 },
        segment_log_n: 15,
        name_log_n: name_air::NAME_LOG_ROWS,
        max_segments: 1 << 14,
        fan_in: 4,
        outer: StarkConfig { log_blowup: 2, num_queries: 54, pow_bits: 16, zk: false, commit_bits: 121 },
        wrap: StarkConfig { log_blowup: 5, num_queries: 22, pow_bits: 16, zk: true, commit_bits: 121 },
        direct: false,
        pow: PowParams::MAINNET,
        min_reveal: crate::name::MIN_REVEAL,
    };

    /// The recursive dev network's: the mainnet way at the smallest
    /// parameters, for testing the proof path.
    pub const DEV_RECURSIVE: AggregatorParams = AggregatorParams {
        segment: StarkConfig { log_blowup: 1, num_queries: 2, pow_bits: 0, zk: false, commit_bits: 0 },
        segment_log_n: 11,
        name_log_n: 11,
        max_segments: 64,
        fan_in: 4,
        outer: StarkConfig { log_blowup: 2, num_queries: 2, pow_bits: 0, zk: false, commit_bits: 0 },
        wrap: StarkConfig { log_blowup: 3, num_queries: 2, pow_bits: 0, zk: true, commit_bits: 0 },
        direct: false,
        pow: PowParams::DEV,
        min_reveal: 3,
    };

    /// The dev network's: its blocks' segment and name proofs are
    /// checked directly ([`AggregatorParams::direct`]).
    pub const DEV: AggregatorParams = AggregatorParams { direct: true, ..Self::DEV_RECURSIVE };

    pub fn segment_rows(&self) -> usize {
        1 << self.segment_log_n
    }

    pub fn name_rows(&self) -> usize {
        1 << self.name_log_n
    }

    /// The shape of the network's proof of work.
    pub fn work_shape(&self) -> WorkShape {
        WorkShape::of(&SeedText::new(self.pow))
    }

    /// Scalars in a statement's encoding on this network.
    pub fn statement_len(&self) -> usize {
        ST_WORK + self.work_shape().num_public()
    }

    /// The window table of the network's proof of work, committed at the
    /// segment configuration: once for the process (0.3 s and about 50 MB
    /// on mainnet), then kept.
    pub fn work_setup(&self) -> &'static WorkSetup<'static> {
        type Setups = Mutex<Vec<(StarkConfig, PowParams, &'static WorkSetup<'static>)>>;
        static SETUPS: Setups = Mutex::new(Vec::new());
        let mut setups = SETUPS.lock().unwrap();
        if let Some((_, _, s)) = setups.iter().find(|(c, p, _)| *c == self.segment && *p == self.pow) {
            return s;
        }
        let setup: &'static WorkSetup<'static> =
            Box::leak(Box::new(WorkSetup::new(&SeedText::new(self.pow), &self.segment)));
        setups.push((self.segment, self.pow, setup));
        setup
    }

    /// Proves `work`: that its mix is hashimoto's, in the table of its
    /// size.
    pub fn prove_work(&self, work: &Work) -> WorkProof {
        let (proof, proven) =
            crate::pow_air::prove_work(self.work_setup(), &self.segment, work.log_items, &work.pow_hash, &work.nonce);
        assert_eq!(proven.mix, work.mix, "the work's mix is not hashimoto's");
        WorkProof { work: *work, proof }
    }
}

/// A proven [`Work`].
#[derive(Clone, Debug)]
pub struct WorkProof {
    pub work: Work,
    pub proof: Proof,
}

/// Work that is no header's: all zero, in the smallest table.
pub fn zero_work(shape: &WorkShape) -> Work {
    Work { pow_hash: [Fp::ZERO; DIGEST], nonce: [0; 32], mix: [Fp::ZERO; DIGEST], log_items: shape.log_pairs + 1 }
}

/// Values the root's output digest commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub prev_state_root: [Fp; DIGEST],
    pub new_state_root: [Fp; DIGEST],
    /// Inputs sponge state after the block's input positions.
    pub inputs_state: [Fp; WIDTH],
    /// Outputs sponge state after the block's outputs.
    pub outputs_state: [Fp; WIDTH],
    pub first_output_position: u64,
    /// The next position after the block's outputs and commits.
    pub end_output_position: u64,
    pub subsidy: u64,
    pub height: u32,
    /// Name operations sponge state after the block's operation digests.
    pub names_state: [Fp; WIDTH],
    /// Sweeps sponge state after the block's swept positions.
    pub sweeps_state: [Fp; WIDTH],
    /// The parent header's hash (the block's `prev_hash`), which the chain
    /// step recomputes from the parent's fields and links to the previous
    /// block's.
    pub parent_hash: Digest,
    /// The parent header's work, which the root's work segment proves.
    pub parent_work: Work,
}

// Where each part of a statement's encoding begins. The parent's work is
// last, its length the network's.
// Read by the programs, which are to come.
#[allow(dead_code)]
pub(crate) const ST_PREV: usize = 0;
// Read by the programs, which are to come.
#[allow(dead_code)]
pub(crate) const ST_NEW: usize = DIGEST;
pub(crate) const ST_ISP: usize = 2 * DIGEST;
pub(crate) const ST_OSP: usize = ST_ISP + WIDTH;
pub(crate) const ST_POS_IN: usize = ST_OSP + WIDTH;
pub(crate) const ST_POS_OUT: usize = ST_POS_IN + 2;
pub(crate) const ST_SUBSIDY: usize = ST_POS_OUT + 2;
pub(crate) const ST_HEIGHT: usize = ST_SUBSIDY + LIMBS;
pub(crate) const ST_NSP: usize = ST_HEIGHT + 1;
pub(crate) const ST_SSP: usize = ST_NSP + WIDTH;
pub(crate) const ST_PARENT: usize = ST_SSP + WIDTH;
pub(crate) const ST_WORK: usize = ST_PARENT + DIGEST;

impl Statement {
    /// The statement of a block: what the chain asks its proof to show.
    pub fn from_block(s: &BlockStatement<'_>) -> Statement {
        Statement {
            prev_state_root: s.prev_state_root,
            new_state_root: s.new_state_root,
            inputs_state: inputs_state(s.body.inputs()),
            outputs_state: outputs_state(s.body.outputs()),
            first_output_position: s.first_output_position,
            end_output_position: s.first_output_position + (s.body.outputs().len() + s.body.commits()) as u64,
            subsidy: s.subsidy,
            height: s.height,
            names_state: names_state(s.body.ops().map(|op| op.digest())),
            sweeps_state: sweeps_state(s.body.sweeps()),
            parent_hash: s.parent_hash,
            parent_work: s.parent_work,
        }
    }

    /// The statement of nothing: what a proof made only for its shape
    /// speaks to.
    pub fn zero(shape: &WorkShape) -> Statement {
        Statement {
            prev_state_root: [Fp::ZERO; DIGEST],
            new_state_root: [Fp::ZERO; DIGEST],
            inputs_state: [Fp::ZERO; WIDTH],
            outputs_state: [Fp::ZERO; WIDTH],
            first_output_position: 0,
            end_output_position: 0,
            subsidy: 0,
            height: 0,
            names_state: [Fp::ZERO; WIDTH],
            sweeps_state: [Fp::ZERO; WIDTH],
            parent_hash: [Fp::ZERO; DIGEST],
            parent_work: zero_work(shape),
        }
    }

    /// The statement as scalars, the parent's work in the table sizes of
    /// `shape`.
    pub fn to_values(&self, shape: &WorkShape) -> Vec<Fp> {
        let mut v = Vec::with_capacity(ST_WORK + shape.num_public());
        v.extend_from_slice(&self.prev_state_root);
        v.extend_from_slice(&self.new_state_root);
        v.extend_from_slice(&self.inputs_state);
        v.extend_from_slice(&self.outputs_state);
        v.extend_from_slice(&position_limbs(self.first_output_position));
        v.extend_from_slice(&position_limbs(self.end_output_position));
        v.extend_from_slice(&limbs16(self.subsidy));
        v.push(Fp::new(self.height));
        v.extend_from_slice(&self.names_state);
        v.extend_from_slice(&self.sweeps_state);
        v.extend_from_slice(&self.parent_hash);
        debug_assert_eq!(v.len(), ST_WORK);
        v.extend(self.parent_work.to_values(shape));
        debug_assert_eq!(v.len(), ST_WORK + shape.num_public());
        v
    }

    /// Output digest of a root whose tree digest is `tree`, and of the
    /// wrap (see [`wrap_tree`]).
    pub fn output(&self, shape: &WorkShape, tree: &Digest) -> Digest {
        let mut v = self.to_values(shape);
        v.extend_from_slice(tree);
        crate::poseidon2::hash(&v)
    }
}

/// Descriptor tag of a segment child.
pub(crate) const SEGMENT_TAG: u32 = 0x41;
/// Descriptor tag of the root's name segment child.
pub(crate) const NAME_TAG: u32 = 0x42;
/// Descriptor tag of the root's work segment child.
pub(crate) const WORK_TAG: u32 = 0x43;
/// Scalars per child descriptor.
pub(crate) const DESCRIPTOR: usize = 2 * DIGEST;

fn describe(v: &mut Vec<Fp>, children: &[Option<(Digest, Digest)>]) {
    for ch in children {
        match ch {
            None => {
                v.push(Fp::new(SEGMENT_TAG));
                v.extend_from_slice(&[Fp::ZERO; DESCRIPTOR - 1]);
            }
            Some((digest, tree)) => {
                v.extend_from_slice(digest);
                v.extend_from_slice(tree);
            }
        }
    }
}

/// Tree digest of a node: the hash of one descriptor per child, a segment
/// `[SEGMENT_TAG, 0, ..]` and a node its program digest and tree digest
/// (`Some((digest, tree))`). It commits to every program below the node,
/// which the node itself takes from its children's proofs unchecked.
pub fn tree_digest(children: &[Option<(Digest, Digest)>]) -> Digest {
    let mut v = Vec::with_capacity(DESCRIPTOR * children.len());
    describe(&mut v, children);
    crate::poseidon2::hash(&v)
}

/// Tree digest of the root: its children's descriptors, then the name
/// segment's `[NAME_TAG, 0, ..]` and the work segment's `[WORK_TAG, 0, ..]`.
pub fn root_tree_digest(children: &[Option<(Digest, Digest)>]) -> Digest {
    let mut v = Vec::with_capacity(DESCRIPTOR * (children.len() + 2));
    describe(&mut v, children);
    for tag in [NAME_TAG, WORK_TAG] {
        v.push(Fp::new(tag));
        v.extend_from_slice(&[Fp::ZERO; DESCRIPTOR - 1]);
    }
    crate::poseidon2::hash(&v)
}

/// The wrap's tree digest: that of a node with the root as its one child.
pub fn wrap_tree(root_digest: &Digest, root_tree: &Digest) -> Digest {
    tree_digest(&[Some((*root_digest, *root_tree))])
}

/// Output digest of an inner node: its record and tree digest.
pub fn node_output(record: &SegmentPublic, tree: &Digest) -> Digest {
    let mut v = record.to_values().to_vec();
    v.extend_from_slice(tree);
    crate::poseidon2::hash(&v)
}

/// The span covered by consecutive records: first in, last out, summed
/// limbs.
pub fn combine_records(records: &[SegmentPublic]) -> SegmentPublic {
    let (first, last) = (&records[0], &records[records.len() - 1]);
    // Sums are normalized to 16-bit limbs, as the node program does.
    let normal = |f: fn(&SegmentPublic) -> &[u32; LIMBS]| -> [u32; LIMBS] {
        let total: u128 = records.iter().map(|r| SegmentPublic::total(f(r))).sum();
        limbs16_wide(total).map(|x| x.to_canonical())
    };
    SegmentPublic {
        height: first.height,
        root_in: first.root_in,
        root_out: last.root_out,
        isp_in: first.isp_in,
        isp_out: last.isp_out,
        osp_in: first.osp_in,
        osp_out: last.osp_out,
        nsp_in: first.nsp_in,
        nsp_out: last.nsp_out,
        pos_in: first.pos_in,
        pos_out: last.pos_out,
        sum_in: normal(|r| &r.sum_in),
        sum_out: normal(|r| &r.sum_out),
        carry_in: first.carry_in,
        carry_out: last.carry_out,
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use crate::block::Header;
use crate::block_air::{
    BlockAir, CARRY_LEN, NUM_PUBLIC as SEGMENT_PUBLIC, PUB_CARRY_IN, PUB_CARRY_OUT, PUB_HEIGHT, PUB_ISP_IN,
    PUB_ISP_OUT, PUB_NSP_IN, PUB_NSP_OUT, PUB_OSP_IN, PUB_OSP_OUT, PUB_POS_IN, PUB_POS_OUT, PUB_ROOT_IN, PUB_ROOT_OUT,
    PUB_SUM_IN, PUB_SUM_OUT, ROWS_PER_OUTPUT, SegmentWitness, initial_inputs_state, initial_names_state,
    initial_outputs_state,
};
use crate::block_proof::{
    DOM_NAME_PROOF, DOM_SEGMENT_PROOF, NameProof, SegmentProof, prove_name_padded, prove_segment_padded,
};
use crate::chain::verify::ProofVerifier;
use crate::chain_verifier::DOM_CHAIN_PROOF;
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::Fp4;
use crate::hash_table::HashTableAir;
use crate::name::OpKind;
use crate::name_air::{
    NUM_PUBLIC as NAME_PUBLIC, NameAir, NamePublic, NameWitness, PUB_COUNTS as NM_COUNTS, PUB_HEIGHT as NM_HEIGHT,
    PUB_NSP as NM_NSP, PUB_POS_IN as NM_POS_IN, PUB_POS_OUT as NM_POS_OUT, PUB_ROOT_IN as NM_ROOT_IN,
    PUB_ROOT_OUT as NM_ROOT_OUT, PUB_SSP as NM_SSP,
};
use crate::poseidon2::P;
use crate::pow_air::{DOM_WORK_PROOF, RangeAir, TextAir};
use crate::recursion::{Compiler, dummy_proof};
use crate::stark::{self, Preprocessed};
use crate::vm_air::{Addr, NUM_PUBLIC as VM_PUBLIC, PUB_OUTPUT, Program, VmAir};

/// Transcript domain separator for node (aggregate) proofs.
const DOM_AGGREGATE_PROOF: u32 = 0x31;
/// Transcript domain separator for the wrap proof.
const DOM_WRAP_PROOF: u32 = 0x32;

fn outer_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_AGGREGATE_PROOF));
    c
}

fn wrap_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_WRAP_PROOF));
    c
}

const CARRY_BITS: usize = 14;

/// Normalizes limb sums to 16-bit limbs with hinted, range-checked
/// carries; the top limb must fit 16 bits on its own, so the value is
/// below `2^96`. A normalized form is unique, so two of them are equal
/// exactly when the integers are.
fn normalize(c: &mut Compiler, sums: &[Addr; LIMBS]) -> [Addr; LIMBS] {
    let two16 = c.scalar(Fp::new(1 << 16));
    let mut out = [0; LIMBS];
    let mut carry: Option<Addr> = None;
    for j in 0..LIMBS {
        let d = match carry {
            Some(cp) => c.add(sums[j], cp),
            None => sums[j],
        };
        if j + 1 == LIMBS {
            c.assert_bits_zero_from(d, 16);
            out[j] = d;
            break;
        }
        let v = c.val(d).0[0].to_canonical();
        let r = c.input(Fp4::from_base(Fp::new(v & 0xffff)));
        let cj = c.input(Fp4::from_base(Fp::new(v >> 16)));
        c.assert_bits_zero_from(r, 16);
        c.assert_bits_zero_from(cj, CARRY_BITS);
        let back = c.muladd(cj, two16, r);
        c.assert_eq(back, d);
        out[j] = r;
        carry = Some(cj);
    }
    out
}

/// Limb sums of field `field` over `recs`, plus `extra` limbs if given.
fn sum_limbs(c: &mut Compiler, recs: &[Addr], field: usize, extra: Option<Addr>) -> [Addr; LIMBS] {
    core::array::from_fn(|j| {
        let mut acc = extra.map_or(0, |e| e + j as Addr);
        for &r in recs {
            acc = c.add(acc, r + (field + j) as Addr);
        }
        acc
    })
}

/// A proven node: its span record and machine proof, with the program it
/// ran.
#[derive(Clone, Debug)]
pub struct NodeProof {
    pub record: SegmentPublic,
    /// Program digest.
    pub digest: Digest,
    /// Tree digest: the programs below.
    pub tree: Digest,
    pub proof: stark::Proof,
}

/// A child of a node program.
pub enum Child<'a> {
    Segment(&'a SegmentProof),
    Node(&'a NodeProof),
}

impl Child<'_> {
    fn record(&self) -> SegmentPublic {
        match self {
            Child::Segment(s) => s.public,
            Child::Node(n) => n.record,
        }
    }
}

/// What a node program outputs, along with its tree digest.
pub enum Output<'a> {
    /// The combined span record (inner nodes).
    Record,
    /// The block statement, after binding the span, the name segment and
    /// the parent's work segment to it (the root).
    Statement(&'a Statement, &'a NameProof, &'a WorkProof),
}

/// Copies `words` into a fresh block, zero padded to a multiple of eight,
/// for hashing.
fn concat(c: &mut Compiler, words: &[Addr]) -> Addr {
    let padded = words.len().div_ceil(8).max(1) * 8;
    let base = c.prog.alloc(padded as u32);
    for i in 0..padded {
        let src = words.get(i).copied().unwrap_or(0);
        let v = c.val(src);
        c.prog.muladd_to(src, 1, 0, base + i as Addr);
        c.set_word(base + i as Addr, v);
    }
    base
}

/// Builds a node program over `children`, along with the witness.
pub fn compile_node(params: &AggregatorParams, children: &[Child<'_>], output: Output<'_>) -> Compiler {
    let k = children.len();
    assert!(k >= 1 && k <= params.fan_in, "child count {k} out of range");
    // The bound behind CARRY_BITS: a limb sum over the children (each at
    // most a segment's items of 16 bits), the subsidy and a carry.
    let items = (params.segment_rows() / ROWS_PER_OUTPUT + 1) as u64;
    let limb_sum = ((params.fan_in as u64 * items + 1) << 16) + (1 << CARRY_BITS);
    assert!(limb_sum >> 16 < 1 << CARRY_BITS && (1u64 << (16 + CARRY_BITS)) + limb_sum < P as u64);
    let mut c = Compiler::new();
    let at = |base: Addr, field: usize| base + field as Addr;

    // Each child: its record as inputs, then its proof; and its
    // descriptor for the tree digest.
    let seg_prefix = [Fp::new(DOM_SEGMENT_PROOF)];
    let mut recs: Vec<Addr> = Vec::with_capacity(k);
    let mut descriptors: Vec<Addr> = Vec::with_capacity(k * DESCRIPTOR);
    for child in children {
        match child {
            Child::Segment(sp) => {
                let rec = c.scalar_inputs(&child.record().to_values());
                assert_eq!(sp.proof.tables[0].log_n, params.segment_log_n, "segment proof has the wrong height");
                c.verify_stark(&[(&BlockAir, None)], &params.segment, &seg_prefix, rec, SEGMENT_PUBLIC, &sp.proof);
                let tag = c.scalar(Fp::new(SEGMENT_TAG));
                descriptors.push(tag);
                descriptors.extend([0; DESCRIPTOR - 1]);
                recs.push(rec);
            }
            Child::Node(np) => {
                let (rec, pubv) = verify_node_child(&mut c, params, np, |c, np| {
                    let mut v = np.record.to_values().to_vec();
                    v.extend_from_slice(&np.tree);
                    let rec = c.scalar_inputs(&v);
                    (rec, SEGMENT_PUBLIC + DIGEST, node_output(&np.record, &np.tree))
                });
                descriptors.extend((0..DIGEST as Addr).map(|i| pubv + i));
                descriptors.extend((0..DIGEST).map(|i| at(rec, SEGMENT_PUBLIC + i)));
                recs.push(rec);
            }
        }
    }
    // Chaining between consecutive children.
    for w in recs.windows(2) {
        let (a, b) = (w[0], w[1]);
        c.assert_block(at(a, PUB_ROOT_OUT), at(b, PUB_ROOT_IN), DIGEST);
        c.assert_block(at(a, PUB_ISP_OUT), at(b, PUB_ISP_IN), WIDTH);
        c.assert_block(at(a, PUB_OSP_OUT), at(b, PUB_OSP_IN), WIDTH);
        c.assert_block(at(a, PUB_NSP_OUT), at(b, PUB_NSP_IN), WIDTH);
        c.assert_block(at(a, PUB_POS_OUT), at(b, PUB_POS_IN), 2);
        c.assert_block(at(a, PUB_CARRY_OUT), at(b, PUB_CARRY_IN), CARRY_LEN);
        c.assert_eq(at(a, PUB_HEIGHT), at(b, PUB_HEIGHT));
    }
    let (first, last) = (recs[0], recs[k - 1]);

    match output {
        Output::Record => {
            let block = concat(&mut c, &descriptors);
            c.hash_scalars(block, descriptors.len());
            let tree = c.squeeze_digest();
            // Combined record: copies of the boundary fields, summed limbs;
            // then the tree digest.
            let padded = (SEGMENT_PUBLIC + DIGEST).div_ceil(8) * 8;
            let out = c.prog.alloc(padded as u32);
            let copy = |c: &mut Compiler, src: Addr, dst: usize, n: usize| {
                for i in 0..n {
                    let v = c.val(src + i as Addr);
                    c.prog.muladd_to(src + i as Addr, 1, 0, at(out, dst + i));
                    c.set_word(at(out, dst + i), v);
                }
            };
            copy(&mut c, at(first, PUB_ROOT_IN), PUB_ROOT_IN, DIGEST);
            copy(&mut c, at(last, PUB_ROOT_OUT), PUB_ROOT_OUT, DIGEST);
            copy(&mut c, at(first, PUB_ISP_IN), PUB_ISP_IN, WIDTH);
            copy(&mut c, at(last, PUB_ISP_OUT), PUB_ISP_OUT, WIDTH);
            copy(&mut c, at(first, PUB_OSP_IN), PUB_OSP_IN, WIDTH);
            copy(&mut c, at(last, PUB_OSP_OUT), PUB_OSP_OUT, WIDTH);
            copy(&mut c, at(first, PUB_NSP_IN), PUB_NSP_IN, WIDTH);
            copy(&mut c, at(last, PUB_NSP_OUT), PUB_NSP_OUT, WIDTH);
            copy(&mut c, at(first, PUB_POS_IN), PUB_POS_IN, 2);
            copy(&mut c, at(last, PUB_POS_OUT), PUB_POS_OUT, 2);
            copy(&mut c, at(first, PUB_CARRY_IN), PUB_CARRY_IN, CARRY_LEN);
            copy(&mut c, at(last, PUB_CARRY_OUT), PUB_CARRY_OUT, CARRY_LEN);
            copy(&mut c, at(first, PUB_HEIGHT), PUB_HEIGHT, 1);
            for field in [PUB_SUM_IN, PUB_SUM_OUT] {
                let sums = sum_limbs(&mut c, &recs, field, None);
                let limbs = normalize(&mut c, &sums);
                for (j, &l) in limbs.iter().enumerate() {
                    let v = c.val(l);
                    c.prog.muladd_to(l, 1, 0, at(out, field + j));
                    c.set_word(at(out, field + j), v);
                }
            }
            for i in 0..DIGEST {
                let v = c.val(tree + i as Addr);
                c.prog.muladd_to(tree + i as Addr, 1, 0, at(out, SEGMENT_PUBLIC + i));
                c.set_word(at(out, SEGMENT_PUBLIC + i), v);
            }
            for i in SEGMENT_PUBLIC + DIGEST..padded {
                c.prog.muladd_to(0, 1, 0, at(out, i));
                c.set_word(at(out, i), Fp4::ZERO);
            }
            c.hash_scalars(out, SEGMENT_PUBLIC + DIGEST);
            c.assert_public();
        }
        Output::Statement(statement, name, work) => {
            // The name segment: its record as inputs, then its proof, and
            // its descriptor last in the tree digest.
            let nm = c.scalar_inputs(&name.public.to_values());
            assert_eq!(name.proof.tables[0].log_n, params.name_log_n, "name segment proof has the wrong height");
            let name_prefix = [Fp::new(DOM_NAME_PROOF)];
            c.verify_stark(
                &[(&NameAir::of(params.min_reveal), None)],
                &params.segment,
                &name_prefix,
                nm,
                NAME_PUBLIC,
                &name.proof,
            );
            let tag = c.scalar(Fp::new(NAME_TAG));
            descriptors.push(tag);
            descriptors.extend([0; DESCRIPTOR - 1]);
            // The work segment: the parent's work as inputs, then its proof
            // against the window table, a constant of the program; its
            // descriptor after the name segment's.
            let wk = c.scalar_inputs(&work.work.to_values(&params.work_shape()));
            let setup = params.work_setup();
            let heights: Vec<usize> = work.proof.tables.iter().map(|t| t.log_n).collect();
            assert_eq!(heights, setup.shape.log_heights(), "work segment proof has the wrong heights");
            let text_root = c.scalar_inputs(&setup.root());
            for (i, v) in setup.root().iter().enumerate() {
                c.assert_scalar(text_root + i as Addr, *v);
            }
            let (perm, mix) = (setup.shape.perm_air(), setup.shape.mix_air());
            let tables: [(&dyn stark::DynAir, Option<Addr>); 4] =
                [(&TextAir, Some(text_root)), (&perm, None), (&RangeAir, None), (&mix, None)];
            c.verify_stark(
                &tables,
                &params.segment,
                &[Fp::new(DOM_WORK_PROOF)],
                wk,
                params.work_shape().num_public(),
                &work.proof,
            );
            let tag = c.scalar(Fp::new(WORK_TAG));
            descriptors.push(tag);
            descriptors.extend([0; DESCRIPTOR - 1]);
            let block = concat(&mut c, &descriptors);
            c.hash_scalars(block, descriptors.len());
            let tree = c.squeeze_digest();

            let st = c.scalar_inputs(&statement.to_values(&params.work_shape()));
            // The span starts at the block's previous state and the fixed
            // initial list states, and ends at the statement's.
            c.assert_block(at(first, PUB_ROOT_IN), at(st, ST_PREV), DIGEST);
            for (i, v) in initial_inputs_state().iter().enumerate() {
                c.assert_scalar(at(first, PUB_ISP_IN + i), *v);
            }
            for (i, v) in initial_outputs_state().iter().enumerate() {
                c.assert_scalar(at(first, PUB_OSP_IN + i), *v);
            }
            for (i, v) in initial_names_state().iter().enumerate() {
                c.assert_scalar(at(first, PUB_NSP_IN + i), *v);
            }
            c.assert_block(at(first, PUB_POS_IN), at(st, ST_POS_IN), 2);
            c.assert_block(at(last, PUB_ISP_OUT), at(st, ST_ISP), WIDTH);
            c.assert_block(at(last, PUB_OSP_OUT), at(st, ST_OSP), WIDTH);
            c.assert_block(at(last, PUB_NSP_OUT), at(st, ST_NSP), WIDTH);
            // The name segment continues from the last segment to the
            // statement's end: root, position, and the operations it
            // applied are the ones the transactions carried.
            c.assert_block(at(nm, NM_ROOT_IN), at(last, PUB_ROOT_OUT), DIGEST);
            c.assert_block(at(nm, NM_ROOT_OUT), at(st, ST_NEW), DIGEST);
            c.assert_block(at(nm, NM_POS_IN), at(last, PUB_POS_OUT), 2);
            c.assert_block(at(nm, NM_POS_OUT), at(st, ST_POS_OUT), 2);
            c.assert_block(at(nm, NM_NSP), at(st, ST_NSP), WIDTH);
            c.assert_block(at(nm, NM_SSP), at(st, ST_SSP), WIDTH);
            c.assert_eq(at(nm, NM_HEIGHT), at(st, ST_HEIGHT));
            // The work proven is the statement's parent work.
            c.assert_block(wk, at(st, ST_WORK), params.work_shape().num_public());
            // Every transaction segment created its outputs at the block's
            // height.
            c.assert_eq(at(first, PUB_HEIGHT), at(st, ST_HEIGHT));
            // Operation counts within the caps: the count is one of 0..=cap.
            for (k, kind) in [OpKind::Commit, OpKind::Reveal, OpKind::Update, OpKind::Sweep].into_iter().enumerate() {
                let count = at(nm, NM_COUNTS + k);
                let mut product = c.scalar(Fp::ONE);
                for i in 0..=kind.cap() {
                    let v = c.scalar(Fp::new(i as u32));
                    let term = c.sub(count, v);
                    product = c.mul(product, term);
                }
                c.assert_eq(product, 0);
            }
            // No transaction is open at either end.
            for i in 0..CARRY_LEN {
                c.assert_eq(at(first, PUB_CARRY_IN + i), 0);
                c.assert_eq(at(last, PUB_CARRY_OUT + i), 0);
            }

            // Balance: the inputs plus the subsidy equal the outputs, as
            // integers: both normalized, then compared limb by limb.
            let ins = sum_limbs(&mut c, &recs, PUB_SUM_IN, Some(at(st, ST_SUBSIDY)));
            let outs = sum_limbs(&mut c, &recs, PUB_SUM_OUT, None);
            let (ins, outs) = (normalize(&mut c, &ins), normalize(&mut c, &outs));
            for (a, b) in ins.iter().zip(&outs) {
                c.assert_eq(*a, *b);
            }

            let words: Vec<Addr> =
                (0..params.statement_len()).map(|i| at(st, i)).chain((0..DIGEST).map(|i| tree + i as Addr)).collect();
            let block = concat(&mut c, &words);
            c.hash_scalars(block, words.len());
            c.assert_public();
        }
    }
    c
}

/// Verifies a node child's machine proof under the program digest its
/// public values claim, which the caller commits to in a tree digest.
/// `inputs` lays out the values the child's output digest covers and
/// returns their address, length and the expected digest. Returns that
/// address and the child's public values.
fn verify_node_child(
    c: &mut Compiler,
    params: &AggregatorParams,
    np: &NodeProof,
    inputs: impl FnOnce(&mut Compiler, &NodeProof) -> (Addr, usize, Digest),
) -> (Addr, Addr) {
    let (base, len, output) = inputs(c, np);
    let pubv = c.scalar_inputs(&VmAir::public_values(&np.digest, &output));
    c.hash_scalars(base, len);
    let out = c.squeeze_digest();
    c.assert_block(pubv + PUB_OUTPUT as Addr, out, DIGEST);
    let tables: [(&dyn stark::DynAir, Option<Addr>); 2] = [(&VmAir, Some(pubv)), (&HashTableAir, None)];
    let node_prefix = [Fp::new(DOM_AGGREGATE_PROOF)];
    c.verify_stark(&tables, &params.outer, &node_prefix, pubv, VM_PUBLIC, &np.proof);
    (base, pubv)
}

/// Builds the wrap program: verifies the root's machine proof (at
/// `params.outer`) and outputs the statement with the wrap's tree digest
/// ([`wrap_tree`]), so the block's proof can be a single proof at the
/// lower rate of `params.wrap`. Like every node, it depends only on the
/// root's table heights. `pad`, the heights every wrap is padded to (the
/// chain program verifies all of them at one set of heights), is `None`
/// only when finding those heights.
pub fn compile_wrap(
    params: &AggregatorParams,
    root: &NodeProof,
    statement: &Statement,
    pad: Option<(usize, usize)>,
) -> Compiler {
    let mut c = Compiler::new();
    let (st, pubv) = verify_node_child(&mut c, params, root, |c, root| {
        let mut v = statement.to_values(&params.work_shape());
        v.extend_from_slice(&root.tree);
        (c.scalar_inputs(&v), params.statement_len() + DIGEST, statement.output(&params.work_shape(), &root.tree))
    });
    let words: Vec<Addr> = (0..DIGEST as Addr)
        .map(|i| pubv + i)
        .chain((0..DIGEST).map(|i| st + (params.statement_len() + i) as Addr))
        .collect();
    let block = concat(&mut c, &words);
    c.hash_scalars(block, DESCRIPTOR);
    let tree = c.squeeze_digest();
    let words: Vec<Addr> =
        (0..params.statement_len()).map(|i| st + i as Addr).chain((0..DIGEST).map(|i| tree + i as Addr)).collect();
    let block = concat(&mut c, &words);
    c.hash_scalars(block, words.len());
    c.assert_public();
    c.prog.reserve(params.wrap.blind_rows());
    if let Some((log_n, hash_log_n)) = pad {
        c.prog.pad_to(log_n, hash_log_n);
    }
    c
}

// ---------------------------------------------------------------------------
// Tree planning
// ---------------------------------------------------------------------------

/// The shape of a node: its children (a child with no children of its own
/// is a segment proof), the segments under it, and the program digest and
/// table heights a node of this shape has.
#[derive(Clone, Debug)]
pub struct Shape {
    pub children: Vec<Shape>,
    /// Segments under this node.
    pub segments: usize,
    pub digest: Digest,
    pub log_n: usize,
    /// Log height of the node's hash table.
    pub hash_log_n: usize,
    /// Tree digest: the programs below ([`tree_digest`]).
    pub tree: Digest,
    /// The wrap program over this node, for the root.
    pub wrap: Option<Wrap>,
}

/// Program digest and table heights of the wrap over a root, and its tree
/// digest ([`wrap_tree`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wrap {
    pub digest: Digest,
    pub log_n: usize,
    pub hash_log_n: usize,
    pub tree: Digest,
}

impl Shape {
    pub fn is_segment(&self) -> bool {
        self.children.is_empty()
    }
}

/// Splits `k > fan_in` segments into full subtrees of `u` segments, `u`
/// the largest power of `fan_in` below `k`, and the remainder. Full
/// subtrees of a size have one shape whatever `k` is, so planning a new
/// segment count only plans the remainder's path. At most `fan_in`
/// groups, at least two, each smaller than `k`.
fn split(k: usize, fan_in: usize) -> Vec<usize> {
    debug_assert!(k > fan_in && fan_in >= 2);
    let mut u = 1;
    while u * fan_in < k {
        u *= fan_in;
    }
    let mut groups = vec![u; k / u];
    if !k.is_multiple_of(u) {
        groups.push(k % u);
    }
    groups
}

/// What a node program depends on: whether it is the root, and per child
/// whether it is a segment (`None`) or a node with the given table heights.
type NodeType = (bool, Vec<Option<(usize, usize)>>);

/// Program digest and table heights of a compiled program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Compiled {
    digest: Digest,
    log_n: usize,
    hash_log_n: usize,
}

impl Compiled {
    fn of(prog: &Program, log_blowup: usize) -> Compiled {
        Compiled {
            digest: prog.digest(log_blowup),
            log_n: prog.height().trailing_zeros() as usize,
            hash_log_n: VmAir::hash_height(prog).trailing_zeros() as usize,
        }
    }
}

/// Node and wrap programs compiled so far, by type. There are few types
/// (child kinds and heights), so a cache warmed by a few plans makes
/// planning any segment count a matter of hashing.
#[derive(Default)]
pub struct PlanCache {
    nodes: HashMap<NodeType, Compiled>,
    wraps: HashMap<(usize, usize), Compiled>,
    /// The heights every wrap is padded to ([`wrap_pad`]).
    wrap_pad: Option<(usize, usize)>,
}

impl PlanCache {
    pub fn new() -> PlanCache {
        PlanCache::default()
    }

    /// Programs compiled so far.
    pub fn len(&self) -> usize {
        self.nodes.len() + self.wraps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Plans the tree for `k` segments: its shape, every node's program digest
/// and heights, and the tree digests.
pub fn plan(params: &AggregatorParams, k: usize) -> Shape {
    plan_with(params, k, &mut PlanCache::new())
}

/// As [`plan`], compiling only the program types `cache` lacks.
pub fn plan_with(params: &AggregatorParams, k: usize, cache: &mut PlanCache) -> Shape {
    assert!(k >= 1 && k <= params.max_segments, "segment count {k} out of range");
    let pad = wrap_pad(params, cache);
    let mut root = plan_node(params, k, true, cache);
    let wrap = *cache.wraps.entry((root.log_n, root.hash_log_n)).or_insert_with(|| {
        let dummy = dummy_root(params, &root);
        Compiled::of(
            &compile_wrap(params, &dummy, &Statement::zero(&params.work_shape()), Some(pad)).prog,
            params.wrap.log_blowup,
        )
    });
    root.wrap = Some(Wrap {
        digest: wrap.digest,
        log_n: wrap.log_n,
        hash_log_n: wrap.hash_log_n,
        tree: wrap_tree(&root.digest, &root.tree),
    });
    root
}

/// A root proof of `root`'s heights with zero values, for planning.
fn dummy_root(params: &AggregatorParams, root: &Shape) -> NodeProof {
    NodeProof {
        record: dummy_record(),
        digest: [Fp::ZERO; DIGEST],
        tree: [Fp::ZERO; DIGEST],
        proof: dummy_proof(&[(&VmAir, root.log_n), (&HashTableAir, root.hash_log_n)], &params.outer, VM_PUBLIC),
    }
}

/// The heights every wrap is padded to: those of the wrap over a root as
/// tall as the tallest of the roots over 1 to `fan_in` segments (segment
/// children only) and over `max_segments` (the largest subtrees), table by
/// table. A wrap depends only on its root's heights, and every other root
/// mixes such children; a count whose wrap needs more rows all the same is
/// caught by [`plan_leaves`].
fn wrap_pad(params: &AggregatorParams, cache: &mut PlanCache) -> (usize, usize) {
    if let Some(pad) = cache.wrap_pad {
        return pad;
    }
    let mut root = plan_node(params, params.max_segments, true, cache);
    for k in 1..=params.fan_in.min(params.max_segments) {
        let r = plan_node(params, k, true, cache);
        root.log_n = root.log_n.max(r.log_n);
        root.hash_log_n = root.hash_log_n.max(r.hash_log_n);
    }
    let p = compile_wrap(params, &dummy_root(params, &root), &Statement::zero(&params.work_shape()), None).prog;
    let pad = (p.height().trailing_zeros() as usize, VmAir::hash_height(&p).trailing_zeros() as usize);
    cache.wrap_pad = Some(pad);
    pad
}

fn dummy_record() -> SegmentPublic {
    SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap()
}

/// A work segment proof of the right shape with zero values, for planning.
fn dummy_work(params: &AggregatorParams) -> WorkProof {
    let setup = params.work_setup();
    let (perm, mix) = (setup.shape.perm_air(), setup.shape.mix_air());
    let h = setup.shape.log_heights();
    let tables: [(&dyn stark::DynAir, usize); 4] = [(&TextAir, h[0]), (&perm, h[1]), (&RangeAir, h[2]), (&mix, h[3])];
    WorkProof {
        work: zero_work(&params.work_shape()),
        proof: dummy_proof(&tables, &params.segment, params.work_shape().num_public()),
    }
}

/// A name segment proof of the right shape with zero values, for planning.
fn dummy_name(params: &AggregatorParams) -> NameProof {
    NameProof {
        public: NamePublic::from_values(&vec![Fp::ZERO; NAME_PUBLIC]).unwrap(),
        proof: dummy_proof(&[(&NameAir::of(params.min_reveal), params.name_log_n)], &params.segment, NAME_PUBLIC),
    }
}

fn plan_node(params: &AggregatorParams, k: usize, root: bool, cache: &mut PlanCache) -> Shape {
    if k == 1 && !root {
        return Shape {
            children: vec![],
            segments: 1,
            digest: [Fp::ZERO; DIGEST],
            log_n: params.segment_log_n,
            hash_log_n: 0,
            tree: [Fp::ZERO; DIGEST],
            wrap: None,
        };
    }
    let sizes = if k <= params.fan_in { vec![1; k] } else { split(k, params.fan_in) };
    // Equal sizes plan equally; full subtrees repeat.
    let mut children: Vec<Shape> = Vec::with_capacity(sizes.len());
    for (i, &n) in sizes.iter().enumerate() {
        let shape = match sizes[..i].iter().position(|&m| m == n) {
            Some(j) => children[j].clone(),
            None => plan_node(params, n, false, cache),
        };
        children.push(shape);
    }
    let kinds: Vec<Option<(usize, usize)>> =
        children.iter().map(|c| (!c.is_segment()).then_some((c.log_n, c.hash_log_n))).collect();
    let compiled = *cache.nodes.entry((root, kinds.clone())).or_insert_with(|| {
        let segment_dummy = SegmentProof {
            public: dummy_record(),
            proof: dummy_proof(&[(&BlockAir, params.segment_log_n)], &params.segment, SEGMENT_PUBLIC),
        };
        let node_dummies: Vec<NodeProof> = kinds
            .iter()
            .flatten()
            .map(|&(log_n, hash_log_n)| NodeProof {
                record: dummy_record(),
                digest: [Fp::ZERO; DIGEST],
                tree: [Fp::ZERO; DIGEST],
                proof: dummy_proof(&[(&VmAir, log_n), (&HashTableAir, hash_log_n)], &params.outer, VM_PUBLIC),
            })
            .collect();
        let mut nd = node_dummies.iter();
        let child_refs: Vec<Child<'_>> = kinds
            .iter()
            .map(|kind| if kind.is_none() { Child::Segment(&segment_dummy) } else { Child::Node(nd.next().unwrap()) })
            .collect();
        let zero = Statement::zero(&params.work_shape());
        let name_dummy = dummy_name(params);
        let work_dummy = if root { Some(dummy_work(params)) } else { None };
        let output = match &work_dummy {
            Some(w) => Output::Statement(&zero, &name_dummy, w),
            None => Output::Record,
        };
        Compiled::of(&compile_node(params, &child_refs, output).prog, params.outer.log_blowup)
    });
    let descriptors: Vec<Option<(Digest, Digest)>> =
        children.iter().map(|c| (!c.is_segment()).then_some((c.digest, c.tree))).collect();
    Shape {
        segments: k,
        digest: compiled.digest,
        log_n: compiled.log_n,
        hash_log_n: compiled.hash_log_n,
        tree: if root { root_tree_digest(&descriptors) } else { tree_digest(&descriptors) },
        wrap: None,
        children,
    }
}

// ---------------------------------------------------------------------------
// Proving and verifying
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    Malformed,
    /// Segment count is zero or above the maximum.
    BadSegmentCount(usize),
    /// The machine proof does not verify against the expected program and
    /// statement digests.
    Rejected,
}

/// A step of [`prove_block_with`], reported as it completes.
#[derive(Clone, Copy, Debug)]
pub enum Progress {
    /// Segment `index` of `count` is proven.
    Segment { index: usize, count: usize, elapsed: std::time::Duration },
    /// The name segment is proven.
    Name { elapsed: std::time::Duration },
    /// The parent's work is proven.
    Work { elapsed: std::time::Duration },
    /// A node over `segments` segments is proven; `root` for the last one.
    Node { segments: usize, log_n: usize, hash_log_n: usize, root: bool, elapsed: std::time::Duration },
    /// The wrap over the root is proven.
    Wrap { log_n: usize, hash_log_n: usize, elapsed: std::time::Duration },
    /// The chain step over the wrap and the previous block's proof.
    Chain { elapsed: std::time::Duration },
}

/// Recently used committed programs, most recent last. A program type's
/// table is the same in every block, and committing it costs about as much
/// as a trace column set, so the last few are kept (a few hundred MB each).
static PROGRAMS: Mutex<Vec<(Digest, Arc<Preprocessed>)>> = Mutex::new(Vec::new());
const CACHED_PROGRAMS: usize = 4;

/// The commitment to `prog` at `log_blowup`, whose digest the plan says is
/// `digest`; from the cache when it was committed recently.
fn committed_program(prog: &Program, config: &StarkConfig, digest: &Digest) -> Arc<Preprocessed> {
    {
        let mut cache = PROGRAMS.lock().unwrap();
        if let Some(i) = cache.iter().position(|(d, _)| d == digest) {
            let entry = cache.remove(i);
            let pre = entry.1.clone();
            cache.push(entry);
            debug_assert_eq!(pre.table().values, prog.table().values, "program differs from the planned shape");
            return pre;
        }
    }
    let pre = Arc::new(prog.preprocess(config));
    assert_eq!(pre.root(), *digest, "program differs from the planned shape");
    let mut cache = PROGRAMS.lock().unwrap();
    cache.push((*digest, pre.clone()));
    if cache.len() > CACHED_PROGRAMS {
        cache.remove(0);
    }
    pre
}

/// Proves one node of the tree over `segments[..shape.segments]`; `None`
/// if `cancel` fired.
fn prove_node(
    params: &AggregatorParams,
    shape: &Shape,
    segments: &[SegmentProof],
    output: Output<'_>,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: stark::Cancel<'_>,
) -> Option<NodeProof> {
    let mut nodes: Vec<Option<NodeProof>> = Vec::with_capacity(shape.children.len());
    let mut at = 0;
    for child in &shape.children {
        let slice = &segments[at..at + child.segments];
        at += child.segments;
        nodes.push(if child.is_segment() {
            None
        } else {
            Some(prove_node(params, child, slice, Output::Record, progress, cancel)?)
        });
    }
    if cancel() {
        return None;
    }
    let t = std::time::Instant::now();
    let root = matches!(output, Output::Statement(..));
    let mut at = 0;
    let children: Vec<Child<'_>> = shape
        .children
        .iter()
        .zip(&nodes)
        .map(|(child, node)| {
            let seg = &segments[at];
            at += child.segments;
            match node {
                Some(n) => Child::Node(n),
                None => Child::Segment(seg),
            }
        })
        .collect();
    let records: Vec<SegmentPublic> = children.iter().map(|c| c.record()).collect();
    let record = combine_records(&records);
    let out_digest = match &output {
        Output::Record => node_output(&record, &shape.tree),
        Output::Statement(s, _, _) => s.output(&params.work_shape(), &shape.tree),
    };
    let c = compile_node(params, &children, output);
    let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).expect("node program rejects its own witness");
    let pre = committed_program(&c.prog, &params.outer, &shape.digest);
    let public = VmAir::public_values(&pre.root(), &out_digest);
    let tables = VmAir::tables(&trace, &hashes, &pre);
    let proof = stark::try_prove_tables(&params.outer, &tables, &public, &mut outer_transcript(), Some(cancel)).ok()?;
    progress(Progress::Node {
        segments: shape.segments,
        log_n: shape.log_n,
        hash_log_n: shape.hash_log_n,
        root,
        elapsed: t.elapsed(),
    });
    Some(NodeProof { record, digest: shape.digest, tree: shape.tree, proof })
}

/// Proves a block: segments in parallel, then the tree. The segments must
/// each fit `params.segment_log_n` rows and the name segment
/// `params.name_log_n`.
pub fn prove_block(
    params: &AggregatorParams,
    statement: &Statement,
    segments: &[SegmentWitness],
    names: &NameWitness,
) -> Vec<u8> {
    prove_block_with(params, &plan(params, segments.len()), statement, segments, names, segments.len(), &|_| {})
}

/// As [`prove_block`], with the tree `shape` already planned for
/// `segments.len()`, at most `jobs` segment provers at a time (each is
/// itself parallel, and a mainnet segment prover holds about a gigabyte),
/// and `progress` called after every segment and node.
pub fn prove_block_with(
    params: &AggregatorParams,
    shape: &Shape,
    statement: &Statement,
    segments: &[SegmentWitness],
    names: &NameWitness,
    jobs: usize,
    progress: &(dyn Fn(Progress) + Sync),
) -> Vec<u8> {
    prove_block_cancellable(params, shape, statement, segments, names, jobs, progress, &|| false)
        .expect("no cancellation")
}

/// As [`prove_block_with`], giving up with `None` once `cancel` returns
/// `true`: before each segment and node, and between the phases of each
/// proof.
#[allow(clippy::too_many_arguments)]
pub fn prove_block_cancellable(
    params: &AggregatorParams,
    shape: &Shape,
    statement: &Statement,
    segments: &[SegmentWitness],
    names: &NameWitness,
    jobs: usize,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: stark::Cancel<'_>,
) -> Option<Vec<u8>> {
    let proof = prove_wrap(params, shape, statement, segments, names, jobs, progress, cancel)?;
    let bytes = proof.to_bytes();
    let mut w = Writer::with_capacity(bytes.len() + 4);
    w.u32(segments.len() as u32);
    w.0.extend_from_slice(&bytes);
    Some(w.finish())
}

/// The last work proof made, by segment configuration: a block template
/// rebuilt on the same parent reuses it.
static LAST_WORK: Mutex<Option<(StarkConfig, WorkProof)>> = Mutex::new(None);

fn cached_work(params: &AggregatorParams, work: &Work) -> Option<WorkProof> {
    match &*LAST_WORK.lock().unwrap() {
        Some((config, p)) if *config == params.segment && p.work == *work => Some(p.clone()),
        _ => None,
    }
}

fn remember_work(params: &AggregatorParams, proof: &WorkProof) {
    *LAST_WORK.lock().unwrap() = Some((params.segment, proof.clone()));
}

/// The wrap proof of a block: segments, the name segment and the parent's
/// work, the tree,
/// then the wrap, as [`prove_block_cancellable`] encodes it.
#[allow(clippy::too_many_arguments)]
pub fn prove_wrap(
    params: &AggregatorParams,
    shape: &Shape,
    statement: &Statement,
    segments: &[SegmentWitness],
    names: &NameWitness,
    jobs: usize,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: stark::Cancel<'_>,
) -> Option<stark::Proof> {
    assert_eq!(shape.segments, segments.len(), "shape planned for a different segment count");
    let count = segments.len();
    // Job `count` is the name segment, job `count + 1` the parent's work
    // (unless proven for an earlier template on the same parent).
    let work_done: Mutex<Option<WorkProof>> = Mutex::new(cached_work(params, &statement.parent_work));
    let jobs_total = if work_done.lock().unwrap().is_some() { count + 1 } else { count + 2 };
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done: Vec<Mutex<Option<SegmentProof>>> = (0..count).map(|_| Mutex::new(None)).collect();
    let name_done: Mutex<Option<NameProof>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..jobs.clamp(1, jobs_total) {
            s.spawn(|| {
                loop {
                    let taken = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if taken >= jobs_total || cancel() {
                        break;
                    }
                    // The work first, if it is a job: the longest one.
                    let index = if jobs_total == count + 2 { (taken + count + 1) % jobs_total } else { taken };
                    let t = std::time::Instant::now();
                    if index == count + 1 {
                        let p = params.prove_work(&statement.parent_work);
                        progress(Progress::Work { elapsed: t.elapsed() });
                        *work_done.lock().unwrap() = Some(p);
                    } else if index == count {
                        let p = prove_name_padded(&params.segment, names, params.name_log_n);
                        progress(Progress::Name { elapsed: t.elapsed() });
                        *name_done.lock().unwrap() = Some(p);
                    } else {
                        let p = prove_segment_padded(&params.segment, &segments[index], params.segment_log_n);
                        progress(Progress::Segment { index, count, elapsed: t.elapsed() });
                        *done[index].lock().unwrap() = Some(p);
                    }
                }
            });
        }
    });
    if cancel() {
        return None;
    }
    let proofs: Vec<SegmentProof> = done.into_iter().map(|m| m.into_inner().unwrap().unwrap()).collect();
    let name_proof = name_done.into_inner().unwrap().unwrap();
    let work_proof = work_done.into_inner().unwrap().unwrap();
    remember_work(params, &work_proof);
    let root =
        prove_node(params, shape, &proofs, Output::Statement(statement, &name_proof, &work_proof), progress, cancel)?;
    let wrap = shape.wrap.expect("shape is a planned root");
    let t = std::time::Instant::now();
    let c = compile_wrap(params, &root, statement, Some((wrap.log_n, wrap.hash_log_n)));
    let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).expect("wrap program rejects its own witness");
    let pre = committed_program(&c.prog, &params.wrap, &wrap.digest);
    let public = VmAir::public_values(&pre.root(), &statement.output(&params.work_shape(), &wrap.tree));
    let tables = VmAir::tables(&trace, &hashes, &pre);
    let proof = stark::try_prove_tables(&params.wrap, &tables, &public, &mut wrap_transcript(), Some(cancel)).ok()?;
    progress(Progress::Wrap { log_n: wrap.log_n, hash_log_n: wrap.hash_log_n, elapsed: t.elapsed() });
    Some(proof)
}

// ---------------------------------------------------------------------------
// Chain proofs
// ---------------------------------------------------------------------------
//
// A chain proof shows that a block and every block before it are valid. The
// chain program verifies the block's wrap proof, under a wrap program and
// tree digest that the plan allows for some segment count (a membership
// path in the Merkle tree of all of them), checks the block's subsidy
// against the emission schedule for its height, and links to the previous
// block's chain proof: the same state root and output position, one less
// height. Height 1 uses a base program that instead starts from the empty
// state. Every chain proof outputs
//
//     H(height || statement || step program digest || plan root)
//
// and a step verifies its predecessor under the step digest it outputs (or
// the base digest at height 2), so a valid proof at height h covers the
// whole chain up to h. The verifier supplies the step digest and the plan
// root it expects, which pins every program involved.

/// Transcript domain separator for chain proofs.
fn chain_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_CHAIN_PROOF));
    c
}

/// The allowed wraps: one leaf `H(wrap digest || wrap tree)` per segment
/// count `1..=max_segments`, padded with empty leaves to a power of two.
///
/// Panics if a count's wrap has other table heights than one segment's:
/// the chain program verifies every wrap at those heights
/// ([`wrap_heights`]), so such a count could never be proven.
pub fn plan_leaves(params: &AggregatorParams, cache: &mut PlanCache) -> Vec<Digest> {
    let heights = wrap_heights(params, cache);
    let mut leaves: Vec<Digest> = (1..=params.max_segments)
        .map(|k| {
            let w = plan_with(params, k, cache).wrap.expect("planned root");
            assert_eq!(
                (w.log_n, w.hash_log_n),
                heights,
                "the wrap of {k} segments has other table heights than one segment's"
            );
            let mut v = w.digest.to_vec();
            v.extend_from_slice(&w.tree);
            crate::poseidon2::hash(&v)
        })
        .collect();
    leaves.resize(params.max_segments.next_power_of_two(), [Fp::ZERO; DIGEST]);
    leaves
}

/// Holds the flags of a work's table to the height the work was done at.
///
/// A header's work is done in the table of its height, and the work's
/// public values say which table by a flag for each doubling it has
/// had ([`crate::pow_air`]). `flags` are those values and `height` the
/// header's height, below `2^30`. The flags are bits, none set after
/// one that is not, so that their sum is the epoch `e`; and the height
/// lies in that epoch: `e E <= height`, and `height < (e + 1) E` unless
/// the epoch is the last, which has no end.
///
/// Each difference is shown not to be below zero by its bits, and how
/// many bits are asked is what makes that so. The first is above
/// `-2^19` (a few epochs' blocks), so below zero it is an element over
/// `2^30`: thirty bits refuse it. The second is above `-2^30` (the
/// height), so below zero it is an element over `2^29` but not always
/// over `2^30`: twenty-nine bits refuse it, and an epoch has fewer
/// blocks than that.
fn table_of_height(c: &mut Compiler, pow: &PowParams, height: Addr, flags: Addr) {
    let growth = (pow.max_log_dataset_items - pow.log_dataset_items) as usize;
    if growth == 0 {
        return;
    }
    assert!(growth as u64 * (pow.epoch_blocks as u64) < 1 << 19 && pow.epoch_blocks < 1 << 28, "the bounds above");
    let flag = |j: usize| flags + j as Addr;
    let mut epoch: Addr = 0;
    for j in 0..growth {
        let f = flag(j);
        let ff = c.mul(f, f);
        c.assert_eq(ff, f);
        if j > 0 {
            // Set only after one that is set.
            let before = c.sub(1, flag(j - 1));
            let gap = c.mul(f, before);
            c.assert_eq(gap, 0);
        }
        epoch = c.add(epoch, f);
    }
    let blocks = c.scalar(Fp::new(pow.epoch_blocks));
    let begins = c.mul(epoch, blocks);
    let since = c.sub(height, begins);
    c.assert_bits_zero_from(since, 30);
    // The epoch's last height, less this one: read only while the last
    // doubling is still to come.
    let ends = c.add(begins, blocks);
    let last = c.sub(ends, 1);
    let left = c.sub(last, height);
    let open = c.sub(1, flag(growth - 1));
    let left = c.mul(open, left);
    c.assert_bits_zero_from(left, 29);
}

/// Output digest of a chain proof.
pub fn chain_output(
    shape: &WorkShape,
    height: u32,
    statement: &Statement,
    step: &Digest,
    plan_root: &Digest,
) -> Digest {
    let mut v = Vec::with_capacity(1 + ST_WORK + shape.num_public() + 2 * DIGEST);
    v.push(Fp::new(height));
    v.extend(statement.to_values(shape));
    v.extend_from_slice(step);
    v.extend_from_slice(plan_root);
    crate::poseidon2::hash(&v)
}

/// The previous block's chain proof, for a step, and its header: the
/// block's parent, whose hash the step recomputes.
pub struct PrevChain<'a> {
    pub height: u32,
    pub statement: &'a Statement,
    pub proof: &'a stark::Proof,
    pub header: &'a Header,
}

/// What the base chain program (height 1) fixes of genesis, the parent of
/// block 1: its hash, and its work as the work segment proves it (its
/// header's `mix` is empty, so the true mix computed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub hash: Digest,
    pub work: Work,
}

impl Genesis {
    pub fn of(header: &Header, seed: &crate::pow::SeedText) -> Genesis {
        Genesis { hash: header.hash(), work: Work::computed(seed, header) }
    }
}

/// Everything a chain program needs about one block.
pub struct ChainWitness<'a> {
    pub height: u32,
    pub statement: &'a Statement,
    pub wrap: Wrap,
    pub wrap_proof: &'a stark::Proof,
    /// Membership path of the wrap's leaf, and its index.
    pub path: Vec<Digest>,
    pub index: usize,
    /// `None` for the base program (height 1).
    pub prev: Option<PrevChain<'a>>,
}

/// The fixed context of the chain programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSetup {
    pub genesis: Genesis,
    pub plan_root: Digest,
    /// Height of the plan tree.
    pub plan_depth: usize,
    pub base: Digest,
    pub step: Digest,
    /// Table heights every chain proof has.
    pub log_n: usize,
    pub hash_log_n: usize,
}

/// Builds a chain program: the base when `w.prev` is `None`, else a step.
/// `self_step` is the step digest the output commits to (an input, not
/// part of the program); `pad_to` pads to common heights.
#[allow(clippy::too_many_arguments)]
fn compile_chain(
    params: &AggregatorParams,
    emission: &[(u32, u64)],
    genesis: &Genesis,
    plan_root: &Digest,
    base_digest: &Digest,
    self_step: &Digest,
    w: &ChainWitness<'_>,
    pad_to: Option<(usize, usize)>,
) -> Compiler {
    let mut c = Compiler::new();
    let at = |base: Addr, field: usize| base + field as Addr;
    let st = c.scalar_inputs(&w.statement.to_values(&params.work_shape()));
    let h = c.input(Fp4::from_base(Fp::new(w.height)));
    let dself = c.scalar_inputs(self_step);

    // The wrap is an allowed one: its leaf is in the plan tree.
    let mut pair_values = w.wrap.digest.to_vec();
    pair_values.extend_from_slice(&w.wrap.tree);
    let pair = c.scalar_inputs(&pair_values);
    let idx = c.input(Fp4::from_base(Fp::new(w.index as u32)));
    let bits = c.prog.decompose(idx);
    for k in 0..8 {
        let v = w.index as u32;
        c.set_word(bits + k as Addr, Fp4(core::array::from_fn(|j| Fp::new((v >> (4 * k + j)) & 1))));
    }
    let root = c.merkle_root(pair, 2 * DIGEST, &w.path, bits);
    for (i, v) in plan_root.iter().enumerate() {
        c.assert_scalar(root + i as Addr, *v);
    }

    // The wrap proof, for this block's statement.
    let words: Vec<Addr> =
        (0..params.statement_len()).map(|i| at(st, i)).chain((0..DIGEST).map(|i| at(pair, DIGEST + i))).collect();
    let block = concat(&mut c, &words);
    c.hash_scalars(block, words.len());
    let wrap_out = c.squeeze_digest();
    let expected = w.statement.output(&params.work_shape(), &w.wrap.tree);
    let pubv = c.scalar_inputs(&VmAir::public_values(&w.wrap.digest, &expected));
    c.assert_block(pubv, pair, DIGEST);
    c.assert_block(at(pubv, PUB_OUTPUT), wrap_out, DIGEST);
    let tables: [(&dyn stark::DynAir, Option<Addr>); 2] = [(&VmAir, Some(pubv)), (&HashTableAir, None)];
    c.verify_stark(&tables, &params.wrap, &[Fp::new(DOM_WRAP_PROOF)], pubv, VM_PUBLIC, w.wrap_proof);

    // The subsidy is the schedule's for the height: for each era boundary
    // a hinted bit says whether the height is within it, checked by a
    // range check on the difference either way.
    let mut sels: Vec<Addr> = Vec::with_capacity(emission.len());
    let mut end = 0u64;
    let mut prev_bit: Addr = 0;
    for (i, &(blocks, _)) in emission.iter().enumerate() {
        end += blocks as u64;
        let t = c.scalar(Fp::new(end as u32));
        let bit = if i + 1 == emission.len() {
            // Every height is within the last era: the chain ends there.
            let d = c.sub(t, h);
            c.assert_bits_zero_from(d, 30);
            1
        } else {
            let within = (w.height as u64) <= end;
            let b = c.input(Fp4::from_base(Fp::new(within as u32)));
            let bb = c.mul(b, b);
            c.assert_eq(bb, b);
            let below = c.sub(t, h);
            let above = c.sub(h, t);
            let above = c.sub(above, 1);
            let x = c.sub(below, above);
            let d = c.muladd(b, x, above);
            c.assert_bits_zero_from(d, 30);
            b
        };
        sels.push(c.sub(bit, prev_bit));
        prev_bit = bit;
    }
    for j in 0..LIMBS {
        let mut acc: Addr = 0;
        for (sel, &(_, subsidy)) in sels.iter().zip(emission) {
            let l = c.scalar(limbs16(subsidy)[j]);
            acc = c.muladd(*sel, l, acc);
        }
        c.assert_eq(acc, at(st, ST_SUBSIDY + j));
    }
    // Heights start at 1, and the statement's is the proof's.
    let h0 = c.sub(h, 1);
    c.assert_bits_zero_from(h0, 30);
    c.assert_eq(at(st, ST_HEIGHT), h);

    table_of_height(&mut c, &params.pow, h0, at(st, ST_WORK + crate::pow_air::PUB_TABLE));

    match &w.prev {
        None => {
            // Height 1 starts from the empty state.
            c.assert_scalar(h, Fp::ONE);
            for (i, v) in crate::store::sparse::empty(crate::store::sparse::STATE_HEIGHT).iter().enumerate() {
                c.assert_scalar(at(st, ST_PREV + i), *v);
            }
            c.assert_eq(at(st, ST_POS_IN), 0);
            c.assert_eq(at(st, ST_POS_IN + 1), 0);
            // Its parent is genesis.
            for (i, v) in genesis.hash.iter().enumerate() {
                c.assert_scalar(at(st, ST_PARENT + i), *v);
            }
            for (i, v) in genesis.work.to_values(&params.work_shape()).iter().enumerate() {
                c.assert_scalar(at(st, ST_WORK + i), *v);
            }
        }
        Some(prev) => {
            let pst = c.scalar_inputs(&prev.statement.to_values(&params.work_shape()));
            let ph = c.input(Fp4::from_base(Fp::new(prev.height)));
            let next = c.add(ph, 1);
            c.assert_eq(next, h);
            c.assert_block(at(pst, ST_NEW), at(st, ST_PREV), DIGEST);
            c.assert_block(at(pst, ST_POS_OUT), at(st, ST_POS_IN), 2);
            // The parent header, the previous block's: its hash recomputed
            // from its fields. Its prev_hash is the parent hash the
            // previous proof bound, its height that proof's, its state
            // root this block's previous one, and its pow_hash, nonce and
            // mix the work this block's root proved.
            let hd = prev.header;
            let ts = c.scalar_inputs(&hd.timestamp_limbs());
            let body = c.scalar_inputs(&hd.body_commitment);
            let aux = c.scalar_inputs(&crate::codec::packed(&hd.aux).collect::<Vec<Fp>>());
            let dom = c.scalar(Fp::new(crate::block::DOM_POW_HASH));
            let mut words: Vec<Addr> = vec![dom];
            words.extend((0..DIGEST).map(|i| at(pst, ST_PARENT + i)));
            words.push(ph);
            words.extend((0..3).map(|i| at(ts, i)));
            words.extend((0..DIGEST).map(|i| at(body, i)));
            words.extend((0..DIGEST).map(|i| at(st, ST_PREV + i)));
            words.extend((0..11).map(|i| at(aux, i)));
            let block = concat(&mut c, &words);
            c.hash_scalars(block, words.len());
            let pow_hash = c.squeeze_digest();
            c.assert_block(pow_hash, at(st, ST_WORK + crate::pow_air::PUB_HASH), DIGEST);
            let dom = c.scalar(Fp::new(crate::block::DOM_BLOCK_ID));
            let mut words: Vec<Addr> = vec![dom];
            words.extend((0..DIGEST).map(|i| pow_hash + i as Addr));
            words.extend((0..DIGEST).map(|i| at(st, ST_WORK + crate::pow_air::PUB_MIX + i)));
            words.extend((0..11).map(|i| at(st, ST_WORK + crate::pow_air::PUB_NONCE + i)));
            let block = concat(&mut c, &words);
            c.hash_scalars(block, words.len());
            let id = c.squeeze_digest();
            c.assert_block(id, at(st, ST_PARENT), DIGEST);
            // The predecessor's program: the base at height 2, else the
            // step this proof itself claims.
            let two = c.scalar(Fp::new(2));
            let e = c.sub(h, two);
            let b = c.input(Fp4::from_base(Fp::new((w.height == 2) as u32)));
            let bb = c.mul(b, b);
            c.assert_eq(bb, b);
            let eb = c.mul(e, b);
            c.assert_eq(eb, 0);
            let inv_v = if w.height == 2 { Fp::ZERO } else { (Fp::new(w.height) - Fp::new(2)).inverse().unwrap() };
            let inv = c.input(Fp4::from_base(inv_v));
            let ei = c.mul(e, inv);
            let one_minus_b = c.sub(1, b);
            c.assert_eq(ei, one_minus_b);
            let mut digest_words = Vec::with_capacity(DIGEST);
            for (i, v) in base_digest.iter().enumerate() {
                let bd = c.scalar(*v);
                let diff = c.sub(bd, dself + i as Addr);
                digest_words.push(c.muladd(b, diff, dself + i as Addr));
            }
            let prev_digest: Digest = core::array::from_fn(|i| c.val(digest_words[i]).0[0]);
            // Its output: its statement, this proof's step digest, the plan.
            let mut words: Vec<Addr> = vec![ph];
            words.extend((0..params.statement_len()).map(|i| at(pst, i)));
            words.extend((0..DIGEST).map(|i| dself + i as Addr));
            let plan_words: Vec<Addr> = plan_root.iter().map(|v| c.scalar(*v)).collect();
            words.extend(plan_words);
            let block = concat(&mut c, &words);
            c.hash_scalars(block, words.len());
            let prev_out = c.squeeze_digest();
            let expected = chain_output(&params.work_shape(), prev.height, prev.statement, self_step, plan_root);
            let ppub = c.scalar_inputs(&VmAir::public_values(&prev_digest, &expected));
            for (i, dw) in digest_words.iter().enumerate() {
                c.assert_eq(ppub + i as Addr, *dw);
            }
            c.assert_block(at(ppub, PUB_OUTPUT), prev_out, DIGEST);
            let tables: [(&dyn stark::DynAir, Option<Addr>); 2] = [(&VmAir, Some(ppub)), (&HashTableAir, None)];
            c.verify_stark(&tables, &params.wrap, &[Fp::new(DOM_CHAIN_PROOF)], ppub, VM_PUBLIC, prev.proof);
        }
    }

    // Output, after padding to the common heights if asked: the padding
    // leaves room for the output hash, which must come last.
    let mut words: Vec<Addr> = vec![h];
    words.extend((0..params.statement_len()).map(|i| at(st, i)));
    words.extend((0..DIGEST).map(|i| dself + i as Addr));
    let plan_words: Vec<Addr> = plan_root.iter().map(|v| c.scalar(*v)).collect();
    words.extend(plan_words);
    let block = concat(&mut c, &words);
    let blind = params.wrap.blind_rows();
    let final_hashes = words.len().div_ceil(8);
    if let Some((log_n, hash_log_n)) = pad_to {
        c.prog.reserve(blind + final_hashes);
        let zero = concat(&mut c, &[]);
        while VmAir::hash_height(&c.prog) < 1 << hash_log_n {
            c.hash_scalars(zero, 8);
        }
        c.prog.reserve(blind + final_hashes + 1);
        while c.prog.height() < 1 << log_n {
            c.add(0, 0);
        }
    }
    c.hash_scalars(block, words.len());
    c.prog.reserve(blind);
    c.assert_public();
    if let Some((log_n, hash_log_n)) = pad_to {
        assert_eq!(c.prog.height(), 1 << log_n, "chain program does not match its padding");
        assert_eq!(VmAir::hash_height(&c.prog), 1 << hash_log_n, "chain program does not match its hash padding");
    }
    c
}

/// Heights of every wrap proof (the same for every segment count).
fn wrap_heights(params: &AggregatorParams, cache: &mut PlanCache) -> (usize, usize) {
    let w = plan_with(params, 1, cache).wrap.expect("planned root");
    (w.log_n, w.hash_log_n)
}

/// Compiles the chain programs for `plan_root` (the root of
/// [`plan_leaves`]) and finds their common heights.
pub fn chain_setup(
    params: &AggregatorParams,
    emission: &[(u32, u64)],
    genesis: &Genesis,
    plan_root: &Digest,
    plan_depth: usize,
    cache: &mut PlanCache,
) -> ChainSetup {
    let (wn, wh) = wrap_heights(params, cache);
    let wrap_dummy = dummy_proof(&[(&VmAir, wn), (&HashTableAir, wh)], &params.wrap, VM_PUBLIC);
    let zero = Statement::zero(&params.work_shape());
    let wrap = Wrap { digest: [Fp::ZERO; DIGEST], log_n: wn, hash_log_n: wh, tree: [Fp::ZERO; DIGEST] };
    let path = vec![[Fp::ZERO; DIGEST]; plan_depth];
    let zd = [Fp::ZERO; DIGEST];
    let dummy_header = Header {
        prev_hash: zd,
        height: 0,
        timestamp: 0,
        body_commitment: zd,
        state_root: zd,
        aux: [0; 32],
        mix: zd,
        nonce: [0; 32],
    };
    fn witness<'a>(
        height: u32,
        statement: &'a Statement,
        wrap: Wrap,
        wrap_proof: &'a stark::Proof,
        path: &[Digest],
        prev: Option<PrevChain<'a>>,
    ) -> ChainWitness<'a> {
        ChainWitness { height, statement, wrap, wrap_proof, path: path.to_vec(), index: 0, prev }
    }
    let heights = |c: &Compiler| {
        (c.prog.height().trailing_zeros() as usize, VmAir::hash_height(&c.prog).trailing_zeros() as usize)
    };
    let base = compile_chain(
        params,
        emission,
        genesis,
        plan_root,
        &zd,
        &zd,
        &witness(1, &zero, wrap, &wrap_dummy, &path, None),
        None,
    );
    // The step verifies a proof of its own heights: find the fixed point,
    // with room for the padding's bookkeeping.
    let (bn, bh) = heights(&base);
    let mut guess = (bn.max(wn), bh.max(wh));
    loop {
        let prev = dummy_proof(&[(&VmAir, guess.0), (&HashTableAir, guess.1)], &params.wrap, VM_PUBLIC);
        let w = witness(
            3,
            &zero,
            wrap,
            &wrap_dummy,
            &path,
            Some(PrevChain { height: 2, statement: &zero, proof: &prev, header: &dummy_header }),
        );
        let step = compile_chain(params, emission, genesis, plan_root, &zd, &zd, &w, None);
        let (sn, sh) = heights(&step);
        let room = step.prog.num_rows() + 64 < 1 << guess.0;
        if sn <= guess.0 && sh <= guess.1 && room {
            break;
        }
        guess = (if room { guess.0.max(sn) } else { guess.0 + 1 }, guess.1.max(sh));
    }
    let pad = Some(guess);
    let base = compile_chain(
        params,
        emission,
        genesis,
        plan_root,
        &zd,
        &zd,
        &witness(1, &zero, wrap, &wrap_dummy, &path, None),
        pad,
    );
    let base_digest = base.prog.digest(params.wrap.log_blowup);
    let prev = dummy_proof(&[(&VmAir, guess.0), (&HashTableAir, guess.1)], &params.wrap, VM_PUBLIC);
    let w = witness(
        3,
        &zero,
        wrap,
        &wrap_dummy,
        &path,
        Some(PrevChain { height: 2, statement: &zero, proof: &prev, header: &dummy_header }),
    );
    let step = compile_chain(params, emission, genesis, plan_root, &base_digest, &zd, &w, pad);
    ChainSetup {
        genesis: *genesis,
        plan_root: *plan_root,
        plan_depth,
        base: base_digest,
        step: step.prog.digest(params.wrap.log_blowup),
        log_n: guess.0,
        hash_log_n: guess.1,
    }
}

/// Proves a chain step (or the base, without `w.prev`).
pub fn prove_chain(
    params: &AggregatorParams,
    emission: &[(u32, u64)],
    setup: &ChainSetup,
    w: &ChainWitness<'_>,
    cancel: stark::Cancel<'_>,
) -> Option<stark::Proof> {
    let pad = Some((setup.log_n, setup.hash_log_n));
    let c = compile_chain(params, emission, &setup.genesis, &setup.plan_root, &setup.base, &setup.step, w, pad);
    let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).expect("chain program rejects its own witness");
    let digest = if w.prev.is_none() { setup.base } else { setup.step };
    let pre = committed_program(&c.prog, &params.wrap, &digest);
    let public = VmAir::public_values(
        &digest,
        &chain_output(&params.work_shape(), w.height, w.statement, &setup.step, &setup.plan_root),
    );
    let tables = VmAir::tables(&trace, &hashes, &pre);
    stark::try_prove_tables(&params.wrap, &tables, &public, &mut chain_transcript(), Some(cancel)).ok()
}

/// Verifies that `proof` shows the block at `height` with `statement`, and
/// every block before it, valid. The check is the compiled verifier a
/// chain step runs on its predecessor, compiled for the setup's heights
/// and interpreted ([`crate::chain_verifier`]): the fam node runs the same
/// program, so both accept the same proofs, and a proof of other heights
/// is refused.
pub fn verify_chain(
    params: &AggregatorParams,
    setup: &ChainSetup,
    height: u32,
    statement: &Statement,
    proof: &stark::Proof,
) -> Result<(), AggregateError> {
    if height == 0 {
        return Err(AggregateError::Rejected);
    }
    let digest = if height == 1 { setup.base } else { setup.step };
    let public = VmAir::public_values(
        &digest,
        &chain_output(&params.work_shape(), height, statement, &setup.step, &setup.plan_root),
    );
    let verifier = crate::chain_verifier::chain_verifier(&params.wrap, setup.log_n, setup.hash_log_n);
    if verifier.verify(&public, proof) { Ok(()) } else { Err(AggregateError::Rejected) }
}

/// Verifies an encoded block proof against a statement. `wrap` gives the
/// planned wrap for a segment count: the program digest the proof is
/// checked against and the tree digest its output commits to.
pub fn verify_block(
    params: &AggregatorParams,
    wrap: &dyn Fn(usize) -> Wrap,
    statement: &Statement,
    proof: &[u8],
) -> Result<(), AggregateError> {
    let mut r = Reader(proof);
    let k = r.u32().ok_or(AggregateError::Malformed)? as usize;
    if k == 0 || k > params.max_segments {
        return Err(AggregateError::BadSegmentCount(k));
    }
    let proof = stark::Proof::from_bytes(r.0).map_err(|_| AggregateError::Malformed)?;
    let wrap = wrap(k);
    let public = VmAir::public_values(&wrap.digest, &statement.output(&params.work_shape(), &wrap.tree));
    stark::verify_tables(&params.wrap, &VmAir::specs(&wrap.digest), &public, &proof, &mut wrap_transcript())
        .map_err(|_| AggregateError::Rejected)
}

/// Mainnet's chain-proof setup: the root of the allowed wraps and the
/// chain programs, fixed by the circuits. Regenerate with the ignored test
/// `aggregate::tests::mainnet_chain_constants` after any circuit change.
pub const MAINNET_CHAIN: Option<ChainSetupConst> = Some(ChainSetupConst {
    plan_root: [1346113909, 950221934, 1662504710, 1263405605, 1499417996, 1332630054, 1803947677, 1745527222],
    plan_depth: 14,
    base: [1659149308, 1235761572, 1207475574, 27107541, 825104444, 1480942281, 609688179, 1439400594],
    step: [124176826, 1357102206, 1086211802, 2000845285, 616290429, 1240340100, 1715838614, 651851502],
    log_n: 17,
    hash_log_n: 15,
});

/// Mainnet's plan leaves ([`plan_leaves`]), 32 bytes each: fixed by the
/// circuits like [`MAINNET_CHAIN`] and regenerated with it, so a miner
/// need not plan every segment count when it starts. Checked against
/// [`MAINNET_CHAIN`]'s plan root before use.
const MAINNET_PLAN: &[u8] = include_bytes!("mainnet_plan.bin");

/// The recursive dev network's constants ([`AggregatorParams::DEV_RECURSIVE`]
/// with mainnet's emission), as [`MAINNET_CHAIN`]; regenerated by
/// `dev_recursive_chain_constants`.
pub const DEV_RECURSIVE_CHAIN: Option<ChainSetupConst> = Some(ChainSetupConst {
    plan_root: [217685549, 267035602, 557151517, 736380337, 1721595136, 410516935, 892636323, 517673064],
    plan_depth: 6,
    base: [1295076407, 1418767323, 865231049, 1546652879, 186830396, 1845261226, 1126091648, 532969542],
    step: [1830583902, 791796703, 1318684135, 1507565309, 960084889, 918307785, 760054666, 767522199],
    log_n: 16,
    hash_log_n: 12,
});

/// The recursive dev network's plan leaves, as [`MAINNET_PLAN`]; built in
/// with the `dev` feature only.
#[cfg(feature = "dev")]
const DEV_RECURSIVE_PLAN: &[u8] = include_bytes!("dev_recursive_plan.bin");

/// [`ChainSetup`] as plain integers, for a constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSetupConst {
    pub plan_root: [u32; DIGEST],
    pub plan_depth: usize,
    pub base: [u32; DIGEST],
    pub step: [u32; DIGEST],
    pub log_n: usize,
    pub hash_log_n: usize,
}

impl ChainSetupConst {
    fn setup(&self, genesis: Genesis) -> ChainSetup {
        let d = |x: &[u32; DIGEST]| x.map(Fp::new);
        ChainSetup {
            genesis,
            plan_root: d(&self.plan_root),
            plan_depth: self.plan_depth,
            base: d(&self.base),
            step: d(&self.step),
            log_n: self.log_n,
            hash_log_n: self.hash_log_n,
        }
    }
}

/// Verifies block proofs: each a chain proof covering the block and every
/// block before it. Also proves them, for a miner.
pub struct AggregateVerifier {
    pub params: AggregatorParams,
    pub emission: &'static [(u32, u64)],
    /// The chain's genesis, block 1's parent.
    pub genesis: Genesis,
    /// Compiled program types, and the planned wrap by segment count.
    plans: Mutex<(PlanCache, HashMap<usize, Wrap>)>,
    setup: std::sync::OnceLock<ChainSetup>,
    tree: std::sync::OnceLock<crate::merkle::MerkleTree>,
    /// Debugging only: accept every proof without checking it.
    unchecked: bool,
}

impl AggregateVerifier {
    /// The parameters proofs are made and checked with.
    pub fn params(&self) -> &AggregatorParams {
        &self.params
    }

    pub fn new(params: AggregatorParams, emission: &'static [(u32, u64)], genesis: Genesis) -> AggregateVerifier {
        AggregateVerifier {
            params,
            emission,
            genesis,
            plans: Mutex::new((PlanCache::new(), HashMap::new())),
            setup: std::sync::OnceLock::new(),
            tree: std::sync::OnceLock::new(),
            unchecked: false,
        }
    }

    /// Debugging only: a verifier that accepts every block proof unchecked,
    /// so blocks too large to prove in reasonable time can be simulated.
    /// Such a node can be fed any block.
    pub fn unchecked(mut self) -> AggregateVerifier {
        self.unchecked = true;
        self
    }

    /// Whether proofs go unchecked.
    pub fn is_unchecked(&self) -> bool {
        self.unchecked
    }

    /// The planned tree for `k` segments. Program types compiled for
    /// earlier counts are reused, so once warm this only hashes.
    pub fn shape(&self, k: usize) -> Shape {
        let mut plans = self.plans.lock().unwrap();
        let s = plan_with(&self.params, k, &mut plans.0);
        plans.1.insert(k, s.wrap.expect("planned root"));
        s
    }

    /// The planned wrap a `k`-segment block proof is checked against.
    pub fn wrap(&self, k: usize) -> Wrap {
        if let Some(w) = self.plans.lock().unwrap().1.get(&k) {
            return *w;
        }
        self.shape(k).wrap.expect("planned root")
    }

    /// The constants and plan leaves built into the binary for these
    /// parameters, if any: mainnet's and the recursive dev network's.
    /// Otherwise the setup is computed, which plans every segment count.
    fn built_in(&self) -> Option<(ChainSetupConst, &'static [u8])> {
        use crate::chain::params::ChainParams;
        if self.emission != crate::chain::params::MAINNET_EMISSION {
            return None;
        }
        if self.params == AggregatorParams::MAINNET && self.genesis.hash == ChainParams::MAINNET.genesis().header.hash()
        {
            return MAINNET_CHAIN.map(|c| (c, MAINNET_PLAN));
        }
        #[cfg(feature = "dev")]
        if self.params == AggregatorParams::DEV_RECURSIVE
            && self.genesis.hash == ChainParams::DEV_RECURSIVE.genesis().header.hash()
        {
            return DEV_RECURSIVE_CHAIN.map(|c| (c, DEV_RECURSIVE_PLAN));
        }
        None
    }

    /// The tree of allowed wraps, which proving needs: on mainnet (and the
    /// recursive dev network) from the leaves built into the binary
    /// ([`MAINNET_PLAN`]), checked against the plan root; otherwise, or if
    /// they do not match, planned (about a minute on mainnet).
    pub fn plan_tree(&self) -> &crate::merkle::MerkleTree {
        self.tree.get_or_init(|| {
            if let Some(t) = self.embedded_plan() {
                return t;
            }
            let mut plans = self.plans.lock().unwrap();
            crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&self.params, &mut plans.0))
        })
    }

    /// Whether the plan tree comes built in, without planning.
    pub fn plan_is_built_in(&self) -> bool {
        self.tree.get().is_some() || self.embedded_plan().is_some()
    }

    /// Whether proving needs the plan and the chain setup: not with
    /// direct proofs.
    pub fn needs_plan(&self) -> bool {
        !self.params.direct && !self.unchecked
    }

    fn embedded_plan(&self) -> Option<crate::merkle::MerkleTree> {
        let (c, plan) = self.built_in()?;
        let root = c.setup(self.genesis).plan_root;
        let leaves = plan
            .chunks_exact(32)
            .map(crate::poseidon2::digest_from_bytes)
            .collect::<Option<Vec<_>>>()
            .filter(|l| l.len() == self.params.max_segments.next_power_of_two())?;
        let t = crate::merkle::MerkleTree::from_leaf_hashes(leaves);
        (t.root() == root).then_some(t)
    }

    /// The chain-proof setup.
    pub fn setup(&self) -> &ChainSetup {
        self.setup.get_or_init(|| {
            if let Some((c, _)) = self.built_in() {
                return c.setup(self.genesis);
            }
            let tree = self.plan_tree();
            let (root, depth) = (tree.root(), tree.height());
            let mut plans = self.plans.lock().unwrap();
            chain_setup(&self.params, self.emission, &self.genesis, &root, depth, &mut plans.0)
        })
    }

    /// Verifies a block proof: the chain proof of the block at `height`.
    pub fn verify_chain_proof(&self, height: u32, statement: &Statement, proof: &[u8]) -> Result<(), AggregateError> {
        let proof = stark::Proof::from_bytes(proof).map_err(|_| AggregateError::Malformed)?;
        verify_chain(&self.params, self.setup(), height, statement, &proof)
    }

    /// Verifies a wrap encoding (segment count and wrap proof), as
    /// [`prove_block_cancellable`] makes.
    pub fn verify_statement(&self, statement: &Statement, proof: &[u8]) -> Result<(), AggregateError> {
        verify_block(&self.params, &|k| self.wrap(k), statement, proof)
    }

    /// Proves the block at `height`: its segments and name segment, tree
    /// and wrap, then the chain step on `prev` (the previous block's
    /// height, statement, proof and header; `None` at height 1). Returns
    /// the block proof.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_block(
        &self,
        height: u32,
        statement: &Statement,
        segments: &[SegmentWitness],
        names: &NameWitness,
        prev: Option<(u32, &Statement, &[u8], &Header)>,
        jobs: usize,
        progress: &(dyn Fn(Progress) + Sync),
        cancel: stark::Cancel<'_>,
    ) -> Option<Vec<u8>> {
        if self.params.direct {
            let t = std::time::Instant::now();
            let proof = crate::block_proof::prove_block(&self.params.segment, segments, names);
            progress(Progress::Segment { index: segments.len() - 1, count: segments.len(), elapsed: t.elapsed() });
            return (!cancel()).then_some(proof);
        }
        let shape = self.shape(segments.len());
        let wrap_proof = prove_wrap(&self.params, &shape, statement, segments, names, jobs, progress, cancel)?;
        let prev_proof = match prev {
            Some((_, _, bytes, _)) => {
                Some(stark::Proof::from_bytes(bytes).expect("the previous block's proof decodes"))
            }
            None => None,
        };
        let setup = *self.setup();
        let tree = self.plan_tree();
        let index = segments.len() - 1;
        let w = ChainWitness {
            height,
            statement,
            wrap: shape.wrap.expect("planned root"),
            wrap_proof: &wrap_proof,
            path: tree.open(index),
            index,
            prev: prev.zip(prev_proof.as_ref()).map(|((h, st, _, header), proof)| PrevChain {
                height: h,
                statement: st,
                proof,
                header,
            }),
        };
        let t = std::time::Instant::now();
        let proof = prove_chain(&self.params, self.emission, &setup, &w, cancel)?;
        progress(Progress::Chain { elapsed: t.elapsed() });
        Some(proof.to_bytes())
    }
}

impl ProofVerifier for AggregateVerifier {
    fn verify(&self, s: &BlockStatement<'_>, proof: &[u8]) -> bool {
        if self.params.direct {
            let names = NameAir::of(self.params.min_reveal);
            return self.unchecked || crate::block_proof::verify_block(&self.params.segment, &names, s, proof).is_ok();
        }
        self.unchecked || self.verify_chain_proof(s.height, &Statement::from_block(s), proof).is_ok()
    }

    fn is_unchecked(&self) -> bool {
        self.unchecked
    }
}

#[cfg(test)]
#[path = "aggregate_tests.rs"]
mod tree_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Body, BodyRef};
    use crate::block_air::Carry;
    use crate::name::BlockNameOp;
    use crate::output::BlockOutput;
    use crate::pow_air::{PUB_HASH, PUB_MIX, PUB_NONCE, PUB_TABLE};

    fn d(x: u32) -> Digest {
        [Fp::new(x); DIGEST]
    }

    /// A block's statement is of its body: the sponges of what it
    /// lists, and the position after its outputs and its commits.
    #[test]
    fn a_statement_is_of_its_block() {
        let body = Body {
            inputs: vec![3, 9],
            outputs: vec![BlockOutput { commitment: d(1), memo: [Fp::new(2); 5], amount: 70 }; 3],
            ops: vec![BlockNameOp::Commit { commit: d(4), memo: [Fp::new(5); 5] }],
            sweeps: vec![6],
            proof: vec![1, 2, 3],
        };
        let bytes = body.to_bytes();
        let view = BodyRef::from_bytes(&bytes).unwrap();
        let work = Work { pow_hash: d(7), nonce: [8; 32], mix: d(9), log_items: 25 };
        let block = BlockStatement {
            height: 60_000,
            prev_state_root: d(10),
            new_state_root: d(11),
            first_output_position: (1 << 30) + 5,
            subsidy: 1500,
            body: view,
            parent_work: work,
            parent_hash: d(12),
        };
        let s = Statement::from_block(&block);
        assert_eq!(s.end_output_position, (1 << 30) + 5 + 3 + 1);
        assert_eq!(s.inputs_state, inputs_state([3, 9]));
        assert_eq!(s.outputs_state, outputs_state(body.outputs.iter().copied()));
        assert_eq!(s.names_state, names_state(body.ops.iter().map(|o| o.digest())));
        assert_eq!(s.sweeps_state, sweeps_state([6]));
        assert_eq!((s.parent_work, s.parent_hash, s.height, s.subsidy), (work, d(12), 60_000, 1500));

        // Encoded: every part in its place, the parent's work last.
        let params = AggregatorParams::MAINNET;
        let shape = params.work_shape();
        let v = s.to_values(&shape);
        assert_eq!(v.len(), params.statement_len());
        assert_eq!(v[ST_PREV..ST_PREV + DIGEST], d(10));
        assert_eq!(v[ST_NEW..ST_NEW + DIGEST], d(11));
        assert_eq!(v[ST_POS_IN..ST_POS_IN + 2], [Fp::new(5), Fp::ONE]);
        assert_eq!(v[ST_POS_OUT..ST_POS_OUT + 2], [Fp::new(9), Fp::ONE]);
        assert_eq!(v[ST_SUBSIDY], Fp::new(1500));
        assert_eq!(v[ST_HEIGHT], Fp::new(60_000));
        assert_eq!(v[ST_PARENT..ST_PARENT + DIGEST], d(12));
        assert_eq!(v[ST_WORK + PUB_HASH..ST_WORK + PUB_HASH + DIGEST], d(7));
        assert_eq!(v[ST_WORK + PUB_MIX..ST_WORK + PUB_MIX + DIGEST], d(9));
        assert!(PUB_NONCE < PUB_MIX && PUB_MIX < PUB_TABLE);
        // The table of the second year: one doubling had, four to come.
        let flags: Vec<u32> = v[ST_WORK + PUB_TABLE..].iter().map(|f| f.to_canonical()).collect();
        assert_eq!(flags, [1, 0, 0, 0, 0]);
        // A network whose table does not grow says nothing of its size.
        let dev = AggregatorParams::DEV_RECURSIVE;
        assert_eq!(dev.statement_len(), ST_WORK + PUB_TABLE);
        assert_eq!(Statement::zero(&dev.work_shape()).to_values(&dev.work_shape()).len(), dev.statement_len());

        // Every value is under the output digest, and so is the tree.
        let out = s.output(&shape, &d(20));
        assert_ne!(out, s.output(&shape, &d(21)));
        for change in [
            Statement { height: 60_001, ..s.clone() },
            Statement { subsidy: 1501, ..s.clone() },
            Statement { end_output_position: s.end_output_position + 1, ..s.clone() },
            Statement { parent_hash: d(13), ..s.clone() },
            Statement { parent_work: Work { log_items: 26, ..work }, ..s.clone() },
            Statement { parent_work: Work { nonce: [9; 32], ..work }, ..s.clone() },
        ] {
            assert_ne!(change.output(&shape, &d(20)), out);
        }
    }

    /// A tree's digest says what its children are and in what order; the
    /// root's also that it has a name segment and a work segment.
    #[test]
    fn tree_digests_tell_the_trees_apart() {
        let (a, b) = (Some((d(1), d(2))), Some((d(3), d(4))));
        let trees = [
            tree_digest(&[]),
            tree_digest(&[None]),
            tree_digest(&[None, None]),
            tree_digest(&[a]),
            tree_digest(&[a, b]),
            tree_digest(&[b, a]),
            tree_digest(&[a, None]),
            tree_digest(&[None, a]),
            root_tree_digest(&[]),
            root_tree_digest(&[None]),
            root_tree_digest(&[a]),
            root_tree_digest(&[a, b]),
        ];
        for i in 0..trees.len() {
            for j in 0..i {
                assert_ne!(trees[i], trees[j], "trees {j} and {i}");
            }
        }
        assert_eq!(wrap_tree(&d(1), &d(2)), tree_digest(&[a]));
        // A segment is not a node with a digest of its tag.
        let mut tag = [Fp::ZERO; DIGEST];
        tag[0] = Fp::new(SEGMENT_TAG);
        assert_eq!(tree_digest(&[None]), tree_digest(&[Some((tag, [Fp::ZERO; DIGEST]))]));
    }

    /// Records one after another make the record of their span, their
    /// sums added in limbs of sixteen bits.
    #[test]
    fn records_combine_into_their_span() {
        let state = |x: u32| [Fp::new(x); WIDTH];
        let record = |i: u32, sum_in: [u32; LIMBS], sum_out: [u32; LIMBS]| SegmentPublic {
            root_in: d(i),
            root_out: d(i + 1),
            isp_in: state(i),
            isp_out: state(i + 1),
            osp_in: state(i + 10),
            osp_out: state(i + 11),
            nsp_in: state(i + 20),
            nsp_out: state(i + 21),
            pos_in: i as u64 * 100,
            pos_out: i as u64 * 100 + 100,
            sum_in,
            sum_out,
            carry_in: Carry::CLOSED,
            carry_out: Carry::CLOSED,
            height: 7,
        };
        let records = [
            record(1, [0xffff, 0xffff, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0]),
            record(2, [0xffff, 1, 0, 0, 0, 0], [0xffff, 0xffff, 0xffff, 0xffff, 0, 0]),
            record(3, [2, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]),
        ];
        let span = combine_records(&records);
        assert_eq!((span.root_in, span.root_out), (d(1), d(4)));
        assert_eq!((span.isp_in, span.isp_out, span.osp_out, span.nsp_out), (state(1), state(4), state(14), state(24)));
        assert_eq!((span.pos_in, span.pos_out, span.height), (100, 400, 7));
        // Carried from limb to limb.
        assert_eq!(span.sum_in, [0, 2, 1, 0, 0, 0]);
        assert_eq!(span.sum_out, [0, 0, 0, 0, 1, 0]);
        let total =
            |f: fn(&SegmentPublic) -> &[u32; LIMBS]| records.iter().map(|r| SegmentPublic::total(f(r))).sum::<u128>();
        assert_eq!(SegmentPublic::total(&span.sum_in), total(|r| &r.sum_in));
        assert_eq!(SegmentPublic::total(&span.sum_out), total(|r| &r.sum_out));
        assert_eq!(combine_records(&records[..1]), records[0]);
        // A node's output is of its record and of its tree.
        let out = node_output(&span, &d(9));
        assert_ne!(out, node_output(&span, &d(8)));
        assert_ne!(out, node_output(&combine_records(&records[..2]), &d(9)));
    }

    /// The work setup is made once for a configuration and a proof of
    /// work, and a header's work is proven against it.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "proves a header's work; run with --release")]
    fn a_networks_work_is_proven_against_its_setup() {
        let params = AggregatorParams::DEV_RECURSIVE;
        let setup = params.work_setup();
        assert!(std::ptr::eq(setup, params.work_setup()), "made once");
        assert!(std::ptr::eq(setup, AggregatorParams::DEV.work_setup()), "the same configuration and proof of work");
        let seed = SeedText::new(params.pow);
        let header = crate::chain::params::ChainParams::DEV_RECURSIVE.genesis().header;
        let work = Work::computed(&seed, &header);
        let proven = params.prove_work(&work);
        assert_eq!(proven.work, work);
        let bytes = proven.proof.to_bytes();
        assert_eq!(crate::pow_air::verify_work(&setup.verifier(), &params.segment, &work, &bytes), Ok(()));
        let other = Work { mix: d(1), ..work };
        assert!(crate::pow_air::verify_work(&setup.verifier(), &params.segment, &other, &bytes).is_err());
    }
}
