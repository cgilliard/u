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
