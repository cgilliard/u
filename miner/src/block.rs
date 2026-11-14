//! Block format: a proof-of-work header over a body of input positions,
//! outputs and a validity proof.
//!
//! # Header, 204 bytes
//!
//! | field           | bytes | meaning                                        |
//! |-----------------|-------|------------------------------------------------|
//! | prev_hash       | 32    | [`Header::hash`] of the previous block         |
//! | height          | 4     | genesis is 0                                   |
//! | timestamp       | 8     | unix seconds                                   |
//! | body_commitment | 32    | [`Body::commitment`]                           |
//! | state_root      | 32    | UTXO tree root after applying this block       |
//! | aux             | 32    | the miner's own bytes, any value; zero here    |
//! | mix             | 32    | proof-of-work mix digest                       |
//! | nonce           | 32    | proof-of-work nonce                            |
//!
//! [`Header::pow_hash`] covers the first six fields and seeds the proof of
//! work together with the nonce. [`Header::hash`] covers everything and is
//! the block id. The difficulty target is not stored; it follows from the
//! parent header through [`crate::difficulty::Asert`]. Neither is the size
//! of the table the work is of: it follows from the height
//! ([`crate::pow::PowParams::log_items_at`]).
//!
//! # Body
//!
//! 1. Inputs: positions in the state tree of the outputs being spent, six
//!    bytes each (little endian, below 2^41), in transaction order and
//!    without repeats.
//! 2. Outputs: a commitment (32 bytes), a memo (20) and an amount (8,
//!    public), in the order they are appended to the state tree. The memo
//!    is opaque to consensus (its owner's wallet uses it for recovery); the
//!    proof binds it, and the amount, to the transaction that created the
//!    output, and the amount to the one the output's commitment hides.
//! 3. Name operations, in order (see [`crate::name::BlockNameOp`]), at
//!    most the cap of each kind. A commit occupies the counter position
//!    after the block's outputs, in operation order; a reveal names the
//!    position of the commit it spends.
//! 4. Swept commits: positions, six bytes each. The positions spent by
//!    inputs, reveals and sweeps are all distinct; at most
//!    [`crate::name::MAX_SWEEPS`] sweeps.
//! 5. The validity proof.
//!
//! Each of the five is a count of four bytes and then its items (the
//! proof's count is its length in bytes).
//!
//! Keys, input amounts, signatures, salts and transaction boundaries are
//! not on chain; the proof attests to them. Output amounts are, so every
//! node checks the supply outside the proof.
//!
//! The body commitment hashes all five.
//!
//! # Two forms
//!
//! A header is 204 bytes held in place: reading one, hashing it and
//! checking its work use no heap. A body can be megabytes, so a node reads
//! the one it is sent as a view: [`BodyRef`] and [`BlockRef`] borrow the
//! encoded bytes, check the encoding once and hash it where it lies, the
//! proof included, a block of the sponge at a time. The one thing a body
//! needs memory for is to see that no position is spent twice: a list of
//! them, eight bytes each, held while it is sorted. [`Body`] and [`Block`]
//! are the owned forms, for building a block.

use core::fmt;

use crate::codec::{POSITION_BYTES, packed, read_digest, read_position, read_u32, read_u64, write_position};
use crate::hash::{DOM_BLOCK_BODY, DOM_BLOCK_PROOF, Digest, DomainHasher};
use crate::name::{BlockNameOp, OpKind, count_ops};
pub use crate::output::{BLOCK_OUTPUT_SIZE, BlockOutput};
use crate::output::OUTPUT_CAPACITY;
use crate::poseidon2::{DIGEST, Fp, digest_to_bytes};
use crate::pow::{self, ItemSource, Nonce, PowOutput, Target};

pub const HEADER_SIZE: usize = 32 + 4 + 8 + 32 + 32 + 32 + 32 + 32;
pub const COMMITMENT_SIZE: usize = 4 * DIGEST;

/// The header hashes' domains: the first element hashed, in the plain
/// sponge (`poseidon2::hash`, the input length in the capacity), so that
/// the chain proof's machine can recompute them.
pub(crate) const DOM_POW_HASH: u32 = 0x10;
pub(crate) const DOM_BLOCK_ID: u32 = 0x11;
const MASK30: u64 = (1 << 30) - 1;

/// Elements 32 bytes pack into, three bytes each.
const PACKED_32: usize = 32usize.div_ceil(3);

/// 32 bytes as elements, three bytes each.
fn pack_32(bytes: &[u8; 32]) -> [Fp; PACKED_32] {
    let mut out = [Fp::ZERO; PACKED_32];
    for (x, v) in out.iter_mut().zip(packed(bytes)) {
        *x = v;
    }
    out
}

// ---------------------------------------------------------------------------
// The header
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Header {
    pub prev_hash: Digest,
    pub height: u32,
    pub timestamp: u64,
    pub body_commitment: Digest,
    pub state_root: Digest,
    /// Auxiliary bytes for the miner's own use, any value: under the
    /// proof of work, unread by consensus.
    pub aux: [u8; 32],
    pub mix: Digest,
    pub nonce: Nonce,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let mut at = 0;
        let mut put = |b: &[u8]| {
            out[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        };
        put(&digest_to_bytes(&self.prev_hash));
        put(&self.height.to_le_bytes());
        put(&self.timestamp.to_le_bytes());
        put(&digest_to_bytes(&self.body_commitment));
        put(&digest_to_bytes(&self.state_root));
        put(&self.aux);
        put(&digest_to_bytes(&self.mix));
        put(&self.nonce);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Header> {
        if bytes.len() != HEADER_SIZE {
            return None;
        }
        let (prev_hash, rest) = read_digest(bytes)?;
        let (height, rest) = read_u32(rest)?;
        let (timestamp, rest) = read_u64(rest)?;
        let (body_commitment, rest) = read_digest(rest)?;
        let (state_root, rest) = read_digest(rest)?;
        let (aux, rest) = rest.split_at(32);
        let (mix, nonce) = read_digest(rest)?;
        Some(Header {
            prev_hash,
            height,
            timestamp,
            body_commitment,
            state_root,
            aux: aux.try_into().unwrap(),
            mix,
            nonce: nonce.try_into().unwrap(),
        })
    }

    /// The timestamp in three elements of 30, 30 and 4 bits.
    pub fn timestamp_limbs(&self) -> [Fp; 3] {
        [
            Fp::new((self.timestamp & MASK30) as u32),
            Fp::new(((self.timestamp >> 30) & MASK30) as u32),
            Fp::new((self.timestamp >> 60) as u32),
        ]
    }

    /// Hash of the fields under proof of work: everything but mix and nonce.
    /// `H(DOM_POW_HASH, prev_hash, height, timestamp limbs, body_commitment,
    /// state_root, aux packed)`: 40 elements.
    pub fn pow_hash(&self) -> Digest {
        let mut v = [Fp::ZERO; 5 + 3 * DIGEST + PACKED_32];
        v[0] = Fp::new(DOM_POW_HASH);
        v[1..9].copy_from_slice(&self.prev_hash);
        v[9] = Fp::from_u32(self.height);
        v[10..13].copy_from_slice(&self.timestamp_limbs());
        v[13..21].copy_from_slice(&self.body_commitment);
        v[21..29].copy_from_slice(&self.state_root);
        v[29..].copy_from_slice(&pack_32(&self.aux));
        crate::poseidon2::hash(&v)
    }

    /// Block id: hash of the whole header including the proof of work.
    /// `H(DOM_BLOCK_ID, pow_hash, mix, nonce packed)`: 28 elements.
    pub fn hash(&self) -> Digest {
        let mut v = [Fp::ZERO; 1 + 2 * DIGEST + PACKED_32];
        v[0] = Fp::new(DOM_BLOCK_ID);
        v[1..9].copy_from_slice(&self.pow_hash());
        v[9..17].copy_from_slice(&self.mix);
        v[17..].copy_from_slice(&pack_32(&self.nonce));
        crate::poseidon2::hash(&v)
    }

    /// Evaluates the proof of work for this header's nonce with `source`,
    /// which is to be the table of the header's height.
    pub fn pow_output<S: ItemSource>(&self, source: &S) -> PowOutput {
        pow::hashimoto(source, &self.pow_hash(), &self.nonce)
    }

    /// Cheap pre-check from the claimed mix: two permutations. A header that
    /// fails this is invalid; one that passes still needs [`Header::verify_pow`].
    pub fn quick_pow_check(&self, target: &Target) -> bool {
        target.is_met_by(&pow::result_from_mix(&self.pow_hash(), &self.nonce, &self.mix))
    }

    /// Full proof-of-work check: `source` must be the table of the header's
    /// height (from the seed text alone, [`pow::SeedText::at`], or a
    /// miner's), the mix the true mix, and the result must meet the target.
    pub fn verify_pow<S: ItemSource>(&self, source: &S, target: &Target) -> bool {
        source.log_items() == source.params().log_items_at(self.height as u64)
            && self.quick_pow_check(target)
            && pow::verify(source, &self.pow_hash(), &self.nonce, &self.mix, target)
    }
}

// ---------------------------------------------------------------------------
// What a body must be
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// The same position is spent twice.
    DuplicateInput(u64),
    /// An input position is not below the tree capacity.
    InputOutOfRange(u64),
    /// More operations of a kind than its cap.
    TooMany(OpKind),
    /// A position spent by a reveal or a sweep is repeated or also spent.
    DuplicateSpend(u64),
    /// A position spent by a reveal or a sweep is not below the tree capacity.
    SpendOutOfRange(u64),
    Malformed,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyError::DuplicateInput(p) => write!(f, "input position {p} appears twice"),
            BodyError::InputOutOfRange(p) => write!(f, "input position {p} exceeds the state tree"),
            BodyError::TooMany(k) => write!(f, "more than {} {} operations", k.cap(), k.name()),
            BodyError::DuplicateSpend(p) => write!(f, "position {p} is spent twice"),
            BodyError::SpendOutOfRange(p) => write!(f, "spent position {p} exceeds the state tree"),
            BodyError::Malformed => f.write_str("malformed block body"),
        }
    }
}

impl std::error::Error for BodyError {}

/// Checks a body's positions and operations: `inputs`, then the positions
/// `spends` that reveals and sweeps consume, all below the tree's capacity
/// and no two alike, taken in order so that the first at fault is the one
/// reported; and no more operations of a kind than its cap.
fn validate(
    inputs: impl Iterator<Item = u64> + Clone,
    spends: impl Iterator<Item = u64> + Clone,
    kinds: impl Iterator<Item = OpKind>,
) -> Result<(), BodyError> {
    let positions = || inputs.clone().map(|p| (p, true)).chain(spends.clone().map(|p| (p, false)));
    // In range, and gathered to be compared: the one list a body needs.
    let mut sorted = Vec::with_capacity(inputs.size_hint().0 + spends.size_hint().0);
    let mut out_of_range = None;
    for (i, (p, input)) in positions().enumerate() {
        if p >= OUTPUT_CAPACITY && out_of_range.is_none() {
            out_of_range = Some((i, if input { BodyError::InputOutOfRange(p) } else { BodyError::SpendOutOfRange(p) }));
        }
        sorted.push(p);
    }
    // No two alike: sorted, a repeat has its like beside it.
    sorted.sort_unstable();
    let repeated = sorted.windows(2).any(|w| w[0] == w[1]);
    drop(sorted);
    // A body at fault is rare: only then is the first repeat looked for,
    // in order, a position at a time.
    let mut repeat = None;
    if repeated {
        let mut seen = std::collections::HashSet::new();
        for (i, (p, input)) in positions().enumerate() {
            if !seen.insert(p) {
                repeat = Some((i, if input { BodyError::DuplicateInput(p) } else { BodyError::DuplicateSpend(p) }));
                break;
            }
        }
    }
    // Inputs are judged before spends, and a position's range before its
    // being a repeat.
    match (out_of_range, repeat) {
        (Some((i, e)), Some((j, _))) if i <= j => return Err(e),
        (_, Some((_, e))) | (Some((_, e)), None) => return Err(e),
        (None, None) => {}
    }
    count_ops(kinds).map_err(BodyError::TooMany)?;
    Ok(())
}

/// Elements of the body commitment's input ([`body_commitment`]).
fn commitment_len(inputs: usize, outputs: usize, ops: usize, reveals: usize, sweeps: usize) -> usize {
    5 + 2 * (inputs + reveals + sweeps) + DIGEST * (2 * outputs + ops + 1)
}

/// The body's commitment from its items: each list of positions as its
/// count and two limbs a position, the outputs as their count and each
/// one's commitment and slot, the operations as their count and digests,
/// then the positions reveals spend (their digests leave them out), the
/// sweeps, and the proof's hash.
fn body_commitment(
    inputs: impl ExactSizeIterator<Item = u64>,
    outputs: impl ExactSizeIterator<Item = BlockOutput>,
    ops: impl ExactSizeIterator<Item = BlockNameOp> + Clone,
    sweeps: impl ExactSizeIterator<Item = u64>,
    proof_hash: &Digest,
) -> Digest {
    let reveals = ops.clone().filter(|op| op.spends().is_some()).count();
    let len = commitment_len(inputs.len(), outputs.len(), ops.len(), reveals, sweeps.len());
    let mut h = DomainHasher::new(DOM_BLOCK_BODY, len);
    let count = |h: &mut DomainHasher, n: usize| h.absorb(&[Fp::from_u64(n as u64)]);
    let position = |h: &mut DomainHasher, p: u64| {
        h.absorb(&[Fp::new((p & MASK30) as u32), Fp::from_u64(p >> 30)]);
    };
    count(&mut h, inputs.len());
    inputs.for_each(|p| position(&mut h, p));
    count(&mut h, outputs.len());
    for o in outputs {
        h.absorb(&o.commitment);
        h.absorb(&o.slot());
    }
    count(&mut h, ops.len());
    for op in ops.clone() {
        h.absorb(&op.digest());
    }
    count(&mut h, reveals);
    ops.filter_map(|op| op.spends()).for_each(|p| position(&mut h, p));
    count(&mut h, sweeps.len());
    sweeps.for_each(|p| position(&mut h, p));
    h.absorb(proof_hash);
    h.finish()
}

/// Hash of the proof bytes, length bound: their length, then the bytes
/// three to an element, absorbed as they are packed.
pub fn proof_hash(proof: &[u8]) -> Digest {
    let mut h = DomainHasher::new(DOM_BLOCK_PROOF, 1 + proof.len().div_ceil(3));
    h.absorb(&[Fp::from_u64(proof.len() as u64)]);
    let mut block = [Fp::ZERO; DIGEST];
    for chunk in proof.chunks(3 * DIGEST) {
        let n = chunk.len().div_ceil(3);
        for (x, v) in block.iter_mut().zip(packed(chunk)) {
            *x = v;
        }
        h.absorb(&block[..n]);
    }
    h.finish()
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// A body in its encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BodyRef<'a> {
    /// The whole body: all read once, so every item is whole and the
    /// positions are in range and distinct.
    bytes: &'a [u8],
    inputs: &'a [u8],
    outputs: &'a [u8],
    ops: &'a [u8],
    n_ops: usize,
    sweeps: &'a [u8],
    proof: &'a [u8],
}

/// Positions in their encoding, [`POSITION_BYTES`] each.
#[derive(Clone)]
pub struct Positions<'a>(core::slice::ChunksExact<'a, u8>);

impl Iterator for Positions<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        Some(read_position(self.0.next()?).expect("a whole position").0)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for Positions<'_> {}

/// A body's name operations in their encoding, decoded one at a time.
#[derive(Clone)]
pub struct BlockOps<'a> {
    rest: &'a [u8],
    left: usize,
}

impl Iterator for BlockOps<'_> {
    type Item = BlockNameOp;

    fn next(&mut self) -> Option<BlockNameOp> {
        if self.left == 0 {
            return None;
        }
        let (op, rest) = BlockNameOp::parse(self.rest).expect("checked when read");
        self.rest = rest;
        self.left -= 1;
        Some(op)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for BlockOps<'_> {}

/// A count of four bytes and that many items of `size` bytes each, from
/// the front of `bytes`: the items' bytes, and the rest.
fn section(bytes: &[u8], size: usize) -> Option<(&[u8], &[u8])> {
    let (n, rest) = read_u32(bytes)?;
    rest.split_at_checked((n as usize).checked_mul(size)?)
}

impl<'a> BodyRef<'a> {
    /// The four lists that come before the proof, from the front of
    /// `bytes`, each item whole; and the rest, which begins with the
    /// proof's length.
    fn lists(bytes: &'a [u8]) -> Option<(BodyRef<'a>, &'a [u8])> {
        let (inputs, rest) = section(bytes, POSITION_BYTES)?;
        let (outputs, rest) = section(rest, BLOCK_OUTPUT_SIZE)?;
        if !outputs.chunks_exact(BLOCK_OUTPUT_SIZE).all(|o| BlockOutput::from_bytes(o).is_some()) {
            return None;
        }
        let (n_ops, ops) = read_u32(rest)?;
        let mut rest = ops;
        for _ in 0..n_ops {
            rest = BlockNameOp::parse(rest)?.1;
        }
        let ops = &ops[..ops.len() - rest.len()];
        let (sweeps, rest) = section(rest, POSITION_BYTES)?;
        Some((BodyRef { bytes, inputs, outputs, ops, n_ops: n_ops as usize, sweeps, proof: &[] }, rest))
    }

    /// Reads and validates a body that is the whole of `bytes`: every item
    /// whole, the positions it spends in range and distinct, and no more
    /// operations of a kind than its cap.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<BodyRef<'a>, BodyError> {
        let (mut body, rest) = Self::lists(bytes).ok_or(BodyError::Malformed)?;
        let (proof, rest) = section(rest, 1).ok_or(BodyError::Malformed)?;
        if !rest.is_empty() {
            return Err(BodyError::Malformed);
        }
        body.proof = proof;
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), BodyError> {
        validate(
            self.inputs(),
            self.ops().filter_map(|op| op.spends()).chain(self.sweeps()),
            self.ops().map(|op| op.kind()).chain(self.sweeps().map(|_| OpKind::Sweep)),
        )
    }

    /// The body's encoding.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Its serialized size.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// State tree positions being spent, in transaction order.
    pub fn inputs(&self) -> Positions<'a> {
        Positions(self.inputs.chunks_exact(POSITION_BYTES))
    }

    /// The new outputs, in tree order.
    pub fn outputs(&self) -> impl ExactSizeIterator<Item = BlockOutput> + Clone + 'a {
        self.outputs.chunks_exact(BLOCK_OUTPUT_SIZE).map(|o| BlockOutput::from_bytes(o).expect("checked when read"))
    }

    /// Name operations, in order.
    pub fn ops(&self) -> BlockOps<'a> {
        BlockOps { rest: self.ops, left: self.n_ops }
    }

    /// Positions of the commits swept, in order.
    pub fn sweeps(&self) -> Positions<'a> {
        Positions(self.sweeps.chunks_exact(POSITION_BYTES))
    }

    /// The validity proof.
    pub fn proof(&self) -> &'a [u8] {
        self.proof
    }

    /// How many commits the block makes.
    pub fn commits(&self) -> usize {
        self.ops().filter(|op| op.kind() == OpKind::Commit).count()
    }

    /// The counter positions the commits take: after the outputs, in order.
    pub fn commit_positions(&self, first_output: u64) -> core::ops::Range<u64> {
        let first = first_output + self.outputs().len() as u64;
        first..first + self.commits() as u64
    }

    /// Every position the block spends: inputs, then the commits its
    /// reveals and sweeps consume.
    pub fn spent_positions(&self) -> impl Iterator<Item = u64> + 'a {
        self.inputs().chain(self.ops().filter_map(|op| op.spends())).chain(self.sweeps())
    }

    /// Serialized size of the name section's items (operations and swept
    /// positions), without the counts.
    pub fn names_size(&self) -> usize {
        self.ops.len() + self.sweeps.len()
    }

    /// Hash of the proof bytes, length bound.
    pub fn proof_hash(&self) -> Digest {
        proof_hash(self.proof)
    }

    /// Commitment to inputs, outputs, name operations (by digest, plus the
    /// positions reveals spend), sweeps and proof.
    pub fn commitment(&self) -> Digest {
        self.commitment_with(&self.proof_hash())
    }

    /// [`BodyRef::commitment`] with the proof's hash given: what a lite
    /// block ([`Block::lite_bytes`]) carries in place of the proof.
    pub fn commitment_with(&self, proof_hash: &Digest) -> Digest {
        body_commitment(self.inputs(), self.outputs(), self.ops(), self.sweeps(), proof_hash)
    }

    /// The body, owned.
    pub fn to_body(&self) -> Body {
        Body {
            inputs: self.inputs().collect(),
            outputs: self.outputs().collect(),
            ops: self.ops().collect(),
            sweeps: self.sweeps().collect(),
            proof: self.proof.to_vec(),
        }
    }
}

impl fmt::Debug for BodyRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyRef")
            .field("inputs", &self.inputs().len())
            .field("outputs", &self.outputs().len())
            .field("ops", &self.n_ops)
            .field("sweeps", &self.sweeps().len())
            .field("proof", &self.proof.len())
            .finish()
    }
}

/// A block in its encoding: its header, read, and its body's view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockRef<'a> {
    header: Header,
    body: BodyRef<'a>,
    bytes: &'a [u8],
}

impl<'a> BlockRef<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<BlockRef<'a>, BodyError> {
        let (head, body) = bytes.split_at_checked(HEADER_SIZE).ok_or(BodyError::Malformed)?;
        let header = Header::from_bytes(head).ok_or(BodyError::Malformed)?;
        Ok(BlockRef { header, body: BodyRef::from_bytes(body)?, bytes })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn body(&self) -> BodyRef<'a> {
        self.body
    }

    /// The block's encoding.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Its serialized size.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the header commits to this body.
    pub fn body_commitment_matches(&self) -> bool {
        self.header.body_commitment == self.body.commitment()
    }

    /// The block, owned.
    pub fn to_block(&self) -> Block {
        Block { header: self.header, body: self.body.to_body() }
    }
}

// ---------------------------------------------------------------------------
// Owned forms: for building
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Body {
    /// State tree positions being spent, in transaction order, no repeats.
    pub inputs: Vec<u64>,
    /// The new outputs, in tree order.
    pub outputs: Vec<BlockOutput>,
    /// Name operations, in order.
    pub ops: Vec<BlockNameOp>,
    /// Positions of the commits swept, in order.
    pub sweeps: Vec<u64>,
    /// Validity proof.
    pub proof: Vec<u8>,
}

impl Body {
    /// Checks that inputs and sweeps are in range and distinct and
    /// operation counts within the caps.
    pub fn validate(&self) -> Result<(), BodyError> {
        validate(
            self.inputs.iter().copied(),
            self.ops.iter().filter_map(BlockNameOp::spends).chain(self.sweeps.iter().copied()),
            self.ops.iter().map(BlockNameOp::kind).chain(self.sweeps.iter().map(|_| OpKind::Sweep)),
        )
    }

    /// The digests of the name operations, in order.
    pub fn op_digests(&self) -> Vec<Digest> {
        self.ops.iter().map(BlockNameOp::digest).collect()
    }

    /// The counter positions the commits take: after the outputs, in order.
    pub fn commit_positions(&self, first_output: u64) -> Vec<u64> {
        let first = first_output + self.outputs.len() as u64;
        (0..self.commits() as u64).map(|i| first + i).collect()
    }

    /// How many commits the block makes.
    pub fn commits(&self) -> usize {
        self.ops.iter().filter(|op| op.kind() == OpKind::Commit).count()
    }

    /// Every position the block spends: inputs, then the commits its
    /// reveals and sweeps consume.
    pub fn spent_positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.inputs
            .iter()
            .copied()
            .chain(self.ops.iter().filter_map(BlockNameOp::spends))
            .chain(self.sweeps.iter().copied())
    }

    /// Serialized size of the name section's items (operations and swept
    /// positions), without the counts.
    pub fn names_size(&self) -> usize {
        self.ops.iter().map(BlockNameOp::size).sum::<usize>() + self.sweeps.len() * POSITION_BYTES
    }

    /// Hash of the proof bytes, length bound.
    pub fn proof_hash(&self) -> Digest {
        proof_hash(&self.proof)
    }

    /// Commitment to inputs, outputs, name operations (by digest, plus the
    /// positions reveals spend), sweeps and proof.
    pub fn commitment(&self) -> Digest {
        self.commitment_with(&self.proof_hash())
    }

    /// [`Body::commitment`] with the proof's hash given: what a lite block
    /// ([`Block::lite_bytes`]) carries in place of the proof.
    pub fn commitment_with(&self, proof_hash: &Digest) -> Digest {
        body_commitment(
            self.inputs.iter().copied(),
            self.outputs.iter().copied(),
            self.ops.iter().copied(),
            self.sweeps.iter().copied(),
            proof_hash,
        )
    }

    pub fn size(&self) -> usize {
        Self::size_of(self.inputs.len(), self.outputs.len(), self.names_size(), self.proof.len())
    }

    /// The serialized size of a body with these counts, a name section of
    /// `names` bytes ([`names_size`](Body::names_size)) and a proof of
    /// `proof` bytes: what a block builder checks against the size limit.
    pub fn size_of(inputs: usize, outputs: usize, names: usize, proof: usize) -> usize {
        20 + inputs * POSITION_BYTES + outputs * BLOCK_OUTPUT_SIZE + names + proof
    }

    /// The body's bytes. Panics for a position that does not fit its six
    /// bytes: such a body has no encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        let positions = |out: &mut Vec<u8>, ps: &[u64]| {
            out.extend_from_slice(&(ps.len() as u32).to_le_bytes());
            for &p in ps {
                let at = out.len();
                out.resize(at + POSITION_BYTES, 0);
                write_position(&mut out[at..], p);
            }
        };
        positions(&mut out, &self.inputs);
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.to_bytes());
        }
        out.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            let at = out.len();
            out.resize(at + op.size(), 0);
            op.write_bytes(&mut out[at..]);
        }
        positions(&mut out, &self.sweeps);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out
    }

    /// Parses and validates a body; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Body, BodyError> {
        Ok(BodyRef::from_bytes(bytes)?.to_body())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: Header,
    pub body: Body,
}

impl Block {
    /// Its serialized size: what `to_bytes` makes.
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.body.size()
    }

    /// Whether the header commits to this body.
    pub fn body_commitment_matches(&self) -> bool {
        self.header.body_commitment == self.body.commitment()
    }

    /// The block without its proof: its bytes up to and with the proof's
    /// length, then the proof's hash (32 bytes) in place of the proof. All
    /// its body commitment needs: a node fetches so the blocks of a batch
    /// whose proofs the batch's last block's chain proof attests, a few KB
    /// rather than the proof's 200 or so each.
    pub fn lite_bytes(&self) -> Vec<u8> {
        let mut out = self.to_bytes();
        out.truncate(out.len() - self.body.proof.len());
        out.extend_from_slice(&digest_to_bytes(&self.body.proof_hash()));
        out
    }

    /// A lite block's header and the body commitment its bytes make (the
    /// proof's hash as given), or `None` if malformed: the header commits
    /// to it if the lite block is the block's. Read where the bytes lie.
    pub fn lite_commitment(bytes: &[u8]) -> Option<(Header, Digest)> {
        let (head, body) = bytes.split_at_checked(HEADER_SIZE)?;
        let header = Header::from_bytes(head)?;
        // The lists as in a block, then the proof's length (which the hash
        // binds, not these four bytes) and its hash.
        let (lists, rest) = BodyRef::lists(body)?;
        let (_length, rest) = read_u32(rest)?;
        let (hash, rest) = read_digest(rest)?;
        if !rest.is_empty() {
            return None;
        }
        lists.validate().ok()?;
        Some((header, lists.commitment_with(&hash)))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.body.size());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.body.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Block, BodyError> {
        Ok(BlockRef::from_bytes(bytes)?.to_block())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::{MAX_COMMITS, MAX_REVEALS, MAX_SWEEPS, MAX_UPDATES, Record};
    use crate::output::{Key, Output, memo5, pubkey_hash};
    use crate::pow::{Dataset, LazyDataset, PowParams, SeedText, nonce_from_u64};

    fn d(n: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(n + i as u32))
    }

    fn header() -> Header {
        Header {
            prev_hash: d(1),
            height: 7,
            timestamp: 1_700_000_000,
            body_commitment: d(100),
            state_root: d(200),
            aux: [9u8; 32],
            mix: d(300),
            nonce: nonce_from_u64(42),
        }
    }

    fn outputs() -> Vec<BlockOutput> {
        let mut seed = [0u8; 32];
        seed[0] = 9;
        let pk = Key::generate(&seed).public_key();
        let memo = core::array::from_fn(|i| Fp::new(1000 + i as u32));
        let with_memo = Output::with_memo(&pubkey_hash(&pk), u64::MAX, memo);
        vec![Output::new(&pk, 5).block_output(), with_memo.block_output()]
    }

    #[test]
    fn header_roundtrip_and_hashes() {
        let h = header();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 204);
        assert_eq!(HEADER_SIZE, 204);
        assert_eq!(Header::from_bytes(&bytes), Some(h));
        // The aux bytes are under the proof of work.
        let other = Header { aux: [10u8; 32], ..h };
        assert_ne!(other.pow_hash(), h.pow_hash());
        assert_ne!(other.hash(), h.hash());
        assert!(Header::from_bytes(&bytes[1..]).is_none());
        let mut bad = bytes;
        bad[..4].copy_from_slice(&0x7800_0001u32.to_le_bytes());
        assert!(Header::from_bytes(&bad).is_none());

        // pow_hash ignores mix and nonce; hash does not.
        let mut h2 = h;
        h2.mix = d(999);
        h2.nonce = nonce_from_u64(1);
        assert_eq!(h2.pow_hash(), h.pow_hash());
        assert_ne!(h2.hash(), h.hash());
        for f in [
            |x: &mut Header| x.prev_hash = d(2),
            |x: &mut Header| x.height += 1,
            |x: &mut Header| x.timestamp += 1,
            |x: &mut Header| x.timestamp += 1 << 40,
            |x: &mut Header| x.body_commitment = d(2),
            |x: &mut Header| x.state_root = d(2),
        ] {
            let mut x = h;
            f(&mut x);
            assert_ne!(x.pow_hash(), h.pow_hash());
        }
        // The hashes are the plain sponge of their fields in a row: the
        // tag, then each field, bytes three to an element.
        let aux: Vec<Fp> = packed(&h.aux).collect();
        let fields = [
            &[Fp::new(DOM_POW_HASH)][..],
            &h.prev_hash,
            &[Fp::new(7)],
            &[Fp::new(1_700_000_000 & ((1 << 30) - 1)), Fp::new(1_700_000_000 >> 30), Fp::ZERO],
            &h.body_commitment,
            &h.state_root,
            &aux,
        ]
        .concat();
        assert_eq!((fields.len(), h.pow_hash()), (40, crate::poseidon2::hash(&fields)));
        let nonce: Vec<Fp> = packed(&h.nonce).collect();
        let fields = [&[Fp::new(DOM_BLOCK_ID)][..], &h.pow_hash(), &h.mix, &nonce].concat();
        assert_eq!((fields.len(), h.hash()), (28, crate::poseidon2::hash(&fields)));
        // Each of the other fields that is a digest must be one.
        for at in [44, 76, 140] {
            let mut bad = bytes;
            bad[at..at + 4].copy_from_slice(&0x7800_0001u32.to_le_bytes());
            assert!(Header::from_bytes(&bad).is_none(), "digest at {at}");
        }
    }

    fn record(name: &str, n: u32) -> Record {
        Record::new(name.as_bytes(), d(n), d(n + 1), d(n + 2)).unwrap()
    }

    fn ops() -> Vec<BlockNameOp> {
        vec![
            BlockNameOp::Commit { commit: d(10), memo: memo5(d(11)) },
            BlockNameOp::Reveal { record: record("alice", 20), commit: 12 },
            BlockNameOp::Update(record("bob_99", 30)),
            BlockNameOp::Reveal { record: record("carol", 40), commit: 14 },
        ]
    }

    #[test]
    fn body_canonical_form() {
        let outs = outputs();
        let ok = Body {
            inputs: vec![5, 1, 0, OUTPUT_CAPACITY - 1],
            outputs: outs.clone(),
            proof: vec![1, 2, 3],
            ..Default::default()
        };
        assert_eq!(ok.validate(), Ok(()));
        let dup = Body { inputs: vec![1, 7, 1], ..ok.clone() };
        assert_eq!(dup.validate(), Err(BodyError::DuplicateInput(1)));
        let big = Body { inputs: vec![OUTPUT_CAPACITY], ..ok.clone() };
        assert_eq!(big.validate(), Err(BodyError::InputOutOfRange(OUTPUT_CAPACITY)));
        assert_eq!(Body::default().validate(), Ok(()));

        let bytes = ok.to_bytes();
        assert_eq!(bytes.len(), ok.size());
        assert_eq!(bytes.len(), 20 + 4 * 6 + 2 * 60 + 3);
        assert_eq!(Body::from_bytes(&bytes), Ok(ok.clone()));
        assert_eq!(Body::from_bytes(&dup.to_bytes()), Err(BodyError::DuplicateInput(1)));
        assert_eq!(Body::from_bytes(&big.to_bytes()), Err(BodyError::InputOutOfRange(OUTPUT_CAPACITY)));
        assert_eq!(Body::from_bytes(&bytes[..bytes.len() - 1]), Err(BodyError::Malformed));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Body::from_bytes(&extra), Err(BodyError::Malformed));
        // Six-byte positions hold the last position there is.
        let top = Body { inputs: vec![OUTPUT_CAPACITY - 1], sweeps: vec![OUTPUT_CAPACITY - 2], ..Default::default() };
        assert_eq!(OUTPUT_CAPACITY, 1 << 41);
        let back = Body::from_bytes(&top.to_bytes()).unwrap();
        assert_eq!((back.inputs, back.sweeps), (vec![OUTPUT_CAPACITY - 1], vec![OUTPUT_CAPACITY - 2]));
        // The first fault, in order, is the one reported: inputs before
        // spends, a position's range before its being a repeat.
        let both = |inputs: Vec<u64>, sweeps: Vec<u64>| Body { inputs, sweeps, ..Default::default() }.validate();
        let far = OUTPUT_CAPACITY + 5;
        assert_eq!(both(vec![1, far, 1], vec![]), Err(BodyError::InputOutOfRange(far)));
        assert_eq!(both(vec![1, 1, far], vec![]), Err(BodyError::DuplicateInput(1)));
        assert_eq!(both(vec![far, far], vec![]), Err(BodyError::InputOutOfRange(far)));
        assert_eq!(both(vec![3], vec![far, 3]), Err(BodyError::SpendOutOfRange(far)));
        assert_eq!(both(vec![3], vec![3, far]), Err(BodyError::DuplicateSpend(3)));
        assert_eq!(both(vec![3, 3], vec![far]), Err(BodyError::DuplicateInput(3)));
        assert_eq!(both(vec![2, 9], vec![4, 9, 2]), Err(BodyError::DuplicateSpend(9)));
        assert!(BodyError::DuplicateInput(1).to_string().contains("twice"));
        // A position that does not fit six bytes has no encoding.
        let wide = Body { inputs: vec![1 << 48], ..Default::default() };
        assert!(std::panic::catch_unwind(|| wide.to_bytes()).is_err());
    }

    #[test]
    fn name_section() {
        let ok = Body { inputs: vec![3], outputs: outputs(), ops: ops(), sweeps: vec![7, 8], proof: vec![1] };
        assert_eq!(ok.validate(), Ok(()));
        let bytes = ok.to_bytes();
        assert_eq!(bytes.len(), ok.size());
        assert_eq!(ok.names_size(), 53 + 2 * (98 + 5 + 6) + (98 + 6) + 2 * 6);
        assert_eq!(bytes.len(), 20 + 6 + 2 * 60 + ok.names_size() + 1);
        assert_eq!(Body::from_bytes(&bytes), Ok(ok.clone()));
        assert_eq!(Body::from_bytes(&bytes[..bytes.len() - 1]), Err(BodyError::Malformed));
        assert_eq!(ok.op_digests().len(), 4);
        assert_eq!(ok.op_digests(), ops().iter().map(|o| o.digest()).collect::<Vec<_>>());
        // A commit takes the position after the outputs.
        assert_eq!(ok.commit_positions(100), vec![102]);
        assert_eq!(Body::default().commit_positions(5), Vec::<u64>::new());

        // The commitment covers every part of the section.
        let c = ok.commitment();
        let mut b = ok.clone();
        b.ops.swap(0, 3);
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.ops[1] = BlockNameOp::Update(record("alice", 20));
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        if let BlockNameOp::Reveal { commit, .. } = &mut b.ops[1] {
            *commit = 9;
        }
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.ops.pop();
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.sweeps[0] = 9;
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.sweeps.pop();
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        if let BlockNameOp::Reveal { record, .. } = &mut b.ops[1] {
            record.memo = d(0);
        }
        assert_ne!(b.commitment(), c);

        // Validation: sweeps distinct and apart from inputs, in range; caps.
        let bad = Body { sweeps: vec![1, 1], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::DuplicateSpend(1)));
        let bad = Body { inputs: vec![4], sweeps: vec![4], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::DuplicateSpend(4)));
        let bad = Body { ops: ops(), sweeps: vec![12], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::DuplicateSpend(12)));
        let bad = Body { sweeps: vec![OUTPUT_CAPACITY], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::SpendOutOfRange(OUTPUT_CAPACITY)));
        assert_eq!(ok.spent_positions().collect::<Vec<_>>(), vec![3, 12, 14, 7, 8]);
        let bad = Body { sweeps: (0..MAX_SWEEPS as u64 + 1).collect(), ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Sweep)));
        assert_eq!(Body::from_bytes(&bad.to_bytes()), Err(BodyError::TooMany(OpKind::Sweep)));
        let full = Body { sweeps: (0..MAX_SWEEPS as u64).collect(), ..Default::default() };
        assert_eq!(full.validate(), Ok(()));
        let reveal = |i: u64| BlockNameOp::Reveal { record: record("a", 1), commit: 100 + i };
        let bad = Body { ops: (0..MAX_REVEALS as u64 + 1).map(reveal).collect(), ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Reveal)));
        let bad = Body { ops: vec![BlockNameOp::Update(record("a", 1)); MAX_UPDATES + 1], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Update)));
        let bad = Body { ops: vec![ops()[0]; MAX_COMMITS + 1], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Commit)));
        assert!(BodyError::TooMany(OpKind::Commit).to_string().contains("commit"));
        let at_caps = Body {
            ops: [
                (0..MAX_REVEALS as u64).map(reveal).collect(),
                vec![BlockNameOp::Update(record("a", 1)); MAX_UPDATES],
                vec![ops()[0]; MAX_COMMITS],
            ]
            .concat(),
            ..Default::default()
        };
        assert_eq!(at_caps.validate(), Ok(()));
        assert_eq!(Body::from_bytes(&at_caps.to_bytes()), Ok(at_caps));
        // A name that is none is no operation: its bytes are no body.
        let named = Body { ops: vec![reveal(0)], ..Default::default() };
        let mut bytes = named.to_bytes();
        let name_at = 4 + 4 + 4 + 1 + 1;
        assert_eq!(bytes[name_at], b'a');
        bytes[name_at] = b'A';
        assert_eq!(Body::from_bytes(&bytes), Err(BodyError::Malformed));
    }

    #[test]
    fn body_commitment_covers_everything() {
        let outs = outputs();
        let base = Body { inputs: vec![3, 9], outputs: outs.clone(), proof: vec![7; 100], ..Default::default() };
        let c = base.commitment();
        assert_eq!(c, base.clone().commitment());
        let mut b = base.clone();
        b.inputs[0] = 4;
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.inputs.push(10);
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.outputs[0].commitment[0] += Fp::ONE;
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.outputs.swap(0, 1);
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.proof[50] ^= 1;
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.proof.push(0);
        assert_ne!(b.commitment(), c);
        assert_ne!(Body::default().commitment(), [Fp::ZERO; DIGEST]);
        // A position's two limbs: its low 30 bits and the rest.
        let mut b = base.clone();
        b.inputs[0] = 3 + (1 << 30);
        assert_ne!(b.commitment(), c);
    }

    /// The commitment and the proof's hash are `hash_domain` of their
    /// layouts: counts, positions as two limbs, outputs as commitment and
    /// slot, operations as digests, the positions reveals spend, the
    /// sweeps and the proof's hash; and the proof's length and its bytes
    /// three to an element, whatever its length.
    #[test]
    fn the_commitment_is_laid_out_as_documented() {
        use crate::hash::hash_domain;
        for len in [0usize, 1, 2, 3, 23, 24, 25, 48, 100, 1000] {
            let proof: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let mut v = vec![Fp::from_u64(len as u64)];
            v.extend(packed(&proof));
            assert_eq!(proof_hash(&proof), hash_domain(DOM_BLOCK_PROOF, &v), "proof of {len} bytes");
        }
        let far = OUTPUT_CAPACITY - 1;
        let body = Body { inputs: vec![3, far], outputs: outputs(), ops: ops(), sweeps: vec![6, 1 << 35], proof: vec![9; 50] };
        let limbs = |p: u64| [Fp::new((p & ((1 << 30) - 1)) as u32), Fp::new((p >> 30) as u32)];
        let mut v = vec![Fp::new(2)];
        v.extend([limbs(3), limbs(far)].concat());
        v.push(Fp::new(2));
        for o in &body.outputs {
            v.extend(o.commitment);
            v.extend(o.slot());
        }
        v.push(Fp::new(4));
        for op in &body.ops {
            v.extend(op.digest());
        }
        v.push(Fp::new(2));
        v.extend([limbs(12), limbs(14)].concat());
        v.push(Fp::new(2));
        v.extend([limbs(6), limbs(1 << 35)].concat());
        v.extend(body.proof_hash());
        assert_eq!(v.len(), commitment_len(2, 2, 4, 2, 2));
        assert_eq!(body.commitment(), hash_domain(DOM_BLOCK_BODY, &v));
        assert_eq!(body.commitment(), body.commitment_with(&proof_hash(&body.proof)));
    }

    #[test]
    fn block_roundtrip() {
        let body = Body { inputs: vec![1, 2], outputs: outputs(), ops: ops(), sweeps: vec![6], proof: vec![0xab; 10] };
        let mut h = header();
        h.body_commitment = body.commitment();
        let block = Block { header: h, body };
        assert!(block.body_commitment_matches());
        let bytes = block.to_bytes();
        assert_eq!(bytes.len(), block.size());
        assert_eq!(Block::from_bytes(&bytes), Ok(block.clone()));
        assert_eq!(Block::from_bytes(&bytes[..100]), Err(BodyError::Malformed));
        let mut other = block.clone();
        other.body.proof[0] ^= 1;
        assert!(!other.body_commitment_matches());
    }

    /// The view of a block's bytes gives what the owned block gives: its
    /// header, every list, the proof, sizes, positions, hashes.
    #[test]
    fn the_view_agrees_with_the_owned_form() {
        let body = Body { inputs: vec![1, 2], outputs: outputs(), ops: ops(), sweeps: vec![6], proof: vec![0xab; 1000] };
        let mut h = header();
        h.body_commitment = body.commitment();
        let block = Block { header: h, body: body.clone() };
        let bytes = block.to_bytes();
        let view = BlockRef::from_bytes(&bytes).unwrap();
        assert_eq!((view.as_bytes(), view.size(), block.size()), (&bytes[..], bytes.len(), bytes.len()));
        assert_eq!((view.header(), view.to_block()), (&h, block.clone()));
        assert!(view.body_commitment_matches());
        let b = view.body();
        assert_eq!((b.as_bytes(), b.size(), body.size()), (&bytes[HEADER_SIZE..], bytes.len() - HEADER_SIZE, bytes.len() - HEADER_SIZE));
        assert_eq!(b.to_body(), body);
        assert_eq!(b.inputs().collect::<Vec<_>>(), body.inputs);
        assert_eq!(b.outputs().collect::<Vec<_>>(), body.outputs);
        assert_eq!(b.ops().collect::<Vec<_>>(), body.ops);
        assert_eq!(b.sweeps().collect::<Vec<_>>(), body.sweeps);
        assert_eq!((b.inputs().len(), b.outputs().len(), b.ops().len(), b.sweeps().len()), (2, 2, 4, 1));
        assert_eq!(b.proof(), &body.proof[..]);
        assert_eq!((b.commits(), body.commits()), (1, 1));
        assert_eq!(b.commit_positions(100).collect::<Vec<_>>(), body.commit_positions(100));
        assert_eq!(b.spent_positions().collect::<Vec<_>>(), body.spent_positions().collect::<Vec<_>>());
        assert_eq!(b.names_size(), body.names_size());
        assert_eq!((b.proof_hash(), b.commitment()), (body.proof_hash(), body.commitment()));
        assert_eq!(b.commitment_with(&d(5)), body.commitment_with(&d(5)));
        assert!(format!("{view:?}").contains("outputs: 2"));
        // Another proof: another body, and the header no longer commits to it.
        let mut other = bytes.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(!BlockRef::from_bytes(&other).unwrap().body_commitment_matches());
        // A body at fault is refused as the owned form refuses it.
        for bad in [
            Body { inputs: vec![1, 7, 1], ..body.clone() },
            Body { inputs: vec![OUTPUT_CAPACITY], ..body.clone() },
            Body { sweeps: vec![12], ..body.clone() },
            Body { sweeps: vec![OUTPUT_CAPACITY + 1], ..body.clone() },
            Body { sweeps: (100..117).collect(), ..body.clone() },
        ] {
            let err = bad.validate().unwrap_err();
            assert_eq!(BodyRef::from_bytes(&bad.to_bytes()).unwrap_err(), err);
            let block = Block { header: h, body: bad };
            assert_eq!(BlockRef::from_bytes(&block.to_bytes()).unwrap_err(), err);
        }
        // Bytes that are no body: each list cut short or over-counted, an
        // element that is none, bytes after the proof.
        let body_bytes = body.to_bytes();
        for cut in [0, 3, 4, 10, 100, body_bytes.len() - 1] {
            assert_eq!(BodyRef::from_bytes(&body_bytes[..cut]).unwrap_err(), BodyError::Malformed, "cut at {cut}");
        }
        assert_eq!(BodyRef::from_bytes(&[&body_bytes[..], &[0]].concat()).unwrap_err(), BodyError::Malformed);
        let n_out = 4 + 2 * POSITION_BYTES;
        let n_ops = n_out + 4 + 2 * BLOCK_OUTPUT_SIZE;
        let n_sweeps = n_ops + 4 + body.ops.iter().map(BlockNameOp::size).sum::<usize>();
        let n_proof = n_sweeps + 4 + POSITION_BYTES;
        for (name, at, n) in [("inputs", 0, 2u32), ("outputs", n_out, 2), ("operations", n_ops, 4), ("sweeps", n_sweeps, 1), ("proof", n_proof, 1000)] {
            assert_eq!(body_bytes[at..at + 4], n.to_le_bytes(), "{name}");
            for other in [n - 1, n + 1, u32::MAX] {
                let mut bad = body_bytes.clone();
                bad[at..at + 4].copy_from_slice(&other.to_le_bytes());
                assert_eq!(BodyRef::from_bytes(&bad).unwrap_err(), BodyError::Malformed, "{other} {name}");
            }
        }
        let mut bad = body_bytes.clone();
        bad[n_out + 4..n_out + 8].copy_from_slice(&crate::poseidon2::P.to_le_bytes());
        assert_eq!(BodyRef::from_bytes(&bad).unwrap_err(), BodyError::Malformed);
        assert_eq!(BlockRef::from_bytes(&bytes[..HEADER_SIZE - 1]).unwrap_err(), BodyError::Malformed);
        let mut bad = bytes.clone();
        bad[..4].copy_from_slice(&crate::poseidon2::P.to_le_bytes());
        assert_eq!(BlockRef::from_bytes(&bad).unwrap_err(), BodyError::Malformed);
        // A body of nothing is one.
        let empty = BodyRef::from_bytes(&[0u8; 20]).unwrap();
        assert_eq!((empty.inputs().len(), empty.outputs().len(), empty.ops().len(), empty.proof().len()), (0, 0, 0, 0));
        assert_eq!(empty.commitment(), Body::default().commitment());
    }

    /// A lite block (the proof's hash in place of the proof) makes the body
    /// commitment its header commits to; a wrong proof hash, an altered
    /// body or a short one does not.
    #[test]
    fn lite_block_commits_as_the_block() {
        let body = Body { inputs: vec![1, 2], outputs: outputs(), ops: ops(), sweeps: vec![6], proof: vec![0xab; 3000] };
        let mut h = header();
        h.body_commitment = body.commitment();
        let block = Block { header: h, body };
        let lite = block.lite_bytes();
        assert_eq!(lite.len(), block.to_bytes().len() - 3000 + 32);
        assert_eq!(Block::lite_commitment(&lite), Some((block.header, block.header.body_commitment)));
        // the proof's hash changed: another commitment
        let mut bad = lite.clone();
        let n = bad.len();
        bad[n - 32] ^= 1;
        assert_ne!(Block::lite_commitment(&bad).map(|(_, c)| c), Some(block.header.body_commitment));
        // an output's amount changed: another commitment
        let mut bad = lite.clone();
        bad[HEADER_SIZE + 4 + 2 * POSITION_BYTES + 4 + 32 + 20] ^= 1;
        assert_ne!(Block::lite_commitment(&bad).map(|(_, c)| c), Some(block.header.body_commitment));
        // cut short, or the hash's bytes not canonical: malformed
        assert_ne!(Block::lite_commitment(&lite[..lite.len() - 1]).map(|(_, c)| c), Some(block.header.body_commitment));
        let mut bad = lite.clone();
        bad[n - 4..].copy_from_slice(&[0xff; 4]);
        assert_eq!(Block::lite_commitment(&bad), None);
        assert_eq!(Block::lite_commitment(&[&lite[..], &[0]].concat()), None);
        assert_eq!(Block::lite_commitment(&lite[..HEADER_SIZE + 3]), None);
        // The proof's length is bound by its hash, not by the four bytes
        // before it: changing those changes nothing.
        let mut same = lite.clone();
        same[n - 36..n - 32].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(Block::lite_commitment(&same), Block::lite_commitment(&lite));
        // A body at fault is no lite block either.
        let mut twice = block.clone();
        twice.body.inputs = vec![1, 1];
        assert_eq!(Block::lite_commitment(&twice.lite_bytes()), None);
    }

    /// The header, body and block decoders, fuzzed: no input makes them
    /// panic, a view's bytes are the bytes read, and what they decode
    /// encodes back to the same bytes.
    #[test]
    fn fuzz_block_decoders() {
        let body = Body { inputs: vec![1, 2], outputs: outputs(), ops: ops(), sweeps: vec![6], proof: vec![0xab; 10] };
        let mut h = header();
        h.body_commitment = body.commitment();
        let block = Block { header: h, body: body.clone() };
        let empty = Body::default();
        crate::test_util::fuzz_decoder("Header::from_bytes", &[h.to_bytes().to_vec()], 20_000, |b| {
            Header::from_bytes(b).map(|h| {
                let _ = (h.pow_hash(), h.hash(), h.quick_pow_check(&Target::MAX));
                Some(h.to_bytes().to_vec())
            })
        });
        crate::test_util::fuzz_decoder("BodyRef::from_bytes", &[body.to_bytes(), empty.to_bytes()], 20_000, |b| {
            BodyRef::from_bytes(b).ok().map(|view| {
                let owned = view.to_body();
                assert_eq!(owned.validate(), Ok(()));
                assert_eq!(owned.to_bytes(), view.as_bytes());
                assert_eq!(owned.commitment(), view.commitment());
                assert_eq!(view.spent_positions().count(), owned.spent_positions().count());
                Some(view.as_bytes().to_vec())
            })
        });
        crate::test_util::fuzz_decoder("Body::from_bytes", &[body.to_bytes(), empty.to_bytes()], 20_000, |b| {
            Body::from_bytes(b).ok().map(|x| Some(x.to_bytes()))
        });
        crate::test_util::fuzz_decoder("Block::from_bytes", &[block.to_bytes()], 20_000, |b| {
            assert_eq!(BlockRef::from_bytes(b).map(|v| v.to_block()), Block::from_bytes(b));
            Block::from_bytes(b).ok().map(|x| Some(x.to_bytes()))
        });
        crate::test_util::fuzz_decoder("Block::lite_commitment", &[block.lite_bytes()], 20_000, |b| {
            Block::lite_commitment(b).map(|_| None)
        });
    }

    #[test]
    fn header_proof_of_work() {
        // A table that doubles once: epochs of 10 blocks.
        let params = PowParams { log_dataset_items: 8, max_log_dataset_items: 9, epoch_blocks: 10, parents: 64, accesses: 64 };
        let text: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 253) as u8).collect();
        let seed = SeedText::from_bytes(params, &text);
        let dataset = Dataset::generate(&seed, 8);
        let target = Target::from_leading_zero_bits(5);
        let mut h = header();
        let (nonce, out) = pow::mine(&dataset, &h.pow_hash(), &target, (0..5000).map(nonce_from_u64)).unwrap();
        h.nonce = nonce;
        h.mix = out.mix;
        assert_eq!(h.pow_output(&dataset), out);
        assert!(h.quick_pow_check(&target));
        // From the seed text alone, from a whole table and from a miner's.
        assert!(h.verify_pow(&seed.at(h.height as u64), &target));
        assert!(h.verify_pow(&dataset, &target));
        assert!(h.verify_pow(&LazyDataset::new(&seed, 8).unwrap(), &target));
        // A forged mix that passes the quick check still fails the full check.
        let mut forged = h;
        forged.mix = d(1);
        let mut n = 0u64;
        while !forged.quick_pow_check(&target) {
            n += 1;
            forged.nonce = nonce_from_u64(1_000_000 + n);
        }
        assert!(!forged.verify_pow(&seed.at(7), &target));
        let mut harder = h;
        harder.height += 1;
        assert!(!harder.verify_pow(&seed.at(8), &target) || harder.pow_output(&dataset).mix != h.mix);
        assert!(!h.verify_pow(&seed.at(7), &Target::from_leading_zero_bits(200)));
        // The work is of the table of the header's height: the next
        // epoch's table does not verify it, and a header of the next epoch
        // is not verified by this one's.
        let larger = Dataset::generate(&seed, 9);
        assert!(!h.verify_pow(&larger, &target));
        assert!(!h.verify_pow(&seed.at(10), &target));
        let mut next = Header { height: 10, ..h };
        let (nonce, out) = pow::mine(&larger, &next.pow_hash(), &target, (0..5000).map(nonce_from_u64)).unwrap();
        next.nonce = nonce;
        next.mix = out.mix;
        assert!(next.verify_pow(&seed.at(10), &target) && next.verify_pow(&larger, &target));
        assert!(!next.verify_pow(&dataset, &target) && !next.verify_pow(&seed.at(9), &target));
    }
}
