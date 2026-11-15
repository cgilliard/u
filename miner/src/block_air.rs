//! The transaction segments of a block's proof: what they say in public.
//!
//! A block's transactions are proven in segments, each a trace of a
//! fixed number of rows, and a segment's proof speaks of the state
//! before it and after it: [`SegmentPublic`]. Segments chain, each
//! beginning where the one before ended, and what the first begins with
//! and the last ends with is the block's own statement
//! ([`crate::chain::verify`]).
//!
//! What chains:
//!
//! - The **state root**, before and after.
//! - Four **sponges**, each absorbing what the block lists in public, so
//!   that the proof is of this body and no other: the positions spent,
//!   the outputs made, the name operations and the positions swept. The
//!   states here are computed from a body as the circuit computes them
//!   from its rows ([`inputs_state`] and the others).
//! - The **position** the next output takes.
//! - The **sums** of the amounts spent and made so far, in limbs of
//!   sixteen bits ([`LIMBS`] of them, which no block's sum outgrows).
//!   There is no fee: when the last segment ends, what was spent and the
//!   subsidy is what was made, and whoever checks the segments checks
//!   that.
//! - A **carry**: a transaction too long for what is left of a segment
//!   goes on in the next, and what is needed to go on with it crosses
//!   the boundary in public ([`Carry`]).
//!
//! A position is 41 bits ([`crate::store::outputs`]), and a field
//! element holds less than 31: it is two elements, the low 30 bits and
//! the 11 above.
//!
//! The circuit itself is not here yet.

use crate::block::BlockOutput;
use crate::hash::{DOM_INPUTS, DOM_NAME_OPS, DOM_OUTPUTS, DOM_SWEEPS, Digest};
use crate::output::Commitment;
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, permute};

/// 16-bit limbs of amount sums: four hold an amount, six any sum of a
/// block's amounts (fewer than `2^32` of them).
pub const LIMBS: usize = 6;
/// Bits of a position's low element, and of its high one.
pub const POS_LOW_BITS: u32 = 30;
pub const POS_HIGH_BITS: u32 = crate::store::outputs::HEIGHT - POS_LOW_BITS;
const MASK30: u64 = (1 << POS_LOW_BITS) - 1;

// ---- public values ----
pub const PUB_ROOT_IN: usize = 0;
pub const PUB_ROOT_OUT: usize = DIGEST;
pub const PUB_ISP_IN: usize = 2 * DIGEST;
pub const PUB_ISP_OUT: usize = PUB_ISP_IN + WIDTH;
pub const PUB_OSP_IN: usize = PUB_ISP_OUT + WIDTH;
pub const PUB_OSP_OUT: usize = PUB_OSP_IN + WIDTH;
pub const PUB_NSP_IN: usize = PUB_OSP_OUT + WIDTH;
pub const PUB_NSP_OUT: usize = PUB_NSP_IN + WIDTH;
pub const PUB_POS_IN: usize = PUB_NSP_OUT + WIDTH; // lo, hi
pub const PUB_POS_OUT: usize = PUB_POS_IN + 2;
pub const PUB_SUM_IN: usize = PUB_POS_OUT + 2;
pub const PUB_SUM_OUT: usize = PUB_SUM_IN + LIMBS;
pub const PUB_CARRY_IN: usize = PUB_SUM_OUT + LIMBS;
pub const PUB_CARRY_OUT: usize = PUB_CARRY_IN + CARRY_LEN;
/// The block's height: the creation height of every output.
pub const PUB_HEIGHT: usize = PUB_CARRY_OUT + CARRY_LEN;
pub const NUM_PUBLIC: usize = PUB_HEIGHT + 1;

/// Layout of a carry: open flag, message, body sponge, items left.
pub const CARRY_OPEN: usize = 0;
pub const CARRY_MSG: usize = 1;
pub const CARRY_BSP: usize = CARRY_MSG + DIGEST;
pub const CARRY_IN_LEFT: usize = CARRY_BSP + WIDTH;
pub const CARRY_OUT_LEFT: usize = CARRY_IN_LEFT + 1;
pub const CARRY_OPS_LEFT: usize = CARRY_OUT_LEFT + 1;
pub const CARRY_LEN: usize = CARRY_OPS_LEFT + 1;

// ---------------------------------------------------------------------------
// The sponges
// ---------------------------------------------------------------------------

fn initial(domain: u32) -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE] = Fp::new(domain);
    state
}

fn absorb_block(state: &mut [Fp; WIDTH], block: &[Fp; RATE]) {
    for (s, x) in state.iter_mut().zip(block) {
        *s = s.add(x);
    }
    *state = permute(*state);
}

/// A position as the circuits hold it: its low 30 bits, and the rest.
pub fn position_limbs(position: u64) -> [Fp; 2] {
    debug_assert!(position >> (POS_LOW_BITS + POS_HIGH_BITS) == 0, "a position is 41 bits");
    [Fp::new((position & MASK30) as u32), Fp::new((position >> POS_LOW_BITS) as u32)]
}

/// The position two elements are, if they are one's.
pub fn position_of(lo: Fp, hi: Fp) -> Option<u64> {
    let (lo, hi) = (lo.to_canonical() as u64, hi.to_canonical() as u64);
    (lo >> POS_LOW_BITS == 0 && hi >> POS_HIGH_BITS == 0).then_some(lo | hi << POS_LOW_BITS)
}

/// Initial state of the inputs sponge.
pub fn initial_inputs_state() -> [Fp; WIDTH] {
    initial(DOM_INPUTS)
}

/// Initial state of the outputs sponge.
pub fn initial_outputs_state() -> [Fp; WIDTH] {
    initial(DOM_OUTPUTS)
}

/// Initial state of the name operations sponge.
pub fn initial_names_state() -> [Fp; WIDTH] {
    initial(DOM_NAME_OPS)
}

/// Initial state of the sweeps sponge: the positions of the commits a
/// block's name segment sweeps.
pub fn initial_sweeps_state() -> [Fp; WIDTH] {
    initial(DOM_SWEEPS)
}

/// Absorbs one input position into the inputs sponge.
pub fn absorb_position(state: &mut [Fp; WIDTH], position: u64) {
    let [lo, hi] = position_limbs(position);
    state[0] = state[0].add(&lo);
    state[1] = state[1].add(&hi);
    *state = permute(*state);
}

/// Absorbs one swept position into the sweeps sponge, as
/// [`absorb_position`] does for the inputs sponge.
pub fn absorb_sweep(state: &mut [Fp; WIDTH], position: u64) {
    absorb_position(state, position);
}

/// Absorbs one output's commitment, then its memo slot (memo and public
/// amount), into the outputs sponge.
pub fn absorb_output(state: &mut [Fp; WIDTH], commitment: &Commitment, slot: &Digest) {
    absorb_block(state, commitment);
    absorb_block(state, slot);
}

/// Absorbs one operation digest into the name operations sponge.
pub fn absorb_op(state: &mut [Fp; WIDTH], digest: &Digest) {
    absorb_block(state, digest);
}

/// Inputs sponge state after absorbing all of a block's positions.
pub fn inputs_state(positions: impl IntoIterator<Item = u64>) -> [Fp; WIDTH] {
    let mut state = initial_inputs_state();
    positions.into_iter().for_each(|p| absorb_position(&mut state, p));
    state
}

/// Outputs sponge state after absorbing all of a block's outputs.
pub fn outputs_state(outputs: impl IntoIterator<Item = BlockOutput>) -> [Fp; WIDTH] {
    let mut state = initial_outputs_state();
    outputs.into_iter().for_each(|o| absorb_output(&mut state, &o.commitment, &o.slot()));
    state
}

/// Name operations sponge state after absorbing all of a block's
/// operation digests, in order.
pub fn names_state(digests: impl IntoIterator<Item = Digest>) -> [Fp; WIDTH] {
    let mut state = initial_names_state();
    digests.into_iter().for_each(|d| absorb_op(&mut state, &d));
    state
}

/// Sweeps sponge state after absorbing all of a block's swept positions.
pub fn sweeps_state(positions: impl IntoIterator<Item = u64>) -> [Fp; WIDTH] {
    let mut state = initial_sweeps_state();
    positions.into_iter().for_each(|p| absorb_sweep(&mut state, p));
    state
}

/// Splits a `u64` into 16-bit limbs, least significant first.
pub fn limbs16(v: u64) -> [Fp; LIMBS] {
    limbs16_wide(v as u128)
}

/// As [`limbs16`] for a sum below `2^96`.
pub fn limbs16_wide(v: u128) -> [Fp; LIMBS] {
    assert!(v >> (16 * LIMBS) == 0, "sum out of range");
    core::array::from_fn(|j| Fp::new(((v >> (16 * j)) & 0xffff) as u32))
}

// ---------------------------------------------------------------------------
// A segment's public values
// ---------------------------------------------------------------------------

/// A transaction left open across a segment boundary: its signed message,
/// body sponge state and items still to come. [`Carry::CLOSED`] when none
/// is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carry {
    pub open: bool,
    pub msg: Digest,
    pub bsp: [Fp; WIDTH],
    pub in_left: u32,
    pub out_left: u32,
    pub ops_left: u32,
}

impl Carry {
    pub const CLOSED: Carry =
        Carry { open: false, msg: [Fp::ZERO; DIGEST], bsp: [Fp::ZERO; WIDTH], in_left: 0, out_left: 0, ops_left: 0 };

    fn write(&self, v: &mut [Fp]) {
        v[CARRY_OPEN] = Fp::new(self.open as u32);
        v[CARRY_MSG..CARRY_MSG + DIGEST].copy_from_slice(&self.msg);
        v[CARRY_BSP..CARRY_BSP + WIDTH].copy_from_slice(&self.bsp);
        v[CARRY_IN_LEFT] = Fp::new(self.in_left);
        v[CARRY_OUT_LEFT] = Fp::new(self.out_left);
        v[CARRY_OPS_LEFT] = Fp::new(self.ops_left);
    }

    /// Parses a carry; a closed one must be all zero.
    fn from_values(v: &[Fp]) -> Option<Carry> {
        let open = match v[CARRY_OPEN].to_canonical() {
            0 => false,
            1 => true,
            _ => return None,
        };
        let c = Carry {
            open,
            msg: v[CARRY_MSG..CARRY_MSG + DIGEST].try_into().unwrap(),
            bsp: v[CARRY_BSP..CARRY_BSP + WIDTH].try_into().unwrap(),
            in_left: v[CARRY_IN_LEFT].to_canonical(),
            out_left: v[CARRY_OUT_LEFT].to_canonical(),
            ops_left: v[CARRY_OPS_LEFT].to_canonical(),
        };
        (open || c == Carry::CLOSED).then_some(c)
    }
}

/// Boundary values of a segment: its public statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentPublic {
    pub root_in: Digest,
    pub root_out: Digest,
    pub isp_in: [Fp; WIDTH],
    pub isp_out: [Fp; WIDTH],
    pub osp_in: [Fp; WIDTH],
    pub osp_out: [Fp; WIDTH],
    pub nsp_in: [Fp; WIDTH],
    pub nsp_out: [Fp; WIDTH],
    pub pos_in: u64,
    pub pos_out: u64,
    pub sum_in: [u32; LIMBS],
    pub sum_out: [u32; LIMBS],
    pub carry_in: Carry,
    pub carry_out: Carry,
    pub height: u32,
}

impl SegmentPublic {
    /// The values, as the proof's verifier takes them: held in place.
    pub fn to_values(&self) -> [Fp; NUM_PUBLIC] {
        let mut v = [Fp::ZERO; NUM_PUBLIC];
        v[PUB_ROOT_IN..PUB_ROOT_IN + DIGEST].copy_from_slice(&self.root_in);
        v[PUB_ROOT_OUT..PUB_ROOT_OUT + DIGEST].copy_from_slice(&self.root_out);
        for (at, state) in [
            (PUB_ISP_IN, &self.isp_in),
            (PUB_ISP_OUT, &self.isp_out),
            (PUB_OSP_IN, &self.osp_in),
            (PUB_OSP_OUT, &self.osp_out),
            (PUB_NSP_IN, &self.nsp_in),
            (PUB_NSP_OUT, &self.nsp_out),
        ] {
            v[at..at + WIDTH].copy_from_slice(state);
        }
        v[PUB_POS_IN..PUB_POS_IN + 2].copy_from_slice(&position_limbs(self.pos_in));
        v[PUB_POS_OUT..PUB_POS_OUT + 2].copy_from_slice(&position_limbs(self.pos_out));
        for j in 0..LIMBS {
            v[PUB_SUM_IN + j] = Fp::new(self.sum_in[j]);
            v[PUB_SUM_OUT + j] = Fp::new(self.sum_out[j]);
        }
        self.carry_in.write(&mut v[PUB_CARRY_IN..PUB_CARRY_IN + CARRY_LEN]);
        self.carry_out.write(&mut v[PUB_CARRY_OUT..PUB_CARRY_OUT + CARRY_LEN]);
        v[PUB_HEIGHT] = Fp::new(self.height);
        v
    }

    /// Parses values written by [`SegmentPublic::to_values`]. Positions
    /// must be positions (41 bits), and a closed carry all zero.
    pub fn from_values(v: &[Fp]) -> Option<SegmentPublic> {
        if v.len() != NUM_PUBLIC {
            return None;
        }
        let digest = |at: usize| -> Digest { v[at..at + DIGEST].try_into().unwrap() };
        let state = |at: usize| -> [Fp; WIDTH] { v[at..at + WIDTH].try_into().unwrap() };
        let sums = |at: usize| -> [u32; LIMBS] { core::array::from_fn(|j| v[at + j].to_canonical()) };
        Some(SegmentPublic {
            root_in: digest(PUB_ROOT_IN),
            root_out: digest(PUB_ROOT_OUT),
            isp_in: state(PUB_ISP_IN),
            isp_out: state(PUB_ISP_OUT),
            osp_in: state(PUB_OSP_IN),
            osp_out: state(PUB_OSP_OUT),
            nsp_in: state(PUB_NSP_IN),
            nsp_out: state(PUB_NSP_OUT),
            pos_in: position_of(v[PUB_POS_IN], v[PUB_POS_IN + 1])?,
            pos_out: position_of(v[PUB_POS_OUT], v[PUB_POS_OUT + 1])?,
            sum_in: sums(PUB_SUM_IN),
            sum_out: sums(PUB_SUM_OUT),
            carry_in: Carry::from_values(&v[PUB_CARRY_IN..PUB_CARRY_IN + CARRY_LEN])?,
            carry_out: Carry::from_values(&v[PUB_CARRY_OUT..PUB_CARRY_OUT + CARRY_LEN])?,
            height: v[PUB_HEIGHT].to_canonical(),
        })
    }

    /// Integer value of a limb-sum vector.
    pub fn total(limbs: &[u32; LIMBS]) -> u128 {
        limbs.iter().enumerate().map(|(j, l)| (*l as u128) << (16 * j)).sum()
    }
}

// ---------------------------------------------------------------------------
// Packing transactions into segments
// ---------------------------------------------------------------------------

/// A run of one transaction's items, `start..end` in input, output then
/// operation order, placed in a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part {
    pub tx: usize,
    pub start: usize,
    pub end: usize,
}

/// Packs transactions into segments of `max_rows` trace rows (one kept
/// for padding), greedily and splitting a transaction between items when
/// it does not fit what is left of a segment. Each segment lists its
/// parts in order. `items(t)` gives the rows of each of transaction `t`'s
/// items and whether it must stay whole.
pub fn pack(num_txs: usize, items: impl Fn(usize) -> (Vec<usize>, bool), max_rows: usize) -> Vec<Vec<Part>> {
    let cap = max_rows - 1;
    let mut segments = Vec::new();
    let mut cur: Vec<Part> = Vec::new();
    let mut rows = 0;
    for tx in 0..num_txs {
        let (item_rows, whole) = items(tx);
        let n = item_rows.len();
        if whole {
            let total = 2 + item_rows.iter().sum::<usize>();
            assert!(total <= cap, "a transaction that must stay whole does not fit a segment of {max_rows} rows");
            if rows + total > cap {
                segments.push(std::mem::take(&mut cur));
                rows = 0;
            }
            cur.push(Part { tx, start: 0, end: n });
            rows += total;
            continue;
        }
        // Rows item k needs, with the end row after the last item.
        let cost = |k: usize| item_rows[k] + usize::from(k + 1 == n);
        let mut k = 0;
        loop {
            // A part needs its start (or resume) row and its first item,
            // or the end row for an empty transaction.
            let first = if k < n { cost(k) } else { 1 };
            assert!(first < cap, "an item does not fit a segment of {max_rows} rows");
            if rows + 1 + first > cap {
                segments.push(std::mem::take(&mut cur));
                rows = 0;
            }
            let start = k;
            rows += 1;
            while k < n && rows + cost(k) <= cap {
                rows += item_rows[k];
                k += 1;
            }
            cur.push(Part { tx, start, end: k });
            if k == n {
                rows += 1;
                break;
            }
            segments.push(std::mem::take(&mut cur));
            rows = 0;
        }
    }
    if !cur.is_empty() {
        segments.push(cur);
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::hash;
    use crate::test_util::Rng;

    fn digest(rng: &mut Rng) -> Digest {
        core::array::from_fn(|_| rng.fp())
    }

    /// A sponge here is the plain sponge over the same elements with the
    /// domain in the capacity: one permutation an item's block, nothing
    /// absorbed at the end.
    #[test]
    fn the_sponges_absorb_a_block_an_item() {
        let mut rng = Rng::new(0xb10c);
        // By hand: add into the rate, permute.
        let by_hand = |domain: u32, blocks: &[[Fp; RATE]]| {
            let mut s = [Fp::ZERO; WIDTH];
            s[RATE] = Fp::new(domain);
            for b in blocks {
                (0..RATE).for_each(|i| s[i] += b[i]);
                s = permute(s);
            }
            s
        };
        let positions = [0u64, 1, (1 << 30) - 1, 1 << 30, (1 << 41) - 1, 77 << 30 | 5];
        let as_blocks: Vec<[Fp; RATE]> = positions
            .iter()
            .map(|p| {
                let mut b = [Fp::ZERO; RATE];
                b[0] = Fp::new((p & 0x3fff_ffff) as u32);
                b[1] = Fp::new((p >> 30) as u32);
                b
            })
            .collect();
        assert_eq!(inputs_state(positions), by_hand(DOM_INPUTS, &as_blocks));
        assert_eq!(sweeps_state(positions), by_hand(DOM_SWEEPS, &as_blocks));
        assert_ne!(inputs_state(positions), sweeps_state(positions));
        assert_eq!(inputs_state([]), initial_inputs_state());
        // Order counts, and so does every position.
        assert_ne!(inputs_state([1, 2]), inputs_state([2, 1]));
        assert_ne!(inputs_state([1 << 30]), inputs_state([1]));

        let outputs: Vec<BlockOutput> = (0..5)
            .map(|i| BlockOutput {
                commitment: digest(&mut rng),
                memo: core::array::from_fn(|_| rng.fp()),
                amount: 1 << (i * 15),
            })
            .collect();
        let blocks: Vec<[Fp; RATE]> = outputs.iter().flat_map(|o| [o.commitment, o.slot()]).collect();
        assert_eq!(outputs_state(outputs.iter().copied()), by_hand(DOM_OUTPUTS, &blocks));
        let mut other = outputs.clone();
        other[2].amount += 1;
        assert_ne!(outputs_state(other), outputs_state(outputs.iter().copied()));

        let ops: Vec<Digest> = (0..4).map(|_| digest(&mut rng)).collect();
        assert_eq!(names_state(ops.iter().copied()), by_hand(DOM_NAME_OPS, &ops));
        assert_eq!(names_state([]), initial_names_state());
        // The four are four sponges.
        let initials = [initial_inputs_state(), initial_outputs_state(), initial_names_state(), initial_sweeps_state()];
        assert!((0..4).all(|i| (0..i).all(|j| initials[i] != initials[j])));
        // And none is the hash of the same elements.
        assert_ne!(names_state(ops.iter().copied())[..DIGEST], hash(&ops.concat()));
    }

    #[test]
    fn positions_and_sums_in_limbs() {
        for p in [0u64, 5, (1 << 30) - 1, 1 << 30, 1 << 40, (1 << 41) - 1] {
            let [lo, hi] = position_limbs(p);
            assert_eq!(position_of(lo, hi), Some(p));
        }
        assert_eq!((POS_LOW_BITS, POS_HIGH_BITS), (30, 11));
        // Not positions: a low element of 30 bits and more, a high one
        // of 11 and more.
        assert_eq!(position_of(Fp::new(1 << 30), Fp::ZERO), None);
        assert_eq!(position_of(Fp::ZERO, Fp::new(1 << 11)), None);
        assert_eq!(position_of(Fp::new((1 << 30) - 1), Fp::new((1 << 11) - 1)), Some((1 << 41) - 1));

        let limbs = limbs16(0x0123_4567_89ab_cdef);
        assert_eq!(limbs.map(|l| l.to_canonical()), [0xcdef, 0x89ab, 0x4567, 0x0123, 0, 0]);
        let wide = limbs16_wide((1u128 << 96) - 1);
        assert!(wide.iter().all(|l| l.to_canonical() == 0xffff));
        let sum: [u32; LIMBS] = [0xffff, 0x1_0000, 3, 0, 0, 9];
        assert_eq!(SegmentPublic::total(&sum), 0xffff + (0x1_0000u128 << 16) + (3 << 32) + (9u128 << 80));
    }

    #[test]
    #[should_panic(expected = "sum out of range")]
    fn a_sum_too_wide_for_its_limbs() {
        limbs16_wide(1u128 << 96);
    }

    fn public(rng: &mut Rng) -> SegmentPublic {
        let state = |rng: &mut Rng| -> [Fp; WIDTH] { core::array::from_fn(|_| rng.fp()) };
        SegmentPublic {
            root_in: digest(rng),
            root_out: digest(rng),
            isp_in: state(rng),
            isp_out: state(rng),
            osp_in: state(rng),
            osp_out: state(rng),
            nsp_in: state(rng),
            nsp_out: state(rng),
            pos_in: rng.next_u64() >> 23,
            pos_out: (1 << 41) - 1,
            sum_in: core::array::from_fn(|_| rng.next_u64() as u32 >> 14),
            sum_out: core::array::from_fn(|_| rng.next_u64() as u32 >> 14),
            carry_in: Carry::CLOSED,
            carry_out: Carry { open: true, msg: digest(rng), bsp: state(rng), in_left: 3, out_left: 0, ops_left: 1 },
            height: 77,
        }
    }

    /// The public values are read as they were written, each in its
    /// place, and what is no segment's statement is refused.
    #[test]
    fn public_values_are_read_as_written() {
        let mut rng = Rng::new(0x5e9);
        let p = public(&mut rng);
        let v = p.to_values();
        assert_eq!(v.len(), NUM_PUBLIC);
        assert_eq!(SegmentPublic::from_values(&v), Some(p));
        assert_eq!(v[PUB_ROOT_OUT..PUB_ROOT_OUT + DIGEST], p.root_out);
        assert_eq!(v[PUB_NSP_OUT..PUB_NSP_OUT + WIDTH], p.nsp_out);
        assert_eq!((v[PUB_POS_OUT], v[PUB_POS_OUT + 1]), (Fp::new((1 << 30) - 1), Fp::new((1 << 11) - 1)));
        assert_eq!(v[PUB_HEIGHT], Fp::new(77));
        assert_eq!(v[PUB_CARRY_OUT + CARRY_IN_LEFT], Fp::new(3));
        assert_eq!(NUM_PUBLIC, 2 * DIGEST + 6 * WIDTH + 4 + 2 * LIMBS + 2 * CARRY_LEN + 1);
        // Every value is someone's: changing any changes what is read,
        // or makes it nothing.
        for i in 0..NUM_PUBLIC {
            let mut w = v;
            w[i] += Fp::ONE;
            assert_ne!(SegmentPublic::from_values(&w), Some(p), "value {i}");
        }
        assert_eq!(SegmentPublic::from_values(&v[1..]), None);
        // A position that is none.
        let mut w = v;
        w[PUB_POS_IN + 1] = Fp::new(1 << 11);
        assert_eq!(SegmentPublic::from_values(&w), None);
        // A carry neither open nor closed, and a closed one with
        // something in it.
        let mut w = v;
        w[PUB_CARRY_OUT + CARRY_OPEN] = Fp::new(2);
        assert_eq!(SegmentPublic::from_values(&w), None);
        let mut w = v;
        w[PUB_CARRY_IN + CARRY_OUT_LEFT] = Fp::ONE;
        assert_eq!(SegmentPublic::from_values(&w), None);
    }

    /// Transactions are packed into segments in order, split between
    /// items when they must be, and never over a segment's rows.
    #[test]
    fn transactions_are_packed_into_segments() {
        // Rows a list of parts takes: a row to start or resume each, its
        // items, and an end row after a transaction's last item.
        let rows_of = |segment: &[Part], txs: &[(Vec<usize>, bool)]| -> usize {
            segment
                .iter()
                .map(|p| {
                    1 + txs[p.tx].0[p.start..p.end].iter().sum::<usize>() + usize::from(p.end == txs[p.tx].0.len())
                })
                .sum()
        };
        let check = |txs: &[(Vec<usize>, bool)], max_rows: usize| -> Vec<Vec<Part>> {
            let segments = pack(txs.len(), |t| txs[t].clone(), max_rows);
            // Every item once, in order.
            let mut next = (0usize, 0usize);
            for part in segments.iter().flatten() {
                if part.tx != next.0 {
                    assert_eq!((part.tx, next.1), (next.0 + 1, txs[next.0].0.len()));
                    next = (part.tx, 0);
                }
                assert_eq!(part.start, next.1);
                next.1 = part.end;
            }
            assert_eq!(next, (txs.len() - 1, txs.last().unwrap().0.len()));
            for s in &segments {
                assert!(rows_of(s, txs) < max_rows, "{} rows of {max_rows}", rows_of(s, txs));
                assert!(!s.is_empty());
            }
            segments
        };
        // All in one segment.
        let small = vec![(vec![10, 10], false), (vec![5], false), (vec![], false)];
        assert_eq!(check(&small, 64).len(), 1);
        // One transaction over three segments, split between its items.
        let long = vec![(vec![20; 7], false)];
        let segments = check(&long, 64);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], vec![Part { tx: 0, start: 0, end: 3 }]);
        // One that must stay whole begins a new segment if it must.
        let whole = vec![(vec![30], false), (vec![20, 20], true), (vec![4], false)];
        let segments = check(&whole, 64);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[1][0], Part { tx: 1, start: 0, end: 2 });
        assert!(segments.iter().flatten().filter(|p| p.tx == 1).count() == 1);
        // Many of many sizes.
        let mut rng = Rng::new(0x9ac);
        let many: Vec<(Vec<usize>, bool)> = (0..200)
            .map(|i| {
                // One that must stay whole is short enough to.
                let (whole, longest) = (i % 17 == 0, if i % 17 == 0 { 20 } else { 40 });
                ((0..rng.next_u64() % 6).map(|_| 1 + (rng.next_u64() % longest) as usize).collect(), whole)
            })
            .collect();
        check(&many, 128);
    }

    #[test]
    #[should_panic(expected = "does not fit a segment")]
    fn an_item_longer_than_a_segment() {
        pack(1, |_| (vec![70], false), 64);
    }
}
