//! The work segment: a header's proof of work, proven (docs/NODE.md, the
//! work in the chain proof). Each block's root verifies its parent's
//! (`aggregate::Output::Statement`), against the block statement's
//! `parent_work`.
//!
//! One proof of four tables shows that `hashimoto` (see [`crate::pow`]),
//! its items computed from the seed file, gives the mix it gives:
//!
//! - **perm**: the hash machine ([`crate::hash_machine`]), one permutation a
//!   row. Three seed rows (a start with the header hash and `DOM_SEED`,
//!   then the nonce's two blocks absorbed), then for each dataset item a
//!   start `[index, DOM_ITEM]` and exactly `parents` absorbs of windows (a
//!   counter). On each absorb, the window's index
//!   `w = (out0 + out1 * 2^31) mod N`, from the previous permutation's
//!   output, is proven in 10-bit limbs (both outputs shown canonical, the
//!   quotient and remainder decomposed, the carries ranged, `w < N`), and
//!   the window it absorbs is looked up in the text table. An item's final
//!   output is offered under its index.
//! - **text**: the windows of the seed file at 24-byte boundaries
//!   (`N` = 53,795, a table of 2^16 rows), a preprocessed table
//!   `[w, eight packed elements]` committed once, and how often each is
//!   read.
//! - **mix**: hashimoto's accesses: each row derives a pair's index from
//!   the mix (the low bits of a canonical value, as many as the table has
//!   pairs), takes its two items from perm and folds them in (`fnv`), and
//!   reads one window directly: its index from a second canonical value
//!   ([`crate::pow::direct_window`]: the low `L` bits, less `N` once if
//!   they are `N` or more, `w < N` in limbs), looked up in the text table
//!   and added to the mix.
//! - **range**: 0 to 1023, for the limbs.
//!
//! The public values are the header's `pow_hash` (8 elements), its nonce
//! (11), its `mix` (8) and the table's size: the mix after the 64
//! accesses, folded to eight elements, must be the header's. That the
//! result from the mix meets the target is left to the native check
//! (`Header::quick_pow_check`, two permutations): the proof supplies the
//! expensive fact, that the `mix` is the true one.
//!
//! # One circuit for every table
//!
//! The table doubles each epoch to its largest ([`crate::pow`]), and only
//! one thing in the work depends on its size: how many of a selector's low
//! bits pick the pair. An item is the same in every table that has it. So
//! the circuit is the same for every epoch, and the size is a public
//! value: one flag for each doubling the schedule has, set if this
//! header's table has had it ([`Work::to_values`]). Each flag lets one
//! more bit of the selector into the pair's index. Whoever checks the
//! proof sets the flags from the header's height, as it sets the rest
//! from the header.
//!
//! # Memory
//!
//! Proving is the perm table: 2^15 rows of [`PERM_COLS`] columns on
//! mainnet (53 MB), laid out once. A verifier holds the window table's
//! root and the proof.

use crate::codec::packed;
use crate::error::Error;
use crate::field::Field;
use crate::hash::Digest;
use crate::hash_machine::{
    COL_ABSORB, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_LOAD, COL_START, HashTraceBuilder, NUM_COLS as HM_COLS,
    eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, P, RATE, WIDTH};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::pow::{DOM_ITEM, DOM_SEED, FNV_PRIME, MIX_WORDS, NONCE_FPS, Nonce, SeedText, direct_window, fnv};
use crate::stark::{
    Air, Builder, Preprocessed, Proof, StarkConfig, TableInput, TableSpec, Trace, prove_tables, refuse, verify_bytes,
};

const LIMB: u32 = 1 << 10;
const TAG_ITEM: u32 = 1;
const TAG_SEED: u32 = 2;
const TAG_RANGE: u32 = 3;
const TAG_TEXT: u32 = 4;
/// `p - 2^30 - 1`: the largest low 30 bits of a canonical element whose
/// bit 30 is set.
const CANON_LOW: u32 = 0x3800_0000;
/// The public values: `pow_hash`, the nonce's 11 elements, the `mix`, then
/// a flag for each doubling of the table.
pub const PUB_HASH: usize = 0;
pub const PUB_NONCE: usize = DIGEST;
pub const PUB_MIX: usize = PUB_NONCE + NONCE_FPS;
pub const PUB_TABLE: usize = PUB_MIX + DIGEST;
/// The work segment's transcript domain (the other proofs': 0x30 to 0x34).
pub const DOM_WORK_PROOF: u32 = 0x35;

// ---------------------------------------------------------------------------
// perm: the permutations
// ---------------------------------------------------------------------------

const P_S0: usize = HM_COLS;
const P_S1: usize = P_S0 + 1;
const P_S2: usize = P_S0 + 2;
const P_IS: usize = P_S0 + 3;
const P_IA: usize = P_S0 + 4;
const P_LAST: usize = P_S0 + 5;
const P_K: usize = P_S0 + 6;
const P_CUR: usize = P_S0 + 7;
const P_PA0: usize = P_S0 + 8;
const P_PA1: usize = P_S0 + 9;
const P_A: usize = P_S0 + 10; // a0..a3
const P_B: usize = P_A + 4; // b0..b3
const P_DA: usize = P_B + 4; // 3
const P_DB: usize = P_DA + 3; // 3
const P_Q: usize = P_DB + 3; // 5
const P_W: usize = P_Q + 5; // 3
const P_D: usize = P_W + 3; // 3
const P_E: usize = P_D + 3; // 2
const P_C: usize = P_E + 2; // 6 low limbs of the carries
const P_CH: usize = P_C + 6; // 6 x 4 high bits
pub const PERM_COLS: usize = P_CH + 24;
const CARRY_BIAS: i64 = 1 << 13;

/// The perm table's AIR for a file of `windows` windows and `parents`
/// absorbs an item (mainnet has 254, which fits 2^15 rows).
pub struct PermAir {
    pub windows: usize,
    pub parents: usize,
}

impl PermAir {
    /// The limbs every row ranges.
    fn range_cols() -> impl Iterator<Item = usize> {
        (P_A..P_A + 3)
            .chain(P_B..P_B + 3)
            .chain(P_DA..P_DA + 3)
            .chain(P_DB..P_DB + 3)
            .chain(P_Q..P_Q + 5)
            .chain(P_W..P_W + 3)
            .chain(P_D..P_D + 3)
            .chain(P_C..P_C + 6)
    }
}

fn lin<F: Field>(l: &[F], at: usize, n: usize) -> F {
    (0..n).rev().fold(F::ZERO, |acc, i| acc.scale(Fp::new(LIMB)) + l[at + i])
}

/// A value below 2^30 in three 10-bit limbs, the lowest first.
fn limbs3(v: u32) -> [u32; 3] {
    [v % LIMB, (v / LIMB) % LIMB, v / (LIMB * LIMB)]
}

// The messages of the buses, each built where it is sent: on the stack.

/// A window of the file under its number.
fn text_message<F: Field>(w: F, window: &[F]) -> [F; 2 + RATE] {
    let mut m = [F::ZERO; 2 + RATE];
    m[0] = F::from_u32(TAG_TEXT);
    m[1] = w;
    m[2..].copy_from_slice(window);
    m
}

/// A dataset item under its index.
fn item_message<F: Field>(index: F, item: &[F]) -> [F; 2 + WIDTH] {
    let mut m = [F::ZERO; 2 + WIDTH];
    m[0] = F::from_u32(TAG_ITEM);
    m[1] = index;
    m[2..].copy_from_slice(item);
    m
}

/// The seed state of the header hash and nonce.
fn seed_message<F: Field>(seed: &[F]) -> [F; 1 + WIDTH] {
    let mut m = [F::ZERO; 1 + WIDTH];
    m[0] = F::from_u32(TAG_SEED);
    m[1..].copy_from_slice(seed);
    m
}

impl Air for PermAir {
    fn width(&self) -> usize {
        PERM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn lookup_group(&self) -> usize {
        2
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        let p = b.public();
        let one = F::ONE;
        let c = |v: u32| F::from_u32(v);
        b.mark("pow flags");
        let (s0, s1, s2, is, ia, last) = (l[P_S0], l[P_S1], l[P_S2], l[P_IS], l[P_IA], l[P_LAST]);
        for f in [s0, s1, s2, is, ia, last] {
            b.assert_zero(f * f - f);
        }
        b.assert_zero(l[COL_CHAIN]);
        b.assert_zero(l[COL_COMPRESS]);
        b.assert_zero(l[COL_LOAD]);
        b.assert_eq(l[COL_START], s0 + is);
        b.assert_eq(l[COL_ABSORB], s1 + s2 + ia);
        // The seed: rows 0, 1, 2.
        b.when_first_row(s0 - one);
        b.when_transition(n[P_S0]);
        b.when_transition(n[P_S1] - s0);
        b.when_transition(n[P_S2] - s1);
        b.mark("pow seed");
        for k in 0..DIGEST {
            b.assert_zero(s0 * (l[COL_INPUT + k] - p[k]));
        }
        b.assert_zero(s0 * (l[COL_INPUT + DIGEST] - c(DOM_SEED)));
        for k in DIGEST + 1..WIDTH {
            b.assert_zero(s0 * l[COL_INPUT + k]);
        }
        for k in 0..RATE {
            b.assert_zero(s1 * (l[COL_DATA + k] - p[DIGEST + k]));
            let block2 = if k < 3 { p[DIGEST + RATE + k] } else { F::ZERO };
            b.assert_zero(s2 * (l[COL_DATA + k] - block2));
        }
        // An item: a start, then exactly 256 absorbs.
        b.mark("pow items");
        b.assert_zero(is * (l[COL_INPUT] - l[P_CUR]));
        b.assert_zero(is * (l[COL_INPUT + 1] - c(DOM_ITEM)));
        for k in 2..WIDTH {
            b.assert_zero(is * l[COL_INPUT + k]);
        }
        b.assert_zero(is * l[P_K]);
        let it = is + ia;
        b.when_transition(n[P_IA] * (one - it));
        b.when_transition(n[P_IA] * (n[P_K] - l[P_K] - one));
        b.when_transition(n[P_IA] * (n[P_CUR] - l[P_CUR]));
        b.when_transition(n[P_IA] * last);
        b.assert_zero(last * (l[P_K] - c(self.parents as u32)));
        b.assert_zero(last * (one - ia));
        b.when_transition(it * (one - last) * (one - n[P_IA]));
        b.when_last_row(it - last);
        b.when_transition(n[P_IA] * (n[P_PA0] - l[COL_OUTPUT]));
        b.when_transition(n[P_IA] * (n[P_PA1] - l[COL_OUTPUT + 1]));
        // The window: w = (pa0 + pa1 * 2^31) mod N, in 10-bit limbs.
        b.mark("pow window");
        for x in [P_A + 3, P_B + 3, P_E, P_E + 1] {
            b.assert_zero(l[x] * l[x] - l[x]);
        }
        for k in 0..24 {
            let h = l[P_CH + k];
            b.assert_zero(h * h - h);
        }
        b.assert_zero(ia * (l[P_PA0] - lin(l, P_A, 4)));
        b.assert_zero(ia * (l[P_PA1] - lin(l, P_B, 4)));
        // Canonical: with bit 30 set, the low 30 bits at most CANON_LOW.
        b.assert_zero(ia * (lin(l, P_DA, 3) - l[P_A + 3] * (c(CANON_LOW) - lin(l, P_A, 3))));
        b.assert_zero(ia * (lin(l, P_DB, 3) - l[P_B + 3] * (c(CANON_LOW) - lin(l, P_B, 3))));
        let nl = limbs3(self.windows as u32);
        let r = [
            l[P_A],
            l[P_A + 1],
            l[P_A + 2],
            l[P_A + 3] + l[P_B].scale(Fp::new(2)),
            l[P_B + 1].scale(Fp::new(2)),
            l[P_B + 2].scale(Fp::new(2)),
            l[P_B + 3].scale(Fp::new(2)),
        ];
        let carry = |k: usize| -> F {
            let hi = (0..4).fold(F::ZERO, |acc, j| acc + l[P_CH + 4 * k + j].scale(Fp::new(1 << j)));
            l[P_C + k] + hi.scale(Fp::new(LIMB)) - c(CARRY_BIAS as u32)
        };
        let mut prev = F::ZERO;
        for k in 0..7 {
            let mut ck = if k < 3 { l[P_W + k] } else { F::ZERO };
            for (j, nj) in nl.iter().enumerate() {
                if k >= j && k - j < 5 {
                    ck += l[P_Q + k - j].scale(Fp::new(*nj));
                }
            }
            let out = if k < 6 { carry(k).scale(Fp::new(LIMB)) } else { F::ZERO };
            b.assert_zero(ia * (ck - r[k] + prev - out));
            if k < 6 {
                prev = carry(k);
            }
        }
        // w < N: w + d = N - 1.
        let m = limbs3(self.windows as u32 - 1);
        b.assert_zero(ia * (l[P_W] + l[P_D] - c(m[0]) - l[P_E].scale(Fp::new(LIMB))));
        b.assert_zero(ia * (l[P_W + 1] + l[P_D + 1] + l[P_E] - c(m[1]) - l[P_E + 1].scale(Fp::new(LIMB))));
        b.assert_zero(ia * (l[P_W + 2] + l[P_D + 2] + l[P_E + 1] - c(m[2])));
        // The buses.
        let w = lin(l, P_W, 3);
        let out = &l[COL_OUTPUT..COL_OUTPUT + WIDTH];
        b.lookup(true, ia, &text_message(w, &l[COL_DATA..COL_DATA + RATE]));
        b.lookup(true, last, &item_message(l[P_CUR], out));
        b.lookup(true, s2, &seed_message(out));
        for x in Self::range_cols() {
            b.lookup(true, one, &[c(TAG_RANGE), l[x]]);
        }
    }
}

// ---------------------------------------------------------------------------
// text, range, mix
// ---------------------------------------------------------------------------

/// The windows: preprocessed `[w, packed[8]]`, and the reads of each.
pub struct TextAir;

impl Air for TextAir {
    fn width(&self) -> usize {
        1
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn preprocessed_width(&self) -> usize {
        1 + RATE
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let pre = b.preprocessed();
        let m = b.local()[0];
        b.lookup(false, m, &text_message(pre[0], &pre[1..1 + RATE]));
    }
}

/// 0 to 1023, and how often each is ranged.
pub struct RangeAir;

impl Air for RangeAir {
    fn width(&self) -> usize {
        2
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let l = b.local();
        let n = b.next();
        b.when_first_row(l[0]);
        b.when_transition(n[0] - l[0] - F::ONE);
        b.lookup(false, l[1], &[F::from_u32(TAG_RANGE), l[0]]);
    }
}

const M_FIRST: usize = 0;
const M_I: usize = 1;
const M_IB: usize = 2; // 7 bits of I
const M_SEED0: usize = M_IB + 7;
const M_MIX: usize = M_SEED0 + 1; // 32
const M_OH: usize = M_MIX + MIX_WORDS; // 32
const M_SB: usize = M_OH + MIX_WORDS; // 31 bits of sel
const M_T: usize = M_SB + 31; // 3 helpers
const M_A: usize = M_T + 3; // 16
const M_BB: usize = M_A + WIDTH; // 16
const M_FIN: usize = M_BB + WIDTH; // the row after the last access
const M_SEED1: usize = M_FIN + 1;
const M_SB2: usize = M_SEED1 + 1; // 31 bits of the direct read's selector
const M_T2: usize = M_SB2 + 31; // 3 helpers
const M_WF: usize = M_T2 + 3; // the low bits were N or more
const M_WL: usize = M_WF + 1; // 2 limbs of its window
const M_WD: usize = M_WL + 2; // 2 limbs of N - 1 - w
const M_X: usize = M_WD + 2; // the window, 8 packed elements
pub const MIX_COLS: usize = M_X + RATE;
const MIX_ROWS: usize = 128;

/// hashimoto's accesses, one a row (64 active rows of 128).
pub struct MixAir {
    /// The first epoch's table has `2^log_pairs` pairs of items (`2^23` on
    /// mainnet).
    pub log_pairs: u32,
    /// The doublings to the largest table (five on mainnet): the public
    /// values say how many of them the table of this proof has had.
    pub growth: u32,
    /// The seed file's windows, `N`: at most 2^20.
    pub windows: usize,
}

/// A canonical value's 31 bits, from `bits`: binary, summing to `v`, and
/// with bits 30 to 27 all set the rest zero (`t`, three helpers).
fn canonical_bits<F: Field>(b: &mut Builder<'_, F>, v: F, bits: &[F], t: &[F]) {
    for x in bits {
        b.assert_zero(*x * *x - *x);
    }
    b.assert_eq(v, (0..31).fold(F::ZERO, |acc, k| acc + bits[k].scale(Fp::from_u32(1 << k))));
    b.assert_eq(t[0], bits[30] * bits[29]);
    b.assert_eq(t[1], bits[28] * bits[27]);
    b.assert_eq(t[2], t[0] * t[1]);
    b.assert_zero(t[2] * (0..27).fold(F::ZERO, |acc, k| acc + bits[k]));
}

impl Air for MixAir {
    fn width(&self) -> usize {
        MIX_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn lookup_group(&self) -> usize {
        2
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let l = b.local();
        let n = b.next();
        let p = b.public();
        let one = F::ONE;
        let c = |v: u32| F::from_u32(v);
        b.when_first_row(l[M_FIRST] - one);
        b.when_transition(n[M_FIRST]);
        b.when_first_row(l[M_I]);
        b.when_transition(n[M_I] - l[M_I] - one);
        for k in 0..7 {
            let x = l[M_IB + k];
            b.assert_zero(x * x - x);
        }
        b.assert_eq(l[M_I], (0..7).fold(F::ZERO, |acc, k| acc + l[M_IB + k].scale(Fp::new(1 << k))));
        let act = one - l[M_IB + 6];
        // The seed fills both halves of the first mix; seed0 is kept.
        for k in 0..WIDTH {
            b.when_first_row(l[M_MIX + WIDTH + k] - l[M_MIX + k]);
        }
        b.when_first_row(l[M_SEED0] - l[M_MIX]);
        b.when_transition(n[M_SEED0] - l[M_SEED0]);
        // mix[i % 32] by a rotating one-hot.
        b.when_first_row(l[M_OH] - one);
        for k in 1..MIX_WORDS {
            b.when_first_row(l[M_OH + k]);
        }
        for k in 0..MIX_WORDS {
            b.when_transition(n[M_OH + (k + 1) % MIX_WORDS] - l[M_OH + k]);
        }
        let picked = (0..MIX_WORDS).fold(F::ZERO, |acc, k| acc + l[M_OH + k] * l[M_MIX + k]);
        let sel = (l[M_I] + l[M_SEED0]).scale(FNV_PRIME) + picked;
        // sel in bits, canonical: bits 30..27 all set leave the rest zero.
        canonical_bits(b, sel, &l[M_SB..M_SB + 31], &l[M_T..M_T + 3]);
        // The pair is sel's low bits, as many as the table has pairs: those
        // of the first epoch's table, and one more for each doubling the
        // public values say this table has had.
        let lp = self.log_pairs as usize;
        let mut idx = (0..lp).fold(F::ZERO, |acc, k| acc + l[M_SB + k].scale(Fp::new(2 << k)));
        for j in 0..self.growth as usize {
            idx += p[PUB_TABLE + j] * l[M_SB + lp + j].scale(Fp::new(2 << (lp + j)));
        }
        // The direct read: sel2 = fnv(i + seed1, mix[(i + 16) % 32]) in bits,
        // canonical; its low L bits, less N once if they are N or more, are
        // the window: 0 <= w < N in limbs.
        b.when_first_row(l[M_SEED1] - l[M_MIX + 1]);
        b.when_transition(n[M_SEED1] - l[M_SEED1]);
        let picked2 = (0..MIX_WORDS).fold(F::ZERO, |acc, k| acc + l[M_OH + k] * l[M_MIX + (k + WIDTH) % MIX_WORDS]);
        let sel2 = (l[M_I] + l[M_SEED1]).scale(FNV_PRIME) + picked2;
        canonical_bits(b, sel2, &l[M_SB2..M_SB2 + 31], &l[M_T2..M_T2 + 3]);
        let bits = (self.windows as u32).next_power_of_two().trailing_zeros() as usize;
        let low = (0..bits).fold(F::ZERO, |acc, k| acc + l[M_SB2 + k].scale(Fp::new(1 << k)));
        let wf = l[M_WF];
        b.assert_zero(wf * wf - wf);
        let w = l[M_WL] + l[M_WL + 1].scale(Fp::new(LIMB));
        b.assert_eq(w, low - wf.scale(Fp::new(self.windows as u32)));
        b.assert_eq(l[M_WD] + l[M_WD + 1].scale(Fp::new(LIMB)), c(self.windows as u32 - 1) - w);
        // The two items folded in, and the window added.
        for k in 0..MIX_WORDS {
            let d = if k < WIDTH { l[M_A + k] } else { l[M_BB + k - WIDTH] };
            let x = l[M_X + k % RATE];
            b.when_transition(
                n[M_MIX + k] - l[M_MIX + k] - act * (l[M_MIX + k].scale(FNV_PRIME.sub(&Fp::ONE)) + d + x),
            );
        }
        // The row after the 64th access holds the final mix: folded to eight
        // elements (fnv is linear), the header's.
        b.when_first_row(l[M_FIN]);
        b.when_transition(n[M_FIN] - (n[M_IB + 6] - l[M_IB + 6]));
        let f = FNV_PRIME;
        for k in 0..DIGEST {
            let w = &l[M_MIX + 4 * k..M_MIX + 4 * k + 4];
            let folded = ((w[0].scale(f) + w[1]).scale(f) + w[2]).scale(f) + w[3];
            b.assert_zero(l[M_FIN] * (folded - p[PUB_MIX + k]));
        }
        b.lookup(false, l[M_FIRST], &seed_message(&l[M_MIX..M_MIX + WIDTH]));
        b.lookup(false, act, &item_message(idx, &l[M_A..M_A + WIDTH]));
        b.lookup(false, act, &item_message(idx + one, &l[M_BB..M_BB + WIDTH]));
        b.lookup(true, act, &text_message(w, &l[M_X..M_X + RATE]));
        for x in Self::range_cols() {
            b.lookup(true, act, &[c(TAG_RANGE), l[x]]);
        }
    }
}

impl MixAir {
    /// The limbs an active row ranges.
    fn range_cols() -> [usize; 4] {
        [M_WL, M_WL + 1, M_WD, M_WD + 1]
    }
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

/// The four traces of one header's proof of work, the public values and
/// the mix before its fold.
pub struct PowWitness {
    pub text: Trace,
    pub perm: Trace,
    pub range: Trace,
    pub mix: Trace,
    pub public: Vec<Fp>,
    pub mix_out: [Fp; MIX_WORDS],
}

/// What a proof of work's circuit depends on: the file's windows, the
/// absorbs an item and the sizes the table takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkShape {
    pub windows: usize,
    pub parents: usize,
    /// `2^log_pairs` pairs of items in the first epoch's table.
    pub log_pairs: u32,
    /// Doublings from the first table to the largest.
    pub growth: u32,
}

impl WorkShape {
    /// The proof of work's, for `seed`.
    pub fn of(seed: &SeedText<'_>) -> WorkShape {
        let params = seed.params();
        assert_eq!(params.accesses, MIX_ROWS / 2, "the mix table has a row an access, and as many idle");
        WorkShape {
            windows: seed.windows(),
            parents: params.parents,
            log_pairs: params.log_dataset_items - 1,
            growth: params.max_log_dataset_items - params.log_dataset_items,
        }
    }

    pub fn perm_air(&self) -> PermAir {
        // Two outputs make a value below 2^62, and its quotient by the
        // windows is ranged in five limbs: 50 bits.
        assert!(self.windows >= 1 << 12, "the quotient by the windows is ranged in five limbs");
        assert!(self.windows < 1 << 30, "a window's number is ranged in three limbs");
        PermAir { windows: self.windows, parents: self.parents }
    }

    pub fn mix_air(&self) -> MixAir {
        assert!(self.windows <= 1 << 20, "the direct read's window is ranged in two limbs");
        MixAir { log_pairs: self.log_pairs, growth: self.growth, windows: self.windows }
    }

    /// How many public values a proof has.
    pub fn num_public(&self) -> usize {
        PUB_TABLE + self.growth as usize
    }

    /// Whether the schedule has a table of `2^log_items` items.
    pub fn has_table(&self, log_items: u32) -> bool {
        log_items > self.log_pairs && log_items <= self.log_pairs + 1 + self.growth
    }

    /// The public values that say the table has `2^log_items` items: for
    /// each doubling, whether this table has had it.
    fn table_values(&self, log_items: u32) -> impl Iterator<Item = Fp> {
        let had = log_items - 1 - self.log_pairs;
        (0..self.growth).map(move |j| if j < had { Fp::ONE } else { Fp::ZERO })
    }

    /// Rows of the text table: a window a row.
    fn text_rows(&self) -> usize {
        self.windows.next_power_of_two().max(2)
    }

    /// Rows of the perm table: the seed's three, then a start and
    /// `parents` absorbs for each of the two items of each access.
    fn perm_rows(&self) -> usize {
        (3 + MIX_ROWS * (self.parents + 1)).next_power_of_two()
    }

    /// Log heights of the four tables (text, perm, range, mix), which a
    /// recursive verifier's program depends on: the same for every header.
    pub fn log_heights(&self) -> [usize; 4] {
        [self.text_rows(), self.perm_rows(), LIMB as usize, MIX_ROWS].map(|n| n.trailing_zeros() as usize)
    }
}

/// The seed file's window table: `[w, eight packed elements]` a row, the
/// rows past the last window zero.
pub fn text_table(seed: &SeedText<'_>) -> Trace {
    let rows = WorkShape::of(seed).text_rows();
    let mut pre = vec![Fp::ZERO; rows * (1 + RATE)];
    for (w, row) in pre.chunks_exact_mut(1 + RATE).enumerate() {
        row[0] = Fp::from_u32(w as u32);
        if w < seed.windows() {
            row[1..].copy_from_slice(&seed.window(w));
        }
    }
    Trace::new(pre, 1 + RATE)
}

/// A way to cheat, for the attack tests: the witness generator, made
/// lenient, writes the trace as a cheating prover would, everything after
/// the cheat computed from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cheat {
    None,
    /// Absorbs the next window while showing the true index.
    OtherWindow,
    /// Shows the next index (and absorbs its window) with the true quotient.
    OtherIndex,
    /// Absorbs the true window with an element changed.
    OtherText,
    /// An item of one parent too few, or too many.
    FewerParents,
    MoreParents,
    /// The first access's first item computed for another index.
    OtherItem,
    /// The first access picks another pair than its selector's bits.
    OtherPair,
    /// An output decomposed as itself plus p, where that fits 31 bits.
    NonCanonical,
    /// A window index past N (and so a padding row's zeros), the quotient one
    /// less.
    BeyondN,
    /// Another mix claimed, or another header hash.
    WrongMix,
    WrongHash,
    /// The first access adds the next window while showing the true index.
    OtherDirect,
    /// A direct read whose low bits are N or more taken unreduced, the
    /// table's padding row (zeros) read.
    DirectUnreduced,
    /// The pairs picked as in a table of another size than the public
    /// values say: twice the size, or half where there is none larger.
    OtherTable,
}

/// hashimoto's mix of `(header_hash, nonce)` in the table of
/// `2^log_items` items, its items computed from the seed file, and the
/// traces that prove it.
pub fn witness(seed: &SeedText<'_>, log_items: u32, header_hash: &Digest, nonce: &Nonce) -> PowWitness {
    witness_cheating(seed, log_items, header_hash, nonce, Cheat::None).0
}

/// [`witness`], cheating as `cheat` says (tests, with the generator
/// lenient), and whether it found where to: some cheats need a value few
/// headers give them.
pub fn witness_cheating(
    seed_text: &SeedText<'_>,
    log_items: u32,
    header_hash: &Digest,
    nonce: &Nonce,
    cheat: Cheat,
) -> (PowWitness, bool) {
    let shape = WorkShape::of(seed_text);
    assert!(shape.has_table(log_items), "no epoch has a table of 2^{log_items} items");
    let (windows, parents) = (shape.windows, shape.parents);
    let n_text = shape.text_rows();
    let window = |w: usize| seed_text.window(w);
    let mut reads = vec![0u32; n_text];
    let mut ranged = vec![0u32; LIMB as usize];
    let mut perm = HashTraceBuilder::with_capacity(PERM_COLS, shape.perm_rows());

    // The seed.
    let mut nonce_values = [Fp::ZERO; NONCE_FPS];
    for (x, v) in nonce_values.iter_mut().zip(packed(nonce)) {
        *x = v;
    }
    let mut input = [Fp::ZERO; WIDTH];
    input[..DIGEST].copy_from_slice(header_hash);
    input[DIGEST] = Fp::new(DOM_SEED);
    perm.start(input);
    perm.last_row_mut()[P_S0] = Fp::ONE;
    for (j, block) in nonce_values.chunks(RATE).enumerate() {
        let mut data = [Fp::ZERO; RATE];
        data[..block.len()].copy_from_slice(block);
        perm.absorb(data);
        perm.last_row_mut()[if j == 0 { P_S1 } else { P_S2 }] = Fp::ONE;
    }
    let seed = perm.state();

    // An item, its rows appended; `first` for the first access's first item,
    // where the cheats happen.
    let mut cheated = false;
    let mut item = |index: u32, first: bool, perm: &mut HashTraceBuilder, reads: &mut [u32]| -> [Fp; WIDTH] {
        let index = if first && cheat == Cheat::OtherItem { index + 2 } else { index };
        let parents = match (first, cheat) {
            (true, Cheat::FewerParents) => parents - 1,
            (true, Cheat::MoreParents) => parents + 1,
            _ => parents,
        };
        let mut input = [Fp::ZERO; WIDTH];
        input[0] = Fp::from_u32(index);
        input[1] = Fp::new(DOM_ITEM);
        perm.start(input);
        {
            let row = perm.last_row_mut();
            row[P_IS] = Fp::ONE;
            row[P_CUR] = Fp::from_u32(index);
        }
        for k in 1..=parents {
            let st = perm.state();
            let (mut a, bv) = (st[0].to_canonical(), st[1].to_canonical());
            // Not on an item's first steps: a cheat is then in the middle
            // of its rows.
            let here = first && !cheated && k >= 2;
            if here && cheat == Cheat::NonCanonical && (a as u64) + (P as u64) < 1 << 31 {
                a += P;
                cheated = true;
            }
            let r = a as u64 | (bv as u64) << 31;
            let mut w = (r % windows as u64) as u32;
            let mut q = r / windows as u64;
            let mut data = window(w as usize);
            if here {
                match cheat {
                    Cheat::OtherWindow => {
                        data = window((w as usize + 1) % windows);
                        cheated = true;
                    }
                    Cheat::OtherIndex => {
                        w = (w + 1) % windows as u32;
                        data = window(w as usize);
                        cheated = true;
                    }
                    Cheat::OtherText => {
                        data[0] = data[0].add(&Fp::ONE);
                        cheated = true;
                    }
                    Cheat::BeyondN if ((w as usize) + windows) < n_text && q > 0 => {
                        w += windows as u32;
                        q -= 1;
                        data = [Fp::ZERO; RATE];
                        cheated = true;
                    }
                    _ => {}
                }
            }
            refuse(a < P, "the output is canonical");
            refuse((w as usize) < windows, "the window is in the text");
            perm.absorb(data);
            reads[w as usize] += 1;
            let row = perm.last_row_mut();
            row[P_IA] = Fp::ONE;
            row[P_K] = Fp::from_u32(k as u32);
            row[P_CUR] = Fp::from_u32(index);
            row[P_PA0] = st[0];
            row[P_PA1] = st[1];
            let limbs4 = |v: u32| [v % LIMB, (v >> 10) % LIMB, (v >> 20) % LIMB, v >> 30];
            let (al, bl) = (limbs4(a), limbs4(bv));
            for j in 0..4 {
                row[P_A + j] = Fp::new(al[j]);
                row[P_B + j] = Fp::new(bl[j]);
            }
            // A value that is not canonical (only a cheat's) has no such
            // difference: what is written is its low 30 bits.
            let diff = |l: [u32; 4]| {
                let low = l[0] + l[1] * LIMB + l[2] * LIMB * LIMB;
                if l[3] == 1 { CANON_LOW.wrapping_sub(low) & ((1 << 30) - 1) } else { 0 }
            };
            for (at, d) in [(P_DA, diff(al)), (P_DB, diff(bl))] {
                for (j, x) in limbs3(d).iter().enumerate() {
                    row[at + j] = Fp::new(*x);
                }
            }
            let ql: [i64; 5] = core::array::from_fn(|j| ((q >> (10 * j)) % LIMB as u64) as i64);
            for j in 0..5 {
                row[P_Q + j] = Fp::new(ql[j] as u32);
            }
            let wl = limbs3(w);
            let m = limbs3(windows as u32 - 1);
            let dl = limbs3((windows as u32 - 1).wrapping_sub(w) & ((1 << 30) - 1));
            for j in 0..3 {
                row[P_W + j] = Fp::new(wl[j]);
                row[P_D + j] = Fp::new(dl[j]);
            }
            let e0 = (wl[0] as i64 + dl[0] as i64 - m[0] as i64).div_euclid(LIMB as i64);
            let e1 = (wl[1] as i64 + dl[1] as i64 + e0 - m[1] as i64).div_euclid(LIMB as i64);
            row[P_E] = Fp::from_u32(e0 as u32 & 1);
            row[P_E + 1] = Fp::from_u32(e1 as u32 & 1);
            let nl = limbs3(windows as u32);
            let rl = [al[0], al[1], al[2], al[3] + 2 * bl[0], 2 * bl[1], 2 * bl[2], 2 * bl[3]];
            let mut prev = 0i64;
            for kk in 0..7 {
                let mut ck = if kk < 3 { wl[kk] as i64 } else { 0 };
                for (j, nj) in nl.iter().enumerate() {
                    if kk >= j && kk - j < 5 {
                        ck += ql[kk - j] * *nj as i64;
                    }
                }
                let v = ck - rl[kk] as i64 + prev;
                if kk < 6 {
                    refuse(v % LIMB as i64 == 0, "the limbs carry whole");
                    let carry = v.div_euclid(LIMB as i64);
                    let biased = ((carry + CARRY_BIAS) as u32) & ((1 << 14) - 1);
                    row[P_C + kk] = Fp::new(biased % LIMB);
                    for j in 0..4 {
                        row[P_CH + 4 * kk + j] = Fp::new((biased >> (10 + j)) & 1);
                    }
                    prev = carry;
                } else {
                    refuse(v == 0, "the last limb balances");
                }
            }
            if k == parents {
                row[P_LAST] = Fp::ONE;
            }
        }
        perm.state()
    };

    // The accesses, and the mix table beside them.
    let pairs = 1u32 << (log_items - 1);
    // A cheat's table: the next size up, or down from the largest.
    let other_pairs = if log_items <= shape.log_pairs + shape.growth { pairs << 1 } else { pairs >> 1 };
    let low_mask = (windows as u32).next_power_of_two() - 1;
    let (mut unreduced, mut other_table) = (false, false);
    let mut mixv = [Fp::ZERO; MIX_WORDS];
    mixv[..WIDTH].copy_from_slice(&seed);
    mixv[WIDTH..].copy_from_slice(&seed);
    let mut mix_rows = vec![Fp::ZERO; MIX_ROWS * MIX_COLS];
    for (i, row) in mix_rows.chunks_exact_mut(MIX_COLS).enumerate() {
        row[M_FIRST] = if i == 0 { Fp::ONE } else { Fp::ZERO };
        row[M_I] = Fp::from_u32(i as u32);
        for k in 0..7 {
            row[M_IB + k] = Fp::new((i as u32 >> k) & 1);
        }
        row[M_SEED0] = seed[0];
        row[M_MIX..M_MIX + MIX_WORDS].copy_from_slice(&mixv);
        row[M_OH + i % MIX_WORDS] = Fp::ONE;
        let sel = fnv(Fp::from_u32(i as u32).add(&seed[0]), mixv[i % MIX_WORDS]);
        let sv = sel.to_canonical();
        for k in 0..31 {
            row[M_SB + k] = Fp::new((sv >> k) & 1);
        }
        let sv = if i == 0 && cheat == Cheat::OtherPair { sv ^ 2 } else { sv };
        let bit = |k: usize| (sv >> k) & 1;
        row[M_T] = Fp::new(bit(30) * bit(29));
        row[M_T + 1] = Fp::new(bit(28) * bit(27));
        row[M_T + 2] = Fp::new(bit(30) * bit(29) * bit(28) * bit(27));
        row[M_FIN] = if i == MIX_ROWS / 2 { Fp::ONE } else { Fp::ZERO };
        // The direct read.
        row[M_SEED1] = seed[1];
        let sel2 = fnv(Fp::from_u32(i as u32).add(&seed[1]), mixv[(i + WIDTH) % MIX_WORDS]);
        let s2 = sel2.to_canonical();
        for k in 0..31 {
            row[M_SB2 + k] = Fp::new((s2 >> k) & 1);
        }
        let bit2 = |k: usize| (s2 >> k) & 1;
        row[M_T2] = Fp::new(bit2(30) * bit2(29));
        row[M_T2 + 1] = Fp::new(bit2(28) * bit2(27));
        row[M_T2 + 2] = Fp::new(bit2(30) * bit2(29) * bit2(28) * bit2(27));
        let low = s2 & low_mask;
        let mut wrapped = low >= windows as u32;
        let mut wd = direct_window(s2, windows) as u32;
        let mut x = window(wd as usize);
        if i < MIX_ROWS / 2 {
            if i == 0 && cheat == Cheat::OtherDirect {
                x = window((wd as usize + 1) % windows);
            }
            if wrapped && !unreduced && cheat == Cheat::DirectUnreduced {
                unreduced = true;
                wrapped = false;
                wd = low;
                x = [Fp::ZERO; RATE];
            }
        }
        row[M_WF] = Fp::new(wrapped as u32);
        let d = (windows as u32 - 1).wrapping_sub(wd) & ((1 << 20) - 1);
        for (at, v) in [(M_WL, wd), (M_WD, d)] {
            row[at] = Fp::new(v % LIMB);
            row[at + 1] = Fp::new(v / LIMB);
        }
        row[M_X..M_X + RATE].copy_from_slice(&x);
        if i < MIX_ROWS / 2 {
            refuse((wd as usize) < windows, "the direct read is in the file");
            reads[wd as usize] += 1;
            for col in MixAir::range_cols() {
                if let Some(c) = ranged.get_mut(row[col].to_canonical() as usize) {
                    *c += 1;
                }
            }
            let mut pair = sv % pairs;
            if cheat == Cheat::OtherTable && !other_table && sv % other_pairs != pair {
                other_table = true;
                pair = sv % other_pairs;
            }
            let idx = pair * 2;
            let a = item(idx, i == 0, &mut perm, &mut reads);
            let bv = item(idx + 1, false, &mut perm, &mut reads);
            row[M_A..M_A + WIDTH].copy_from_slice(&a);
            row[M_BB..M_BB + WIDTH].copy_from_slice(&bv);
            for (k, (m, d)) in mixv.iter_mut().zip(a.iter().chain(&bv)).enumerate() {
                *m = fnv(*m, *d).add(&x[k % RATE]);
            }
        }
    }

    // Pass rows to a power of two; every row's limbs ranged.
    let perm_trace = perm.finish();
    for i in 0..perm_trace.height() {
        let row = perm_trace.row(i);
        for x in PermAir::range_cols() {
            // A limb out of range (only a cheat's) has no row to count on:
            // its lookup goes unanswered.
            if let Some(c) = ranged.get_mut(row[x].to_canonical() as usize) {
                *c += 1;
            }
        }
    }

    let text_main: Vec<Fp> = reads.iter().map(|r| Fp::new(*r)).collect();
    let mut range = vec![Fp::ZERO; 2 * LIMB as usize];
    for (v, row) in range.chunks_exact_mut(2).enumerate() {
        row[0] = Fp::new(v as u32);
        row[1] = Fp::new(ranged[v]);
    }
    let mut work = Work { pow_hash: *header_hash, nonce: *nonce, mix: fold_mix(&mixv), log_items };
    match cheat {
        Cheat::WrongHash => work.pow_hash[0] = work.pow_hash[0].add(&Fp::ONE),
        Cheat::WrongMix => work.mix[0] = work.mix[0].add(&Fp::ONE),
        _ => {}
    }
    let applied = match cheat {
        Cheat::None => false,
        Cheat::OtherWindow | Cheat::OtherIndex | Cheat::OtherText | Cheat::NonCanonical | Cheat::BeyondN => cheated,
        Cheat::DirectUnreduced => unreduced,
        Cheat::OtherTable => other_table,
        _ => true,
    };
    let witness = PowWitness {
        text: Trace::new(text_main, 1),
        perm: perm_trace,
        range: Trace::new(range, 2),
        mix: Trace::new(mix_rows, MIX_COLS),
        public: work.to_values(&shape),
        mix_out: mixv,
    };
    (witness, applied)
}

/// hashimoto's fold of the 32-element mix to the header's eight.
pub fn fold_mix(mix: &[Fp; MIX_WORDS]) -> Digest {
    core::array::from_fn(|k| {
        let w = &mix[4 * k..4 * k + 4];
        fnv(fnv(fnv(w[0], w[1]), w[2]), w[3])
    })
}

// ---------------------------------------------------------------------------
// The work segment
// ---------------------------------------------------------------------------

/// A header's work, as the work segment proves it: its `pow_hash`, nonce
/// and the true hashimoto `mix` of the two in the table of `2^log_items`
/// items. A block's statement carries its parent's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub pow_hash: Digest,
    pub nonce: Nonce,
    pub mix: Digest,
    pub log_items: u32,
}

impl Work {
    /// A header's, as it claims it (its `mix` checked by the proof of
    /// work), in the table of its height.
    pub fn of_header(seed: &SeedText<'_>, h: &crate::block::Header) -> Work {
        let log_items = seed.params().log_items_at(h.height as u64);
        Work { pow_hash: h.pow_hash(), nonce: h.nonce, mix: h.mix, log_items }
    }

    /// A header's, its mix computed (genesis, whose `mix` field is empty):
    /// from the seed file, a few tens of milliseconds.
    pub fn computed(seed: &SeedText<'_>, h: &crate::block::Header) -> Work {
        let pow_hash = h.pow_hash();
        let mix = crate::pow::hashimoto(&seed.at(h.height as u64), &pow_hash, &h.nonce).mix;
        Work { mix, ..Work::of_header(seed, h) }
    }

    /// The work segment's public values: the hash, the nonce's elements,
    /// the mix, and the flags of the table's size. `shape` must have the
    /// table ([`WorkShape::has_table`]).
    pub fn to_values(&self, shape: &WorkShape) -> Vec<Fp> {
        let mut v = Vec::with_capacity(shape.num_public());
        v.extend_from_slice(&self.pow_hash);
        v.extend(packed(&self.nonce));
        v.extend_from_slice(&self.mix);
        v.extend(shape.table_values(self.log_items));
        v
    }
}

/// The text's window table, committed once, and the shape of the proof of
/// work it serves (0.3 s and about 50 MB on mainnet: whoever proves keeps
/// one).
pub struct WorkSetup<'a> {
    pub shape: WorkShape,
    seed: SeedText<'a>,
    pre: Preprocessed,
}

impl<'a> WorkSetup<'a> {
    /// Commits the windows of `seed`'s file at `config`.
    pub fn new(seed: &SeedText<'a>, config: &StarkConfig) -> WorkSetup<'a> {
        let stride = config.quotient_stride(TextAir.max_constraint_degree());
        let pre = Preprocessed::new(&text_table(seed), config.log_blowup, stride);
        WorkSetup { shape: WorkShape::of(seed), seed: *seed, pre }
    }

    /// The root of the committed window table, which a verifier needs.
    pub fn root(&self) -> Digest {
        self.pre.root()
    }

    /// The committed window table.
    pub fn preprocessed(&self) -> &Preprocessed {
        &self.pre
    }

    /// What a verifier needs of it.
    pub fn verifier(&self) -> WorkVerifier {
        WorkVerifier { root: self.root(), shape: self.shape }
    }
}

/// What verifying a header's work needs: the window table's root and the
/// proof of work's shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkVerifier {
    pub root: Digest,
    pub shape: WorkShape,
}

fn work_transcript() -> crate::challenger::Challenger {
    let mut c = crate::challenger::Challenger::new();
    c.observe(Fp::new(DOM_WORK_PROOF));
    c
}

/// Proves a header's work: that `hashimoto(pow_hash, nonce)` in the table
/// of `2^log_items` items, its items computed from the seed file, gives
/// the mix of the [`Work`] returned.
pub fn prove_work(
    setup: &WorkSetup<'_>,
    config: &StarkConfig,
    log_items: u32,
    pow_hash: &Digest,
    nonce: &Nonce,
) -> (Proof, Work) {
    let w = witness(&setup.seed, log_items, pow_hash, nonce);
    let (perm, mix) = (setup.shape.perm_air(), setup.shape.mix_air());
    let inputs = [
        TableInput { air: &TextAir, trace: &w.text, pre: Some(&setup.pre) },
        TableInput { air: &perm, trace: &w.perm, pre: None },
        TableInput { air: &RangeAir, trace: &w.range, pre: None },
        TableInput { air: &mix, trace: &w.mix, pre: None },
    ];
    let proof = prove_tables(config, &inputs, &w.public, &mut work_transcript());
    (proof, Work { pow_hash: *pow_hash, nonce: *nonce, mix: fold_mix(&w.mix_out), log_items })
}

/// Verifies the bytes of a proof of [`prove_work`] for `work`, against
/// the window table's root. The caller takes `work` from a header: its
/// hash, nonce and mix, and the table of its height.
pub fn verify_work(verifier: &WorkVerifier, config: &StarkConfig, work: &Work, proof: &[u8]) -> Result<(), Error> {
    if !verifier.shape.has_table(work.log_items) {
        return Err(Error::Malformed("work"));
    }
    let (perm, mix_air) = (verifier.shape.perm_air(), verifier.shape.mix_air());
    let specs = [
        TableSpec { air: &TextAir, pre_root: Some(&verifier.root) },
        TableSpec { air: &perm, pre_root: None },
        TableSpec { air: &RangeAir, pre_root: None },
        TableSpec { air: &mix_air, pre_root: None },
    ];
    verify_bytes(config, &specs, &work.to_values(&verifier.shape), proof, &mut work_transcript())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{self, PowParams};
    use crate::stark::audit::{audit_report, mutation_audit};
    use crate::stark::{self, DynAir, LENIENT, measure_degree};
    use crate::test_util::Rng;

    const SEGMENT: StarkConfig =
        StarkConfig { log_blowup: 2, num_queries: 54, pow_bits: 16, zk: false, commit_bits: 121 };
    /// A configuration quick to prove at, for the small work below.
    const QUICK: StarkConfig = StarkConfig { log_blowup: 2, num_queries: 8, pow_bits: 0, zk: false, commit_bits: 0 };

    /// A proof of work small enough to prove in a test: tables of 256
    /// items doubling to 1,024, twelve parents an item, and a file of
    /// 4,102 windows whose last overlaps the one before (the circuit
    /// needs 4,096 at least).
    const SMALL: PowParams =
        PowParams { log_dataset_items: 8, max_log_dataset_items: 10, epoch_blocks: 100, parents: 12, accesses: 64 };

    fn small_text() -> Vec<u8> {
        let mut rng = Rng::new(0x706f77);
        (0..4101 * pow::WINDOW + 7).map(|_| rng.next_u64() as u8).collect()
    }

    fn header() -> (Digest, Nonce) {
        (core::array::from_fn(|k| Fp::new(1000 + k as u32 * 7)), core::array::from_fn(|k| (k * 13) as u8))
    }

    fn tables<'a>(
        w: &'a PowWitness,
        text: &'a Trace,
        perm: &'a PermAir,
        mix: &'a MixAir,
    ) -> Vec<(&'a dyn DynAir, &'a Trace, Option<&'a Trace>)> {
        vec![(&TextAir, &w.text, Some(text)), (perm, &w.perm, None), (&RangeAir, &w.range, None), (mix, &w.mix, None)]
    }

    #[test]
    fn degrees_and_heights() {
        let text = small_text();
        for seed in [SeedText::from_bytes(SMALL, &text), SeedText::new(PowParams::MAINNET)] {
            let shape = WorkShape::of(&seed);
            let public = shape.num_public();
            assert_eq!(measure_degree(&shape.perm_air(), public), 3);
            assert_eq!(measure_degree(&shape.mix_air(), public), 3);
            assert!(measure_degree(&TextAir, public) <= 3);
            assert!(measure_degree(&RangeAir, public) <= 3);
        }
        // The heights a shape promises are the witness's, with no witness made.
        let seed = SeedText::from_bytes(SMALL, &text);
        let (hh, nonce) = header();
        let w = witness(&seed, 9, &hh, &nonce);
        let heights = [&w.text, &w.perm, &w.range, &w.mix].map(|t| t.height().trailing_zeros() as usize);
        assert_eq!(WorkShape::of(&seed).log_heights(), heights);
        assert_eq!(heights, [13, 11, 10, 7]);
        // Mainnet's: 53,795 windows, and 128 items of 255 rows.
        let mainnet = WorkShape::of(&SeedText::new(PowParams::MAINNET));
        assert_eq!(mainnet.log_heights(), [16, 15, 10, 7]);
        assert_eq!((mainnet.log_pairs, mainnet.growth, mainnet.num_public()), (23, 5, 32));
    }

    /// In every table of the schedule the witness's mix is hashimoto's,
    /// every constraint holds and the buses balance; the public values
    /// are the header's work.
    #[test]
    fn the_witness_is_hashimotos_in_every_table() {
        let text = small_text();
        let seed = SeedText::from_bytes(SMALL, &text);
        let shape = WorkShape::of(&seed);
        let (perm, mix) = (shape.perm_air(), shape.mix_air());
        let table = text_table(&seed);
        let mut mixes = Vec::new();
        for log_items in 8..=10 {
            for n in 0..3u64 {
                let (hh, nonce) = (header().0, pow::nonce_from_u64(n));
                let w = witness(&seed, log_items, &hh, &nonce);
                let want = pow::hashimoto(&seed.table(log_items), &hh, &nonce);
                assert_eq!(fold_mix(&w.mix_out), want.mix);
                let work = Work { pow_hash: hh, nonce, mix: want.mix, log_items };
                assert_eq!(w.public, work.to_values(&shape));
                assert_eq!(w.public.len(), shape.num_public());
                assert_eq!(stark::check_tables(&tables(&w, &table, &perm, &mix), &w.public), Ok(()));
                mixes.push(want.mix);
            }
        }
        // The tables differ: so do the mixes, and the flags that tell them apart.
        let distinct: std::collections::HashSet<[u32; DIGEST]> =
            mixes.iter().map(|m| m.map(|x| x.to_canonical())).collect();
        assert_eq!(distinct.len(), 9);
        let flags = |log_items| shape.table_values(log_items).map(|f| f.to_canonical()).collect::<Vec<_>>();
        assert_eq!([flags(8), flags(9), flags(10)], [vec![0, 0], vec![1, 0], vec![1, 1]]);
        assert!(!shape.has_table(7) && !shape.has_table(11));
    }

    const CHEATS: [Cheat; 14] = [
        Cheat::OtherWindow,
        Cheat::OtherIndex,
        Cheat::OtherText,
        Cheat::FewerParents,
        Cheat::MoreParents,
        Cheat::OtherItem,
        Cheat::OtherPair,
        Cheat::NonCanonical,
        Cheat::BeyondN,
        Cheat::WrongMix,
        Cheat::WrongHash,
        Cheat::OtherDirect,
        Cheat::DirectUnreduced,
        Cheat::OtherTable,
    ];

    /// The witness of the first nonce `cheat` finds its place with.
    fn cheating(seed: &SeedText<'_>, log_items: u32, cheat: Cheat) -> PowWitness {
        let hh = header().0;
        LENIENT.with(|l| l.set(true));
        let found = (0..2000).find_map(|n| {
            let (w, applied) = witness_cheating(seed, log_items, &hh, &pow::nonce_from_u64(n), cheat);
            applied.then_some(w)
        });
        LENIENT.with(|l| l.set(false));
        found.unwrap_or_else(|| panic!("{cheat:?} found no place"))
    }

    /// Each way of cheating, written as a cheating prover would (the
    /// generator lenient, all after the cheat computed from it), is refused
    /// by the constraints or the buses, in the smallest table and the
    /// largest.
    #[test]
    fn attacks() {
        let text = small_text();
        let seed = SeedText::from_bytes(SMALL, &text);
        let shape = WorkShape::of(&seed);
        let (perm, mix) = (shape.perm_air(), shape.mix_air());
        let table = text_table(&seed);
        for log_items in [8, 10] {
            for cheat in CHEATS {
                let w = cheating(&seed, log_items, cheat);
                let checked = stark::check_tables(&tables(&w, &table, &perm, &mix), &w.public);
                assert!(checked.is_err(), "{cheat:?} accepted in the table of 2^{log_items}");
            }
        }
    }

    /// Soundness audit of the four tables together: the cells a prover
    /// can change with nothing noticing are those of rows that do
    /// nothing.
    #[test]
    fn the_free_cells_are_on_idle_rows() {
        let text = small_text();
        let seed = SeedText::from_bytes(SMALL, &text);
        let shape = WorkShape::of(&seed);
        let (perm, mix) = (shape.perm_air(), shape.mix_air());
        let table = text_table(&seed);
        let (hh, nonce) = header();
        let w = witness(&seed, 9, &hh, &nonce);
        let survivors = mutation_audit(&tables(&w, &table, &perm, &mix), &w.public, 48);
        let report = audit_report(&survivors, |t, c| format!("table {t} column {c}"));
        for s in &survivors {
            let idle = match s.table {
                1 => s.column == crate::hash_machine::COL_DIR || w.perm.row(s.row)[P_IA] == Fp::ZERO,
                3 => s.row >= MIX_ROWS / 2,
                _ => false,
            };
            assert!(idle, "table {} column {} row {} is free\n{report}", s.table, s.column, s.row);
        }
    }

    /// A small header's work: proven, and verified only against its own
    /// hash, nonce, mix and table, and the window table's root.
    #[test]
    fn proves_and_verifies() {
        let text = small_text();
        let seed = SeedText::from_bytes(SMALL, &text);
        let setup = WorkSetup::new(&seed, &QUICK);
        let verifier = setup.verifier();
        let (hh, nonce) = header();
        let (proof, work) = prove_work(&setup, &QUICK, 9, &hh, &nonce);
        assert_eq!(work.mix, pow::hashimoto(&seed.table(9), &hh, &nonce).mix);
        let bytes = proof.to_bytes();
        assert_eq!(verify_work(&verifier, &QUICK, &work, &bytes), Ok(()));

        let refused = |v: &WorkVerifier, w: &Work| verify_work(v, &QUICK, w, &bytes).is_err();
        let mut mix = work.mix;
        mix[3] = mix[3].add(&Fp::ONE);
        assert!(refused(&verifier, &Work { mix, ..work }), "another mix");
        assert!(refused(&verifier, &Work { nonce: pow::nonce_from_u64(43), ..work }), "another nonce");
        let mut pow_hash = work.pow_hash;
        pow_hash[0] = pow_hash[0].add(&Fp::ONE);
        assert!(refused(&verifier, &Work { pow_hash, ..work }), "another header");
        // The proof is of one table: not of a smaller or a larger, nor of
        // one the schedule does not have.
        for log_items in [8, 10] {
            assert!(refused(&verifier, &Work { log_items, ..work }), "the table of 2^{log_items}");
        }
        for log_items in [0, 7, 11, 40] {
            assert_eq!(
                verify_work(&verifier, &QUICK, &Work { log_items, ..work }, &bytes),
                Err(Error::Malformed("work"))
            );
        }
        let mut root = verifier.root;
        root[0] = root[0].add(&Fp::ONE);
        assert!(refused(&WorkVerifier { root, ..verifier }, &work), "another text");
        // Another file's table has another root.
        let mut other = text.clone();
        other[1000] ^= 1;
        assert_ne!(WorkSetup::new(&SeedText::from_bytes(SMALL, &other), &QUICK).root(), verifier.root);
    }

    /// A header's work is its own fields and the table of its height.
    #[test]
    fn a_headers_work() {
        use crate::block::Header;
        let text = small_text();
        let seed = SeedText::from_bytes(SMALL, &text);
        let mut header = Header {
            prev_hash: core::array::from_fn(|k| Fp::new(11 + k as u32)),
            height: 150,
            timestamp: 1_793_400_000,
            body_commitment: core::array::from_fn(|k| Fp::new(500 + k as u32)),
            state_root: core::array::from_fn(|k| Fp::new(900 + k as u32)),
            aux: [0; 32],
            mix: [Fp::ZERO; DIGEST],
            nonce: pow::nonce_from_u64(42),
        };
        let work = Work::computed(&seed, &header);
        // Height 150 is in the second epoch: the table of 2^9 items.
        assert_eq!(work.log_items, 9);
        assert_eq!(work.mix, pow::hashimoto(&seed.at(150), &header.pow_hash(), &header.nonce).mix);
        header.mix = work.mix;
        assert_eq!(Work::of_header(&seed, &header), work);
        header.height = 950;
        assert_eq!(Work::of_header(&seed, &header).log_items, 10);
    }

    /// The verifier of a work proof as a machine program, as a block's
    /// root runs it: given the window table's root and `work`.
    fn fold(setup: &WorkSetup<'_>, config: &StarkConfig, work: &Work, proof: &Proof) -> crate::recursion::Compiler {
        let mut c = crate::recursion::Compiler::new();
        let public = work.to_values(&setup.shape);
        let pubv = c.scalar_inputs(&public);
        let root = c.scalar_inputs(&setup.root());
        for (i, v) in setup.root().iter().enumerate() {
            c.assert_scalar(root + i as u32, *v);
        }
        let (perm, mix) = (setup.shape.perm_air(), setup.shape.mix_air());
        let tables: [(&dyn DynAir, Option<u32>); 4] =
            [(&TextAir, Some(root)), (&perm, None), (&RangeAir, None), (&mix, None)];
        c.verify_stark(&tables, config, &[Fp::new(DOM_WORK_PROOF)], pubv, public.len(), proof);
        c
    }

    /// The work segment verified inside a machine program: it accepts the
    /// proof for its own work and table, refuses it for another, and is
    /// the same program whatever the proof and whichever the table.
    #[test]
    fn folds() {
        use crate::vm_air::VmAir;
        let text = small_text();
        let seed = SeedText::from_bytes(SMALL, &text);
        let setup = WorkSetup::new(&seed, &QUICK);
        let (hh, nonce) = header();
        let (proof, work) = prove_work(&setup, &QUICK, 9, &hh, &nonce);
        let c = fold(&setup, &QUICK, &work, &proof);
        VmAir::execute(&c.prog, &c.inputs).expect("the verifier program accepts");
        for log_items in [8, 10] {
            let other = fold(&setup, &QUICK, &Work { log_items, ..work }, &proof);
            assert_eq!(other.prog.instrs, c.prog.instrs, "one program for every table");
            assert!(VmAir::execute(&other.prog, &other.inputs).is_err(), "the table of 2^{log_items}");
        }
        // A proof of zeros of the same shape compiles to the same program:
        // a verifier knows it with no proof in hand.
        let heights = setup.shape.log_heights();
        let (perm, mix) = (setup.shape.perm_air(), setup.shape.mix_air());
        let airs: [(&dyn DynAir, usize); 4] =
            [(&TextAir, heights[0]), (&perm, heights[1]), (&RangeAir, heights[2]), (&mix, heights[3])];
        let dummy = crate::recursion::dummy_proof(&airs, &QUICK, setup.shape.num_public());
        assert_eq!(fold(&setup, &QUICK, &work, &dummy).prog.instrs, c.prog.instrs);
    }

    /// Mainnet's work segment as a machine program: its size, and that it
    /// accepts.
    #[test]
    #[ignore = "slow: proves a header's work and compiles its verifier"]
    fn mainnet_folds() {
        use crate::vm_air::VmAir;
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let setup = WorkSetup::new(&seed, &SEGMENT);
        let (proof, work) = prove_work(&setup, &SEGMENT, 26, &hh, &nonce);
        let t = std::time::Instant::now();
        let c = fold(&setup, &SEGMENT, &work, &proof);
        println!(
            "compiled in {:.2?}: {} rows (2^{}), hash rows 2^{}",
            t.elapsed(),
            c.prog.instrs.len(),
            c.prog.height().trailing_zeros(),
            VmAir::hash_height(&c.prog).trailing_zeros()
        );
        VmAir::execute(&c.prog, &c.inputs).expect("the verifier program accepts");
    }

    /// Mainnet's work: the witness's mix is hashimoto's and the
    /// constraints hold, in the first table and the last.
    #[test]
    #[ignore = "slow: the seed file and 128 items of 254 parents, twice"]
    fn mainnet_constraints_hold() {
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let shape = WorkShape::of(&seed);
        let table = text_table(&seed);
        for log_items in [24, 29] {
            let w = witness(&seed, log_items, &hh, &nonce);
            assert_eq!(fold_mix(&w.mix_out), pow::hashimoto(&seed.table(log_items), &hh, &nonce).mix);
            let checked = stark::check_tables(&tables(&w, &table, &shape.perm_air(), &shape.mix_air()), &w.public);
            assert_eq!(checked, Ok(()));
        }
    }

    /// Mainnet's attacks: as [`attacks`], with the real file and parents.
    #[test]
    #[ignore = "slow: the seed file and 128 items, for each cheat"]
    fn mainnet_attacks() {
        let seed = SeedText::new(PowParams::MAINNET);
        let shape = WorkShape::of(&seed);
        let (perm, mix) = (shape.perm_air(), shape.mix_air());
        let table = text_table(&seed);
        for cheat in CHEATS {
            let w = cheating(&seed, 26, cheat);
            assert!(stark::check_tables(&tables(&w, &table, &perm, &mix), &w.public).is_err(), "{cheat:?} accepted");
        }
    }

    /// Proving and verifying one header's proof of work at the mainnet
    /// segment configuration.
    /// `cargo test --release --lib pow_air::tests::cost -- --ignored --nocapture`
    #[test]
    #[ignore = "slow: measures proving"]
    fn cost() {
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let shape = WorkShape::of(&seed);
        let t = std::time::Instant::now();
        let w = witness(&seed, 24, &hh, &nonce);
        let built = t.elapsed();
        drop(w);
        let t = std::time::Instant::now();
        let setup = WorkSetup::new(&seed, &SEGMENT);
        let commit = t.elapsed();
        let t = std::time::Instant::now();
        let (proof, work) = prove_work(&setup, &SEGMENT, 24, &hh, &nonce);
        let proved = t.elapsed() - built;
        let bytes = proof.to_bytes();
        let t = std::time::Instant::now();
        let ok = verify_work(&setup.verifier(), &SEGMENT, &work, &bytes);
        let verified = t.elapsed();
        assert_eq!(ok, Ok(()));
        let heights = shape.log_heights();
        println!(
            "parents {}: text 2^{} perm 2^{} ({PERM_COLS} cols) mix {MIX_COLS} cols | witness {built:.2?}, text commit (once) {commit:.2?}, prove {proved:.2?}, {} KB, verify {verified:.2?}",
            shape.parents,
            heights[0],
            heights[1],
            bytes.len() / 1024,
        );
    }
}
