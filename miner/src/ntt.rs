//! Number-theoretic transform over BabyBear and its two-adic cosets.
//!
//! BabyBear has `p - 1 = 15 * 2^27`, so multiplicative subgroups of every
//! power-of-two order up to `2^27` exist. [`ntt`] evaluates a polynomial given
//! by coefficients on the subgroup of order `n` (natural order in, natural
//! order out); [`intt`] interpolates. The coset variants work on `shift * H`.
//! Extension field versions apply the transform to each of the four base
//! coordinates, which is valid because the transform is `Fp`-linear.
//!
//! # Memory
//!
//! A transform works in place. What it keeps is its twiddles: for stage
//! `s`, the `2^(s-1)` powers of the root of order `2^s`, made the first
//! time a transform that large runs and kept for the life of the process,
//! one table for each direction. A transform of size `n` uses the stages
//! up to its own, so all sizes share them: `4 n` bytes for each direction
//! at the largest size used, and nothing more for the smaller ones.
//!
//! A coset's shift needs no table: its powers are made as they are
//! multiplied in, eight chains abreast.
//!
//! Only a prover transforms. A verifier takes from here the roots of
//! unity and the evaluation of a polynomial at a point, which use no heap.

use std::sync::OnceLock;

use crate::ext::{DEGREE, Fp4};
use crate::poseidon2::Fp;

/// Largest `k` such that a subgroup of order `2^k` exists.
pub const TWO_ADICITY: usize = 27;

/// Generator of the subgroup of order `2^27` (`31^15`, as in Plonky3).
pub const TWO_ADIC_GENERATOR: Fp = Fp::new(440_564_289);

/// Multiplicative generator of the whole field, used as the default coset
/// shift so that `shift * H` is disjoint from `H`.
pub const MULTIPLICATIVE_GENERATOR: Fp = Fp::new(31);

const INV_2: Fp = Fp::new(1_006_632_961);

/// A primitive root of unity of order `2^log_n`.
pub fn root_of_unity(log_n: usize) -> Fp {
    assert!(log_n <= TWO_ADICITY, "no subgroup of order 2^{log_n}");
    TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - log_n))
}

pub fn log2_strict(n: usize) -> usize {
    assert!(n.is_power_of_two(), "{n} is not a power of two");
    n.trailing_zeros() as usize
}

/// Reorders `v` so that index `i` moves to the bit reversal of `i`.
pub fn bit_reverse_permute<T>(v: &mut [T]) {
    let n = v.len();
    if n <= 2 {
        return;
    }
    let bits = log2_strict(n);
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - bits);
        if i < j {
            v.swap(i, j);
        }
    }
}

/// The twiddles of stage `stage` (1 and up): the `2^(stage-1)` first
/// powers of the root of unity of order `2^stage`, or of its inverse.
/// Made once and kept; every transform that has the stage shares them.
fn stage_twiddles(stage: usize, inverse: bool) -> &'static [Fp] {
    const STAGES: usize = TWO_ADICITY + 1;
    static FORWARD: [OnceLock<Vec<Fp>>; STAGES] = [const { OnceLock::new() }; STAGES];
    static INVERSE: [OnceLock<Vec<Fp>>; STAGES] = [const { OnceLock::new() }; STAGES];
    let table = if inverse { &INVERSE } else { &FORWARD };
    table[stage].get_or_init(|| {
        let root = root_of_unity(stage);
        let root = if inverse { root.inverse().expect("a root of unity is not zero") } else { root };
        let half = 1usize << (stage - 1);
        let mut v = Vec::with_capacity(half);
        let mut w = Fp::ONE;
        for _ in 0..half {
            v.push(w);
            w = w.mul(&root);
        }
        v
    })
}

/// In-place radix-2 transform with the root of unity of order `n`, or
/// with its inverse.
fn transform(v: &mut [Fp], inverse: bool) {
    let n = v.len();
    if n <= 1 {
        return;
    }
    let log_n = log2_strict(n);
    assert!(log_n <= TWO_ADICITY, "no subgroup of order 2^{log_n}");
    bit_reverse_permute(v);
    for stage in 1..=log_n {
        let half = 1usize << (stage - 1);
        let twiddles = stage_twiddles(stage, inverse);
        for block in v.chunks_exact_mut(2 * half) {
            let (lo, hi) = block.split_at_mut(half);
            butterflies(lo, hi, twiddles);
        }
    }
}

/// `(a, b) <- (a + w b, a - w b)` elementwise.
#[inline]
fn butterflies(lo: &mut [Fp], hi: &mut [Fp], twiddles: &[Fp]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    if lo.len() >= 8 {
        use crate::packed::{add, load_fp, mul, store_fp, sub};
        for ((a, b), w) in lo.chunks_exact_mut(8).zip(hi.chunks_exact_mut(8)).zip(twiddles.chunks_exact(8)) {
            let (va, t) = (load_fp(a), mul(load_fp(b), load_fp(w)));
            store_fp(a, add(va, t));
            store_fp(b, sub(va, t));
        }
        return;
    }
    for ((a, b), w) in lo.iter_mut().zip(hi.iter_mut()).zip(twiddles) {
        let t = b.mul(w);
        *b = a.sub(&t);
        *a = a.add(&t);
    }
}

/// `v[i] *= base^i`. The powers are made as they are used, in eight
/// chains each stepping by `base^8`, so that no multiplication waits for
/// the one before it; they are held nowhere.
#[inline]
fn scale_by_powers(v: &mut [Fp], base: Fp) {
    let mut powers = [Fp::ONE; 8];
    for k in 1..8 {
        powers[k] = powers[k - 1].mul(&base);
    }
    let step = powers[7].mul(&base);
    let mut chunks = v.chunks_exact_mut(8);
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        use crate::packed::{load_fp, mul, splat_fp, store_fp};
        let (mut p, s) = (load_fp(&powers), splat_fp(step));
        for x in &mut chunks {
            store_fp(x, mul(load_fp(x), p));
            p = mul(p, s);
        }
        store_fp(&mut powers, p);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    for x in &mut chunks {
        for (x, p) in x.iter_mut().zip(powers.iter_mut()) {
            *x = x.mul(p);
            *p = p.mul(&step);
        }
    }
    for (x, p) in chunks.into_remainder().iter_mut().zip(&powers) {
        *x = x.mul(p);
    }
}

/// The sum of `a[i] * b[i]`: a polynomial's value at a point, from its
/// coefficients and the point's powers. Eight products at a time where
/// the machine has the instructions for it, one at a time where it has
/// not: the same sum either way.
pub fn dot(a: &[Fp], b: &[Fp]) -> Fp {
    assert_eq!(a.len(), b.len());
    let (mut xs, mut ys) = (a.chunks_exact(8), b.chunks_exact(8));
    let mut sum = Fp::ZERO;
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        use crate::packed::{add, load_fp, mul, splat_fp, store_fp};
        let mut lanes = splat_fp(Fp::ZERO);
        for (x, y) in (&mut xs).zip(&mut ys) {
            lanes = add(lanes, mul(load_fp(x), load_fp(y)));
        }
        let mut sums = [Fp::ZERO; 8];
        store_fp(&mut sums, lanes);
        for part in sums {
            sum = sum.add(&part);
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    for (x, y) in (&mut xs).zip(&mut ys) {
        for (p, q) in x.iter().zip(y) {
            sum = sum.add(&p.mul(q));
        }
    }
    for (p, q) in xs.remainder().iter().zip(ys.remainder()) {
        sum = sum.add(&p.mul(q));
    }
    sum
}

/// `v[i] *= c`.
#[inline]
fn scale_const(v: &mut [Fp], c: Fp) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        use crate::packed::{load_fp, mul, splat_fp, store_fp};
        let vc = splat_fp(c);
        let whole = v.len() / 8 * 8;
        let (head, tail) = v.split_at_mut(whole);
        for x in head.chunks_exact_mut(8) {
            store_fp(x, mul(load_fp(x), vc));
        }
        for x in tail {
            *x = x.mul(&c);
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    for x in v.iter_mut() {
        *x = x.mul(&c);
    }
}

/// Coefficients to evaluations on `H`.
pub fn ntt(v: &mut [Fp]) {
    transform(v, false);
}

/// Evaluations on `H` to coefficients.
pub fn intt(v: &mut [Fp]) {
    let n = v.len();
    if n <= 1 {
        return;
    }
    transform(v, true);
    let inv_n = Fp::new(n as u32).inverse().unwrap();
    scale_const(v, inv_n);
}

/// Coefficients to evaluations on the coset `shift * H`.
pub fn coset_ntt(v: &mut [Fp], shift: Fp) {
    scale_by_powers(v, shift);
    ntt(v);
}

/// Evaluations of the polynomial with coefficients `coeffs` (`n` of them)
/// on the coset `shift * H` of size `n * 2^log_blowup`, in coset-major
/// order: entry `j * n + m` is the value at `shift * w^(j + 2^log_blowup *
/// m)`, `w` of order `n * 2^log_blowup`. Each of the `2^log_blowup` cosets
/// `shift * w^j * H_n` is one transform of size `n`, which stays in cache
/// where a single transform of the full size would not.
pub fn lde_cosets(coeffs: &[Fp], log_blowup: usize, shift: Fp) -> Vec<Fp> {
    let mut out = crate::poseidon2::zeroed_vec(coeffs.len() << log_blowup);
    lde_cosets_into(coeffs, log_blowup, shift, &mut out);
    out
}

/// [`lde_cosets`] into `out`, which is to hold `coeffs.len() << log_blowup`
/// values: each coset is transformed where it is to lie.
pub fn lde_cosets_into(coeffs: &[Fp], log_blowup: usize, shift: Fp, out: &mut [Fp]) {
    let n = coeffs.len();
    assert_eq!(out.len(), n << log_blowup, "a value for each point of the coset");
    if n == 0 {
        return;
    }
    let w = root_of_unity(log2_strict(n) + log_blowup);
    let mut s = shift;
    for coset in out.chunks_exact_mut(n) {
        coset.copy_from_slice(coeffs);
        coset_ntt(coset, s);
        s = s.mul(&w);
    }
}

/// Evaluations of the polynomial with coefficients `coeffs` on the coset
/// `shift * H` of its own size.
pub fn coset_evals(coeffs: &[Fp], shift: Fp) -> Vec<Fp> {
    let mut v = coeffs.to_vec();
    coset_ntt(&mut v, shift);
    v
}

/// Evaluations on `shift * H` to coefficients.
pub fn coset_intt(v: &mut [Fp], shift: Fp) {
    intt(v);
    let inv = shift.inverse().expect("shift must be non-zero");
    scale_by_powers(v, inv);
}

/// Applies a transform of base values to each of the four coordinates of
/// extension values, through one column of base values that is freed.
fn map_components(v: &mut [Fp4], f: impl Fn(&mut [Fp])) {
    let mut col = vec![Fp::ZERO; v.len()];
    for k in 0..DEGREE {
        for (c, x) in col.iter_mut().zip(v.iter()) {
            *c = x.0[k];
        }
        f(&mut col);
        for (x, c) in v.iter_mut().zip(&col) {
            x.0[k] = *c;
        }
    }
}

/// [`coset_ntt`] for extension field polynomials.
pub fn coset_ntt_ext(v: &mut [Fp4], shift: Fp) {
    map_components(v, |c| coset_ntt(c, shift));
}

/// [`coset_intt`] for extension field evaluations.
pub fn coset_intt_ext(v: &mut [Fp4], shift: Fp) {
    map_components(v, |c| coset_intt(c, shift));
}

/// Evaluates the polynomial with coefficients `coeffs` at `x` (Horner).
pub fn eval_poly(coeffs: &[Fp], x: Fp) -> Fp {
    coeffs.iter().rev().fold(Fp::ZERO, |acc, c| acc.mul(&x).add(c))
}

/// Evaluates an extension polynomial at an extension point.
pub fn eval_poly_ext(coeffs: &[Fp4], x: Fp4) -> Fp4 {
    coeffs.iter().rev().fold(Fp4::ZERO, |acc, c| acc.mul(&x).add(c))
}

/// `1/2`, used by FRI folding.
pub const fn inv_two() -> Fp {
    INV_2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    #[test]
    fn roots_have_exact_order() {
        assert_eq!(TWO_ADIC_GENERATOR, MULTIPLICATIVE_GENERATOR.pow(15));
        for log_n in 0..=TWO_ADICITY {
            let w = root_of_unity(log_n);
            assert_eq!(w.pow(1u64 << log_n), Fp::ONE, "order 2^{log_n}");
            if log_n > 0 {
                assert_eq!(w.pow(1u64 << (log_n - 1)), -Fp::ONE);
            }
        }
        assert_eq!(INV_2 + INV_2, Fp::ONE);
    }

    #[test]
    fn coset_split_extension_matches_one_transform() {
        let mut rng = Rng::new(77);
        for (log_n, log_blowup) in [(0, 2), (3, 1), (5, 3), (8, 5)] {
            let n = 1usize << log_n;
            let coeffs: Vec<Fp> = (0..n).map(|_| rng.fp()).collect();
            let shift = MULTIPLICATIVE_GENERATOR;
            let mut full = coeffs.clone();
            full.resize(n << log_blowup, Fp::ZERO);
            coset_ntt(&mut full, shift);
            let split = lde_cosets(&coeffs, log_blowup, shift);
            let b = 1usize << log_blowup;
            for i in 0..n << log_blowup {
                assert_eq!(split[(i % b) * n + i / b], full[i], "log_n {log_n} blowup {log_blowup} point {i}");
            }
        }
    }

    /// The sum of products is the sum of the products one by one, at
    /// every length: whole eights, and what is left over.
    #[test]
    fn a_dot_product_is_its_products_added_up() {
        let mut rng = crate::test_util::Rng::new(7);
        for n in [0usize, 1, 7, 8, 9, 16, 63, 64, 1000, 1 << 12] {
            let a: Vec<Fp> = (0..n).map(|_| Fp::new(rng.next_u64() as u32 % crate::poseidon2::P)).collect();
            let b: Vec<Fp> = (0..n).map(|_| Fp::new(rng.next_u64() as u32 % crate::poseidon2::P)).collect();
            let one_by_one = a.iter().zip(&b).fold(Fp::ZERO, |acc, (x, y)| acc.add(&x.mul(y)));
            assert_eq!(dot(&a, &b), one_by_one, "{n}");
        }
    }

    #[test]
    fn bit_reversal() {
        let mut v: Vec<u32> = (0..8).collect();
        bit_reverse_permute(&mut v);
        assert_eq!(v, vec![0, 4, 2, 6, 1, 5, 3, 7]);
        let mut v: Vec<u32> = (0..2).collect();
        bit_reverse_permute(&mut v);
        assert_eq!(v, vec![0, 1]);
    }

    #[test]
    fn matches_naive_evaluation() {
        let mut rng = Rng::new(10);
        for log_n in 0..=6 {
            let n = 1 << log_n;
            let coeffs: Vec<Fp> = (0..n).map(|_| rng.fp()).collect();
            let shift = MULTIPLICATIVE_GENERATOR;
            let w = root_of_unity(log_n);
            let mut evals = coeffs.clone();
            coset_ntt(&mut evals, shift);
            for (i, e) in evals.iter().enumerate() {
                let x = shift.mul(&w.pow(i as u64));
                assert_eq!(*e, eval_poly(&coeffs, x), "n={n} i={i}");
            }
            coset_intt(&mut evals, shift);
            assert_eq!(evals, coeffs);

            let mut plain = coeffs.clone();
            ntt(&mut plain);
            for (i, e) in plain.iter().enumerate() {
                assert_eq!(*e, eval_poly(&coeffs, w.pow(i as u64)));
            }
            intt(&mut plain);
            assert_eq!(plain, coeffs);
        }
    }

    #[test]
    fn extension_transform_roundtrip() {
        let mut rng = Rng::new(11);
        let coeffs: Vec<Fp4> = (0..16).map(|_| rng.fp4()).collect();
        let shift = Fp::new(7);
        let w = root_of_unity(4);
        let mut evals = coeffs.clone();
        coset_ntt_ext(&mut evals, shift);
        for (i, e) in evals.iter().enumerate() {
            let x = Fp4::from_base(shift.mul(&w.pow(i as u64)));
            assert_eq!(*e, eval_poly_ext(&coeffs, x));
        }
        coset_intt_ext(&mut evals, shift);
        assert_eq!(evals, coeffs);
    }

    /// Every size and every shift, against the polynomial evaluated a
    /// point at a time: sizes that are not whole eights, shifts that are
    /// roots of unity of the size itself (which once shared a table with
    /// the transform's own), and back again.
    #[test]
    fn every_size_and_shift_matches_naive_evaluation() {
        let mut rng = Rng::new(12);
        for log_n in 0..=9 {
            let n = 1usize << log_n;
            let w = root_of_unity(log_n);
            let coeffs: Vec<Fp> = (0..n).map(|_| rng.fp()).collect();
            for shift in [
                Fp::ONE,
                w,
                w.inverse().unwrap(),
                root_of_unity((log_n + 1).min(TWO_ADICITY)),
                MULTIPLICATIVE_GENERATOR,
                rng.fp(),
            ] {
                // The transform of the size first, as a prover runs it.
                let mut plain = coeffs.clone();
                ntt(&mut plain);
                let mut evals = coeffs.clone();
                coset_ntt(&mut evals, shift);
                for i in (0..n).step_by(1 + n / 16) {
                    assert_eq!(evals[i], eval_poly(&coeffs, shift.mul(&w.pow(i as u64))), "n {n} point {i}");
                }
                assert_eq!(coset_evals(&coeffs, shift), evals);
                coset_intt(&mut evals, shift);
                assert_eq!(evals, coeffs, "n {n}");
            }
        }
    }

    /// The powers of a shift, multiplied in as they are made, are its
    /// powers: at every length, whole eights or not.
    #[test]
    fn scaling_by_powers() {
        let mut rng = Rng::new(13);
        for len in (0..40).chain([64, 100, 1000]) {
            let base = rng.fp();
            let v: Vec<Fp> = (0..len).map(|_| rng.fp()).collect();
            let mut scaled = v.clone();
            scale_by_powers(&mut scaled, base);
            for (i, (x, y)) in v.iter().zip(&scaled).enumerate() {
                assert_eq!(*y, x.mul(&base.pow(i as u64)), "length {len} index {i}");
            }
            let mut by_const = v.clone();
            scale_const(&mut by_const, base);
            assert!(v.iter().zip(&by_const).all(|(x, y)| *y == x.mul(&base)));
        }
    }

    /// The twiddles are shared by every size and made once: a stage's
    /// table is the powers of its root, the same slice each time asked.
    #[test]
    fn twiddles_are_made_once_and_shared() {
        for stage in 1..=10 {
            for inverse in [false, true] {
                let t = stage_twiddles(stage, inverse);
                let root = if inverse { root_of_unity(stage).inverse().unwrap() } else { root_of_unity(stage) };
                assert_eq!(t.len(), 1 << (stage - 1));
                assert!(t.iter().enumerate().all(|(i, w)| *w == root.pow(i as u64)), "stage {stage}");
                assert!(core::ptr::eq(t, stage_twiddles(stage, inverse)));
            }
        }
    }

    #[test]
    fn extensions_into_a_buffer_and_edges() {
        let mut rng = Rng::new(14);
        let coeffs: Vec<Fp> = (0..32).map(|_| rng.fp()).collect();
        let mut out = vec![Fp::ONE; 32 << 2];
        lde_cosets_into(&coeffs, 2, Fp::new(5), &mut out);
        assert_eq!(out, lde_cosets(&coeffs, 2, Fp::new(5)));
        // Its first coset is the coset of its own size.
        assert_eq!(out[..32], coset_evals(&coeffs, Fp::new(5))[..]);
        assert!(lde_cosets(&[], 3, Fp::new(5)).is_empty());
        assert!(std::panic::catch_unwind(|| lde_cosets_into(&[Fp::ONE; 4], 1, Fp::ONE, &mut [Fp::ZERO; 7])).is_err());
        // Nothing and one value are their own transforms.
        let mut none: [Fp; 0] = [];
        let mut one = [Fp::new(9)];
        ntt(&mut none);
        intt(&mut none);
        ntt(&mut one);
        intt(&mut one);
        assert_eq!(one, [Fp::new(9)]);
        // Polynomials at a point.
        assert_eq!(eval_poly(&[], Fp::new(3)), Fp::ZERO);
        assert_eq!(eval_poly(&[Fp::new(1), Fp::new(2), Fp::new(3)], Fp::new(10)), Fp::new(321));
        assert_eq!(eval_poly_ext(&[Fp4::from(1u32), Fp4::from(2u32)], Fp4::from(10u32)), Fp4::from(21u32));
        assert_eq!(inv_two().mul(&Fp::new(2)), Fp::ONE);
        assert_eq!((log2_strict(1), log2_strict(1 << 20)), (0, 20));
        // What has no transform is refused.
        assert!(std::panic::catch_unwind(|| log2_strict(12)).is_err());
        assert!(std::panic::catch_unwind(|| root_of_unity(TWO_ADICITY + 1)).is_err());
        assert!(std::panic::catch_unwind(|| ntt(&mut [Fp::ONE; 6])).is_err());
        assert!(std::panic::catch_unwind(|| coset_intt(&mut [Fp::ONE; 4], Fp::ZERO)).is_err());
        let mut v: Vec<u32> = (0..1).collect();
        bit_reverse_permute(&mut v);
        assert_eq!(v, vec![0]);
    }
}
