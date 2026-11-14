//! The DEEP combination of a table's openings, which prover and verifier
//! form alike, and the transcript's first words.

use crate::challenger::Challenger;
use crate::ext::Fp4;
use crate::field::Field;
use crate::ntt::{MULTIPLICATIVE_GENERATOR, root_of_unity};
use crate::parallel::par_chunks_mut;
use crate::poseidon2::Fp;
use super::proof::*;

/// The coset `shift * H` of the `2^log_n`-th roots of unity, in order.
pub(super) fn coset_points(shift: Fp, log_n: usize) -> Vec<Fp> {
    let omega = root_of_unity(log_n);
    let mut v = Vec::with_capacity(1 << log_n);
    let mut x = shift;
    for _ in 0..1usize << log_n {
        v.push(x);
        x = x.mul(&omega);
    }
    v
}

/// Coset of the evaluation domain of a table whose domain has `2^log_m`
/// points, in a proof whose largest domain has `2^log_big`: the coset the
/// FRI folding of the largest domain reaches at that size.
pub(super) fn table_shift(log_big: usize, log_m: usize) -> Fp {
    MULTIPLICATIVE_GENERATOR.pow(1u64 << (log_big - log_m))
}

/// Out-of-domain openings: trace, aux and preprocessed columns at zeta and
/// g zeta, quotient chunks at zeta_q.
/// DEEP combination with an independent coefficient `r_k` per committed
/// polynomial: `sum_k r_k (col_k(x) - I_k(x)) / ((x - zeta)(x - g zeta))`
/// over the columns, with `I_k` the line through the column's two
/// openings, plus `sum_j r_j (Q_j(x) - Q_j(zeta_q)) / (x - zeta_q)` over the
/// chunks. Each row costs one base-times-extension product per column: the
/// lines fold into two constants, `sum_k r_k I_k(x) = c_a x + c_b`.
/// Coefficient layout: trace columns, aux columns, preprocessed columns,
/// then the chunks; later tables take the coefficients after the tables
/// before them. Independent coefficients make the batching error that of
/// a line (BCIKS20, affine spaces) rather than that of a curve of degree
/// the number of polynomials (powers of one challenge).
pub(super) struct Deep<'a> {
    w: usize,
    aux_w: usize,
    pre_w: usize,
    coeffs: &'a [Fp4],
    c_a: Fp4,
    c_b: Fp4,
    c_q: Fp4,
}

impl<'a> Deep<'a> {
    /// `coeffs` starts at this table's coefficients and holds at least
    /// [`TableProof::deep_len`] of them.
    pub(super) fn new(coeffs: &'a [Fp4], t: &TableProof, zeta: Fp4, zeta_next: Fp4) -> Deep<'a> {
        let [t_z, t_zn, a_z, a_zn, p_z, p_zn, q_zq] = t.opened();
        let (w, aux_w, pre_w) = (t_z.len(), a_z.len(), p_z.len());
        let coeffs = &coeffs[..t.deep_len()];
        let dot = |from: usize, vals: &[Fp4]| -> Fp4 {
            vals.iter().zip(&coeffs[from..]).fold(Fp4::ZERO, |acc, (v, r)| acc + *v * *r)
        };
        let c_z = dot(0, t_z) + dot(w, a_z) + dot(w + aux_w, p_z);
        let c_zn = dot(0, t_zn) + dot(w, a_zn) + dot(w + aux_w, p_zn);
        // The combined line through (zeta, c_z) and (g zeta, c_zn).
        let c_a = (c_zn - c_z) * (zeta_next - zeta).inv().unwrap_or(Fp4::ZERO);
        let c_b = c_z - c_a * zeta;
        Deep { w, aux_w, pre_w, coeffs, c_a, c_b, c_q: dot(w + aux_w + pre_w, q_zq) }
    }

    /// Number of coefficients this table takes.
    pub(super) fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// The combination in coefficient form, which is linear in the
    /// columns: the column sum (to be divided by `(x - zeta)(x - g zeta)`)
    /// and the chunk sum (by `x - zeta_q`), each of `n` coefficients.
    /// Evaluated at a point, less the constants of [`Deep::constants`],
    /// they give [`Deep::value`].
    pub(super) fn polys(&self, trace: &[Vec<Fp>], aux: &[Vec<Fp>], pre: &[Vec<Fp>], quotient: &[Vec<Fp4>]) -> [Vec<Fp4>; 2] {
        const CHUNK: usize = 4096;
        let n = trace[0].len();
        let r = self.coeffs;
        let groups = [(trace, 0), (aux, self.w), (pre, self.w + self.aux_w)];
        let mut cols = vec![Fp4::ZERO; n];
        par_chunks_mut(&mut cols, CHUNK, |c, part| {
            for (group, from) in groups {
                for (k, col) in group.iter().enumerate() {
                    let weight = r[from + k];
                    for (a, x) in part.iter_mut().zip(&col[c * CHUNK..]) {
                        *a += weight.mul_base(x);
                    }
                }
            }
        });
        let q_from = self.w + self.aux_w + self.pre_w;
        let at_q: Vec<Fp4> = (0..n)
            .map(|k| quotient.iter().enumerate().fold(Fp4::ZERO, |acc, (j, c)| acc + r[q_from + j] * c[k]))
            .collect();
        [cols, at_q]
    }

    /// The constants subtracted from [`Deep::polys`] at the point `x`: the
    /// combined line at `x`, and the combined chunk openings.
    pub(super) fn constants(&self, x: Fp) -> [Fp4; 2] {
        [self.c_a.mul_base(&x) + self.c_b, self.c_q]
    }

    /// The combination at `x` from the opened rows, given `1 / ((x -
    /// zeta)(x - g zeta))` and `1 / (x - zeta_q)`.
    pub(super) fn value(&self, rows: Rows<'_>, x: Fp, inv_zzn: Fp4, inv_q: Fp4) -> Fp4 {
        let (trace_row, aux_row, pre_row, quotient_row) = rows;
        let r = self.coeffs;
        let base_dot =
            |row: &[Fp], from: usize| row.iter().zip(&r[from..]).fold(Fp4::ZERO, |acc, (v, b)| acc + b.mul_base(v));
        let s = base_dot(trace_row, 0) + base_dot(aux_row, self.w) + base_dot(pre_row, self.w + self.aux_w);
        let q_from = self.w + self.aux_w + self.pre_w;
        let s_q = quotient_row.iter().zip(&r[q_from..]).fold(Fp4::ZERO, |acc, (v, b)| acc + *v * *b);
        let [line, c_q] = self.constants(x);
        (s - line) * inv_zzn + (s_q - c_q) * inv_q
    }
}

/// The DEEP batching coefficients: `count` independent challenges.
pub(super) fn sample_coefficients(challenger: &mut Challenger, count: usize) -> Vec<Fp4> {
    (0..count).map(|_| challenger.sample_ext()).collect()
}

pub(super) type Rows<'a> = (&'a [Fp], &'a [Fp], &'a [Fp], &'a [Fp4]);

/// Binds the table heights and public values.
pub(super) fn observe_setup(challenger: &mut Challenger, log_ns: &[usize], public: &[Fp]) {
    for log_n in log_ns {
        challenger.observe(Fp::from_u32(*log_n as u32));
    }
    challenger.observe(Fp::from_u32(public.len() as u32));
    challenger.observe_slice(public);
}
