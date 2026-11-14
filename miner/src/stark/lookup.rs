//! The LogUp lookup argument's challenges, and the combination of an AIR's
//! constraints with the lookup's under powers of one challenge: the same
//! code for the prover, on the evaluation domain, and for the verifier, at
//! the out-of-domain point.

use super::air::LookupTerm;
use super::config::BLIND_TAG;
use crate::challenger::Challenger;
use crate::ext::{DEGREE, Fp4};
use crate::field::Field;

/// Lookup challenges, with the powers of `delta` that denominators use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupChallenges {
    pub gamma: Fp4,
    pub delta: Fp4,
    /// `delta^1 .. delta^DELTA_POWERS`.
    delta_powers: Vec<Fp4>,
    /// `delta^BLIND_TAG`.
    delta_blind: Fp4,
}

pub(super) const DELTA_POWERS: usize = 32;

impl LookupChallenges {
    pub fn new(gamma: Fp4, delta: Fp4) -> LookupChallenges {
        let delta_powers = powers(delta, DELTA_POWERS + 1)[1..].to_vec();
        LookupChallenges { gamma, delta, delta_powers, delta_blind: delta.exp(BLIND_TAG as u64) }
    }

    pub(super) fn sample(ch: &mut Challenger) -> LookupChallenges {
        let gamma = ch.sample_ext();
        let delta = ch.sample_ext();
        LookupChallenges::new(gamma, delta)
    }

    /// Denominator of the blinding message `u`, `gamma + sum delta^(k+1)
    /// u[k] + delta^BLIND_TAG`.
    pub(super) fn blind_denominator<F: Field>(&self, u: &[F]) -> Fp4 {
        self.denominator(u) + self.delta_blind
    }

    /// `gamma + sum delta^(k+1) values[k]`.
    pub(super) fn denominator<F: Field>(&self, values: &[F]) -> Fp4 {
        let mut acc = self.gamma;
        for (v, pow) in values.iter().zip(&self.delta_powers) {
            acc += v.mul_ext(*pow);
        }
        if values.len() > DELTA_POWERS {
            let mut pow = self.delta_powers[DELTA_POWERS - 1];
            for v in &values[DELTA_POWERS..] {
                pow *= self.delta;
                acc += v.mul_ext(pow);
            }
        }
        acc
    }
}

/// Lookup settings of a table for [`combine`]: challenges, the table's
/// lookup total and the group size.
#[derive(Clone, Copy)]
pub(super) struct LookupArgs<'a> {
    pub(super) ch: &'a LookupChallenges,
    pub(super) total: Fp4,
    pub(super) group: usize,
}

/// Combines main constraints and lookup constraints with powers of alpha.
/// The lookup constraints, in order: one per group of terms
/// (`h * prod d_i - sum m_i prod_(j != i) d_j`), the running-sum transition,
/// the running sum starting at zero, and the last row reaching the table's
/// lookup `total`. `aux_local`/`aux_next` are the extension values: the
/// group sums then the running sum.
///
/// In a zero-knowledge proof `blind` holds the row's blinding messages `u`
/// and `v`, the auxiliary values continue with `h_u` and `h_v`, and the
/// running sum starts at `h_u - h_v` instead of zero, with two more
/// constraints on the first row: `h_u d(u) = 1` and `h_v d(v) = 1`. The
/// total then also counts the message `u` sent and `v` received.
#[allow(clippy::too_many_arguments)]
pub(super) fn combine<F: Field>(
    constraints: &[F],
    terms: &[LookupTerm<F>],
    aux_local: &[Fp4],
    aux_next: &[Fp4],
    sel: (Fp4, Fp4, Fp4),
    lookup: Option<LookupArgs<'_>>,
    blind: Option<&[F]>,
    alpha_powers: &[Fp4],
) -> Fp4 {
    let mut acc = Fp4::ZERO;
    for (c, a) in constraints.iter().zip(alpha_powers) {
        acc += c.mul_ext(*a);
    }
    if let Some(LookupArgs { ch, total, group }) = lookup {
        let a = &alpha_powers[constraints.len()..];
        let groups = terms.len().div_ceil(group);
        let mut contrib = Fp4::ZERO;
        for (j, members) in terms.chunks(group).enumerate() {
            // Running numerator and denominator of the group's fractions.
            let (mut num, mut den) = (Fp4::ZERO, Fp4::ONE);
            for term in members {
                let d = ch.denominator(&term.values);
                let m = term.multiplicity.mul_ext(Fp4::ONE);
                num = num * d + if term.send { m * den } else { -(m * den) };
                den *= d;
            }
            let h = aux_local[j];
            acc += (h * den - num) * a[j];
            contrib += h;
        }
        let s = aux_local[groups];
        let s_next = aux_next[groups];
        acc += sel.2 * (s_next - s - contrib) * a[groups];
        acc += sel.1 * (s + contrib - total) * a[groups + 2];
        match blind {
            None => acc += sel.0 * s * a[groups + 1],
            Some(uv) => {
                let (h_u, h_v) = (aux_local[groups + 1], aux_local[groups + 2]);
                acc += sel.0 * (s - h_u + h_v) * a[groups + 1];
                acc += sel.0 * (h_u * ch.blind_denominator(&uv[..DEGREE]) - Fp4::ONE) * a[groups + 3];
                acc += sel.0 * (h_v * ch.blind_denominator(&uv[DEGREE..]) - Fp4::ONE) * a[groups + 4];
            }
        }
    }
    acc
}

pub(crate) fn powers(base: Fp4, count: usize) -> Vec<Fp4> {
    let mut out = Vec::with_capacity(count);
    let mut acc = Fp4::ONE;
    for _ in 0..count {
        out.push(acc);
        acc *= base;
    }
    out
}

/// Horner evaluation of extension coefficients at an extension point.
pub(super) fn eval_ext_poly_at(coeffs: &[Fp4], x: Fp4) -> Fp4 {
    coeffs.iter().rev().fold(Fp4::ZERO, |acc, c| acc * x + *c)
}

/// Reconstructs extension column values from their four base-column
/// openings: `c0 + c1 X + c2 X^2 + c3 X^3`.
pub(super) fn ext_from_base_openings(opened: &[Fp4]) -> Vec<Fp4> {
    opened
        .chunks_exact(DEGREE)
        .map(|c| {
            let mut acc = c[DEGREE - 1];
            for k in (0..DEGREE - 1).rev() {
                acc = acc * Fp4::X + c[k];
            }
            acc
        })
        .collect()
}
