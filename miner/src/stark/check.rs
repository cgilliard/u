//! A trace checked against its AIR directly, row by row: a debugging aid
//! for AIR authors, which names the constraint that fails.

use super::air::{Air, Builder, DynAir, Trace};
use super::lookup::LookupChallenges;
use crate::ext::Fp4;
use crate::field::Field;
use crate::poseidon2::Fp;

/// Evaluates every constraint on every row pair of `trace` with the
/// selectors as plain 0/1 flags and reports the first violation as
/// `(row, constraint index, section label)`, the label being the last
/// [`Builder::mark`] before the constraint. Also checks that the lookup
/// terms cancel, reporting `(usize::MAX, 0, "lookup sum")` if they do not.
/// A debugging aid for AIR authors; the prover does not need it.
pub fn check_constraints<A: Air>(air: &A, trace: &Trace, public: &[Fp]) -> Result<(), (usize, usize, &'static str)> {
    check_constraints_with(air, trace, None, public)
}

/// [`check_constraints`] with a preprocessed table of the trace's height.
pub fn check_constraints_with<A: Air>(
    air: &A,
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
) -> Result<(), (usize, usize, &'static str)> {
    check_tables(&[(air, trace, pre)], public).map_err(|(_, e)| e)
}

/// [`check_constraints`] over several tables whose lookup terms must cancel
/// together. Errors carry the index of the offending table.
#[allow(clippy::type_complexity)]
pub fn check_tables(
    tables: &[(&dyn DynAir, &Trace, Option<&Trace>)],
    public: &[Fp],
) -> Result<(), (usize, (usize, usize, &'static str))> {
    let ch = LookupChallenges::new(Fp4::from_u32(0x1234_5678), Fp4([Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11)]));
    let mut sum = Fp4::ZERO;
    for (t, (air, trace, pre)) in tables.iter().enumerate() {
        let n = trace.height();
        let empty: Vec<Fp> = Vec::new();
        let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.row(i)) };
        for i in 0..n {
            let next = (i + 1) % n;
            let sel = (
                if i == 0 { Fp::ONE } else { Fp::ZERO },
                if i == n - 1 { Fp::ONE } else { Fp::ZERO },
                if i == n - 1 { Fp::ZERO } else { Fp::ONE },
            );
            let mut b = Builder::new(trace.row(i), trace.row(next), (pre_row(i), pre_row(next)), public, sel);
            air.eval_fp(&mut b);
            if let Some(k) = b.out.constraints.iter().position(|c| *c != Fp::ZERO) {
                let label = b.out.marks.iter().rev().find(|(at, _)| *at <= k).map(|(_, l)| *l).unwrap_or("");
                return Err((t, (i, k, label)));
            }
            for term in b.out.terms() {
                let d = ch.denominator(&term.values);
                let Some(inv) = d.inverse() else {
                    return Err((t, (i, 0, "lookup denominator zero")));
                };
                let c = term.multiplicity.mul_ext(inv);
                if term.send { sum += c } else { sum -= c }
            }
        }
    }
    if sum != Fp4::ZERO {
        return Err((tables.len() - 1, (usize::MAX, 0, "lookup sum")));
    }
    Ok(())
}
