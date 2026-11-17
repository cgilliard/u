//! A field element as its bits: columns for a circuit to range what it
//! reads.
//!
//! Thirty-one bit columns and a flag, held on every row to the one way
//! a field element is written in bits: each a bit, and the whole below
//! the modulus. What value they are of is the enclosing circuit's to
//! say, on the rows where it reads them ([`value`]).
//!
//! What that gives a circuit is a decomposition, not a bound: every
//! field element has one. A circuit that means a value to be small (an
//! age, a count of blocks that must not be negative) must itself
//! require the high bits to be zero on the rows where it reads them; a
//! difference that went below zero is a field element near the modulus,
//! whose high bits are set.

use crate::field::Field;
use crate::poseidon2::Fp;
use crate::stark::Builder;

/// Bits of a field element.
pub const BITS: usize = 31;
/// Columns the gadget uses.
pub const LEN: usize = BITS + 1;

/// Where the gadget's columns sit in the enclosing trace.
#[derive(Clone, Copy, Debug)]
pub struct Cols {
    pub base: usize,
}

impl Cols {
    pub const fn new(base: usize) -> Cols {
        Cols { base }
    }

    /// Bit `i`, the least significant first.
    pub const fn bit(&self, i: usize) -> usize {
        self.base + i
    }

    /// One when the three highest bits are set.
    pub const fn top(&self) -> usize {
        self.base + BITS
    }
}

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

/// The value the bits of `row` are of.
pub fn value<F: Field>(row: &[F], c: &Cols) -> F {
    (0..BITS).fold(F::ZERO, |acc, i| acc + row[c.bit(i)] * pow2::<F>(i))
}

/// Holds the columns to the bits of a field element, on every row. The
/// modulus is `2^31 - 2^27 + 1`: with the four highest bits set, the
/// rest must be zero.
pub fn eval<F: Field>(b: &mut Builder<'_, F>, c: &Cols) {
    b.mark("bits");
    let l = b.local();
    let bits: [F; BITS] = core::array::from_fn(|i| l[c.bit(i)]);
    let mut low27 = F::ZERO;
    for (i, bit) in bits.iter().enumerate() {
        b.assert_zero(*bit * *bit - *bit);
        if i < 27 {
            low27 += *bit * pow2::<F>(i);
        }
    }
    let top = l[c.top()];
    b.assert_eq(top, bits[30] * bits[29] * bits[28]);
    b.assert_zero(top * bits[27] * low27);
}

/// Writes the bits of `value` to `row`.
pub fn write(row: &mut [Fp], c: &Cols, value: u32) {
    for i in 0..BITS {
        row[c.bit(i)] = Fp::new((value >> i) & 1);
    }
    row[c.top()] = Fp::new(((value >> 28) & 7 == 7) as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::P;
    use crate::stark::{Air, Trace, check_constraints, measure_degree};

    struct Only;
    const COLS: Cols = Cols::new(0);

    impl Air for Only {
        fn width(&self) -> usize {
            LEN
        }
        fn max_constraint_degree(&self) -> usize {
            3
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            eval(b, &COLS);
        }
    }

    fn trace(rows: &[u32]) -> Trace {
        let mut values = vec![Fp::ZERO; rows.len() * LEN];
        for (r, v) in rows.iter().enumerate() {
            write(&mut values[r * LEN..(r + 1) * LEN], &COLS, *v);
        }
        Trace { width: LEN, values }
    }

    /// Every way a field element is written holds, the greatest with
    /// the rest; and what is no field element's bits does not: the
    /// modulus, a value above it, a cell that is no bit, a flag that
    /// is not the bits'.
    #[test]
    fn the_bits_are_of_a_field_element() {
        assert_eq!(measure_degree(&Only, 0), 3);
        let good = [0, 1, 5, 1 << 27, (1 << 30) - 1, 0x7000_0000, 0x77ff_ffff, P - 2, P - 1];
        let t = trace(&[good.as_slice(), &[0; 7]].concat());
        assert_eq!(check_constraints(&Only, &t, &[]), Ok(()));
        for (r, v) in good.iter().enumerate() {
            assert_eq!(value(t.row(r), &COLS), Fp::new(*v));
        }
        for bad in [P, P + 1, 0x7fff_ffff, 0x7800_0002] {
            let t = trace(&[bad, 0, 0, 0]);
            assert!(check_constraints(&Only, &t, &[]).is_err(), "{bad:#x}");
        }
        let mut t = trace(&[5, 0, 0, 0]);
        t.values[1] = Fp::new(2);
        assert!(check_constraints(&Only, &t, &[]).is_err());
        let mut t = trace(&[P - 1, 0, 0, 0]);
        t.values[BITS] = Fp::ZERO;
        assert!(check_constraints(&Only, &t, &[]).is_err());
    }
}
