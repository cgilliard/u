//! A minimal field abstraction so AIR constraints can be evaluated both over
//! the base field (by the prover, on the low-degree extension) and over the
//! extension field (by the verifier, at the out-of-domain point).

use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::ext::Fp4;
use crate::poseidon2::Fp;

pub trait Field:
    Copy
    + PartialEq
    + Eq
    + Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + From<Fp>
    + 'static
{
    const ZERO: Self;
    const ONE: Self;

    fn from_u32(v: u32) -> Self {
        Fp::from_u32(v).into()
    }

    /// Multiplication by a base field element.
    fn scale(self, b: Fp) -> Self;

    /// `e * self`, with the result in the extension field.
    fn mul_ext(self, e: Fp4) -> Fp4;

    fn inv(self) -> Option<Self>;

    fn exp(self, e: u64) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        let mut e = e;
        while e != 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base *= base;
            e >>= 1;
        }
        acc
    }
}

impl Field for Fp {
    const ZERO: Fp = Fp::ZERO;
    const ONE: Fp = Fp::ONE;

    fn scale(self, b: Fp) -> Fp {
        Fp::mul(&self, &b)
    }

    fn mul_ext(self, e: Fp4) -> Fp4 {
        e.mul_base(&self)
    }

    fn inv(self) -> Option<Fp> {
        Fp::inverse(&self)
    }
}

impl Field for Fp4 {
    const ZERO: Fp4 = Fp4::ZERO;
    const ONE: Fp4 = Fp4::ONE;

    fn scale(self, b: Fp) -> Fp4 {
        Fp4::mul_base(&self, &b)
    }

    fn mul_ext(self, e: Fp4) -> Fp4 {
        Fp4::mul(&e, &self)
    }

    fn inv(self) -> Option<Fp4> {
        Fp4::inverse(&self)
    }
}

/// Polynomial-degree tracker: a pseudo-field whose "values" are degrees.
/// Addition takes the maximum, multiplication adds, constants are degree
/// zero. Evaluating an AIR over it bounds the degree of every constraint.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Deg(pub u32);

macro_rules! deg_ops {
    ($tr:ident, $m:ident, $tra:ident, $ma:ident, $f:expr) => {
        impl core::ops::$tr for Deg {
            type Output = Deg;
            fn $m(self, rhs: Deg) -> Deg {
                Deg($f(self.0, rhs.0))
            }
        }
        impl core::ops::$tra for Deg {
            fn $ma(&mut self, rhs: Deg) {
                self.0 = $f(self.0, rhs.0);
            }
        }
    };
}
deg_ops!(Add, add, AddAssign, add_assign, u32::max);
deg_ops!(Sub, sub, SubAssign, sub_assign, u32::max);
deg_ops!(Mul, mul, MulAssign, mul_assign, |a, b| a + b);

impl core::ops::Neg for Deg {
    type Output = Deg;
    fn neg(self) -> Deg {
        self
    }
}

impl From<Fp> for Deg {
    fn from(_: Fp) -> Deg {
        Deg(0)
    }
}

impl Field for Deg {
    const ZERO: Deg = Deg(0);
    const ONE: Deg = Deg(0);

    fn scale(self, _: Fp) -> Deg {
        self
    }

    fn mul_ext(self, e: Fp4) -> Fp4 {
        e
    }

    fn inv(self) -> Option<Deg> {
        Some(self)
    }
}

/// Inverts every element of `v` into `out` with Montgomery's trick (three
/// multiplications per element plus one inversion). All elements must be
/// non-zero. `out` is the only memory used: it holds the running products
/// on the way up and the inverses on the way back.
pub fn batch_inverse_into<F: Field>(v: &[F], out: &mut [F]) {
    assert_eq!(v.len(), out.len(), "an inverse for each element");
    let mut acc = F::ONE;
    for (o, x) in out.iter_mut().zip(v) {
        *o = acc;
        acc *= *x;
    }
    let mut inv = acc.inv().expect("batch_inverse: zero element");
    for (o, x) in out.iter_mut().zip(v).rev() {
        *o = inv * *o;
        inv *= *x;
    }
}

/// [`batch_inverse_into`] a new buffer.
pub fn batch_inverse<F: Field>(v: &[F]) -> Vec<F> {
    let mut out = vec![F::ZERO; v.len()];
    batch_inverse_into(v, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    #[test]
    fn batch_inverse_matches_individual() {
        let mut rng = Rng::new(40);
        let xs: Vec<Fp> = (0..17).map(|_| rng.fp()).collect();
        for (x, inv) in xs.iter().zip(batch_inverse(&xs)) {
            assert_eq!(*x * inv, Fp::ONE);
        }
        let ys: Vec<Fp4> = (0..9).map(|_| rng.fp4()).collect();
        for (y, inv) in ys.iter().zip(batch_inverse(&ys)) {
            assert_eq!(*y * inv, Fp4::ONE);
        }
        assert!(batch_inverse::<Fp>(&[]).is_empty());
        // Into a buffer the caller holds: the same inverses.
        let mut buf = [Fp4::ZERO; 9];
        batch_inverse_into(&ys, &mut buf);
        assert_eq!(buf.to_vec(), batch_inverse(&ys));
        let one = [Fp::new(7)];
        assert_eq!(batch_inverse(&one), vec![Fp::new(7).inverse().unwrap()]);
        // A zero among them has no inverse; a buffer of another length is no answer.
        assert!(std::panic::catch_unwind(|| batch_inverse(&[Fp::ONE, Fp::ZERO])).is_err());
        assert!(std::panic::catch_unwind(|| batch_inverse_into(&[Fp::ONE; 2], &mut [Fp::ZERO; 3])).is_err());
    }

    /// The base field and the extension agree where they meet: a base
    /// element scaled, multiplied into the extension, inverted and raised
    /// to a power is what its extension element gives.
    #[test]
    fn base_and_extension_agree() {
        let mut rng = Rng::new(41);
        for _ in 0..50 {
            let (a, b, e) = (rng.fp(), rng.fp(), rng.fp4());
            let wide = Fp4::from_base(a);
            assert_eq!(Fp4::from_base(a.scale(b)), wide.scale(b));
            assert_eq!(a.mul_ext(e), wide.mul_ext(e));
            assert_eq!(a.mul_ext(e), e.scale(a));
            assert_eq!(a.inv().map(Fp4::from_base), wide.inv());
            assert_eq!(Fp4::from_base(a.exp(77)), wide.exp(77));
            assert_eq!((a.exp(0), e.exp(0), e.exp(1)), (Fp::ONE, Fp4::ONE, e));
            assert_eq!(e.inv().map(|i| i * e), Some(Fp4::ONE));
        }
        assert_eq!((<Fp as Field>::ZERO.inv(), <Fp4 as Field>::ZERO.inv()), (None, None));
        assert_eq!((<Fp as Field>::from_u32(5), <Fp4 as Field>::from_u32(5)), (Fp::new(5), Fp4::from_base(Fp::new(5))));
    }

    /// Degrees: a sum is as high as its highest term, a product as the
    /// sum of its factors', and constants and scaling add nothing.
    #[test]
    fn degrees_add_under_products() {
        let (x, y) = (Deg(2), Deg(3));
        assert_eq!((x + y, x - y, x * y, -x), (Deg(3), Deg(3), Deg(5), Deg(2)));
        let mut z = x;
        z += y;
        assert_eq!(z, Deg(3));
        z *= x;
        assert_eq!(z, Deg(5));
        z -= Deg(9);
        assert_eq!(z, Deg(9));
        assert_eq!((Deg::from(Fp::new(7)), <Deg as Field>::ZERO, <Deg as Field>::ONE, Deg::default()), (Deg(0), Deg(0), Deg(0), Deg(0)));
        assert_eq!((x.scale(Fp::new(9)), x.inv(), x.exp(3), <Deg as Field>::from_u32(4)), (Deg(2), Some(Deg(2)), Deg(6), Deg(0)));
        let e = Fp4::from_u32(3);
        assert_eq!(x.mul_ext(e), e);
        // A constraint of the shape a * b * c - d: degree 3 in degree-1 columns.
        let col = Deg(1);
        assert_eq!(col * col * col - col, Deg(3));
        assert_eq!(Fp::from_u32(3).exp(4), Fp::new(81));
        assert_eq!(Fp4::from_u32(2).exp(10), Fp4::from_u32(1024));
    }
}
