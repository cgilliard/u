//! A field whose values are addresses of words in a machine's memory, and
//! whose operations are whatever a backend makes of them.
//!
//! An AIR's constraints are written once, over any [`Field`]. Evaluated
//! over [`Expr`] they are not computed but compiled: each operation is
//! handed to the backend installed for the time being ([`with_backend`]),
//! which emits an instruction and answers with the address of its result.
//! That is how a verifier of any AIR is turned into a program for the
//! recursion machine, without circuits written by hand.
//!
//! The type lives here, below both the proof system (whose AIRs must be
//! evaluable over it) and the compiler that is its backend, so that
//! neither has to know the other.
//!
//! A backend's memory begins with zero at address 0 and one at address 1:
//! the field's constants are those addresses.

use std::any::Any;
use std::cell::RefCell;

use crate::ext::Fp4;
use crate::field::Field;
use crate::poseidon2::Fp;

/// Address of a memory word.
pub type Addr = u32;

/// Address of a memory word, usable as a field inside an AIR's `eval`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Expr(pub Addr);

/// The address of zero in every backend's memory.
pub const A_ZERO: Addr = 0;
/// The address of one in every backend's memory.
pub const A_ONE: Addr = 1;

/// What gives [`Expr`]'s operations their meaning: each takes addresses
/// and answers with the address of the result.
pub trait Backend: Any {
    fn add(&mut self, a: Addr, b: Addr) -> Addr;
    fn sub(&mut self, a: Addr, b: Addr) -> Addr;
    fn mul(&mut self, a: Addr, b: Addr) -> Addr;
    fn neg(&mut self, a: Addr) -> Addr;
    /// The address of a word that holds `v`.
    fn constant(&mut self, v: Fp4) -> Addr;
    /// The address of the inverse of the word at `a`.
    fn inverse(&mut self, a: Addr) -> Addr;
}

thread_local! {
    static BACKEND: RefCell<Option<Box<dyn Backend>>> = const { RefCell::new(None) };
}

/// Runs `f` with `backend` giving this thread's [`Expr`] operations their
/// meaning, and gives the backend back with what `f` returns. One backend
/// at a time: a second inside the first panics. If `f` panics the backend
/// is dropped.
pub fn with_backend<B: Backend, R>(backend: B, f: impl FnOnce() -> R) -> (B, R) {
    /// Leaves the slot empty however `f` ends.
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            BACKEND.with(|slot| drop(slot.borrow_mut().take()));
        }
    }
    BACKEND.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none(), "an Expr backend is already installed");
        *slot = Some(Box::new(backend));
    });
    let clear = Clear;
    let out = f();
    core::mem::forget(clear);
    let boxed: Box<dyn Any> = BACKEND.with(|slot| slot.borrow_mut().take()).expect("the backend installed above");
    (*boxed.downcast::<B>().expect("the backend installed above"), out)
}

fn with<R>(f: impl FnOnce(&mut dyn Backend) -> R) -> R {
    BACKEND.with(|slot| f(slot.borrow_mut().as_deref_mut().expect("Expr used outside of a compilation context")))
}

macro_rules! expr_binop {
    ($tr:ident, $m:ident, $tra:ident, $ma:ident) => {
        impl core::ops::$tr for Expr {
            type Output = Expr;
            fn $m(self, rhs: Expr) -> Expr {
                Expr(with(|b| b.$m(self.0, rhs.0)))
            }
        }
        impl core::ops::$tra for Expr {
            fn $ma(&mut self, rhs: Expr) {
                *self = core::ops::$tr::$m(*self, rhs);
            }
        }
    };
}
expr_binop!(Add, add, AddAssign, add_assign);
expr_binop!(Sub, sub, SubAssign, sub_assign);
expr_binop!(Mul, mul, MulAssign, mul_assign);

impl core::ops::Neg for Expr {
    type Output = Expr;
    fn neg(self) -> Expr {
        Expr(with(|b| b.neg(self.0)))
    }
}

impl From<Fp> for Expr {
    fn from(x: Fp) -> Expr {
        Expr(with(|b| b.constant(Fp4::from_base(x))))
    }
}

impl Field for Expr {
    const ZERO: Expr = Expr(A_ZERO);
    const ONE: Expr = Expr(A_ONE);

    fn scale(self, k: Fp) -> Expr {
        Expr(with(|b| {
            let k = b.constant(Fp4::from_base(k));
            b.mul(self.0, k)
        }))
    }

    fn mul_ext(self, _: Fp4) -> Fp4 {
        unreachable!("mul_ext is not used inside AIR evaluation")
    }

    fn inv(self) -> Option<Expr> {
        Some(Expr(with(|b| b.inverse(self.0))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    /// A backend that computes: a memory of words, an operation appending
    /// its result, and a count of what it was asked.
    struct Memory {
        words: Vec<Fp4>,
        ops: usize,
    }

    impl Memory {
        fn new(inputs: &[Fp4]) -> Memory {
            Memory { words: [&[Fp4::ZERO, Fp4::ONE][..], inputs].concat(), ops: 0 }
        }

        fn push(&mut self, v: Fp4) -> Addr {
            self.words.push(v);
            self.ops += 1;
            self.words.len() as Addr - 1
        }
    }

    impl Backend for Memory {
        fn add(&mut self, a: Addr, b: Addr) -> Addr {
            self.push(self.words[a as usize] + self.words[b as usize])
        }
        fn sub(&mut self, a: Addr, b: Addr) -> Addr {
            self.push(self.words[a as usize] - self.words[b as usize])
        }
        fn mul(&mut self, a: Addr, b: Addr) -> Addr {
            self.push(self.words[a as usize] * self.words[b as usize])
        }
        fn neg(&mut self, a: Addr) -> Addr {
            self.push(-self.words[a as usize])
        }
        fn constant(&mut self, v: Fp4) -> Addr {
            self.push(v)
        }
        fn inverse(&mut self, a: Addr) -> Addr {
            self.push(self.words[a as usize].inverse().unwrap())
        }
    }

    /// One expression, written once over any field.
    fn formula<F: Field>(x: F, y: F) -> F {
        let mut acc = (x * y + F::ONE - y) * x;
        acc += F::from(Fp::new(7));
        acc -= x.scale(Fp::new(3));
        acc *= -y;
        acc * x.inv().unwrap() + F::ZERO + x.exp(5)
    }

    /// Over `Expr` the formula is carried out by the backend, word by
    /// word, and its result is the word the formula computes directly.
    #[test]
    fn a_formula_over_expr_is_what_the_backend_makes_of_it() {
        let mut rng = Rng::new(50);
        for _ in 0..20 {
            let (x, y) = (rng.fp4(), rng.fp4());
            let (memory, out) = with_backend(Memory::new(&[x, y]), || formula(Expr(2), Expr(3)));
            assert_eq!(memory.words[out.0 as usize], formula(x, y));
            assert!(memory.ops > 10);
            assert_eq!((memory.words[A_ZERO as usize], memory.words[A_ONE as usize]), (Fp4::ZERO, Fp4::ONE));
        }
        // The backend comes back as it was given, with what it did.
        let (memory, ()) = with_backend(Memory::new(&[]), || ());
        assert_eq!((memory.words.len(), memory.ops), (2, 0));
    }

    #[test]
    fn expr_has_no_meaning_without_a_backend() {
        assert!(std::panic::catch_unwind(|| Expr(0) + Expr(1)).is_err());
        assert!(std::panic::catch_unwind(|| Expr::from(Fp::ONE)).is_err());
        // One at a time; and a panic inside leaves none installed.
        let nested =
            std::panic::catch_unwind(|| with_backend(Memory::new(&[]), || with_backend(Memory::new(&[]), || ())));
        assert!(nested.is_err());
        assert!(std::panic::catch_unwind(|| Expr(0) * Expr(1)).is_err());
        let (_, sum) = with_backend(Memory::new(&[]), || Expr(1) + Expr(1));
        assert_eq!(sum, Expr(2));
        assert!(std::panic::catch_unwind(|| with_backend(Memory::new(&[]), || Expr(1).mul_ext(Fp4::ONE))).is_err());
    }
}
