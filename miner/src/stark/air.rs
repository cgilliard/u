//! What a statement is written as: an AIR, its constraints over consecutive
//! rows of a trace, and the builder they are collected in.

use crate::expr::Expr;
use crate::ext::Fp4;
use crate::field::{Deg, Field};
use crate::poseidon2::Fp;

/// One lookup term: `multiplicity / (gamma + sum delta^(k+1) values[k])`,
/// added for sends and subtracted for receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupTerm<F> {
    pub send: bool,
    pub multiplicity: F,
    pub values: Vec<F>,
}

/// Output buffers of a [`Builder`], kept between rows so that evaluating
/// an AIR on many rows does not allocate per row.
pub(crate) struct Scratch<F> {
    pub(super) constraints: Vec<F>,
    /// Lookup terms; only the first `num_lookups` are current, the rest
    /// keep their value buffers for reuse.
    lookups: Vec<LookupTerm<F>>,
    num_lookups: usize,
    pub(super) marks: Vec<(usize, &'static str)>,
}

impl<F> Default for Scratch<F> {
    fn default() -> Self {
        Scratch { constraints: Vec::new(), lookups: Vec::new(), num_lookups: 0, marks: Vec::new() }
    }
}

impl<F> Scratch<F> {
    pub(crate) fn constraints(&self) -> &[F] {
        &self.constraints
    }

    pub(crate) fn terms(&self) -> &[LookupTerm<F>] {
        &self.lookups[..self.num_lookups]
    }
}

/// Collects constraint evaluations and lookup terms for one row pair.
pub struct Builder<'a, F: Field> {
    local: &'a [F],
    next: &'a [F],
    pre_local: &'a [F],
    pre_next: &'a [F],
    public: &'a [F],
    is_first_row: F,
    is_last_row: F,
    is_transition: F,
    pub(super) out: Scratch<F>,
}

impl<'a, F: Field> Builder<'a, F> {
    pub(crate) fn new(local: &'a [F], next: &'a [F], pre: (&'a [F], &'a [F]), public: &'a [F], sel: (F, F, F)) -> Self {
        Self::with_scratch(local, next, pre, public, sel, Scratch::default())
    }

    /// A builder writing into reused buffers, which it clears.
    fn with_scratch(
        local: &'a [F],
        next: &'a [F],
        pre: (&'a [F], &'a [F]),
        public: &'a [F],
        sel: (F, F, F),
        mut out: Scratch<F>,
    ) -> Self {
        out.constraints.clear();
        out.num_lookups = 0;
        out.marks.clear();
        Builder {
            local,
            next,
            pre_local: pre.0,
            pre_next: pre.1,
            public,
            is_first_row: sel.0,
            is_last_row: sel.1,
            is_transition: sel.2,
            out,
        }
    }

    /// Labels the constraints emitted from here on, for diagnostics from
    /// [`check_constraints`]. Has no effect on proving.
    pub fn mark(&mut self, label: &'static str) {
        self.out.marks.push((self.out.constraints.len(), label));
    }

    pub fn local(&self) -> &'a [F] {
        self.local
    }

    pub fn next(&self) -> &'a [F] {
        self.next
    }

    /// Preprocessed columns of this row (see [`Air::preprocessed_width`]).
    pub fn preprocessed(&self) -> &'a [F] {
        self.pre_local
    }

    /// Preprocessed columns of the next row.
    pub fn preprocessed_next(&self) -> &'a [F] {
        self.pre_next
    }

    /// Public values, embedded in the evaluation field.
    pub fn public(&self) -> &'a [F] {
        self.public
    }

    /// Constraints and lookup terms collected so far (for compilers).
    pub(crate) fn into_parts(self) -> (Vec<F>, Vec<LookupTerm<F>>) {
        let mut out = self.out;
        out.lookups.truncate(out.num_lookups);
        (out.constraints, out.lookups)
    }

    /// Requires `c == 0` on every row.
    pub fn assert_zero(&mut self, c: F) {
        self.out.constraints.push(c);
    }

    pub fn assert_eq(&mut self, a: F, b: F) {
        self.assert_zero(a - b);
    }

    /// Requires `c == 0` on the first row only (adds one to the degree).
    pub fn when_first_row(&mut self, c: F) {
        let s = self.is_first_row;
        self.assert_zero(s * c);
    }

    /// Requires `c == 0` on the last row only (adds one to the degree).
    pub fn when_last_row(&mut self, c: F) {
        let s = self.is_last_row;
        self.assert_zero(s * c);
    }

    /// Requires `c == 0` on every row but the last, where `next` wraps
    /// around. The selector is `x - g^-1`, degree one in `x`, so unlike the
    /// row selectors it does not add to the constraint degree count.
    pub fn when_transition(&mut self, c: F) {
        let s = self.is_transition;
        self.assert_zero(s * c);
    }

    /// Declares a lookup term. `send` adds `multiplicity / denom` to the
    /// running sum, a receive subtracts it. Values and multiplicity must be
    /// built from columns and constants only.
    pub fn lookup(&mut self, send: bool, multiplicity: F, values: &[F]) {
        let out = &mut self.out;
        if out.num_lookups < out.lookups.len() {
            let term = &mut out.lookups[out.num_lookups];
            term.send = send;
            term.multiplicity = multiplicity;
            term.values.clear();
            term.values.extend_from_slice(values);
        } else {
            out.lookups.push(LookupTerm { send, multiplicity, values: values.to_vec() });
        }
        out.num_lookups += 1;
    }
}

/// A rule of the statement the witness generator checks before writing
/// the trace: it refuses (panics) on a witness that breaks it. In tests a
/// lenient generator ([`LENIENT`]) writes the trace anyway, as a cheating
/// prover's would, so that the attack tests can show the constraints
/// themselves reject it. Whether it is lenient now.
#[allow(dead_code)] // the circuits' witness generators call it
pub(crate) fn lenient() -> bool {
    #[cfg(test)]
    if LENIENT.with(|l| l.get()) {
        return true;
    }
    false
}

/// See [`lenient`]: asserts `holds` unless the generator is lenient.
#[allow(dead_code)] // the circuits' witness generators call it
pub(crate) fn refuse(holds: bool, rule: &str) {
    #[cfg(test)]
    if LENIENT.with(|l| l.get()) {
        return;
    }
    assert!(holds, "{rule}");
}

#[cfg(test)]
thread_local! {
    /// Tests: the witness generator writes a trace whatever rule it breaks.
    pub(crate) static LENIENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// An algebraic intermediate representation: constraints over consecutive
/// trace rows. `eval` must be the same polynomial map for both field types.
pub trait Air: Sync {
    /// Number of trace columns.
    fn width(&self) -> usize;

    /// Maximum total degree of any constraint, counting each column as one
    /// and each of `when_first_row` / `when_last_row` as one;
    /// `when_transition` is free. Lookup terms add one to the degree of
    /// their multiplicity and values (two for the multiplicity). Must be at
    /// least one.
    fn max_constraint_degree(&self) -> usize;

    /// Number of preprocessed columns: a fixed table, committed once and
    /// known to the verifier by its root, that constraints may read through
    /// [`Builder::preprocessed`]. Zero by default.
    fn preprocessed_width(&self) -> usize {
        0
    }

    /// Lookup terms summed per auxiliary column, in declaration order. A
    /// group's constraint has degree one plus the degrees of its
    /// denominators, which must fit [`Air::max_constraint_degree`].
    fn lookup_group(&self) -> usize {
        1
    }

    fn eval<F: Field>(&self, builder: &mut Builder<'_, F>);
}

/// An [`Air`] behind a trait object, so that the tables of one proof can
/// have different AIR types. Implemented for every `Air`.
pub trait DynAir: Sync {
    fn air_width(&self) -> usize;
    fn air_degree(&self) -> usize;
    fn air_preprocessed_width(&self) -> usize;
    fn air_lookup_group(&self) -> usize;
    fn eval_fp(&self, b: &mut Builder<'_, Fp>);
    fn eval_fp4(&self, b: &mut Builder<'_, Fp4>);
    fn eval_deg(&self, b: &mut Builder<'_, Deg>);
    fn eval_expr(&self, b: &mut Builder<'_, Expr>);
}

impl<A: Air> DynAir for A {
    fn air_width(&self) -> usize {
        self.width()
    }
    fn air_degree(&self) -> usize {
        self.max_constraint_degree()
    }
    fn air_preprocessed_width(&self) -> usize {
        self.preprocessed_width()
    }
    fn air_lookup_group(&self) -> usize {
        self.lookup_group().max(1)
    }
    fn eval_fp(&self, b: &mut Builder<'_, Fp>) {
        self.eval(b)
    }
    fn eval_fp4(&self, b: &mut Builder<'_, Fp4>) {
        self.eval(b)
    }
    fn eval_deg(&self, b: &mut Builder<'_, Deg>) {
        self.eval(b)
    }
    fn eval_expr(&self, b: &mut Builder<'_, Expr>) {
        self.eval(b)
    }
}

/// Fields a [`DynAir`] can be evaluated over.
pub trait EvalField: Field {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Self>);
}

impl EvalField for Fp {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Fp>) {
        air.eval_fp(b)
    }
}

impl EvalField for Fp4 {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Fp4>) {
        air.eval_fp4(b)
    }
}

impl EvalField for Deg {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Deg>) {
        air.eval_deg(b)
    }
}

impl EvalField for Expr {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Expr>) {
        air.eval_expr(b)
    }
}

/// Row-major trace matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub values: Vec<Fp>,
    pub width: usize,
}

impl Trace {
    pub fn new(values: Vec<Fp>, width: usize) -> Trace {
        assert!(width > 0 && values.len().is_multiple_of(width));
        let t = Trace { values, width };
        assert!(t.height().is_power_of_two() && t.height() >= 2, "trace height must be a power of two >= 2");
        t
    }

    pub fn height(&self) -> usize {
        self.values.len() / self.width
    }

    pub fn row(&self, i: usize) -> &[Fp] {
        &self.values[i * self.width..(i + 1) * self.width]
    }

    pub fn column(&self, k: usize) -> Vec<Fp> {
        (0..self.height()).map(|i| self.values[i * self.width + k]).collect()
    }
}

/// The sum over an AIR's lookup terms of the tuple length plus one.
pub(crate) fn lookup_weight(air: &dyn DynAir, public: &[Fp]) -> usize {
    let zeros = vec![Fp::ZERO; air.air_width()];
    let pre = vec![Fp::ZERO; air.air_preprocessed_width()];
    let (_, terms) = evaluate(air, &zeros, &zeros, (&pre, &pre), public, (Fp::ZERO, Fp::ZERO, Fp::ZERO));
    terms.iter().map(|t| t.values.len() + 1).sum()
}

/// Evaluates the AIR at one row pair.
pub(crate) fn evaluate<F: EvalField>(
    air: &dyn DynAir,
    local: &[F],
    next: &[F],
    pre: (&[F], &[F]),
    public: &[F],
    sel: (F, F, F),
) -> (Vec<F>, Vec<LookupTerm<F>>) {
    let mut b = Builder::new(local, next, pre, public, sel);
    F::eval_air(air, &mut b);
    b.into_parts()
}

/// Evaluates the AIR at one row pair into reused buffers.
pub(crate) fn evaluate_into<F: EvalField>(
    air: &dyn DynAir,
    local: &[F],
    next: &[F],
    pre: (&[F], &[F]),
    public: &[F],
    sel: (F, F, F),
    scratch: &mut Scratch<F>,
) {
    let mut b = Builder::with_scratch(local, next, pre, public, sel, std::mem::take(scratch));
    F::eval_air(air, &mut b);
    *scratch = b.out;
}

/// Counts constraints and lookup terms an AIR emits (on an all-zero row pair).
pub(crate) fn shape(air: &dyn DynAir, public: &[Fp]) -> (usize, usize) {
    let zeros = vec![Fp::ZERO; air.air_width()];
    let pre = vec![Fp::ZERO; air.air_preprocessed_width()];
    let (c, t) = evaluate(air, &zeros, &zeros, (&pre, &pre), public, (Fp::ZERO, Fp::ZERO, Fp::ZERO));
    (c.len(), t.len())
}

/// Upper bound on the degree of the AIR's constraints, measured by
/// evaluating it over [`Deg`] with every column at degree one, the row
/// selectors at degree one and the transition selector at degree zero.
/// A group of lookup terms counts as `1 + sum deg d_i`, and as
/// `deg m_i + sum_(j != i) deg d_j` for each member, where a denominator
/// has the largest degree of its values. Must not exceed
/// `air.max_constraint_degree()`.
pub fn measure_degree<A: Air>(air: &A, num_public: usize) -> usize {
    measure_degree_dyn(air, num_public)
}

pub(super) fn measure_degree_dyn(air: &dyn DynAir, num_public: usize) -> usize {
    let cols = vec![Deg(1); air.air_width()];
    let pre = vec![Deg(1); air.air_preprocessed_width()];
    let public = vec![Deg(0); num_public];
    let (constraints, terms) = evaluate(air, &cols, &cols, (&pre, &pre), &public, (Deg(1), Deg(1), Deg(0)));
    let mut max = constraints.iter().map(|d| d.0 as usize).max().unwrap_or(0);
    for members in terms.chunks(air.air_lookup_group()) {
        let d: Vec<usize> = members.iter().map(|t| t.values.iter().map(|d| d.0 as usize).max().unwrap_or(0)).collect();
        let sum: usize = d.iter().sum();
        max = max.max(1 + sum);
        for (t, dt) in members.iter().zip(&d) {
            max = max.max(t.multiplicity.0 as usize + sum - dt);
        }
    }
    max
}
