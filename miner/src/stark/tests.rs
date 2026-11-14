//! The proof system's tests: small AIRs proved and verified, tampered
//! with, and audited.

use crate::challenger::Challenger;
use crate::ext::Fp4;
use crate::field::Field;
use crate::fri::FriError;
use crate::poseidon2::Fp;
use super::air::*;
use super::audit::*;
use super::check::*;
use super::config::*;
use super::proof::*;
use super::prove::*;
use super::verify::*;


/// Fibonacci: columns (a, b); next = (b, a + b); a_0 = 0, b_0 = 1;
/// last b equals the public value. Max degree 2 (selector + column).
struct Fibonacci;

impl Air for Fibonacci {
    fn width(&self) -> usize {
        2
    }
    fn max_constraint_degree(&self) -> usize {
        2
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let (a0, b0) = (b.local()[0], b.local()[1]);
        let (a1, b1) = (b.next()[0], b.next()[1]);
        let out: F = b.public()[0];
        b.when_first_row(a0);
        b.when_first_row(b0 - F::ONE);
        b.when_transition(a1 - b0);
        b.when_transition(b1 - a0 - b0);
        b.when_last_row(b0 - out);
    }
}

fn fib_trace(log_n: usize) -> (Trace, Vec<Fp>) {
    let n = 1 << log_n;
    let mut values = Vec::with_capacity(2 * n);
    let (mut a, mut b) = (Fp::ZERO, Fp::ONE);
    for _ in 0..n {
        values.push(a);
        values.push(b);
        let c = a + b;
        a = b;
        b = c;
    }
    let last_b = values[2 * n - 1];
    (Trace::new(values, 2), vec![last_b])
}

/// x = b0 + 2 b1 from two "bits", checked as bits or not: the audit's
/// control.
struct TwoBits {
    boolean: bool,
}

impl Air for TwoBits {
    fn width(&self) -> usize {
        3
    }
    fn max_constraint_degree(&self) -> usize {
        2
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let (b0, b1, x) = (b.local()[0], b.local()[1], b.local()[2]);
        let two: F = Fp::new(2).into();
        b.assert_zero(x - b0 - two * b1);
        // x is pinned, as a register a real circuit takes elsewhere.
        let three: F = Fp::new(3).into();
        b.assert_zero(x - three);
        if self.boolean {
            b.assert_zero(b0 * (b0 - F::ONE));
            b.assert_zero(b1 * (b1 - F::ONE));
        }
    }
}

/// The degrees-of-freedom audit finds bits nobody checks are bits, and
/// nothing once they are; the single-cell audit finds neither.
#[test]
fn the_freedom_audit_finds_a_missing_bit_check() {
    let row = [Fp::ONE, Fp::ONE, Fp::new(3)];
    let trace = Trace::new([row, row].concat(), 3);
    let loose = TwoBits { boolean: false };
    assert!(mutation_audit(&[(&loose, &trace, None)], &[], 8).is_empty(), "every cell is read");
    let found = freedom_audit(&loose, &trace, None, &[], &[0]);
    assert_eq!(found.len(), 1);
    assert!(found[0].exact);
    let cols: Vec<usize> = found[0].cells.iter().map(|(c, _)| *c).collect();
    assert_eq!(cols, vec![0, 1], "b0 and b1 move together: {:?}", found[0].cells);
    let tight = TwoBits { boolean: true };
    assert!(freedom_audit(&tight, &trace, None, &[], &[0]).is_empty());
}

/// x_{i+1} = x_i^2 + k with x_0 public; degree 3 with the selector, so
/// the quotient is split into two chunks.
struct Squaring {
    k: Fp,
}

impl Air for Squaring {
    fn width(&self) -> usize {
        1
    }
    fn max_constraint_degree(&self) -> usize {
        3
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let x0 = b.local()[0];
        let x1 = b.next()[0];
        let start: F = b.public()[0];
        let k: F = self.k.into();
        b.when_first_row(x0 - start);
        b.when_transition(x1 - x0 * x0 - k);
    }
}

fn squaring_trace(air: &Squaring, log_n: usize, start: Fp) -> Trace {
    let mut values = Vec::with_capacity(1 << log_n);
    let mut x = start;
    for _ in 0..1 << log_n {
        values.push(x);
        x = x * x + air.k;
    }
    Trace::new(values, 1)
}

const CONFIG: StarkConfig = StarkConfig { log_blowup: 2, num_queries: 16, pow_bits: 0, zk: false, commit_bits: 0 };

fn transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(77));
    c
}

#[test]
fn measured_degrees() {
    assert_eq!(measure_degree(&Fibonacci, 1), 2);
    assert_eq!(measure_degree(&Squaring { k: Fp::ONE }, 1), 2); // declared 3 is a safe over-estimate
}

#[test]
fn quotient_degree_sizing() {
    assert_eq!(log_quotient_degree(1), 0);
    assert_eq!(log_quotient_degree(2), 0);
    assert_eq!(log_quotient_degree(3), 1);
    assert_eq!(log_quotient_degree(4), 2);
    assert_eq!(log_quotient_degree(5), 2);
    assert_eq!(log_quotient_degree(9), 3);
}

#[test]
fn fibonacci_roundtrip() {
    for log_n in [1, 3, 6] {
        let (trace, public) = fib_trace(log_n);
        let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
        assert_eq!(proof.tables[0].log_n, log_n);
        assert_eq!(proof.tables[0].quotient_at_zeta_q.len(), 1);
        assert_eq!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()), Ok(()), "log_n={log_n}");
        // Wrong public value fails the constraint identity.
        let bad = vec![public[0] + Fp::ONE];
        assert_eq!(
            verify(&CONFIG, &Fibonacci, &bad, &proof, &mut transcript()),
            Err(VerifyError::ConstraintIdentity)
        );
    }
}

#[test]
fn squaring_with_two_quotient_chunks() {
    let air = Squaring { k: Fp::new(5) };
    let start = Fp::new(3);
    let trace = squaring_trace(&air, 5, start);
    let proof = prove(&CONFIG, &air, &trace, &[start], &mut transcript());
    assert_eq!(proof.tables[0].quotient_at_zeta_q.len(), 2);
    assert_eq!(verify(&CONFIG, &air, &[start], &proof, &mut transcript()), Ok(()));
    assert!(verify(&CONFIG, &air, &[start + Fp::ONE], &proof, &mut transcript()).is_err());
    let other = Squaring { k: Fp::new(6) };
    assert!(verify(&CONFIG, &other, &[start], &proof, &mut transcript()).is_err());
}

#[test]
fn invalid_trace_is_rejected() {
    // A trace violating a transition constraint in one row.
    let (mut trace, public) = fib_trace(5);
    trace.values[2 * 7 + 1] += Fp::ONE;
    let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
    assert!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()).is_err());
    // A consistent trace with the wrong boundary.
    let (trace, public) = fib_trace(4);
    let mut shifted = trace.values.clone();
    shifted.rotate_left(2);
    let proof = prove(&CONFIG, &Fibonacci, &Trace::new(shifted, 2), &public, &mut transcript());
    assert!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()).is_err());
}

#[test]
fn proof_bytes_roundtrip() {
    let (trace, public) = fib_trace(4);
    let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
    let bytes = proof.to_bytes();
    let back = Proof::from_bytes(&bytes).unwrap();
    assert_eq!(back, proof);
    assert_eq!(verify(&CONFIG, &Fibonacci, &public, &back, &mut transcript()), Ok(()));
    // A proof claiming other query indices is rejected, though it
    // decodes.
    let mut moved = proof.clone();
    moved.query_indices[0] ^= 1;
    assert_eq!(verify(&CONFIG, &Fibonacci, &public, &moved, &mut transcript()), Err(VerifyError::Shape));
    assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_none());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Proof::from_bytes(&extra).is_none());
}

/// A proof of no queries whose header still claims FRI rounds once
/// panicked the decoder (an exhausted iterator), before any check.
#[test]
fn a_proof_without_queries_is_refused() {
    let (trace, public) = fib_trace(4);
    let mut proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
    let nt = proof.tables.len();
    proof.openings.clear();
    proof.query_indices.clear();
    proof.fri.queries.clear();
    // Written with no queries: ... nq = 0, rounds = 0, 4·nt heights.
    let bytes = proof.to_bytes();
    let mut forged = bytes[..bytes.len() - 8 - 16 * nt].to_vec();
    forged.extend(0u32.to_le_bytes()); // nq
    forged.extend(1u32.to_le_bytes()); // rounds
    for _ in 0..4 * nt + 1 {
        forged.extend(0u32.to_le_bytes()); // heights
    }
    assert!(Proof::from_bytes(&forged).is_none());
    assert!(Proof::from_bytes(&bytes).is_none());
}

#[test]
fn tampered_proofs_are_rejected() {
    let (trace, public) = fib_trace(4);
    let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
    assert_eq!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()), Ok(()));

    assert!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut Challenger::new()).is_err());
    let mut p = proof.clone();
    p.tables[0].trace_at_zeta[0] += Fp4::ONE;
    assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.openings[2][0].trace_row[1] += Fp::ONE;
    assert_eq!(
        verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()),
        Err(VerifyError::InvalidTraceOpening { table: 0 })
    );
    let mut p = proof.clone();
    p.openings[5][0].quotient_row[0] += Fp::ONE;
    assert_eq!(
        verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()),
        Err(VerifyError::InvalidQuotientOpening { table: 0 })
    );
    let mut p = proof.clone();
    p.openings.pop();
    assert_eq!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()), Err(VerifyError::Shape));
    let mut p = proof.clone();
    p.tables[0].trace_root[0] += Fp::ONE;
    assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.fri.final_value += Fp4::ONE;
    assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.tables[0].log_n = 5;
    assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
}

/// Read-only memory: write rows publish `(addr, value)` with a
/// multiplicity, read rows consume one copy. Columns:
/// `[mult, is_read, addr, value]`.
struct RomAir;

impl Air for RomAir {
    fn width(&self) -> usize {
        4
    }
    fn max_constraint_degree(&self) -> usize {
        3
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let (mult, is_read, addr, value) = (b.local()[0], b.local()[1], b.local()[2], b.local()[3]);
        b.assert_zero(is_read * is_read - is_read);
        b.assert_zero(mult * is_read);
        b.lookup(true, mult, &[addr, value]);
        b.lookup(false, is_read, &[addr, value]);
    }
}

fn rom_trace(rows: &[[u32; 4]]) -> Trace {
    let n = rows.len().max(2).next_power_of_two();
    let mut values = Vec::with_capacity(4 * n);
    for r in rows {
        values.extend(r.iter().map(|v| Fp::new(*v)));
    }
    values.resize(4 * n, Fp::ZERO);
    Trace::new(values, 4)
}

#[test]
fn rom_lookup_roundtrip() {
    assert_eq!(measure_degree(&RomAir, 0), 2);
    let good = rom_trace(&[
        [2, 0, 1, 10], // write (1, 10) twice
        [1, 0, 2, 20], // write (2, 20) once
        [0, 1, 1, 10],
        [0, 1, 2, 20],
        [0, 1, 1, 10],
    ]);
    assert_eq!(check_constraints(&RomAir, &good, &[]), Ok(()));
    let proof = prove(&CONFIG, &RomAir, &good, &[], &mut transcript());
    assert!(proof.tables[0].aux_root.is_some());
    assert_eq!(proof.tables[0].aux_at_zeta.len(), 3 * 4);
    assert_eq!(verify(&CONFIG, &RomAir, &[], &proof, &mut transcript()), Ok(()));
    let back = Proof::from_bytes(&proof.to_bytes()).unwrap();
    assert_eq!(back, proof);

    // Reading a value that was never written.
    let bad = rom_trace(&[[1, 0, 1, 10], [0, 1, 1, 11]]);
    assert_eq!(check_constraints(&RomAir, &bad, &[]), Err((usize::MAX, 0, "lookup sum")));
    // Multiplicity too small for the reads.
    let bad2 = rom_trace(&[[1, 0, 1, 10], [0, 1, 1, 10], [0, 1, 1, 10]]);
    assert!(check_constraints(&RomAir, &bad2, &[]).is_err());
    // A dishonest prover's proof for an unsatisfied relation fails: the
    // running sum cannot end at zero. (Aux generation asserts in debug;
    // emulate by proving a trace whose sum is non-zero in release only.)
    if !cfg!(debug_assertions) {
        let proof = prove(&CONFIG, &RomAir, &bad, &[], &mut transcript());
        assert!(verify(&CONFIG, &RomAir, &[], &proof, &mut transcript()).is_err());
    }
    // Tampering with the auxiliary opening is caught.
    let mut p = proof.clone();
    p.tables[0].aux_at_zeta[0] += Fp4::ONE;
    assert!(verify(&CONFIG, &RomAir, &[], &p, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.openings[0][0].aux_row[0] += Fp::ONE;
    assert_eq!(
        verify(&CONFIG, &RomAir, &[], &p, &mut transcript()),
        Err(VerifyError::InvalidAuxOpening { table: 0 })
    );
}

/// [`RomAir`] with its two lookup terms summed in one column.
struct PairedRom;

impl Air for PairedRom {
    fn width(&self) -> usize {
        4
    }
    fn max_constraint_degree(&self) -> usize {
        3
    }
    fn lookup_group(&self) -> usize {
        2
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        RomAir.eval(b)
    }
}

#[test]
fn paired_lookup_terms() {
    assert_eq!(measure_degree(&PairedRom, 0), 3);
    let good = rom_trace(&[[2, 0, 1, 10], [1, 0, 2, 20], [0, 1, 1, 10], [0, 1, 2, 20], [0, 1, 1, 10]]);
    let proof = prove(&CONFIG, &PairedRom, &good, &[], &mut transcript());
    // One group column and the running sum.
    assert_eq!(proof.tables[0].aux_at_zeta.len(), 2 * 4);
    assert_eq!(verify(&CONFIG, &PairedRom, &[], &proof, &mut transcript()), Ok(()));
    // The unpaired verifier expects a different shape.
    assert!(verify(&CONFIG, &RomAir, &[], &proof, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.tables[0].aux_at_zeta[0] += Fp4::ONE;
    assert!(verify(&CONFIG, &PairedRom, &[], &p, &mut transcript()).is_err());
    if !cfg!(debug_assertions) {
        let bad = rom_trace(&[[1, 0, 1, 10], [0, 1, 1, 11]]);
        let proof = prove(&CONFIG, &PairedRom, &bad, &[], &mut transcript());
        assert!(verify(&CONFIG, &PairedRom, &[], &proof, &mut transcript()).is_err());
    }
}

/// Sends its single column, once per row.
struct Sender;

impl Air for Sender {
    fn width(&self) -> usize {
        1
    }
    fn max_constraint_degree(&self) -> usize {
        2
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        b.lookup(true, F::ONE, &[b.local()[0]]);
    }
}

/// Receives `value` with multiplicity `mult`, and runs a Fibonacci
/// sequence over `(a, b)` so that its own row structure is checked.
/// Columns: `[value, mult, a, b]`.
struct Receiver;

impl Air for Receiver {
    fn width(&self) -> usize {
        4
    }
    fn max_constraint_degree(&self) -> usize {
        3
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let l = b.local();
        let n = b.next();
        b.lookup(false, l[1], &[l[0]]);
        b.when_first_row(l[2]);
        b.when_first_row(l[3] - F::ONE);
        b.when_transition(n[2] - l[3]);
        b.when_transition(n[3] - l[2] - l[3]);
    }
}

/// A 16-row and a 4-row sender and a 4-row receiver of their values.
fn exchange(mults: [u32; 4]) -> (Trace, Trace, Trace) {
    let tall = Trace::new((0..16).map(|i| Fp::new(10 + i % 4)).collect(), 1);
    let short = Trace::new((0..4).map(|i| Fp::new(10 + i)).collect(), 1);
    let (mut a, mut b) = (Fp::ZERO, Fp::ONE);
    let mut values = Vec::new();
    for (i, m) in mults.iter().enumerate() {
        values.extend([Fp::new(10 + i as u32), Fp::new(*m), a, b]);
        let c = a + b;
        a = b;
        b = c;
    }
    (tall, short, Trace::new(values, 4))
}

#[test]
fn tables_of_different_heights() {
    let (tall, short, recv) = exchange([5; 4]);
    let tables = [
        TableInput { air: &Sender, trace: &tall, pre: None },
        TableInput { air: &Sender, trace: &short, pre: None },
        TableInput { air: &Receiver, trace: &recv, pre: None },
    ];
    let specs = [
        TableSpec { air: &Sender, pre_root: None },
        TableSpec { air: &Sender, pre_root: None },
        TableSpec { air: &Receiver, pre_root: None },
    ];
    let checks: Vec<(&dyn DynAir, &Trace, Option<&Trace>)> =
        vec![(&Sender, &tall, None), (&Sender, &short, None), (&Receiver, &recv, None)];
    assert_eq!(check_tables(&checks, &[]), Ok(()));
    let proof = prove_tables(&CONFIG, &tables, &[], &mut transcript());
    assert_eq!(proof.tables.iter().map(|t| t.log_n).collect::<Vec<_>>(), vec![4, 2, 2]);
    assert_eq!(verify_tables(&CONFIG, &specs, &[], &proof, &mut transcript()), Ok(()));
    let back = Proof::from_bytes(&proof.to_bytes()).unwrap();
    assert_eq!(back, proof);

    // Tables in another order, or one missing.
    let swapped = [specs[0], specs[2], specs[1]];
    assert!(verify_tables(&CONFIG, &swapped, &[], &proof, &mut transcript()).is_err());
    assert_eq!(verify_tables(&CONFIG, &specs[..2], &[], &proof, &mut transcript()), Err(VerifyError::Shape));
    // Openings of a smaller table are checked.
    let mut p = proof.clone();
    p.openings[3][2].trace_row[2] += Fp::ONE;
    assert_eq!(
        verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()),
        Err(VerifyError::InvalidTraceOpening { table: 2 })
    );
    let mut p = proof.clone();
    p.tables[2].trace_at_zeta_next[3] += Fp4::ONE;
    assert!(verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()).is_err());
    // Moving lookup weight between tables keeps the total but breaks
    // the last-row constraint of both.
    let mut p = proof.clone();
    p.tables[0].lookup_sum += Fp4::ONE;
    p.tables[2].lookup_sum -= Fp4::ONE;
    assert!(verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.tables[1].lookup_sum += Fp4::ONE;
    assert_eq!(verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()), Err(VerifyError::LookupSum));

    // Messages that do not balance.
    let (tall, short, recv) = exchange([5, 5, 4, 5]);
    let checks: Vec<(&dyn DynAir, &Trace, Option<&Trace>)> =
        vec![(&Sender, &tall, None), (&Sender, &short, None), (&Receiver, &recv, None)];
    assert_eq!(check_tables(&checks, &[]), Err((2, (usize::MAX, 0, "lookup sum"))));
    if !cfg!(debug_assertions) {
        let tables = [
            TableInput { air: &Sender, trace: &tall, pre: None },
            TableInput { air: &Sender, trace: &short, pre: None },
            TableInput { air: &Receiver, trace: &recv, pre: None },
        ];
        let proof = prove_tables(&CONFIG, &tables, &[], &mut transcript());
        assert_eq!(verify_tables(&CONFIG, &specs, &[], &proof, &mut transcript()), Err(VerifyError::LookupSum));
    }
}

const ZK: StarkConfig = StarkConfig { log_blowup: 3, num_queries: 4, pow_bits: 0, zk: true, commit_bits: 0 };

/// A 128-row sender and a 128-row receiver for zero-knowledge proofs:
/// the rows before the blinding rows send `10 + i % 4`, and the
/// receiver takes each value with multiplicity `mults` on its first
/// four rows. The blinding rows hold junk the proof must ignore.
fn zk_exchange(mults: [u32; 4]) -> (Trace, Trace) {
    let n = 128;
    let real = n - ZK.blind_rows();
    let send = Trace::new((0..n).map(|i| Fp::new(if i < real { 10 + i as u32 % 4 } else { 999 })).collect(), 1);
    let (mut a, mut b) = (Fp::ZERO, Fp::ONE);
    let mut values = Vec::new();
    for i in 0..n {
        let (v, m) = match mults.get(i) {
            Some(&m) => (10 + i as u32, m),
            None if i < real => (0, 0),
            None => (7, 3),
        };
        values.extend([Fp::new(v), Fp::new(m), a, b]);
        let c = a + b;
        a = b;
        b = c;
    }
    (send, Trace::new(values, 4))
}

#[test]
fn zero_knowledge_tables() {
    let real = 128 - ZK.blind_rows();
    let (send, recv) = zk_exchange([real as u32 / 4; 4]);
    let tables = [
        TableInput { air: &Sender, trace: &send, pre: None },
        TableInput { air: &Receiver, trace: &recv, pre: None },
    ];
    let specs = [TableSpec { air: &Sender, pre_root: None }, TableSpec { air: &Receiver, pre_root: None }];
    let proof = prove_tables(&ZK, &tables, &[], &mut transcript());
    assert_eq!(verify_tables(&ZK, &specs, &[], &proof, &mut transcript()), Ok(()));
    assert_eq!(Proof::from_bytes(&proof.to_bytes()).unwrap(), proof);
    // Contiguous, masked chunks: twice the interleaved count of degree 3.
    assert_eq!(proof.tables.iter().map(|t| t.quotient_at_zeta_q.len()).collect::<Vec<_>>(), vec![4, 4]);
    assert_eq!(proof.tables[0].trace_at_zeta.len(), 1 + ZK_COLS);

    // A second proof of the same statement shares nothing derived
    // from the traces: commitments, openings and lookup totals differ.
    let again = prove_tables(&ZK, &tables, &[], &mut transcript());
    assert_eq!(verify_tables(&ZK, &specs, &[], &again, &mut transcript()), Ok(()));
    for (a, b) in proof.tables.iter().zip(&again.tables) {
        assert_ne!(a.trace_root, b.trace_root);
        assert_ne!(a.quotient_root, b.quotient_root);
        assert_ne!(a.lookup_sum, b.lookup_sum);
        assert!(a.trace_at_zeta.iter().zip(&b.trace_at_zeta).all(|(x, y)| x != y));
    }
    assert_ne!(proof.fri.final_value, again.fri.final_value);
    // What the proof opens of any column stays within the blinding
    // rows: four Fp-linear functions at each of zeta and g*zeta, and
    // at each query row one value (a single point per leaf) and, through
    // the quotient, the next row's.
    let rows: std::collections::HashSet<usize> = proof.query_indices.iter().copied().collect();
    assert!(rows.len() <= ZK.num_queries);
    for (t, table) in proof.tables.iter().enumerate() {
        assert_eq!(table.trace_at_zeta.len(), table.trace_at_zeta_next.len());
        for o in &proof.openings {
            assert_eq!(o[t].trace_row.len(), table.trace_at_zeta.len(), "one value per column per query");
        }
        let revealed = 4 * 2 + 2 * rows.len();
        assert!(revealed <= ZK.blind_rows(), "table {t}: {revealed} values revealed, {} blind", ZK.blind_rows());
    }
    // The totals still cancel.
    assert!((proof.tables[0].lookup_sum + proof.tables[1].lookup_sum).is_zero());

    // Tampering is caught.
    let mut p = proof.clone();
    p.tables[1].quotient_at_zeta_q[3] += Fp4::ONE;
    assert_eq!(verify_tables(&ZK, &specs, &[], &p, &mut transcript()), Err(VerifyError::ConstraintIdentity));
    let mut p = proof.clone();
    p.tables[0].trace_at_zeta[1] += Fp4::ONE;
    assert_eq!(verify_tables(&ZK, &specs, &[], &p, &mut transcript()), Err(VerifyError::ConstraintIdentity));
    let mut p = proof.clone();
    p.tables[0].lookup_sum += Fp4::ONE;
    p.tables[1].lookup_sum -= Fp4::ONE;
    assert!(verify_tables(&ZK, &specs, &[], &p, &mut transcript()).is_err());
    let mut p = proof.clone();
    p.openings[1][1].aux_row[0] += Fp::ONE;
    assert_eq!(
        verify_tables(&ZK, &specs, &[], &p, &mut transcript()),
        Err(VerifyError::InvalidAuxOpening { table: 1 })
    );
    // A proof is only accepted under the configuration it was made in.
    let plain = StarkConfig { zk: false, ..ZK };
    assert_eq!(verify_tables(&plain, &specs, &[], &proof, &mut transcript()), Err(VerifyError::Shape));

    // Unbalanced messages before the blinding rows are rejected.
    if !cfg!(debug_assertions) {
        let (send, recv) = zk_exchange([real as u32 / 4, real as u32 / 4, real as u32 / 4 - 1, real as u32 / 4]);
        let tables = [
            TableInput { air: &Sender, trace: &send, pre: None },
            TableInput { air: &Receiver, trace: &recv, pre: None },
        ];
        let proof = prove_tables(&ZK, &tables, &[], &mut transcript());
        assert_eq!(verify_tables(&ZK, &specs, &[], &proof, &mut transcript()), Err(VerifyError::LookupSum));
    }
}

#[test]
fn commit_phase_grinding() {
    // A target high enough that every challenge before the queries,
    // the lookup ones included, needs a little work.
    let config = StarkConfig { commit_bits: 122, ..CONFIG };
    let (tall, short, recv) = exchange([5; 4]);
    let tables = [
        TableInput { air: &Sender, trace: &tall, pre: None },
        TableInput { air: &Sender, trace: &short, pre: None },
        TableInput { air: &Receiver, trace: &recv, pre: None },
    ];
    let specs = [
        TableSpec { air: &Sender, pre_root: None },
        TableSpec { air: &Sender, pre_root: None },
        TableSpec { air: &Receiver, pre_root: None },
    ];
    let g = grinding_of(&config, &[(&Sender, 4), (&Sender, 2), (&Receiver, 2)], &[]);
    assert!(g.lookup > 0 && g.alpha > 0 && g.zeta > 0 && g.beta > 0, "{g:?}");
    let proof = prove_tables(&config, &tables, &[], &mut transcript());
    assert_eq!(verify_tables(&config, &specs, &[], &proof, &mut transcript()), Ok(()));
    assert!(proof.grinding.iter().all(|w| *w != Fp::ZERO));
    assert!(crate::fri::fold_grinding(&config.fri(), 2, 6) > 0);
    assert_eq!(Proof::from_bytes(&proof.to_bytes()).unwrap(), proof);
    for k in 0..4 {
        let mut p = proof.clone();
        p.grinding[k] += Fp::ONE;
        assert_eq!(verify_tables(&config, &specs, &[], &p, &mut transcript()), Err(VerifyError::ProofOfWork));
    }
    let mut p = proof.clone();
    p.fri.fold_witnesses[0] += Fp::ONE;
    assert_eq!(
        verify_tables(&config, &specs, &[], &p, &mut transcript()),
        Err(VerifyError::Fri(FriError::ProofOfWork))
    );
    // A proof made without the grinding does not pass.
    let plain = prove_tables(&CONFIG, &tables, &[], &mut transcript());
    assert!(verify_tables(&config, &specs, &[], &plain, &mut transcript()).is_err());
}

#[test]
fn zero_knowledge_rejects_bad_rows() {
    // Fibonacci with the public value at the last row before the
    // blinding rows; what follows is junk.
    let (mut trace, _) = fib_trace(7);
    let last = 127 - ZK.blind_rows();
    let out = vec![trace.values[2 * last + 1]];
    for v in &mut trace.values[2 * (last + 1)..] {
        *v = Fp::new(5);
    }
    let proof = prove(&ZK, &Fibonacci, &trace, &out, &mut transcript());
    assert_eq!(verify(&ZK, &Fibonacci, &out, &proof, &mut transcript()), Ok(()));
    let wrong = vec![out[0] + Fp::ONE];
    assert!(verify(&ZK, &Fibonacci, &wrong, &proof, &mut transcript()).is_err());
    // A broken row before the blinding rows leaves no quotient.
    let mut bad = trace;
    bad.values[2 * 20] += Fp::ONE;
    let r = std::panic::catch_unwind(|| prove(&ZK, &Fibonacci, &bad, &out, &mut transcript()));
    assert!(r.is_err());
}

/// Two columns that must be permutations of each other.
struct PermAir;

impl Air for PermAir {
    fn width(&self) -> usize {
        2
    }
    fn max_constraint_degree(&self) -> usize {
        2
    }
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        b.lookup(true, F::ONE, &[b.local()[0]]);
        b.lookup(false, F::ONE, &[b.local()[1]]);
    }
}

#[test]
fn permutation_lookup() {
    let a = [5u32, 3, 9, 1, 7, 7, 2, 0];
    let bperm = [7u32, 1, 0, 9, 3, 2, 7, 5];
    let values: Vec<Fp> = a.iter().zip(&bperm).flat_map(|(x, y)| [Fp::new(*x), Fp::new(*y)]).collect();
    let trace = Trace::new(values, 2);
    assert_eq!(check_constraints(&PermAir, &trace, &[]), Ok(()));
    let proof = prove(&CONFIG, &PermAir, &trace, &[], &mut transcript());
    assert_eq!(verify(&CONFIG, &PermAir, &[], &proof, &mut transcript()), Ok(()));
    let mut bad = trace.clone();
    bad.values[3] = Fp::new(4);
    assert!(check_constraints(&PermAir, &bad, &[]).is_err());
}

/// The verifier reads a proof from its bytes. It accepts the bytes of a
/// proof and nothing near them: not with a byte more or fewer, not with
/// any count, length, height, index or flag set to another value, not
/// with any bit flipped; and none of those makes it panic.
#[test]
fn the_byte_verifier_accepts_a_proof_and_nothing_near_it() {
    let (fib, public) = fib_trace(5);
    let rom = rom_trace(&[[2, 0, 1, 10], [1, 0, 2, 20], [0, 1, 1, 10], [0, 1, 2, 20], [0, 1, 1, 10]]);
    let (tall, short, recv) = exchange([5, 5, 5, 5]);
    let exchange_specs = [
        TableSpec { air: &Sender, pre_root: None },
        TableSpec { air: &Sender, pre_root: None },
        TableSpec { air: &Receiver, pre_root: None },
    ];
    let exchange_inputs = [
        TableInput { air: &Sender, trace: &tall, pre: None },
        TableInput { air: &Sender, trace: &short, pre: None },
        TableInput { air: &Receiver, trace: &recv, pre: None },
    ];
    let grinding = StarkConfig { pow_bits: 3, commit_bits: 100, ..CONFIG };
    #[allow(clippy::type_complexity)]
    let cases: [(&str, StarkConfig, Vec<TableSpec<'_>>, &[Fp], Proof); 3] = [
        (
            "fibonacci",
            grinding,
            vec![TableSpec { air: &Fibonacci, pre_root: None }],
            &public,
            prove(&grinding, &Fibonacci, &fib, &public, &mut transcript()),
        ),
        ("rom", CONFIG, vec![TableSpec { air: &RomAir, pre_root: None }], &[], prove(&CONFIG, &RomAir, &rom, &[], &mut transcript())),
        ("exchange", CONFIG, exchange_specs.to_vec(), &[], prove_tables(&CONFIG, &exchange_inputs, &[], &mut transcript())),
    ];
    for (name, config, specs, public, proof) in &cases {
        let bytes = proof.to_bytes();
        let check = |b: &[u8]| verify_bytes(config, specs, public, b, &mut transcript());
        assert_eq!(check(&bytes), Ok(()), "{name}");
        // The owned form says the same, and decodes from the same bytes.
        assert_eq!(verify_tables(config, specs, public, proof, &mut transcript()), Ok(()));
        assert_eq!(Proof::from_bytes(&bytes).as_ref(), Some(proof));
        assert_eq!(check(&[]), Err(VerifyError::Malformed));
        assert_eq!(check(&[&bytes[..], &[0]].concat()), Err(VerifyError::Malformed), "{name}: a byte more");
        for cut in (0..bytes.len()).step_by(1 + bytes.len() / 300).chain([bytes.len() - 1, bytes.len() - 32]) {
            assert!(check(&bytes[..cut]).is_err(), "{name}: cut to {cut} bytes");
        }
        // Every structural field, set to each value at its bounds.
        let (fields, panicked, accepted) = crate::codec::sweep_fields(&bytes, |b| match check(b) {
            Err(VerifyError::Malformed) => None,
            verdict => Some(verdict.is_ok()),
        });
        assert!(fields > 20 + 16 * (specs.len() * 4 + 2), "{name}: {fields} structural fields found");
        assert!(panicked.is_empty(), "{name}: {panicked:?}");
        assert!(accepted.is_empty(), "{name}: {accepted:?}");
        // Any bit, anywhere.
        let (iters, seed) = crate::test_util::fuzz_params(400, 60);
        let mut rng = crate::test_util::Rng::new(seed);
        let quiet = crate::test_util::Quiet::new();
        for _ in 0..iters {
            let mut bad = bytes.clone();
            let at = rng.next_u64() as usize % bad.len();
            bad[at] ^= 1 << (rng.next_u64() % 8);
            let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&bad)));
            assert!(matches!(verdict, Ok(Err(_))), "{name}: bit flipped in byte {at}: {verdict:?}");
        }
        drop(quiet);
        // The last bytes are a sibling of the last tree that is sent any:
        // with it changed, that tree's openings are not the tree's.
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            matches!(check(&bad), Err(VerifyError::InvalidFriOpening { .. } | VerifyError::InvalidQuotientOpening { .. })),
            "{name}: {:?}",
            check(&bad)
        );
        // Another statement, another transcript: refused.
        assert!(verify_bytes(config, specs, public, &bytes, &mut Challenger::new()).is_err());
    }
    // A fold that fails where every opening is its tree's is reported as
    // the fold: the final value is in no tree.
    let (name, config, specs, public, proof) = &cases[0];
    let mut p = proof.clone();
    p.fri.final_value += Fp4::ONE;
    let verdict = verify_bytes(config, specs, public, &p.to_bytes(), &mut transcript());
    assert!(matches!(verdict, Err(VerifyError::Fri(_))), "{name}: {verdict:?}");
    // A row that is not its tree's is reported as that, though its fold
    // fails too.
    let mut p = proof.clone();
    p.openings[1][0].trace_row[0] += Fp::ONE;
    assert_eq!(
        verify_bytes(config, specs, public, &p.to_bytes(), &mut transcript()),
        Err(VerifyError::InvalidTraceOpening { table: 0 })
    );
    // An owned proof the encoding cannot hold has the wrong shape.
    for break_it in [
        |p: &mut Proof| p.query_indices.clear(),
        |p: &mut Proof| drop(p.fri.queries.pop()),
        |p: &mut Proof| drop(p.fri.queries[2].pop()),
        |p: &mut Proof| p.openings[0].clear(),
        |p: &mut Proof| p.openings[3][0].trace_path.truncate(1),
        |p: &mut Proof| p.tables[0].lookup_sum = Fp4::ONE,
        |p: &mut Proof| p.query_indices[0] = usize::MAX,
    ] {
        let mut p = proof.clone();
        break_it(&mut p);
        assert_eq!(p.try_to_bytes(), None);
        assert_eq!(verify_tables(config, specs, public, &p, &mut transcript()), Err(VerifyError::Shape));
        assert!(std::panic::catch_unwind(|| p.to_bytes()).is_err());
    }
    for e in [
        VerifyError::Malformed,
        VerifyError::Shape,
        VerifyError::ProofOfWork,
        VerifyError::ConstraintIdentity,
        VerifyError::LookupSum,
        VerifyError::Fri(FriError::Shape),
        VerifyError::InvalidTraceOpening { table: 1 },
        VerifyError::InvalidAuxOpening { table: 1 },
        VerifyError::InvalidPreprocessedOpening { table: 1 },
        VerifyError::InvalidQuotientOpening { table: 1 },
        VerifyError::InvalidFriOpening { round: 1 },
    ] {
        assert!(!e.to_string().is_empty());
    }
}
