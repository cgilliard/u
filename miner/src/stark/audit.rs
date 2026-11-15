//! Tests' tools for auditing an AIR: constraints that no mutation of a
//! valid trace violates, cells no constraint reads, and proofs mutated at
//! random.
//!
//! Some of these have no caller yet: the circuits' tests are theirs.
#![allow(dead_code)]

use super::air::{Builder, DynAir, Trace};
use super::check::check_tables;
use super::lookup::LookupChallenges;
use super::proof::Proof;
use crate::ext::Fp4;
use crate::field::Field;
use crate::poseidon2::Fp;

/// Tests: what one row pair of a table gives: whether every constraint
/// holds there (else the label of the first that fails) and its lookup
/// terms' share of the sum.
pub(super) fn row_pair(
    air: &dyn DynAir,
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
    i: usize,
    ch: &LookupChallenges,
) -> (Option<&'static str>, Option<Fp4>) {
    let n = trace.height();
    let next = (i + 1) % n;
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.row(i)) };
    let sel = (
        if i == 0 { Fp::ONE } else { Fp::ZERO },
        if i == n - 1 { Fp::ONE } else { Fp::ZERO },
        if i == n - 1 { Fp::ZERO } else { Fp::ONE },
    );
    let mut b = Builder::new(trace.row(i), trace.row(next), (pre_row(i), pre_row(next)), public, sel);
    air.eval_fp(&mut b);
    let failed = b
        .out
        .constraints
        .iter()
        .position(|c| *c != Fp::ZERO)
        .map(|k| b.out.marks.iter().rev().find(|(at, _)| *at <= k).map(|(_, l)| *l).unwrap_or("(unlabelled)"));
    let mut sum = Fp4::ZERO;
    for term in b.out.terms() {
        let Some(inv) = ch.denominator(&term.values).inverse() else {
            return (failed.or(Some("lookup denominator zero")), None);
        };
        let c = term.multiplicity.mul_ext(inv);
        if term.send { sum += c } else { sum -= c }
    }
    (failed, Some(sum))
}

/// Tests: one change to an honest trace that no constraint caught.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Survivor {
    pub table: usize,
    pub column: usize,
    pub row: usize,
}

/// Tests: the soundness audit of a set of tables proven together. For
/// every column of every table, at up to `rows` rows (all of them when the
/// table is shorter; else the first, the last and evenly between), adds
/// one to the cell and checks that a constraint of the row pairs it is in
/// fails or that the lookup sums move. Returns every change that passed:
/// a column a prover could set at will there. The honest trace must pass
/// [`check_tables`] first. Public inputs are changed one at a time too;
/// those that pass come back as `(table usize::MAX, column = index)`.
pub(crate) fn mutation_audit(
    tables: &[(&dyn DynAir, &Trace, Option<&Trace>)],
    public: &[Fp],
    rows: usize,
) -> Vec<Survivor> {
    assert_eq!(check_tables(tables, public), Ok(()), "the honest trace must hold");
    let ch = LookupChallenges::new(Fp4::from_u32(0x1234_5678), Fp4([Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11)]));
    let mut out = Vec::new();
    for (t, (air, trace, pre)) in tables.iter().enumerate() {
        let n = trace.height();
        let base: Vec<Fp4> = (0..n).map(|i| row_pair(*air, trace, *pre, public, i, &ch).1.unwrap()).collect();
        let sample: Vec<usize> = if n <= rows {
            (0..n).collect()
        } else {
            let mut v: Vec<usize> = (0..rows).map(|k| k * (n - 1) / (rows - 1)).collect();
            v.dedup();
            v
        };
        let mut work = (*trace).clone();
        for col in 0..trace.width {
            for &r in &sample {
                let at = r * trace.width + col;
                let was = work.values[at];
                work.values[at] = was + Fp::ONE;
                // The pairs this row is in: (r - 1, r) and (r, r + 1).
                let prev = (r + n - 1) % n;
                let mut caught = false;
                let mut moved = Fp4::ZERO;
                for i in [prev, r] {
                    match row_pair(*air, &work, *pre, public, i, &ch) {
                        (Some(_), _) | (_, None) => caught = true,
                        (None, Some(sum)) => moved += sum - base[i],
                    }
                    if prev == r {
                        break;
                    }
                }
                if !caught && moved == Fp4::ZERO {
                    out.push(Survivor { table: t, column: col, row: r });
                }
                work.values[at] = was;
            }
        }
    }
    for k in 0..public.len() {
        let mut changed = public.to_vec();
        changed[k] += Fp::ONE;
        if check_tables(tables, &changed).is_ok() {
            out.push(Survivor { table: usize::MAX, column: k, row: 0 });
        }
    }
    out
}

/// Tests: everything the constraints of the two row pairs a row is in
/// say about it, flattened: each constraint's value, then each lookup
/// term's multiplicity and values. A change to the row that leaves all of
/// it as it was is invisible to the proof.
pub(super) fn row_view(air: &dyn DynAir, trace: &Trace, pre: Option<&Trace>, public: &[Fp], r: usize) -> Vec<Fp> {
    let n = trace.height();
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.row(i)) };
    let mut out = Vec::new();
    let prev = (r + n - 1) % n;
    for i in if prev == r { vec![r] } else { vec![prev, r] } {
        let next = (i + 1) % n;
        let sel = (
            if i == 0 { Fp::ONE } else { Fp::ZERO },
            if i == n - 1 { Fp::ONE } else { Fp::ZERO },
            if i == n - 1 { Fp::ZERO } else { Fp::ONE },
        );
        let mut b = Builder::new(trace.row(i), trace.row(next), (pre_row(i), pre_row(next)), public, sel);
        air.eval_fp(&mut b);
        out.extend_from_slice(&b.out.constraints);
        for term in b.out.terms() {
            out.push(term.multiplicity);
            out.extend_from_slice(&term.values);
        }
    }
    out
}

/// Tests: a way the cells of one row can change together that the
/// constraints and lookups of its row pairs cannot see: `cells` are the
/// columns and their weights in the direction. `exact` if moving along it
/// by an arbitrary amount keeps every constraint and lookup as it was (a
/// real freedom); else only to first order (a nonlinear constraint, such
/// as a product with an inverse, still pins it).
#[derive(Clone, Debug)]
pub(crate) struct Freedom {
    pub row: usize,
    pub cells: Vec<(usize, Fp)>,
    pub exact: bool,
}

/// Tests: the degrees-of-freedom audit of one table at `rows`. For each
/// row, the exact Jacobian of [`row_view`] with respect to the row's cells
/// (constraints are polynomials of bounded degree, so derivatives come
/// exactly from evaluations along a line), and a basis of its null space
/// among the cells the view reads: each is a direction in which several
/// cells can move with nothing seen to change to first order, then tested
/// exactly at two arbitrary distances. Unread cells (a zero Jacobian
/// column) are left to [`mutation_audit`].
pub(crate) fn freedom_audit(
    air: &dyn DynAir,
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
    rows: &[usize],
) -> Vec<Freedom> {
    let w = trace.width;
    // Derivative at 0 of the polynomial through t = 0..=d, by Lagrange:
    // coefficients c_k with g'(0) = sum c_k g(k).
    let d = air.air_degree() + 2;
    let nodes: Vec<Fp> = (0..=d).map(|k| Fp::new(k as u32)).collect();
    let coeff: Vec<Fp> = (0..=d)
        .map(|k| {
            // L_k'(0) = sum over j != k of prod over m != k, j of (0 - x_m)
            // over prod over m != k of (x_k - x_m).
            let mut denom = Fp::ONE;
            for m in 0..=d {
                if m != k {
                    denom *= nodes[k] - nodes[m];
                }
            }
            let mut num = Fp::ZERO;
            for j in 0..=d {
                if j == k {
                    continue;
                }
                let mut prod = Fp::ONE;
                for m in 0..=d {
                    if m != k && m != j {
                        prod *= Fp::ZERO - nodes[m];
                    }
                }
                num += prod;
            }
            num * denom.inverse().unwrap()
        })
        .collect();
    let mut out = Vec::new();
    let mut work = trace.clone();
    for &r in rows {
        let base = row_view(air, &work, pre, public, r);
        // The Jacobian's columns, for the cells the view reads.
        let mut read: Vec<usize> = Vec::new();
        let mut columns: Vec<Vec<Fp>> = Vec::new();
        for c in 0..w {
            let at = r * w + c;
            let was = work.values[at];
            let mut g = vec![Fp::ZERO; base.len()];
            for k in 0..=d {
                work.values[at] = was + nodes[k];
                let v = row_view(air, &work, pre, public, r);
                assert_eq!(v.len(), base.len(), "lookup terms vary with the row's cells");
                for (gi, vi) in g.iter_mut().zip(&v) {
                    *gi += coeff[k] * *vi;
                }
            }
            work.values[at] = was;
            if g.iter().any(|x| *x != Fp::ZERO) {
                read.push(c);
                columns.push(g);
            }
        }
        // Null space of the m x v matrix with these columns, by reduction
        // to row echelon form: one basis vector per free column.
        let (m, v) = (base.len(), read.len());
        let mut a: Vec<Vec<Fp>> = (0..m).map(|i| (0..v).map(|j| columns[j][i]).collect()).collect();
        let mut pivots: Vec<usize> = Vec::new();
        let mut row = 0;
        for col in 0..v {
            let Some(p) = (row..m).find(|&i| a[i][col] != Fp::ZERO) else { continue };
            a.swap(row, p);
            let inv = a[row][col].inverse().unwrap();
            for x in a[row].iter_mut() {
                *x *= inv;
            }
            for i in 0..m {
                if i != row && a[i][col] != Fp::ZERO {
                    let f = a[i][col];
                    for j in 0..v {
                        let sub = f * a[row][j];
                        a[i][j] -= sub;
                    }
                }
            }
            pivots.push(col);
            row += 1;
            if row == m {
                break;
            }
        }
        for free in (0..v).filter(|j| !pivots.contains(j)) {
            // x_free = 1, each pivot variable = -(its row's entry there).
            let mut dir = vec![(read[free], Fp::ONE)];
            for (i, &pc) in pivots.iter().enumerate() {
                if a[i][free] != Fp::ZERO {
                    dir.push((read[pc], Fp::ZERO - a[i][free]));
                }
            }
            let exact = [Fp::new(0x1234_567), Fp::new(0x3141_5926)].iter().all(|&t| {
                let saved: Vec<Fp> = dir.iter().map(|(c, _)| work.values[r * w + c]).collect();
                for (c, k) in &dir {
                    work.values[r * w + c] += t * *k;
                }
                let same = row_view(air, &work, pre, public, r) == base;
                for ((c, _), s) in dir.iter().zip(saved) {
                    work.values[r * w + c] = s;
                }
                same
            });
            dir.sort_by_key(|(c, _)| *c);
            out.push(Freedom { row: r, cells: dir, exact });
        }
    }
    out
}

/// Tests: whether a change to the cell at `(row, col)` is seen by the
/// constraints or lookups of its row pairs: whether the cell is read.
pub(crate) fn cell_read(
    air: &dyn DynAir,
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
    row: usize,
    col: usize,
) -> bool {
    let mut work = trace.clone();
    let base = row_view(air, &work, pre, public, row);
    work.values[row * trace.width + col] += Fp::ONE;
    row_view(air, &work, pre, public, row) != base
}

/// Tests: the run-wide audit of one table: for each `(column, first,
/// end)`, adds one to the column on every row `first..end` at once and
/// checks the row pairs around and inside the run, and the lookup sums.
/// Returns the runs whose shift nothing saw: a register carried along a
/// run with neither end pinned (a per-row change breaks the copy between
/// rows, so the row-by-row audits cannot see it).
pub(crate) fn run_audit(
    air: &dyn DynAir,
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
    runs: &[(usize, usize, usize)],
) -> Vec<(usize, usize, usize)> {
    let ch = LookupChallenges::new(Fp4::from_u32(0x1234_5678), Fp4([Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11)]));
    let n = trace.height();
    let w = trace.width;
    let base: Vec<Fp4> = (0..n).map(|i| row_pair(air, trace, pre, public, i, &ch).1.unwrap()).collect();
    let mut work = trace.clone();
    let mut out = Vec::new();
    for &(col, first, end) in runs {
        for r in first..end {
            work.values[r * w + col] += Fp::ONE;
        }
        let mut caught = false;
        let mut moved = Fp4::ZERO;
        let from = (first + n - 1) % n;
        let mut i = from;
        loop {
            match row_pair(air, &work, pre, public, i, &ch) {
                (Some(_), _) | (_, None) => {
                    caught = true;
                    break;
                }
                (None, Some(sum)) => moved += sum - base[i],
            }
            if i == end - 1 {
                break;
            }
            i = (i + 1) % n;
        }
        if !caught && moved == Fp4::ZERO {
            out.push((col, first, end));
        }
        for r in first..end {
            work.values[r * w + col] -= Fp::ONE;
        }
    }
    out
}

/// Tests: [`freedom_audit`] over up to `per_kind` rows of each kind (rows
/// with the same set of nonzero cells among `kinds`), on every core, as
/// lines "row r [kind]: exact|first-order cols", the columns in runs.
pub(crate) fn freedom_report(
    air: &(dyn DynAir + Sync),
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
    kinds: &[usize],
    per_kind: usize,
    keep: impl Fn(&Freedom) -> bool,
) -> Vec<String> {
    let kind = |r: usize| -> Vec<usize> { kinds.iter().copied().filter(|&c| trace.row(r)[c] != Fp::ZERO).collect() };
    let mut of: std::collections::BTreeMap<Vec<usize>, Vec<usize>> = Default::default();
    for r in 0..trace.height() {
        of.entry(kind(r)).or_default().push(r);
    }
    let mut rows = Vec::new();
    for list in of.values() {
        let n = list.len().min(per_kind);
        rows.extend((0..n).map(|k| list[if n == 1 { 0 } else { k * (list.len() - 1) / (n - 1) }]));
    }
    let threads = crate::parallel::threads();
    let chunk = rows.len().div_ceil(threads).max(1);
    let found: Vec<Freedom> = std::thread::scope(|s| {
        let hs: Vec<_> =
            rows.chunks(chunk).map(|c| s.spawn(move || freedom_audit(air, trace, pre, public, c))).collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    found
        .iter()
        .filter(|f| keep(f))
        .map(|f| {
            // Columns as runs a..b.
            let mut cols: Vec<usize> = f.cells.iter().map(|(c, _)| *c).collect();
            cols.sort();
            let mut runs: Vec<String> = Vec::new();
            let mut i = 0;
            while i < cols.len() {
                let mut j = i;
                while j + 1 < cols.len() && cols[j + 1] == cols[j] + 1 {
                    j += 1;
                }
                runs.push(if i == j { cols[i].to_string() } else { format!("{}..={}", cols[i], cols[j]) });
                i = j + 1;
            }
            format!(
                "row {} {:?}: {} {}",
                f.row,
                kind(f.row),
                if f.exact { "exact" } else { "first-order" },
                runs.join(" ")
            )
        })
        .collect()
}

/// Tests: what the verifier fuzzer saw.
#[derive(Debug, Default)]
pub(crate) struct ProofFuzz {
    /// Mutations that left the bytes as they were.
    pub unchanged: usize,
    /// Mutants the decoder refused.
    pub undecodable: usize,
    /// Mutants that decoded and failed verification.
    pub rejected: usize,
    /// Mutants that decoded to the very proof: another encoding of it.
    pub same_proof: Vec<String>,
    /// Mutants verification accepted, though another proof: failures.
    pub accepted: Vec<String>,
    /// Mutants the decoder or verifier panicked on: failures.
    pub panicked: Vec<String>,
    /// Structural fields swept to boundary values (`codec::sweep_fields`),
    /// whose panics and acceptances join those above.
    pub fields: usize,
}

/// Tests: fuzzes a verifier with `iters` mutants of a valid proof's bytes
/// (a bit flipped, bytes overwritten, truncated, extended, a slice zeroed,
/// duplicated or moved), each decoded with [`Proof::from_bytes`] and, if
/// it decodes, given to `verify`. Never a panic, never an acceptance of
/// another proof.
pub(crate) fn fuzz_proof(proof: &Proof, iters: u64, seed: u64, verify: impl Fn(&Proof) -> bool) -> ProofFuzz {
    let mut rng = crate::test_util::Rng::new(seed);
    let bytes = proof.to_bytes();
    assert!(verify(proof), "the proof to fuzz must verify");
    let mut out = ProofFuzz::default();
    let quiet = crate::test_util::Quiet::new();
    for _ in 0..iters {
        let mut b = bytes.clone();
        let mut r = |n: usize| (rng.next_u64() % n.max(1) as u64) as usize;
        let (at, len) = (r(b.len()), 1 + r(64));
        let what = match r(8) {
            0 => {
                b[at] ^= 1 << r(8);
                format!("bit flipped at {at}")
            }
            1 => {
                let v = r(256) as u8;
                b[at] = v;
                format!("byte {at} set to {v}")
            }
            2 => {
                for i in at..(at + len).min(b.len()) {
                    b[i] = r(256) as u8;
                }
                format!("{len} bytes randomized at {at}")
            }
            3 => {
                b.truncate(at);
                format!("truncated to {at}")
            }
            4 => {
                b.extend((0..len).map(|_| r(256) as u8));
                format!("{len} bytes appended")
            }
            5 => {
                for i in at..(at + len).min(b.len()) {
                    b[i] = 0;
                }
                format!("{len} bytes zeroed at {at}")
            }
            6 => {
                let end = (at + len).min(b.len());
                let slice = b[at..end].to_vec();
                b.splice(at..at, slice);
                format!("{len} bytes duplicated at {at}")
            }
            _ => {
                let from = r(b.len());
                let end = (from + len).min(b.len());
                let slice = b[from..end].to_vec();
                let to = at.min(b.len() - slice.len());
                b[to..to + slice.len()].copy_from_slice(&slice);
                format!("{} bytes moved from {from} to {to}", slice.len())
            }
        };
        // A mutation that changed nothing (zeros zeroed, a byte rewritten
        // with itself) is not a mutant.
        if b == bytes {
            out.unchanged += 1;
            continue;
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Proof::from_bytes(&b).map(|p| {
                let same = p == *proof;
                (same, verify(&p))
            })
        }));
        match r {
            Err(_) => out.panicked.push(what),
            Ok(Err(_)) => out.undecodable += 1,
            Ok(Ok((true, _))) => out.same_proof.push(what),
            Ok(Ok((false, false))) => out.rejected += 1,
            Ok(Ok((false, true))) => out.accepted.push(what),
        }
    }
    drop(quiet);
    // Then every count, length, height and index at its boundary values:
    // what random mutation rarely reaches.
    let (fields, panicked, accepted) =
        crate::codec::sweep_fields(&bytes, |b| Proof::from_bytes(b).ok().map(|p| p != *proof && verify(&p)));
    out.fields = fields;
    out.panicked.extend(panicked);
    out.accepted.extend(accepted);
    out
}

/// Tests: [`mutation_audit`]'s survivors as "column: rows" lines, the
/// columns with the most first.
pub(crate) fn audit_report(survivors: &[Survivor], name: impl Fn(usize, usize) -> String) -> String {
    let mut cols: std::collections::BTreeMap<(usize, usize), Vec<usize>> = std::collections::BTreeMap::new();
    for s in survivors {
        cols.entry((s.table, s.column)).or_default().push(s.row);
    }
    let mut lines: Vec<(usize, String)> = cols
        .into_iter()
        .map(|((t, c), rows)| {
            let shown: Vec<String> = rows.iter().take(8).map(|r| r.to_string()).collect();
            let more = if rows.len() > 8 { format!(" (+{})", rows.len() - 8) } else { String::new() };
            (rows.len(), format!("{:>4} rows  {}: {}{more}", rows.len(), name(t, c), shown.join(" ")))
        })
        .collect();
    lines.sort_by(|a, b| b.0.cmp(&a.0));
    lines.into_iter().map(|(_, l)| l).collect::<Vec<_>>().join("\n")
}
