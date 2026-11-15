//! The hash table of the verifier machine: one Poseidon2 permutation per
//! row, in the order [`crate::vm_air`] performs them.
//!
//! The machine does no hashing itself. Each hashing instruction sends the
//! message `(index, kind, cap, dir, data[8], digest[8])` over the lookup
//! bus, and this table receives it on the row of that index. The table is
//! the hash machine of [`crate::hash_machine`] restricted to three ops,
//! plus a row counter, padded with pass rows:
//!
//! | kind | op       | permutation input                                     |
//! |------|----------|-------------------------------------------------------|
//! | 1    | start    | `data | cap, 0, ..`                                   |
//! | 2    | absorb   | previous output with `data` added to the rate         |
//! | 3    | compress | `(digest, data)`, or `(data, digest)` when `dir`      |
//!
//! and `digest` is the first eight elements of the output. `cap` and `dir`
//! are zero for the ops that do not use them. Indices are distinct and the
//! machine numbers its hashing instructions from zero, so the received rows
//! are the first rows of the table, in the machine's order: an absorb or
//! compress chains to the hashing instruction just before it. The machine
//! therefore only absorbs right after a start or another absorb.
//!
//! Only a small fraction of a verifier program hashes, so this table is
//! several times shorter than the machine's, which is the point: the
//! permutation's 314 columns are paid for once per hash, not once per
//! instruction.

use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH};
use crate::poseidon2_air::COL_INPUT;
use crate::stark::{Air, Builder, Trace};

/// Row number, matched against the machine's count of hashing
/// instructions.
pub const COL_INDEX: usize = HM_COLS;
pub const NUM_COLS: usize = COL_INDEX + 1;

pub const KIND_START: u32 = 1;
pub const KIND_ABSORB: u32 = 2;
pub const KIND_COMPRESS: u32 = 3;

/// Number of values in a bus message.
pub const MESSAGE_LEN: usize = 4 + RATE + DIGEST;

/// Values of one bus message, in order.
pub fn message<F: Field>(index: F, kind: F, cap: F, dir: F, data: [F; RATE], digest: [F; DIGEST]) -> [F; MESSAGE_LEN] {
    let mut m = [F::ZERO; MESSAGE_LEN];
    m[..4].copy_from_slice(&[index, kind, cap, dir]);
    m[4..4 + RATE].copy_from_slice(&data);
    m[4 + RATE..].copy_from_slice(&digest);
    m
}

/// One permutation of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashOp {
    Start { data: [Fp; RATE], cap: Fp },
    Absorb { data: [Fp; RATE] },
    Compress { sibling: [Fp; DIGEST], right: bool },
}

pub struct HashTableAir;

impl Air for HashTableAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        b.assert_zero(l[COL_CHAIN]);
        b.assert_zero(l[COL_LOAD]);
        // The first row has nothing to chain to.
        b.when_first_row(l[COL_ABSORB] + l[COL_COMPRESS]);
        let start = l[COL_START];
        for k in 0..RATE {
            b.assert_zero(start * (l[COL_INPUT + k] - l[COL_DATA + k]));
        }
        for k in 1..RATE {
            b.assert_zero(start * l[COL_INPUT + RATE + k]);
        }
        b.when_first_row(l[COL_INDEX]);
        b.when_transition(n[COL_INDEX] - l[COL_INDEX] - F::ONE);

        let used = start + l[COL_ABSORB] + l[COL_COMPRESS];
        let kind = start + l[COL_ABSORB].scale(Fp::new(KIND_ABSORB)) + l[COL_COMPRESS].scale(Fp::new(KIND_COMPRESS));
        let cap = start * l[COL_INPUT + RATE];
        let data: [F; RATE] = core::array::from_fn(|k| l[COL_DATA + k]);
        let digest: [F; DIGEST] = core::array::from_fn(|k| l[COL_ACC + k]);
        b.lookup(false, used, &message(l[COL_INDEX], kind, cap, l[COL_DIR], data, digest));
    }
}

impl HashTableAir {
    /// Rows for `ops` in order, padded with pass rows to a power of two.
    pub fn generate_trace(ops: &[HashOp]) -> Trace {
        Self::generate_trace_height(ops, ops.len().max(2).next_power_of_two())
    }

    /// [`HashTableAir::generate_trace`] padded to `n` rows.
    pub fn generate_trace_height(ops: &[HashOp], n: usize) -> Trace {
        assert!(n.is_power_of_two() && n >= ops.len().max(2), "hash table of {n} rows cannot hold {} ops", ops.len());
        let mut b = HashTraceBuilder::with_capacity(NUM_COLS, n);
        for op in ops {
            match *op {
                HashOp::Start { data, cap } => {
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(&data);
                    input[RATE] = cap;
                    b.start(input);
                    b.last_row_mut()[COL_DATA..COL_DATA + RATE].copy_from_slice(&data);
                }
                HashOp::Absorb { data } => {
                    b.absorb(data);
                }
                HashOp::Compress { sibling, right } => {
                    b.compress(sibling, right);
                }
            }
            let i = b.len() - 1;
            b.last_row_mut()[COL_INDEX] = Fp::new(i as u32);
        }
        while b.len() < n {
            b.pass();
            let i = b.len() - 1;
            b.last_row_mut()[COL_INDEX] = Fp::new(i as u32);
        }
        b.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::hash_machine::COL_PASS;
    use crate::poseidon2::{compress, hash};
    use crate::stark::audit::{audit_report, mutation_audit};
    use crate::stark::{
        StarkConfig, TableInput, TableSpec, check_constraints, check_tables, measure_degree, prove_tables,
        verify_tables,
    };
    use crate::test_util::Rng;

    /// The machine's side of the bus, as little of it as sends: a flag and
    /// a message a row.
    struct Sender;

    const S_USED: usize = MESSAGE_LEN;
    const S_COLS: usize = S_USED + 1;

    impl Air for Sender {
        fn width(&self) -> usize {
            S_COLS
        }

        fn max_constraint_degree(&self) -> usize {
            2
        }

        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            let l = b.local();
            b.assert_zero(l[S_USED] * l[S_USED] - l[S_USED]);
            b.lookup(true, l[S_USED], &l[..MESSAGE_LEN]);
        }
    }

    /// The messages a machine performing `ops` sends, one a row, read off
    /// the table's own rows.
    fn sender_trace(ops: &[HashOp], table: &Trace) -> Trace {
        let n = ops.len().max(2).next_power_of_two();
        let mut values = vec![Fp::ZERO; n * S_COLS];
        for (i, (op, row)) in ops.iter().zip(values.chunks_exact_mut(S_COLS)).enumerate() {
            let t = table.row(i);
            let (kind, cap, dir, data) = match *op {
                HashOp::Start { data, cap } => (KIND_START, cap, false, data),
                HashOp::Absorb { data } => (KIND_ABSORB, Fp::ZERO, false, data),
                HashOp::Compress { sibling, right } => (KIND_COMPRESS, Fp::ZERO, right, sibling),
            };
            let digest: [Fp; DIGEST] = t[COL_ACC..COL_ACC + DIGEST].try_into().unwrap();
            let dir = if dir { Fp::ONE } else { Fp::ZERO };
            row[..MESSAGE_LEN].copy_from_slice(&message(Fp::new(i as u32), Fp::new(kind), cap, dir, data, digest));
            row[S_USED] = Fp::ONE;
        }
        Trace::new(values, S_COLS)
    }

    fn random_ops(rng: &mut Rng, count: usize) -> Vec<HashOp> {
        let mut ops = Vec::new();
        let mut sponge = false;
        for i in 0..count {
            let data: [Fp; RATE] = core::array::from_fn(|_| rng.fp());
            let pick = if i == 0 { 0 } else { rng.next_u64() % 3 };
            ops.push(match pick {
                1 if sponge => HashOp::Absorb { data },
                2 => {
                    sponge = false;
                    HashOp::Compress { sibling: data, right: rng.next_u64() % 2 == 1 }
                }
                _ => {
                    sponge = true;
                    HashOp::Start { data, cap: rng.fp() }
                }
            });
        }
        ops
    }

    #[test]
    fn degree_and_rows() {
        assert_eq!(measure_degree(&HashTableAir, 0), 3);
        let data: [Fp; RATE] = core::array::from_fn(|i| Fp::new(i as u32 + 1));
        let sib: [Fp; DIGEST] = core::array::from_fn(|i| Fp::new(50 + i as u32));
        let ops = [
            HashOp::Start { data, cap: Fp::new(16) },
            HashOp::Absorb { data },
            HashOp::Compress { sibling: sib, right: true },
        ];
        let trace = HashTableAir::generate_trace(&ops);
        assert_eq!(trace.height(), 4);
        // The sponge rows hash 16 values; the compress puts the sibling left.
        let mut sixteen = data.to_vec();
        sixteen.extend(data);
        let d1: [Fp; DIGEST] = trace.row(1)[COL_ACC..COL_ACC + DIGEST].try_into().unwrap();
        assert_eq!(d1, hash(&sixteen));
        assert_eq!(trace.row(2)[COL_ACC..COL_ACC + DIGEST], compress(&sib, &d1));
        assert_eq!(trace.row(3)[COL_INDEX], Fp::new(3));
        // Without the machine's messages the lookup terms do not cancel,
        // but every row constraint holds.
        assert_eq!(check_constraints(&HashTableAir, &trace, &[]), Err((usize::MAX, 0, "lookup sum")));
        let mut bad = trace.clone();
        bad.values[NUM_COLS + COL_INDEX] += Fp::ONE;
        assert_eq!(check_constraints(&HashTableAir, &bad, &[]).unwrap_err().0, 0);
    }

    /// With the machine's messages the sums cancel, at any height of
    /// either table; and a message the table has no row for is refused.
    #[test]
    fn the_table_answers_the_messages_sent_to_it() {
        let mut rng = Rng::new(70);
        for count in [1usize, 2, 3, 7, 8, 21] {
            let ops = random_ops(&mut rng, count);
            let table = HashTableAir::generate_trace_height(&ops, 32);
            let sender = sender_trace(&ops, &table);
            assert_eq!(
                check_tables(&[(&Sender, &sender, None), (&HashTableAir, &table, None)], &[]),
                Ok(()),
                "{count}"
            );

            // Each field of a message matters.
            for col in 0..MESSAGE_LEN {
                let mut bad = sender.clone();
                bad.values[(count - 1) * S_COLS + col] += Fp::ONE;
                assert!(check_tables(&[(&Sender, &bad, None), (&HashTableAir, &table, None)], &[]).is_err(), "{col}");
            }
        }
    }

    /// The rules this table adds to the hash machine's.
    #[test]
    fn what_the_table_refuses() {
        let mut rng = Rng::new(71);
        let data: [Fp; RATE] = core::array::from_fn(|_| rng.fp());
        let ops = [
            HashOp::Start { data, cap: Fp::new(9) },
            HashOp::Absorb { data },
            HashOp::Compress { sibling: data, right: false },
        ];
        let trace = HashTableAir::generate_trace(&ops);
        let row_fails = |t: &Trace| check_constraints(&HashTableAir, t, &[]).unwrap_err().0;
        let flip = |t: &mut Trace, row: usize, from: usize, to: usize| {
            t.values[row * NUM_COLS + from] = Fp::ZERO;
            t.values[row * NUM_COLS + to] = Fp::ONE;
        };

        // The machine's other ops: chain and load.
        let mut bad = trace.clone();
        flip(&mut bad, 3, COL_PASS, COL_LOAD);
        assert_eq!(row_fails(&bad), 3);
        let mut bad = trace.clone();
        flip(&mut bad, 3, COL_PASS, COL_CHAIN);
        assert!(row_fails(&bad) <= 3);

        // A start whose capacity holds more than the one value sent.
        let mut bad = HashTableAir::generate_trace(&ops);
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&data);
        input[RATE] = Fp::new(9);
        input[RATE + 3] = Fp::ONE;
        let mut b = HashTraceBuilder::new(NUM_COLS);
        b.start(input);
        b.last_row_mut()[COL_DATA..COL_DATA + RATE].copy_from_slice(&data);
        bad.values[..NUM_COLS].copy_from_slice(b.last_row_mut());
        assert_eq!(row_fails(&bad), 0);

        // A start whose data is not what it hashes.
        let mut bad = trace.clone();
        bad.values[COL_DATA + 2] += Fp::ONE;
        assert_eq!(row_fails(&bad), 0);

        // An absorb or a compress on the first row, with nothing before it.
        let first = [HashOp::Start { data, cap: Fp::ZERO }, HashOp::Start { data, cap: Fp::ZERO }];
        let mut bad = HashTableAir::generate_trace(&first);
        flip(&mut bad, 0, COL_START, COL_ABSORB);
        assert_eq!(row_fails(&bad), 0);
        let mut bad = HashTableAir::generate_trace(&first);
        flip(&mut bad, 0, COL_START, COL_COMPRESS);
        assert_eq!(row_fails(&bad), 0);

        // An index that does not count the rows.
        let mut bad = trace.clone();
        bad.values[COL_INDEX] = Fp::ONE;
        assert_eq!(row_fails(&bad), 0);
        let mut bad = trace.clone();
        bad.values[2 * NUM_COLS + COL_INDEX] = Fp::new(7);
        assert_eq!(row_fails(&bad), 1);
    }

    /// Soundness audit of the table with its messages: the only cells
    /// free are those of pass rows that nothing reads (`data` and `dir`).
    #[test]
    fn the_free_cells_are_on_pass_rows() {
        let mut rng = Rng::new(72);
        let ops = random_ops(&mut rng, 11);
        let table = HashTableAir::generate_trace(&ops);
        let sender = sender_trace(&ops, &table);
        let survivors = mutation_audit(&[(&Sender, &sender, None), (&HashTableAir, &table, None)], &[], 64);
        let mut free = 0;
        for s in &survivors {
            let unused = s.row >= ops.len();
            let ok = match s.table {
                // An unused row of the sender sends nothing, whatever it holds.
                0 => unused && s.column < MESSAGE_LEN,
                _ => unused && (s.column == COL_DIR || (COL_DATA..COL_DATA + RATE).contains(&s.column)),
            };
            assert!(ok, "{}", audit_report(&survivors, |t, c| format!("table {t} column {c}")));
            free += usize::from(s.table == 1);
        }
        assert_eq!(free, (table.height() - ops.len()) * (RATE + 1));
    }

    #[test]
    fn prove_and_verify_with_the_messages() {
        let config = StarkConfig { log_blowup: 1, num_queries: 16, pow_bits: 0, zk: false, commit_bits: 0 };
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xc3));
            c
        };
        let mut rng = Rng::new(73);
        let ops = random_ops(&mut rng, 6);
        let table = HashTableAir::generate_trace(&ops);
        let sender = sender_trace(&ops, &table);
        let specs = [TableSpec { air: &Sender, pre_root: None }, TableSpec { air: &HashTableAir, pre_root: None }];
        let inputs = [
            TableInput { air: &Sender, trace: &sender, pre: None },
            TableInput { air: &HashTableAir, trace: &table, pre: None },
        ];
        let proof = prove_tables(&config, &inputs, &[], &mut tr());
        assert_eq!(verify_tables(&config, &specs, &[], &proof, &mut tr()), Ok(()));

        // A machine claiming a digest the table did not compute.
        let mut lying = sender.clone();
        lying.values[2 * S_COLS + 4 + RATE] += Fp::ONE;
        assert!(check_tables(&[(&Sender, &lying, None), (&HashTableAir, &table, None)], &[]).is_err());
    }
}
