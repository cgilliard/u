//! A straight-line machine for verifier programs: Fp4 arithmetic, hashing
//! and a write-once memory, as an AIR with lookups, proved together with
//! the [`crate::hash_table`] that performs its permutations.
//!
//! A program is a list of instructions executed one per row in order. Every
//! value lives in a write-once memory of `Fp4` words addressed by small
//! integers: an instruction reads its operands by address and writes its
//! result to a fresh address. Reads and writes are tied together by a LogUp
//! lookup (writes send `(addr, word)` with the number of reads as
//! multiplicity, reads receive), so a value produced on one row can be used
//! on any later row without register plumbing. Blocks of eight consecutive
//! addresses hold sponge blocks, digests and squeezed state.
//!
//! The program itself is a preprocessed table (see
//! [`crate::stark::Preprocessed`]): row `pc` holds the opcode flags and
//! fields of instruction `pc`, padded with `done` rows. Its commitment is
//! the program digest, public value 0..8, which a verifier computes from
//! the program and checks the proof against; the execution rows carry no
//! instruction columns of their own.
//!
//! | instruction      | fields                       | effect                                            |
//! |------------------|------------------------------|---------------------------------------------------|
//! | `Const`          | imm[4], out                  | mem[out] = imm                                    |
//! | `Input`          | out                          | mem[out] = witness                                |
//! | `Input8`         | out                          | mem[out+k] = witness, k < 8                       |
//! | `InputDot`       | out, pows, acc, acc_out      | as `Input8`, and mem[acc_out] = mem[acc] + sum_k mem[out+k] mem[pows+k] |
//! | `MulAdd`         | a, b, d, out                 | mem[out] = mem[a] * mem[b] + mem[d]               |
//! | `AssertEq`       | a, b                         | mem[a] == mem[b]                                  |
//! | `Decompose`      | a, out                       | mem[out+k] = bits 4k..4k+4 of the scalar mem[a]   |
//! | `Select`         | src, comp[4], out            | mem[out] = (mem[src].comp, 0, 0, 0)               |
//! | `SpongeStart`    | data, cap0                   | state = [mem[data..+8] scalars | cap0, 0, ...]    |
//! | `Absorb`         | data                         | add mem[data..+8] into the rate, permute          |
//! | `Compress`       | sib, dir, comp[4]            | Merkle step with sibling block and direction bit  |
//! | `CompressIn`     | dir, comp[4]                 | as `Compress`, the sibling eight witness scalars  |
//! | `Squeeze`        | out                          | mem[out+k] = (rate[k], 0, 0, 0)                   |
//! | `AssertPublic`   |                              | digest == public value 8..16                      |
//!
//! Scalars are words whose last three components are zero; the hashing
//! instructions enforce that on what they read. Public values: the program
//! digest (8) and the output digest (8).
//!
//! Hashing instructions (`SpongeStart`, `Absorb`, `Compress`,
//! `CompressIn`) send their
//! operands and the resulting digest to the hash table, numbered by a
//! counter of hashing instructions; the digest register holds the result
//! of the last one for `Squeeze` and `AssertPublic`. An absorb continues
//! the sponge of the hashing instruction just before it, which must be a
//! start or an absorb.

use crate::error::Error;
pub use crate::expr::Addr;
use crate::ext::{DEGREE, Fp4, W};
use crate::field::Field;
use crate::hash_table::{HashOp, HashTableAir, KIND_ABSORB, KIND_COMPRESS, message};
use crate::merkle::Digest;
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, permute};
use crate::stark::{Air, Builder, Preprocessed, StarkConfig, TableInput, TableSpec, Trace};

const FIELDS: usize = 6;
const READS: usize = 9;
const WRITES: usize = 9;

// ---- preprocessed columns (opcode order) ----
pub const P_CONST: usize = 0;
pub const P_INPUT: usize = 1;
pub const P_INPUT8: usize = 2;
pub const P_DOT: usize = 3;
pub const P_MULADD: usize = 4;
pub const P_ASSERT_EQ: usize = 5;
pub const P_DECOMP: usize = 6;
pub const P_SELECT: usize = 7;
pub const P_SSTART: usize = 8;
pub const P_ABSORB: usize = 9;
pub const P_COMPRESS: usize = 10;
pub const P_COMPRESS_IN: usize = 11;
pub const P_SQUEEZE: usize = 12;
pub const P_ASSERT_PUB: usize = 13;
pub const NUM_OPS: usize = 14;
pub const P_DONE: usize = NUM_OPS;
pub const P_F: usize = P_DONE + 1; // [FIELDS]
pub const PRE_WIDTH: usize = P_F + FIELDS;

// ---- main columns ----
pub const C_READ: usize = 0; // [READS][4]
pub const C_WRITE: usize = C_READ + READS * DEGREE; // [WRITES][4]
pub const C_MULT: usize = C_WRITE + WRITES * DEGREE; // [WRITES]
/// Products of the top bits of a decomposition, for its range check.
pub const C_T2: usize = C_MULT + WRITES;
pub const C_T3: usize = C_T2 + 1;
/// Digest of the last hashing instruction up to this row.
pub const C_ACC: usize = C_T3 + 1; // [DIGEST]
/// Number of hashing instructions before this row.
pub const C_HASHES: usize = C_ACC + DIGEST;
pub const NUM_COLS: usize = C_HASHES + 1;

pub const PUB_PROGRAM: usize = 0;
pub const PUB_OUTPUT: usize = DIGEST;
pub const NUM_PUBLIC: usize = 2 * DIGEST;

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

/// `Fp4` multiplication on components over any field.
pub fn ext_mul<F: Field>(a: &[F; DEGREE], b: &[F; DEGREE]) -> [F; DEGREE] {
    let w: F = W.into();
    [
        a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
        a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * (a[3] * b[3]),
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
    ]
}

// ---------------------------------------------------------------------------
// Instructions and programs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instr {
    Const {
        imm: Fp4,
        out: Addr,
    },
    Input {
        out: Addr,
    },
    Input8 {
        out: Addr,
    },
    InputDot {
        out: Addr,
        pows: Addr,
        acc: Addr,
        acc_out: Addr,
    },
    MulAdd {
        a: Addr,
        b: Addr,
        d: Addr,
        out: Addr,
    },
    AssertEq {
        a: Addr,
        b: Addr,
    },
    Decompose {
        a: Addr,
        out: Addr,
    },
    Select {
        src: Addr,
        comp: u8,
        out: Addr,
    },
    SpongeStart {
        data: Addr,
        cap0: Fp,
    },
    Absorb {
        data: Addr,
    },
    Compress {
        sib: Addr,
        dir: Addr,
        comp: u8,
    },
    /// A Merkle step whose sibling is the next eight witness values, not
    /// read from memory: a sibling is unchecked data either way, and this
    /// saves the `Input8` row that would load it.
    CompressIn {
        dir: Addr,
        comp: u8,
    },
    Squeeze {
        out: Addr,
    },
    AssertPublic,
}

impl Instr {
    fn opcode(&self) -> usize {
        match self {
            Instr::Const { .. } => P_CONST,
            Instr::Input { .. } => P_INPUT,
            Instr::Input8 { .. } => P_INPUT8,
            Instr::InputDot { .. } => P_DOT,
            Instr::MulAdd { .. } => P_MULADD,
            Instr::AssertEq { .. } => P_ASSERT_EQ,
            Instr::Decompose { .. } => P_DECOMP,
            Instr::Select { .. } => P_SELECT,
            Instr::SpongeStart { .. } => P_SSTART,
            Instr::Absorb { .. } => P_ABSORB,
            Instr::Compress { .. } => P_COMPRESS,
            Instr::CompressIn { .. } => P_COMPRESS_IN,
            Instr::Squeeze { .. } => P_SQUEEZE,
            Instr::AssertPublic => P_ASSERT_PUB,
        }
    }

    /// Witness values this instruction consumes.
    fn num_inputs(&self) -> usize {
        match self {
            Instr::Input { .. } => 1,
            Instr::Input8 { .. } | Instr::InputDot { .. } | Instr::CompressIn { .. } => 8,
            _ => 0,
        }
    }

    fn fields(&self) -> [Fp; FIELDS] {
        let a = |x: Addr| Fp::new(x);
        let onehot = |c: u8, f: &mut [Fp; FIELDS], at: usize| f[at + c as usize] = Fp::ONE;
        let mut f = [Fp::ZERO; FIELDS];
        match *self {
            Instr::Const { imm, out } => {
                f[..4].copy_from_slice(&imm.0);
                f[4] = a(out);
            }
            Instr::Input { out } | Instr::Input8 { out } => f[0] = a(out),
            Instr::InputDot { out, pows, acc, acc_out } => {
                f[0] = a(out);
                f[1] = a(pows);
                f[2] = a(acc);
                f[3] = a(acc_out);
            }
            Instr::MulAdd { a: x, b, d, out } => {
                f[0] = a(x);
                f[1] = a(b);
                f[2] = a(d);
                f[3] = a(out);
            }
            Instr::AssertEq { a: x, b } => {
                f[0] = a(x);
                f[1] = a(b);
            }
            Instr::Decompose { a: x, out } => {
                f[0] = a(x);
                f[1] = a(out);
            }
            Instr::Select { src, comp, out } => {
                f[0] = a(src);
                onehot(comp, &mut f, 1);
                f[5] = a(out);
            }
            Instr::SpongeStart { data, cap0 } => {
                f[0] = a(data);
                f[1] = cap0;
            }
            Instr::Absorb { data } => f[0] = a(data),
            Instr::Compress { sib, dir, comp } => {
                f[0] = a(sib);
                f[1] = a(dir);
                onehot(comp, &mut f, 2);
            }
            Instr::CompressIn { dir, comp } => {
                f[1] = a(dir);
                onehot(comp, &mut f, 2);
            }
            Instr::Squeeze { out } => f[0] = a(out),
            Instr::AssertPublic => {}
        }
        f
    }

    /// The words this instruction writes, as `(slot, address)`: fixed by
    /// the program, whatever the witness.
    fn each_write(&self, mut f: impl FnMut(usize, Addr)) {
        match *self {
            Instr::Const { out, .. } | Instr::Input { out } | Instr::MulAdd { out, .. } | Instr::Select { out, .. } => {
                f(0, out)
            }
            Instr::Input8 { out } | Instr::Decompose { out, .. } | Instr::Squeeze { out } => {
                (0..8).for_each(|k| f(k, out + k as Addr))
            }
            Instr::InputDot { out, acc_out, .. } => {
                (0..8).for_each(|k| f(k, out + k as Addr));
                f(8, acc_out);
            }
            _ => {}
        }
    }

    fn is_hash(&self) -> bool {
        matches!(
            self,
            Instr::SpongeStart { .. } | Instr::Absorb { .. } | Instr::Compress { .. } | Instr::CompressIn { .. }
        )
    }

    /// The preprocessed row of this instruction.
    fn pre_row(&self) -> [Fp; PRE_WIDTH] {
        let mut row = [Fp::ZERO; PRE_WIDTH];
        row[self.opcode()] = Fp::ONE;
        row[P_F..].copy_from_slice(&self.fields());
        row
    }
}

/// A program under construction, with an address allocator.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub instrs: Vec<Instr>,
    next_addr: Addr,
    num_inputs: usize,
    /// Padding rows both tables keep at their ends (see [`Program::reserve`]).
    reserved: usize,
}

impl Program {
    pub fn new() -> Program {
        Program::default()
    }

    /// Reserves `n` consecutive fresh addresses.
    pub fn alloc(&mut self, n: u32) -> Addr {
        let a = self.next_addr;
        self.next_addr += n;
        a
    }

    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    fn push(&mut self, ins: Instr) {
        self.num_inputs += ins.num_inputs();
        self.instrs.push(ins);
    }

    pub fn constant(&mut self, v: Fp4) -> Addr {
        let out = self.alloc(1);
        self.push(Instr::Const { imm: v, out });
        out
    }

    pub fn scalar(&mut self, v: Fp) -> Addr {
        self.constant(Fp4::from_base(v))
    }

    /// Next witness value, at a fresh address.
    pub fn input(&mut self) -> Addr {
        let out = self.alloc(1);
        self.input_at(out)
    }

    /// Next witness value, at a caller-chosen address.
    pub fn input_at(&mut self, out: Addr) -> Addr {
        self.push(Instr::Input { out });
        out
    }

    /// Eight witness values at eight fresh consecutive addresses, one row.
    pub fn input8(&mut self) -> Addr {
        let out = self.alloc(8);
        self.input8_at(out)
    }

    /// Eight witness values at `out..out + 8`, one row.
    pub fn input8_at(&mut self, out: Addr) -> Addr {
        self.push(Instr::Input8 { out });
        out
    }

    /// Eight witness values at eight fresh addresses, and their dot product
    /// with the eight words at `pows` added to `acc`. Returns `(out,
    /// acc_out)`.
    pub fn input_dot(&mut self, pows: Addr, acc: Addr) -> (Addr, Addr) {
        let out = self.alloc(8);
        let acc_out = self.input_dot_at(out, pows, acc);
        (out, acc_out)
    }

    /// As [`Program::input_dot`] with the values written at `out..out + 8`.
    pub fn input_dot_at(&mut self, out: Addr, pows: Addr, acc: Addr) -> Addr {
        let acc_out = self.alloc(1);
        self.push(Instr::InputDot { out, pows, acc, acc_out });
        acc_out
    }

    /// `n` witness values at consecutive addresses.
    pub fn inputs(&mut self, n: u32) -> Addr {
        let base = self.alloc(n);
        for k in 0..n {
            self.input_at(base + k);
        }
        base
    }

    pub fn muladd_to(&mut self, a: Addr, b: Addr, d: Addr, out: Addr) -> Addr {
        self.push(Instr::MulAdd { a, b, d, out });
        out
    }

    pub fn muladd(&mut self, a: Addr, b: Addr, d: Addr) -> Addr {
        let out = self.alloc(1);
        self.muladd_to(a, b, d, out)
    }

    pub fn assert_eq(&mut self, a: Addr, b: Addr) {
        self.push(Instr::AssertEq { a, b });
    }

    /// Eight words holding the 31 bits of the scalar at `a`, four per word.
    pub fn decompose(&mut self, a: Addr) -> Addr {
        let out = self.alloc(8);
        self.push(Instr::Decompose { a, out });
        out
    }

    /// Component `comp` of the word at `src`, as a scalar word.
    pub fn component(&mut self, src: Addr, comp: u8) -> Addr {
        let out = self.alloc(1);
        self.push(Instr::Select { src, comp, out });
        out
    }

    /// Bit `i` (0..31) of a decomposition at `bits`, as a scalar word.
    pub fn bit(&mut self, bits: Addr, i: usize) -> Addr {
        self.component(bits + (i / 4) as Addr, (i % 4) as u8)
    }

    /// Starts a sponge with the eight scalars at `data` and capacity
    /// `[cap0, 0, ...]`.
    pub fn sponge_start(&mut self, data: Addr, cap0: Fp) {
        self.push(Instr::SpongeStart { data, cap0 });
    }

    pub fn absorb(&mut self, data: Addr) {
        self.push(Instr::Absorb { data });
    }

    /// Merkle step with the sibling digest at `sib` and direction bit
    /// component `comp` of the word at `dir`.
    pub fn compress(&mut self, sib: Addr, dir: Addr, comp: u8) {
        self.push(Instr::Compress { sib, dir, comp });
    }

    /// Merkle step with the sibling digest taken from the next eight
    /// witness values.
    pub fn compress_in(&mut self, dir: Addr, comp: u8) {
        self.push(Instr::CompressIn { dir, comp });
    }

    /// Writes the current digest (rate) to eight fresh words.
    pub fn squeeze(&mut self) -> Addr {
        let out = self.alloc(8);
        self.push(Instr::Squeeze { out });
        out
    }

    pub fn assert_public(&mut self) {
        self.push(Instr::AssertPublic);
    }

    /// Rows a trace for this program needs before padding.
    pub fn num_rows(&self) -> usize {
        self.instrs.len()
    }

    /// Keeps at least `rows` padding rows at the end of the machine table
    /// and of the hash table, as a zero-knowledge proof needs (see
    /// [`crate::stark::StarkConfig::blind_rows`]).
    pub fn reserve(&mut self, rows: usize) {
        self.reserved = rows;
    }

    /// Reserves rows so that the machine table has exactly `2^log_n` rows
    /// and the hash table `2^hash_log_n`, keeping the rows already
    /// reserved. Panics if that cannot be done (a table already taller, or
    /// the padding pushing the other over).
    pub fn pad_to(&mut self, log_n: usize, hash_log_n: usize) {
        let hashes = VmAir::hash_rows(self);
        let fill = |rows: usize, log: usize| ((1usize << log) / 2 + 1).saturating_sub(rows);
        self.reserved = self.reserved.max(fill(self.instrs.len(), log_n)).max(fill(hashes, hash_log_n));
        assert_eq!(self.height(), 1 << log_n, "program does not fit its padding");
        assert_eq!(VmAir::hash_height(self), 1 << hash_log_n, "program does not fit its hash padding");
    }

    /// Trace height: the instruction count and reserved rows rounded up
    /// to a power of two.
    pub fn height(&self) -> usize {
        (self.instrs.len() + self.reserved).max(2).next_power_of_two()
    }

    /// The preprocessed table: one row per instruction, then `done` rows.
    pub fn table(&self) -> Trace {
        let n = self.height();
        let mut values = Vec::with_capacity(n * PRE_WIDTH);
        for ins in &self.instrs {
            values.extend_from_slice(&ins.pre_row());
        }
        let mut done = [Fp::ZERO; PRE_WIDTH];
        done[P_DONE] = Fp::ONE;
        for _ in self.instrs.len()..n {
            values.extend_from_slice(&done);
        }
        Trace::new(values, PRE_WIDTH)
    }

    /// The committed program for proofs under `config`.
    pub fn preprocess(&self, config: &StarkConfig) -> Preprocessed {
        Preprocessed::new(&self.table(), config.log_blowup, config.quotient_stride(VmAir.max_constraint_degree()))
    }

    /// The program digest: root of the committed table.
    pub fn digest(&self, log_blowup: usize) -> Digest {
        Preprocessed::new(&self.table(), log_blowup, 1 << log_blowup).root()
    }
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

pub struct VmAir;

impl Air for VmAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    /// Lookup terms are paired: a read or write denominator has degree two
    /// (addresses are selected by program flags), so a pair's constraint
    /// has degree five, which takes four quotient chunks instead of two
    /// but nearly halves the auxiliary columns.
    fn max_constraint_degree(&self) -> usize {
        5
    }

    fn lookup_group(&self) -> usize {
        2
    }

    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }

    #[allow(clippy::needless_range_loop)]
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let l = b.local();
        let n = b.next();
        let p = b.preprocessed();
        let pn = b.preprocessed_next();
        let public = b.public();
        let one = F::ONE;
        let zero = F::ZERO;

        // ---- instruction flags (from the committed program) ----
        b.mark("row types");
        let t_const = p[P_CONST];
        let t_input = p[P_INPUT];
        let t_input8 = p[P_INPUT8];
        let t_dot = p[P_DOT];
        let t_muladd = p[P_MULADD];
        let t_assert = p[P_ASSERT_EQ];
        let t_decomp = p[P_DECOMP];
        let t_select = p[P_SELECT];
        let t_sstart = p[P_SSTART];
        let t_absorb = p[P_ABSORB];
        let t_compress = p[P_COMPRESS];
        let t_compress_in = p[P_COMPRESS_IN];
        let t_squeeze = p[P_SQUEEZE];
        let t_apub = p[P_ASSERT_PUB];
        let f: [F; FIELDS] = core::array::from_fn(|i| p[P_F + i]);

        // ---- hashing counter and digest register ----
        b.mark("hashing");
        let t_hash = t_sstart + t_absorb + t_compress + t_compress_in;
        let t_hash_next = pn[P_SSTART] + pn[P_ABSORB] + pn[P_COMPRESS] + pn[P_COMPRESS_IN];
        b.when_first_row(l[C_HASHES]);
        b.when_transition(n[C_HASHES] - l[C_HASHES] - t_hash);
        for i in 0..DIGEST {
            // Zero until the first hash, set by hashing rows through their
            // message, carried by all others.
            b.when_first_row((one - t_hash) * l[C_ACC + i]);
            b.when_transition((one - t_hash_next) * (n[C_ACC + i] - l[C_ACC + i]));
            b.assert_zero(t_apub * (l[C_ACC + i] - public[PUB_OUTPUT + i]));
        }

        let read = |k: usize, c: usize| l[C_READ + k * DEGREE + c];
        let rv = |k: usize| -> [F; DEGREE] { core::array::from_fn(|c| read(k, c)) };
        let write = |k: usize, c: usize| l[C_WRITE + k * DEGREE + c];
        let wv = |k: usize| -> [F; DEGREE] { core::array::from_fn(|c| write(k, c)) };

        // ---- memory reads ----
        b.mark("reads");
        let block_ops = t_absorb + t_sstart + t_compress;
        for k in 0..READS {
            let (used, addr) = if k < 8 {
                let single = match k {
                    0 => t_muladd + t_assert + t_select + t_decomp,
                    1 => t_muladd + t_assert,
                    2 => t_muladd,
                    _ => zero,
                };
                let single_addr = match k {
                    0 => f[0],
                    1 => f[1],
                    2 => f[2],
                    _ => zero,
                };
                let kf = F::from_u32(k as u32);
                (single + block_ops + t_dot, single * single_addr + block_ops * (f[0] + kf) + t_dot * (f[1] + kf))
            } else {
                let t_dir = t_compress + t_compress_in;
                (t_dir + t_dot, t_dir * f[1] + t_dot * f[2])
            };
            let values = [addr, read(k, 0), read(k, 1), read(k, 2), read(k, 3)];
            b.lookup(false, used, &values);
        }
        // Hashing instructions read scalars, and send them with the
        // capacity (starts) or direction bit (compresses) and the resulting
        // digest to the hash table. The direction is component `comp` of
        // the dir word. A `CompressIn` reads no memory for its data: the
        // read columns hold its witness sibling, unconstrained but scalar.
        let data_ops = block_ops + t_compress_in;
        for k in 0..8 {
            for c in 1..DEGREE {
                b.assert_zero(data_ops * read(k, c));
            }
        }
        let kind = t_sstart
            + t_absorb.scale(Fp::new(KIND_ABSORB))
            + (t_compress + t_compress_in).scale(Fp::new(KIND_COMPRESS));
        let cap = t_sstart * f[1];
        let mut dir = zero;
        for c in 0..DEGREE {
            dir += f[2 + c] * read(8, c);
        }
        let data: [F; RATE] = core::array::from_fn(|k| read(k, 0));
        let digest: [F; DIGEST] = core::array::from_fn(|k| l[C_ACC + k]);
        b.lookup(true, t_hash, &message(l[C_HASHES], kind, cap, dir, data, digest));
        // AssertEq
        for c in 0..DEGREE {
            b.assert_zero(t_assert * (read(0, c) - read(1, c)));
        }

        // ---- memory writes ----
        b.mark("writes");
        let multi = t_decomp + t_squeeze + t_input8 + t_dot;
        let multi_base = t_decomp * f[1] + (t_squeeze + t_input8 + t_dot) * f[0];
        let single_w = t_const + t_input + t_muladd + t_select;
        let single_addr = t_const * f[4] + t_input * f[0] + t_muladd * f[3] + t_select * f[5];
        let prod = ext_mul(&rv(0), &rv(1));
        // InputDot: acc_out = acc + sum_k in_k * pow_k.
        let mut dot: [F; DEGREE] = rv(8);
        for k in 0..8 {
            let t = ext_mul(&wv(k), &rv(k));
            for c in 0..DEGREE {
                dot[c] += t[c];
            }
        }
        for k in 0..WRITES {
            let kf = F::from_u32(k as u32);
            let (used, addr) = match k {
                0 => (single_w + multi, single_addr + multi_base),
                1..=7 => (multi, multi_base + multi * kf),
                _ => (t_dot, t_dot * f[3]),
            };
            let mult = l[C_MULT + k];
            b.assert_zero(mult * (one - used));
            let values = [addr, write(k, 0), write(k, 1), write(k, 2), write(k, 3)];
            b.lookup(true, mult, &values);
            // value definitions
            for c in 0..DEGREE {
                let w = write(k, c);
                if k == 8 {
                    b.assert_zero(t_dot * (w - dot[c]));
                    continue;
                }
                let acc_c = if c == 0 { l[C_ACC + k] } else { zero };
                b.assert_zero(t_squeeze * (w - acc_c));
                if k == 0 {
                    b.assert_zero(t_const * (w - f[c]));
                    b.assert_zero(t_muladd * (w - prod[c] - read(2, c)));
                    let sel_val = if c == 0 { (0..DEGREE).fold(zero, |a, j| a + f[1 + j] * read(0, j)) } else { zero };
                    b.assert_zero(t_select * (w - sel_val));
                }
            }
        }

        // ---- decomposition ----
        // The 31 bits are the components of the eight written words; the
        // 32nd component is zero.
        b.mark("decompose");
        let bit = |i: usize| write(i / DEGREE, i % DEGREE);
        let mut value = zero;
        let mut low27 = zero;
        for i in 0..32 {
            b.assert_zero(t_decomp * (bit(i) * bit(i) - bit(i)));
            if i < 31 {
                value += bit(i) * pow2::<F>(i);
            }
            if i < 27 {
                low27 += bit(i) * pow2::<F>(i);
            }
        }
        b.assert_zero(t_decomp * bit(31));
        // Canonical: if bits 27..31 are all set the low bits are zero. The
        // products are forced to zero on other rows.
        let (t2, t3) = (l[C_T2], l[C_T3]);
        b.assert_eq(t2, t_decomp * bit(30) * bit(29));
        b.assert_eq(t3, t2 * bit(28));
        b.assert_zero(t3 * bit(27) * low27);
        b.assert_zero(t_decomp * (read(0, 0) - value));
        for c in 1..DEGREE {
            b.assert_zero(t_decomp * read(0, c));
        }
    }
}

// ---------------------------------------------------------------------------
// Execution and trace generation
// ---------------------------------------------------------------------------

/// Result of running a program natively.
pub struct Execution {
    /// Memory words in address order (`None` where never written).
    pub mem: Vec<Option<Fp4>>,
    /// Digest at the `AssertPublic` instruction, if any.
    pub output_digest: Option<[Fp; DIGEST]>,
    /// The permutations, in order.
    pub hashes: Vec<HashOp>,
    /// Digest of the last hashing instruction.
    pub digest: [Fp; DIGEST],
}

struct Machine<'a> {
    inputs: &'a [Fp4],
    next_input: usize,
    mem: Vec<Option<Fp4>>,
    reads: Vec<u32>,
}

impl Machine<'_> {
    fn read(&mut self, pc: usize, addr: Addr) -> Result<Fp4, Error> {
        let v = self.mem.get(addr as usize).copied().flatten().ok_or(Error::VmUninitialized { pc, addr })?;
        self.reads[addr as usize] += 1;
        Ok(v)
    }

    fn read_scalar(&mut self, pc: usize, addr: Addr) -> Result<Fp, Error> {
        let v = self.read(pc, addr)?;
        if v.0[1..].iter().any(|x| !x.is_zero()) {
            return Err(Error::VmNotScalar { pc, addr });
        }
        Ok(v.0[0])
    }

    fn read_block(&mut self, pc: usize, base: Addr) -> Result<[Fp; RATE], Error> {
        let mut out = [Fp::ZERO; RATE];
        for (k, o) in out.iter_mut().enumerate() {
            *o = self.read_scalar(pc, base + k as Addr)?;
        }
        Ok(out)
    }

    fn next_input(&mut self) -> Result<Fp4, Error> {
        let v = *self.inputs.get(self.next_input).ok_or(Error::VmInputs)?;
        self.next_input += 1;
        Ok(v)
    }

    fn write(&mut self, pc: usize, addr: Addr, v: Fp4) -> Result<(), Error> {
        let a = addr as usize;
        // Only a program whose instructions were not made by its own
        // allocator writes past what was laid out for it.
        if a >= self.mem.len() {
            self.mem.resize(a + 1, None);
            self.reads.resize(a + 1, 0);
        }
        if self.mem[a].is_some() {
            return Err(Error::VmDoubleWrite { pc, addr });
        }
        self.mem[a] = Some(v);
        Ok(())
    }
}

/// What one instruction read and wrote, in slot order: a row's cells. Held
/// on the stack, one for the whole run.
struct RowIo {
    reads: [Fp4; READS],
    num_reads: usize,
    writes: [Fp4; WRITES],
    num_writes: usize,
}

impl RowIo {
    fn read(&mut self, v: Fp4) {
        self.reads[self.num_reads] = v;
        self.num_reads += 1;
    }

    fn read_block(&mut self, block: &[Fp; RATE]) {
        block.iter().for_each(|x| self.read(Fp4::from_base(*x)));
    }

    fn write(&mut self, v: Fp4) {
        self.writes[self.num_writes] = v;
        self.num_writes += 1;
    }
}

impl VmAir {
    /// Runs `program` on `inputs`, checking assertions. Used both to compute
    /// witnesses and, inside [`VmAir::generate_trace`], to fill the trace.
    pub fn execute(program: &Program, inputs: &[Fp4]) -> Result<Execution, Error> {
        let (exec, _) = Self::run(program, inputs, None)?;
        Ok(exec)
    }

    /// Executes, and fills the rows of the main trace when `rows` is given:
    /// a row an instruction, all but the multiplicities of its writes,
    /// which are known only once every read has been counted. Returns the
    /// execution and how often each address was read.
    fn run(program: &Program, inputs: &[Fp4], mut rows: Option<&mut [Fp]>) -> Result<(Execution, Vec<u32>), Error> {
        let words = program.next_addr as usize;
        let mut m = Machine { inputs, next_input: 0, mem: vec![None; words], reads: vec![0; words] };
        let mut output_digest = None;
        let mut digest = [Fp::ZERO; DIGEST];
        let mut hashes: Vec<HashOp> = Vec::with_capacity(Self::hash_rows(program));
        // State after the last hashing instruction, when that was a start or
        // an absorb (which an absorb continues).
        let mut sponge: Option<[Fp; WIDTH]> = None;
        let mut io = RowIo { reads: [Fp4::ZERO; READS], num_reads: 0, writes: [Fp4::ZERO; WRITES], num_writes: 0 };
        for (pc, ins) in program.instrs.iter().enumerate() {
            (io.num_reads, io.num_writes) = (0, 0);
            let mut bits_val: Option<u32> = None;
            let mut hash_op: Option<HashOp> = None;
            let hash_index = hashes.len();
            match *ins {
                Instr::Const { imm, out } => {
                    m.write(pc, out, imm)?;
                    io.write(imm);
                }
                Instr::Input { out } => {
                    let v = m.next_input()?;
                    m.write(pc, out, v)?;
                    io.write(v);
                }
                Instr::Input8 { out } => {
                    for k in 0..8 {
                        let v = m.next_input()?;
                        m.write(pc, out + k as Addr, v)?;
                        io.write(v);
                    }
                }
                Instr::InputDot { out, pows, acc, acc_out } => {
                    let mut vals = [Fp4::ZERO; 8];
                    for v in vals.iter_mut() {
                        *v = m.next_input()?;
                    }
                    let mut sum = Fp4::ZERO;
                    for (k, v) in vals.iter().enumerate() {
                        let pw = m.read(pc, pows + k as Addr)?;
                        io.read(pw);
                        sum += *v * pw;
                    }
                    let a = m.read(pc, acc)?;
                    io.read(a);
                    for (k, v) in vals.iter().enumerate() {
                        m.write(pc, out + k as Addr, *v)?;
                        io.write(*v);
                    }
                    m.write(pc, acc_out, a + sum)?;
                    io.write(a + sum);
                }
                Instr::MulAdd { a, b, d, out } => {
                    let (x, y, z) = (m.read(pc, a)?, m.read(pc, b)?, m.read(pc, d)?);
                    [x, y, z].into_iter().for_each(|v| io.read(v));
                    let v = x * y + z;
                    m.write(pc, out, v)?;
                    io.write(v);
                }
                Instr::AssertEq { a, b } => {
                    let (x, y) = (m.read(pc, a)?, m.read(pc, b)?);
                    io.read(x);
                    io.read(y);
                    if x != y {
                        return Err(Error::VmAssertion(pc));
                    }
                }
                Instr::Decompose { a, out } => {
                    let x = m.read_scalar(pc, a)?;
                    io.read(Fp4::from_base(x));
                    let v = x.to_canonical();
                    bits_val = Some(v);
                    for k in 0..8 {
                        let word = Fp4(core::array::from_fn(|c| Fp::new((v >> (4 * k + c)) & 1)));
                        m.write(pc, out + k as Addr, word)?;
                        io.write(word);
                    }
                }
                Instr::Select { src, comp, out } => {
                    let x = m.read(pc, src)?;
                    io.read(x);
                    let v = Fp4::from_base(x.0[comp as usize]);
                    m.write(pc, out, v)?;
                    io.write(v);
                }
                Instr::SpongeStart { data, cap0 } => {
                    let block = m.read_block(pc, data)?;
                    io.read_block(&block);
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(&block);
                    input[RATE] = cap0;
                    let out = permute(input);
                    sponge = Some(out);
                    digest.copy_from_slice(&out[..DIGEST]);
                    hash_op = Some(HashOp::Start { data: block, cap: cap0 });
                }
                Instr::Absorb { data } => {
                    let block = m.read_block(pc, data)?;
                    io.read_block(&block);
                    let mut st = sponge.ok_or(Error::VmHashOrder(pc))?;
                    for (x, y) in st.iter_mut().zip(&block) {
                        *x = x.add(y);
                    }
                    let out = permute(st);
                    sponge = Some(out);
                    digest.copy_from_slice(&out[..DIGEST]);
                    hash_op = Some(HashOp::Absorb { data: block });
                }
                Instr::Compress { dir, comp, .. } | Instr::CompressIn { dir, comp } => {
                    if hashes.is_empty() {
                        return Err(Error::VmHashOrder(pc));
                    }
                    // The sibling: eight words of memory, or the next
                    // eight of the witness.
                    let sibling = match *ins {
                        Instr::Compress { sib, .. } => m.read_block(pc, sib)?,
                        _ => {
                            let mut sibling = [Fp::ZERO; DIGEST];
                            for x in sibling.iter_mut() {
                                let v = m.next_input()?;
                                if v.0[1..].iter().any(|y| !y.is_zero()) {
                                    return Err(Error::VmNotScalarInput(pc));
                                }
                                *x = v.0[0];
                            }
                            sibling
                        }
                    };
                    io.read_block(&sibling);
                    let d = m.read(pc, dir)?;
                    io.read(d);
                    let right = d.0[comp as usize] == Fp::ONE;
                    let mut st = [Fp::ZERO; WIDTH];
                    let (lo, hi) = if right { (&sibling, &digest) } else { (&digest, &sibling) };
                    st[..DIGEST].copy_from_slice(lo);
                    st[DIGEST..].copy_from_slice(hi);
                    let out = permute(st);
                    sponge = None;
                    digest.copy_from_slice(&out[..DIGEST]);
                    hash_op = Some(HashOp::Compress { sibling, right });
                }
                Instr::Squeeze { out } => {
                    for (k, d) in digest.iter().enumerate() {
                        let v = Fp4::from_base(*d);
                        m.write(pc, out + k as Addr, v)?;
                        io.write(v);
                    }
                }
                Instr::AssertPublic => {
                    output_digest = Some(digest);
                }
            }
            hashes.extend(hash_op);
            if let Some(trace) = rows.as_deref_mut() {
                let row = &mut trace[pc * NUM_COLS..(pc + 1) * NUM_COLS];
                row[C_HASHES] = Fp::new(hash_index as u32);
                row[C_ACC..C_ACC + DIGEST].copy_from_slice(&digest);
                for (k, v) in io.reads[..io.num_reads].iter().enumerate() {
                    row[C_READ + k * DEGREE..C_READ + (k + 1) * DEGREE].copy_from_slice(&v.0);
                }
                for (k, v) in io.writes[..io.num_writes].iter().enumerate() {
                    row[C_WRITE + k * DEGREE..C_WRITE + (k + 1) * DEGREE].copy_from_slice(&v.0);
                }
                if let Some(v) = bits_val {
                    let t2 = (v >> 30) & (v >> 29) & 1;
                    row[C_T2] = Fp::new(t2);
                    row[C_T3] = Fp::new(t2 & (v >> 28) & 1);
                }
            }
        }
        Ok((Execution { mem: m.mem, output_digest, hashes, digest }, m.reads))
    }

    /// Builds the traces for `program` on `inputs`: the machine's, of
    /// height [`Program::height`], and its hash table's. The program runs
    /// once: a write's multiplicity is how often its word is read, by any
    /// row, so those cells are filled when the run is over, each from the
    /// address its instruction names.
    pub fn generate_trace(program: &Program, inputs: &[Fp4]) -> Result<(Trace, Trace), Error> {
        let n = program.height();
        let used = program.instrs.len() * NUM_COLS;
        let mut rows = vec![Fp::ZERO; n * NUM_COLS];
        let (exec, counts) = Self::run(program, inputs, Some(&mut rows[..used]))?;
        for (ins, row) in program.instrs.iter().zip(rows.chunks_exact_mut(NUM_COLS)) {
            ins.each_write(|slot, addr| row[C_MULT + slot] = Fp::new(counts[addr as usize]));
        }
        for done in rows[used..].chunks_exact_mut(NUM_COLS) {
            done[C_ACC..C_ACC + DIGEST].copy_from_slice(&exec.digest);
            done[C_HASHES] = Fp::new(exec.hashes.len() as u32);
        }
        Ok((Trace::new(rows, NUM_COLS), HashTableAir::generate_trace_height(&exec.hashes, Self::hash_height(program))))
    }

    /// Height of the hash table for `program`.
    pub fn hash_height(program: &Program) -> usize {
        (Self::hash_rows(program) + program.reserved).max(2).next_power_of_two()
    }

    /// Rows of the hash table for `program`'s hashing instructions.
    pub fn hash_rows(program: &Program) -> usize {
        program.instrs.iter().filter(|i| i.is_hash()).count()
    }

    /// The two tables of a machine proof, from [`VmAir::generate_trace`].
    pub fn tables<'a>(main: &'a Trace, hashes: &'a Trace, program: &'a Preprocessed) -> [TableInput<'a>; 2] {
        [
            TableInput { air: &VmAir, trace: main, pre: Some(program) },
            TableInput { air: &HashTableAir, trace: hashes, pre: None },
        ]
    }

    /// The tables a verifier of a machine proof expects.
    pub fn specs(program_digest: &Digest) -> [TableSpec<'_>; 2] {
        [TableSpec { air: &VmAir, pre_root: Some(program_digest) }, TableSpec { air: &HashTableAir, pre_root: None }]
    }

    pub fn public_values(program_digest: &Digest, output_digest: &[Fp; DIGEST]) -> [Fp; NUM_PUBLIC] {
        let mut v = [Fp::ZERO; NUM_PUBLIC];
        v[..DIGEST].copy_from_slice(program_digest);
        v[DIGEST..].copy_from_slice(output_digest);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::merkle::{MerkleTree, hash_row};
    use crate::poseidon2::hash;
    use crate::stark::{StarkConfig, check_tables, measure_degree, prove_tables, verify_tables};
    use crate::test_util::Rng;

    fn tr() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0xf6));
        c
    }

    /// Builds a program exercising every instruction. Returns the program,
    /// its inputs, and the expected output digest.
    fn sample_program(rng: &mut Rng) -> (Program, Vec<Fp4>, [Fp; DIGEST]) {
        let mut p = Program::new();
        let mut inputs = Vec::new();
        let one = p.constant(Fp4::ONE);
        let zero = p.constant(Fp4::ZERO);
        // y = x^3 + 7, asserted against a witness.
        let x_val = rng.fp4();
        let x = p.input();
        inputs.push(x_val);
        let x2 = p.muladd(x, x, zero);
        let seven = p.constant(Fp4::from_u32(7));
        let y = p.muladd(x2, x, seven);
        let y_in = p.input();
        inputs.push(x_val * x_val * x_val + Fp4::from_u32(7));
        p.assert_eq(y, y_in);
        // A sponge hash of eight witness scalars (one block input) equals
        // the native hash.
        let block_vals: Vec<Fp> = (0..8).map(|_| rng.fp()).collect();
        let block = p.input8();
        inputs.extend(block_vals.iter().map(|v| Fp4::from_base(*v)));
        p.sponge_start(block, Fp::from_u32(8));
        let digest = p.squeeze();
        let expected = hash(&block_vals);
        for (i, e) in expected.iter().enumerate() {
            let c = p.scalar(*e);
            p.assert_eq(digest + i as Addr, c);
        }
        // A dot product of eight witness words with eight constants.
        let pows = p.alloc(8);
        let pow_vals: Vec<Fp4> = (0..8).map(|_| rng.fp4()).collect();
        for (k, v) in pow_vals.iter().enumerate() {
            let c = p.constant(*v);
            p.muladd_to(c, one, zero, pows + k as Addr);
        }
        let dot_vals: Vec<Fp4> = (0..8).map(|_| rng.fp4()).collect();
        let (dot_in, acc_out) = p.input_dot(pows, y);
        inputs.extend(dot_vals.iter().copied());
        let want =
            dot_vals.iter().zip(&pow_vals).fold(x_val * x_val * x_val + Fp4::from_u32(7), |a, (v, w)| a + *v * *w);
        let want_c = p.constant(want);
        p.assert_eq(acc_out, want_c);
        let d3 = p.constant(dot_vals[3]);
        p.assert_eq(dot_in + 3, d3);
        // Merkle path: leaf = hash([v]) with index bits from a decomposition.
        let rows: Vec<Vec<Fp>> = (0..16).map(|i| vec![Fp::new(100 + i)]).collect();
        let tree = MerkleTree::new(&rows);
        let index = 11usize;
        let idx = p.input();
        inputs.push(Fp4::from_u32(index as u32));
        let bits = p.decompose(idx);
        let leaf_block = p.alloc(8);
        let v = p.scalar(rows[index][0]);
        p.muladd_to(v, one, zero, leaf_block);
        for k in 1..8 {
            p.muladd_to(zero, one, zero, leaf_block + k);
        }
        p.sponge_start(leaf_block, Fp::ONE);
        let leaf = p.squeeze();
        let want_leaf = hash_row(&rows[index]);
        for (i, e) in want_leaf.iter().enumerate() {
            let c = p.scalar(*e);
            p.assert_eq(leaf + i as Addr, c);
        }
        // Levels alternate between a loaded sibling and a witness one.
        for (level, sib) in tree.open(index).iter().enumerate() {
            let (dir, comp) = (bits + (level / 4) as Addr, (level % 4) as u8);
            if level % 2 == 0 {
                let sib_addr = p.input8();
                p.compress(sib_addr, dir, comp);
            } else {
                p.compress_in(dir, comp);
            }
            inputs.extend(sib.iter().map(|v| Fp4::from_base(*v)));
        }
        let root = p.squeeze();
        for (i, e) in tree.root().iter().enumerate() {
            let c = p.scalar(*e);
            p.assert_eq(root + i as Addr, c);
        }
        // Bit extraction: bit 3 of 11 is 1, bit 2 is 0.
        let b3 = p.bit(bits, 3);
        let b2 = p.bit(bits, 2);
        p.assert_eq(b3, one);
        p.assert_eq(b2, zero);
        // Output digest over y's first component and half the root.
        let out_scalars = p.alloc(8);
        let y0 = p.component(y, 0);
        for i in 0..4 {
            p.muladd_to(y0, one, zero, out_scalars + i);
        }
        for i in 4..8 {
            p.muladd_to(root + (i as Addr - 4), one, zero, out_scalars + i);
        }
        p.sponge_start(out_scalars, Fp::ZERO);
        p.assert_public();
        let exec = VmAir::execute(&p, &inputs).unwrap();
        (p, inputs, exec.output_digest.unwrap())
    }

    #[test]
    fn layout_and_degree() {
        assert_eq!(measure_degree(&VmAir, NUM_PUBLIC), 5);
        assert_eq!(measure_degree(&HashTableAir, NUM_PUBLIC), 3);
        assert_eq!(NUM_COLS, 92);
    }

    /// Degrees-of-freedom audit (`stark::freedom_report`) of a sample
    /// program's machine trace and its hash table: no row may let its
    /// cells move together unseen, but a padding row's unused permutation.
    #[test]
    fn has_no_unintended_freedom() {
        let mut rng = Rng::new(70);
        let (p, inputs, out) = sample_program(&mut rng);
        let (trace, hashes) = VmAir::generate_trace(&p, &inputs).unwrap();
        let table = p.table();
        let public = VmAir::public_values(&p.digest(1), &out);
        assert_eq!(
            crate::stark::check_tables(&[(&VmAir, &trace, Some(&table)), (&HashTableAir, &hashes, None)], &public),
            Ok(())
        );
        let vm =
            crate::stark::audit::freedom_report(&VmAir, &trace, Some(&table), &public, &[], trace.height(), |_| true);
        assert!(vm.is_empty(), "machine: {} freedoms:\n{}", vm.len(), vm.join("\n"));
        let pass = crate::hash_machine::COL_PASS;
        let h = crate::stark::audit::freedom_report(&HashTableAir, &hashes, None, &public, &[], hashes.height(), |f| {
            // Padding rows are pass rows: their permutation is not used.
            !(hashes.row(f.row)[pass] == Fp::ONE && f.cells.iter().all(|(c, _)| *c < crate::poseidon2_air::NUM_COLS))
        });
        assert!(h.is_empty(), "hash table: {} freedoms:\n{}", h.len(), h.join("\n"));
    }

    #[test]
    fn program_executes_and_satisfies_constraints() {
        let mut rng = Rng::new(70);
        let (p, inputs, out) = sample_program(&mut rng);
        assert_eq!(p.num_inputs(), inputs.len());
        let (trace, hashes) = VmAir::generate_trace(&p, &inputs).unwrap();
        assert_eq!(trace.height(), p.height());
        assert_eq!(hashes.height(), VmAir::hash_height(&p));
        let table = p.table();
        let public = VmAir::public_values(&p.digest(1), &out);
        let check = |trace: &Trace, hashes: &Trace, table: &Trace, public: &[Fp]| {
            check_tables(&[(&VmAir, trace, Some(table)), (&HashTableAir, hashes, None)], public)
        };
        assert_eq!(check(&trace, &hashes, &table, &public), Ok(()));
        // Wrong output digest.
        let mut bad = public;
        bad[PUB_OUTPUT + 7] += Fp::ONE;
        assert!(check(&trace, &hashes, &table, &bad).is_err());
        // A different permutation result, or hashes out of order.
        let mut bad = hashes.clone();
        bad.values[crate::hash_table::NUM_COLS + crate::hash_machine::COL_ACC] += Fp::ONE;
        assert!(check(&trace, &bad, &table, &public).is_err());
        let w = crate::hash_table::NUM_COLS;
        let mut bad = hashes.clone();
        let (r0, r1) = bad.values.split_at_mut(2 * w);
        r0[w..].swap_with_slice(&mut r1[..w]);
        assert!(check(&trace, &bad, &table, &public).is_err());
        // A wrong witness fails an assertion natively.
        let mut wrong = inputs.clone();
        wrong[1] += Fp4::ONE;
        assert!(matches!(VmAir::execute(&p, &wrong), Err(Error::VmAssertion(_))));
        // Tampering with a read value breaks the memory relation.
        let width = NUM_COLS;
        let r = p.instrs.iter().position(|i| matches!(i, Instr::MulAdd { .. })).unwrap();
        let mut bad = trace.clone();
        bad.values[r * width + C_READ] += Fp::ONE;
        assert!(check(&bad, &hashes, &table, &public).is_err());
        // A different program (one changed field) rejects the same trace.
        let mut other = table.clone();
        other.values[r * PRE_WIDTH + P_F] += Fp::ONE;
        assert!(check(&trace, &hashes, &other, &public).is_err());
        // A dot-product row with a wrong accumulator.
        let r = p.instrs.iter().position(|i| matches!(i, Instr::InputDot { .. })).unwrap();
        let mut bad = trace.clone();
        bad.values[r * width + C_WRITE + 8 * DEGREE] += Fp::ONE;
        assert!(check(&bad, &hashes, &table, &public).is_err());
        // A decomposition with a flipped bit, or of a non-canonical value.
        let r = p.instrs.iter().position(|i| matches!(i, Instr::Decompose { .. })).unwrap();
        let mut bad = trace.clone();
        bad.values[r * width + C_WRITE] = Fp::ONE - bad.values[r * width + C_WRITE];
        assert!(check(&bad, &hashes, &table, &public).is_err());
        // A witness sibling that differs from the hashed one.
        let r = p.instrs.iter().position(|i| matches!(i, Instr::CompressIn { .. })).unwrap();
        let mut bad = trace.clone();
        bad.values[r * width + C_READ + 2 * DEGREE] += Fp::ONE;
        assert!(check(&bad, &hashes, &table, &public).is_err());
        let mut bad = trace.clone();
        bad.values[r * width + C_READ + 2 * DEGREE + 1] += Fp::ONE;
        assert!(check(&bad, &hashes, &table, &public).is_err());
        let k = p.instrs[..r].iter().map(|i| i.num_inputs()).sum::<usize>();
        let mut wrong = inputs.clone();
        wrong[k + 2].0[1] = Fp::ONE;
        assert_eq!(VmAir::execute(&p, &wrong).err(), Some(Error::VmNotScalarInput(r)));
        // An absorb after a compress has no sponge to continue.
        let mut q = Program::new();
        let blk = q.input8();
        q.sponge_start(blk, Fp::ZERO);
        q.compress(blk, blk, 0);
        q.absorb(blk);
        assert_eq!(VmAir::execute(&q, &[Fp4::ZERO; 8]).err(), Some(Error::VmHashOrder(3)));
    }

    #[test]
    fn prove_and_verify_program() {
        let config = StarkConfig { log_blowup: 2, num_queries: 16, pow_bits: 0, zk: false, commit_bits: 0 };
        let mut rng = Rng::new(71);
        let (p, inputs, out) = sample_program(&mut rng);
        let (trace, hashes) = VmAir::generate_trace(&p, &inputs).unwrap();
        let pre = p.preprocess(&config);
        let public = VmAir::public_values(&pre.root(), &out);
        let proof = prove_tables(&config, &VmAir::tables(&trace, &hashes, &pre), &public, &mut tr());
        let root = pre.root();
        assert_eq!(verify_tables(&config, &VmAir::specs(&root), &public, &proof, &mut tr()), Ok(()));
        // The verifier of several tables, fuzzed.
        let (iters, seed) = crate::test_util::fuzz_params(200, 0xf022_7a);
        let verifies =
            |p: &crate::stark::Proof| verify_tables(&config, &VmAir::specs(&root), &public, p, &mut tr()).is_ok();
        let fuzz = crate::stark::audit::fuzz_proof(&proof, iters, seed, verifies);
        assert!(fuzz.accepted.is_empty() && fuzz.panicked.is_empty(), "seed {seed}: {fuzz:?}");
        let mut bad = public;
        bad[PUB_OUTPUT] += Fp::ONE;
        assert!(verify_tables(&config, &VmAir::specs(&root), &bad, &proof, &mut tr()).is_err());
        // Against another program's digest.
        let mut q = p.clone();
        q.assert_eq(0, 0);
        let other = q.digest(config.log_blowup);
        assert_ne!(other, pre.root());
        assert!(verify_tables(&config, &VmAir::specs(&other), &public, &proof, &mut tr()).is_err());
    }

    /// Each way a program refuses a witness, or is itself ill-formed.
    #[test]
    fn what_a_run_refuses() {
        let run = |p: &Program, inputs: &[Fp4]| VmAir::execute(p, inputs).err();
        // A word read before anything wrote it.
        let mut p = Program::new();
        let a = p.alloc(1);
        let one = p.constant(Fp4::ONE);
        p.muladd(a, one, one);
        assert_eq!(run(&p, &[]), Some(Error::VmUninitialized { pc: 1, addr: a }));
        // A word written twice.
        let mut p = Program::new();
        let a = p.input();
        p.input_at(a);
        assert_eq!(run(&p, &[Fp4::ONE; 2]), Some(Error::VmDoubleWrite { pc: 1, addr: a }));
        // Fewer witness values than the program takes.
        assert_eq!(run(&p, &[Fp4::ONE]), Some(Error::VmInputs));
        // A hash of a word that is not a scalar.
        let mut p = Program::new();
        let block = p.input8();
        p.sponge_start(block, Fp::ZERO);
        let mut inputs = [Fp4::ONE; 8];
        assert_eq!(run(&p, &inputs), None);
        inputs[5].0[2] = Fp::ONE;
        assert_eq!(run(&p, &inputs), Some(Error::VmNotScalar { pc: 1, addr: block + 5 }));
        // A decomposition of one, too.
        let mut p = Program::new();
        let x = p.input();
        p.decompose(x);
        assert_eq!(run(&p, &[Fp4::from_u32(77)]), None);
        assert_eq!(run(&p, &[inputs[5]]), Some(Error::VmNotScalar { pc: 1, addr: x }));
        // A compress, or an absorb, before any hash.
        for absorb in [false, true] {
            let mut p = Program::new();
            let block = p.input8();
            if absorb {
                p.absorb(block)
            } else {
                p.compress(block, block, 0)
            }
            assert_eq!(run(&p, &[Fp4::ONE; 8]), Some(Error::VmHashOrder(1)));
        }
        let mut p = Program::new();
        let block = p.input8();
        p.compress_in(block, 0);
        assert_eq!(run(&p, &[Fp4::ONE; 16]), Some(Error::VmHashOrder(1)));
    }

    /// A write's multiplicity is the reads of its word by every row, the
    /// later ones too: the trace is filled in one run and these cells after
    /// it.
    #[test]
    fn multiplicities_count_every_read() {
        let mut p = Program::new();
        let one = p.constant(Fp4::ONE);
        let unread = p.constant(Fp4::from_u32(5));
        let x = p.input();
        let block = p.input8();
        let y = p.muladd(x, x, one);
        p.muladd(y, x, one);
        p.sponge_start(block, Fp::ZERO);
        p.absorb(block);
        p.assert_eq(x, x);
        let _ = unread;
        let inputs = [Fp4::from_u32(3); 9];
        let (trace, hashes) = VmAir::generate_trace(&p, &inputs).unwrap();
        let mult = |row: usize, slot: usize| trace.row(row)[C_MULT + slot].to_canonical();
        // one: read by both muladds. unread: by none. x: twice by the
        // first muladd, once by the second, twice by the assertion.
        assert_eq!((mult(0, 0), mult(1, 0), mult(2, 0)), (2, 0, 5));
        // Each word of the block: by the start and by the absorb.
        assert!((0..8).all(|k| mult(3, k) == 2));
        // y: once; the second product: never.
        assert_eq!((mult(4, 0), mult(5, 0)), (1, 0));
        let public = VmAir::public_values(&p.digest(1), &[Fp::ZERO; DIGEST]);
        assert_eq!(
            check_tables(&[(&VmAir, &trace, Some(&p.table())), (&HashTableAir, &hashes, None)], &public),
            Ok(())
        );
        // One too many, or too few, and the memory does not balance.
        for delta in [Fp::ONE, Fp::ZERO - Fp::ONE] {
            let mut bad = trace.clone();
            bad.values[2 * NUM_COLS + C_MULT] += delta;
            assert!(
                check_tables(&[(&VmAir, &bad, Some(&p.table())), (&HashTableAir, &hashes, None)], &public).is_err()
            );
        }
    }

    /// Reserved rows and padding to given heights.
    #[test]
    fn heights() {
        let mut p = Program::new();
        let block = p.input8();
        p.sponge_start(block, Fp::ZERO);
        for _ in 0..5 {
            p.absorb(block);
        }
        assert_eq!((p.num_rows(), p.height(), VmAir::hash_rows(&p), VmAir::hash_height(&p)), (7, 8, 6, 8));
        // Six rows of padding push both tables to the next power of two.
        p.reserve(6);
        assert_eq!((p.height(), VmAir::hash_height(&p)), (16, 16));
        let mut q = p.clone();
        q.pad_to(6, 5);
        assert_eq!((q.height(), VmAir::hash_height(&q)), (64, 32));
        let (trace, hashes) = VmAir::generate_trace(&p, &[Fp4::ONE; 8]).unwrap();
        assert_eq!((trace.height(), hashes.height()), (16, 16));
    }
}
