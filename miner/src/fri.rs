//! FRI low-degree test over `Fp4` codewords on BabyBear cosets.
//!
//! The prover holds the evaluations of a polynomial `f` of degree below
//! `n / 2^log_blowup` on the coset `shift * H` of size `n`. In each round it
//! commits to the current codeword, receives a challenge `beta` from the
//! transcript and folds
//!
//! ```text
//! f'(x^2) = (f(x) + f(-x)) / 2 + beta * (f(x) - f(-x)) / (2x)
//! ```
//!
//! halving both the domain and the degree bound. Rounds fold by four where
//! they can: two binary folds in one round, the first with `beta` and the
//! second with `beta^2`, which is the same as
//! `f'(x^4) = f0(x^4) + beta f1(x^4) + beta^2 f2(x^4) + beta^3 f3(x^4)` for
//! `f(X) = sum_k X^k f_k(X^4)`. When `log_n - log_blowup` is odd the last
//! round folds by two. Once the degree bound reaches one the codeword must
//! be constant; that constant is sent in the clear. The verifier then checks
//! `num_queries` random positions: for each, it walks the rounds, verifying
//! Merkle openings and recomputing the fold.
//!
//! In a round of arity `a` on a domain of size `m`, leaf `i < m/a` holds
//! `c[i + k m/a]` for `k < a`: the values at `x, w x, .., w^(a-1) x` with
//! `w` a primitive `a`-th root of unity. The fold of leaf `i` lands at index
//! `i` of the next codeword, which lives in leaf `i mod m/(a a')` at
//! position `i / (m/(a a'))`. One opening per round therefore suffices.
//!
//! Several codewords of different sizes can be tested together: each
//! smaller one, evaluated on the coset `shift^(n/m) * H_m` that the folded
//! codeword reaches at size `m`, is added to the folded codeword at the
//! start of the round of that size. The round arities are chosen so that
//! every input size starts a round.
//!
//! Queries are sampled as indices into the full input domain. For every
//! query the verifier asks the enclosing protocol for the input values at
//! that index (index `i mod m` for an input of size `m`), which it must
//! compute from its own openings (in a STARK, the DEEP combination of the
//! trace and quotient rows there), and checks them against the committed
//! codewords.
//!
//! # Memory
//!
//! A verifier's work is on the stack. The rounds of a test follow from its
//! parameters ([`Schedule`]), at most one for each bit of the largest
//! domain, so what a verifier holds of them (a challenge and the domain of
//! each round, [`Verifier`]) is of fixed size, and a query is checked from
//! the opened values where they lie. [`verify`] checks an owned proof with
//! each opening's own path; a proof whose paths travel together
//! ([`crate::merkle::batch_root`]) is checked through [`Verifier`], which
//! leaves the trees to its caller.
//!
//! A prover holds each round's codeword, as the rows its tree commits to,
//! and the tree, until the queries are answered: about twice the bytes of
//! the input codewords. The rows are laid out once and folded from where
//! they lie.

use crate::challenger::Challenger;
use crate::error::Error;
use crate::ext::{DEGREE, Fp4, as_base};
use crate::merkle::{Digest, MerkleTree, verify as merkle_verify};
use crate::ntt::{TWO_ADICITY, inv_two, log2_strict, root_of_unity};
use crate::parallel::{par_chunks_mut, par_map};
use crate::poseidon2::{Fp, LANES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FriConfig {
    /// Rate is `2^-log_blowup`; the degree bound is `n >> log_blowup`.
    pub log_blowup: usize,
    /// Number of query positions checked by the verifier.
    pub num_queries: usize,
    /// Proof-of-work bits ground before the queries are sampled.
    pub pow_bits: usize,
    /// Target security of each folding challenge: before sampling it the
    /// prover grinds [`fold_grinding`] bits, so that the round's error,
    /// about `arity * size / |K|`, falls below `2^-commit_bits`. Zero for
    /// no grinding.
    pub commit_bits: usize,
}

/// `log2(p^4)` in 1/256 bits, rounded down: the size of the extension
/// field challenges come from.
const LOG_K_X256: i64 = 31_648;

/// `log2(x)` in 1/256 bits, rounded up (computed with integers only, so
/// every verifier derives the same grinding).
pub(crate) fn log2_x256_ceil(x: u128) -> i64 {
    assert!(x > 0);
    let k = 127 - x.leading_zeros() as i64;
    // The mantissa x / 2^k in [1, 2) with 62 fractional bits, rounded down.
    let mut y: u128 = if k >= 62 { x >> (k - 62) } else { x << (62 - k) };
    let mut frac = 0i64;
    for _ in 0..8 {
        y = (y * y) >> 62;
        frac <<= 1;
        if y >= 2 << 62 {
            y >>= 1;
            frac |= 1;
        }
    }
    // Truncation only ever lowers the estimate; one unit covers it.
    256 * k + frac + 1
}

/// Grinding bits that bring a challenge whose soundness error is `term /
/// |K|` (a count of bad challenges, from Schwartz-Zippel or a proximity
/// gap) to `target` bits of security: `ceil(target - log2(|K| / term))`,
/// and none for a zero target.
pub fn grinding_bits(target: usize, term: u128) -> usize {
    if target == 0 {
        return 0;
    }
    let need = target as i64 * 256 + log2_x256_ceil(term.max(1)) - LOG_K_X256;
    if need <= 0 { 0 } else { ((need + 255) / 256) as usize }
}

/// Grinding before the folding challenge of a round of `2^log_arity`-to-1
/// on a domain of `2^log_size` points.
pub fn fold_grinding(config: &FriConfig, log_arity: usize, log_size: usize) -> usize {
    grinding_bits(config.commit_bits, 1u128 << (log_arity + log_size))
}

/// One round of a query: the opened leaf (as many values as the round's
/// arity) and its Merkle path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryStep {
    pub values: Vec<Fp4>,
    pub path: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriProof {
    /// Merkle roots of the codewords of each round, first round first.
    pub commitments: Vec<Digest>,
    /// The constant final codeword.
    pub final_value: Fp4,
    /// Proof-of-work witness: observed after the final value, the next
    /// sample has `pow_bits` low zero bits. Zero when `pow_bits` is zero.
    pub pow_witness: Fp,
    /// Per round, the witness ground before its folding challenge (see
    /// [`fold_grinding`]); zero where the round needs none.
    pub fold_witnesses: Vec<Fp>,
    /// `num_queries` queries, each with one step per round.
    pub queries: Vec<Vec<QueryStep>>,
}

/// Finds the smallest witness `w` such that observing it makes the next
/// sample's low `bits` bits zero, and leaves `challenger` past that sample
/// as [`check_pow`] does. Candidates are tried in parallel, a batch per
/// thread at a time. With `bits == 0` the transcript is untouched and the
/// witness is zero.
pub fn grind(challenger: &mut Challenger, bits: usize) -> Fp {
    if bits == 0 {
        return Fp::ZERO;
    }
    const BATCH: u32 = 1 << 12;
    let lanes = LANES as u32;
    let threads = crate::parallel::threads() as u32;
    let mut start = 0u32;
    let w = loop {
        let hits = par_map(threads as usize, |t| {
            let lo = start + t as u32 * BATCH;
            (lo..lo + BATCH).step_by(LANES).find_map(|w0| {
                let ws: [Fp; LANES] = core::array::from_fn(|l| Fp::new(w0 + l as u32));
                let ok = challenger.zero_bits_after(&ws, bits);
                (0..lanes).find(|&l| ok[l as usize]).map(|l| w0 + l)
            })
        });
        if let Some(w) = hits.into_iter().flatten().next() {
            break w;
        }
        start += threads * BATCH;
        assert!(start < crate::poseidon2::P - threads * BATCH, "no proof-of-work witness found");
    };
    let w = Fp::new(w);
    assert!(check_pow(challenger, bits, w));
    w
}

/// Observes `witness` and checks that the next sample has `bits` low zero
/// bits. With `bits == 0` nothing is observed and the witness must be zero.
pub fn check_pow(challenger: &mut Challenger, bits: usize, witness: Fp) -> bool {
    if bits == 0 {
        return witness == Fp::ZERO;
    }
    challenger.observe(witness);
    challenger.sample_bits(bits) == 0
}

/// The scalars of a leaf, as hashed into the Merkle tree: its values'
/// coordinates in a row, read where they lie.
pub(crate) fn leaf_row(values: &[Fp4]) -> &[Fp] {
    as_base(values)
}

/// `f'(x^2)` from `a = f(x)`, `b = f(-x)` and `x_inv = 1/x`.
#[inline]
fn fold(a: Fp4, b: Fp4, x_inv: Fp, beta: Fp4) -> Fp4 {
    let even = a.add(&b).mul_base(&inv_two());
    let odd = a.sub(&b).mul_base(&inv_two().mul(&x_inv));
    even.add(&beta.mul(&odd))
}

/// Folds one opened leaf: `values[k]` is the codeword at `w^k x` for `w` a
/// primitive root of unity of order `values.len()` (two or four), with
/// `x_inv = 1/x` and `w_inv = 1/w`.
#[inline]
pub(crate) fn fold_leaf(values: &[Fp4], x_inv: Fp, w_inv: Fp, beta: Fp4) -> Fp4 {
    match values.len() {
        2 => fold(values[0], values[1], x_inv, beta),
        4 => {
            // Pairs at (x, -x) and (w x, -w x), then the pair (x^2, -x^2).
            let g0 = fold(values[0], values[2], x_inv, beta);
            let g1 = fold(values[1], values[3], x_inv.mul(&w_inv), beta);
            fold(g0, g1, x_inv.square(), beta.mul(&beta))
        }
        n => panic!("unsupported fri arity {n}"),
    }
}

/// Most rounds a test can have: each folds a bit away at least, and the
/// largest domain has [`TWO_ADICITY`] of them. Also the most codewords it
/// can test together, their sizes all different.
pub const MAX_ROUNDS: usize = TWO_ADICITY;

/// The rounds of a test, which follow from its parameters alone: for input
/// codewords of sizes `2^log_sizes[g]` (strictly decreasing), between
/// consecutive sizes, and from the last one down to the blowup, rounds
/// that fold by four and then one by two if the bit count is odd. So
/// every input's size starts a round, at whose start it is added in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    rounds: usize,
    inputs: usize,
    /// Per round: log2 of its arity, log2 of its domain's size, and the
    /// input added at its start (zero for none: the first input is the
    /// codeword the first round begins with).
    log_arity: [u8; MAX_ROUNDS],
    log_size: [u8; MAX_ROUNDS],
    inject: [u8; MAX_ROUNDS],
}

impl Schedule {
    /// The rounds for these sizes, or [`Error::ProofShape`] if they are none a test can
    /// have: no sizes, a domain beyond the field's subgroups, or sizes
    /// that do not strictly decrease to above the blowup.
    pub fn new(config: &FriConfig, log_sizes: &[usize]) -> Result<Schedule, Error> {
        let (&first, rest) = log_sizes.split_first().ok_or(Error::ProofShape)?;
        if first > TWO_ADICITY {
            return Err(Error::ProofShape);
        }
        let mut s = Schedule {
            rounds: 0,
            inputs: log_sizes.len(),
            log_arity: [0; MAX_ROUNDS],
            log_size: [0; MAX_ROUNDS],
            inject: [0; MAX_ROUNDS],
        };
        let mut cur = first;
        for (g, &stop) in rest.iter().chain([&config.log_blowup]).enumerate() {
            if stop >= cur {
                return Err(Error::ProofShape);
            }
            let mut inject = g;
            while cur > stop {
                let la = if cur - stop >= 2 { 2 } else { 1 };
                s.log_arity[s.rounds] = la as u8;
                s.log_size[s.rounds] = cur as u8;
                s.inject[s.rounds] = inject as u8;
                inject = 0;
                s.rounds += 1;
                cur -= la;
            }
        }
        Ok(s)
    }

    /// Number of folding rounds.
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// Number of input codewords.
    pub fn inputs(&self) -> usize {
        self.inputs
    }

    /// Log2 of the largest domain's size: the bits of a query's index.
    pub fn log_n(&self) -> usize {
        self.log_size[0] as usize
    }

    /// Log2 of round `r`'s arity: one or two.
    pub fn log_arity(&self, r: usize) -> usize {
        self.log_arity[..self.rounds][r] as usize
    }

    /// Log2 of the size of round `r`'s domain.
    pub fn log_size(&self, r: usize) -> usize {
        self.log_size[..self.rounds][r] as usize
    }

    /// Log2 of the number of leaves of round `r`'s tree: its height.
    pub fn log_leaves(&self, r: usize) -> usize {
        self.log_size(r) - self.log_arity(r)
    }

    /// The input added to the folded codeword at the start of round `r`
    /// (never the first, which round 0 begins with), if one is.
    pub fn injected(&self, r: usize) -> Option<usize> {
        Some(self.inject[..self.rounds][r] as usize).filter(|&g| g != 0)
    }
}

/// Log2 of the arity of each folding round for input codewords of sizes
/// `2^log_sizes[g]` (strictly decreasing): see [`Schedule`].
pub fn round_log_arities(config: &FriConfig, log_sizes: &[usize]) -> Vec<usize> {
    let s = Schedule::new(config, log_sizes).expect("codeword sizes must decrease and exceed the blowup");
    (0..s.rounds()).map(|r| s.log_arity(r)).collect()
}

/// Number of folding rounds for input codewords of sizes `2^log_sizes[g]`.
pub fn num_rounds(config: &FriConfig, log_sizes: &[usize]) -> usize {
    Schedule::new(config, log_sizes).expect("codeword sizes must decrease and exceed the blowup").rounds()
}

/// For every input after the first, the round at whose start it is added.
pub fn injection_rounds(config: &FriConfig, log_sizes: &[usize]) -> Vec<usize> {
    let s = Schedule::new(config, log_sizes).expect("codeword sizes must decrease and exceed the blowup");
    (0..s.rounds()).filter(|&r| s.injected(r).is_some()).collect()
}

/// Leaves a thread folds or lays out at a time.
const CHUNK: usize = 1 << 10;

/// Proves that each of `inputs` (strictly decreasing sizes) has degree
/// below its length `>> log_blowup`, where `inputs[0]` holds evaluations on
/// `shift * H` and an input of size `m` evaluations on `shift^(n/m) * H_m`.
/// The caller's transcript must be in the same state the verifier's will
/// be. Also returns the sampled query indices into the largest domain, so
/// the caller can open its own commitments at the same positions.
pub fn prove(
    config: &FriConfig,
    challenger: &mut Challenger,
    shift: Fp,
    inputs: Vec<Vec<Fp4>>,
) -> (FriProof, Vec<usize>) {
    let log_sizes: Vec<usize> = inputs.iter().map(|c| log2_strict(c.len())).collect();
    assert!(!log_sizes.is_empty(), "no codewords");
    assert!(log_sizes[0] <= TWO_ADICITY, "domain too large for query sampling");
    let schedule = Schedule::new(config, &log_sizes).expect("codeword sizes must decrease and exceed the blowup");
    let (log_n, rounds) = (log_sizes[0], schedule.rounds());
    let mut inputs = inputs.into_iter();
    let codeword = inputs.next().unwrap();
    let mut pending = inputs.peekable();

    // Each round's tree, and its codeword as the rows the tree commits to:
    // row `i` holds the codeword at `i + k * leaves`.
    let mut committed: Vec<(MerkleTree, Vec<Fp4>)> = Vec::with_capacity(rounds);
    let mut commitments = Vec::with_capacity(rounds);
    let mut fold_witnesses = Vec::with_capacity(rounds);
    let mut cur = codeword;
    let mut shift_r = shift;
    let mut omega_inv = root_of_unity(log_n).inverse().unwrap();

    for r in 0..rounds {
        let la = schedule.log_arity(r);
        if let Some(extra) = pending.next_if(|c| c.len() == cur.len()) {
            par_chunks_mut(&mut cur, 1 << 12, |c, chunk| {
                for (k, v) in chunk.iter_mut().enumerate() {
                    *v += extra[(c << 12) + k];
                }
            });
        }
        let arity = 1usize << la;
        let leaves = cur.len() >> la;
        let mut rows = vec![Fp4::ZERO; cur.len()];
        par_chunks_mut(&mut rows, CHUNK * arity, |c, chunk| {
            for (j, row) in chunk.chunks_exact_mut(arity).enumerate() {
                let i = c * CHUNK + j;
                for (k, v) in row.iter_mut().enumerate() {
                    *v = cur[i + k * leaves];
                }
            }
        });
        let tree = MerkleTree::from_flat(leaf_row(&rows), arity * DEGREE);
        challenger.observe_digest(&tree.root());
        fold_witnesses.push(grind(challenger, fold_grinding(config, la, log2_strict(cur.len()))));
        let beta = challenger.sample_ext();

        // x_i = shift_r * omega^i, so 1/x_i = shift_r^-1 * omega^-i; the
        // leaf's root of unity is omega^leaves.
        let w_inv = omega_inv.pow(leaves as u64);
        let shift_inv = shift_r.inverse().unwrap();
        // The next codeword takes this one's buffer: a quarter or a half of it.
        cur.truncate(leaves);
        cur.shrink_to_fit();
        par_chunks_mut(&mut cur, CHUNK, |c, chunk| {
            let start = c * CHUNK;
            let mut x_inv = shift_inv.mul(&omega_inv.pow(start as u64));
            for (j, out) in chunk.iter_mut().enumerate() {
                *out = fold_leaf(&rows[(start + j) * arity..][..arity], x_inv, w_inv, beta);
                x_inv = x_inv.mul(&omega_inv);
            }
        });

        commitments.push(tree.root());
        committed.push((tree, rows));
        for _ in 0..la {
            shift_r = shift_r.square();
            omega_inv = omega_inv.square();
        }
    }

    debug_assert!(pending.next().is_none());
    // For an honest prover the final codeword is constant. A dishonest one
    // may send anything here; the query phase is what catches it.
    let final_value = cur[0];
    challenger.observe_ext(&final_value);
    let pow_witness = grind(challenger, config.pow_bits);

    let mut queries = Vec::with_capacity(config.num_queries);
    let mut indices = Vec::with_capacity(config.num_queries);
    for _ in 0..config.num_queries {
        let mut index = challenger.sample_bits(log_n);
        indices.push(index);
        let mut steps = Vec::with_capacity(rounds);
        for (r, (tree, rows)) in committed.iter().enumerate() {
            let arity = 1usize << schedule.log_arity(r);
            index %= tree.len();
            steps.push(QueryStep { values: rows[index * arity..][..arity].to_vec(), path: tree.open(index) });
        }
        queries.push(steps);
    }

    (FriProof { commitments, final_value, pow_witness, fold_witnesses, queries }, indices)
}

/// A verifier past the commitments of a proof: each round's challenge and
/// domain, held in place. What remains is the queries, one at a time
/// ([`Verifier::query`]).
#[derive(Clone, Debug)]
pub struct Verifier {
    schedule: Schedule,
    final_value: Fp4,
    betas: [Fp4; MAX_ROUNDS],
    /// Round `r` lives on `shift_r * H`: the inverses of `shift_r`, of
    /// `H`'s generator and of its leaves' root of unity.
    shift_invs: [Fp; MAX_ROUNDS],
    omega_invs: [Fp; MAX_ROUNDS],
    w_invs: [Fp; MAX_ROUNDS],
}

impl Verifier {
    /// Replays the commitments of a proof for input codewords of sizes
    /// `2^log_sizes[g]` in the transcript: each round's root, its ground
    /// witness and its challenge, then the final value and the witness
    /// ground before the queries. The transcript is left where the
    /// queries' indices are sampled ([`Verifier::sample_index`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &FriConfig,
        challenger: &mut Challenger,
        shift: Fp,
        log_sizes: &[usize],
        commitments: &[Digest],
        fold_witnesses: &[Fp],
        final_value: &Fp4,
        pow_witness: Fp,
    ) -> Result<Verifier, Error> {
        let schedule = Schedule::new(config, log_sizes)?;
        let rounds = schedule.rounds();
        if commitments.len() != rounds || fold_witnesses.len() != rounds {
            return Err(Error::ProofShape);
        }
        let mut v = Verifier {
            schedule,
            final_value: *final_value,
            betas: [Fp4::ZERO; MAX_ROUNDS],
            shift_invs: [Fp::ZERO; MAX_ROUNDS],
            omega_invs: [Fp::ZERO; MAX_ROUNDS],
            w_invs: [Fp::ZERO; MAX_ROUNDS],
        };
        let mut s_inv = shift.inverse().ok_or(Error::ProofShape)?;
        let mut w_inv = root_of_unity(schedule.log_n()).inverse().unwrap();
        for r in 0..rounds {
            let la = schedule.log_arity(r);
            challenger.observe_digest(&commitments[r]);
            if !check_pow(challenger, fold_grinding(config, la, schedule.log_size(r)), fold_witnesses[r]) {
                return Err(Error::FriGrinding);
            }
            v.betas[r] = challenger.sample_ext();
            v.shift_invs[r] = s_inv;
            v.omega_invs[r] = w_inv;
            v.w_invs[r] = w_inv.pow(1u64 << schedule.log_leaves(r));
            for _ in 0..la {
                s_inv = s_inv.square();
                w_inv = w_inv.square();
            }
        }
        challenger.observe_ext(final_value);
        if !check_pow(challenger, config.pow_bits, pow_witness) {
            return Err(Error::FriGrinding);
        }
        Ok(v)
    }

    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// The next query's index into the largest domain, from the transcript.
    pub fn sample_index(&self, challenger: &mut Challenger) -> usize {
        challenger.sample_bits(self.schedule.log_n())
    }

    /// Checks query `q` at `index`: `inputs` are the input codewords'
    /// values there (the input of size `m` at `index mod m`), one for each,
    /// computed independently of the proof's FRI part; `leaf(round)` is the
    /// leaf the proof opens in each round, `None` if it has none.
    ///
    /// That a leaf is its round's tree's is asked of `opened(round, leaf
    /// index, values)`: it checks the opening there and then, or notes it
    /// and answers `true`, to check a round's openings together after the
    /// queries ([`crate::merkle::batch_root`]). The query holds only if
    /// they are checked.
    pub fn query<'v>(
        &self,
        q: usize,
        index: usize,
        inputs: &[Fp4],
        mut leaf: impl FnMut(usize) -> Option<&'v [Fp4]>,
        mut opened: impl FnMut(usize, usize, &[Fp4]) -> bool,
    ) -> Result<(), Error> {
        let s = &self.schedule;
        if inputs.len() != s.inputs() || index >> s.log_n() != 0 {
            return Err(Error::ProofShape);
        }
        let mut index = index;
        let mut folded = inputs[0];
        for r in 0..s.rounds() {
            let values = leaf(r).ok_or(Error::ProofShape)?;
            if values.len() != 1 << s.log_arity(r) {
                return Err(Error::ProofShape);
            }
            if let Some(g) = s.injected(r) {
                folded += inputs[g];
            }
            let log_leaves = s.log_leaves(r);
            let pos = index >> log_leaves;
            index &= (1usize << log_leaves) - 1;
            if !opened(r, index, values) {
                return Err(Error::InvalidFriOpening { round: r });
            }
            if values[pos] != folded {
                return Err(Error::FoldMismatch { query: q, round: r });
            }
            let x_inv = self.shift_invs[r].mul(&self.omega_invs[r].pow(index as u64));
            folded = fold_leaf(values, x_inv, self.w_invs[r], self.betas[r]);
        }
        if folded != self.final_value {
            return Err(Error::FinalMismatch { query: q });
        }
        Ok(())
    }
}

/// Verifies a proof for input codewords of sizes `2^log_sizes[g]` (see
/// [`prove`]). For each query, `open(query, index, values)` must write the
/// input values at `index` (an index into the largest domain; the input of
/// size `m` is read at `index mod m`), one per input, computed
/// independently of the proof's FRI part.
pub fn verify(
    config: &FriConfig,
    challenger: &mut Challenger,
    shift: Fp,
    log_sizes: &[usize],
    proof: &FriProof,
    mut open: impl FnMut(usize, usize, &mut [Fp4]) -> Result<(), Error>,
) -> Result<(), Error> {
    if proof.queries.len() != config.num_queries {
        return Err(Error::ProofShape);
    }
    let v = Verifier::new(
        config,
        challenger,
        shift,
        log_sizes,
        &proof.commitments,
        &proof.fold_witnesses,
        &proof.final_value,
        proof.pow_witness,
    )?;
    let s = v.schedule();
    let mut inputs = [Fp4::ZERO; MAX_ROUNDS];
    let inputs = &mut inputs[..s.inputs()];
    for (q, steps) in proof.queries.iter().enumerate() {
        if steps.len() != s.rounds() {
            return Err(Error::ProofShape);
        }
        let index = v.sample_index(challenger);
        open(q, index, inputs)?;
        v.query(
            q,
            index,
            inputs,
            |r| Some(&steps[r].values[..]),
            |r, i, values| merkle_verify(&proof.commitments[r], s.log_leaves(r), i, leaf_row(values), &steps[r].path),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::{MULTIPLICATIVE_GENERATOR, coset_ntt_ext};
    use crate::test_util::Rng;

    const CONFIG: FriConfig = FriConfig { log_blowup: 3, num_queries: 20, pow_bits: 8, commit_bits: 0 };

    fn transcript() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0xf21));
        c
    }

    /// Evaluations on `shift * H` of a random polynomial with `degree_bound`
    /// coefficients, padded to a domain of size `2^log_n`.
    fn low_degree_codeword(rng: &mut Rng, log_n: usize, degree_bound: usize, shift: Fp) -> Vec<Fp4> {
        let mut v = vec![Fp4::ZERO; 1 << log_n];
        for c in v.iter_mut().take(degree_bound) {
            *c = rng.fp4();
        }
        coset_ntt_ext(&mut v, shift);
        v
    }

    /// Verifies against the true input codewords, checking that the
    /// queried indices are the ones the prover opened.
    fn check(log_sizes: &[usize], shift: Fp, proof: &FriProof, inputs: &[Vec<Fp4>]) -> Result<Vec<usize>, Error> {
        let mut seen = Vec::new();
        verify(&CONFIG, &mut transcript(), shift, log_sizes, proof, |_, index, values| {
            seen.push(index);
            for (v, c) in values.iter_mut().zip(inputs) {
                *v = c[index % c.len()];
            }
            Ok(())
        })?;
        Ok(seen)
    }

    #[test]
    fn accepts_low_degree_codewords() {
        let mut rng = Rng::new(30);
        for log_n in [4, 7, 10] {
            let bound = 1 << (log_n - CONFIG.log_blowup);
            let shift = MULTIPLICATIVE_GENERATOR;
            let cw = low_degree_codeword(&mut rng, log_n, bound, shift);
            let (proof, indices) = prove(&CONFIG, &mut transcript(), shift, vec![cw.clone()]);
            assert_eq!(proof.commitments.len(), (log_n - CONFIG.log_blowup).div_ceil(2));
            assert_eq!(proof.queries.len(), CONFIG.num_queries);
            assert_eq!(check(&[log_n], shift, &proof, &[cw]), Ok(indices));
            // Also with a smaller polynomial than the bound, and no shift.
            let cw = low_degree_codeword(&mut rng, log_n, bound / 2, Fp::ONE);
            let (proof, _) = prove(&CONFIG, &mut transcript(), Fp::ONE, vec![cw.clone()]);
            assert!(check(&[log_n], Fp::ONE, &proof, &[cw]).is_ok());
        }
    }

    #[test]
    fn round_schedules() {
        assert_eq!(round_log_arities(&CONFIG, &[10]), vec![2, 2, 2, 1]);
        assert_eq!(round_log_arities(&CONFIG, &[10, 7, 6]), vec![2, 1, 1, 2, 1]);
        assert_eq!(injection_rounds(&CONFIG, &[10, 7, 6]), vec![2, 3]);
        assert_eq!(injection_rounds(&CONFIG, &[10]), Vec::<usize>::new());
        assert_eq!((num_rounds(&CONFIG, &[10]), num_rounds(&CONFIG, &[10, 7, 6])), (4, 5));
        // The schedule the lists are read from: each round's arity, its
        // domain, its tree's height and the input added at its start.
        let s = Schedule::new(&CONFIG, &[10, 7, 6]).unwrap();
        assert_eq!((s.rounds(), s.inputs(), s.log_n()), (5, 3, 10));
        let per_round = |f: &dyn Fn(usize) -> usize| (0..5).map(f).collect::<Vec<_>>();
        assert_eq!(per_round(&|r| s.log_size(r)), vec![10, 8, 7, 6, 4]);
        assert_eq!(per_round(&|r| s.log_leaves(r)), vec![8, 7, 6, 4, 3]);
        assert_eq!((0..5).map(|r| s.injected(r)).collect::<Vec<_>>(), vec![None, None, Some(1), Some(2), None]);
        assert!(std::panic::catch_unwind(|| s.log_arity(5)).is_err());
        // The largest test there is: a round for every bit.
        let all: Vec<usize> = (1..=TWO_ADICITY).rev().collect();
        let widest = Schedule::new(&FriConfig { log_blowup: 0, ..CONFIG }, &all).unwrap();
        assert_eq!((widest.rounds(), widest.inputs()), (MAX_ROUNDS, MAX_ROUNDS));
        assert_eq!(widest.injected(MAX_ROUNDS - 1), Some(MAX_ROUNDS - 1));
        // Sizes that are no test's.
        for sizes in [&[][..], &[3], &[2], &[10, 10], &[10, 11], &[10, 3], &[28], &[usize::MAX]] {
            assert!(Schedule::new(&CONFIG, sizes).is_err(), "{sizes:?}");
        }
        assert!(std::panic::catch_unwind(|| round_log_arities(&CONFIG, &[10, 10])).is_err());
        assert!(std::panic::catch_unwind(|| num_rounds(&CONFIG, &[])).is_err());
        assert!(std::panic::catch_unwind(|| injection_rounds(&CONFIG, &[3])).is_err());
    }

    #[test]
    fn injected_codewords() {
        let mut rng = Rng::new(36);
        let shift = MULTIPLICATIVE_GENERATOR;
        for sizes in [vec![10, 7], vec![11, 9, 5], vec![8, 7]] {
            let n = sizes[0];
            let inputs: Vec<Vec<Fp4>> = sizes
                .iter()
                .map(|&l| {
                    let s = shift.pow(1u64 << (n - l));
                    low_degree_codeword(&mut rng, l, 1 << (l - CONFIG.log_blowup), s)
                })
                .collect();
            let (proof, indices) = prove(&CONFIG, &mut transcript(), shift, inputs.clone());
            assert_eq!(proof.commitments.len(), round_log_arities(&CONFIG, &sizes).len());
            assert_eq!(check(&sizes, shift, &proof, &inputs), Ok(indices));
            // A smaller input above its degree bound is caught.
            let mut bad = inputs.clone();
            let l = sizes[1];
            let s = shift.pow(1u64 << (n - l));
            bad[1] = low_degree_codeword(&mut rng, l, (1 << (l - CONFIG.log_blowup)) + 1, s);
            let (proof, _) = prove(&CONFIG, &mut transcript(), shift, bad.clone());
            assert!(check(&sizes, shift, &proof, &bad).is_err());
            // Values that differ from the committed smaller input are caught.
            let (proof, _) = prove(&CONFIG, &mut transcript(), shift, inputs.clone());
            let mut other = inputs.clone();
            other[1].iter_mut().for_each(|v| *v += Fp4::ONE);
            assert!(check(&sizes, shift, &proof, &other).is_err());
        }
    }

    #[test]
    fn rejects_degree_just_above_bound() {
        let mut rng = Rng::new(31);
        let log_n = 8;
        let bound = 1 << (log_n - CONFIG.log_blowup);
        let shift = MULTIPLICATIVE_GENERATOR;
        let cw = low_degree_codeword(&mut rng, log_n, bound + 1, shift);
        let (proof, _) = prove(&CONFIG, &mut transcript(), shift, vec![cw.clone()]);
        assert!(check(&[log_n], shift, &proof, &[cw]).is_err());
    }

    #[test]
    fn rejects_random_codeword() {
        let mut rng = Rng::new(32);
        let log_n = 8;
        let cw: Vec<Fp4> = (0..1 << log_n).map(|_| rng.fp4()).collect();
        let (proof, _) = prove(&CONFIG, &mut transcript(), Fp::ONE, vec![cw.clone()]);
        assert!(check(&[log_n], Fp::ONE, &proof, &[cw]).is_err());
    }

    #[test]
    fn rejects_tampering_and_mismatched_parameters() {
        let mut rng = Rng::new(33);
        let log_n = 8;
        let bound = 1 << (log_n - CONFIG.log_blowup);
        let shift = MULTIPLICATIVE_GENERATOR;
        let cw = low_degree_codeword(&mut rng, log_n, bound, shift);
        let (proof, _) = prove(&CONFIG, &mut transcript(), shift, vec![cw.clone()]);
        let inputs = [cw.clone()];
        assert!(check(&[log_n], shift, &proof, &inputs).is_ok());
        let open = |_: usize, i: usize, v: &mut [Fp4]| {
            v[0] = cw[i % cw.len()];
            Ok(())
        };

        // Different transcript prefix.
        assert!(verify(&CONFIG, &mut Challenger::new(), shift, &[log_n], &proof, open).is_err());
        // Wrong shift or size.
        assert!(check(&[log_n], Fp::new(3), &proof, &inputs).is_err());
        // One size up has the same round count with arity four (5 and 6
        // folding bits), so it fails at the openings; two up changes shape.
        assert!(check(&[log_n + 1], shift, &proof, &inputs).is_err());
        assert_eq!(check(&[log_n + 2], shift, &proof, &inputs).unwrap_err(), Error::ProofShape);
        let fewer = FriConfig { num_queries: 19, ..CONFIG };
        assert_eq!(verify(&fewer, &mut transcript(), shift, &[log_n], &proof, open).unwrap_err(), Error::ProofShape);
        // An input value that differs from the committed codeword.
        let wrong = |_: usize, i: usize, v: &mut [Fp4]| {
            v[0] = cw[i] + Fp4::ONE;
            Ok(())
        };
        assert_eq!(
            verify(&CONFIG, &mut transcript(), shift, &[log_n], &proof, wrong).unwrap_err(),
            Error::FoldMismatch { query: 0, round: 0 }
        );

        let mut p = proof.clone();
        p.final_value += Fp4::ONE;
        assert!(check(&[log_n], shift, &p, &inputs).is_err());
        let mut p = proof.clone();
        p.queries[3][1].values[0] += Fp4::ONE;
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::InvalidFriOpening { round: 1 });
        let mut p = proof.clone();
        p.commitments[0][0] += Fp::ONE;
        assert!(check(&[log_n], shift, &p, &inputs).is_err());
        let mut p = proof.clone();
        p.queries[0].pop();
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::ProofShape);
        // A witness that misses the proof-of-work target; and any witness
        // but zero when no grinding is configured.
        let mut p = proof.clone();
        p.pow_witness += Fp::ONE;
        if check(&[log_n], shift, &p, &inputs).is_ok() {
            p.pow_witness += Fp::ONE;
        }
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::FriGrinding);
        let none = FriConfig { pow_bits: 0, ..CONFIG };
        let (p, _) = prove(&none, &mut transcript(), shift, inputs.to_vec());
        assert_eq!(p.pow_witness, Fp::ZERO);
        assert!(verify(&none, &mut transcript(), shift, &[log_n], &p, open).is_ok());
        let mut p = p;
        p.pow_witness = Fp::ONE;
        assert_eq!(verify(&none, &mut transcript(), shift, &[log_n], &p, open).unwrap_err(), Error::FriGrinding);
        // Sizes no test has, and a shift with no coset, are refused, not panicked at.
        for sizes in [&[][..], &[3], &[28], &[log_n, log_n]] {
            assert_eq!(verify(&CONFIG, &mut transcript(), shift, sizes, &proof, open).unwrap_err(), Error::ProofShape);
        }
        assert_eq!(
            verify(&CONFIG, &mut transcript(), Fp::ZERO, &[log_n], &proof, open).unwrap_err(),
            Error::ProofShape
        );
        // Every other part of the proof, each a refusal of its own kind.
        let mut p = proof.clone();
        p.fold_witnesses.pop();
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::ProofShape);
        let mut p = proof.clone();
        p.commitments.push(p.commitments[0]);
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::ProofShape);
        let mut p = proof.clone();
        p.fold_witnesses[0] += Fp::ONE;
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::FriGrinding);
        let mut p = proof.clone();
        p.queries[2][0].values.pop();
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::ProofShape);
        let mut p = proof.clone();
        p.queries[5][2].path[0][0] += Fp::ONE;
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::InvalidFriOpening { round: 2 });
        let mut p = proof.clone();
        p.queries[1][0].path.pop();
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), Error::InvalidFriOpening { round: 0 });
        // The caller's own refusal comes back as it is.
        let refuse = |q: usize, i: usize, v: &mut [Fp4]| {
            if q == 4 { Err(Error::FinalMismatch { query: 99 }) } else { open(q, i, v) }
        };
        assert_eq!(
            verify(&CONFIG, &mut transcript(), shift, &[log_n], &proof, refuse).unwrap_err(),
            Error::FinalMismatch { query: 99 }
        );
    }

    #[test]
    fn integer_logarithms() {
        let p = crate::poseidon2::P as u128;
        let exact = |x: u128| (x as f64).log2() * 256.0;
        assert_eq!(LOG_K_X256, exact(p * p * p * p).floor() as i64);
        for x in [1u128, 2, 3, 5, 1000, 1030 << 21, (1 << 70) + 12345, p * p * p * p, u128::MAX] {
            let l = log2_x256_ceil(x);
            assert!(l as f64 >= exact(x) && (l as f64) < exact(x) + 2.0, "log2({x}) = {l}/256");
        }
        // 2^30 bad challenges out of 2^123.6 is 93.6 bits: 113 needs 20.
        assert_eq!(grinding_bits(113, 1 << 30), 20);
        assert_eq!(grinding_bits(113, 1), 0);
        assert_eq!(grinding_bits(0, 1 << 100), 0);
    }

    #[test]
    fn grinding_finds_low_zero_bits() {
        let mut c = transcript();
        let w = grind(&mut c, 12);
        let mut v = transcript();
        assert!(check_pow(&mut v, 12, w));
        // Both transcripts continue identically.
        assert_eq!(c.sample(), v.sample());
        // The witness is the smallest that works.
        assert!((0..w.to_canonical()).all(|x| !check_pow(&mut transcript(), 12, Fp::new(x))));
    }

    #[test]
    fn fold_matches_polynomial_split() {
        // f(x) = e(x^2) + x o(x^2); fold with beta gives e(x^2) + beta o(x^2).
        let mut rng = Rng::new(34);
        let e: Vec<Fp4> = (0..4).map(|_| rng.fp4()).collect();
        let o: Vec<Fp4> = (0..4).map(|_| rng.fp4()).collect();
        let x = rng.fp();
        let beta = rng.fp4();
        let x2 = Fp4::from_base(x.square());
        let ev = crate::ntt::eval_poly_ext;
        let f = |p: Fp| ev(&e, Fp4::from_base(p.square())) + ev(&o, Fp4::from_base(p.square())) * p;
        let got = fold(f(x), f(-x), x.inverse().unwrap(), beta);
        assert_eq!(got, ev(&e, x2) + beta * ev(&o, x2));
    }

    #[test]
    fn fold_by_four_matches_polynomial_split() {
        let mut rng = Rng::new(35);
        let parts: Vec<Vec<Fp4>> = (0..4).map(|_| (0..3).map(|_| rng.fp4()).collect()).collect();
        let x = rng.fp();
        let beta = rng.fp4();
        let ev = crate::ntt::eval_poly_ext;
        // f(X) = sum_k X^k f_k(X^4).
        let f = |p: Fp| {
            let p4 = Fp4::from_base(p.square().square());
            let mut acc = Fp4::ZERO;
            let mut pk = Fp::ONE;
            for part in &parts {
                acc += ev(part, p4) * pk;
                pk = pk.mul(&p);
            }
            acc
        };
        let w = root_of_unity(2);
        let values: Vec<Fp4> = (0..4).map(|k| f(x.mul(&w.pow(k)))).collect();
        let got = fold_leaf(&values, x.inverse().unwrap(), w.inverse().unwrap(), beta);
        let x4 = Fp4::from_base(x.square().square());
        let mut want = Fp4::ZERO;
        let mut bk = Fp4::ONE;
        for part in &parts {
            want += ev(part, x4) * bk;
            bk *= beta;
        }
        assert_eq!(got, want);
    }

    /// A proof whose paths travel together is checked through the
    /// verifier's parts: the folds a query at a time from the opened
    /// values, and each round's openings together against its root after
    /// the queries, the leaves noted as they are folded. It accepts what
    /// [`verify`] accepts, and refuses a leaf, a sibling or a value that
    /// is not the proof's.
    #[test]
    fn a_proof_with_batched_paths_is_checked_through_the_verifier() {
        use crate::merkle::{batch_root, compress_paths, hash_row};
        let mut rng = Rng::new(37);
        let shift = MULTIPLICATIVE_GENERATOR;
        let sizes = [11usize, 9, 5];
        let inputs: Vec<Vec<Fp4>> = sizes
            .iter()
            .map(|&l| low_degree_codeword(&mut rng, l, 1 << (l - CONFIG.log_blowup), shift.pow(1u64 << (11 - l))))
            .collect();
        let (proof, indices) = prove(&CONFIG, &mut transcript(), shift, inputs.clone());
        let rounds = proof.commitments.len();
        let s = Schedule::new(&CONFIG, &sizes).unwrap();
        // As it travels: every step's values, and for each round the
        // siblings its openings do not determine.
        let mut siblings: Vec<Vec<Digest>> = Vec::new();
        for r in 0..rounds {
            let leaves: Vec<Digest> = proof.queries.iter().map(|q| hash_row(leaf_row(&q[r].values))).collect();
            let paths: Vec<&[Digest]> = proof.queries.iter().map(|q| &q[r].path[..]).collect();
            siblings.push(compress_paths(s.log_leaves(r), &indices, &leaves, &paths));
        }
        let all: usize = proof.queries.iter().flatten().map(|st| st.path.len()).sum();
        assert!(siblings.iter().map(Vec::len).sum::<usize>() < all);

        let check = |proof: &FriProof, siblings: &[Vec<Digest>]| -> Result<(), Error> {
            let mut ch = transcript();
            let v = Verifier::new(
                &CONFIG,
                &mut ch,
                shift,
                &sizes,
                &proof.commitments,
                &proof.fold_witnesses,
                &proof.final_value,
                proof.pow_witness,
            )?;
            // Per round, each query's leaf index and hash.
            let nq = proof.queries.len();
            let mut noted = vec![(0usize, [Fp::ZERO; 8]); rounds * nq];
            for (q, steps) in proof.queries.iter().enumerate() {
                let index = v.sample_index(&mut ch);
                let at: Vec<Fp4> = inputs.iter().map(|c| c[index % c.len()]).collect();
                v.query(
                    q,
                    index,
                    &at,
                    |r| steps.get(r).map(|st| &st.values[..]),
                    |r, i, values| {
                        noted[r * nq + q] = (i, hash_row(leaf_row(values)));
                        true
                    },
                )?;
            }
            for r in 0..rounds {
                let (idx, leaves): (Vec<usize>, Vec<Digest>) = noted[r * nq..(r + 1) * nq].iter().copied().unzip();
                let mut sent = siblings[r].iter().copied();
                let root = batch_root(v.schedule().log_leaves(r), &idx, &leaves, || sent.next());
                if root != Some(proof.commitments[r]) || sent.next().is_some() {
                    return Err(Error::InvalidFriOpening { round: r });
                }
            }
            Ok(())
        };
        assert_eq!(check(&proof, &siblings), Ok(()));
        // A sibling that is not the tree's; one too few; one too many.
        let r = (0..rounds).find(|&r| !siblings[r].is_empty()).unwrap();
        let mut bad = siblings.clone();
        bad[r][0][0] += Fp::ONE;
        assert_eq!(check(&proof, &bad), Err(Error::InvalidFriOpening { round: r }));
        let mut bad = siblings.clone();
        bad[r].pop();
        assert_eq!(check(&proof, &bad), Err(Error::InvalidFriOpening { round: r }));
        let mut bad = siblings.clone();
        bad[r].push([Fp::ZERO; 8]);
        assert_eq!(check(&proof, &bad), Err(Error::InvalidFriOpening { round: r }));
        // An opened value that is not the codeword's, where the fold does
        // not read it: only the tree can tell.
        let mut p = proof.clone();
        let pos = indices[3] >> s.log_leaves(0);
        p.queries[3][0].values[(pos + 1) % 4] += Fp4::ONE;
        assert!(matches!(
            check(&p, &siblings),
            Err(Error::FoldMismatch { query: 3, round: 1 } | Error::InvalidFriOpening { .. })
        ));
        // A query's parts that are none: a round with no leaf, an index
        // outside the domain, an input too few.
        let mut ch = transcript();
        let v = Verifier::new(
            &CONFIG,
            &mut ch,
            shift,
            &sizes,
            &proof.commitments,
            &proof.fold_witnesses,
            &proof.final_value,
            proof.pow_witness,
        )
        .unwrap();
        let index = v.sample_index(&mut ch);
        assert_eq!(index, indices[0]);
        let at: Vec<Fp4> = inputs.iter().map(|c| c[index % c.len()]).collect();
        let steps = &proof.queries[0];
        let leaf = |r: usize| steps.get(r).map(|st| &st.values[..]);
        assert_eq!(v.query(0, index, &at, leaf, |_, _, _| true), Ok(()));
        assert_eq!(v.query(0, index, &at, |r| leaf(r).filter(|_| r < 2), |_, _, _| true), Err(Error::ProofShape));
        assert_eq!(v.query(0, index + (1 << 11), &at, leaf, |_, _, _| true), Err(Error::ProofShape));
        assert_eq!(v.query(0, index, &at[..2], leaf, |_, _, _| true), Err(Error::ProofShape));
        assert_eq!(v.query(7, index, &at, leaf, |r, _, _| r != 1), Err(Error::InvalidFriOpening { round: 1 }));
        assert!(size_of::<Verifier>() <= 1024);
    }

    #[test]
    #[should_panic(expected = "unsupported fri arity")]
    fn a_leaf_of_three_has_no_fold() {
        fold_leaf(&[Fp4::ONE; 3], Fp::ONE, Fp::ONE, Fp4::ONE);
    }
}
