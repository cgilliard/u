//! The prover.

use crate::challenger::Challenger;
use crate::ext::{DEGREE, Fp4, as_fp4};
use crate::field::{Field, batch_inverse};
use crate::fri::{self};
use crate::merkle::{Digest, MerkleTree};
use crate::ntt::{MULTIPLICATIVE_GENERATOR, coset_evals, coset_intt_ext, intt, lde_cosets, log2_strict, root_of_unity};
use crate::parallel::{par_chunks_mut, par_map, par_map_min, par_map_with};
use crate::poseidon2::{Fp, zeroed_vec};
use super::air::*;
use super::config::*;
use super::lookup::*;
use super::proof::*;
use super::deep::*;

/// Randomness for zero-knowledge proofs: Poseidon2 in counter mode, with
/// feed-forward, under a key from the operating system.
pub(super) struct Rng {
    key: [Fp; crate::poseidon2::DIGEST],
}

impl Rng {
    fn new() -> Rng {
        let mut bytes = [0u8; 4 * crate::poseidon2::DIGEST];
        crate::random::fill(&mut bytes).expect("the system's random source");
        let key = core::array::from_fn(|i| {
            Fp::from_u64(u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()) as u64)
        });
        Rng { key }
    }

    /// Fills `out` with the stream of `domain`.
    fn fill(&self, domain: u32, out: &mut [Fp]) {
        use crate::poseidon2::{DIGEST, WIDTH, permute};
        const CHUNK: usize = 1 << 12;
        par_chunks_mut(out, CHUNK, |c, part| {
            for (b, block) in part.chunks_mut(DIGEST).enumerate() {
                let counter = (c * CHUNK / DIGEST + b) as u64;
                let mut state = [Fp::ZERO; WIDTH];
                state[..DIGEST].copy_from_slice(&self.key);
                state[DIGEST] = Fp::new(domain);
                state[DIGEST + 1] = Fp::new((counter & 0x3fff_ffff) as u32);
                state[DIGEST + 2] = Fp::new((counter >> 30) as u32);
                let outp = permute(state);
                for (k, v) in block.iter_mut().enumerate() {
                    *v = outp[k].add(&self.key[k]);
                }
            }
        });
    }

    fn vec(&self, domain: u32, len: usize) -> Vec<Fp> {
        let mut v = vec![Fp::ZERO; len];
        self.fill(domain, &mut v);
        v
    }

    fn ext_vec(&self, domain: u32, len: usize) -> Vec<Fp4> {
        self.vec(domain, len * DEGREE).chunks_exact(DEGREE).map(|c| Fp4(c.try_into().unwrap())).collect()
    }
}

/// A committed fixed table: the low-degree extension and Merkle tree of
/// preprocessed columns, built once and reused across proofs.
pub struct Preprocessed {
    pub width: usize,
    pub log_n: usize,
    pub log_blowup: usize,
    table: Trace,
    committed: Committed,
}

impl Preprocessed {
    /// Commits to `table` at `log_blowup`, keeping the rows a quotient at
    /// `stride` ([`quotient_stride`]) reads.
    pub fn new(table: &Trace, log_blowup: usize, stride: usize) -> Preprocessed {
        let w = table.width;
        let log_n = log2_strict(table.height());
        let committed = Committed::new(w, table.height() << log_blowup, MULTIPLICATIVE_GENERATOR, Some(stride), |k| {
            table.column(k)
        });
        Preprocessed { width: w, log_n, log_blowup, table: table.clone(), committed }
    }

    pub fn root(&self) -> Digest {
        self.committed.tree.root()
    }

    /// The committed table.
    pub fn table(&self) -> &Trace {
        &self.table
    }

    /// The rows a quotient reads are kept every `stride` points.
    pub fn stride(&self) -> usize {
        self.committed.stride.unwrap()
    }

    fn row(&self, i: usize) -> &[Fp] {
        self.committed.row(i)
    }
}

/// Evaluates base-coefficient polynomials at `x`, sharing a table of powers.
pub(super) fn eval_base_polys_at(polys: &[Vec<Fp>], x: Fp4) -> Vec<Fp4> {
    let n = polys.first().map_or(0, |p| p.len());
    let xp = powers(x, n);
    par_map_min(polys.len(), 1, |k| polys[k].iter().zip(&xp).fold(Fp4::ZERO, |acc, (c, p)| acc + p.mul_base(c)))
}

/// The blinding of a table's auxiliary trace in a zero-knowledge proof.
pub(super) struct ZkAux<'a> {
    rng: &'a Rng,
    domain: u32,
    /// Rows before the blinding rows.
    real: usize,
    /// The blinding messages `u` and `v` on row 0.
    uv: &'a [Fp],
}

/// Builds the auxiliary trace (row-major extension values: group sums
/// then the running sum, and in a zero-knowledge proof `h_u` and `h_v`)
/// for `trace` under the given challenges, and returns it with the
/// table's lookup total. Only the first `air.air_width()` columns of
/// `trace` are the AIR's. With `zk`, only the rows before the blinding
/// rows are summed and the rest are random.
pub(super) fn build_aux(
    air: &dyn DynAir,
    trace: &Trace,
    pre: Option<&Preprocessed>,
    public: &[Fp],
    ch: &LookupChallenges,
    terms: usize,
    zk: Option<ZkAux<'_>>,
) -> (Vec<Fp4>, Fp4) {
    let n = trace.height();
    let w = air.air_width();
    let real = zk.as_ref().map_or(n, |z| z.real);
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.table.row(i)) };
    let group = air.air_lookup_group();
    let groups = terms.div_ceil(group);
    let width = groups + 1 + if zk.is_some() { ZK_AUX } else { 0 };
    let mut aux = match &zk {
        Some(z) => z.rng.ext_vec(z.domain, n * width),
        None => vec![Fp4::ZERO; n * width],
    };
    for row in aux[..real * width].chunks_exact_mut(width) {
        row[..=groups].fill(Fp4::ZERO);
    }
    // Denominators and signed multiplicities of every term, row by row.
    const ROWS: usize = 256;
    let mut dm = vec![(Fp4::ZERO, Fp::ZERO); real * terms];
    par_chunks_mut(&mut dm, ROWS * terms, |c, chunk| {
        let mut scratch = Scratch::default();
        for (r, out) in chunk.chunks_exact_mut(terms).enumerate() {
            let i = c * ROWS + r;
            evaluate_into(
                air,
                &trace.row(i)[..w],
                &trace.row((i + 1) % n)[..w],
                (pre_row(i), pre_row((i + 1) % n)),
                public,
                (Fp::ZERO, Fp::ZERO, Fp::ZERO),
                &mut scratch,
            );
            assert_eq!(scratch.terms().len(), terms, "lookup term count varies between rows");
            for (o, t) in out.iter_mut().zip(scratch.terms()) {
                *o = (ch.denominator(&t.values), if t.send { t.multiplicity } else { -t.multiplicity });
            }
        }
    });
    let (denoms, mults): (Vec<Fp4>, Vec<Fp>) = dm.into_iter().unzip();
    let invs = par_batch_inverse(&denoms);
    // Group sums, and each row's contribution in the running-sum column,
    // which the prefix sums then replace.
    par_chunks_mut(&mut aux[..real * width], ROWS * width, |c, chunk| {
        for (r, row) in chunk.chunks_exact_mut(width).enumerate() {
            let i = c * ROWS + r;
            let mut contrib = Fp4::ZERO;
            for k in 0..terms {
                let f = invs[i * terms + k].mul_base(&mults[i * terms + k]);
                row[k / group] += f;
                contrib += f;
            }
            row[groups] = contrib;
        }
    });
    let mut sum = Fp4::ZERO;
    if let Some(z) = &zk {
        let inv = |d: Fp4| d.inv().expect("blinding message hits a pole");
        let (h_u, h_v) = (inv(ch.blind_denominator(&z.uv[..DEGREE])), inv(ch.blind_denominator(&z.uv[DEGREE..])));
        aux[groups + 1] = h_u;
        aux[groups + 2] = h_v;
        sum = h_u - h_v;
    }
    for row in aux[..real * width].chunks_exact_mut(width) {
        let contrib = row[groups];
        row[groups] = sum;
        sum += contrib;
    }
    (aux, sum)
}

/// Batch inversion in parallel chunks.
pub(super) fn par_batch_inverse<F: Field + Send + Sync>(xs: &[F]) -> Vec<F> {
    const CHUNK: usize = 1 << 14;
    par_map_min(xs.len().div_ceil(CHUNK), 1, |c| batch_inverse(&xs[c * CHUNK..((c + 1) * CHUNK).min(xs.len())]))
        .into_iter()
        .flatten()
        .collect()
}

/// Asked by a prover between phases; `true` abandons the proof.
pub type Cancel<'a> = &'a (dyn Fn() -> bool + Sync);

/// The prover's `cancel` fired; no proof was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled;

/// Phase boundary: times the phase when `TABMINER_TIMING` is set, and
/// checks for cancellation.
pub(super) struct Timer<'a> {
    on: bool,
    last: std::time::Instant,
    cancel: Option<Cancel<'a>>,
}

impl<'a> Timer<'a> {
    fn new(cancel: Option<Cancel<'a>>) -> Timer<'a> {
        Timer { on: std::env::var_os("TABMINER_TIMING").is_some(), last: std::time::Instant::now(), cancel }
    }

    fn lap(&mut self, what: &str) -> Result<(), Cancelled> {
        if self.on {
            eprintln!("  {what}: {:?}", self.last.elapsed());
            self.last = std::time::Instant::now();
        }
        if self.cancel.is_some_and(|c| c()) { Err(Cancelled) } else { Ok(()) }
    }
}

/// Randomness stream of table `k` for one purpose.
pub(super) fn zk_domain(k: usize, purpose: u32) -> u32 {
    ((k as u32) << 4) | purpose
}

/// The traces of a zero-knowledge proof: each table's rows before its
/// blinding rows, then random rows, with [`ZK_COLS`] random columns
/// appended. Row 0 of a table's `v` repeats the `u` of the previous table
/// with lookups (cyclically), so the blinding messages cancel.
pub(super) fn blind_traces(config: &StarkConfig, tables: &[TableInput<'_>], shapes: &[(usize, usize)], rng: &Rng) -> Vec<Trace> {
    let blind = config.blind_rows();
    let mut out: Vec<Trace> = tables
        .iter()
        .enumerate()
        .map(|(k, t)| {
            let (n, w) = (t.trace.height(), t.trace.width);
            let width = w + ZK_COLS;
            let mut values = rng.vec(zk_domain(k, 0), n * width);
            par_chunks_mut(&mut values[..(n - blind) * width], 256 * width, |c, chunk| {
                for (r, row) in chunk.chunks_exact_mut(width).enumerate() {
                    row[..w].copy_from_slice(t.trace.row(c * 256 + r));
                }
            });
            Trace::new(values, width)
        })
        .collect();
    let with_lookups: Vec<usize> = (0..tables.len()).filter(|&k| shapes[k].1 > 0).collect();
    for (j, &k) in with_lookups.iter().enumerate() {
        let prev = with_lookups[(j + with_lookups.len() - 1) % with_lookups.len()];
        let wp = tables[prev].trace.width;
        let u: Vec<Fp> = out[prev].row(0)[wp..wp + DEGREE].to_vec();
        let w = tables[k].trace.width;
        out[k].values[w + DEGREE..w + 2 * DEGREE].copy_from_slice(&u);
    }
    out
}

/// A committed matrix: `width` columns of `n` coefficients extended to
/// `n << log_blowup` points on the coset `shift * H`, and the Merkle tree
/// over the rows. The extension is computed and hashed one coset of `H_n`
/// at a time and never held whole: only the rows on the sub-coset of every
/// `stride`-th point are kept (the points the quotient reads; none for
/// `None`). Other rows are recomputed from the coefficients when opened.
pub(super) struct Committed {
    width: usize,
    log_blowup: usize,
    shift: Fp,
    stride: Option<usize>,
    coeffs: Vec<Vec<Fp>>,
    /// Kept rows, one block of `n` rows per kept coset `j` (`j` a multiple
    /// of `stride`): point `j + 2^log_blowup * m` at row `m` of block
    /// `j / stride`.
    kept: Vec<Vec<Fp>>,
    tree: MerkleTree,
}

impl Committed {
    /// Interpolates the `width` columns `column(k)` (values on `H`) and
    /// commits to their extension to `big_n` points on `shift * H`.
    fn new(
        width: usize,
        big_n: usize,
        shift: Fp,
        stride: Option<usize>,
        column: impl Fn(usize) -> Vec<Fp> + Sync,
    ) -> Committed {
        let coeffs: Vec<Vec<Fp>> = par_map_min(width, 1, |k| {
            let mut c = column(k);
            intt(&mut c);
            c
        });
        let log_blowup = log2_strict(big_n / coeffs[0].len());
        Self::from_coeffs(coeffs, log_blowup, shift, stride)
    }

    fn from_coeffs(coeffs: Vec<Vec<Fp>>, log_blowup: usize, shift: Fp, stride: Option<usize>) -> Committed {
        const ROWS: usize = 256;
        let width = coeffs.len();
        let n = coeffs[0].len();
        let b = 1usize << log_blowup;
        let w_big = root_of_unity(log2_strict(n) + log_blowup);
        let mut leaves: Vec<Digest> = vec![[Fp::ZERO; crate::poseidon2::DIGEST]; n * b];
        let mut kept = Vec::new();
        let mut rows = zeroed_vec(n * width);
        let mut s_j = shift;
        for j in 0..b {
            let cols: Vec<Vec<Fp>> = par_map_min(width, 1, |k| coset_evals(&coeffs[k], s_j));
            par_chunks_mut(&mut rows, ROWS * width, |c, chunk| {
                for (r, row) in chunk.chunks_exact_mut(width).enumerate() {
                    let m = c * ROWS + r;
                    for (x, col) in row.iter_mut().zip(&cols) {
                        *x = col[m];
                    }
                }
            });
            drop(cols);
            for (m, h) in crate::merkle::leaf_hashes(&rows, width).into_iter().enumerate() {
                leaves[j + b * m] = h;
            }
            if stride.is_some_and(|s| j.is_multiple_of(s)) {
                kept.push(std::mem::replace(&mut rows, zeroed_vec(n * width)));
            }
            s_j = s_j.mul(&w_big);
        }
        let tree = MerkleTree::from_leaf_hashes(leaves);
        Committed { width, log_blowup, shift, stride, coeffs, kept, tree }
    }

    /// Row `i`, a point of the kept sub-coset.
    fn row(&self, i: usize) -> &[Fp] {
        let s = self.stride.expect("no rows kept");
        let (b, n) = (1usize << self.log_blowup, self.coeffs[0].len());
        let (j, m) = (i % b, i / b);
        debug_assert!(j.is_multiple_of(s) && m < n);
        &self.kept[j / s][m * self.width..(m + 1) * self.width]
    }

    /// Row `i` of the extension, kept or recomputed.
    fn row_at(&self, i: usize) -> Vec<Fp> {
        let b = 1usize << self.log_blowup;
        if self.stride.is_some_and(|s| (i % b).is_multiple_of(s)) {
            return self.row(i).to_vec();
        }
        let n = self.coeffs[0].len();
        let x = self.shift.mul(&root_of_unity(log2_strict(n) + self.log_blowup).pow(i as u64));
        let mut xp = Vec::with_capacity(n);
        let mut p = Fp::ONE;
        for _ in 0..n {
            xp.push(p);
            p = p.mul(&x);
        }
        par_map_min(self.width, 1, |k| self.coeffs[k].iter().zip(&xp).fold(Fp::ZERO, |acc, (c, p)| acc.add(&c.mul(p))))
    }
}

/// One table of a proof: its AIR, trace, and the committed preprocessed
/// table when the AIR has preprocessed columns (it must have the trace's
/// height and the config's blowup).
#[derive(Clone, Copy)]
pub struct TableInput<'a> {
    pub air: &'a dyn DynAir,
    pub trace: &'a Trace,
    pub pre: Option<&'a Preprocessed>,
}

/// The prover's state for one table.
pub(super) struct TableState<'a> {
    input: TableInput<'a>,
    log_n: usize,
    /// The rows the constraints hold on.
    rows: Constrained,
    /// [`table_degree`].
    degree: usize,
    /// Auxiliary extension columns.
    aux_ext_w: usize,
    /// Evaluation coset of the table.
    shift: Fp,
    num_constraints: usize,
    num_terms: usize,
    trace: Committed,
    /// Auxiliary columns (rows of extension values as base values) and the
    /// lookup total.
    aux: Option<(Committed, Fp4)>,
}

impl TableState<'_> {
    fn big_n(&self, log_blowup: usize) -> usize {
        1 << (self.log_n + log_blowup)
    }

    fn aux_ext_w(&self) -> usize {
        self.aux_ext_w
    }

    fn pre_row(&self, i: usize) -> &[Fp] {
        self.input.pre.map_or(&[], |p| p.row(i))
    }

    fn aux_row(&self, i: usize) -> &[Fp] {
        self.aux.as_ref().map_or(&[], |(c, _)| c.row(i))
    }
}

/// The committed quotient of one table.
pub(super) struct Quotient {
    coeffs: Vec<Vec<Fp4>>,
    /// The chunks' extension, `chunks` extension values per row as base
    /// values; no rows kept.
    committed: Committed,
    chunks: usize,
}

/// Evaluates the combined constraints of a table on its coset, divides by
/// the vanishing polynomial, splits the quotient into chunks and commits.
///
/// Without zero knowledge the chunks interleave, `Q(x) = sum_j x^j
/// Q_j(x^chunks)`. With it they are contiguous runs of `L = n - slack`
/// coefficients, `Q(x) = sum_j x^(j L) Q_j(x)`, each masked with random
/// polynomials `S_j` of degree below the slack that telescope away:
/// `Q_j + x^L S_j - S_(j-1)`, with `S_(-1) = S_(chunks-1) = 0`.
pub(super) fn commit_quotient(
    t: &TableState<'_>,
    config: &StarkConfig,
    public: &[Fp],
    lookup: Option<&LookupChallenges>,
    alpha_powers: &[Fp4],
    rng: Option<(&Rng, u32)>,
    timer: &mut Timer<'_>,
) -> Result<Quotient, Cancelled> {
    let log_blowup = config.log_blowup;
    let air = t.input.air;
    let w = air.air_width();
    let zk = config.zk;
    let n = 1usize << t.log_n;
    let big_n = t.big_n(log_blowup);
    let aux_ext_w = t.aux_ext_w();
    let num_chunks = 1usize << config.log_chunks(t.degree);
    let shift = t.shift;
    let rows = t.rows;
    let p_last = rows.last_point();
    let xs = coset_points(shift, t.log_n + log_blowup);
    let period = 1usize << log_blowup;
    let z_h: Vec<Fp> = (0..period).map(|i| xs[i].pow(n as u64).sub(&Fp::ONE)).collect();
    let z_h_inv = batch_inverse(&z_h);
    // The quotient has degree below `num_chunks * n`, so its values on the
    // sub-coset of every `stride`-th point determine it: only those are
    // evaluated. Their next rows (`period` on) are points of it too.
    let qn = num_chunks * n;
    let stride = big_n / qn;
    debug_assert!(period.is_multiple_of(stride));
    // Per point: 1 / Z_B (with zero knowledge), 1 / (x - 1), 1 / (x - last).
    let z_b: Vec<Fp> = if zk { par_map(qn, |m| rows.z_blind(xs[m * stride])) } else { Vec::new() };
    let denoms: Vec<Fp> = (0..qn)
        .flat_map(|m| {
            let x = xs[m * stride];
            [x.sub(&Fp::ONE), x.sub(&p_last)]
        })
        .chain(z_b.iter().copied())
        .collect();
    let denom_inv = par_batch_inverse(&denoms);
    let empty: [Fp4; 0] = [];
    let total = t.aux.as_ref().map_or(Fp4::ZERO, |(_, s)| *s);
    let group = air.air_lookup_group();
    let lookup = lookup.filter(|_| t.num_terms > 0).map(|ch| LookupArgs { ch, total, group });

    let mut quotient: Vec<Fp4> = par_map_with(qn, Scratch::default, |scratch, m| {
        let i = m * stride;
        // Z of the constrained rows, and its inverse.
        let (zr, zr_inv) = if zk {
            let zb = z_b[m];
            (z_h[i % period].mul(&denom_inv[2 * qn + m]), zb.mul(&z_h_inv[i % period]))
        } else {
            (z_h[i % period], z_h_inv[i % period])
        };
        let first = zr.mul(&denom_inv[2 * m]);
        let last = zr.mul(&denom_inv[2 * m + 1]);
        let transition = xs[i].sub(&p_last);
        let next_i = (i + period) % big_n;
        let (row, row_next) = (t.trace.row(i), t.trace.row(next_i));
        evaluate_into(
            air,
            &row[..w],
            &row_next[..w],
            (t.pre_row(i), t.pre_row(next_i)),
            public,
            (first, last, transition),
            scratch,
        );
        let (constraints, terms) = (scratch.constraints(), scratch.terms());
        let (aux_l, aux_n): (&[Fp4], &[Fp4]) =
            if aux_ext_w > 0 { (as_fp4(t.aux_row(i)), as_fp4(t.aux_row(next_i))) } else { (&empty, &empty) };
        let sel_ext = (Fp4::from_base(first), Fp4::from_base(last), Fp4::from_base(transition));
        let blind = if zk && lookup.is_some() { Some(&row[w..]) } else { None };
        let c = combine(constraints, terms, aux_l, aux_n, sel_ext, lookup, blind, alpha_powers);
        c.mul_base(&zr_inv)
    });
    timer.lap("quotient eval")?;

    coset_intt_ext(&mut quotient, shift);
    let coeffs: Vec<Vec<Fp4>> = match rng {
        None => {
            // Q(x) = sum_j x^j Q_j(x^(2^log_q)).
            (0..num_chunks).map(|j| quotient.iter().skip(j).step_by(num_chunks).copied().collect()).collect()
        }
        Some((rng, domain)) => {
            let slack = config.chunk_slack();
            let len = n - slack;
            assert!(
                quotient[num_chunks * len..].iter().all(|c| c.is_zero()),
                "the constraints fail on a row before the blinding rows (are the last {} rows of the trace padding?)",
                rows.blind
            );
            let masks = rng.ext_vec(domain, (num_chunks - 1) * slack);
            (0..num_chunks)
                .map(|j| {
                    let mut c = quotient[j * len..(j + 1) * len].to_vec();
                    c.resize(n, Fp4::ZERO);
                    if j + 1 < num_chunks {
                        for (a, m) in c[len..].iter_mut().zip(&masks[j * slack..(j + 1) * slack]) {
                            *a += *m;
                        }
                    }
                    if j > 0 {
                        for (a, m) in c.iter_mut().zip(&masks[(j - 1) * slack..j * slack]) {
                            *a -= *m;
                        }
                    }
                    c
                })
                .collect()
        }
    };
    drop(quotient);
    // Rows of `num_chunks` extension values, as base values.
    let base: Vec<Vec<Fp>> =
        (0..num_chunks * DEGREE).map(|jk| coeffs[jk / DEGREE].iter().map(|v| v.0[jk % DEGREE]).collect()).collect();
    timer.lap("quotient lde")?;
    let committed = Committed::from_coeffs(base, log_blowup, shift, None);
    timer.lap("quotient commit")?;
    Ok(Quotient { coeffs, committed, chunks: num_chunks })
}

pub fn prove<A: Air>(
    config: &StarkConfig,
    air: &A,
    trace: &Trace,
    public: &[Fp],
    challenger: &mut Challenger,
) -> Proof {
    assert_eq!(air.preprocessed_width(), 0, "this air needs a preprocessed table: use prove_with");
    prove_with(config, air, trace, None, public, challenger)
}

/// [`prove`] with a preprocessed table (required when the AIR declares
/// preprocessed columns; it must have the trace's height and the config's
/// blowup).
pub fn prove_with<A: Air>(
    config: &StarkConfig,
    air: &A,
    trace: &Trace,
    pre: Option<&Preprocessed>,
    public: &[Fp],
    challenger: &mut Challenger,
) -> Proof {
    prove_tables(config, &[TableInput { air, trace, pre }], public, challenger)
}

/// Proves several tables at once, tallest first. The tables share the
/// public values, the lookup challenges (their lookup terms must cancel
/// together, so tables can exchange messages) and one FRI proof, into
/// which the DEEP combination of a smaller table enters at its size. Only
/// tables of the tallest height may have preprocessed columns.
pub fn prove_tables(
    config: &StarkConfig,
    tables: &[TableInput<'_>],
    public: &[Fp],
    challenger: &mut Challenger,
) -> Proof {
    try_prove_tables(config, tables, public, challenger, None).expect("no cancellation")
}

/// [`prove_tables`] that gives up with [`Cancelled`] once `cancel` returns
/// `true`, checked between phases (a few seconds apart at most).
pub fn try_prove_tables(
    config: &StarkConfig,
    tables: &[TableInput<'_>],
    public: &[Fp],
    challenger: &mut Challenger,
    cancel: Option<Cancel<'_>>,
) -> Result<Proof, Cancelled> {
    assert!(!tables.is_empty(), "no tables");
    let log_blowup = config.log_blowup;
    let log_ns: Vec<usize> = tables.iter().map(|t| log2_strict(t.trace.height())).collect();
    assert!(log_ns.windows(2).all(|w| w[0] >= w[1]), "tables must be ordered by height, tallest first");
    let log_big = log_ns[0] + log_blowup;
    for (t, &log_n) in tables.iter().zip(&log_ns) {
        let air = t.air;
        assert_eq!(t.trace.width, air.air_width(), "trace width does not match air");
        assert_eq!(t.pre.map_or(0, |p| p.width), air.air_preprocessed_width(), "preprocessed width does not match air");
        if let Some(p) = t.pre {
            assert_eq!(p.log_n, log_n, "preprocessed table height does not match trace");
            assert_eq!(p.log_blowup, log_blowup, "preprocessed table blowup does not match config");
            assert_eq!(log_n, log_ns[0], "only the tallest tables may have preprocessed columns");
        }
        debug_assert!(
            measure_degree_dyn(air, public.len()) <= air.air_degree(),
            "air constraints exceed the declared degree"
        );
        let degree = table_degree(config, air, shape(air, public).1);
        let log_q = config.log_chunks(degree);
        assert!(log_blowup >= log_q, "log_blowup must be at least {log_q} for this air");
        if config.zk {
            let (n, d, slack) = (1usize << log_n, degree, config.chunk_slack());
            assert!(
                n > slack && (n - slack) << log_q > d * (n - 1) - n + config.blind_rows(),
                "table of 2^{log_n} rows is too small for zero knowledge"
            );
        }
    }

    observe_setup(challenger, &log_ns, public);
    for t in tables {
        if let Some(p) = t.pre {
            challenger.observe_digest(&p.root());
        }
    }
    let mut timer = Timer::new(cancel);
    let shapes: Vec<(usize, usize)> = tables.iter().map(|t| shape(t.air, public)).collect();

    // 0. Zero knowledge: random blinding rows and blinding columns.
    let rng = config.zk.then(Rng::new);
    let blinded: Vec<Trace> = match &rng {
        Some(rng) => blind_traces(config, tables, &shapes, rng),
        None => Vec::new(),
    };
    let tables: Vec<TableInput<'_>> =
        tables.iter().enumerate().map(|(k, t)| TableInput { trace: blinded.get(k).unwrap_or(t.trace), ..*t }).collect();

    // 1. Trace LDEs and commitments.
    let mut states: Vec<TableState<'_>> = tables
        .iter()
        .zip(&log_ns)
        .zip(&shapes)
        .map(|((input, &log_n), &(num_constraints, num_terms))| {
            let shift = table_shift(log_big, log_n + log_blowup);
            let degree = table_degree(config, input.air, num_terms);
            let stride = kept_stride(config, degree);
            if let Some(p) = input.pre {
                let needed = config.quotient_stride(degree);
                assert!(needed.is_multiple_of(p.stride()), "preprocessed table lacks rows the quotient reads");
            }
            let trace = Committed::new(input.trace.width, 1 << (log_n + log_blowup), shift, Some(stride), |k| {
                input.trace.column(k)
            });
            challenger.observe_digest(&trace.tree.root());
            let aux_ext_w = lookup_columns(num_terms, input.air.air_lookup_group())
                + if config.zk && num_terms > 0 { ZK_AUX } else { 0 };
            let rows = Constrained { log_n, blind: config.blind_rows() };
            TableState {
                input: *input,
                log_n,
                rows,
                degree,
                aux_ext_w,
                shift,
                num_constraints,
                num_terms,
                trace,
                aux: None,
            }
        })
        .collect();
    timer.lap("trace commit")?;
    let grinding = grinding_of(config, &states.iter().map(|t| (t.input.air, t.log_n)).collect::<Vec<_>>(), public);
    let mut witnesses = [Fp::ZERO; 4];

    // 2. Lookup challenges and auxiliary traces.
    let mut lookup_ch = None;
    if states.iter().any(|t| t.num_terms > 0) {
        witnesses[0] = fri::grind(challenger, grinding.lookup);
        let ch = LookupChallenges::sample(challenger);
        for (k, t) in states.iter_mut().enumerate().filter(|(_, t)| t.num_terms > 0) {
            let w = t.input.air.air_width();
            let zk = rng.as_ref().map(|rng| ZkAux {
                rng,
                domain: zk_domain(k, 1),
                real: t.rows.n() - t.rows.blind,
                uv: &t.input.trace.row(0)[w..],
            });
            let (aux, total) = build_aux(t.input.air, t.input.trace, t.input.pre, public, &ch, t.num_terms, zk);
            timer.lap("aux build")?;
            let ext_w = t.aux_ext_w();
            let n = 1usize << t.log_n;
            let stride = kept_stride(config, t.degree);
            let committed = Committed::new(ext_w * DEGREE, t.big_n(log_blowup), t.shift, Some(stride), |j| {
                let (e, k) = (j / DEGREE, j % DEGREE);
                (0..n).map(|i| aux[i * ext_w + e].0[k]).collect()
            });
            challenger.observe_digest(&committed.tree.root());
            challenger.observe_ext(&total);
            t.aux = Some((committed, total));
            timer.lap("aux commit")?;
        }
        debug_assert!(
            states.iter().filter_map(|t| t.aux.as_ref()).fold(Fp4::ZERO, |a, (_, s)| a + *s).is_zero(),
            "lookup terms do not cancel: the traces violate a multiset relation"
        );
        lookup_ch = Some(ch);
    }

    // 3. Constraint combinations and quotients.
    witnesses[1] = fri::grind(challenger, grinding.alpha);
    let alpha = challenger.sample_ext();
    let quotients: Vec<Quotient> = states
        .iter()
        .enumerate()
        .map(|(k, t)| {
            let alpha_powers =
                powers(alpha, t.num_constraints + num_constraints_lookup(config, t.num_terms, t.input.air));
            let rng = rng.as_ref().map(|r| (r, zk_domain(k, 2)));
            let q = commit_quotient(t, config, public, lookup_ch.as_ref(), &alpha_powers, rng, &mut timer)?;
            challenger.observe_digest(&q.committed.tree.root());
            Ok(q)
        })
        .collect::<Result<_, Cancelled>>()?;

    // 4. Out-of-domain openings.
    witnesses[2] = fri::grind(challenger, grinding.zeta);
    let zeta = challenger.sample_ext();
    let no_coeffs: Vec<Vec<Fp>> = Vec::new();
    let parts: Vec<TableProof> = states
        .iter()
        .zip(&quotients)
        .map(|(t, q)| {
            let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
            let zeta_q = quotient_point(config, zeta, q.chunks);
            let aux_coeffs = t.aux.as_ref().map_or(&no_coeffs, |(c, _)| &c.coeffs);
            let pre_coeffs = t.input.pre.map_or(&no_coeffs, |p| &p.committed.coeffs);
            let part = TableProof {
                log_n: t.log_n,
                trace_root: t.trace.tree.root(),
                aux_root: t.aux.as_ref().map(|(c, _)| c.tree.root()),
                lookup_sum: t.aux.as_ref().map_or(Fp4::ZERO, |(_, s)| *s),
                quotient_root: q.committed.tree.root(),
                trace_at_zeta: eval_base_polys_at(&t.trace.coeffs, zeta),
                trace_at_zeta_next: eval_base_polys_at(&t.trace.coeffs, zeta_next),
                aux_at_zeta: eval_base_polys_at(aux_coeffs, zeta),
                aux_at_zeta_next: eval_base_polys_at(aux_coeffs, zeta_next),
                pre_at_zeta: eval_base_polys_at(pre_coeffs, zeta),
                pre_at_zeta_next: eval_base_polys_at(pre_coeffs, zeta_next),
                quotient_at_zeta_q: q.coeffs.iter().map(|c| eval_ext_poly_at(c, zeta_q)).collect(),
            };
            for v in part.opened().into_iter().flatten() {
                challenger.observe_ext(v);
            }
            part
        })
        .collect();
    timer.lap("openings")?;

    // 5. DEEP combinations, summed per domain size, and FRI.
    witnesses[3] = fri::grind(challenger, grinding.beta);
    let coeffs = sample_coefficients(challenger, parts.iter().map(|p| p.deep_len()).sum());
    let mut inputs: Vec<Vec<Fp4>> = Vec::new();
    let mut input_log_sizes: Vec<usize> = Vec::new();
    let mut offset = 0usize;
    for ((t, q), part) in states.iter().zip(&quotients).zip(&parts) {
        let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
        let deep = Deep::new(&coeffs[offset..], part, zeta, zeta_next);
        offset += deep.len();
        let log_m = t.log_n + log_blowup;
        let zeta_q = quotient_point(config, zeta, q.chunks);
        let xs = coset_points(t.shift, log_m);
        let mut denoms: Vec<Fp4> = Vec::with_capacity(2 * xs.len());
        for x in &xs {
            let xe = Fp4::from_base(*x);
            denoms.push((xe - zeta) * (xe - zeta_next));
            denoms.push(xe - zeta_q);
        }
        let inv = par_batch_inverse(&denoms);
        // The combination on coefficients, extended once per component.
        let no_coeffs: Vec<Vec<Fp>> = Vec::new();
        let aux_coeffs = t.aux.as_ref().map_or(&no_coeffs, |(c, _)| &c.coeffs);
        let pre_coeffs = t.input.pre.map_or(&no_coeffs, |p| &p.committed.coeffs);
        let polys = deep.polys(&t.trace.coeffs, aux_coeffs, pre_coeffs, &q.coeffs);
        let ext: Vec<Vec<Fp>> = par_map_min(2 * DEGREE, 1, |pk| {
            let base: Vec<Fp> = polys[pk / DEGREE].iter().map(|v| v.0[pk % DEGREE]).collect();
            lde_cosets(&base, log_blowup, t.shift)
        });
        drop(polys);
        let (n, b) = (1usize << t.log_n, 1usize << log_blowup);
        let reduced: Vec<Fp4> = par_map(xs.len(), |i| {
            let e = (i % b) * n + i / b;
            let v = |p: usize| Fp4(core::array::from_fn(|k| ext[p * DEGREE + k][e]));
            let [line, c_q] = deep.constants(xs[i]);
            (v(0) - line) * inv[2 * i] + (v(1) - c_q) * inv[2 * i + 1]
        });
        if input_log_sizes.last() == Some(&log_m) {
            let last = inputs.last_mut().unwrap();
            for (a, b) in last.iter_mut().zip(&reduced) {
                *a += *b;
            }
        } else {
            inputs.push(reduced);
            input_log_sizes.push(log_m);
        }
    }
    timer.lap("deep")?;
    let (fri_proof, indices) = fri::prove(&config.fri(), challenger, MULTIPLICATIVE_GENERATOR, inputs);
    timer.lap("fri")?;

    let openings = indices
        .iter()
        .map(|&index| {
            states
                .iter()
                .zip(&quotients)
                .map(|(t, q)| {
                    let i = index % t.big_n(log_blowup);
                    let aux = t.aux.as_ref().map(|(c, _)| c);
                    let pre = t.input.pre.map(|p| &p.committed);
                    QueryOpening {
                        trace_row: t.trace.row_at(i),
                        trace_path: t.trace.tree.open(i),
                        aux_row: aux.map(|c| c.row_at(i)).unwrap_or_default(),
                        aux_path: aux.map(|c| c.tree.open(i)).unwrap_or_default(),
                        pre_row: pre.map(|c| c.row_at(i)).unwrap_or_default(),
                        pre_path: pre.map(|c| c.tree.open(i)).unwrap_or_default(),
                        quotient_row: q.committed.row_at(i),
                        quotient_path: q.committed.tree.open(i),
                    }
                })
                .collect()
        })
        .collect();

    Ok(Proof { tables: parts, fri: fri_proof, openings, query_indices: indices, grinding: witnesses })
}
