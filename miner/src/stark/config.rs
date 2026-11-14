//! A proof's parameters, and what follows from them and a table's AIR: its
//! quotient, its grinding, the rows its constraints hold on.

use crate::ext::{DEGREE, Fp4};
use crate::field::Field;
use crate::fri::{self, FriConfig};
use crate::ntt::root_of_unity;
use crate::poseidon2::Fp;
use super::air::*;
use super::lookup::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarkConfig {
    /// Evaluation domain is `2^log_blowup` times the trace height. Must be at
    /// least `log2_ceil(max_constraint_degree - 1)`.
    pub log_blowup: usize,
    pub num_queries: usize,
    /// Proof-of-work bits ground before the FRI queries are sampled; each
    /// bit adds one bit of security against a prover trying many
    /// transcripts.
    pub pow_bits: usize,
    /// Zero knowledge (see the module notes): the proof reveals nothing
    /// about the traces beyond the statement. Costs a quotient of twice
    /// the chunks and the last [`StarkConfig::blind_rows`] rows of every
    /// table, which must be padding.
    pub zk: bool,
    /// Target security of every challenge before the queries (lookup,
    /// constraint combination, out-of-domain point, batching and folding):
    /// the prover grinds before each just enough that its soundness error
    /// (see [`Grinding`]) falls below `2^-commit_bits`. Zero for none.
    pub commit_bits: usize,
}

impl StarkConfig {
    pub(crate) fn fri(&self) -> FriConfig {
        FriConfig {
            log_blowup: self.log_blowup,
            num_queries: self.num_queries,
            pow_bits: self.pow_bits,
            commit_bits: self.commit_bits,
        }
    }

    /// Rows at the end of every table that a zero-knowledge proof fills
    /// with randomness: more than the values any column gives away. A
    /// column is a polynomial over `Fp`, so each of the two out-of-domain
    /// openings (at ζ and gζ, in the quartic extension) reveals four
    /// `Fp`-linear functions of it, and each query row one more; the
    /// quotient opened at a query row also reveals the next row's. Twice
    /// the queries plus eight exceeds all of that.
    pub fn blind_rows(&self) -> usize {
        if self.zk { 2 * self.num_queries + 8 } else { 0 }
    }

    /// Degree of the random polynomials masking the quotient chunks.
    pub(crate) fn chunk_slack(&self) -> usize {
        2 * self.blind_rows()
    }

    /// Log of the number of quotient chunks of a table of this degree.
    pub fn log_chunks(&self, degree: usize) -> usize {
        log_quotient_degree(degree) + usize::from(self.zk)
    }

    /// [`quotient_stride`] under this configuration.
    pub fn quotient_stride(&self, degree: usize) -> usize {
        1 << self.log_blowup.saturating_sub(self.log_chunks(degree))
    }
}

/// Proof-of-work bits before each challenge of a proof's commit phase up to
/// the batching challenge (FRI grinds before its own folding challenges,
/// see [`crate::fri::fold_grinding`]). Each round's soundness error is a
/// count of bad challenges over `|K|`, bounded per round by:
///
/// - lookup challenges: the degree of the LogUp identity in `(gamma,
///   delta)`, rows times the sum over terms of the tuple length plus one;
/// - constraint combination: the number of constraints (powers of alpha);
/// - out-of-domain point: the quotient's degree plus the trace length, per
///   table;
/// - batching: the domain of each FRI input, summed. The coefficients are
///   independent, so the number of polynomials does not enter (BCIKS20's
///   bound for affine spaces; powers of one challenge would multiply it by
///   their count, the degree of the curve).
///
/// The grinding brings each to [`StarkConfig::commit_bits`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Grinding {
    pub lookup: usize,
    pub alpha: usize,
    pub zeta: usize,
    pub beta: usize,
}

/// What [`Grinding`] needs of one table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GrindShape {
    pub log_n: usize,
    /// Constraints, lookup constraints included.
    pub constraints: usize,
    /// Sum over lookup terms of the tuple length plus one.
    pub lookup_weight: usize,
    pub chunks: usize,
}

impl Grinding {
    pub(crate) fn new(config: &StarkConfig, tables: &[GrindShape]) -> Grinding {
        let target = config.commit_bits;
        let bits = |term: u128| fri::grinding_bits(target, term);
        let lookup: u128 = tables.iter().map(|t| (t.lookup_weight as u128) << t.log_n).sum();
        // One FRI input per distinct domain size (tables come tallest first).
        let mut domains: Vec<usize> = tables.iter().map(|t| t.log_n + config.log_blowup).collect();
        domains.dedup();
        Grinding {
            lookup: if lookup > 0 { bits(lookup) } else { 0 },
            alpha: bits(tables.iter().map(|t| t.constraints as u128).sum()),
            zeta: bits(tables.iter().map(|t| ((t.chunks + 1) as u128) << t.log_n).sum()),
            beta: bits(domains.iter().map(|&l| 1u128 << l).sum()),
        }
    }
}

/// The [`GrindShape`] of a table of `2^log_n` rows of `air`.
pub(crate) fn grind_shape(config: &StarkConfig, air: &dyn DynAir, log_n: usize, public: &[Fp]) -> GrindShape {
    let (constraints, terms) = shape(air, public);
    let chunks = 1 << config.log_chunks(table_degree(config, air, terms));
    GrindShape {
        log_n,
        constraints: constraints + num_constraints_lookup(config, terms, air),
        lookup_weight: if terms > 0 { lookup_weight(air, public) } else { 0 },
        chunks,
    }
}

/// The grinding of a proof of `tables` (AIR and log height, tallest first).
pub fn grinding_of(config: &StarkConfig, tables: &[(&dyn DynAir, usize)], public: &[Fp]) -> Grinding {
    let shapes: Vec<GrindShape> = tables.iter().map(|&(air, log_n)| grind_shape(config, air, log_n, public)).collect();
    Grinding::new(config, &shapes)
}

/// Columns a zero-knowledge proof appends to every trace, random on every
/// row: a blinding message `u` the table sends and the message `v` it
/// receives, which on row 0 equals the previous table's `u`. They hide the
/// tables' lookup totals and mask the FRI codeword.
pub(crate) const ZK_COLS: usize = 2 * DEGREE;

/// Auxiliary extension columns a zero-knowledge proof appends: `1 / d(u)`
/// and `1 / d(v)` on row 0, random elsewhere.
pub(crate) const ZK_AUX: usize = 2;

/// Lookup constraints a zero-knowledge proof adds: the two inverses.
pub(super) const ZK_LOOKUP_CONSTRAINTS: usize = 2;

/// Blinding messages carry `delta^BLIND_TAG`, a power no AIR tuple
/// reaches, so they can only match each other.
pub(crate) const BLIND_TAG: usize = 64;

/// Where a table's constraints hold: on all `n` rows, or in a
/// zero-knowledge proof only on the rows before the blinding rows. The
/// vanishing polynomial of those rows is `Z_H / Z_B` with `Z_B` the
/// product over the blinding rows, and the last row the boundary
/// selector picks and the transition selector skips is the last of them.
#[derive(Clone, Copy)]
pub(super) struct Constrained {
    pub(super) log_n: usize,
    pub(super) blind: usize,
}

impl Constrained {
    pub(super) fn n(&self) -> usize {
        1 << self.log_n
    }

    /// The last constrained row's point.
    pub(super) fn last_point(&self) -> Fp {
        root_of_unity(self.log_n).pow((self.n() - self.blind - 1) as u64)
    }

    /// `Z_B(x)`.
    pub(super) fn z_blind<F: Field>(&self, x: F) -> F {
        let g = root_of_unity(self.log_n);
        let mut p = g.pow((self.n() - self.blind) as u64);
        let mut acc = F::ONE;
        for _ in 0..self.blind {
            acc *= x - F::from(p);
            p = p.mul(&g);
        }
        acc
    }
}

/// `log2_ceil(max(d - 1, 1))`: number of quotient chunks is `2^this`.
pub fn log_quotient_degree(max_constraint_degree: usize) -> usize {
    let q = max_constraint_degree.saturating_sub(1).max(1);
    (usize::BITS - (q - 1).leading_zeros()) as usize
}

/// Gap between the points a table's quotient is evaluated on: the
/// quotient has `2^log_quotient_degree` chunks, so it is determined by its
/// values on the sub-coset of every `stride`-th point of the extension.
/// One below the blowup the degree needs (where no proof can be made, but
/// a table can still be committed).
pub fn quotient_stride(degree: usize, log_blowup: usize) -> usize {
    1 << log_blowup.saturating_sub(log_quotient_degree(degree))
}

/// Which rows of a table's trace and auxiliary extensions to keep: only
/// those the quotient reads ([`quotient_stride`]) when there are fewer
/// queries than cosets, since each opened row is then recomputed from the
/// coefficients at a cost of one pass over them; otherwise every row,
/// as the recomputation would cost more than the extension.
pub(super) fn kept_stride(config: &StarkConfig, degree: usize) -> usize {
    if config.num_queries >= 1 << config.log_blowup { 1 } else { config.quotient_stride(degree) }
}

/// Degree of a table's combined constraints: its AIR's, or with zero
/// knowledge and lookups at least that of the blinding constraints
/// (selector, inverse and message).
pub(crate) fn table_degree(config: &StarkConfig, air: &dyn DynAir, terms: usize) -> usize {
    let d = air.air_degree();
    if config.zk && terms > 0 { d.max(3) } else { d }
}

/// Lookup constraints of a table with `terms` lookup terms.
pub(crate) fn num_constraints_lookup(config: &StarkConfig, terms: usize, air: &dyn DynAir) -> usize {
    num_lookup_constraints(terms, air.air_lookup_group())
        + if config.zk && terms > 0 { ZK_LOOKUP_CONSTRAINTS } else { 0 }
}

/// Where the quotient chunks are opened: `zeta^chunks` for interleaved
/// chunks, `zeta` for the contiguous chunks of a zero-knowledge proof.
pub(super) fn quotient_point(config: &StarkConfig, zeta: Fp4, chunks: usize) -> Fp4 {
    if config.zk { zeta } else { zeta.exp(chunks as u64) }
}
