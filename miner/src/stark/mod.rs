//! A univariate STARK: AIR constraints over an execution trace, proved with
//! Merkle-committed low-degree extensions, a DEEP out-of-domain opening and
//! the FRI low-degree test from [`crate::fri`], with an optional LogUp
//! lookup argument for multiset relations between rows.
//!
//! # Protocol
//!
//! Let the trace have `n = 2^log_n` rows (the domain `H` with generator `g`)
//! and `w` columns, and let `N = n * 2^log_blowup` be the size of the
//! evaluation coset `D = shift * H_N`.
//!
//! 1. The prover interpolates each column over `H`, evaluates it on `D` and
//!    commits to the `N x w` matrix.
//! 2. If the AIR declares lookup terms, the verifier samples `gamma, delta`
//!    and the prover builds the auxiliary trace: for every group of
//!    [`Air::lookup_group`] terms the sum of their signed fractions
//!    `multiplicity / (gamma + sum delta^(k+1) v_k)`, and one running sum of
//!    those columns. It commits to it as a second matrix (extension columns
//!    stored as four base columns each).
//! 3. The verifier samples `alpha`. On every point of `D` the prover
//!    evaluates the AIR constraints and the lookup constraints (one per
//!    group with its denominators cleared, the running-sum transition, and
//!    its values at both ends), combines them as
//!    `C = sum alpha^k c_k`, and divides by `Z_H(x) = x^n - 1`. The
//!    quotient is split into chunks of degree below `n` and committed.
//! 4. The verifier samples `zeta`. The prover opens every trace and
//!    auxiliary column at `zeta` and `g * zeta`, and every chunk at
//!    `zeta_q = zeta^(2^log_quotient)`. The verifier samples one
//!    independent coefficient per opened polynomial.
//! 5. Both sides form the DEEP combination over all openings (see
//!    [`Deep`]); the prover runs FRI on its evaluations over `D` and opens
//!    the committed rows at every FRI query index.
//!
//! The verifier checks the constraint identity `Q(zeta) Z_H(zeta) = C(zeta)`
//! from the openings, runs the FRI verifier, and recomputes the DEEP value
//! at each queried index from the opened rows.
//!
//! Selectors: `is_first_row = Z_H / (x - 1)`, `is_last_row = Z_H / (x - g^-1)`
//! and `is_transition = x - g^-1`. The first two have degree `n - 1` and
//! count as a column when sizing the quotient; the transition selector has
//! degree one and is absorbed by the slack in the bound.
//!
//! # Zero knowledge
//!
//! With [`StarkConfig::zk`] the proof reveals nothing about the traces
//! beyond the public values (the preprocessed tables are public anyway):
//!
//! - The last [`StarkConfig::blind_rows`] rows of every trace and
//!   auxiliary trace are replaced with random values, more than the
//!   `Fp`-linear functions of any column the openings reveal (four per
//!   out-of-domain point, one per query row, and the next row's through
//!   the quotient). Interpolation turns them into independent uniform
//!   values at those points. The constraints hold on the rows
//!   before: the vanishing polynomial is `Z_H / Z_B` with `Z_B` the product
//!   over the blinding rows, and the boundary and transition selectors
//!   treat the last row before them as the last row. The quotient's
//!   degree grows by the blinding rows, so it has twice the chunks.
//! - The chunks are contiguous runs of coefficients, `Q = sum_j x^(j L)
//!   Q_j` with `L = n - slack`, masked with random polynomials of degree
//!   below the slack that cancel in the sum, and opened at `zeta`.
//! - Every table gains [`ZK_COLS`] random columns: they make the DEEP
//!   combination, and so every FRI codeword, uniformly random, and they
//!   carry blinding messages. Each table with lookups sends its `u` on row
//!   0 and receives the previous table's `v` there (the running sum starts
//!   at `1/d(u) - 1/d(v)`), so the lookup totals, otherwise a function of
//!   the traces, are blinded while still cancelling. The messages carry
//!   `delta^BLIND_TAG`, a power no AIR tuple reaches, so they can only
//!   cancel each other.
//!
//! The recursive verifier of [`crate::recursion`] checks proofs without
//! zero knowledge only; the final proof of a block, which is published,
//! is the one that needs it.
//!
//! # Lookups
//!
//! An AIR calls [`Builder::lookup`] with a direction, a multiplicity and a
//! tuple of values. The sum over all rows of `+m / denom` for sends and
//! `-m / denom` for receives must vanish, which (with random challenges)
//! means the multiset of sent tuples, with multiplicities, equals the
//! multiset of received tuples. Lookup terms must not use the row
//! selectors, only columns and constants.
//!
//! A group of terms with denominators `d_i` and signed multiplicities
//! `m_i` has one column `h` and the constraint
//! `h * prod d_i = sum_i m_i prod_(j != i) d_j`, of degree
//! `1 + sum deg d_i`. Larger groups mean fewer columns for a higher
//! constraint degree. The constraint only fixes `h` when no denominator
//! vanishes, which holds except with negligible probability over `gamma`.
//!
//! # Layout
//!
//! - [`air`]: what a statement is written as.
//! - [`config`]: a proof's parameters and what follows from them.
//! - [`lookup`], [`deep`]: what prover and verifier compute alike.
//! - [`proof`]: a proof and its encoding.
//! - [`prove`], [`verify`]: the two sides.
//! - [`check`]: a trace checked against its AIR directly.

mod air;
#[cfg(test)]
pub(crate) mod audit;
mod check;
mod config;
mod deep;
mod lookup;
mod proof;
mod prove;
#[cfg(test)]
mod tests;
mod verify;

pub use air::*;
pub use check::*;
pub use config::*;
pub use lookup::*;
pub use proof::*;
pub use prove::*;
pub use verify::*;
