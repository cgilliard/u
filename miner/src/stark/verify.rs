//! The verifier.

use crate::challenger::Challenger;
use crate::ext::{DEGREE, Fp4};
use crate::field::Field;
use crate::fri::{self};
use crate::merkle::{Digest, verify as merkle_verify};
use crate::ntt::{MULTIPLICATIVE_GENERATOR, root_of_unity};
use crate::poseidon2::Fp;
use super::air::*;
use super::config::*;
use super::lookup::*;
use super::proof::*;
use super::deep::*;

pub fn verify<A: Air>(
    config: &StarkConfig,
    air: &A,
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    verify_with(config, air, None, public, proof, challenger)
}

/// [`verify`] against a preprocessed table known by its root.
pub fn verify_with<A: Air>(
    config: &StarkConfig,
    air: &A,
    pre_root: Option<&Digest>,
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    verify_tables(config, &[TableSpec { air, pre_root }], public, proof, challenger)
}

/// One table a verifier expects: its AIR and, when the AIR has
/// preprocessed columns, the root of the committed table.
#[derive(Clone, Copy)]
pub struct TableSpec<'a> {
    pub air: &'a dyn DynAir,
    pub pre_root: Option<&'a Digest>,
}

/// Shape of one table, derived from its AIR and checked against the proof.
pub(super) struct TableShape {
    w: usize,
    aux_w: usize,
    pre_w: usize,
    chunks: usize,
    num_constraints: usize,
    num_terms: usize,
    group: usize,
}

/// Verifies a proof of [`prove_tables`] for the given tables, in order.
pub fn verify_tables(
    config: &StarkConfig,
    specs: &[TableSpec<'_>],
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    let log_blowup = config.log_blowup;
    if specs.is_empty() || proof.tables.len() != specs.len() || proof.openings.len() != config.num_queries {
        return Err(VerifyError::Shape);
    }
    let log_ns: Vec<usize> = proof.tables.iter().map(|t| t.log_n).collect();
    if log_ns.windows(2).any(|w| w[0] < w[1]) {
        return Err(VerifyError::Shape);
    }
    let mut shapes = Vec::with_capacity(specs.len());
    for (spec, t) in specs.iter().zip(&proof.tables) {
        let air = spec.air;
        let (num_constraints, num_terms) = shape(air, public);
        let log_q = config.log_chunks(table_degree(config, air, num_terms));
        let group = air.air_lookup_group();
        let zk_aux = if config.zk && num_terms > 0 { ZK_AUX } else { 0 };
        let aux_w = (lookup_columns(num_terms, group) + zk_aux) * DEGREE;
        let s = TableShape {
            w: air.air_width() + if config.zk { ZK_COLS } else { 0 },
            aux_w,
            pre_w: air.air_preprocessed_width(),
            chunks: 1 << log_q,
            num_constraints,
            num_terms,
            group,
        };
        // The height's bound first: the proof's `log_n` is untrusted, and the
        // zero-knowledge check shifts by it.
        if t.log_n == 0
            || t.log_n + log_blowup > 27
            || (config.zk && 1 << t.log_n <= config.chunk_slack())
            || log_blowup < log_q
            || t.trace_at_zeta.len() != s.w
            || t.trace_at_zeta_next.len() != s.w
            || t.aux_at_zeta.len() != s.aux_w
            || t.aux_at_zeta_next.len() != s.aux_w
            || t.aux_root.is_some() != (num_terms > 0)
            || (t.aux_root.is_none() && !t.lookup_sum.is_zero())
            || spec.pre_root.is_some() != (s.pre_w > 0)
            || (s.pre_w > 0 && t.log_n != log_ns[0])
            || t.pre_at_zeta.len() != s.pre_w
            || t.pre_at_zeta_next.len() != s.pre_w
            || t.quotient_at_zeta_q.len() != s.chunks
        {
            return Err(VerifyError::Shape);
        }
        shapes.push(s);
    }
    let log_big = log_ns[0] + log_blowup;
    let grinding =
        grinding_of(config, &specs.iter().map(|s| s.air).zip(log_ns.iter().copied()).collect::<Vec<_>>(), public);
    let ground = |challenger: &mut Challenger, bits: usize, w: Fp| -> Result<(), VerifyError> {
        if fri::check_pow(challenger, bits, w) { Ok(()) } else { Err(VerifyError::ProofOfWork) }
    };

    observe_setup(challenger, &log_ns, public);
    for spec in specs {
        if let Some(root) = spec.pre_root {
            challenger.observe_digest(root);
        }
    }
    for t in &proof.tables {
        challenger.observe_digest(&t.trace_root);
    }
    let lookup_ch = if proof.tables.iter().any(|t| t.aux_root.is_some()) {
        ground(challenger, grinding.lookup, proof.grinding[0])?;
        let ch = LookupChallenges::sample(challenger);
        for t in &proof.tables {
            if let Some(root) = &t.aux_root {
                challenger.observe_digest(root);
                challenger.observe_ext(&t.lookup_sum);
            }
        }
        Some(ch)
    } else {
        if proof.grinding[0] != Fp::ZERO {
            return Err(VerifyError::ProofOfWork);
        }
        None
    };
    if !proof.tables.iter().fold(Fp4::ZERO, |a, t| a + t.lookup_sum).is_zero() {
        return Err(VerifyError::LookupSum);
    }
    ground(challenger, grinding.alpha, proof.grinding[1])?;
    let alpha = challenger.sample_ext();
    for t in &proof.tables {
        challenger.observe_digest(&t.quotient_root);
    }
    ground(challenger, grinding.zeta, proof.grinding[2])?;
    let zeta = challenger.sample_ext();
    for t in &proof.tables {
        for v in t.opened().into_iter().flatten() {
            challenger.observe_ext(v);
        }
    }
    ground(challenger, grinding.beta, proof.grinding[3])?;
    let coeffs = sample_coefficients(challenger, proof.tables.iter().map(|t| t.deep_len()).sum());

    // Constraint identity of every table at zeta.
    let public_ext: Vec<Fp4> = public.iter().map(|x| Fp4::from_base(*x)).collect();
    for ((spec, t), s) in specs.iter().zip(&proof.tables).zip(&shapes) {
        let rows = Constrained { log_n: t.log_n, blind: config.blind_rows() };
        let p_last = Fp4::from_base(rows.last_point());
        // Z of the constrained rows at zeta.
        let z_r =
            (zeta.exp(1u64 << t.log_n) - Fp4::ONE) * rows.z_blind(zeta).inv().ok_or(VerifyError::ConstraintIdentity)?;
        let first = z_r * (zeta - Fp4::ONE).inv().ok_or(VerifyError::ConstraintIdentity)?;
        let last = z_r * (zeta - p_last).inv().ok_or(VerifyError::ConstraintIdentity)?;
        let transition = zeta - p_last;
        let w = spec.air.air_width();
        let (constraints, terms) = evaluate(
            spec.air,
            &t.trace_at_zeta[..w],
            &t.trace_at_zeta_next[..w],
            (&t.pre_at_zeta, &t.pre_at_zeta_next),
            &public_ext,
            (first, last, transition),
        );
        if config.zk && terms.iter().any(|t| t.values.len() >= BLIND_TAG) {
            return Err(VerifyError::Shape);
        }
        let aux_l = ext_from_base_openings(&t.aux_at_zeta);
        let aux_n = ext_from_base_openings(&t.aux_at_zeta_next);
        let alpha_powers = powers(alpha, s.num_constraints + num_constraints_lookup(config, s.num_terms, spec.air));
        let lookup = lookup_ch.as_ref().filter(|_| s.num_terms > 0).map(|ch| LookupArgs {
            ch,
            total: t.lookup_sum,
            group: s.group,
        });
        let blind = if config.zk && lookup.is_some() { Some(&t.trace_at_zeta[w..]) } else { None };
        let c_zeta =
            combine(&constraints, &terms, &aux_l, &aux_n, (first, last, transition), lookup, blind, &alpha_powers);
        // Interleaved chunks step by zeta; contiguous ones by zeta^L.
        let step = if config.zk { zeta.exp(((1usize << t.log_n) - config.chunk_slack()) as u64) } else { zeta };
        let mut q_zeta = Fp4::ZERO;
        let mut zeta_pow = Fp4::ONE;
        for q in &t.quotient_at_zeta_q {
            q_zeta += *q * zeta_pow;
            zeta_pow *= step;
        }
        if q_zeta * z_r != c_zeta {
            return Err(VerifyError::ConstraintIdentity);
        }
    }

    // FRI over the DEEP combinations recomputed from the opened rows.
    let mut offset = 0usize;
    let deeps: Vec<Deep> = proof
        .tables
        .iter()
        .map(|t| {
            let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
            let d = Deep::new(&coeffs[offset..], t, zeta, zeta_next);
            offset += d.len();
            d
        })
        .collect();
    let mut log_sizes: Vec<usize> = log_ns.iter().map(|l| l + log_blowup).collect();
    log_sizes.dedup();
    if proof.query_indices.len() != config.num_queries {
        return Err(VerifyError::Shape);
    }
    let open = |q: usize, index: usize, values: &mut [Fp4]| -> Result<(), VerifyError> {
        let openings = &proof.openings[q];
        if openings.len() != specs.len() || proof.query_indices[q] != index {
            return Err(VerifyError::Shape);
        }
        // One value for each size of domain: tables of one size add up.
        let mut filled = 0;
        let mut last_size = None;
        for ((((spec, t), s), opening), deep) in specs.iter().zip(&proof.tables).zip(&shapes).zip(openings).zip(&deeps)
        {
            if opening.trace_row.len() != s.w
                || opening.aux_row.len() != s.aux_w
                || opening.pre_row.len() != s.pre_w
                || opening.quotient_row.len() != s.chunks * DEGREE
            {
                return Err(VerifyError::Shape);
            }
            let log_m = t.log_n + log_blowup;
            let i = index % (1 << log_m);
            if !merkle_verify(&t.trace_root, log_m, i, &opening.trace_row, &opening.trace_path) {
                return Err(VerifyError::InvalidTraceOpening { query: q });
            }
            if let Some(root) = &t.aux_root
                && !merkle_verify(root, log_m, i, &opening.aux_row, &opening.aux_path)
            {
                return Err(VerifyError::InvalidAuxOpening { query: q });
            }
            if let Some(root) = spec.pre_root
                && !merkle_verify(root, log_m, i, &opening.pre_row, &opening.pre_path)
            {
                return Err(VerifyError::InvalidPreprocessedOpening { query: q });
            }
            if !merkle_verify(&t.quotient_root, log_m, i, &opening.quotient_row, &opening.quotient_path) {
                return Err(VerifyError::InvalidQuotientOpening { query: q });
            }
            let shift = table_shift(log_big, log_m);
            let x_base = shift.mul(&root_of_unity(log_m).pow(i as u64));
            let x = Fp4::from_base(x_base);
            let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
            let zeta_q = quotient_point(config, zeta, s.chunks);
            // Zeta is drawn from the transcript, so a zero here is a 2^-90
            // chance; still an error, not a panic.
            let (Some(inv0), Some(inv1)) = (((x - zeta) * (x - zeta_next)).inv(), (x - zeta_q).inv()) else {
                return Err(VerifyError::InvalidQuotientOpening { query: q });
            };
            let inv = [inv0, inv1];
            let rows = (&opening.trace_row[..], &opening.aux_row[..], &opening.pre_row[..]);
            let quotient = ext_from_row(&opening.quotient_row);
            let v = deep.value((rows.0, rows.1, rows.2, &quotient), x_base, inv[0], inv[1]);
            if last_size == Some(log_m) {
                values[filled - 1] += v;
            } else {
                values[filled] = v;
                filled += 1;
                last_size = Some(log_m);
            }
        }
        Ok(())
    };
    fri::verify(&config.fri(), challenger, MULTIPLICATIVE_GENERATOR, &log_sizes, &proof.fri, open)
}
