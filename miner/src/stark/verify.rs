//! The verifier.

use super::air::{Air, DynAir, evaluate, shape};
use super::config::{
    BLIND_TAG, Constrained, StarkConfig, ZK_AUX, ZK_COLS, grinding_of, lookup_columns, num_constraints_lookup,
    quotient_point, table_degree,
};
use super::deep::{Deep, observe_setup, sample_coefficients, table_shift};
use super::lookup::{LookupArgs, LookupChallenges, combine, ext_from_base_openings, powers};
use super::proof::{Proof, ProofHead, VerifyError};
use crate::challenger::Challenger;
use crate::codec::Reader;
use crate::ext::{DEGREE, Fp4, as_fp4};
use crate::field::Field;
use crate::fri::{self};
use crate::hash::EMPTY;
use crate::merkle::{Digest, batch_root, hash_row};
use crate::ntt::{MULTIPLICATIVE_GENERATOR, root_of_unity};
use crate::poseidon2::Fp;

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
///
/// The proof is checked as its bytes are: this encodes it and calls
/// [`verify_bytes`], the one verifier there is. A proof the encoding
/// cannot hold has the wrong shape.
pub fn verify_tables(
    config: &StarkConfig,
    specs: &[TableSpec<'_>],
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    match proof.try_to_bytes() {
        Some(bytes) => verify_bytes(config, specs, public, &bytes, challenger),
        None => Err(VerifyError::Shape),
    }
}

/// Verifies the bytes of a proof of [`prove_tables`] for the given tables,
/// in order.
///
/// What comes before the queries is read into place ([`ProofHead`]): its
/// size is the tables' widths', not the queries'. The queries are then
/// read where they lie, one at a time: each row is decoded into one
/// buffer, hashed and combined there, and its hash noted. The openings of
/// each tree are checked together at the end, against the siblings the
/// proof sends for them ([`crate::merkle::batch_root`]); no path is
/// rebuilt. A query whose folds fail is reported after the trees, so that
/// a row that is not its tree's is reported as that.
pub fn verify_bytes(
    config: &StarkConfig,
    specs: &[TableSpec<'_>],
    public: &[Fp],
    bytes: &[u8],
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    let head = ProofHead::read(bytes).ok_or(VerifyError::Malformed)?;
    let proof = &head;
    let log_blowup = config.log_blowup;
    if specs.is_empty() || proof.tables.len() != specs.len() || proof.num_queries != config.num_queries {
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
    let fri_verifier = fri::Verifier::new(
        &config.fri(),
        challenger,
        MULTIPLICATIVE_GENERATOR,
        &log_sizes,
        &proof.commitments,
        &proof.fold_witnesses,
        &proof.final_value,
        proof.pow_witness,
    )?;
    let schedule = *fri_verifier.schedule();
    let rounds = schedule.rounds();
    if proof.rounds != rounds {
        return Err(VerifyError::Shape);
    }

    // What each table's openings are read with: the same for every query.
    struct At {
        log_m: usize,
        shift: Fp,
        omega: Fp,
        zeta_next: Fp4,
        zeta_q: Fp4,
        /// Lengths of its trace, auxiliary, preprocessed and quotient rows.
        lens: [usize; 4],
    }
    let ats: Vec<At> = proof
        .tables
        .iter()
        .zip(&shapes)
        .map(|(t, s)| {
            let log_m = t.log_n + log_blowup;
            At {
                log_m,
                shift: table_shift(log_big, log_m),
                omega: root_of_unity(log_m),
                zeta_next: zeta.mul_base(&root_of_unity(t.log_n)),
                zeta_q: quotient_point(config, zeta, s.chunks),
                lens: [s.w, s.aux_w, s.pre_w, s.chunks * DEGREE],
            }
        })
        .collect();

    // The trees the proof opens: each table's trace, auxiliary,
    // preprocessed and quotient trees, then the FRI rounds'. For each, its
    // root and height, or `None` for a tree a table does not have.
    let (nt, nq) = (specs.len(), config.num_queries);
    let num_trees = 4 * nt + rounds;
    let tree = |k: usize| -> Option<(&Digest, usize)> {
        if k >= 4 * nt {
            let r = k - 4 * nt;
            return Some((&proof.commitments[r], schedule.log_leaves(r)));
        }
        let (t, log_m) = (&proof.tables[k / 4], ats[k / 4].log_m);
        match k % 4 {
            0 => Some((&t.trace_root, log_m)),
            1 => t.aux_root.as_ref().map(|r| (r, log_m)),
            2 => specs[k / 4].pre_root.map(|r| (r, log_m)),
            _ => Some((&t.quotient_root, log_m)),
        }
    };
    let not_the_trees = |k: usize| -> VerifyError {
        if k >= 4 * nt {
            return VerifyError::InvalidFriOpening { round: k - 4 * nt };
        }
        let table = k / 4;
        match k % 4 {
            0 => VerifyError::InvalidTraceOpening { table },
            1 => VerifyError::InvalidAuxOpening { table },
            2 => VerifyError::InvalidPreprocessedOpening { table },
            _ => VerifyError::InvalidQuotientOpening { table },
        }
    };

    // The queries, where they lie. All the heap a query needs is here:
    // every opened leaf's hash, the queries' indices, and one row.
    let mut leaves = vec![EMPTY; num_trees * nq];
    let mut indices = vec![0usize; nq];
    let mut row = vec![Fp::ZERO; ats.iter().map(|a| a.lens.iter().sum::<usize>()).max().unwrap_or(0)];
    let mut steps = [Fp4::ZERO; 4 * fri::MAX_ROUNDS];
    let mut inputs = [Fp4::ZERO; fri::MAX_ROUNDS];
    let mut fold_error = None;
    let mut r = Reader(proof.rest);
    let malformed = VerifyError::Malformed;
    for q in 0..nq {
        let index = fri_verifier.sample_index(challenger);
        if r.u32().ok_or(malformed)? as usize != index {
            return Err(VerifyError::Shape);
        }
        indices[q] = index;
        for rd in 0..rounds {
            let arity = 1usize << schedule.log_arity(rd);
            if r.u32().ok_or(malformed)? as usize != arity {
                return Err(VerifyError::Shape);
            }
            for v in &mut steps[4 * rd..4 * rd + arity] {
                *v = r.fp4().ok_or(malformed)?;
            }
        }
        // One value for each size of domain: tables of one size add up.
        let mut filled = 0;
        let mut last_size = None;
        for (t, (at, deep)) in ats.iter().zip(&deeps).enumerate() {
            let mut ends = [0usize; 5];
            for (k, &len) in at.lens.iter().enumerate() {
                if r.u32().ok_or(malformed)? as usize != len {
                    return Err(VerifyError::Shape);
                }
                let part = &mut row[ends[k]..ends[k] + len];
                for x in part.iter_mut() {
                    *x = r.fp().ok_or(malformed)?;
                }
                leaves[(4 * t + k) * nq + q] = if len == 0 { EMPTY } else { hash_row(part) };
                ends[k + 1] = ends[k] + len;
            }
            let i = index & ((1usize << at.log_m) - 1);
            let x_base = at.shift.mul(&at.omega.pow(i as u64));
            let x = Fp4::from_base(x_base);
            // Zeta is drawn from the transcript, so a zero here is a 2^-90
            // chance; still an error, not a panic.
            let (Some(inv0), Some(inv1)) = (((x - zeta) * (x - at.zeta_next)).inv(), (x - at.zeta_q).inv()) else {
                return Err(VerifyError::InvalidQuotientOpening { table: t });
            };
            let rows =
                (&row[..ends[1]], &row[ends[1]..ends[2]], &row[ends[2]..ends[3]], as_fp4(&row[ends[3]..ends[4]]));
            let v = deep.value(rows, x_base, inv0, inv1);
            if last_size == Some(at.log_m) {
                inputs[filled - 1] += v;
            } else {
                inputs[filled] = v;
                filled += 1;
                last_size = Some(at.log_m);
            }
        }
        let folds = fri_verifier.query(
            q,
            index,
            &inputs[..filled],
            |rd| Some(&steps[4 * rd..4 * rd + (1usize << schedule.log_arity(rd))]),
            |rd, _, values| {
                leaves[(4 * nt + rd) * nq + q] = hash_row(fri::leaf_row(values));
                true
            },
        );
        match folds {
            Ok(()) => {}
            Err(fri::FriError::Shape) => return Err(VerifyError::Shape),
            Err(e) => {
                fold_error.get_or_insert(e);
            }
        }
    }

    // Every tree's height, as the proof says it: what it must be.
    for k in 0..num_trees {
        let height = r.u32().ok_or(malformed)? as usize;
        if height != tree(k).map_or(0, |(_, h)| h) {
            return Err(not_the_trees(k));
        }
    }
    // Each tree's openings together, against the siblings sent for them.
    let mut at = vec![0usize; nq];
    for k in 0..num_trees {
        let Some((root, height)) = tree(k) else { continue };
        for (a, i) in at.iter_mut().zip(&indices) {
            *a = i & ((1usize << height) - 1);
        }
        if batch_root(height, &at, &leaves[k * nq..(k + 1) * nq], || r.digest()) != Some(*root) {
            return Err(not_the_trees(k));
        }
    }
    if !r.is_empty() {
        return Err(malformed);
    }
    match fold_error {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}
