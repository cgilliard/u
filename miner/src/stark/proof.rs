//! A proof, its encoding, and why a verifier refuses one.

use crate::codec::{Reader, Writer};
use crate::ext::Fp4;
use crate::fri::{FriError, FriProof, QueryStep, leaf_row};
use crate::merkle::Digest;
use crate::poseidon2::Fp;

/// Openings of one table's committed matrices at one queried index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryOpening {
    pub trace_row: Vec<Fp>,
    pub trace_path: Vec<Digest>,
    pub aux_row: Vec<Fp>,
    pub aux_path: Vec<Digest>,
    pub pre_row: Vec<Fp>,
    pub pre_path: Vec<Digest>,
    pub quotient_row: Vec<Fp>,
    pub quotient_path: Vec<Digest>,
}

/// The part of a proof that belongs to one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableProof {
    pub log_n: usize,
    pub trace_root: Digest,
    /// Present when the AIR declares lookups.
    pub aux_root: Option<Digest>,
    /// The table's total of its lookup terms (zero without lookups). The
    /// totals of all tables must add up to zero.
    pub lookup_sum: Fp4,
    pub quotient_root: Digest,
    pub trace_at_zeta: Vec<Fp4>,
    pub trace_at_zeta_next: Vec<Fp4>,
    /// Auxiliary base columns at zeta (four per extension column).
    pub aux_at_zeta: Vec<Fp4>,
    pub aux_at_zeta_next: Vec<Fp4>,
    /// Preprocessed columns at zeta (empty without preprocessed columns).
    pub pre_at_zeta: Vec<Fp4>,
    pub pre_at_zeta_next: Vec<Fp4>,
    pub quotient_at_zeta_q: Vec<Fp4>,
}

impl TableProof {
    /// The out-of-domain openings, in transcript order.
    pub fn opened(&self) -> [&Vec<Fp4>; 7] {
        [
            &self.trace_at_zeta,
            &self.trace_at_zeta_next,
            &self.aux_at_zeta,
            &self.aux_at_zeta_next,
            &self.pre_at_zeta,
            &self.pre_at_zeta_next,
            &self.quotient_at_zeta_q,
        ]
    }

    /// Coefficients of the DEEP combination this table takes: one per
    /// committed column and per quotient chunk (see `Deep`).
    pub fn deep_len(&self) -> usize {
        self.trace_at_zeta.len() + self.aux_at_zeta.len() + self.pre_at_zeta.len() + self.quotient_at_zeta_q.len()
    }

    fn write(&self, w: &mut Writer) {
        w.u32(self.log_n as u32);
        w.digest(&self.trace_root);
        match &self.aux_root {
            Some(r) => {
                w.u32(1);
                w.digest(r);
                w.fp4(&self.lookup_sum);
            }
            None => w.u32(0),
        }
        w.digest(&self.quotient_root);
        for v in self.opened() {
            w.fp4_vec(v);
        }
    }

    fn read(r: &mut Reader) -> Option<TableProof> {
        let log_n = r.u32()? as usize;
        if log_n > 32 {
            return None;
        }
        let trace_root = r.digest()?;
        let (aux_root, lookup_sum) = match r.u32()? {
            0 => (None, Fp4::ZERO),
            1 => (Some(r.digest()?), r.fp4()?),
            _ => return None,
        };
        Some(TableProof {
            log_n,
            trace_root,
            aux_root,
            lookup_sum,
            quotient_root: r.digest()?,
            trace_at_zeta: r.fp4_vec()?,
            trace_at_zeta_next: r.fp4_vec()?,
            aux_at_zeta: r.fp4_vec()?,
            aux_at_zeta_next: r.fp4_vec()?,
            pre_at_zeta: r.fp4_vec()?,
            pre_at_zeta_next: r.fp4_vec()?,
            quotient_at_zeta_q: r.fp4_vec()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// One part per table, tallest table first.
    pub tables: Vec<TableProof>,
    pub fri: FriProof,
    /// For every FRI query, one opening per table.
    pub openings: Vec<Vec<QueryOpening>>,
    /// The sampled query indices into the largest domain. The verifier
    /// samples them itself and rejects a proof that disagrees; a decoder
    /// that rebuilds the Merkle paths the encoding leaves out
    /// ([`Proof::from_bytes`]) needs them before any transcript is run.
    pub query_indices: Vec<usize>,
    /// Proof-of-work witnesses before the lookup challenges, the constraint
    /// combination, the out-of-domain point and the batching challenge
    /// (see [`Grinding`]); zero where none is needed.
    pub grinding: [Fp; 4],
}

impl Proof {
    /// Every Merkle tree the proof opens, as its height and, per query,
    /// the opened leaf's hash and path: per table its trace, auxiliary,
    /// preprocessed and quotient trees, then the FRI rounds. An absent tree
    /// has height zero. A query's leaf in a tree of height `h` is its index
    /// modulo `2^h`.
    #[allow(clippy::type_complexity)]
    fn trees(&self) -> Vec<(usize, Vec<(Digest, &[Digest])>)> {
        let nq = self.openings.len();
        let mut out = Vec::new();
        for t in 0..self.tables.len() {
            for k in 0..4 {
                let per_q: Vec<(Digest, &[Digest])> = (0..nq)
                    .map(|q| {
                        let o = &self.openings[q][t];
                        let (row, path) = match k {
                            0 => (&o.trace_row, &o.trace_path),
                            1 => (&o.aux_row, &o.aux_path),
                            2 => (&o.pre_row, &o.pre_path),
                            _ => (&o.quotient_row, &o.quotient_path),
                        };
                        (
                            if row.is_empty() {
                                [Fp::ZERO; crate::poseidon2::DIGEST]
                            } else {
                                crate::merkle::hash_row(row)
                            },
                            &path[..],
                        )
                    })
                    .collect();
                out.push((per_q.first().map_or(0, |p| p.1.len()), per_q));
            }
        }
        let rounds = self.fri.queries.first().map_or(0, |q| q.len());
        for r in 0..rounds {
            let per_q: Vec<(Digest, &[Digest])> = self
                .fri
                .queries
                .iter()
                .map(|q| (crate::merkle::hash_row(&leaf_row(&q[r].values)), &q[r].path[..]))
                .collect();
            out.push((per_q.first().map_or(0, |p| p.1.len()), per_q));
        }
        out
    }

    /// Encodes the proof. Merkle paths are batched per tree: a sibling
    /// that another opening determines, or that an earlier query already
    /// sent, is left out (see [`crate::merkle::compress_paths`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes().expect("a proof of one shape")
    }

    /// [`Proof::to_bytes`], or `None` for a proof the encoding cannot
    /// hold: queries, openings and indices that are not one for one,
    /// paths of one tree that differ in length, or a lookup total where
    /// there are no lookups. A prover makes none such.
    pub fn try_to_bytes(&self) -> Option<Vec<u8>> {
        let mut w = Writer::with_capacity(1 << 16);
        w.u32(self.tables.len() as u32);
        for t in &self.tables {
            t.write(&mut w);
        }
        let nq = self.openings.len();
        let rounds = self.fri.queries.first().map_or(0, |q| q.len());
        if self.query_indices.len() != nq
            || self.fri.queries.len() != nq
            || self.fri.queries.iter().any(|q| q.len() != rounds)
            || self.openings.iter().any(|o| o.len() != self.tables.len())
            || self.query_indices.iter().any(|&i| i > u32::MAX as usize)
            || self.tables.iter().any(|t| t.aux_root.is_none() && !t.lookup_sum.is_zero())
        {
            return None;
        }
        w.digest_vec(&self.fri.commitments);
        w.fp4(&self.fri.final_value);
        w.fp(&self.fri.pow_witness);
        w.fp_vec(&self.fri.fold_witnesses);
        for g in &self.grinding {
            w.fp(g);
        }
        w.u32(nq as u32);
        w.u32(rounds as u32);
        for (q, steps) in self.fri.queries.iter().enumerate() {
            w.u32(self.query_indices[q] as u32);
            for step in steps {
                w.fp4_vec(&step.values);
            }
            for o in &self.openings[q] {
                w.fp_vec(&o.trace_row);
                w.fp_vec(&o.aux_row);
                w.fp_vec(&o.pre_row);
                w.fp_vec(&o.quotient_row);
            }
        }
        let trees = self.trees();
        for (height, per_q) in &trees {
            if per_q.iter().any(|p| p.1.len() != *height) {
                return None;
            }
            w.u32(*height as u32);
        }
        for (height, per_q) in &trees {
            let leaves: Vec<Digest> = per_q.iter().map(|p| p.0).collect();
            let paths: Vec<&[Digest]> = per_q.iter().map(|p| p.1).collect();
            for d in crate::merkle::compress_paths(*height, &self.query_indices, &leaves, &paths) {
                w.digest(&d);
            }
        }
        Some(w.finish())
    }

    /// Parses a proof into its owned form, every path rebuilt: a
    /// prover's, and the recursion's, which lay a proof out as a witness.
    /// A verifier reads the bytes as they are ([`super::verify_bytes`]).
    /// The whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        let ProofHead { tables, commitments, final_value, pow_witness, fold_witnesses, grinding, num_queries, rounds, rest } =
            ProofHead::read(bytes)?;
        let (nt, nq) = (tables.len(), num_queries);
        let mut r = Reader(rest);
        // Capacity from the untrusted count, but not beyond any real proof's.
        let mut query_indices = Vec::with_capacity(nq.min(128));
        let mut fri_queries = Vec::with_capacity(nq.min(128));
        let mut openings = Vec::with_capacity(nq.min(128));
        for _ in 0..nq {
            query_indices.push(r.u32()? as usize);
            let steps = (0..rounds)
                .map(|_| Some(QueryStep { values: r.fp4_vec()?, path: Vec::new() }))
                .collect::<Option<Vec<_>>>()?;
            fri_queries.push(steps);
            let mut per_table = Vec::with_capacity(nt);
            for _ in 0..nt {
                per_table.push(QueryOpening {
                    trace_row: r.fp_vec()?,
                    trace_path: Vec::new(),
                    aux_row: r.fp_vec()?,
                    aux_path: Vec::new(),
                    pre_row: r.fp_vec()?,
                    pre_path: Vec::new(),
                    quotient_row: r.fp_vec()?,
                    quotient_path: Vec::new(),
                });
            }
            openings.push(per_table);
        }
        let mut proof = Proof {
            tables,
            fri: FriProof { commitments, final_value, pow_witness, fold_witnesses, queries: fri_queries },
            openings,
            query_indices,
            grinding,
        };
        let num_trees = 4 * nt + rounds;
        let mut heights = Vec::with_capacity(num_trees);
        for _ in 0..num_trees {
            let h = r.u32()? as usize;
            if h > 32 {
                return None;
            }
            heights.push(h);
        }
        // An absent tree (no lookups, no preprocessed columns) has height
        // zero: the verifier never opens it, so any other height would be
        // another encoding of the same proof.
        for (t, table) in proof.tables.iter().enumerate() {
            if (table.aux_root.is_none() && heights[4 * t + 1] != 0)
                || (table.pre_at_zeta.is_empty() && heights[4 * t + 2] != 0)
            {
                return None;
            }
        }
        let mut all_paths: Vec<Vec<Vec<Digest>>> = Vec::with_capacity(num_trees);
        for (tree, (_, per_q)) in proof.trees().into_iter().enumerate() {
            let leaves: Vec<Digest> = per_q.iter().map(|p| p.0).collect();
            all_paths.push(crate::merkle::expand_paths(heights[tree], &proof.query_indices, &leaves, || r.digest())?);
        }
        if !r.is_empty() {
            return None;
        }
        let mut it = all_paths.into_iter();
        for t in 0..nt {
            for k in 0..4 {
                for (q, path) in it.next().unwrap().into_iter().enumerate() {
                    let o = &mut proof.openings[q][t];
                    *match k {
                        0 => &mut o.trace_path,
                        1 => &mut o.aux_path,
                        2 => &mut o.pre_path,
                        _ => &mut o.quotient_path,
                    } = path;
                }
            }
        }
        for rd in 0..rounds {
            for (q, path) in it.next().unwrap().into_iter().enumerate() {
                proof.fri.queries[q][rd].path = path;
            }
        }
        Some(proof)
    }
}

/// What a proof's bytes begin with, read: everything before the queries.
/// Small, of a size set by the tables' widths and the FRI rounds, not by
/// the queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofHead<'a> {
    /// One part per table, tallest table first.
    pub tables: Vec<TableProof>,
    /// The FRI rounds' roots, final value and witnesses.
    pub commitments: Vec<Digest>,
    pub final_value: Fp4,
    pub pow_witness: Fp,
    pub fold_witnesses: Vec<Fp>,
    pub grinding: [Fp; 4],
    /// Queries the proof says it has (not zero), and FRI rounds a query.
    pub num_queries: usize,
    pub rounds: usize,
    /// The rest: for each query its index, its FRI leaves and its rows of
    /// each table; then every tree's height; then the siblings the
    /// openings of each tree do not determine, tree by tree.
    pub rest: &'a [u8],
}

impl<'a> ProofHead<'a> {
    pub fn read(bytes: &'a [u8]) -> Option<ProofHead<'a>> {
        let mut r = Reader(bytes);
        let nt = r.len(64)?;
        if nt == 0 {
            return None;
        }
        let tables = (0..nt).map(|_| TableProof::read(&mut r)).collect::<Option<Vec<_>>>()?;
        let commitments = r.digest_vec()?;
        let final_value = r.fp4()?;
        let pow_witness = r.fp()?;
        let fold_witnesses = r.fp_vec()?;
        let grinding = [r.fp()?, r.fp()?, r.fp()?, r.fp()?];
        let num_queries = r.len(4)?;
        let rounds = r.len(0)?;
        // No queries is no proof, and the FRI trees are counted from the
        // first query: with none, `rounds` would claim trees that are not
        // there.
        if num_queries == 0 || rounds > 32 {
            return None;
        }
        Some(ProofHead { tables, commitments, final_value, pow_witness, fold_witnesses, grinding, num_queries, rounds, rest: r.0 })
    }
}

/// Why a verifier refuses a proof. An opening that is not its tree's is
/// reported by tree: the openings of one tree travel and are checked
/// together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The bytes are not the encoding of a proof.
    Malformed,
    Shape,
    /// A proof-of-work witness before a commit-phase challenge is wrong.
    ProofOfWork,
    ConstraintIdentity,
    /// The tables' lookup totals do not cancel.
    LookupSum,
    Fri(FriError),
    InvalidTraceOpening {
        table: usize,
    },
    InvalidAuxOpening {
        table: usize,
    },
    InvalidPreprocessedOpening {
        table: usize,
    },
    InvalidQuotientOpening {
        table: usize,
    },
    /// An opening of a FRI round's tree is not the tree's.
    InvalidFriOpening {
        round: usize,
    },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Malformed => f.write_str("not the encoding of a stark proof"),
            VerifyError::Shape => f.write_str("stark proof has the wrong shape"),
            VerifyError::ProofOfWork => f.write_str("wrong proof of work before a challenge"),
            VerifyError::ConstraintIdentity => f.write_str("constraints do not hold at the out-of-domain point"),
            VerifyError::LookupSum => f.write_str("lookup totals of the tables do not cancel"),
            VerifyError::Fri(e) => write!(f, "{e}"),
            VerifyError::InvalidFriOpening { round } => write!(f, "fri round {round}: invalid merkle opening"),
            VerifyError::InvalidTraceOpening { table } => {
                write!(f, "table {table}: invalid trace opening")
            }
            VerifyError::InvalidAuxOpening { table } => {
                write!(f, "table {table}: invalid auxiliary opening")
            }
            VerifyError::InvalidPreprocessedOpening { table } => {
                write!(f, "table {table}: invalid preprocessed opening")
            }
            VerifyError::InvalidQuotientOpening { table } => {
                write!(f, "table {table}: invalid quotient opening")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<FriError> for VerifyError {
    fn from(e: FriError) -> Self {
        VerifyError::Fri(e)
    }
}
