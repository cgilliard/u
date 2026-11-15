//! XMSS signature verification as an AIR of its own: the fragment of
//! [`crate::xmss_fragment`], one signature a trace, and nothing else.
//!
//! The circuits that verify signatures (the transaction and name
//! segments) embed the fragment among their own rows. This AIR is the
//! least a circuit around it can be, so that the fragment is tested,
//! audited and measured by itself: the seven row types of the fragment
//! mapped onto the hash machine as it asks, and an eighth, `done`, that
//! pads the trace after the last tree row.
//!
//! ```text
//! msg_start, msg_abs(0), msg_abs(1)                 message digest sponge (3 rows)
//! for each of the 67 chains:
//!     load                                          digest := signature value
//!     step x 15                                     pass while digits remain, then chain steps
//!     leaf                                          absorb the chain end into the leaf sponge
//! for each tree level of the key's height:
//!     tree_start, tree_abs                          th(DOM_TREE, pos, level, left || right)
//! done ...                                          padding
//! ```
//!
//! Public values: `root[8] | pub_seed[4] | height | msg[8]`. Witness: the
//! signature (index, randomizer, 67 chain values, a sibling a level). A
//! key of any height, 1 to [`MAX_HEIGHT`], fits 2,048 rows.

use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder, NUM_COLS as HM_COLS,
    eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp};
use crate::stark::{Air, Builder, Trace};
use crate::xmss::{Digest, MAX_HEIGHT, PUB_SEED_LEN, PublicKey, Signature};
use crate::xmss_fragment::{self, Cols, Regs, Types, height_value};

// Row type flags.
pub const T_MSG_START: usize = HM_COLS;
pub const T_MSG_ABS: usize = HM_COLS + 1;
pub const T_LOAD: usize = HM_COLS + 2;
pub const T_STEP: usize = HM_COLS + 3;
pub const T_LEAF: usize = HM_COLS + 4;
pub const T_TREE_START: usize = HM_COLS + 5;
pub const T_TREE_ABS: usize = HM_COLS + 6;
pub const T_DONE: usize = HM_COLS + 7;
const NUM_TYPES: usize = 8;
/// The fragment's columns, after the row types.
pub const COLS: Cols = Cols::new(HM_COLS + NUM_TYPES);
pub const TYPES: Types = Types {
    msg_start: T_MSG_START,
    msg_abs: T_MSG_ABS,
    load: T_LOAD,
    step: T_STEP,
    leaf: T_LEAF,
    tree_start: T_TREE_START,
    tree_abs: T_TREE_ABS,
};
pub const NUM_COLS: usize = COLS.base + xmss_fragment::LEN;

pub const PUB_ROOT: usize = 0;
pub const PUB_SEED: usize = DIGEST;
pub const PUB_HEIGHT: usize = PUB_SEED + PUB_SEED_LEN;
pub const PUB_MSG: usize = PUB_HEIGHT + 1;
pub const NUM_PUBLIC: usize = PUB_MSG + DIGEST;

/// Rows of the trace: a signature by the tallest key and a `done` row fit.
pub const ROWS: usize = (xmss_fragment::ROWS + 1).next_power_of_two();

/// The XMSS verification AIR.
pub struct XmssAir;

impl Air for XmssAir {
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
        let public = b.public();
        let one = F::ONE;

        // Row types, and the machine op each is.
        b.mark("xmss air row types");
        let types: [F; NUM_TYPES] = core::array::from_fn(|i| l[T_MSG_START + i]);
        let [msg_start, msg_abs, load, step, leaf, tree_start, tree_abs, done] = types;
        for t in types {
            b.assert_zero(t * t - t);
        }
        b.assert_eq(types.iter().fold(F::ZERO, |a, t| a + *t), one);
        let active = l[COLS.active()];
        b.assert_eq(l[COL_START], msg_start + leaf + tree_start);
        b.assert_eq(l[COL_ABSORB], msg_abs + tree_abs);
        b.assert_eq(l[COL_LOAD], load);
        b.assert_eq(l[COL_CHAIN], step * active);
        b.assert_eq(l[COL_PASS], step * (one - active) + done);
        b.assert_zero(l[COL_COMPRESS]);
        // One signature: it starts the trace, and what follows it is padding.
        b.when_first_row(one - msg_start);
        b.when_last_row(one - done);
        b.when_transition(done * (one - n[T_DONE]));

        // The signature, over the public message.
        let msg: [F; DIGEST] = core::array::from_fn(|i| public[PUB_MSG + i]);
        xmss_fragment::eval(b, &COLS, &TYPES, &msg, n[T_DONE]);

        // The key it verifies under is the public one: its seed and height
        // where the signature starts, its root where the tree ends.
        b.mark("xmss air key");
        for i in 0..PUB_SEED_LEN {
            b.when_first_row(l[COLS.pub_seed(i)] - public[PUB_SEED + i]);
        }
        b.when_first_row(height_value(l, &COLS) - public[PUB_HEIGHT]);
        let end = tree_abs * l[COLS.tlast()];
        for i in 0..DIGEST {
            b.assert_zero(end * (l[COL_ACC + i] - public[PUB_ROOT + i]));
        }
    }
}

impl XmssAir {
    /// Builds the trace for verifying `sig` on `msg` under `pk`. The
    /// generator refuses a signature that does not verify.
    pub fn generate_trace(pk: &PublicKey, msg: &Digest, sig: &Signature) -> Trace {
        let mut b = HashTraceBuilder::with_capacity(NUM_COLS, ROWS);
        let mut regs = Regs::default();
        xmss_fragment::generate(&mut b, &mut regs, &COLS, &TYPES, msg, sig, pk, &mut |_, _| {});
        debug_assert_eq!(b.len(), xmss_fragment::rows(pk.height()));
        // Done rows to the trace's height.
        while b.len() < ROWS {
            b.pass();
            let row = b.last_row_mut();
            row[T_DONE] = Fp::ONE;
            regs.write(row, &COLS);
        }
        b.finish()
    }

    /// Public values for `pk` and `msg`.
    pub fn public_values(pk: &PublicKey, msg: &Digest) -> [Fp; NUM_PUBLIC] {
        let mut v = [Fp::ZERO; NUM_PUBLIC];
        v[PUB_ROOT..PUB_SEED].copy_from_slice(&pk.root);
        v[PUB_SEED..PUB_HEIGHT].copy_from_slice(&pk.pub_seed);
        v[PUB_HEIGHT] = Fp::new(pk.height as u32);
        v[PUB_MSG..].copy_from_slice(msg);
        v
    }
}

const _: () = assert!(ROWS == 2048 && MAX_HEIGHT == 20);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::hash_machine::{COL_DATA, COL_DIR};
    use crate::poseidon2::P;
    use crate::stark::audit::{audit_report, freedom_report, fuzz_proof, mutation_audit};
    use crate::stark::{LENIENT, TableSpec};
    use crate::stark::{Proof, StarkConfig, check_constraints, measure_degree, prove, verify, verify_bytes};
    use crate::xmss::{DOM_TREE, SecretKey, th};
    use crate::xmss_fragment::rows;

    fn key(tag: u8, height: usize) -> SecretKey {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        SecretKey::generate_with_height(&seed, height)
    }

    fn msg(tag: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(tag.wrapping_mul(i as u32 + 7) % P))
    }

    /// A signature by a key of `height` at its leaf `leaf`, the leaves
    /// before it spent.
    fn signed(tag: u8, height: usize, leaf: u64, m: &Digest) -> (PublicKey, Signature) {
        let mut sk = key(tag, height);
        sk.set_next_index(leaf);
        let sig = sk.sign(m).unwrap();
        assert_eq!(sig.index, leaf);
        let pk = sk.public_key();
        assert!(pk.verify(m, &sig));
        (pk, sig)
    }

    /// A key of `height` too tall to generate, with a signature at leaf
    /// `leaf` (0 or 1): the leaf a key of height one signs with, and
    /// above it the siblings a tall tree might have, hashed up to the root
    /// that makes.
    fn tall(tag: u8, height: usize, leaf: u64, m: &Digest) -> (PublicKey, Signature) {
        let (low, mut sig) = signed(tag, 1, leaf, m);
        let mut node = leaf_of(&low, m, &sig);
        let mut index = leaf;
        sig.auth_path = Default::default();
        for lv in 0..height {
            let sib: Digest = core::array::from_fn(|i| Fp::new(7000 + 31 * lv as u32 + i as u32));
            let right = index & 1 == 1;
            index >>= 1;
            let mut both = [Fp::ZERO; 2 * DIGEST];
            both[..DIGEST].copy_from_slice(if right { &sib } else { &node });
            both[DIGEST..].copy_from_slice(if right { &node } else { &sib });
            node = th(&low.pub_seed, DOM_TREE, (height as u64) << 30 | index, (lv + 1) as u32, &both);
            sig.auth_path.push(sib);
        }
        let pk = PublicKey { root: node, pub_seed: low.pub_seed, height: height as u8 };
        assert!(pk.verify(m, &sig), "the tall key's signature verifies natively");
        (pk, sig)
    }

    /// The leaf a signature's chains end in: read off the trace of its
    /// verification, on the row before the first tree row.
    fn leaf_of(pk: &PublicKey, m: &Digest, sig: &Signature) -> Digest {
        let trace = XmssAir::generate_trace(pk, m, sig);
        let last_leaf = rows(pk.height()) - 2 * pk.height() - 1;
        assert_eq!(trace.row(last_leaf)[T_LEAF], Fp::ONE);
        trace.row(last_leaf)[COL_ACC..COL_ACC + DIGEST].try_into().unwrap()
    }

    #[test]
    fn layout() {
        assert_eq!(measure_degree(&XmssAir, NUM_PUBLIC), 3);
        assert_eq!(rows(4), 3 + 67 * 17 + 8);
        assert_eq!(xmss_fragment::ROWS, 3 + 67 * 17 + 40);
        assert_eq!(NUM_PUBLIC, 21);
        assert_eq!((xmss_fragment::LEN, NUM_COLS), (176, 521));
    }

    /// Keys of several heights, at their first leaf, their last and one
    /// between: the trace holds, for that key, message and height only.
    #[test]
    fn genuine_signatures_satisfy_constraints() {
        for (tag, height) in [(1u8, 1usize), (2, 2), (3, 4), (4, 7)] {
            let last = (1u64 << height) - 1;
            for leaf in [0, last / 2, last] {
                let m = msg(leaf as u32 + 17 * height as u32);
                let (pk, sig) = signed(tag, height, leaf, &m);
                let trace = XmssAir::generate_trace(&pk, &m, &sig);
                assert_eq!(trace.height(), ROWS);
                let public = XmssAir::public_values(&pk, &m);
                assert_eq!(check_constraints(&XmssAir, &trace, &public), Ok(()), "height {height} leaf {leaf}");
                for at in [PUB_ROOT, PUB_SEED + 1, PUB_HEIGHT, PUB_MSG + 3, PUB_MSG + DIGEST - 1] {
                    let mut bad = public;
                    bad[at] += Fp::ONE;
                    assert!(check_constraints(&XmssAir, &trace, &bad).is_err(), "public value {at}");
                }
            }
        }
    }

    /// The tallest key and others too tall to generate.
    #[test]
    fn tall_keys() {
        for (height, leaf) in [(8usize, 0u64), (13, 1), (MAX_HEIGHT, 1), (MAX_HEIGHT, 0)] {
            let m = msg(height as u32);
            let (pk, sig) = tall(9, height, leaf, &m);
            let trace = XmssAir::generate_trace(&pk, &m, &sig);
            let public = XmssAir::public_values(&pk, &m);
            assert_eq!(check_constraints(&XmssAir, &trace, &public), Ok(()), "height {height}");
            // The same nodes are not a key of one level fewer or more.
            let mut bad = public;
            bad[PUB_HEIGHT] -= Fp::ONE;
            assert!(check_constraints(&XmssAir, &trace, &bad).is_err());
        }
    }

    /// Degrees-of-freedom audit of one signature: each way a row's cells
    /// can move together unseen.
    #[test]
    fn has_no_unintended_freedom() {
        let m = msg(5);
        let (pk, sig) = signed(1, 4, 7, &m);
        let trace = XmssAir::generate_trace(&pk, &m, &sig);
        let public = XmssAir::public_values(&pk, &m);
        let kinds: Vec<usize> = (COL_START..=COL_DIR).collect();
        let lines = freedom_report(&XmssAir, &trace, None, &public, &kinds, 6, |f| {
            // A permutation on a row that does not use it is free by design.
            let row = trace.row(f.row);
            let unused = row[COL_PASS] == Fp::ONE || row[COL_LOAD] == Fp::ONE;
            !(unused && f.cells.iter().all(|(c, _)| *c < crate::poseidon2_air::NUM_COLS))
        });
        assert!(lines.is_empty(), "{} freedoms:\n{}", lines.len(), lines.join("\n"));
    }

    /// Soundness audit: the cells a prover can add one to unseen are the
    /// scratch the fragment leaves on rows that do not read it, and no
    /// other: the machine's `dir` and `data` off the rows whose op uses
    /// them, the bit decomposition off the load rows (an enclosing circuit
    /// may range its own values there), the chain's countdown and its
    /// inverse off the chains, the sibling off the tree.
    #[test]
    fn the_free_cells_are_scratch() {
        let m = msg(6);
        let (pk, sig) = signed(1, 4, 9, &m);
        let trace = XmssAir::generate_trace(&pk, &m, &sig);
        let public = XmssAir::public_values(&pk, &m);
        let survivors = mutation_audit(&[(&XmssAir, &trace, None)], &public, 256);
        let report = audit_report(&survivors, |_, c| format!("column {c}"));
        let mut seen = std::collections::BTreeSet::new();
        for s in &survivors {
            let row = trace.row(s.row);
            let is = |t: usize| row[t] == Fp::ONE;
            let tree = is(T_TREE_START) || is(T_TREE_ABS);
            let (c, class) = (s.column, |from: usize, len: usize| (from..from + len).contains(&s.column));
            let scratch = if c == COL_DIR {
                (!tree).then_some("dir")
            } else if class(COL_DATA, DIGEST) {
                (is(COL_START) || is(COL_PASS)).then_some("data")
            } else if class(COLS.bits(0), xmss_fragment::BITS) {
                (!is(T_LOAD)).then_some("bits")
            } else if c == COLS.rem() {
                (!is(T_LOAD) && !is(T_STEP)).then_some("rem")
            } else if c == COLS.rem_inv() {
                // Read only where a step passes: it shows the countdown is not zero.
                (!is(T_STEP) || is(COLS.active())).then_some("rem_inv")
            } else if class(COLS.sib(0), DIGEST) {
                (!tree).then_some("sib")
            } else {
                None
            };
            let Some(name) = scratch else { panic!("column {c} is free on row {}\n{report}", s.row) };
            seen.insert(name);
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), ["bits", "data", "dir", "rem", "rem_inv", "sib"]);
    }

    #[test]
    fn forged_witness_fails_constraints() {
        let m = msg(5);
        let (pk, sig) = signed(2, 4, 0, &m);
        let trace = XmssAir::generate_trace(&pk, &m, &sig);
        let public = XmssAir::public_values(&pk, &m);
        let w = NUM_COLS;
        let refused = |t: &Trace| check_constraints(&XmssAir, t, &public).is_err();

        // Tamper a chain value on its load row (data and acc together).
        let load_row = 3 + 10 * 17;
        assert_eq!(trace.row(load_row)[T_LOAD], Fp::ONE);
        let mut bad = trace.clone();
        bad.values[load_row * w + COL_DATA] += Fp::ONE;
        bad.values[load_row * w + COL_ACC] += Fp::ONE;
        assert!(refused(&bad));

        // Claim a different digit (skip one chain step) on a chain.
        let mut bad = trace.clone();
        bad.values[load_row * w + COLS.d()] += Fp::ONE;
        assert!(refused(&bad));

        // Flip an index bit everywhere: tweaks and tree path change.
        let mut bad = trace.clone();
        for r in 0..trace.height() {
            let v = &mut bad.values[r * w + COLS.idx(0)];
            *v = Fp::ONE - *v;
        }
        assert!(refused(&bad));

        // An index bit at the key's height, everywhere: a leaf past the tree.
        let mut bad = trace.clone();
        for r in 0..trace.height() {
            bad.values[r * w + COLS.idx(4)] = Fp::ONE;
        }
        assert!(refused(&bad));

        // Stop early: turn the last tree row into a done row.
        let mut bad = trace.clone();
        let last_tree = rows(4) - 1;
        assert_eq!(trace.row(last_tree)[T_TREE_ABS], Fp::ONE);
        bad.values[last_tree * w + T_TREE_ABS] = Fp::ZERO;
        bad.values[last_tree * w + T_DONE] = Fp::ONE;
        assert!(refused(&bad));

        // Claim a shorter tree: the height register one less on every row,
        // the tree ending a level early at a node that is not the root.
        let mut bad = trace.clone();
        for r in 0..trace.height() {
            bad.values[r * w + COLS.hsel(3)] = Fp::ZERO;
            bad.values[r * w + COLS.hsel(2)] = Fp::ONE;
        }
        assert!(refused(&bad));

        // A signature from another key on the same message.
        let (other, sig2) = signed(3, 4, 0, &m);
        let trace2 = XmssAir::generate_trace(&other, &m, &sig2);
        assert!(check_constraints(&XmssAir, &trace2, &public).is_err());
        assert_eq!(check_constraints(&XmssAir, &trace2, &XmssAir::public_values(&other, &m)), Ok(()));

        // A signature that does not verify: the generator refuses it, and
        // made to write the trace anyway, the constraints do.
        let mut forged = sig.clone();
        forged.wots[5][0] += Fp::ONE;
        assert!(!pk.verify(&m, &forged));
        LENIENT.with(|l| l.set(true));
        let bad = XmssAir::generate_trace(&pk, &m, &forged);
        LENIENT.with(|l| l.set(false));
        assert!(refused(&bad));
        let mut wrong_leaf = sig.clone();
        wrong_leaf.index = 1;
        LENIENT.with(|l| l.set(true));
        let bad = XmssAir::generate_trace(&pk, &m, &wrong_leaf);
        LENIENT.with(|l| l.set(false));
        assert!(refused(&bad));
    }

    #[test]
    #[should_panic(expected = "signature does not verify")]
    fn the_generator_refuses_a_forgery() {
        let m = msg(5);
        let (pk, mut sig) = signed(2, 4, 0, &m);
        sig.randomizer[0] += Fp::ONE;
        XmssAir::generate_trace(&pk, &m, &sig);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn prove_and_verify_signature() {
        let config = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0, zk: false, commit_bits: 0 };
        let m = msg(11);
        let (pk, sig) = signed(4, 4, 3, &m);
        let trace = XmssAir::generate_trace(&pk, &m, &sig);
        let public = XmssAir::public_values(&pk, &m);
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xc3));
            c
        };
        let proof = prove(&config, &XmssAir, &trace, &public, &mut tr());
        assert_eq!(verify(&config, &XmssAir, &public, &proof, &mut tr()), Ok(()));
        // The verifier, fuzzed, with and without zero knowledge.
        let (iters, seed) = crate::test_util::fuzz_params(200, 0xf022_55);
        let verifies = |p: &Proof| verify(&config, &XmssAir, &public, p, &mut tr()).is_ok();
        let fuzz = fuzz_proof(&proof, iters, seed, verifies);
        assert!(fuzz.accepted.is_empty() && fuzz.panicked.is_empty(), "seed {seed}: {fuzz:?}");
        let zk = StarkConfig { zk: true, log_blowup: 2, ..config };
        let proof_zk = prove(&zk, &XmssAir, &trace, &public, &mut tr());
        let verifies = |p: &Proof| verify(&zk, &XmssAir, &public, p, &mut tr()).is_ok();
        let fuzz = fuzz_proof(&proof_zk, iters, seed + 1, verifies);
        assert!(fuzz.accepted.is_empty() && fuzz.panicked.is_empty(), "zk, seed {}: {fuzz:?}", seed + 1);
        // Every value of the first table's height (its `log_n`, from byte
        // 4): a large one once overflowed the zero-knowledge shape check.
        let bytes = proof_zk.to_bytes();
        let specs = [TableSpec { air: &XmssAir, pre_root: None }];
        assert_eq!(verify_bytes(&zk, &specs, &public, &bytes, &mut tr()), Ok(()));
        for v in 0..=255u8 {
            let mut b = bytes.clone();
            b[4] = v;
            if b != bytes {
                assert!(verify_bytes(&zk, &specs, &public, &b, &mut tr()).is_err(), "a height of byte {v} verified");
            }
        }
        let mut bad = public;
        bad[PUB_MSG] += Fp::ONE;
        assert!(verify(&config, &XmssAir, &bad, &proof, &mut tr()).is_err());
    }
}
