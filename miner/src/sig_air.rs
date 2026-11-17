//! The signature segment: a trace of XMSS signature checks and nothing
//! else, and what it says in public (`docs/PREPROVING.md`).
//!
//! A transaction segment once checked each of its inputs' signatures
//! itself, beside the state it spends them from. A signature is most of
//! the rows of an input and has nothing to do with the state: whether a
//! key signed a message is the same at any block. Here signatures are
//! checked apart, in a proof that speaks of no block, which can be made
//! when a transaction is first seen and kept until it is in a block.
//!
//! # What it says
//!
//! For each signature it checks, an **entry**:
//!
//! ```text
//! entry = compress(key hash, message)
//! ```
//!
//! the key hash as an output's commitment takes it
//! ([`crate::output::pubkey_hash`]), the message whatever was signed.
//! The public values are the entries, [`SLOTS`] of them, in the order
//! checked; a slot with no signature holds zeros, which no entry is.
//! Whoever verifies the proof makes of them what it needs: a tree, of
//! which a transaction segment shows a path to one.
//!
//! An entry is a compression of two digests and not a hash under a
//! domain of its own. It is only ever a leaf of a tree of a fixed
//! depth, read at that depth, so it is taken for nothing else.
//!
//! # Schedule
//!
//! ```text
//! for each signature:
//!     the fragment's rows            message, chains, the key's tree ([`crate::xmss_fragment`])
//!     pkh0, pkh1                     the key's hash: its root, its seed and its height
//!     ent                            compress(key hash, message): the entry
//! done ...                           padding
//! ```
//!
//! The message is a register, free where a signature starts and held to
//! the entry's row. A count of the slots filled, as a run of ones, says
//! which public values an entry row is held to, and on the last row
//! that the slots not filled are zeros.

use crate::field::Field;
use crate::hash::DOM_PUBKEY;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::output::pubkey_hash;
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, compress};
use crate::poseidon2_air::COL_INPUT;
use crate::stark::{Air, Builder, Trace};
use crate::xmss::{Digest, PUB_SEED_LEN, PublicKey, Signature};
use crate::xmss_fragment::{self, Cols, Regs, Types, height_value};

// Row types (one-hot).
pub const T_MSG_START: usize = HM_COLS;
pub const T_MSG_ABS: usize = HM_COLS + 1;
pub const T_LOAD: usize = HM_COLS + 2;
pub const T_STEP: usize = HM_COLS + 3;
pub const T_LEAF: usize = HM_COLS + 4;
pub const T_TREE_START: usize = HM_COLS + 5;
pub const T_TREE_ABS: usize = HM_COLS + 6;
pub const T_PKH0: usize = HM_COLS + 7;
pub const T_PKH1: usize = HM_COLS + 8;
pub const T_ENT: usize = HM_COLS + 9;
pub const T_DONE: usize = HM_COLS + 10;
const NUM_TYPES: usize = 11;

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

/// Entries a segment has room to say: more than the signatures by the
/// tallest keys that fit a main network's segment, so that shorter keys
/// are not held to fewer than fit.
pub const SLOTS: usize = 32;

/// The message a signature is over: free where it starts, held to its
/// entry.
pub const R_MSG: usize = COLS.base + xmss_fragment::LEN;
/// Slots filled so far, as a run of ones.
pub const R_FILLED: usize = R_MSG + DIGEST;
pub const NUM_COLS: usize = R_FILLED + SLOTS;

/// Public values: the entries, a digest a slot.
pub const NUM_PUBLIC: usize = SLOTS * DIGEST;

/// Rows of a signature by a key of `height`, with its key hash and entry.
pub const fn rows(height: usize) -> usize {
    xmss_fragment::rows(height) + 3
}

/// What a signature segment says of a signature by `pk` over `msg`.
pub fn entry(pk: &PublicKey, msg: &Digest) -> Digest {
    entry_of(&pubkey_hash(pk), msg)
}

/// [`entry`] from the key's hash: what a circuit that has the key hash
/// and the message computes, to look the entry up.
pub fn entry_of(key_hash: &Digest, msg: &Digest) -> Digest {
    compress(key_hash, msg)
}

fn cap_pk<F: Field>() -> [F; RATE] {
    let mut c = [F::ZERO; RATE];
    c[0] = F::from_u32(DOM_PUBKEY);
    c[1] = F::from_u32((DIGEST + PUB_SEED_LEN + 1) as u32);
    c
}

/// The signature segment's AIR.
pub struct SigAir;

impl Air for SigAir {
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
        b.mark("sig air row types");
        let types: [F; NUM_TYPES] = core::array::from_fn(|i| l[T_MSG_START + i]);
        let [msg_start, msg_abs, load, step, leaf, tree_start, tree_abs, pkh0, pkh1, ent, done] = types;
        for t in types {
            b.assert_zero(t * t - t);
        }
        b.assert_eq(types.iter().fold(F::ZERO, |a, t| a + *t), one);
        let active = l[COLS.active()];
        b.assert_eq(l[COL_START], msg_start + leaf + tree_start + pkh0);
        b.assert_eq(l[COL_ABSORB], msg_abs + tree_abs + pkh1);
        b.assert_eq(l[COL_LOAD], load);
        b.assert_eq(l[COL_CHAIN], step * active);
        b.assert_eq(l[COL_PASS], step * (one - active) + done);
        b.assert_eq(l[COL_COMPRESS], ent);

        // The order of things: signatures from the first row, each to its
        // key hash and its entry, and padding to the last.
        b.mark("sig air order");
        b.when_first_row(one - msg_start - done);
        b.when_last_row(one - done);
        b.when_transition(done * (one - n[T_DONE]));
        b.when_transition(pkh0 * (one - n[T_PKH1]));
        b.when_transition(pkh1 * (one - n[T_ENT]));
        b.when_transition(ent * (one - n[T_MSG_START] - n[T_DONE]));
        // And nothing is come to but from what leads to it: a key hash
        // from the top of a key's tree, an entry from a key hash, a
        // signature or the padding from an entry.
        b.when_transition(n[T_PKH0] * (one - tree_abs * l[COLS.tlast()]));
        b.when_transition(n[T_PKH1] * (one - pkh0));
        b.when_transition(n[T_ENT] * (one - pkh1));
        b.when_transition(n[T_MSG_START] * (one - ent));
        b.when_transition(n[T_DONE] * (one - ent - done));

        // The signature, over the message register.
        let msg: [F; DIGEST] = core::array::from_fn(|i| l[R_MSG + i]);
        xmss_fragment::eval(b, &COLS, &TYPES, &msg, n[T_PKH0]);
        b.mark("sig air message");
        for i in 0..DIGEST {
            b.when_transition((one - n[T_MSG_START]) * (n[R_MSG + i] - l[R_MSG + i]));
        }

        // The key's hash: its root, where its tree ended, then its seed
        // and height, as the fragment holds them.
        b.mark("sig air key hash");
        let cap = cap_pk::<F>();
        for i in 0..RATE {
            b.when_transition(n[T_PKH0] * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.assert_zero(pkh0 * (l[COL_INPUT + RATE + i] - cap[i]));
            let data = match i {
                _ if i < PUB_SEED_LEN => l[COLS.pub_seed(i)],
                PUB_SEED_LEN => height_value(l, &COLS),
                _ => F::ZERO,
            };
            b.assert_zero(pkh1 * (l[COL_DATA + i] - data));
        }

        // The entry: the key hash with the message, into the next slot.
        b.mark("sig air entry");
        b.assert_zero(ent * l[COL_DIR]);
        for i in 0..DIGEST {
            b.assert_zero(ent * (l[COL_DATA + i] - l[R_MSG + i]));
        }
        let filled: [F; SLOTS] = core::array::from_fn(|j| l[R_FILLED + j]);
        // Which slot is next: the first not filled.
        let current: [F; SLOTS] = core::array::from_fn(|j| if j == 0 { one } else { filled[j - 1] } - filled[j]);
        for j in 0..SLOTS {
            b.assert_zero(filled[j] * filled[j] - filled[j]);
            if j > 0 {
                b.assert_zero(filled[j] * (one - filled[j - 1]));
            }
            b.when_first_row(filled[j]);
            b.when_transition(n[R_FILLED + j] - filled[j] - ent * current[j]);
        }
        // An entry has a slot to go to.
        b.assert_zero(ent * filled[SLOTS - 1]);
        for i in 0..DIGEST {
            let said = (0..SLOTS).fold(F::ZERO, |a, j| a + current[j] * public[j * DIGEST + i]);
            b.assert_zero(ent * (l[COL_ACC + i] - said));
            // A slot not filled says nothing.
            for j in 0..SLOTS {
                b.when_last_row((one - filled[j]) * public[j * DIGEST + i]);
            }
        }
    }
}

impl SigAir {
    /// The trace checking each signature in turn, of `2^log_n` rows.
    /// The generator refuses a signature that does not verify.
    ///
    /// # Panics
    ///
    /// If there are more signatures than slots, or than fit the rows.
    pub fn generate_trace(signed: &[(PublicKey, Digest, Signature)], log_n: usize) -> Trace {
        assert!(signed.len() <= SLOTS, "more signatures than a segment says");
        let height = 1usize << log_n;
        let mut b = HashTraceBuilder::with_capacity(NUM_COLS, height);
        let mut regs = Regs::default();
        let rest = |row: &mut [Fp], msg: &Digest, filled: usize| {
            row[R_MSG..R_MSG + DIGEST].copy_from_slice(msg);
            row[R_FILLED..R_FILLED + filled].fill(Fp::ONE);
        };
        let mut last = [Fp::ZERO; DIGEST];
        for (k, (pk, msg, sig)) in signed.iter().enumerate() {
            let root = xmss_fragment::generate(&mut b, &mut regs, &COLS, &TYPES, msg, sig, pk, &mut |row, _| {
                rest(row, msg, k)
            });
            assert_eq!(root, pk.root, "signature does not verify");
            let mut input = [Fp::ZERO; WIDTH];
            input[..RATE].copy_from_slice(&root);
            input[RATE..].copy_from_slice(&cap_pk::<Fp>());
            b.start(input);
            let mut seed = [Fp::ZERO; RATE];
            seed[..PUB_SEED_LEN].copy_from_slice(&pk.pub_seed);
            seed[PUB_SEED_LEN] = Fp::new(pk.height as u32);
            for (t, step) in [(T_PKH0, 0), (T_PKH1, 1), (T_ENT, 2)] {
                match step {
                    0 => {}
                    1 => {
                        b.absorb(seed);
                    }
                    _ => {
                        b.compress(*msg, false);
                    }
                }
                let row = b.last_row_mut();
                row[t] = Fp::ONE;
                regs.write(row, &COLS);
                rest(row, msg, k);
            }
            debug_assert_eq!(b.acc(), entry(pk, msg));
            last = *msg;
        }
        assert!(b.len() < height, "the signatures do not fit the rows");
        while b.len() < height {
            b.pass();
            let row = b.last_row_mut();
            row[T_DONE] = Fp::ONE;
            regs.write(row, &COLS);
            rest(row, &last, signed.len());
        }
        b.finish()
    }

    /// The public values of a segment that checks these, in this order.
    pub fn public_values<'a>(signed: impl IntoIterator<Item = (&'a PublicKey, &'a Digest)>) -> [Fp; NUM_PUBLIC] {
        let mut v = [Fp::ZERO; NUM_PUBLIC];
        for (j, (pk, msg)) in signed.into_iter().enumerate() {
            v[j * DIGEST..(j + 1) * DIGEST].copy_from_slice(&entry(pk, msg));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::poseidon2::P;
    use crate::stark::audit::freedom_report;
    use crate::stark::{StarkConfig, check_constraints, measure_degree, prove, verify};
    use crate::xmss::SecretKey;

    fn msg(tag: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(tag.wrapping_mul(i as u32 + 7) % P))
    }

    /// A signature over `m` by a key of `height` at its leaf `leaf`.
    fn signed(tag: u8, height: usize, leaf: u64, m: Digest) -> (PublicKey, Digest, Signature) {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        let mut sk = SecretKey::generate_with_height(&seed, height);
        sk.set_next_index(leaf);
        let sig = sk.sign(&m).unwrap();
        (sk.public_key(), m, sig)
    }

    fn several() -> Vec<(PublicKey, Digest, Signature)> {
        vec![signed(1, 2, 3, msg(5)), signed(2, 4, 0, msg(6)), signed(1, 2, 1, msg(7)), signed(3, 1, 1, msg(5))]
    }

    fn said(s: &[(PublicKey, Digest, Signature)]) -> [Fp; NUM_PUBLIC] {
        SigAir::public_values(s.iter().map(|(pk, m, _)| (pk, m)))
    }

    const LOG_N: usize = 13;

    #[test]
    fn layout() {
        assert_eq!(measure_degree(&SigAir, NUM_PUBLIC), 3);
        assert_eq!(rows(20), 3 + 67 * 17 + 40 + 3);
        assert_eq!((NUM_PUBLIC, NUM_COLS), (256, HM_COLS + 11 + xmss_fragment::LEN + 8 + 32));
        // A main network's segment holds this many by the tallest keys,
        // and has a slot for each.
        assert!((1 << 15) / rows(20) <= SLOTS);
    }

    /// Signatures by several keys of several heights, two by one key
    /// and two over one message: the trace holds for their entries, in
    /// their order, and for nothing else.
    #[test]
    fn signatures_are_said_in_their_order() {
        let s = several();
        let trace = SigAir::generate_trace(&s, LOG_N);
        assert_eq!(trace.height(), 1 << LOG_N);
        let public = said(&s);
        assert_eq!(check_constraints(&SigAir, &trace, &public), Ok(()));
        for j in 0..s.len() {
            assert_eq!(public[j * DIGEST..(j + 1) * DIGEST], entry(&s[j].0, &s[j].1));
            assert_eq!(entry(&s[j].0, &s[j].1), entry_of(&pubkey_hash(&s[j].0), &s[j].1));
        }
        assert!(public[s.len() * DIGEST..].iter().all(|x| *x == Fp::ZERO));
        // Any value of an entry changed, or a slot not filled said to be.
        for at in [0, 7, 8, 3 * DIGEST + 5, 4 * DIGEST, NUM_PUBLIC - 1] {
            let mut bad = public;
            bad[at] += Fp::ONE;
            assert!(check_constraints(&SigAir, &trace, &bad).is_err(), "public value {at}");
        }
        // Two entries the other way round, or one left out.
        let mut swapped = s.clone();
        swapped.swap(0, 1);
        assert!(check_constraints(&SigAir, &trace, &said(&swapped)).is_err());
        assert!(check_constraints(&SigAir, &trace, &said(&s[..3])).is_err());
        // Another message, or another key, is another entry.
        assert_ne!(entry(&s[0].0, &s[0].1), entry(&s[0].0, &s[1].1));
        assert_ne!(entry(&s[0].0, &s[0].1), entry(&s[1].0, &s[0].1));
    }

    /// No signature at all: padding, and every slot zeros.
    #[test]
    fn a_segment_of_nothing_says_nothing() {
        let trace = SigAir::generate_trace(&[], 6);
        assert_eq!(check_constraints(&SigAir, &trace, &[Fp::ZERO; NUM_PUBLIC]), Ok(()));
        let mut bad = [Fp::ZERO; NUM_PUBLIC];
        bad[0] = Fp::ONE;
        assert!(check_constraints(&SigAir, &trace, &bad).is_err());
    }

    /// As many signatures as there are slots, by short keys.
    #[test]
    fn every_slot_can_be_filled() {
        let s: Vec<_> = (0..SLOTS).map(|j| signed(1, 1, (j % 2) as u64, msg(100 + j as u32))).collect();
        let trace = SigAir::generate_trace(&s, 16);
        assert_eq!(check_constraints(&SigAir, &trace, &said(&s)), Ok(()));
    }

    /// What the trace says cannot be moved off what was signed: the
    /// message register changed on its way to the entry, the entry's
    /// row skipped, the key hash's rows of another key, a slot marked
    /// filled that is not.
    #[test]
    fn a_trace_altered_does_not_hold() {
        let s = several();
        let public = said(&s);
        let good = SigAir::generate_trace(&s, LOG_N);
        let w = NUM_COLS;
        let row_of = |t: usize, which: usize| {
            (0..good.height()).filter(|r| good.row(*r)[t] == Fp::ONE).nth(which).expect("there is such a row")
        };
        // The message, from some row of the first signature on.
        let mut bad = good.clone();
        let from = row_of(T_LEAF, 3);
        for r in from..=row_of(T_ENT, 0) {
            bad.values[r * w + R_MSG] += Fp::ONE;
        }
        assert!(check_constraints(&SigAir, &bad, &public).is_err());
        // The message on the entry's row alone.
        let mut bad = good.clone();
        bad.values[row_of(T_ENT, 1) * w + R_MSG + 2] += Fp::ONE;
        assert!(check_constraints(&SigAir, &bad, &public).is_err());
        // A slot marked filled before its entry.
        let mut bad = good.clone();
        bad.values[row_of(T_PKH1, 0) * w + R_FILLED] = Fp::ONE;
        assert!(check_constraints(&SigAir, &bad, &public).is_err());
        // The seed the key hash takes.
        let mut bad = good.clone();
        bad.values[row_of(T_PKH1, 2) * w + COL_DATA] += Fp::ONE;
        assert!(check_constraints(&SigAir, &bad, &public).is_err());
        // An entry's row made padding: the signature said by nothing.
        let mut bad = good.clone();
        let r = row_of(T_ENT, 3);
        bad.values[r * w + T_ENT] = Fp::ZERO;
        bad.values[r * w + T_DONE] = Fp::ONE;
        assert!(check_constraints(&SigAir, &bad, &public).is_err());
    }

    /// Degrees-of-freedom audit: each way a row's cells can move
    /// together unseen.
    #[test]
    fn has_no_unintended_freedom() {
        let s = vec![signed(1, 2, 3, msg(5)), signed(2, 1, 0, msg(6))];
        let trace = SigAir::generate_trace(&s, 12);
        let public = said(&s);
        let kinds: Vec<usize> = (COL_START..=COL_DIR).collect();
        let lines = freedom_report(&SigAir, &trace, None, &public, &kinds, 6, |f| {
            // A permutation on a row that does not use it is free by design.
            let row = trace.row(f.row);
            let unused = row[COL_PASS] == Fp::ONE || row[COL_LOAD] == Fp::ONE;
            !(unused && f.cells.iter().all(|(c, _)| *c < crate::poseidon2_air::NUM_COLS))
        });
        assert!(lines.is_empty(), "{} freedoms:\n{}", lines.len(), lines.join("\n"));
    }

    #[test]
    #[should_panic(expected = "signature does not verify")]
    fn the_generator_refuses_a_forgery() {
        let mut s = several();
        s[1].2.randomizer[0] += Fp::ONE;
        SigAir::generate_trace(&s, LOG_N);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn prove_and_verify_signatures() {
        let config = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0, zk: false, commit_bits: 0 };
        let s = several();
        let trace = SigAir::generate_trace(&s, LOG_N);
        let public = said(&s);
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xc4));
            c
        };
        let proof = prove(&config, &SigAir, &trace, &public, &mut tr());
        assert_eq!(verify(&config, &SigAir, &public, &proof, &mut tr()), Ok(()));
        let mut bad = public;
        bad[DIGEST] += Fp::ONE;
        assert!(verify(&config, &SigAir, &bad, &proof, &mut tr()).is_err());
        let mut swapped = s.clone();
        swapped.swap(2, 3);
        assert!(verify(&config, &SigAir, &said(&swapped), &proof, &mut tr()).is_err());
    }
}
