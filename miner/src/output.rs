//! Outputs and what they commit to: the types and hashes shared by
//! transactions, spend policies, blocks and the state tree.
//!
//! An output pays `amount` to the key with hash `H(pubkey)`; only its
//! commitment `H(H(pubkey) || amount)` goes on chain, with its memo. Every
//! output uses a fresh key, so the key hash is a secret of the payer and
//! payee and the commitment hides the key from everyone else.
//!
//! An output's memo is five field elements its owner's wallet fills to find
//! the output again from its seed; consensus only carries it, bound to the
//! amount in a memo slot ([`memo_slot`]).
//!
//! Hashing works on field elements rather than bytes: a 64-bit amount is
//! three limbs of 30, 30 and 4 bits, a public key is its 13 elements (root,
//! public seed and tree height) and a commitment its 8. Encodings are
//! little-endian, field elements in the 4-byte canonical encoding of
//! [`crate::poseidon2`]:
//!
//! ```text
//! output := key hash (32) | amount u64 (8) | memo (20)
//! ```

use crate::hash::{DOM_COMMITMENT, DOM_PUBKEY, Digest, hash_domain};
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes, digest_to_bytes};
use crate::xmss::{PUB_SEED_LEN, PublicKey};

/// An output commitment `H(H(pubkey) || amount)`.
pub type Commitment = Digest;
/// Elements of an output's memo: a nonce of four and a recognition tag.
pub const MEMO_LEN: usize = 5;
/// An output's recovery memo: opaque to consensus.
pub type Memo = [Fp; MEMO_LEN];
/// The empty memo.
pub const EMPTY_MEMO: Memo = [Fp::ZERO; MEMO_LEN];


/// Serialized size of a field element.
const FP_BYTES: usize = 4;
/// Serialized size of a digest or commitment.
const DIGEST_BYTES: usize = DIGEST * FP_BYTES;
/// Serialized size of a memo.
pub const MEMO_BYTES: usize = MEMO_LEN * FP_BYTES;
/// Serialized size of an [`Output`].
pub const OUTPUT_SIZE: usize = DIGEST_BYTES + 8 + MEMO_BYTES;

const MASK30: u64 = (1 << 30) - 1;
const AMOUNT_LIMBS: usize = 3;
const PUBKEY_FPS: usize = DIGEST + PUB_SEED_LEN + 1;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Splits a `u64` into three field elements of 30, 30 and 4 bits, least
/// significant first. Limbs are kept below 2^30 because the BabyBear modulus
/// is smaller than 2^31.
pub(crate) fn amount_fps(amount: u64) -> [Fp; AMOUNT_LIMBS] {
    [Fp::new((amount & MASK30) as u32), Fp::new(((amount >> 30) & MASK30) as u32), Fp::new((amount >> 60) as u32)]
}

fn pubkey_fps(pk: &PublicKey) -> [Fp; PUBKEY_FPS] {
    let mut out = [Fp::ZERO; PUBKEY_FPS];
    out[..DIGEST].copy_from_slice(&pk.root);
    out[DIGEST..DIGEST + PUB_SEED_LEN].copy_from_slice(&pk.pub_seed);
    out[DIGEST + PUB_SEED_LEN] = Fp::new(pk.height as u32);
    out
}

/// `H(pubkey)`: the root, the public seed and the tree height.
pub fn pubkey_hash(pk: &PublicKey) -> Digest {
    hash_domain(DOM_PUBKEY, &pubkey_fps(pk))
}

/// `H(H(pubkey) || amount)`, the commitment stored in an output.
pub fn commitment(pk: &PublicKey, amount: u64) -> Commitment {
    key_commitment(&pubkey_hash(pk), amount)
}

/// What a leaf, a block's outputs sponge and a body hash take for an
/// output's memo: the memo's five elements, then the amount's three limbs
/// (`docs/AMOUNTS.md`), so that the amount, public, is bound wherever the
/// memo is. An output of amount zero (a name commit) has the memo padded
/// with zeros.
pub fn memo_slot(memo: &Memo, amount: u64) -> Digest {
    let mut slot = [Fp::ZERO; DIGEST];
    slot[..MEMO_LEN].copy_from_slice(memo);
    slot[MEMO_LEN..].copy_from_slice(&amount_fps(amount));
    slot
}

/// The memo and the amount a slot holds; `None` for limbs that are not an
/// amount's (each of the first two below 2^30, the third below 2^4).
pub fn slot_parts(slot: &Digest) -> Option<(Memo, u64)> {
    let memo: Memo = slot[..MEMO_LEN].try_into().unwrap();
    let limb = |i: usize| slot[MEMO_LEN + i].to_canonical() as u64;
    let (lo, mid, hi) = (limb(0), limb(1), limb(2));
    (lo < 1 << 30 && mid < 1 << 30 && hi < 1 << 4).then_some((memo, lo | mid << 30 | hi << 60))
}

/// A memo from a digest's first five elements (tests).
#[cfg(test)]
pub(crate) fn memo5(d: Digest) -> Memo {
    d[..MEMO_LEN].try_into().unwrap()
}

/// A memo's bytes.
pub fn memo_to_bytes(memo: &Memo) -> [u8; MEMO_BYTES] {
    let mut out = [0u8; MEMO_BYTES];
    for (chunk, x) in out.chunks_exact_mut(FP_BYTES).zip(memo) {
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// A memo from its bytes: `None` on a wrong length or a non-canonical
/// element.
pub fn memo_from_bytes(bytes: &[u8]) -> Option<Memo> {
    if bytes.len() != MEMO_BYTES {
        return None;
    }
    let mut out = EMPTY_MEMO;
    for (x, chunk) in out.iter_mut().zip(bytes.chunks_exact(FP_BYTES)) {
        *x = Fp::from_le_bytes(chunk.try_into().unwrap())?;
    }
    Some(out)
}

/// The state tree leaf from a commitment, a memo slot ([`memo_slot`]) and
/// a creation height: the commitment and the slot compressed, then that
/// with the height, so the state root covers the memo and the amount too.
pub fn leaf(commitment: &Commitment, slot: &Digest, height: u32) -> Digest {
    crate::poseidon2::compress(&crate::poseidon2::compress(commitment, slot), &height_digest(height))
}

/// The state tree leaf of an unspent output.
pub fn output_leaf(commitment: &Commitment, memo: &Memo, amount: u64, height: u32) -> Digest {
    leaf(commitment, &memo_slot(memo, amount), height)
}

/// A block height as a digest: one element, then zeros. The second half
/// of a leaf's final compression (see [`leaf`]).
pub fn height_digest(height: u32) -> Digest {
    let mut d = [Fp::ZERO; DIGEST];
    d[0] = Fp::new(height);
    d
}

/// `H(key_hash || amount)`: [`commitment`] from the key's hash.
pub fn key_commitment(key_hash: &Digest, amount: u64) -> Commitment {
    let mut input = [Fp::ZERO; DIGEST + AMOUNT_LIMBS];
    input[..DIGEST].copy_from_slice(key_hash);
    input[DIGEST..].copy_from_slice(&amount_fps(amount));
    hash_domain(DOM_COMMITMENT, &input)
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

/// A newly created output: the recipient's key hash and the amount, which
/// travel with the transaction, the commitment derived from them, and the
/// memo. The commitment and the memo are all that goes on chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Output {
    pub key_hash: Digest,
    pub amount: u64,
    pub commitment: Commitment,
    pub memo: Memo,
}

impl Output {
    /// Creates an output paying `amount` to `pk`, with an empty memo.
    pub fn new(pk: &PublicKey, amount: u64) -> Output {
        Output::to_key_hash(&pubkey_hash(pk), amount)
    }

    /// Creates an output paying `amount` to the key with hash `key_hash`,
    /// with an empty memo.
    pub fn to_key_hash(key_hash: &Digest, amount: u64) -> Output {
        Output::with_memo(key_hash, amount, EMPTY_MEMO)
    }

    /// Its memo slot ([`memo_slot`]).
    pub fn slot(&self) -> Digest {
        memo_slot(&self.memo, self.amount)
    }

    /// Creates an output with a memo.
    pub fn with_memo(key_hash: &Digest, amount: u64, memo: Memo) -> Output {
        Output { key_hash: *key_hash, amount, commitment: key_commitment(key_hash, amount), memo }
    }

    /// Key hash, amount, memo; the commitment is recomputed on decoding.
    pub fn to_bytes(&self) -> [u8; OUTPUT_SIZE] {
        let mut out = [0u8; OUTPUT_SIZE];
        out[..DIGEST_BYTES].copy_from_slice(&digest_to_bytes(&self.key_hash));
        out[DIGEST_BYTES..DIGEST_BYTES + 8].copy_from_slice(&self.amount.to_le_bytes());
        out[DIGEST_BYTES + 8..].copy_from_slice(&memo_to_bytes(&self.memo));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Output> {
        if bytes.len() != OUTPUT_SIZE {
            return None;
        }
        let key_hash = digest_from_bytes(&bytes[..DIGEST_BYTES])?;
        let amount = u64::from_le_bytes(bytes[DIGEST_BYTES..DIGEST_BYTES + 8].try_into().unwrap());
        let memo = memo_from_bytes(&bytes[DIGEST_BYTES + 8..])?;
        Some(Output::with_memo(&key_hash, amount, memo))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::SecretKey;

    fn key(tag: u8) -> SecretKey {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        SecretKey::generate(&seed)
    }

    fn d(x: u32) -> Digest {
        let mut v = [Fp::ZERO; DIGEST];
        for (i, e) in v.iter_mut().enumerate() {
            *e = Fp::new(x + i as u32);
        }
        v
    }

    #[test]
    fn sizes() {
        assert_eq!(OUTPUT_SIZE, 60);
        assert_eq!(MEMO_BYTES, 20);
    }

    #[test]
    fn amount_limbs_cover_u64() {
        let p = crate::poseidon2::P as u64;
        for a in [0u64, 1, MASK30, MASK30 + 1, p, p - 1, p << 30, u64::MAX, 1 << 60, (1 << 60) - 1] {
            let l = amount_fps(a);
            let back =
                l[0].to_canonical() as u64 | (l[1].to_canonical() as u64) << 30 | (l[2].to_canonical() as u64) << 60;
            assert_eq!(back, a);
        }
    }

    #[test]
    fn commitments() {
        let a = key(1).public_key();
        let b = key(2).public_key();
        assert_eq!(commitment(&a, 5), commitment(&a, 5));
        assert_ne!(commitment(&a, 5), commitment(&a, 6));
        assert_ne!(commitment(&a, 5), commitment(&b, 5));
        assert_ne!(commitment(&a, 5), pubkey_hash(&a));
        assert_ne!(pubkey_hash(&a), pubkey_hash(&b));
        let out = Output::new(&a, 5);
        assert_eq!(out.amount, 5);
        assert_eq!(out.commitment, commitment(&a, 5));
        assert_eq!(out.commitment, key_commitment(&pubkey_hash(&a), 5));
    }

    /// A slot gives back its memo and amount, and refuses limbs no amount has.
    #[test]
    fn memo_slots_hold_the_memo_and_the_amount() {
        let memo = memo5(d(40));
        for amount in [0u64, 1, MASK30, MASK30 + 1, 1 << 60, u64::MAX] {
            let slot = memo_slot(&memo, amount);
            assert_eq!(slot_parts(&slot), Some((memo, amount)));
            assert_eq!(Output::with_memo(&d(1), amount, memo).slot(), slot);
        }
        for (limb, over) in [(0, 1 << 30), (1, 1 << 30), (2, 1 << 4)] {
            let mut slot = memo_slot(&memo, 7);
            slot[MEMO_LEN + limb] = Fp::new(over);
            assert_eq!(slot_parts(&slot), None, "limb {limb}");
        }
        assert_eq!(memo_from_bytes(&memo_to_bytes(&memo)), Some(memo));
        assert_eq!(memo_from_bytes(&memo_to_bytes(&memo)[1..]), None);
    }

    /// A leaf depends on each of the commitment, the memo, the amount and
    /// the height.
    #[test]
    fn leaves_cover_every_part() {
        let (c, memo) = (d(1), memo5(d(2)));
        let leaf0 = output_leaf(&c, &memo, 5, 9);
        assert_eq!(leaf0, leaf(&c, &memo_slot(&memo, 5), 9));
        assert_ne!(leaf0, output_leaf(&d(3), &memo, 5, 9));
        assert_ne!(leaf0, output_leaf(&c, &memo5(d(4)), 5, 9));
        assert_ne!(leaf0, output_leaf(&c, &memo, 6, 9));
        assert_ne!(leaf0, output_leaf(&c, &memo, 5, 10));
    }

    /// The output decoder, fuzzed: no input makes it panic, and what it
    /// decodes encodes back to the same bytes.
    #[test]
    fn output_encoding() {
        let out = Output::with_memo(&d(7), u64::MAX, memo5(d(8)));
        let bytes = out.to_bytes();
        assert_eq!(Output::from_bytes(&bytes), Some(out));
        assert_eq!(Output::from_bytes(&bytes[1..]), None);
        let mut bad = bytes;
        bad[..4].copy_from_slice(&crate::poseidon2::P.to_le_bytes()); // == p, non-canonical
        assert_eq!(Output::from_bytes(&bad), None);
        crate::test_util::fuzz_decoder("Output::from_bytes", &[bytes.to_vec()], 20_000, |b| {
            Output::from_bytes(b).map(|o| Some(o.to_bytes().to_vec()))
        });
    }
}
