//! Outputs, what they commit to and the plain way to spend one: the
//! types and hashes shared by transactions, spend policies, blocks and
//! the state tree.
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
//! input  := pubkey (49) | amount u64 (8) | position u64 (8) | signature
//! ```
//!
//! To spend an output, an [`Input`] reveals the public key and the amount
//! (from which the commitment is recomputed and the output found) and
//! carries an XMSS signature, made with that key, over the body of the
//! transaction it is part of. A signature's size grows with the key's tree
//! height: 2312 bytes at [`TREE_HEIGHT`]. Outputs under a spend policy
//! are spent otherwise ([`crate::policy`]).
//!
//! Each input consumes one XMSS leaf of its key, so a key with tree height
//! [`TREE_HEIGHT`] can appear in at most `2^TREE_HEIGHT` inputs in total.

use crate::codec::{DIGEST_BYTES, FP_BYTES, read_digest, read_u64};
use crate::hash::{DOM_COMMITMENT, DOM_PUBKEY, Digest, hash_domain};
use crate::poseidon2::{DIGEST, Fp, digest_to_bytes};
use crate::xmss::{PUB_SEED_LEN, PublicKey, SecretKey, Signature};

/// Outputs the chain can ever hold: an output's position is below this.
/// Positions are given out in order and never again, and the state tree
/// has this many leaves for them (its depth is 42, and the other half of
/// it holds names). A block of 2 MB creates fewer than 30,000 outputs, so
/// the 52,927,920 blocks of the emission schedule, every one full, use
/// `2^40.53` positions.
pub const OUTPUT_CAPACITY: u64 = 1 << 41;
const _: () = assert!(OUTPUT_CAPACITY <= 1 << (8 * crate::codec::POSITION_BYTES));

/// An output commitment `H(H(pubkey) || amount)`.
pub type Commitment = Digest;
/// Elements of an output's memo: a nonce of four and a recognition tag.
pub const MEMO_LEN: usize = 5;
/// An output's recovery memo: opaque to consensus.
pub type Memo = [Fp; MEMO_LEN];
/// The empty memo.
pub const EMPTY_MEMO: Memo = [Fp::ZERO; MEMO_LEN];


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

    /// Whether `bytes` are an output's encoding: [`Output::from_bytes`]
    /// would read them. Does not compute the commitment.
    pub fn is_encoding(bytes: &[u8]) -> bool {
        bytes.len() == OUTPUT_SIZE
            && read_digest(bytes).is_some()
            && memo_from_bytes(&bytes[DIGEST_BYTES + 8..]).is_some()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Output> {
        if bytes.len() != OUTPUT_SIZE {
            return None;
        }
        let (key_hash, rest) = read_digest(bytes)?;
        let (amount, rest) = read_u64(rest)?;
        let memo = memo_from_bytes(rest)?;
        Some(Output::with_memo(&key_hash, amount, memo))
    }
}

/// A transaction's outputs as a spend's check reads them: how many there
/// are, and each one's commitment and memo slot. A slice of outputs is
/// one; so is a transaction's encoding, read where it lies.
pub trait OutputList {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The commitment and the memo slot of output `i`. Panics past the end.
    fn pair(&self, i: usize) -> (Commitment, Digest);
}

impl OutputList for [Output] {
    fn len(&self) -> usize {
        <[Output]>::len(self)
    }

    fn pair(&self, i: usize) -> (Commitment, Digest) {
        (self[i].commitment, self[i].slot())
    }
}

impl OutputList for Vec<Output> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn pair(&self, i: usize) -> (Commitment, Digest) {
        self.as_slice().pair(i)
    }
}

impl<const N: usize> OutputList for [Output; N] {
    fn len(&self) -> usize {
        N
    }

    fn pair(&self, i: usize) -> (Commitment, Digest) {
        self.as_slice().pair(i)
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// XMSS tree height of payment keys (16 leaves per key): the height the
/// block circuit verifies today.
pub const TREE_HEIGHT: usize = crate::xmss::PLAIN_HEIGHT;
/// Signature type used in inputs.
pub type Sig = Signature;
/// Secret key type matching [`Sig`].
pub type Key = SecretKey;
/// Serialized size of an [`Input`] whose key has [`TREE_HEIGHT`]; an input
/// is [`Input::size`] bytes in general.
pub const INPUT_SIZE: usize = PublicKey::SIZE + 8 + 8 + Signature::size(TREE_HEIGHT);

/// A spend of an existing output: the revealed key and amount plus a
/// signature over the transaction body, and the output's position in the
/// UTXO set. The position is not signed (nor part of the transaction id):
/// it only tells nodes where to find the output, which they check, so a
/// wallet can correct it after a reorganization moves the output.
///
/// An input holds no memory but its own: reading one from bytes allocates
/// nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub position: u64,
    pub signature: Sig,
}

impl Input {
    /// Offset of the position in an input's encoding: it is not signed, so
    /// it may be rewritten in place.
    pub const POSITION_AT: usize = PublicKey::SIZE + 8;

    /// The commitment of the output this input spends.
    pub fn commitment(&self) -> Commitment {
        commitment(&self.pubkey, self.amount)
    }

    /// Serialized size: the signature's grows with the key's tree height.
    pub fn size(&self) -> usize {
        PublicKey::SIZE + 8 + 8 + Signature::size(self.pubkey.height())
    }

    /// Writes the input to `out`, which must be [`Input::size`] long.
    /// Panics if the signature is not of the key's height: such an input
    /// has no encoding.
    pub fn write_bytes(&self, out: &mut [u8]) {
        assert_eq!(out.len(), self.size(), "buffer is not the input's size");
        let (pk, rest) = out.split_at_mut(PublicKey::SIZE);
        pk.copy_from_slice(&self.pubkey.to_bytes());
        rest[..8].copy_from_slice(&self.amount.to_le_bytes());
        rest[8..16].copy_from_slice(&self.position.to_le_bytes());
        self.signature.write_bytes(&mut rest[16..]);
    }

    /// The input's bytes, in a new buffer on the heap.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.size()];
        self.write_bytes(&mut out);
        out
    }

    /// Parses an input from the front of `bytes`, returning the rest.
    pub fn read(bytes: &[u8]) -> Option<(Input, &[u8])> {
        let (pk, rest) = bytes.split_at_checked(PublicKey::SIZE)?;
        let pubkey = PublicKey::from_bytes(pk)?;
        let (amount, rest) = read_u64(rest)?;
        let (position, rest) = read_u64(rest)?;
        let (sig, rest) = rest.split_at_checked(Signature::size(pubkey.height()))?;
        let signature = Sig::from_bytes(sig, pubkey.height())?;
        Some((Input { pubkey, amount, position, signature }, rest))
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Input> {
        match Self::read(bytes)? {
            (input, []) => Some(input),
            _ => None,
        }
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
        assert_eq!(INPUT_SIZE, 49 + 8 + 8 + 2312);
        assert_eq!(TREE_HEIGHT, 4);
        assert_eq!(Key::generate(&[7; 32]).leaves(), 16);
    }

    /// An input reads back from its bytes, of whatever height its key is;
    /// its position is where POSITION_AT says and is not part of what it
    /// spends; other lengths and a signature of another height are refused.
    #[test]
    fn input_encoding() {
        let body = d(99);
        for height in [1usize, TREE_HEIGHT, 7] {
            let mut sk = SecretKey::generate_with_height(&[height as u8; 32], height);
            let input = Input { pubkey: sk.public_key(), amount: u64::MAX - 3, position: 1 << 39, signature: sk.sign(&body).unwrap() };
            assert_eq!(input.size(), PublicKey::SIZE + 16 + Signature::size(height));
            assert_eq!(input.commitment(), commitment(&sk.public_key(), u64::MAX - 3));
            let bytes = input.to_bytes();
            assert_eq!(bytes.len(), input.size());
            let mut buf = vec![0u8; input.size()];
            input.write_bytes(&mut buf);
            assert_eq!(buf, bytes);
            assert_eq!(Input::from_bytes(&bytes), Some(input.clone()));
            assert_eq!(Input::read(&[&bytes[..], &[5, 6]].concat()), Some((input.clone(), &[5u8, 6][..])));
            assert_eq!(Input::from_bytes(&bytes[..bytes.len() - 1]), None);
            assert_eq!(Input::from_bytes(&[&bytes[..], &[0]].concat()), None);
            let mut moved = bytes.clone();
            moved[Input::POSITION_AT..Input::POSITION_AT + 8].copy_from_slice(&7u64.to_le_bytes());
            let moved = Input::from_bytes(&moved).unwrap();
            assert_eq!((moved.position, moved.commitment()), (7, input.commitment()));
            assert!(moved.pubkey.verify(&body, &moved.signature));
            // A key that says another height: the signature is not its length.
            let mut other = bytes.clone();
            other[PublicKey::SIZE - 1] = height as u8 + 1;
            assert_eq!(Input::from_bytes(&other), None);
        }
        // An input whose signature is not of its key's height has no encoding.
        let mut a = SecretKey::generate_with_height(&[1; 32], 2);
        let b = SecretKey::generate_with_height(&[2; 32], 3);
        let mixed = Input { pubkey: b.public_key(), amount: 1, position: 0, signature: a.sign(&body).unwrap() };
        assert!(std::panic::catch_unwind(|| mixed.to_bytes()).is_err());
    }

    /// The input decoder, fuzzed: no input makes it panic, and what it
    /// decodes encodes back to the same bytes.
    #[test]
    fn fuzz_input_decoder() {
        let mut sk = key(9);
        let input = Input { pubkey: sk.public_key(), amount: 7, position: 12345, signature: sk.sign(&d(1)).unwrap() };
        crate::test_util::fuzz_decoder("Input::read", &[input.to_bytes()], 20_000, |b| {
            Input::read(b).map(|(i, rest)| Some([i.to_bytes(), rest.to_vec()].concat()))
        });
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

    /// A list of outputs gives each one's commitment and slot, whether a
    /// slice, a vector or an array; `is_encoding` says what `from_bytes` reads.
    #[test]
    fn output_lists_and_encodings() {
        let outs = [Output::with_memo(&d(1), 5, memo5(d(2))), Output::with_memo(&d(3), 6, memo5(d(4)))];
        fn check(list: &(impl OutputList + ?Sized), outs: &[Output]) {
            assert_eq!((list.len(), list.is_empty()), (outs.len(), outs.is_empty()));
            for (i, o) in outs.iter().enumerate() {
                assert_eq!(list.pair(i), (o.commitment, o.slot()));
            }
        }
        check(&outs, &outs);
        check(&outs[..], &outs);
        check(&outs.to_vec(), &outs);
        check(&outs[..0], &[]);
        let bytes = outs[0].to_bytes();
        assert!(Output::is_encoding(&bytes));
        assert!(!Output::is_encoding(&bytes[1..]) && !Output::is_encoding(&[&bytes[..], &[0]].concat()));
        for at in [0, DIGEST_BYTES - 4, DIGEST_BYTES + 8, OUTPUT_SIZE - 4] {
            let mut bad = bytes;
            bad[at..at + 4].copy_from_slice(&crate::poseidon2::P.to_le_bytes());
            assert_eq!((Output::is_encoding(&bad), Output::from_bytes(&bad)), (false, None), "element at {at}");
        }
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
