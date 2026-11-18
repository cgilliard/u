//! What wallets say to each other over the message layer, and how it is
//! kept from everyone between them.
//!
//! A wallet is known by its id, the hash of its Dilithium key
//! ([`crate::address`]). To be reached it says, to each node that
//! stands between it and whoever would reach it, an [`Announced`]: its
//! Dilithium key, a Kyber key made for the purpose, and its signature
//! over that key, a number that only rises, a time it holds until, and
//! a token of the node it is said to. Whoever has a wallet's id asks
//! such a node for what the wallet announced, checks the key against
//! the id and the signature against the key, and so has a key to seal
//! to that the wallet alone opens.
//!
//! What is sent is [`seal`]ed: encapsulated to that Kyber key, and
//! under the secret so agreed (ChaCha20-Poly1305) the sender's own
//! announcement, what kind of thing is said, the thing, and the
//! sender's signature over it and over whom it is to. So a node that
//! passes it on learns whom it is for and how long it is: not who sent
//! it, and nothing of what it says. The one it is for learns who sent
//! it, by a key it can check, and has a Kyber key of the sender's to
//! answer to.
//!
//! The Kyber keys are made anew often, and the old ones dropped: what
//! was sealed to one cannot be opened once it is gone, by anyone.
//!
//! This is not the form the node before this one used.

use crate::address::id_of;
use crate::chacha20poly1305 as aead;
use crate::codec::packed;
use crate::hash::{Digest, hash_domain, hash_domain_of};
use crate::poseidon2::Fp;
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::{mldsa, mlkem};

/// The bytes of an announcement: the Dilithium key, the Kyber key, the
/// sequence number, the expiry, the token, the signature.
pub const ANNOUNCE_LEN: usize = mldsa::PK_LEN + mlkem::EK_LEN + 24 + mldsa::SIG_LEN;
/// The most a message may say: what it carries, not what carries it.
pub const MAX_BODY: usize = 64 << 10;
/// The bytes a sealed message is longer than what it says by.
pub const OVERHEAD: usize = 32 + mlkem::CT_LEN + ANNOUNCE_LEN + 1 + mldsa::SIG_LEN + aead::TAG_LEN;
/// The longest sealed message.
pub const MAX_SEALED: usize = OVERHEAD + MAX_BODY;

/// What a message says: a slate, of a payment being made.
pub const KIND_SLATE: u8 = 1;

/// Domain tag of the id of a sealed message, by which it is fetched.
const DOM_SEALED: u32 = 19;
/// Domain tag of the choice of a wallet's rendezvous points.
const DOM_POINT: u32 = 20;
/// What an announcement is signed under, and a message.
const CTX_ANNOUNCE: &[u8] = b"tab announce";
const CTX_MESSAGE: &[u8] = b"tab message";

const SIGNED: std::ops::Range<usize> = mldsa::PK_LEN..mldsa::PK_LEN + mlkem::EK_LEN + 24;

/// An announcement of the wallet whose key is `identity`: that `kyber`
/// is the key to seal to it with, from now until `expires` (Unix
/// seconds), unless one of a higher `seq` is seen. `bind` is the token
/// of the node it is said to, which takes it from nobody that token
/// was not given to: so that it cannot be said again by another, from
/// elsewhere.
pub fn announce(
    identity: &mldsa::SecretKey,
    kyber: &[u8; mlkem::EK_LEN],
    seq: u64,
    expires: u64,
    bind: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ANNOUNCE_LEN);
    out.extend_from_slice(identity.public_key());
    out.extend_from_slice(kyber);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&expires.to_le_bytes());
    out.extend_from_slice(&bind.to_le_bytes());
    let signature = identity.sign(&out[SIGNED], CTX_ANNOUNCE);
    out.extend_from_slice(&signature);
    out
}

/// An announcement that was checked: of the right length, signed by the
/// key it carries, and not yet past its time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announced<'a>(&'a [u8]);

impl<'a> Announced<'a> {
    /// Reads and checks an announcement, at `now` (Unix seconds).
    pub fn read(bytes: &'a [u8], now: u64) -> Option<Announced<'a>> {
        if bytes.len() != ANNOUNCE_LEN {
            return None;
        }
        let said = Announced(bytes);
        let signature = &bytes[SIGNED.end..];
        let sound = said.expires() > now
            && mlkem::valid_public_key(said.kyber())
            && mldsa::verify(said.key(), &bytes[SIGNED], CTX_ANNOUNCE, signature);
        sound.then_some(said)
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The Dilithium key of whoever said it.
    pub fn key(&self) -> &'a [u8] {
        &self.0[..mldsa::PK_LEN]
    }

    /// Whose it is: the hash of that key.
    pub fn id(&self) -> Digest {
        id_of(self.key())
    }

    /// The Kyber key to seal to.
    pub fn kyber(&self) -> &'a [u8] {
        &self.0[mldsa::PK_LEN..mldsa::PK_LEN + mlkem::EK_LEN]
    }

    fn number(&self, at: usize) -> u64 {
        let from = mldsa::PK_LEN + mlkem::EK_LEN + 8 * at;
        u64::from_le_bytes(self.0[from..from + 8].try_into().expect("eight bytes"))
    }

    pub fn seq(&self) -> u64 {
        self.number(0)
    }

    pub fn expires(&self) -> u64 {
        self.number(1)
    }

    pub fn bind(&self) -> u64 {
        self.number(2)
    }
}

/// The id of a sealed message: what it is asked for by.
pub fn sealed_id(sealed: &[u8]) -> Digest {
    hash_domain_of(DOM_SEALED, packed(sealed))
}

/// Whom a sealed message is for, if it is long enough to be one.
pub fn sealed_to(sealed: &[u8]) -> Option<Digest> {
    digest_from_bytes(sealed.get(..32)?)
}

/// The key a message is sealed under: of the secret agreed and of whom
/// it is for.
fn key_of(secret: &[u8; mlkem::SS_LEN], to: &[u8]) -> [u8; aead::KEY_LEN] {
    let mut input = [0u8; mlkem::SS_LEN + 32];
    input[..mlkem::SS_LEN].copy_from_slice(secret);
    input[mlkem::SS_LEN..].copy_from_slice(to);
    crate::keccak::sha3_256(&input)
}

/// What a sender signs: whom the message is for, the encapsulation it
/// is sealed under, its kind and what it says. (So that it is this
/// message to this wallet, and not to be passed to another as its own.)
fn signed_of(to: &[u8], ct: &[u8], kind: u8, body: &[u8]) -> [u8; 32] {
    let mut h = crate::keccak::Sponge::shake256();
    h.absorb(to).absorb(ct).absorb(&[kind]).absorb(body);
    h.squeezed()
}

/// Seals `body`, of `kind`, to the wallet that announced `to`, from the
/// wallet whose key is `sender` and whose own announcement is `own`
/// (which goes inside: the answer is sealed to it). `chance` is 32
/// random bytes. None if `body` is longer than a message may be.
pub fn seal(
    sender: &mldsa::SecretKey,
    own: &[u8],
    to: &Announced<'_>,
    kind: u8,
    body: &[u8],
    chance: &[u8; 32],
) -> Option<Vec<u8>> {
    if body.len() > MAX_BODY || own.len() != ANNOUNCE_LEN {
        return None;
    }
    let (secret, ct) = mlkem::encapsulate_with(to.kyber(), chance)?;
    let id = digest_to_bytes(&to.id());
    let mut inner = Vec::with_capacity(ANNOUNCE_LEN + 1 + body.len() + mldsa::SIG_LEN);
    inner.extend_from_slice(own);
    inner.push(kind);
    inner.extend_from_slice(body);
    inner.extend_from_slice(&sender.sign(&signed_of(&id, &ct, kind, body), CTX_MESSAGE));
    let mut out = Vec::with_capacity(OVERHEAD + body.len());
    out.extend_from_slice(&id);
    out.extend_from_slice(&ct);
    // (No nonce but nothing: the key is of this encapsulation alone.)
    let sealed = aead::seal(&key_of(&secret, &id), &[0; aead::NONCE_LEN], &out, &inner);
    out.extend_from_slice(&sealed);
    Some(out)
}

/// A message opened: who sent it, by a key that was checked; the
/// announcement to answer it to; and what it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub from: Digest,
    /// The sender's announcement ([`Announced::read`] has taken it).
    pub reply: Vec<u8>,
    pub kind: u8,
    pub body: Vec<u8>,
}

/// Opens a message sealed to the wallet of id `own`, with the Kyber key
/// it was sealed to, at `now`. None if it is not for this wallet, was
/// not sealed to this key, was changed on the way, or is not signed by
/// the wallet whose announcement it carries.
pub fn open(kyber: &mlkem::SecretKey, own: &Digest, sealed: &[u8], now: u64) -> Option<Opened> {
    if sealed.len() < OVERHEAD || sealed.len() > MAX_SEALED {
        return None;
    }
    let (head, rest) = sealed.split_at(32 + mlkem::CT_LEN);
    let (to, ct) = head.split_at(32);
    if to != digest_to_bytes(own) {
        return None;
    }
    let secret = kyber.decapsulate(ct)?;
    let inner = aead::open(&key_of(&secret, to), &[0; aead::NONCE_LEN], head, rest)?;
    let (reply, said) = inner.split_at_checked(ANNOUNCE_LEN)?;
    let (said, signature) = said.split_at_checked(said.len().checked_sub(mldsa::SIG_LEN)?)?;
    let (kind, body) = said.split_first()?;
    let sender = Announced::read(reply, now)?;
    if !mldsa::verify(sender.key(), &signed_of(to, ct, *kind, body), CTX_MESSAGE, signature) {
        return None;
    }
    Some(Opened { from: sender.id(), reply: reply.to_vec(), kind: *kind, body: body.to_vec() })
}

/// Which of `nodes` nodes a wallet of id `id` is to be reached at in
/// the epoch `epoch` (the chain's height over the length of a window):
/// up to three of them, each chosen by a hash of the id, the epoch and
/// a count, none twice. Whoever has the id and the nodes finds the
/// same, and at every epoch they are others.
pub fn points(id: &Digest, epoch: u32, nodes: usize) -> Vec<usize> {
    let mut chosen: Vec<usize> = Vec::with_capacity(3);
    let mut k = 0u32;
    while chosen.len() < nodes.min(3) {
        let mut input = [Fp::ZERO; 10];
        input[..8].copy_from_slice(id);
        (input[8], input[9]) = (Fp::new(epoch & 0x3fff_ffff), Fp::new(k));
        let drawn = hash_domain(DOM_POINT, &input);
        let index = (drawn[0].to_canonical() as usize) % nodes;
        if !chosen.contains(&index) {
            chosen.push(index);
        }
        k += 1;
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> (mldsa::SecretKey, mlkem::SecretKey) {
        (mldsa::keygen(&[seed; 32]), mlkem::keygen(&[seed.wrapping_add(100); 64]))
    }

    fn said(w: &(mldsa::SecretKey, mlkem::SecretKey), seq: u64, expires: u64, bind: u64) -> Vec<u8> {
        announce(&w.0, w.1.public_key().try_into().unwrap(), seq, expires, bind)
    }

    /// An announcement is taken from the key that signed it, while it
    /// holds; changed anywhere, or past its time, it is nothing.
    #[test]
    fn an_announcement_is_its_signers() {
        let alice = wallet(1);
        let bytes = said(&alice, 7, 2000, 99);
        assert_eq!(bytes.len(), ANNOUNCE_LEN);
        let read = Announced::read(&bytes, 1000).unwrap();
        assert_eq!((read.seq(), read.expires(), read.bind()), (7, 2000, 99));
        assert_eq!(read.id(), id_of(alice.0.public_key()));
        assert_eq!(read.kyber(), alice.1.public_key());
        assert_eq!(Announced::read(&bytes, 2000), None);
        assert_eq!(Announced::read(&bytes[1..], 1000), None);
        // Each part of it is under the signature: the key to seal to,
        // the numbers, the token; and the key that signs is the id.
        for at in [0, mldsa::PK_LEN, SIGNED.end - 20, SIGNED.end - 12, SIGNED.end - 4, SIGNED.end, ANNOUNCE_LEN - 1] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert_eq!(Announced::read(&changed, 1000), None, "byte {at}");
        }
    }

    /// A message sealed to a wallet is opened by it, and says who sent
    /// it; nobody else opens it, and changed on the way it is nothing.
    #[test]
    fn a_message_is_for_one_wallet_and_from_one() {
        let (alice, bob, carol) = (wallet(1), wallet(2), wallet(3));
        let (from_alice, to_bob) = (said(&alice, 1, 5000, 0), said(&bob, 1, 5000, 0));
        let bob_said = Announced::read(&to_bob, 1000).unwrap();
        let sealed = seal(&alice.0, &from_alice, &bob_said, KIND_SLATE, b"a slate", &[9; 32]).unwrap();
        assert_eq!(sealed.len(), OVERHEAD + 7);
        assert_eq!(sealed_to(&sealed), Some(bob_said.id()));
        let opened = open(&bob.1, &bob_said.id(), &sealed, 1000).unwrap();
        assert_eq!(
            (opened.from, opened.kind, &opened.body[..]),
            (id_of(alice.0.public_key()), KIND_SLATE, &b"a slate"[..])
        );
        assert_eq!(opened.reply, from_alice);
        // Who it is from is not to be read on the way: Alice's key is
        // nowhere in it in the clear.
        let key = alice.0.public_key();
        assert!(!sealed.windows(32).any(|w| w == &key[..32]));
        // Not Carol's to open, with her key or as if it were hers; nor
        // Bob's with another of his keys.
        let carol_id = id_of(carol.0.public_key());
        assert_eq!(open(&carol.1, &carol_id, &sealed, 1000), None);
        assert_eq!(open(&carol.1, &bob_said.id(), &sealed, 1000), None);
        assert_eq!(open(&mlkem::keygen(&[50; 64]), &bob_said.id(), &sealed, 1000), None);
        // Changed anywhere: nothing.
        for at in [0, 31, 32, 32 + mlkem::CT_LEN - 1, 32 + mlkem::CT_LEN, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[at] ^= 1;
            assert_eq!(open(&bob.1, &bob_said.id(), &changed, 1000), None, "byte {at}");
        }
        // Once the sender's announcement is past its time, the message
        // is: there is nothing to answer it to.
        assert_eq!(open(&bob.1, &bob_said.id(), &sealed, 5000), None);
        // Another message, another id; too long, none.
        let other = seal(&alice.0, &from_alice, &bob_said, KIND_SLATE, b"another", &[9; 32]).unwrap();
        assert_ne!(sealed_id(&other), sealed_id(&sealed));
        assert_eq!(seal(&alice.0, &from_alice, &bob_said, KIND_SLATE, &vec![0; MAX_BODY + 1], &[9; 32]), None);
        assert!(seal(&alice.0, &from_alice, &bob_said, KIND_SLATE, &vec![0; MAX_BODY], &[9; 32]).is_some());
    }

    /// A message cannot be passed on as one's own: Carol, who was sent
    /// Alice's, cannot seal what it said to Bob as from Alice.
    #[test]
    fn a_message_is_not_passed_on_as_anothers() {
        let (alice, bob, carol) = (wallet(1), wallet(2), wallet(3));
        let (a, b, c) = (said(&alice, 1, 5000, 0), said(&bob, 1, 5000, 0), said(&carol, 1, 5000, 0));
        let carol_said = Announced::read(&c, 1000).unwrap();
        let bob_said = Announced::read(&b, 1000).unwrap();
        let sealed = seal(&alice.0, &a, &carol_said, KIND_SLATE, b"pay carol", &[4; 32]).unwrap();
        let opened = open(&carol.1, &carol_said.id(), &sealed, 1000).unwrap();
        // What Carol has of it: Alice's announcement, the words, and a
        // signature that is over Carol's id and her encapsulation. Put
        // under an encapsulation to Bob, it is not signed for him.
        let (secret, ct) = mlkem::encapsulate_with(bob_said.kyber(), &[5; 32]).unwrap();
        let id = digest_to_bytes(&bob_said.id());
        let inner_from = |signature: &[u8]| {
            let mut inner = opened.reply.clone();
            inner.push(opened.kind);
            inner.extend_from_slice(&opened.body);
            inner.extend_from_slice(signature);
            inner
        };
        let carols_copy = aead::open(
            &key_of(&carol.1.decapsulate(&sealed[32..32 + mlkem::CT_LEN]).unwrap(), &sealed[..32]),
            &[0; aead::NONCE_LEN],
            &sealed[..32 + mlkem::CT_LEN],
            &sealed[32 + mlkem::CT_LEN..],
        )
        .unwrap();
        let signature = &carols_copy[carols_copy.len() - mldsa::SIG_LEN..];
        let mut forged = id.to_vec();
        forged.extend_from_slice(&ct);
        let body = aead::seal(&key_of(&secret, &id), &[0; aead::NONCE_LEN], &forged, &inner_from(signature));
        forged.extend_from_slice(&body);
        assert_eq!(open(&bob.1, &bob_said.id(), &forged, 1000), None);
    }

    /// A wallet's points are of its id and the epoch: the same for
    /// whoever reckons them, others at another epoch, as many as there
    /// are nodes up to three, and none twice.
    #[test]
    fn points_are_found_by_anyone_and_move() {
        let id = id_of(mldsa::keygen(&[1; 32]).public_key());
        let other = id_of(mldsa::keygen(&[2; 32]).public_key());
        assert_eq!(points(&id, 5, 2).len(), 2);
        assert_eq!(points(&id, 5, 1), [0]);
        assert_eq!(points(&id, 5, 0), [] as [usize; 0]);
        let at = points(&id, 5, 50);
        assert_eq!(at.len(), 3);
        assert_eq!(at, points(&id, 5, 50));
        assert!(at[0] != at[1] && at[1] != at[2] && at[0] != at[2] && at.iter().all(|i| *i < 50));
        assert_ne!(at, points(&id, 6, 50));
        assert_ne!(at, points(&other, 5, 50));
    }
}
