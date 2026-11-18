//! A way through relays that none of them can follow: the agreement of
//! a key with each, and the layers a message is wrapped in.
//!
//! A wallet that is not to be seen where it is reached goes there by
//! way of relays: it talks to one, has that one pass what it says to a
//! second, and so on to the node it is reached at. With each of them it
//! agrees a key of its own ([`Opening`], [`answer`]), the further ones
//! through the nearer, which pass on what they cannot read. What it
//! then sends it wraps once for each relay on the way, the last first
//! ([`wrap`]); each takes one wrapping off ([`Hop::peel`]) and passes
//! on what is left, which looks like nothing it was given. What comes
//! back is wrapped once more at each relay ([`Hop::cover`]) and
//! unwrapped by the wallet alone ([`unwrap`]). So a relay knows who
//! gave it a thing and whom it gives it to, and nothing else: not what
//! it says, not where it began, not where it ends.
//!
//! A relay is known by the hash of its Dilithium key, as a wallet is
//! ([`crate::address`]): the list of them says that and where it is. In
//! agreeing a key it signs the exchange with that key, so that whoever
//! opens a way through it knows it is the relay the list names, and
//! not whoever happens to answer at its address. Whoever opens the way
//! signs nothing, and is nobody to the relay.
//!
//! The keys agreed are of this way alone, and gone when it is: what
//! went over it cannot be read afterwards by anyone who then takes a
//! relay, or a wallet.

use crate::address::id_of;
use crate::chacha20poly1305 as aead;
use crate::hash::Digest;
use crate::keccak::Sponge;
use crate::{mldsa, mlkem};

/// What whoever opens a way sends a relay: a Kyber key made for it, and
/// 32 bytes the relay is to sign.
pub const HELLO_LEN: usize = mlkem::EK_LEN + 32;
/// What the relay answers: its Dilithium key, the encapsulation, and
/// its signature over the exchange.
pub const ANSWER_LEN: usize = mldsa::PK_LEN + mlkem::CT_LEN + mldsa::SIG_LEN;
/// What the relay's signature is under.
const CTX: &[u8] = b"tab circuit";

/// One end's half of the opening of a way through a relay, until the
/// relay has answered.
pub struct Opening {
    key: mlkem::SecretKey,
    hello: [u8; HELLO_LEN],
}

impl Opening {
    /// Begins: `chance` is 96 random bytes.
    pub fn new(chance: &[u8; 96]) -> Opening {
        let key = mlkem::keygen(chance[..64].try_into().expect("64 bytes"));
        let mut hello = [0u8; HELLO_LEN];
        hello[..mlkem::EK_LEN].copy_from_slice(key.public_key());
        hello[mlkem::EK_LEN..].copy_from_slice(&chance[64..]);
        Opening { key, hello }
    }

    /// What is sent to the relay.
    pub fn hello(&self) -> &[u8; HELLO_LEN] {
        &self.hello
    }

    /// Takes the relay's answer: the keys agreed with it, if it is the
    /// relay of id `relay` that answered, to this opening. None if the
    /// answer is not that relay's, or not to this.
    pub fn agreed(&self, relay: &Digest, answer: &[u8]) -> Option<Hop> {
        if answer.len() != ANSWER_LEN {
            return None;
        }
        let (key, rest) = answer.split_at(mldsa::PK_LEN);
        let (ct, signature) = rest.split_at(mlkem::CT_LEN);
        if id_of(key) != *relay || !mldsa::verify(key, &signed(&self.hello, ct), CTX, signature) {
            return None;
        }
        Some(Hop::of(&self.key.decapsulate(ct)?, &self.hello, ct))
    }
}

/// What a relay signs: the hello it answers and its encapsulation to it.
/// (So that its answer is to this opening and no other.)
fn signed(hello: &[u8], ct: &[u8]) -> [u8; 64] {
    let mut h = Sponge::shake256();
    h.absorb(hello).absorb(ct);
    h.squeezed()
}

/// A relay's answer to a hello: its side of the keys, and what it sends
/// back. `identity` is the relay's Dilithium key; `chance` is 32 random
/// bytes. None if the hello is not one.
pub fn answer(identity: &mldsa::SecretKey, hello: &[u8], chance: &[u8; 32]) -> Option<(Hop, Vec<u8>)> {
    if hello.len() != HELLO_LEN {
        return None;
    }
    let (secret, ct) = mlkem::encapsulate_with(&hello[..mlkem::EK_LEN], chance)?;
    let mut out = Vec::with_capacity(ANSWER_LEN);
    out.extend_from_slice(identity.public_key());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&identity.sign(&signed(hello, &ct), CTX));
    Some((Hop::of(&secret, hello, &ct), out))
}

/// The keys agreed with one relay of a way. Both ends have the same.
/// Each way, one key for the wrapping every relay puts on or takes off,
/// and another for the seal of the relay a thing is for or from: no
/// two uses share a key, so none ever meets another's stream.
#[derive(Clone, PartialEq, Eq)]
pub struct Hop {
    out: [u8; aead::KEY_LEN],
    out_seal: [u8; aead::KEY_LEN],
    back: [u8; aead::KEY_LEN],
    back_seal: [u8; aead::KEY_LEN],
}

impl std::fmt::Debug for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hop(..)")
    }
}

impl Hop {
    /// Of the secret agreed and of the whole exchange.
    fn of(secret: &[u8; mlkem::SS_LEN], hello: &[u8], ct: &[u8]) -> Hop {
        let mut h = Sponge::shake256();
        h.absorb(secret).absorb(hello).absorb(ct);
        let keys: [u8; 128] = h.squeezed();
        let key = |i: usize| -> [u8; aead::KEY_LEN] { keys[32 * i..32 * i + 32].try_into().expect("32 bytes") };
        Hop { out: key(0), out_seal: key(1), back: key(2), back_seal: key(3) }
    }

    /// The relay takes its wrapping off what goes out: the `count`-th
    /// thing sent this way. What is left is the next relay's to peel,
    /// or, of the last, what was sent.
    pub fn peel(&self, count: u64, bytes: &mut [u8]) {
        aead::xor_stream(&self.out, 0, &nonce(count), bytes);
    }

    /// The relay puts its wrapping on what comes back: the `count`-th
    /// thing sent back this way.
    pub fn cover(&self, count: u64, bytes: &mut [u8]) {
        aead::xor_stream(&self.back, 0, &nonce(count), bytes);
    }
}

fn nonce(count: u64) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce[..8].copy_from_slice(&count.to_le_bytes());
    nonce
}

/// The bytes a thing sent out is longer by than what it says: so that
/// the last relay knows it is what was sent, whole and unchanged.
pub const SEAL: usize = aead::TAG_LEN;

/// Wraps `said` for the way through `hops`, nearest first, as the
/// `count`-th thing sent out: sealed for the last of them, then
/// wrapped for each from the last back to the first. Each peels its
/// own; the last then [`open`]s it.
pub fn wrap(hops: &[Hop], count: u64, said: &[u8]) -> Vec<u8> {
    let last = hops.last().expect("a way has a relay");
    let mut bytes = aead::seal(&last.out_seal, &nonce(count), b"sent", said);
    for hop in hops.iter().rev() {
        hop.peel(count, &mut bytes);
    }
    bytes
}

/// The last relay of a way opens what it has peeled: what was said, if
/// it is whole and was sent this way as the `count`-th.
pub fn open(hop: &Hop, count: u64, peeled: &[u8]) -> Option<Vec<u8>> {
    aead::open(&hop.out_seal, &nonce(count), b"sent", peeled)
}

/// The last relay of a way seals what it sends back, as the `count`-th
/// thing sent back; each relay nearer then [`Hop::cover`]s it.
pub fn seal_back(hop: &Hop, count: u64, said: &[u8]) -> Vec<u8> {
    let mut bytes = aead::seal(&hop.back_seal, &nonce(count), b"back", said);
    hop.cover(count, &mut bytes);
    bytes
}

/// Whoever opened the way takes every wrapping off what came back, the
/// `count`-th, and opens it: what the last relay said, if it is whole.
pub fn unwrap(hops: &[Hop], count: u64, came: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = came.to_vec();
    for hop in hops {
        hop.cover(count, &mut bytes);
    }
    aead::open(&hops.last()?.back_seal, &nonce(count), b"back", &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(seed: u8) -> (mldsa::SecretKey, Digest) {
        let key = mldsa::keygen(&[seed; 32]);
        let id = id_of(key.public_key());
        (key, id)
    }

    /// The hops of a way through relays of these seeds: as whoever
    /// opened it has them, and as the relays do.
    fn way(seeds: &[u8]) -> (Vec<Hop>, Vec<Hop>) {
        let mut both = (Vec::new(), Vec::new());
        for (i, seed) in seeds.iter().enumerate() {
            let (key, id) = relay(*seed);
            let opening = Opening::new(&[i as u8 + 40; 96]);
            let (theirs, answered) = answer(&key, opening.hello(), &[i as u8 + 60; 32]).unwrap();
            both.0.push(opening.agreed(&id, &answered).unwrap());
            both.1.push(theirs);
        }
        both
    }

    /// A key is agreed with the relay the list names, and with nobody
    /// who answers in its place; and an answer to one opening is no
    /// answer to another.
    #[test]
    fn a_key_is_agreed_with_the_relay_named() {
        let ((key, id), (other, other_id)) = (relay(1), relay(2));
        let opening = Opening::new(&[7; 96]);
        let (theirs, answered) = answer(&key, opening.hello(), &[8; 32]).unwrap();
        assert_eq!(answered.len(), ANSWER_LEN);
        assert_eq!(opening.agreed(&id, &answered), Some(theirs.clone()));
        // Another relay answers at its address: not the relay named.
        let (_, forged) = answer(&other, opening.hello(), &[8; 32]).unwrap();
        assert_eq!(opening.agreed(&id, &forged), None);
        assert!(opening.agreed(&other_id, &forged).is_some());
        // The relay's answer to someone else, said again here.
        let elsewhere = Opening::new(&[9; 96]);
        let (_, to_another) = answer(&key, elsewhere.hello(), &[8; 32]).unwrap();
        assert_eq!(opening.agreed(&id, &to_another), None);
        // Changed on the way, or cut short.
        for at in [0, mldsa::PK_LEN, mldsa::PK_LEN + mlkem::CT_LEN, ANSWER_LEN - 1] {
            let mut changed = answered.clone();
            changed[at] ^= 1;
            assert_eq!(opening.agreed(&id, &changed), None, "byte {at}");
        }
        assert_eq!(opening.agreed(&id, &answered[1..]), None);
        assert_eq!(answer(&key, &opening.hello()[1..], &[8; 32]), None);
        // Another opening, other keys.
        let (again, _) = answer(&key, elsewhere.hello(), &[8; 32]).unwrap();
        assert_ne!(again, theirs);
    }

    /// What is sent through three relays is peeled once by each, and is
    /// to none of them what it was to the one before; the last opens
    /// it. What comes back is covered by each and opened by whoever
    /// opened the way, and by nobody on it.
    #[test]
    fn a_message_goes_through_and_comes_back() {
        let (mine, theirs) = way(&[1, 2, 3]);
        let said = b"a slate, or anything else";
        let sent = wrap(&mine, 5, said);
        assert_eq!(sent.len(), said.len() + SEAL);
        let mut bytes = sent.clone();
        let mut seen = vec![sent.clone()];
        for hop in &theirs {
            hop.peel(5, &mut bytes);
            assert!(!seen.contains(&bytes), "each relay passes on something else");
            seen.push(bytes.clone());
        }
        assert_eq!(open(&theirs[2], 5, &bytes).as_deref(), Some(&said[..]));
        // No relay before the last can read it, at any stage of it.
        for stage in &seen {
            assert!(!stage.windows(said.len()).any(|w| w == said));
            assert_eq!(open(&theirs[0], 5, stage), None);
            assert_eq!(open(&theirs[1], 5, stage), None);
        }
        // Not as another message of this way, nor changed.
        assert_eq!(open(&theirs[2], 6, &bytes), None);
        let mut changed = sent.clone();
        changed[3] ^= 1;
        theirs.iter().for_each(|hop| hop.peel(5, &mut changed));
        assert_eq!(open(&theirs[2], 5, &changed), None);
        // Back: sealed by the last, covered by the second and the first.
        let answer = b"its answer";
        let mut back = seal_back(&theirs[2], 9, answer);
        theirs[1].cover(9, &mut back);
        theirs[0].cover(9, &mut back);
        assert_eq!(unwrap(&mine, 9, &back).as_deref(), Some(&answer[..]));
        assert_eq!(unwrap(&mine, 10, &back), None);
        assert_eq!(unwrap(&mine[..2], 9, &back), None);
        back[0] ^= 1;
        assert_eq!(unwrap(&mine, 9, &back), None);
        // A way of one relay, too.
        let (one, its) = way(&[4]);
        let mut bytes = wrap(&one, 0, said);
        its[0].peel(0, &mut bytes);
        assert_eq!(open(&its[0], 0, &bytes).as_deref(), Some(&said[..]));
        assert_eq!(unwrap(&one, 0, &seal_back(&its[0], 0, answer)).as_deref(), Some(&answer[..]));
    }
}
