//! The base every module above [`crate::poseidon2`] hashes with: the
//! digest type, the empty digest, the domain-separated hash and the list
//! of its domain tags.
//!
//! Every use of [`hash_domain`] has a tag of its own, listed here and
//! nowhere else, so that no two uses can share one: a constant added
//! below without a place in [`DOMAINS`], or with a tag already taken,
//! does not compile. (The tweakable hash of [`crate::xmss`] is another
//! construction with tags of its own.)

use crate::poseidon2::{DIGEST, Fp, WIDTH, permute_in_place};

/// A hash output: 8 BabyBear elements.
pub type Digest = [Fp; DIGEST];

/// The all-zero digest: an empty leaf, an absent value, padding.
pub const EMPTY: Digest = [Fp::ZERO; DIGEST];

// ---------------------------------------------------------------------------
// Domain tags
// ---------------------------------------------------------------------------

/// `H(pubkey)`: a key's hash ([`crate::output::pubkey_hash`]).
pub(crate) const DOM_PUBKEY: u32 = 1;
/// `H(key hash || amount)`: an output's commitment
/// ([`crate::output::key_commitment`]).
pub(crate) const DOM_COMMITMENT: u32 = 2;
/// A transaction's body: what its inputs sign, and its id
/// ([`crate::transaction`]).
pub(crate) const DOM_BODY: u32 = 3;
/// A name: its characters as elements ([`crate::name`]).
pub(crate) const DOM_NAME: u32 = 5;
/// A name's record: what its trie leaf holds.
pub(crate) const DOM_RECORD: u32 = 6;
/// A commit to a name: `H(H(name), salt, owner)`.
pub(crate) const DOM_COMMIT: u32 = 7;
/// A commit bound to the height of its block.
pub(crate) const DOM_COMMIT_LEAF: u32 = 8;
/// A name operation's digest.
pub(crate) const DOM_OP: u32 = 9;
/// The message a name's owner signs to update its record.
pub(crate) const DOM_UPDATE: u32 = 10;
/// A spend policy's leaf: its conditions ([`crate::policy`]).
pub(crate) const DOM_POLICY_LEAF: u32 = 13;
/// A hash lock: `H(preimage)`.
pub(crate) const DOM_HASHLOCK: u32 = 14;
/// The message a rebindable signature signs: channel, state, covered outputs.
pub(crate) const DOM_REBIND: u32 = 15;
/// A run of outputs a spend covers: what a covenant holds.
pub(crate) const DOM_COVERED: u32 = 16;
/// The signers of a threshold, as the block circuit hashes them.
pub(crate) const DOM_SIGNERS: u32 = 17;

/// Every tag above.
const DOMAINS: &[u32] = &[
    DOM_PUBKEY,
    DOM_COMMITMENT,
    DOM_BODY,
    DOM_NAME,
    DOM_RECORD,
    DOM_COMMIT,
    DOM_COMMIT_LEAF,
    DOM_OP,
    DOM_UPDATE,
    DOM_POLICY_LEAF,
    DOM_HASHLOCK,
    DOM_REBIND,
    DOM_COVERED,
    DOM_SIGNERS,
];

// No two domains share a tag.
const _: () = {
    let mut i = 0;
    while i < DOMAINS.len() {
        let mut j = i + 1;
        while j < DOMAINS.len() {
            assert!(DOMAINS[i] != DOMAINS[j], "two hash domains share a tag");
            j += 1;
        }
        i += 1;
    }
};

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

const MASK30: u64 = (1 << 30) - 1;

/// Domain-separated sponge over the Poseidon2 permutation. The capacity holds
/// the domain tag and the input length, so inputs of different lengths never
/// collide through zero padding.
pub(crate) fn hash_domain(domain: u32, input: &[Fp]) -> Digest {
    let len = input.len() as u64;
    let mut state = [Fp::ZERO; WIDTH];
    state[DIGEST] = Fp::new(domain);
    state[DIGEST + 1] = Fp::new((len & MASK30) as u32);
    state[DIGEST + 2] = Fp::new((len >> 30) as u32);
    let mut absorbed = false;
    for chunk in input.chunks(DIGEST) {
        for (s, x) in state.iter_mut().zip(chunk) {
            *s = s.add(x);
        }
        permute_in_place(&mut state);
        absorbed = true;
    }
    if !absorbed {
        permute_in_place(&mut state);
    }
    state[..DIGEST].try_into().unwrap()
}

/// [`hash_domain`] of an input given in parts: the same digest as of the
/// parts joined, without a buffer to join them in. The capacity holds the
/// input's length, so it is given first, and [`DomainHasher::finish`]
/// checks that exactly that many elements were absorbed.
pub(crate) struct DomainHasher {
    state: [Fp; WIDTH],
    /// Elements absorbed into the current block.
    fill: usize,
    /// Elements still to come.
    left: usize,
    permuted: bool,
}

impl DomainHasher {
    /// Starts the hash of `len` elements under `domain`.
    pub(crate) fn new(domain: u32, len: usize) -> DomainHasher {
        let mut state = [Fp::ZERO; WIDTH];
        state[DIGEST] = Fp::new(domain);
        state[DIGEST + 1] = Fp::new((len as u64 & MASK30) as u32);
        state[DIGEST + 2] = Fp::new((len as u64 >> 30) as u32);
        DomainHasher { state, fill: 0, left: len, permuted: false }
    }

    pub(crate) fn absorb(&mut self, part: &[Fp]) {
        assert!(part.len() <= self.left, "more elements than the hash was started for");
        self.left -= part.len();
        for x in part {
            self.state[self.fill] = self.state[self.fill].add(x);
            self.fill += 1;
            if self.fill == DIGEST {
                permute_in_place(&mut self.state);
                self.fill = 0;
                self.permuted = true;
            }
        }
    }

    pub(crate) fn finish(mut self) -> Digest {
        assert!(self.left == 0, "fewer elements than the hash was started for");
        // A short final block is zero padded; an empty input is one block.
        if self.fill > 0 || !self.permuted {
            permute_in_place(&mut self.state);
        }
        self.state[..DIGEST].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An input absorbed in parts hashes as the parts joined, wherever
    /// they are cut and whatever its length; the length is part of the hash.
    #[test]
    fn hasher_in_parts_is_hash_domain_of_the_whole() {
        let input: Vec<Fp> = (0..40).map(|i| Fp::new(500 + i)).collect();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 40] {
            let want = hash_domain(DOM_COVERED, &input[..len]);
            for cut in 0..=len {
                let mut h = DomainHasher::new(DOM_COVERED, len);
                h.absorb(&input[..cut]);
                h.absorb(&[]);
                h.absorb(&input[cut..len]);
                assert_eq!(h.finish(), want, "length {len} cut at {cut}");
            }
        }
        let short = std::panic::catch_unwind(|| {
            let mut h = DomainHasher::new(DOM_COVERED, 3);
            h.absorb(&[Fp::ONE; 2]);
            h.finish()
        });
        let long = std::panic::catch_unwind(|| DomainHasher::new(DOM_COVERED, 3).absorb(&[Fp::ONE; 4]));
        assert!(short.is_err() && long.is_err());
    }

    #[test]
    fn hash_domain_separates() {
        let x = [Fp::new(1), Fp::new(2)];
        assert_ne!(hash_domain(DOM_PUBKEY, &x), hash_domain(DOM_COMMITMENT, &x));
        assert_ne!(hash_domain(DOM_PUBKEY, &x), hash_domain(DOM_PUBKEY, &x[..1]));
        assert_ne!(hash_domain(DOM_PUBKEY, &[]), hash_domain(DOM_PUBKEY, &[Fp::ZERO]));
        let nine = [Fp::new(3); 9];
        assert_ne!(hash_domain(DOM_PUBKEY, &nine), hash_domain(DOM_PUBKEY, &nine[..8]));
    }

    #[test]
    fn the_empty_digest_is_zero() {
        assert!(EMPTY.iter().all(|x| *x == Fp::ZERO));
    }
}
