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

/// Every tag above.
const DOMAINS: &[u32] = &[DOM_PUBKEY, DOM_COMMITMENT];

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

#[cfg(test)]
mod tests {
    use super::*;

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
