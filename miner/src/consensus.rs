//! The votes for a consensus file, and what names one.
//!
//! The message layer of the network is run by a file its miners agree
//! on. A miner that favours a file sets leaf 0 of the leaves its
//! header's auxiliary bytes commit to ([`crate::chain::leaves`]) to the
//! file's SHA-256: a vote. A node that follows the chain counts the
//! votes over the last [`WINDOW`] blocks of the chain and fetches the
//! files they name, the most voted first.
//!
//! This is the count, and the constants of the rule. What a file says,
//! and which of the files voted for is in force, is the message layer's
//! to read.

use crate::hash::Digest;
use crate::poseidon2::Fp;

/// Blocks over which votes are counted.
pub const WINDOW: u32 = 144;
/// The file in force changes only at heights that are multiples of this,
/// decided from the window ending there.
pub const EPOCH: u32 = WINDOW;
/// Blocks from a boundary `B` over which a change is made: both files
/// stand from `B` to `B + GRACE - 2`, the old one goes at `B + GRACE - 1`.
pub const GRACE: u32 = 6;
/// From `B + SWITCH` senders prefer the new file.
pub const SWITCH: u32 = 2;
/// Largest file.
pub const MAX_CONSENSUS: usize = 1 << 20;

/// The last boundary at or below `height`.
pub fn boundary(height: u32) -> u32 {
    height / EPOCH * EPOCH
}

/// A file's vote value: its SHA-256.
pub type Hash = [u8; 32];

/// The votes over a window of the chain's blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Votes {
    /// Each hash voted for, with its votes and the highest height that
    /// voted for it, most votes first, then most recent.
    pub counts: Vec<(Hash, u32, u32)>,
    /// Blocks of the window whose headers commit to leaves that are not
    /// here yet, so whose vote is unknown: their id and height.
    pub missing: Vec<(Digest, u32)>,
    /// Blocks in the window.
    pub blocks: u32,
    /// The window's first and last heights.
    pub range: (u32, u32),
}

impl Votes {
    /// Builds the count from each block's vote, `None` for a block whose
    /// leaves are missing.
    pub fn tally(range: (u32, u32), blocks: impl Iterator<Item = (Digest, u32, Option<Hash>)>) -> Votes {
        let mut counts: Vec<(Hash, u32, u32)> = Vec::new();
        let mut missing = Vec::new();
        let mut n = 0;
        for (id, height, vote) in blocks {
            n += 1;
            match vote {
                None => missing.push((id, height)),
                Some(h) if h == [0u8; 32] => {}
                Some(h) => match counts.iter_mut().find(|c| c.0 == h) {
                    Some(c) => {
                        c.1 += 1;
                        c.2 = c.2.max(height);
                    }
                    None => counts.push((h, 1, height)),
                },
            }
        }
        counts.sort_by_key(|c| std::cmp::Reverse((c.1, c.2)));
        Votes { counts, missing, blocks: n, range }
    }

    /// Votes cast, for any file.
    pub fn cast(&self) -> u32 {
        self.counts.iter().map(|c| c.1).sum()
    }
}

/// The transfer id of the file with SHA-256 `hash`: the hash's eight
/// little-endian words, each cut to 30 bits so the id is a canonical
/// digest (every word below the field's modulus). A file is still checked
/// by its full hash once it arrives; the id only names it on the wire.
pub fn file_id(hash: &Hash) -> Digest {
    core::array::from_fn(|i| Fp::new(u32::from_le_bytes(hash[4 * i..4 * i + 4].try_into().unwrap()) & 0x3fff_ffff))
}

/// Whether `bytes` are the file `hash` names.
pub fn file_matches(hash: &Hash, bytes: &[u8]) -> bool {
    crate::sha256::sha256(bytes) == *hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::digest_to_bytes;

    fn id(i: u32) -> Digest {
        core::array::from_fn(|k| Fp::new(i * 8 + k as u32))
    }

    #[test]
    fn votes_count_and_break_ties_by_recency() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let blocks = vec![
            (id(1), 10, Some(a)),
            (id(2), 11, Some(b)),
            (id(3), 12, Some([0u8; 32])),
            (id(4), 13, None),
            (id(5), 14, Some(b)),
            (id(6), 15, Some(a)),
        ];
        let v = Votes::tally((10, 15), blocks.into_iter());
        // Two votes each: the one voted for last comes first.
        assert_eq!(v.counts, vec![(a, 2, 15), (b, 2, 14)]);
        assert_eq!(v.missing, vec![(id(4), 13)]);
        assert_eq!((v.blocks, v.cast(), v.range), (6, 4, (10, 15)));
        let more = Votes::tally((1, 3), [(id(1), 1, Some(b)), (id(2), 2, Some(b)), (id(3), 3, Some(a))].into_iter());
        assert_eq!(more.counts, vec![(b, 2, 2), (a, 1, 3)]);
        assert_eq!(Votes::tally((0, 0), std::iter::empty()), Votes { range: (0, 0), ..Votes::default() });
    }

    #[test]
    fn file_ids_are_canonical_digests() {
        let hash: Hash = core::array::from_fn(|i| 0xff - i as u8);
        let fid = file_id(&hash);
        // Every word is below the modulus, so the id survives the wire.
        assert_eq!(crate::poseidon2::digest_from_bytes(&digest_to_bytes(&fid)), Some(fid));
        assert!(fid.iter().all(|x| x.to_canonical() < 1 << 30));
        assert_ne!(file_id(&[1; 32]), file_id(&[2; 32]));
        assert_eq!(file_id(&hash), fid);
        assert!(file_matches(&crate::sha256::sha256(b"mode init\n"), b"mode init\n"));
        assert!(!file_matches(&crate::sha256::sha256(b"mode init\n"), b"mode init"));
    }

    #[test]
    fn boundaries() {
        assert_eq!((boundary(0), boundary(143), boundary(144), boundary(300)), (0, 0, 144, 288));
        assert!(SWITCH < GRACE && GRACE < EPOCH);
    }
}
