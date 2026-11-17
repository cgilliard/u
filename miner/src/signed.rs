//! A block's signed set: every signature its proof rests on, as the
//! leaves of one tree (`docs/PREPROVING.md`).
//!
//! Signatures are checked in signature segments ([`crate::sig_air`]),
//! each saying up to [`SLOTS`] entries. The entries of a block's
//! segments, a segment after another, are the leaves of a Merkle tree
//! of [`DEPTH`] levels: segment `s`'s slot `j` is leaf `s * SLOTS + j`.
//! A leaf with no entry is zeros, and so the tree is the same tree
//! however few segments there are. Its root is what a transaction
//! segment is proven against: wherever one needs a signature, it shows
//! the path from the entry to the root.
//!
//! The tree is a set to whoever reads it: an entry nobody asks for is
//! no harm, so a segment proven for transactions that have since gone
//! into another's block still serves for the rest.

use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, compress};
use crate::sig_air::SLOTS;

/// Levels of the tree inside one segment's entries.
pub const SEGMENT_LEVELS: usize = SLOTS.trailing_zeros() as usize;
/// Levels above the segments: room for `2^14` of them, more signatures
/// than a block's bytes can spend outputs.
pub const SEGMENTS_LEVELS: usize = 14;
/// Levels from an entry to the root: the length of every path.
pub const DEPTH: usize = SEGMENT_LEVELS + SEGMENTS_LEVELS;
/// The most segments a set has.
pub const MAX_SEGMENTS: usize = 1 << SEGMENTS_LEVELS;

/// A leaf with no entry.
pub const NO_ENTRY: Digest = [Fp::ZERO; DIGEST];

const _: () = assert!(SLOTS.is_power_of_two() && DEPTH == 19);

/// The roots of the trees of nothing, by height: `[h]` is that of
/// `2^h` leaves with no entry.
pub fn empty_roots() -> [Digest; DEPTH + 1] {
    let mut roots = [NO_ENTRY; DEPTH + 1];
    for h in 1..=DEPTH {
        roots[h] = compress(&roots[h - 1], &roots[h - 1]);
    }
    roots
}

/// The root of the tree over one segment's entries: what a proof of
/// proofs makes of a signature segment's public values.
pub fn segment_root(entries: &[Digest; SLOTS]) -> Digest {
    let mut level = entries.to_vec();
    while level.len() > 1 {
        level = level.chunks_exact(2).map(|pair| compress(&pair[0], &pair[1])).collect();
    }
    level[0]
}

/// A path through the tree: the leaf's place, and the sibling at each
/// level, the lowest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    pub leaf: u32,
    pub siblings: [Digest; DEPTH],
}

impl Path {
    /// The root the path leads `entry` to.
    pub fn root(&self, entry: &Digest) -> Digest {
        let mut node = *entry;
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = match (self.leaf >> level) & 1 {
                0 => compress(&node, sibling),
                _ => compress(sibling, &node),
            };
        }
        node
    }
}

/// The signed set of a block: its segments' entries, and the tree over
/// them, kept whole where it is not empty.
#[derive(Clone, Debug)]
pub struct SignedSet {
    /// `levels[0]` is the leaves that there are, in whole segments;
    /// each level above is half as long, rounded up.
    levels: Vec<Vec<Digest>>,
    empty: [Digest; DEPTH + 1],
}

impl SignedSet {
    /// The set of these segments' entries.
    ///
    /// # Panics
    ///
    /// If there are more segments than a set has.
    pub fn new(segments: &[[Digest; SLOTS]]) -> SignedSet {
        assert!(segments.len() <= MAX_SEGMENTS, "more signature segments than a block has");
        let empty = empty_roots();
        let mut levels: Vec<Vec<Digest>> = vec![segments.iter().flatten().copied().collect()];
        for h in 0..DEPTH {
            let below = &levels[h];
            let above = below.chunks(2).map(|pair| compress(&pair[0], pair.get(1).unwrap_or(&empty[h]))).collect();
            levels.push(above);
        }
        SignedSet { levels, empty }
    }

    /// The set's root: of nothing, the empty tree's.
    pub fn root(&self) -> Digest {
        self.levels[DEPTH].first().copied().unwrap_or(self.empty[DEPTH])
    }

    /// How many leaves there are, with or without entries.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// The path of leaf `leaf`.
    pub fn path(&self, leaf: u32) -> Path {
        assert!((leaf as usize) < self.len(), "no such leaf");
        let siblings = core::array::from_fn(|h| {
            let at = ((leaf as usize) >> h) ^ 1;
            self.levels[h].get(at).copied().unwrap_or(self.empty[h])
        });
        Path { leaf, siblings }
    }

    /// The first leaf holding `entry`, if one does.
    pub fn find(&self, entry: &Digest) -> Option<u32> {
        self.levels[0].iter().position(|e| e == entry).map(|at| at as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(1 + tag * 10 + i as u32))
    }

    fn segment(tag: u32, filled: usize) -> [Digest; SLOTS] {
        core::array::from_fn(|j| if j < filled { entry(tag * 100 + j as u32) } else { NO_ENTRY })
    }

    /// The whole tree, the slow way: every leaf there could be under a
    /// root of `height` levels, the missing ones empty.
    fn slow_root(leaves: &[Digest], height: usize) -> Digest {
        let mut level: Vec<Digest> = leaves.to_vec();
        level.resize(1 << height, NO_ENTRY);
        while level.len() > 1 {
            level = level.chunks_exact(2).map(|p| compress(&p[0], &p[1])).collect();
        }
        level[0]
    }

    #[test]
    fn the_set_of_nothing_is_the_empty_tree() {
        let set = SignedSet::new(&[]);
        assert!(set.is_empty());
        assert_eq!(set.root(), empty_roots()[DEPTH]);
        assert_eq!(empty_roots()[SEGMENT_LEVELS], segment_root(&[NO_ENTRY; SLOTS]));
        assert_eq!(empty_roots()[3], slow_root(&[], 3));
        // A segment that says nothing is the same as no segment.
        assert_eq!(SignedSet::new(&[[NO_ENTRY; SLOTS]]).root(), set.root());
    }

    /// Every entry's path leads to the root, from its place and no
    /// other, and the root is that of the tree made of the segments'
    /// roots.
    #[test]
    fn every_entry_has_its_path() {
        for count in [1usize, 2, 3, 5] {
            let segments: Vec<[Digest; SLOTS]> = (0..count).map(|s| segment(s as u32, 32 - 3 * s)).collect();
            let set = SignedSet::new(&segments);
            assert_eq!(set.len(), count * SLOTS);
            // Over the segments' roots, up from where the segments end.
            let mut roots: Vec<Digest> = segments.iter().map(segment_root).collect();
            roots.resize(8, empty_roots()[SEGMENT_LEVELS]);
            let mut node = slow_root(&roots, 3);
            for h in SEGMENT_LEVELS + 3..DEPTH {
                node = compress(&node, &empty_roots()[h]);
            }
            assert_eq!(set.root(), node, "{count} segments");
            for (s, entries) in segments.iter().enumerate() {
                for (j, e) in entries.iter().enumerate() {
                    let leaf = (s * SLOTS + j) as u32;
                    let path = set.path(leaf);
                    assert_eq!(path.root(e), set.root());
                    assert_ne!(path.root(&entry(9999)), set.root());
                    if *e != NO_ENTRY {
                        // (Two leaves with no entry are each other's
                        // sibling, and the same either way round.)
                        assert_ne!(Path { leaf: leaf ^ 1, ..path }.root(e), set.root());
                        assert_eq!(set.find(e), Some(leaf));
                    }
                }
            }
            assert_eq!(set.find(&entry(9999)), None);
        }
    }

    /// One entry more or one changed is another root.
    #[test]
    fn the_root_is_of_these_entries() {
        let a = SignedSet::new(&[segment(1, 4)]);
        assert_ne!(a.root(), SignedSet::new(&[segment(1, 5)]).root());
        assert_ne!(a.root(), SignedSet::new(&[segment(2, 4)]).root());
        assert_ne!(a.root(), SignedSet::new(&[segment(1, 4), segment(1, 4)]).root());
    }
}
