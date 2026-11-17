//! A block's signed set: every signature its proof rests on, as the
//! leaves of one tree (`docs/PREPROVING.md`).
//!
//! Signatures are checked in signature segments ([`crate::sig_air`]),
//! each saying up to [`SLOTS`] entries. The entries of a block's
//! segments, a segment after another, are the leaves of a tree: segment
//! `s`'s slot `j` is leaf `s * SLOTS + j`. A leaf with no entry is
//! zeros, and so the tree is the same tree however few segments there
//! are. Its root is what a transaction segment is proven against:
//! wherever one needs a signature, it shows the path from the entry to
//! the root.
//!
//! # The tree
//!
//! The tree is made by proofs of proofs, and is shaped by what their
//! machine can do: it compresses the digest it has just made with one
//! it is given, and what it is given as an input it must hash before it
//! can compress it. So:
//!
//! - A segment's root is over its entries **hashed**, each alone, and
//!   those compressed in pairs, five levels.
//! - A node is over four roots (of segments, or of nodes): each
//!   **hashed**, and those compressed in pairs, two levels. Seven
//!   levels of nodes hold `4^7` segments, more than a block's bytes can
//!   spend outputs.
//!
//! Hashing a digest alone is compressing it with a fixed digest
//! ([`ALONE`]): so to whoever climbs it the tree is one of
//! [`DEPTH`] compressions from an entry to the root, some of whose
//! siblings are that fixed digest. A path is [`DEPTH`] siblings and a
//! side for each, and whoever checks one checks compressions and
//! nothing else: a path that compresses up to the root went through
//! the tree's own nodes, or two compressions collide.
//!
//! The tree is a set to whoever reads it: an entry nobody asks for is
//! no harm, so a segment proven for transactions that have since gone
//! into another's block still serves for the rest.

use std::collections::HashMap;

use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, compress};
use crate::sig_air::{self, SLOTS};
use crate::xmss::{PublicKey, Signature};

/// Levels of pairs inside one segment's entries.
const SEGMENT_PAIRS: usize = SLOTS.trailing_zeros() as usize;
/// Children of a node, and the levels of pairs over them.
pub const FAN: usize = 4;
const NODE_PAIRS: usize = 2;
/// Levels of nodes over the segments.
pub const NODE_LEVELS: usize = 7;
/// The most segments a set has.
pub const MAX_SEGMENTS: usize = 1 << (NODE_PAIRS * NODE_LEVELS);
/// Compressions from an entry to a segment's root, and from an entry to
/// the set's root: the length of every path.
pub const SEGMENT_DEPTH: usize = 1 + SEGMENT_PAIRS;
pub const DEPTH: usize = SEGMENT_DEPTH + NODE_LEVELS * (1 + NODE_PAIRS);

/// A leaf with no entry.
pub const NO_ENTRY: Digest = [Fp::ZERO; DIGEST];

/// What a digest hashed alone is compressed with: `hash` of eight
/// elements is their compression with this.
pub const ALONE: Digest = {
    let mut d = [Fp::ZERO; DIGEST];
    d[0] = Fp::new(DIGEST as u32);
    d
};

const _: () = assert!(SLOTS.is_power_of_two() && FAN == 1 << NODE_PAIRS && DEPTH == 27);

/// Whether the step at `level` of a path (0 the lowest) hashes a
/// digest alone, and is not a pair's.
pub const fn alone(level: usize) -> bool {
    level == 0 || (level >= SEGMENT_DEPTH && (level - SEGMENT_DEPTH).is_multiple_of(1 + NODE_PAIRS))
}

/// A digest hashed alone.
pub fn hashed(d: &Digest) -> Digest {
    compress(d, &ALONE)
}

/// The roots of the trees of nothing: `[h]` is what a path through
/// nothing has reached after `h` steps.
pub fn empty_roots() -> [Digest; DEPTH + 1] {
    let mut roots = [NO_ENTRY; DEPTH + 1];
    for h in 0..DEPTH {
        roots[h + 1] = if alone(h) { hashed(&roots[h]) } else { compress(&roots[h], &roots[h]) };
    }
    roots
}

/// The root of the set of nothing.
pub fn empty_root() -> Digest {
    empty_roots()[DEPTH]
}

/// The root of the tree over one segment's entries: what a proof of
/// proofs makes of a signature segment's public values.
pub fn segment_root(entries: &[Digest; SLOTS]) -> Digest {
    let mut level: Vec<Digest> = entries.iter().map(hashed).collect();
    while level.len() > 1 {
        level = level.chunks_exact(2).map(|pair| compress(&pair[0], &pair[1])).collect();
    }
    level[0]
}

/// The root of a node over four roots.
pub fn node_root(children: &[Digest; FAN]) -> Digest {
    let h: Vec<Digest> = children.iter().map(hashed).collect();
    compress(&compress(&h[0], &h[1]), &compress(&h[2], &h[3]))
}

/// A path through the tree: the leaf's place, and at each step, the
/// lowest first, the sibling and whether the path is on the right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    pub leaf: u32,
    pub siblings: [Digest; DEPTH],
    /// Bit `level` is set where the path's node is the right of its pair.
    pub sides: u32,
}

impl Path {
    /// Whether the path's node is on the right at `level`.
    pub fn right(&self, level: usize) -> bool {
        (self.sides >> level) & 1 == 1
    }

    /// The root the path leads `entry` to.
    pub fn root(&self, entry: &Digest) -> Digest {
        let mut node = *entry;
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if self.right(level) { compress(sibling, &node) } else { compress(&node, sibling) };
        }
        node
    }
}

/// The signed set of a block: its segments' entries, and the tree over
/// them, kept whole where it is not empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSet {
    /// `levels[h]` is what there is of the tree after `h` steps up from
    /// the entries: `levels[0]` the leaves, in whole segments. A step
    /// that hashes alone keeps the length; a pair's halves it, rounded
    /// up.
    levels: Vec<Vec<Digest>>,
    empty: [Digest; DEPTH + 1],
    /// Where each entry is first.
    places: HashMap<[u32; DIGEST], u32>,
}

impl Default for SignedSet {
    fn default() -> SignedSet {
        SignedSet::new(&[])
    }
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
            let above = if alone(h) {
                below.iter().map(hashed).collect()
            } else {
                below.chunks(2).map(|pair| compress(&pair[0], pair.get(1).unwrap_or(&empty[h]))).collect()
            };
            levels.push(above);
        }
        let mut places = HashMap::new();
        for (at, entry) in levels[0].iter().enumerate() {
            if *entry != NO_ENTRY {
                places.entry(entry.map(|x| x.to_canonical())).or_insert(at as u32);
            }
        }
        SignedSet { levels, empty, places }
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
        let mut at = leaf as usize;
        let mut sides = 0u32;
        let siblings = core::array::from_fn(|h| {
            if alone(h) {
                return ALONE;
            }
            let sibling = self.levels[h].get(at ^ 1).copied().unwrap_or(self.empty[h]);
            sides |= ((at & 1) as u32) << h;
            at >>= 1;
            sibling
        });
        Path { leaf, siblings, sides }
    }

    /// The path of the first leaf holding `entry`; of an entry the set
    /// lacks, a path of nothing, which leads nowhere.
    pub fn path_of(&self, entry: &Digest) -> Path {
        match self.find(entry) {
            Some(leaf) => self.path(leaf),
            None => Path { leaf: 0, siblings: [NO_ENTRY; DEPTH], sides: 0 },
        }
    }

    /// The first leaf holding `entry`, if one does.
    pub fn find(&self, entry: &Digest) -> Option<u32> {
        self.places.get(&entry.map(|x| x.to_canonical())).copied()
    }
}

/// A signature to be checked: the key, the message and the signature.
pub type Signing = (PublicKey, Digest, Signature);

/// Rows of a signature segment as [`Signed::pack`] fills one: a main
/// network's segment.
pub const SEGMENT_LOG_ROWS: usize = 15;

/// A block's signatures, as its signature segments take them, and the
/// set they make.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Signed {
    /// What each signature segment checks, in order.
    pub segments: Vec<Vec<Signing>>,
    pub set: SignedSet,
}

impl Signed {
    /// Packs `signings` into segments in their order: as many to a
    /// segment as it has slots and rows for. Nothing is checked here;
    /// a signature that does not verify is refused when its segment's
    /// trace is made.
    pub fn pack(signings: Vec<Signing>) -> Signed {
        let rows = (1usize << SEGMENT_LOG_ROWS) - 1;
        let mut segments: Vec<Vec<Signing>> = Vec::new();
        let mut used = rows;
        for signing in signings {
            let needs = sig_air::rows(signing.0.height());
            if segments.last().is_none_or(|s| s.len() == SLOTS) || used + needs > rows {
                segments.push(Vec::new());
                used = 0;
            }
            used += needs;
            segments.last_mut().expect("there is one").push(signing);
        }
        let entries: Vec<[Digest; SLOTS]> = segments.iter().map(|s| Self::entries(s)).collect();
        Signed { segments, set: SignedSet::new(&entries) }
    }

    /// What a segment that checks `signings` says: its entries.
    pub fn entries(signings: &[Signing]) -> [Digest; SLOTS] {
        core::array::from_fn(|j| signings.get(j).map_or(NO_ENTRY, |(pk, msg, sig)| sig_air::entry(pk, msg, sig.index)))
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

    /// The whole tree the slow way, as its makers make it: every
    /// segment there could be under `levels` levels of nodes, each
    /// node of the roots of four.
    fn slow_root(segments: &[[Digest; SLOTS]], levels: usize) -> Digest {
        let mut roots: Vec<Digest> = segments.iter().map(segment_root).collect();
        roots.resize(FAN.pow(levels as u32), segment_root(&[NO_ENTRY; SLOTS]));
        for _ in 0..levels {
            roots = roots.chunks_exact(FAN).map(|four| node_root(four.try_into().unwrap())).collect();
        }
        roots[0]
    }

    /// Hashing a digest alone is the hash of its eight elements, which
    /// is what a proof of proofs' machine computes of one.
    #[test]
    fn a_digest_alone_is_hashed() {
        for tag in [0, 1, 77] {
            assert_eq!(hashed(&entry(tag)), crate::poseidon2::hash(&entry(tag)));
        }
        assert_eq!(hashed(&NO_ENTRY), crate::poseidon2::hash(&NO_ENTRY));
        let which: Vec<usize> = (0..DEPTH).filter(|h| alone(*h)).collect();
        assert_eq!(which, [0, 6, 9, 12, 15, 18, 21, 24]);
    }

    #[test]
    fn the_set_of_nothing_is_the_empty_tree() {
        let set = SignedSet::new(&[]);
        assert!(set.is_empty());
        assert_eq!(set.root(), empty_root());
        assert_eq!(empty_roots()[SEGMENT_DEPTH], segment_root(&[NO_ENTRY; SLOTS]));
        assert_eq!(empty_roots()[SEGMENT_DEPTH + 3], slow_root(&[], 1));
        assert_eq!(empty_roots()[SEGMENT_DEPTH + 6], slow_root(&[], 2));
        // A segment that says nothing is the same as no segment.
        assert_eq!(SignedSet::new(&[[NO_ENTRY; SLOTS]]).root(), set.root());
    }

    /// Every entry's path leads to the root, from its place and no
    /// other, and the root is that of the tree its makers make.
    #[test]
    fn every_entry_has_its_path() {
        for count in [1usize, 2, 3, 5, 17] {
            let segments: Vec<[Digest; SLOTS]> = (0..count).map(|s| segment(s as u32, 32 - s)).collect();
            let set = SignedSet::new(&segments);
            assert_eq!(set.len(), count * SLOTS);
            // Three levels of nodes, then up beside nothing.
            let mut node = slow_root(&segments, 3);
            for level in 3..NODE_LEVELS {
                let nothing = empty_roots()[SEGMENT_DEPTH + 3 * level];
                node = node_root(&[node, nothing, nothing, nothing]);
            }
            assert_eq!(set.root(), node, "{count} segments");
            for (s, entries) in segments.iter().enumerate() {
                for (j, e) in entries.iter().enumerate() {
                    let leaf = (s * SLOTS + j) as u32;
                    let path = set.path(leaf);
                    assert_eq!(path.root(e), set.root());
                    assert!((0..DEPTH).all(|h| !alone(h) || (path.siblings[h] == ALONE && !path.right(h))));
                    assert_ne!(path.root(&entry(9999)), set.root());
                    if *e != NO_ENTRY {
                        // (Two leaves with no entry are each other's
                        // sibling, and the same either way round.)
                        assert_ne!(Path { sides: path.sides ^ 2, ..path }.root(e), set.root());
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
