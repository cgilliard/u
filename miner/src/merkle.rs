//! Merkle vector commitments over rows of field elements.
//!
//! Each leaf is a row of `Fp` values hashed with the length-binding Poseidon2
//! sponge from [`crate::poseidon2::hash`]; internal nodes use
//! [`crate::poseidon2::compress`]. The number of leaves must be a power of
//! two. Paths list siblings from the leaf level upwards.
//!
//! # Memory
//!
//! A tree ([`MerkleTree`]) is a prover's: all its nodes in one buffer, the
//! leaves first and each level after the one below it, `2 n - 1` digests,
//! each level hashed into its place.
//!
//! A verifier holds no tree. One opening is checked from the row and its
//! path where they lie ([`verify`]), with no heap. The openings a proof's
//! queries make of one tree travel together, the siblings that follow from
//! other openings left out, and are checked together ([`batch_root`]) as
//! the siblings are read: three words and two digests for each opening,
//! held while the root is made.

pub use crate::hash::Digest;
use crate::hash::EMPTY;
use crate::parallel::{par_chunks_mut, par_fill};
use crate::poseidon2::{Fp, LANES, compress, compress_batch, hash, hash_batch};

/// Hashes in a thread's share before a level is worth more threads:
/// eight at a time, 128 times.
const PER_THREAD: usize = LANES * 128;

/// Hash of one leaf row.
pub fn hash_row(row: &[Fp]) -> Digest {
    hash(row)
}

/// A complete binary Merkle tree with all levels kept in memory.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Every node: the `leaves` leaf hashes, then each level above, the
    /// root last.
    nodes: Vec<Digest>,
    leaves: usize,
}

impl MerkleTree {
    /// Builds a tree over `rows`. `rows.len()` must be a non-zero power of two.
    pub fn new(rows: &[Vec<Fp>]) -> MerkleTree {
        Self::build(rows.len(), |leaves| par_fill(leaves, |i| hash_row(&rows[i])))
    }

    /// Builds a tree over rows given as slices of a flat buffer of equal-size
    /// rows (`row_len` elements each).
    pub fn from_flat(flat: &[Fp], row_len: usize) -> MerkleTree {
        assert!(row_len > 0 && flat.len().is_multiple_of(row_len));
        Self::build(flat.len() / row_len, |leaves| leaf_hashes_into(flat, row_len, leaves))
    }

    /// Builds a tree over leaves hashed already; their buffer becomes the
    /// tree's.
    pub fn from_leaf_hashes(mut leaves: Vec<Digest>) -> MerkleTree {
        let n = leaves.len();
        assert!(n.is_power_of_two(), "leaf count must be a power of two");
        leaves.reserve_exact(n - 1);
        leaves.resize(2 * n - 1, EMPTY);
        Self::above(leaves, n)
    }

    /// A tree of `n` leaves, hashed by `fill` into their place.
    fn build(n: usize, fill: impl FnOnce(&mut [Digest])) -> MerkleTree {
        assert!(n.is_power_of_two(), "leaf count must be a power of two");
        let mut nodes = vec![EMPTY; 2 * n - 1];
        fill(&mut nodes[..n]);
        Self::above(nodes, n)
    }

    /// Hashes each level above the leaves into its place.
    fn above(mut nodes: Vec<Digest>, n: usize) -> MerkleTree {
        let (mut start, mut len) = (0, n);
        while len > 1 {
            let (below, level) = nodes.split_at_mut(start + len);
            let (below, level) = (&below[start..], &mut level[..len / 2]);
            if level.len().is_multiple_of(LANES) {
                par_chunks_mut(level, PER_THREAD, |c, out| {
                    for (g, out) in out.chunks_exact_mut(LANES).enumerate() {
                        let first = c * PER_THREAD + g * LANES;
                        out.copy_from_slice(&compress_batch(core::array::from_fn(|l| {
                            let i = first + l;
                            (&below[2 * i], &below[2 * i + 1])
                        })));
                    }
                });
            } else {
                for (i, out) in level.iter_mut().enumerate() {
                    *out = compress(&below[2 * i], &below[2 * i + 1]);
                }
            }
            start += len;
            len /= 2;
        }
        MerkleTree { nodes, leaves: n }
    }

    pub fn root(&self) -> Digest {
        self.nodes[self.nodes.len() - 1]
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Path length, `log2(len)`.
    pub fn height(&self) -> usize {
        self.leaves.trailing_zeros() as usize
    }

    /// Leaf hash `index`.
    pub fn leaf(&self, index: usize) -> Digest {
        self.nodes[..self.leaves][index]
    }

    /// Sibling hashes for `index`, leaf level first, read from the tree.
    pub fn siblings(&self, index: usize) -> impl ExactSizeIterator<Item = Digest> + '_ {
        assert!(index < self.len());
        let n = self.leaves;
        // Level `k` begins `2 n - 2 n / 2^k` nodes in.
        (0..self.height()).map(move |k| self.nodes[2 * n - (2 * n >> k) + ((index >> k) ^ 1)])
    }

    /// Sibling hashes for `index`, leaf level first.
    pub fn open(&self, index: usize) -> Vec<Digest> {
        self.siblings(index).collect()
    }
}

/// The parents of the pairs `(left[i], right[i])`: a level of a tree
/// whose two halves are held apart, hashed several at a time on every
/// thread as the levels of a [`MerkleTree`] are.
pub fn compress_pairs(left: &[Digest], right: &[Digest]) -> Vec<Digest> {
    assert_eq!(left.len(), right.len());
    let mut out = vec![EMPTY; left.len()];
    if out.len().is_multiple_of(LANES) {
        par_chunks_mut(&mut out, PER_THREAD, |c, out| {
            for (g, out) in out.chunks_exact_mut(LANES).enumerate() {
                let first = c * PER_THREAD + g * LANES;
                out.copy_from_slice(&compress_batch(core::array::from_fn(|l| (&left[first + l], &right[first + l]))));
            }
        });
    } else {
        for (i, out) in out.iter_mut().enumerate() {
            *out = compress(&left[i], &right[i]);
        }
    }
    out
}

/// The path of leaf `pos` through a small tree over the leaf hashes
/// `block` (a power of two of them), leaf level first, and that tree's
/// root: for a prover that keeps a large tree from some level up, and
/// makes the levels under it again when a leaf is opened.
pub fn block_path(block: &[Digest], pos: usize) -> (Vec<Digest>, Digest) {
    assert!(block.len().is_power_of_two() && pos < block.len());
    let (mut level, mut at, mut path) = (block.to_vec(), pos, Vec::new());
    while level.len() > 1 {
        path.push(level[at ^ 1]);
        level = level.chunks_exact(2).map(|pair| compress(&pair[0], &pair[1])).collect();
        at >>= 1;
    }
    (path, level[0])
}

/// Leaf hashes of the rows of a flat buffer of `row_len`-element rows.
pub fn leaf_hashes(flat: &[Fp], row_len: usize) -> Vec<Digest> {
    assert!(row_len > 0 && flat.len().is_multiple_of(row_len));
    let mut out = vec![EMPTY; flat.len() / row_len];
    leaf_hashes_into(flat, row_len, &mut out);
    out
}

/// [`leaf_hashes`] into `out`, a digest for each row.
pub fn leaf_hashes_into(flat: &[Fp], row_len: usize, out: &mut [Digest]) {
    assert!(row_len > 0 && flat.len() == out.len() * row_len, "a digest for each row");
    let row = |i: usize| &flat[i * row_len..(i + 1) * row_len];
    if out.len().is_multiple_of(LANES) {
        par_chunks_mut(out, PER_THREAD, |c, out| {
            for (g, out) in out.chunks_exact_mut(LANES).enumerate() {
                let first = c * PER_THREAD + g * LANES;
                out.copy_from_slice(&hash_batch(core::array::from_fn(|l| row(first + l))));
            }
        });
    } else {
        par_fill(out, |i| hash_row(row(i)));
    }
}

/// Recomputes the root from a leaf row and its path.
pub fn root_from_path(index: usize, row: &[Fp], path: &[Digest]) -> Digest {
    let mut node = hash_row(row);
    let mut i = index;
    for sibling in path {
        node = if i & 1 == 0 { compress(&node, sibling) } else { compress(sibling, &node) };
        i >>= 1;
    }
    node
}

/// Checks that `row` is leaf `index` of a tree with `height` levels and the
/// given root.
pub fn verify(root: &Digest, height: usize, index: usize, row: &[Fp], path: &[Digest]) -> bool {
    path.len() == height
        && height < usize::BITS as usize
        && index < (1usize << height)
        && root_from_path(index, row, path) == *root
}

// ---------------------------------------------------------------------------
// Batched openings
// ---------------------------------------------------------------------------

/// An opening on its way up the tree.
#[derive(Clone, Copy)]
struct Opening {
    /// Its node's index in the level the walk is at.
    pos: usize,
    node: Digest,
    /// Its node's sibling.
    sibling: Digest,
}

/// Walks the paths of leaves `indices` (with hashes `leaves`) of a tree of
/// `height` levels, level by level, giving `each(query, level, sibling)`
/// every sibling of every path, and returns the root they make (the empty
/// digest for no openings). A sibling is asked of `supply(query, level)`
/// only when no opened leaf lies under it and it was not supplied before
/// at that level: the others follow from the openings. Encoder and decoder
/// share this walk, so they agree on which siblings travel. Of two
/// openings of one leaf, the first's hash is the leaf's.
///
/// An opening looks for its sibling among the others one at a time: the
/// work grows with the square of their number, a proof's queries, a few
/// tens.
fn walk_paths(
    height: usize,
    indices: &[usize],
    leaves: &[Digest],
    mut supply: impl FnMut(usize, usize) -> Option<Digest>,
    mut each: impl FnMut(usize, usize, &Digest),
) -> Option<Digest> {
    assert_eq!(indices.len(), leaves.len(), "a leaf for each index");
    let mask = if height >= usize::BITS as usize { usize::MAX } else { (1usize << height) - 1 };
    let mut open: Vec<Opening> =
        indices.iter().zip(leaves).map(|(i, leaf)| Opening { pos: i & mask, node: *leaf, sibling: EMPTY }).collect();
    for level in 0..height {
        for q in 0..open.len() {
            let (pos, sibling) = (open[q].pos, open[q].pos ^ 1);
            let d = if let Some(o) = open.iter().find(|o| o.pos == sibling) {
                // Another opening's node.
                o.node
            } else if let Some(o) = open[..q].iter().find(|o| o.pos == pos) {
                // An opening of the same node before this one: supplied to it.
                o.sibling
            } else {
                supply(q, level)?
            };
            open[q].sibling = d;
            each(q, level, &d);
        }
        // Up a level, in place: those before `q` are there already.
        for q in 0..open.len() {
            let parent = open[q].pos >> 1;
            open[q].node = match open[..q].iter().find(|o| o.pos == parent) {
                Some(o) => o.node,
                None => {
                    let (own, sibling) = (&open[q].node, &open[q].sibling);
                    if open[q].pos & 1 == 0 { compress(own, sibling) } else { compress(sibling, own) }
                }
            };
            open[q].pos = parent;
        }
    }
    Some(open.first().map_or(EMPTY, |o| o.node))
}

/// The siblings to send for opening leaves `indices` (hashes `leaves`,
/// paths `paths`) of one tree of `height` levels: those no other opening
/// determines, each once, in walk order. [`expand_paths`] rebuilds the
/// paths from them, and [`batch_root`] the root. For paths that do not
/// belong to one tree the rebuilt paths differ, and fail verification as
/// the originals would.
pub fn compress_paths(height: usize, indices: &[usize], leaves: &[Digest], paths: &[&[Digest]]) -> Vec<Digest> {
    let mut out = Vec::new();
    walk_paths(
        height,
        indices,
        leaves,
        |q, level| {
            let d = paths[q][level];
            out.push(d);
            Some(d)
        },
        |_, _, _| {},
    );
    out
}

/// Rebuilds the paths of [`compress_paths`], reading the sent siblings
/// from `next`. `None` if `next` runs out.
pub fn expand_paths(
    height: usize,
    indices: &[usize],
    leaves: &[Digest],
    next: impl FnMut() -> Option<Digest>,
) -> Option<Vec<Vec<Digest>>> {
    let mut paths = vec![Vec::with_capacity(height); indices.len()];
    let mut next = next;
    walk_paths(height, indices, leaves, |_, _| next(), |q, _, d| paths[q].push(*d))?;
    Some(paths)
}

/// The root that openings of leaves `indices` (hashes `leaves`) of a tree
/// of `height` levels make with the siblings of [`compress_paths`], read
/// from `next`: the openings are those of a tree with a given root exactly
/// when this is that root. The same as rebuilding every path
/// ([`expand_paths`]) and checking each ([`verify`]), without holding the
/// paths. `None` if there is no opening, an index is not in the tree, a
/// leaf is opened twice with two hashes, or `next` runs out.
pub fn batch_root(
    height: usize,
    indices: &[usize],
    leaves: &[Digest],
    mut next: impl FnMut() -> Option<Digest>,
) -> Option<Digest> {
    if indices.is_empty() || indices.len() != leaves.len() || height >= usize::BITS as usize {
        return None;
    }
    for (q, (i, leaf)) in indices.iter().zip(leaves).enumerate() {
        if *i >= 1usize << height {
            return None;
        }
        if indices[..q].iter().zip(leaves).any(|(j, other)| j == i && other != leaf) {
            return None;
        }
    }
    walk_paths(height, indices, leaves, |_, _| next(), |_, _, _| {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    /// A tree kept from some level up, with the levels under it made
    /// again from a block of leaves, gives the paths the whole tree
    /// gives.
    #[test]
    fn a_path_is_the_same_with_its_lowest_levels_made_again() {
        let rows: Vec<Vec<Fp>> = (0..64u32).map(|i| vec![Fp::new(i), Fp::new(i * i + 7)]).collect();
        let whole = MerkleTree::new(&rows);
        let leaves: Vec<Digest> = rows.iter().map(|r| hash_row(r)).collect();
        for skip in 0..=3 {
            let size = 1usize << skip;
            let roots: Vec<Digest> = leaves.chunks(size).map(|block| block_path(block, 0).1).collect();
            let upper = MerkleTree::from_leaf_hashes(roots);
            assert_eq!(upper.root(), whole.root());
            for i in 0..64 {
                let first = i & !(size - 1);
                let (mut path, root) = block_path(&leaves[first..first + size], i - first);
                assert_eq!(root, upper.leaf(i >> skip));
                path.extend(upper.siblings(i >> skip));
                assert_eq!(path, whole.open(i), "skip {skip}, leaf {i}");
                assert!(verify(&whole.root(), 6, i, &rows[i], &path));
            }
        }
    }

    #[test]
    fn pairs_are_compressed_as_one_by_one() {
        for n in [1usize, 3, 8, 64, 1 << 12] {
            let side =
                |tag: u32| -> Vec<Digest> { (0..n as u32).map(|i| hash_row(&[Fp::new(i), Fp::new(tag)])).collect() };
            let (left, right) = (side(1), side(2));
            let one_by_one: Vec<Digest> = left.iter().zip(&right).map(|(l, r)| compress(l, r)).collect();
            assert_eq!(compress_pairs(&left, &right), one_by_one, "{n}");
        }
    }

    #[test]
    fn open_and_verify_all_leaves() {
        let mut rng = Rng::new(20);
        for log_n in 0..=5 {
            let n = 1 << log_n;
            let rows: Vec<Vec<Fp>> = (0..n).map(|i| (0..(i % 3 + 1)).map(|_| rng.fp()).collect()).collect();
            let tree = MerkleTree::new(&rows);
            assert_eq!(tree.len(), n);
            assert_eq!(tree.height(), log_n);
            for (i, row) in rows.iter().enumerate() {
                let path = tree.open(i);
                assert!(verify(&tree.root(), log_n, i, row, &path), "n={n} i={i}");
                if n > 1 {
                    assert!(!verify(&tree.root(), log_n, i ^ 1, row, &path));
                    let mut bad = path.clone();
                    bad[0][0] += Fp::ONE;
                    assert!(!verify(&tree.root(), log_n, i, row, &bad));
                }
                let mut bad_row = row.clone();
                bad_row[0] += Fp::ONE;
                assert!(!verify(&tree.root(), log_n, i, &bad_row, &path));
                assert!(!verify(&tree.root(), log_n + 1, i, row, &path));
            }
        }
    }

    #[test]
    fn batched_paths_roundtrip() {
        let mut rng = Rng::new(22);
        let rows: Vec<Vec<Fp>> = (0..64).map(|_| vec![rng.fp(), rng.fp()]).collect();
        let tree = MerkleTree::new(&rows);
        for indices in [vec![], vec![5], vec![5, 5], vec![4, 5], vec![0, 63, 31, 32, 7, 7, 8], (0..64).collect()] {
            let leaves: Vec<Digest> = indices.iter().map(|&i| hash_row(&rows[i])).collect();
            let paths: Vec<Vec<Digest>> = indices.iter().map(|&i| tree.open(i)).collect();
            let refs: Vec<&[Digest]> = paths.iter().map(|p| &p[..]).collect();
            let sent = compress_paths(6, &indices, &leaves, &refs);
            assert!(sent.len() <= 6 * indices.len());
            if indices.len() == 64 {
                assert!(sent.is_empty(), "all leaves open: nothing to send");
            }
            let mut it = sent.iter().copied();
            assert_eq!(expand_paths(6, &indices, &leaves, || it.next()).unwrap(), paths, "{indices:?}");
            assert!(it.next().is_none());
            if !sent.is_empty() {
                let mut short = sent[..sent.len() - 1].iter().copied();
                assert!(expand_paths(6, &indices, &leaves, || short.next()).is_none());
            }
        }
        // Two openings far apart share only the top: the siblings below it
        // all travel.
        let leaves = [hash_row(&rows[0]), hash_row(&rows[63])];
        let (p0, p63) = (tree.open(0), tree.open(63));
        assert_eq!(compress_paths(6, &[0, 63], &leaves, &[&p0, &p63]).len(), 10);
    }

    #[test]
    fn flat_matches_rows() {
        let mut rng = Rng::new(21);
        let flat: Vec<Fp> = (0..32).map(|_| rng.fp()).collect();
        let rows: Vec<Vec<Fp>> = flat.chunks(4).map(|c| c.to_vec()).collect();
        assert_eq!(MerkleTree::from_flat(&flat, 4).root(), MerkleTree::new(&rows).root());
        assert_ne!(MerkleTree::from_flat(&flat, 8).root(), MerkleTree::new(&rows).root());
    }

    /// The tree is the same however it is built, and its nodes are where
    /// its openings look for them, at every size: those hashed eight at a
    /// time and those too small to be.
    #[test]
    fn every_way_of_building_gives_one_tree() {
        let mut rng = Rng::new(23);
        for log_n in 0..=11 {
            let n = 1usize << log_n;
            let flat: Vec<Fp> = (0..3 * n).map(|_| rng.fp()).collect();
            let rows: Vec<Vec<Fp>> = flat.chunks(3).map(|c| c.to_vec()).collect();
            let tree = MerkleTree::from_flat(&flat, 3);
            let hashes = leaf_hashes(&flat, 3);
            assert_eq!(hashes, rows.iter().map(|r| hash_row(r)).collect::<Vec<_>>());
            // The root by pairs, a level at a time.
            let mut level = hashes.clone();
            while level.len() > 1 {
                level = level.chunks(2).map(|p| compress(&p[0], &p[1])).collect();
            }
            for other in [MerkleTree::new(&rows), MerkleTree::from_leaf_hashes(hashes.clone())] {
                assert_eq!((other.root(), other.len(), other.height()), (level[0], n, log_n));
                assert_eq!(other.nodes, tree.nodes);
            }
            assert_eq!((tree.root(), tree.nodes.len(), tree.is_empty()), (level[0], 2 * n - 1, false));
            for i in (0..n).step_by(1 + n / 7).chain([n - 1]) {
                assert_eq!(tree.leaf(i), hashes[i]);
                assert_eq!(tree.siblings(i).len(), log_n);
                assert_eq!(root_from_path(i, &rows[i], &tree.open(i)), tree.root(), "leaf {i} of {n}");
            }
        }
        assert!(std::panic::catch_unwind(|| MerkleTree::from_leaf_hashes(vec![EMPTY; 3])).is_err());
        assert!(std::panic::catch_unwind(|| MerkleTree::from_leaf_hashes(vec![])).is_err());
        assert!(std::panic::catch_unwind(|| MerkleTree::new(&[])).is_err());
        assert!(std::panic::catch_unwind(|| MerkleTree::from_flat(&[Fp::ONE; 6], 2)).is_err());
        assert!(std::panic::catch_unwind(|| leaf_hashes(&[Fp::ONE; 5], 2)).is_err());
        assert!(std::panic::catch_unwind(|| leaf_hashes_into(&[Fp::ONE; 4], 2, &mut [EMPTY; 3])).is_err());
        let tree = MerkleTree::from_leaf_hashes(vec![EMPTY; 4]);
        assert!(std::panic::catch_unwind(|| tree.open(4)).is_err());
    }

    /// The root made from openings sent together is the tree's exactly
    /// when every path rebuilt from them verifies: for honest openings,
    /// and for a leaf, an index or a sibling that is not the tree's.
    #[test]
    fn the_batch_root_is_the_root_the_paths_verify_against() {
        let mut rng = Rng::new(24);
        let height = 7;
        let rows: Vec<Vec<Fp>> = (0..1 << height).map(|_| vec![rng.fp(), rng.fp(), rng.fp()]).collect();
        let tree = MerkleTree::new(&rows);
        let root = tree.root();
        let (mut accepted, mut refused) = (0, 0);
        for round in 0..400 {
            let n = 1 + rng.next_u64() as usize % 12;
            // Queries cluster, as a proof's do not, so that they meet below the top.
            let mut indices: Vec<usize> =
                (0..n).map(|_| (rng.next_u64() % if round % 2 == 0 { 128 } else { 12 }) as usize).collect();
            if round % 5 == 0 {
                indices.push(indices[0]);
            }
            let mut leaf_rows: Vec<Vec<Fp>> = indices.iter().map(|&i| rows[i].clone()).collect();
            let paths: Vec<Vec<Digest>> = indices.iter().map(|&i| tree.open(i)).collect();
            let refs: Vec<&[Digest]> = paths.iter().map(|p| &p[..]).collect();
            let honest: Vec<Digest> = leaf_rows.iter().map(|r| hash_row(r)).collect();
            let mut sent = compress_paths(height, &indices, &honest, &refs);
            // Something that is not the tree's, most rounds.
            match round % 4 {
                1 => leaf_rows[rng.next_u64() as usize % indices.len()][0] += Fp::ONE,
                2 if !sent.is_empty() => {
                    let at = rng.next_u64() as usize % sent.len();
                    sent[at][3] += Fp::ONE;
                }
                3 => {
                    let at = rng.next_u64() as usize % indices.len();
                    indices[at] ^= 1 << (rng.next_u64() % 7);
                }
                _ => {}
            }
            let leaves: Vec<Digest> = leaf_rows.iter().map(|r| hash_row(r)).collect();
            let mut it = sent.iter().copied();
            let by_paths = expand_paths(height, &indices, &leaves, || it.next()).is_some_and(|paths| {
                (0..indices.len()).all(|q| verify(&root, height, indices[q], &leaf_rows[q], &paths[q]))
            });
            let mut it = sent.iter().copied();
            let by_root = batch_root(height, &indices, &leaves, || it.next()) == Some(root);
            assert_eq!(by_root, by_paths, "round {round}: {indices:?}");
            if round % 4 == 0 {
                assert!(by_root, "honest openings, round {round}");
            }
            if by_root { accepted += 1 } else { refused += 1 }
        }
        assert!(accepted >= 100 && refused >= 100, "{accepted} accepted, {refused} refused");
        // What is no set of openings of the tree.
        let leaf = hash_row(&rows[5]);
        let path = tree.open(5);
        let sent = |n: usize| {
            let mut it = path[..n].to_vec().into_iter();
            move || it.next()
        };
        assert_eq!(batch_root(height, &[5], &[leaf], sent(height)), Some(root));
        assert_eq!(batch_root(height, &[5], &[leaf], sent(height - 1)), None);
        assert_eq!(batch_root(height, &[], &[], sent(0)), None);
        assert_eq!(batch_root(height, &[5 + 128], &[leaf], sent(height)), None);
        assert_eq!(batch_root(height, &[5, 5], &[leaf], sent(height)), None);
        assert_eq!(batch_root(height, &[5, 5], &[leaf, hash_row(&rows[6])], sent(height)), None);
        assert_eq!(batch_root(height, &[5, 5], &[leaf, leaf], sent(height)), Some(root));
        assert_eq!(batch_root(usize::BITS as usize, &[5], &[leaf], sent(height)), None);
        // A tree of one leaf: its root is the leaf.
        assert_eq!(batch_root(0, &[0], &[leaf], || None), Some(leaf));
        assert_eq!(expand_paths(0, &[0, 0], &[leaf, leaf], || None), Some(vec![vec![], vec![]]));
        // A height beyond the machine's words has no tree, but the walk
        // of it stops where its siblings do.
        assert_eq!(expand_paths(usize::BITS as usize, &[5], &[leaf], || None), None);
    }
}
