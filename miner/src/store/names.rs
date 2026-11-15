//! The names: the trie of [`super::trie`] over the keys of names, which
//! is their Merkle tree.
//!
//! A name's key is 120 bits of its hash ([`crate::name::key_of`]), and
//! its record holds the name, its owner and what the owner keeps under
//! it. The names' tree is not the outputs' kind. A record sits at the
//! first depth at which its key's prefix is its alone, so with `n` names
//! a path is about `log2(n)` hashes long, not the key's 120:
//!
//! - a subtree with no name is the zero digest;
//! - a subtree with one name is that name's leaf, the hash of its key
//!   and its record's value ([`leaf_hash`]);
//! - a subtree with more is `compress` of its two halves.
//!
//! The shape follows from the set of names alone, so every node computes
//! the same root. With no name at all the root is that of the empty
//! subtree the state tree has there ([`empty_root`]).
//!
//! Names are never spent: a record is registered, and then replaced as
//! its owner updates it. Undoing a block puts back the records it
//! replaced and removes those it registered.

use std::io;

use super::backend::Backend;
use super::pagefile::{PageFile, ReadPages, Txn};
use super::sparse::{EMPTY, STATE_HEIGHT, empty};
use super::trie::{self, CHILD_BYTES, Child, Edits, Fault, Part, Slot, Tree};
use crate::error::Error;
use crate::hash::{DOM_NAME_LEAF, Digest, hash_domain};
use crate::name::{KEY_BITS, KEY_LIMBS, Key, Record, key_limbs};
use crate::poseidon2::{DIGEST, Fp, compress};

/// The level of the subtrees the names are handed to another node in:
/// 4,096 parts, by the first twelve bits of a key.
pub const PART_LEVEL: u32 = 108;

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// The root of the names' tree with no names: the empty subtree the
/// state tree has in their half.
pub fn empty_root() -> Digest {
    *empty(STATE_HEIGHT - 1)
}

/// The leaf of the name of `key` whose record's value is `value`
/// ([`Record::leaf_value`]).
pub fn leaf_hash(key: Key, value: &Digest) -> Digest {
    let mut input = [Fp::ZERO; KEY_LIMBS + DIGEST];
    input[..KEY_LIMBS].copy_from_slice(&key_limbs(key));
    input[KEY_LIMBS..].copy_from_slice(value);
    hash_domain(DOM_NAME_LEAF, &input)
}

/// The part of the node at level `top` from its nonempty parts at
/// `level`, by the names' rule.
fn canonical(level: u32, top: u32, parts: &[(u128, Part)]) -> Option<Part> {
    match parts {
        [] => None,
        // One name alone, however far up: its leaf.
        [(_, part)] if part.single || top == level => Some(*part),
        _ => {
            let bit = top - 1 - level;
            let mid = parts.partition_point(|(i, _)| i >> bit & 1 == 0);
            let hash = |half: &[(u128, Part)]| canonical(level, top - 1, half).map_or(EMPTY, |p| p.hash);
            Some(Part { hash: compress(&hash(&parts[..mid]), &hash(&parts[mid..])), single: false })
        }
    }
}

/// The names' tree.
pub struct NameTree;

impl Tree for NameTree {
    const HEIGHT: u32 = KEY_BITS as u32;
    type Key = Key;
    type Record = Record;

    fn record_len(r: &Record) -> usize {
        r.size()
    }

    fn write_record(r: &Record, out: &mut Vec<u8>) {
        let at = out.len();
        out.resize(at + r.size(), 0);
        r.write_bytes(&mut out[at..]);
    }

    fn read_record(b: &[u8]) -> io::Result<(Record, &[u8])> {
        Record::read(b).ok_or_else(|| corrupt("a name's record is not one"))
    }

    fn leaf(key: u128, r: &Record) -> Digest {
        leaf_hash(key, &r.leaf_value())
    }

    /// The names' step: a part with a sibling is compressed with it; one
    /// name alone goes up as it is; more than one with no sibling are
    /// compressed with nothing.
    fn lift(_: u32, parts: &mut [(u128, Part)]) -> usize {
        let (mut r, mut w) = (0, 0);
        while r < parts.len() {
            let (i, part) = parts[r];
            let pair = i & 1 == 0 && parts.get(r + 1).is_some_and(|next| next.0 == i + 1);
            let up = if pair {
                r += 1;
                Part { hash: compress(&part.hash, &parts[r].1.hash), single: false }
            } else if part.single {
                part
            } else if i & 1 == 0 {
                Part { hash: compress(&part.hash, &EMPTY), single: false }
            } else {
                Part { hash: compress(&EMPTY, &part.hash), single: false }
            };
            r += 1;
            parts[w] = (i >> 1, up);
            w += 1;
        }
        w
    }

    fn refuse(_: u128, fault: Fault) -> Error {
        match fault {
            Fault::Present => Error::NameTaken,
            Fault::Absent => Error::NoSuchName,
            _ => corrupt("a change to the names cannot be made").into(),
        }
    }
}

/// The root of the names' tree whose nonempty subtrees at `level` have
/// the parts `parts` (ascending by index): what a node that is given the
/// names in parts checks against the names' root.
pub fn parts_root(level: u32, parts: &[(u32, Part)]) -> Digest {
    let parts: Vec<(u128, Part)> = parts.iter().map(|(i, p)| (*i as u128, *p)).collect();
    canonical(level, NameTree::HEIGHT, &parts).map_or_else(empty_root, |p| p.hash)
}

/// The part of the subtree at `level` whose names are `records`
/// (ascending by key): what a part received is checked against. `None`
/// if there are none.
pub fn part_of(level: u32, records: &[Record]) -> Option<Part> {
    let leaves: Vec<(u128, Part)> =
        records.iter().map(|r| (r.key(), Part { hash: leaf_hash(r.key(), &r.leaf_value()), single: true })).collect();
    canonical(0, level, &leaves)
}

/// What a key's path ends at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// An empty subtree: the key is not registered.
    Empty,
    /// A leaf: the key's own, or another's whose prefix it shares (and
    /// then the key is not registered).
    Leaf { key: Key, value: Digest },
}

/// A key's path: what it ends at, and the sibling at each depth from
/// there up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameProof {
    pub terminal: Terminal,
    /// `siblings[0]` is the terminal's sibling, the last the root's other
    /// child: the terminal's depth is their number.
    pub siblings: Vec<Digest>,
}

/// Whether `key` goes right from depth `depth`: its bit there, the
/// highest first.
pub fn bit(key: Key, depth: usize) -> bool {
    key >> (KEY_BITS - 1 - depth) & 1 == 1
}

impl NameProof {
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// The root the proof implies for `key`'s path.
    pub fn root(&self, key: Key) -> Digest {
        let depth = self.depth();
        let mut node = match self.terminal {
            Terminal::Empty if depth == 0 => return empty_root(),
            Terminal::Empty => EMPTY,
            Terminal::Leaf { key, value } => leaf_hash(key, &value),
        };
        for (i, sibling) in self.siblings.iter().enumerate() {
            node = if bit(key, depth - 1 - i) { compress(sibling, &node) } else { compress(&node, sibling) };
        }
        node
    }

    /// Whether the proof shows `key` holding `value` under `root`.
    pub fn verify_member(&self, root: &Digest, key: Key, value: &Digest) -> bool {
        matches!(self.terminal, Terminal::Leaf { key: k, value: v } if k == key && v == *value)
            && self.depth() <= KEY_BITS
            && self.root(key) == *root
    }

    /// Whether the proof shows `key` not registered under `root`: its
    /// path ends at an empty subtree, or at another key's leaf.
    pub fn verify_absent(&self, root: &Digest, key: Key) -> bool {
        let depth = self.depth();
        let shares = |k: Key| depth == 0 || k >> (KEY_BITS - depth) == key >> (KEY_BITS - depth);
        let ends = match self.terminal {
            Terminal::Empty => true,
            Terminal::Leaf { key: k, .. } => k != key && shares(k),
        };
        ends && depth <= KEY_BITS && self.root(key) == *root
    }
}

/// How a key's way through one node, or one leaf, ends.
enum Way {
    /// At an empty subtree.
    Empty,
    /// At a subtree with one name: in a leaf, the name of this key; in a
    /// node, the one under the part of this index, this many levels
    /// above the node's slots.
    Single(u128, u32),
    /// It goes on below, in the child the key is under.
    On,
}

/// The way of `key` through a node of `height` levels, from its own part
/// down to the child the key is under, which covers `2^span` slots:
/// appends the sibling at each depth passed, top first.
fn way_through(levels: &trie::Levels, height: u32, span: u32, key: u128, siblings: &mut Vec<Digest>) -> Way {
    let low = trie::below(height);
    let mut up = height - low;
    loop {
        let mine = key >> (low + up);
        match levels.find(up, mine) {
            None => return Way::Empty,
            Some(part) if part.single => return Way::Single(mine, up),
            Some(_) if up == span => return Way::On,
            Some(_) => {}
        }
        up -= 1;
        siblings.push(levels.find(up, (key >> (low + up)) ^ 1).map_or(EMPTY, |p| p.hash));
    }
}

/// The way of `key` from the node at `top` down through its parts at
/// `level`: appends the sibling at each depth passed, top first.
fn way(level: u32, top: u32, parts: &[(u128, Part)], key: u128, siblings: &mut Vec<Digest>) -> Way {
    match parts {
        [] => Way::Empty,
        [(i, part)] if part.single => Way::Single(*i, 0),
        _ if top == level => Way::On,
        _ => {
            let bit = top - 1 - level;
            let mid = parts.partition_point(|(i, _)| i >> bit & 1 == 0);
            let (left, right) = parts.split_at(mid);
            let (mine, other) = if key >> (top - 1) & 1 == 0 { (left, right) } else { (right, left) };
            siblings.push(canonical(level, top - 1, other).map_or(EMPTY, |p| p.hash));
            way(level, top - 1, mine, key, siblings)
        }
    }
}

/// The names, as a root record holds them: the root of the trie and how
/// many there are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Names {
    pub root: Child,
    pub count: u64,
}

impl Names {
    /// No name yet.
    pub const EMPTY: Names = Names { root: Child::Empty, count: 0 };
    /// Serialized size.
    pub const BYTES: usize = CHILD_BYTES + 8;

    /// The root of the names' tree.
    pub fn hash(&self) -> Digest {
        self.root.part().map_or_else(empty_root, |p| p.hash)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut v = Vec::with_capacity(Self::BYTES);
        self.root.write(&mut v);
        v.resize(CHILD_BYTES, 0);
        v.extend_from_slice(&self.count.to_le_bytes());
        v.try_into().unwrap()
    }

    pub fn from_bytes(b: &[u8]) -> io::Result<Names> {
        let bad = || corrupt("the names' root is not one");
        if b.len() != Self::BYTES {
            return Err(bad());
        }
        let (root, rest) = Child::read(&b[..CHILD_BYTES])?;
        if rest.iter().any(|x| *x != 0) {
            return Err(bad());
        }
        Ok(Names { root, count: u64::from_le_bytes(b[CHILD_BYTES..].try_into().unwrap()) })
    }

    fn pass<B: Backend>(&self, txn: &mut Txn<'_, B>, edits: Edits<'_, NameTree>) -> Result<Names, Error> {
        let (root, change) = trie::update(txn, self.root, 0, edits)?;
        let count = self.count.checked_add_signed(change).ok_or_else(|| corrupt("the count of names is wrong"))?;
        Ok(Names { root, count })
    }

    /// The names after `puts`, ascending by key: each a record put at its
    /// key, with `true` in place of the one registered there
    /// ([`Error::NoSuchName`] if there is none), with `false` as a new
    /// registration ([`Error::NameTaken`] if the key is taken).
    pub fn apply<B: Backend>(&self, txn: &mut Txn<'_, B>, puts: &[(Key, Record, bool)]) -> Result<Names, Error> {
        debug_assert!(puts.windows(2).all(|w| w[0].0 < w[1].0), "keys ascend");
        debug_assert!(puts.iter().all(|p| p.0 == p.1.key()), "a record is put at its name's key");
        self.pass(txn, Edits { puts, ..Edits::none() })
    }

    /// [`Names::apply`], which also returns the part of every subtree at
    /// `level` the puts change, as it was before them (`None` where there
    /// was no name).
    #[allow(clippy::type_complexity)]
    pub fn apply_keeping<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        puts: &[(Key, Record, bool)],
        level: u32,
    ) -> Result<(Names, Vec<(u32, Option<Part>)>), Error> {
        debug_assert!(puts.windows(2).all(|w| w[0].0 < w[1].0), "keys ascend");
        let edits: Edits<'_, NameTree> = Edits { puts, ..Edits::none() };
        let (root, change, before, _) = trie::update_keeping(txn, self.root, 0, edits, level)?;
        let count = self.count.checked_add_signed(change).ok_or_else(|| corrupt("the count of names is wrong"))?;
        Ok((Names { root, count }, before.into_iter().map(|(i, part)| (i as u32, part)).collect()))
    }

    /// The part of every nonempty subtree at `level`, ascending by index.
    pub fn parts(&self, pages: &impl ReadPages, level: u32) -> io::Result<Vec<(u32, Part)>> {
        let mut out = Vec::new();
        trie::parts_at::<NameTree>(pages, self.root, level, &mut |index, part| out.push((index as u32, part)))?;
        Ok(out)
    }

    /// Every name's record in the subtree of index `index` at `level`,
    /// in key order.
    pub fn part(&self, pages: &impl ReadPages, level: u32, index: u32) -> io::Result<Vec<Record>> {
        let mut out = Vec::new();
        trie::for_each_in::<NameTree>(pages, self.root, level, index as u128, &mut |_, record, _| out.push(*record))?;
        Ok(out)
    }

    /// The names before a block: the records it replaced are put back
    /// (`restore`, ascending) and those it registered are removed
    /// (`remove`, ascending).
    pub fn undo<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        restore: &[(Key, Record, bool)],
        remove: &[Key],
    ) -> Result<Names, Error> {
        debug_assert!(restore.iter().all(|p| p.2), "what is put back replaces");
        self.pass(txn, Edits { puts: restore, removes: remove, ..Edits::none() })
    }

    /// The names with those at `removes` taken out and `puts` put in
    /// (both ascending, each put where no name is left): how a part of
    /// a state being received is put in place of an older one.
    pub fn exchange<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        removes: &[Key],
        puts: &[(Key, Record, bool)],
    ) -> Result<Names, Error> {
        debug_assert!(puts.windows(2).all(|w| w[0].0 < w[1].0) && puts.iter().all(|p| !p.2 && p.0 == p.1.key()));
        self.pass(txn, Edits { removes, puts, ..Edits::none() })
    }

    /// Frees every page of the names.
    pub fn free<B: Backend>(&self, txn: &Txn<'_, B>) -> io::Result<()> {
        trie::free::<NameTree, B>(txn, self.root)
    }

    /// The record registered at `key`, if any.
    pub fn get(&self, pages: &impl ReadPages, key: Key) -> io::Result<Option<Record>> {
        Ok(trie::get::<NameTree>(pages, self.root, key)?.map(|(record, _)| record))
    }

    /// The path of `key`: to its own leaf if it is registered, else to
    /// what shows it is not.
    pub fn prove(&self, pages: &impl ReadPages, key: Key) -> io::Result<NameProof> {
        let leaf_of = |s: &Slot<Record>| Terminal::Leaf { key: s.key, value: s.record.leaf_value() };
        let mut siblings = Vec::new();
        let (mut child, mut height, mut base) = (self.root, NameTree::HEIGHT, 0u128);
        let terminal = loop {
            match child {
                Child::Empty => break Terminal::Empty,
                Child::Leaf { .. } => {
                    let slots = trie::load_leaf::<NameTree>(pages, child, height, base)?;
                    let parts: Vec<(u128, Part)> = slots
                        .iter()
                        .map(|s| (s.key, Part { hash: NameTree::leaf(s.key, &s.record), single: true }))
                        .collect();
                    break match way(0, height, &parts, key, &mut siblings) {
                        Way::Empty => Terminal::Empty,
                        Way::Single(k, _) => slots.iter().find(|s| s.key == k).map_or(Terminal::Empty, leaf_of),
                        Way::On => slots.iter().find(|s| s.key == key).map_or(Terminal::Empty, leaf_of),
                    };
                }
                Child::Node { page, .. } => {
                    let children = trie::load_node(pages, page, height)?;
                    let low = trie::below(height);
                    let levels = trie::levels::<NameTree>(&children, height, base);
                    let (slot, span) = trie::group_of(&children, height, ((key - base) >> low) as usize);
                    match way_through(&levels, height, span, key, &mut siblings) {
                        Way::Empty => break Terminal::Empty,
                        // The one name of a subtree lies somewhere under
                        // it, past no more siblings: under the one child
                        // there that is not empty.
                        Way::Single(index, up) => {
                            let first = ((index << (low + up)) - base) >> low;
                            let k = (first as usize..first as usize + (1 << up))
                                .find(|k| children[*k] != Child::Empty)
                                .ok_or_else(|| corrupt("a subtree said to hold one name holds none"))?;
                            let under = low + trie::span_of(children[k]);
                            break Self::only(pages, children[k], under, base + ((k as u128) << low))?;
                        }
                        Way::On => {}
                    }
                    (child, height, base) = (children[slot], low + span, base + ((slot as u128) << low));
                }
            }
        };
        siblings.reverse();
        Ok(NameProof { terminal, siblings })
    }

    /// The leaf of the one name under `child`.
    fn only(pages: &impl ReadPages, mut child: Child, mut height: u32, mut base: u128) -> io::Result<Terminal> {
        loop {
            match child {
                Child::Empty => return Err(corrupt("a subtree said to hold one name holds none")),
                Child::Leaf { .. } => {
                    let slots = trie::load_leaf::<NameTree>(pages, child, height, base)?;
                    let s = slots.first().ok_or_else(|| corrupt("a leaf holds no record"))?;
                    return Ok(Terminal::Leaf { key: s.key, value: s.record.leaf_value() });
                }
                Child::Node { page, .. } => {
                    let children = trie::load_node(pages, page, height)?;
                    let k = children.iter().position(|c| *c != Child::Empty).unwrap_or(0);
                    let low = trie::below(height);
                    (child, base, height) =
                        (children[k], base + ((k as u128) << low), low + trie::span_of(children[k]));
                }
            }
        }
    }

    /// Marks every page of the names in `file`'s map of free space.
    pub fn mark<B: Backend>(&self, file: &PageFile<B>) -> io::Result<()> {
        trie::mark::<NameTree, B>(file, self.root)
    }

    /// Calls `f` with every name's key and record, in key order.
    pub fn for_each(&self, pages: &impl ReadPages, f: &mut dyn FnMut(Key, &Record)) -> io::Result<()> {
        trie::for_each::<NameTree>(pages, self.root, &mut |key, record, _| f(key, record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::{Lost, MemBackend};
    use crate::test_util::Rng;
    use std::collections::BTreeMap;

    fn record(rng: &mut Rng) -> Record {
        let len = 1 + rng.next_u64() as usize % crate::name::NAME_MAX;
        let name: Vec<u8> = (0..len).map(|_| crate::name::CHARSET[rng.next_u64() as usize % 37]).collect();
        let d = |rng: &mut Rng| -> Digest { core::array::from_fn(|_| rng.fp()) };
        Record::new(&name, d(rng), d(rng), d(rng)).unwrap()
    }

    /// The root by the definition: nothing is zero, one name is its leaf,
    /// more are the compression of the two halves.
    fn define(leaves: &[(Key, Digest)], depth: usize) -> Digest {
        match leaves {
            [] => EMPTY,
            [(_, leaf)] => *leaf,
            _ => {
                let mid = leaves.partition_point(|(k, _)| !bit(*k, depth));
                compress(&define(&leaves[..mid], depth + 1), &define(&leaves[mid..], depth + 1))
            }
        }
    }

    struct World {
        file: PageFile<MemBackend>,
        names: Names,
        /// Keys are whatever a test puts records under: not always their
        /// names' own, so that keys can be made to share prefixes.
        model: BTreeMap<Key, Record>,
    }

    impl World {
        fn new() -> World {
            World { file: PageFile::create(MemBackend::new()).unwrap(), names: Names::EMPTY, model: BTreeMap::new() }
        }

        fn root(&self) -> Digest {
            if self.model.is_empty() {
                return empty_root();
            }
            let leaves: Vec<(Key, Digest)> =
                self.model.iter().map(|(k, r)| (*k, leaf_hash(*k, &r.leaf_value()))).collect();
            define(&leaves, 0)
        }

        /// Puts `puts` (sorted here) in one transaction.
        fn put(&mut self, mut puts: Vec<(Key, Record, bool)>) -> Result<(), Error> {
            puts.sort_by_key(|p| p.0);
            let mut txn = self.file.begin()?;
            let names = self.names.pass(&mut txn, Edits { puts: &puts, ..Edits::none() })?;
            txn.commit(&names.to_bytes())?;
            self.names = names;
            self.model.extend(puts.iter().map(|p| (p.0, p.1)));
            Ok(())
        }

        fn check(&self, rng: &mut Rng) {
            let root = self.root();
            assert_eq!(self.names.hash(), root);
            assert_eq!(self.names.count as usize, self.model.len());
            let mut seen = Vec::new();
            self.names.for_each(&self.file, &mut |k, r| seen.push((k, *r))).unwrap();
            assert!(seen.iter().copied().eq(self.model.iter().map(|(k, r)| (*k, *r))));
            // Every name's path leads to the root, and shows it there.
            for (k, r) in self.model.iter().step_by(1 + self.model.len() / 40) {
                assert_eq!(self.names.get(&self.file, *k).unwrap(), Some(*r));
                let proof = self.names.prove(&self.file, *k).unwrap();
                assert!(proof.verify_member(&root, *k, &r.leaf_value()), "key {k:030x}");
                assert!(!proof.verify_absent(&root, *k));
                let mut other = r.leaf_value();
                other[0] += Fp::ONE;
                assert!(!proof.verify_member(&root, *k, &other));
            }
            // Keys not registered: any, and neighbours of registered ones.
            let near: Vec<Key> = self.model.keys().take(8).flat_map(|k| [k ^ 1, k ^ 1 << 60, k ^ 1 << 119]).collect();
            for k in (0..20).map(|_| (rng.next_u64() as u128) << 64 | rng.next_u64() as u128).chain(near) {
                let k = k & ((1 << KEY_BITS) - 1);
                if self.model.contains_key(&k) {
                    continue;
                }
                assert_eq!(self.names.get(&self.file, k).unwrap(), None);
                let proof = self.names.prove(&self.file, k).unwrap();
                assert!(proof.verify_absent(&root, k), "key {k:030x}: {proof:?}");
                assert!(!matches!(proof.terminal, Terminal::Leaf { key, .. } if key == k));
            }
        }

        fn reopen(&mut self) {
            let file = PageFile::open(MemBackend::from_image(self.file.backend().image(Lost::All))).unwrap();
            let names =
                if file.root().seq == 0 { Names::EMPTY } else { Names::from_bytes(file.root().payload()).unwrap() };
            assert_eq!(names, self.names);
            names.mark(&file).unwrap();
            file.seal();
            assert_eq!(file.space().0, self.file.space().0);
            self.file = file;
        }
    }

    #[test]
    fn no_name_one_name_two_names() {
        let mut w = World::new();
        let mut rng = Rng::new(0x4a3e);
        assert_eq!(w.names.hash(), empty_root());
        w.check(&mut rng);
        assert_eq!(Names::from_bytes(&Names::EMPTY.to_bytes()).unwrap(), Names::EMPTY);
        // One name: the root is its leaf, and its path has no sibling.
        let a = record(&mut rng);
        w.put(vec![(a.key(), a, false)]).unwrap();
        assert_eq!(w.names.hash(), leaf_hash(a.key(), &a.leaf_value()));
        assert_eq!(w.names.prove(&w.file, a.key()).unwrap().depth(), 0);
        w.check(&mut rng);
        // Two: they part at their first differing bit.
        let b = record(&mut rng);
        w.put(vec![(b.key(), b, false)]).unwrap();
        let parts_at = (a.key() ^ b.key()).leading_zeros() as usize - (128 - KEY_BITS);
        assert_eq!(w.names.prove(&w.file, a.key()).unwrap().depth(), parts_at + 1);
        w.check(&mut rng);
        w.reopen();
    }

    /// Names by the hundred, registered a few at a time and updated: the
    /// root is the definition's throughout, and every path leads to it.
    #[test]
    fn names_against_the_definition() {
        let mut w = World::new();
        let mut rng = Rng::new(0x4a3e5);
        for round in 0..12 {
            let mut puts = Vec::new();
            for _ in 0..[1, 3, 70, 200][round % 4] {
                let r = record(&mut rng);
                if !w.model.contains_key(&r.key()) && !puts.iter().any(|p: &(Key, Record, bool)| p.0 == r.key()) {
                    puts.push((r.key(), r, false));
                }
            }
            // Some of the names there are given new records.
            for k in w.model.keys().step_by(7).copied().collect::<Vec<_>>() {
                let r = Record { name: w.model[&k].name, ..record(&mut rng) };
                puts.push((k, r, true));
            }
            w.put(puts).unwrap();
            w.check(&mut rng);
            if round % 3 == 2 {
                w.reopen();
            }
        }
        assert!(w.model.len() > 700);
        // With hundreds of names a path is some ten hashes long, not 120.
        let depths: Vec<usize> = w.model.keys().take(50).map(|k| w.names.prove(&w.file, *k).unwrap().depth()).collect();
        assert!(depths.iter().all(|d| (6..40).contains(d)), "{depths:?}");
    }

    /// Keys that share long prefixes, down to all but the last bit: the
    /// tree goes as deep as they part, with empty halves on the way.
    #[test]
    fn keys_that_share_prefixes() {
        let mut w = World::new();
        let mut rng = Rng::new(0x9ef1);
        let top: Key = 0x5a5a5a << 96;
        let mut puts = Vec::new();
        // Pairs that part at bit 119, 118, 100, 64, 37 and 1 from the
        // top, a run of neighbours, and both ends of the key space.
        for (i, low) in [1u128, 2, 3, 1 << 19, 1 << 55, 1 << 82, 1 << 118].into_iter().enumerate() {
            puts.push((top + ((i as u128) << 90) + low, record(&mut rng), false));
            puts.push((top + ((i as u128) << 90), record(&mut rng), false));
        }
        puts.extend((0..90u128).map(|i| (7 << 100 | i, record(&mut rng), false)));
        puts.push((0, record(&mut rng), false));
        puts.push(((1 << KEY_BITS) - 1, record(&mut rng), false));
        puts.sort_by_key(|p| p.0);
        puts.dedup_by_key(|p| p.0);
        // Registered in three goes, so that leaves split where keys are dense.
        for part in puts.chunks(40) {
            w.put(part.to_vec()).unwrap();
            w.check(&mut rng);
        }
        w.reopen();
        // Two keys that differ in the last bit only: a path of 120.
        let (a, b) = (top + (2u128 << 90), top + (2u128 << 90) + 1);
        assert!(w.model.contains_key(&a) || w.model.contains_key(&b));
        let deepest = w.model.keys().map(|k| w.names.prove(&w.file, *k).unwrap().depth()).max().unwrap();
        assert_eq!(deepest, KEY_BITS);
    }

    /// A key taken cannot be registered, a key not registered cannot be
    /// updated, and a refused transaction leaves the names as they were;
    /// undoing a block puts back what it replaced and removes what it
    /// registered.
    #[test]
    fn refusals_and_undo() {
        let mut w = World::new();
        let mut rng = Rng::new(0x0d0);
        let first: Vec<(Key, Record, bool)> = (0..150).map(|_| record(&mut rng)).map(|r| (r.key(), r, false)).collect();
        w.put(first.clone()).unwrap();
        let (root, used) = (w.names.hash(), w.file.space().0);
        let taken = first[20];
        let fresh = record(&mut rng);
        let refused = |puts: Vec<(Key, Record, bool)>, want: Error| {
            let mut sorted = puts;
            sorted.sort_by_key(|p| p.0);
            let mut txn = w.file.begin().unwrap();
            assert_eq!(w.names.pass(&mut txn, Edits { puts: &sorted, ..Edits::none() }).err(), Some(want));
            drop(txn);
            assert_eq!((w.names.hash(), w.file.space().0), (root, used));
        };
        refused(vec![(taken.0, record(&mut rng), false)], Error::NameTaken);
        refused(vec![(fresh.key(), fresh, true)], Error::NoSuchName);
        refused(vec![(fresh.key(), fresh, false), (taken.0, taken.1, false)], Error::NameTaken);

        // A block that registers 30 and replaces 30, then undone.
        let before = w.model.clone();
        let registered: Vec<(Key, Record, bool)> =
            (0..30).map(|_| record(&mut rng)).map(|r| (r.key(), r, false)).collect();
        let replaced: Vec<(Key, Record, bool)> = first.iter().step_by(5).map(|p| (p.0, p.1, true)).collect();
        let mut block = registered.clone();
        block.extend(replaced.iter().map(|p| (p.0, Record { name: p.1.name, ..record(&mut rng) }, true)));
        w.put(block).unwrap();
        w.check(&mut rng);
        assert_ne!(w.names.hash(), root);
        let mut restore = replaced.clone();
        restore.sort_by_key(|p| p.0);
        let mut remove: Vec<Key> = registered.iter().map(|p| p.0).collect();
        remove.sort_unstable();
        let mut txn = w.file.begin().unwrap();
        w.names = w.names.undo(&mut txn, &restore, &remove).unwrap();
        txn.commit(&w.names.to_bytes()).unwrap();
        w.model = before;
        assert_eq!((w.names.hash(), w.names.count), (root, 150));
        w.check(&mut rng);
        w.reopen();
        // Everything removed: no page is left.
        let all: Vec<Key> = w.model.keys().copied().collect();
        let mut txn = w.file.begin().unwrap();
        w.names = w.names.undo(&mut txn, &[], &all).unwrap();
        txn.commit(&w.names.to_bytes()).unwrap();
        assert_eq!(w.names, Names::EMPTY);
        assert_eq!(w.file.space().0, crate::store::pagefile::HEADER_UNITS);
    }
}
