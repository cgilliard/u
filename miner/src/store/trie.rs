//! A trie over keys that is also a Merkle tree of what it holds: the
//! shape the state's two halves share.
//!
//! The outputs and the names are different trees. Their keys are of
//! different lengths, their records of different sizes, and their hashes
//! follow different rules; a new output always takes the next key, a new
//! name falls anywhere. What they share is here, written once over a
//! description of the tree ([`Tree`]): how the records lie in pages, how
//! a block's changes are made in one pass, and how the hashes follow.
//!
//! # Shape
//!
//! A node covers the keys with one prefix and has [`FANOUT`] children,
//! each covering those with [`BITS`] more bits fixed. A child is empty,
//! another node, or a leaf: a page of the records under it, when they fit
//! one. Beside each child the node keeps the child's part in the Merkle
//! tree, so a node's own part follows from its page alone, and a key's
//! path from the pages on the way down to it.
//!
//! ```text
//! node page := height (1) | children (1) | child ...
//! child     := slot (1) | kind (1) | hash (32) | page (6) | leaf's
//! leaf's    := records (1) | live (8) | last spend (4)
//! leaf page := records (1) | record ...
//! record    := distance from the key before (varint) | the tree's record
//! ```
//!
//! # A record can be dead
//!
//! Which records of a leaf count in the tree is a bit each in the node
//! above (`live`). A tree that spends its records (the outputs) clears
//! the bit and changes the hashes above: the nodes on the way are written
//! anew, as they must be, and the page of records is left as it is. A
//! dead record is still there to be had, and comes back with its bit.
//! Beside a leaf the node keeps `last spend`, the height of the latest
//! bit cleared in it, so that a sweep ([`sweep`]) can tell without
//! reading the page when everything dead in it is old enough to drop.
//!
//! # Changes
//!
//! Changes are made in one pass in key order ([`update`]): each page on
//! the way is read once, and written once when the pass leaves it.
//! Nothing is changed in place; the pages replaced are named to the
//! transaction, and the new root is returned to be committed with it.

use std::io;

use super::backend::Backend;
use super::pagefile::{Extent, PageFile, ReadPages, Txn};
use crate::error::Error;
use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes, digest_to_bytes};

/// Bits of a key a node fixes.
pub const BITS: u32 = 4;
/// Children of a node.
pub const FANOUT: usize = 1 << BITS;
/// The most records a leaf holds: a bit each in its `live`.
pub const LEAF_RECORDS: usize = 64;
/// The most bytes of a leaf page's payload: eight units.
const LEAF_BYTES: usize = Extent::capacity(8);
const PAGE: usize = 4096;

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// A subtree's place in the Merkle tree: its hash, and whether it holds
/// exactly one record (which some trees hash differently).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Part {
    pub hash: Digest,
    pub single: bool,
}

/// Why a change cannot be made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// The record to mark dead is not there, or is dead already.
    NotLive,
    /// The record to bring back is not there, or is not dead.
    NotDead,
    /// A record to insert has a key already taken.
    Present,
    /// A record to replace or remove is not there.
    Absent,
    /// A record of a run does not come after every record before it.
    Order,
}

/// A tree the trie can hold: its keys, its records, and how it hashes.
pub trait Tree {
    /// Bits of a key: the height of the tree.
    const HEIGHT: u32;
    /// A key as the tree's users give it.
    type Key: Copy + Into<u128>;
    type Record: Copy + PartialEq + core::fmt::Debug;

    /// Bytes [`Tree::write_record`] appends for `r`.
    fn record_len(r: &Self::Record) -> usize;
    fn write_record(r: &Self::Record, out: &mut Vec<u8>);
    /// Reads a record from the front of `b`, and returns the rest.
    fn read_record(b: &[u8]) -> io::Result<(Self::Record, &[u8])>;

    /// The hash of a live record at the bottom of the tree.
    fn leaf(key: u128, r: &Self::Record) -> Digest;
    /// The hashes of the live records of `slots`, in order, into `out`;
    /// returns how many. A tree that can hash several at once does.
    fn leaves(slots: &[Slot<Self::Record>], out: &mut [(u128, Part); LEAF_RECORDS]) -> usize {
        let mut n = 0;
        for s in slots.iter().filter(|s| s.live) {
            out[n] = (s.key, Part { hash: Self::leaf(s.key, &s.record), single: true });
            n += 1;
        }
        n
    }
    /// The part of the node at level `top`, from its nonempty parts at
    /// `level` (a record is level 0): `(index, part)`, ascending, where
    /// the part of index `i` covers the keys from `i << level`. `None`
    /// if there are none. The slice is scratch.
    fn combine(level: u32, top: u32, parts: &mut [(u128, Part)]) -> Option<Part>;
    /// What a change that cannot be made is refused with.
    fn refuse(key: u128, fault: Fault) -> Error;
}

/// A child of a node, or the root: a subtree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Child {
    /// No record under it, live or dead.
    Empty,
    /// A node's page. `part` is `None` if nothing under it is live.
    Node { page: Extent, part: Option<Part> },
    /// A page of records.
    Leaf {
        page: Extent,
        part: Option<Part>,
        /// Records in the page.
        records: u8,
        /// Which of them are live, the first the lowest bit.
        live: u64,
        /// The height of the latest of them to die, 0 if none.
        last_spend: u32,
    },
}

/// Bytes of a child's encoding, less its slot: the longest, a leaf's.
pub const CHILD_BYTES: usize = 1 + 32 + 6 + 13;
const KIND: u8 = 0x0f;
const SINGLE: u8 = 0x80;
const VOID: u8 = 0x40;

fn put_extent(out: &mut Vec<u8>, e: Extent) {
    debug_assert!(e.start < 1 << 40 && e.units < 256);
    out.extend_from_slice(&e.start.to_le_bytes()[..5]);
    out.push(e.units as u8);
}

fn get_extent(b: &[u8]) -> Extent {
    let mut start = [0u8; 8];
    start[..5].copy_from_slice(&b[..5]);
    Extent { start: u64::from_le_bytes(start), units: b[5] as u32 }
}

impl Child {
    /// The subtree's part in the tree: `None` if nothing in it is live.
    pub fn part(&self) -> Option<Part> {
        match self {
            Child::Empty => None,
            Child::Node { part, .. } | Child::Leaf { part, .. } => *part,
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        let (kind, page, part) = match self {
            Child::Empty => return out.push(0),
            Child::Node { page, part } => (1, page, part),
            Child::Leaf { page, part, .. } => (2, page, part),
        };
        let flags = match part {
            None => VOID,
            Some(p) if p.single => SINGLE,
            Some(_) => 0,
        };
        out.push(kind | flags);
        out.extend_from_slice(&digest_to_bytes(&part.map_or([Fp::ZERO; DIGEST], |p| p.hash)));
        put_extent(out, *page);
        if let Child::Leaf { records, live, last_spend, .. } = self {
            out.push(*records);
            out.extend_from_slice(&live.to_le_bytes());
            out.extend_from_slice(&last_spend.to_le_bytes());
        }
    }

    /// Reads a child from the front of `b`, and returns the rest.
    pub fn read(b: &[u8]) -> io::Result<(Child, &[u8])> {
        let bad = || corrupt("a node's child is not one");
        let (&tag, b) = b.split_first().ok_or_else(bad)?;
        if tag == 0 {
            return Ok((Child::Empty, b));
        }
        let (kind, flags) = (tag & KIND, tag & !KIND);
        let (head, b) = b.split_at_checked(38).ok_or_else(bad)?;
        let hash = digest_from_bytes(&head[..32]).ok_or_else(bad)?;
        let part = match flags {
            VOID if hash == [Fp::ZERO; DIGEST] => None,
            SINGLE => Some(Part { hash, single: true }),
            0 => Some(Part { hash, single: false }),
            _ => return Err(bad()),
        };
        let page = get_extent(&head[32..]);
        if page.units == 0 {
            return Err(bad());
        }
        match kind {
            1 => Ok((Child::Node { page, part }, b)),
            2 => {
                let (tail, b) = b.split_at_checked(13).ok_or_else(bad)?;
                let records = tail[0];
                let live = u64::from_le_bytes(tail[1..9].try_into().unwrap());
                if records == 0 || records as usize > LEAF_RECORDS || (records < 64 && live >> records != 0) {
                    return Err(bad());
                }
                // A leaf with nothing live has no part, and one with has.
                if (live == 0) != part.is_none() {
                    return Err(bad());
                }
                let last_spend = u32::from_le_bytes(tail[9..].try_into().unwrap());
                Ok((Child::Leaf { page, part, records, live, last_spend }, b))
            }
            _ => Err(bad()),
        }
    }
}

/// A node's children, read from its page.
pub fn read_node(payload: &[u8], height: u32) -> io::Result<[Child; FANOUT]> {
    let bad = || corrupt("a node's page is not one");
    let (head, mut b) = payload.split_at_checked(2).ok_or_else(bad)?;
    if head[0] as u32 != height {
        return Err(bad());
    }
    let mut children = [Child::Empty; FANOUT];
    let mut last = None;
    for _ in 0..head[1] {
        let (&slot, rest) = b.split_first().ok_or_else(bad)?;
        // Slots ascend, and none is given as empty.
        if slot as usize >= FANOUT || last.is_some_and(|l| slot <= l) {
            return Err(bad());
        }
        let (child, rest) = Child::read(rest)?;
        if child == Child::Empty {
            return Err(bad());
        }
        children[slot as usize] = child;
        (last, b) = (Some(slot), rest);
    }
    if !b.is_empty() || last.is_none() {
        return Err(bad());
    }
    Ok(children)
}

pub fn write_node(children: &[Child; FANOUT], height: u32, out: &mut Vec<u8>) {
    out.clear();
    out.push(height as u8);
    out.push(children.iter().filter(|c| **c != Child::Empty).count() as u8);
    for (slot, c) in children.iter().enumerate() {
        if *c != Child::Empty {
            out.push(slot as u8);
            c.write(out);
        }
    }
}

/// The height of a node's children: [`BITS`] below it, or what is left
/// of the key.
const fn below(height: u32) -> u32 {
    height.saturating_sub(BITS)
}

/// The parts of a node's children, as [`Tree::combine`] takes them.
pub fn child_parts(children: &[Child; FANOUT], height: u32, base: u128, out: &mut [(u128, Part); FANOUT]) -> usize {
    let low = below(height);
    let mut n = 0;
    for (k, c) in children.iter().enumerate() {
        if let Some(part) = c.part() {
            out[n] = ((base >> low) + k as u128, part);
            n += 1;
        }
    }
    n
}

fn node_part<T: Tree>(children: &[Child; FANOUT], height: u32, base: u128) -> Option<Part> {
    let mut parts = [(0u128, Part { hash: [Fp::ZERO; DIGEST], single: false }); FANOUT];
    let n = child_parts(children, height, base, &mut parts);
    T::combine(below(height), height, &mut parts[..n])
}

/// A record of a leaf, with its key and whether it is live.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Slot<R> {
    pub key: u128,
    pub record: R,
    pub live: bool,
}

fn put_varint(out: &mut Vec<u8>, mut x: u128) {
    while x >= 0x80 {
        out.push(x as u8 | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

fn varint_len(x: u128) -> usize {
    ((128 - x.leading_zeros()).div_ceil(7).max(1)) as usize
}

fn get_varint(b: &[u8]) -> Option<(u128, &[u8])> {
    let (mut x, mut shift) = (0u128, 0);
    for (i, &byte) in b.iter().enumerate().take(19) {
        // The nineteenth byte holds the last two bits of 128.
        if shift == 126 && byte > 3 {
            return None;
        }
        x |= u128::from(byte & 0x7f) << shift;
        shift += 7;
        if byte < 0x80 {
            return Some((x, &b[i + 1..]));
        }
    }
    None
}

/// A leaf page's records, appended to `out`: those of the leaf whose
/// subtree of `height` levels starts at `base`.
pub fn read_leaf<T: Tree>(
    payload: &[u8],
    base: u128,
    height: u32,
    records: u8,
    live: u64,
    out: &mut Vec<Slot<T::Record>>,
) -> io::Result<()> {
    let bad = || corrupt("a leaf's page is not one");
    let (&count, mut b) = payload.split_first().ok_or_else(bad)?;
    if count != records {
        return Err(bad());
    }
    let end = base + (1u128 << height);
    let mut key = base;
    for i in 0..count as usize {
        let (delta, rest) = get_varint(b).ok_or_else(bad)?;
        // Keys ascend, and stay under the leaf.
        if i > 0 && delta == 0 {
            return Err(bad());
        }
        key = key.checked_add(delta).filter(|k| *k < end).ok_or_else(bad)?;
        let (record, rest) = T::read_record(rest)?;
        out.push(Slot { key, record, live: live >> i & 1 == 1 });
        b = rest;
    }
    if !b.is_empty() {
        return Err(bad());
    }
    Ok(())
}

pub fn write_leaf<T: Tree>(slots: &[Slot<T::Record>], base: u128, out: &mut Vec<u8>) {
    out.clear();
    out.push(slots.len() as u8);
    let mut prev = base;
    for s in slots {
        put_varint(out, s.key - prev);
        T::write_record(&s.record, out);
        prev = s.key;
    }
}

/// Whether `slots`, under one subtree starting at `base`, fit a leaf.
fn fits<T: Tree>(slots: &[Slot<T::Record>], base: u128) -> bool {
    if slots.len() > LEAF_RECORDS {
        return false;
    }
    let mut bytes = 1;
    let mut prev = base;
    for s in slots {
        bytes += varint_len(s.key - prev) + T::record_len(&s.record);
        prev = s.key;
    }
    bytes <= LEAF_BYTES
}

/// The part of a subtree of `height` levels, from its live records.
pub fn leaf_part<T: Tree>(slots: &[Slot<T::Record>], height: u32) -> Option<Part> {
    let mut parts = [(0u128, Part { hash: [Fp::ZERO; DIGEST], single: true }); LEAF_RECORDS];
    let n = T::leaves(slots, &mut parts);
    T::combine(0, height, &mut parts[..n])
}

fn live_bits<R>(slots: &[Slot<R>]) -> u64 {
    slots.iter().enumerate().fold(0, |bits, (i, s)| bits | (s.live as u64) << i)
}

/// What one pass changes. Every part of it is in key order, and is cut
/// down to a subtree's keys as the pass descends, at no cost.
pub struct Edits<'a, T: Tree> {
    /// Keys whose records die, or (`revive`) come back.
    pub flips: &'a [T::Key],
    pub revive: bool,
    /// New records at the keys from `run_from` on, one after another:
    /// they come after every record there is.
    pub run: &'a [T::Record],
    pub run_from: u128,
    /// Records put at their keys: with `true` in place of the record
    /// there, which there must be; with `false` where there must be none.
    pub puts: &'a [(T::Key, T::Record, bool)],
    /// Keys whose records are removed.
    pub removes: &'a [T::Key],
    /// Every record at this key or after is removed.
    pub truncate: u128,
}

impl<T: Tree> Clone for Edits<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Tree> Copy for Edits<'_, T> {}

impl<'a, T: Tree> Edits<'a, T> {
    /// No change.
    pub fn none() -> Edits<'a, T> {
        Edits { flips: &[], revive: false, run: &[], run_from: 0, puts: &[], removes: &[], truncate: u128::MAX }
    }

    /// The part that falls in `base..base + 2^height`.
    fn within(&self, base: u128, height: u32) -> Edits<'a, T> {
        let end = base + (1u128 << height);
        let cut = |keys: &'a [T::Key]| -> &'a [T::Key] {
            let from = keys.partition_point(|k| (*k).into() < base);
            let to = keys.partition_point(|k| (*k).into() < end);
            &keys[from..to]
        };
        let run_end = self.run_from + self.run.len() as u128;
        let lo = self.run_from.max(base).min(run_end);
        let hi = run_end.min(end).max(lo);
        let from = self.puts.partition_point(|p| p.0.into() < base);
        let to = self.puts.partition_point(|p| p.0.into() < end);
        Edits {
            flips: cut(self.flips),
            revive: self.revive,
            run: &self.run[(lo - self.run_from) as usize..(hi - self.run_from) as usize],
            run_from: lo,
            puts: &self.puts[from..to],
            removes: cut(self.removes),
            truncate: self.truncate,
        }
    }

    /// Whether nothing of it falls in `base..base + 2^height`: `self` is
    /// already cut down to that.
    fn is_empty(&self, base: u128, height: u32) -> bool {
        self.flips.is_empty()
            && self.run.is_empty()
            && self.puts.is_empty()
            && self.removes.is_empty()
            && self.truncate >= base + (1u128 << height)
    }
}

/// A sweep under way.
struct Sweep {
    /// The key it has reached.
    from: u128,
    /// Leaves it may still look at.
    budget: usize,
    /// A leaf whose last spend is below this height has nothing dead
    /// that could still be wanted back.
    horizon: u32,
}

/// One pass over the trie, inside a transaction.
struct Pass<'t, 'f, T: Tree, B: Backend> {
    txn: &'t mut Txn<'f, B>,
    /// The height of the block the pass applies, or of the tip a pass
    /// that undoes one leaves.
    height: u32,
    /// The change in the number of live records.
    count: i64,
    slots: Vec<Slot<T::Record>>,
    out: Vec<u8>,
}

impl<T: Tree, B: Backend> Pass<'_, '_, T, B> {
    /// The subtree `child` (of `height` levels from `base`) after `edits`.
    fn update(&mut self, child: Child, height: u32, base: u128, edits: Edits<'_, T>) -> Result<Child, Error> {
        if edits.is_empty(base, height) {
            return Ok(child);
        }
        let Child::Node { page, .. } = child else { return self.update_leaf(child, height, base, edits) };
        let mut buf = [0u8; PAGE];
        let mut children = read_node(self.txn.read(page, &mut buf)?, height)?;
        let low = below(height);
        for (k, c) in children.iter_mut().enumerate().take(1 << (height - low)) {
            let at = base + ((k as u128) << low);
            *c = self.update(*c, low, at, edits.within(at, low))?;
        }
        self.txn.free(page);
        if children.iter().all(|c| *c == Child::Empty) {
            return Ok(Child::Empty);
        }
        self.write_node(&children, height, base)
    }

    fn write_node(&mut self, children: &[Child; FANOUT], height: u32, base: u128) -> Result<Child, Error> {
        write_node(children, height, &mut self.out);
        let page = self.txn.write(&self.out)?;
        Ok(Child::Node { page, part: node_part::<T>(children, height, base) })
    }

    /// A leaf, or an empty subtree, after `edits`.
    fn update_leaf(&mut self, child: Child, height: u32, base: u128, edits: Edits<'_, T>) -> Result<Child, Error> {
        let mut slots = std::mem::take(&mut self.slots);
        slots.clear();
        let mut old = None;
        if let Child::Leaf { page, records, live, last_spend, .. } = child {
            let mut buf = [0u8; PAGE];
            read_leaf::<T>(self.txn.read(page, &mut buf)?, base, height, records, live, &mut slots)?;
            old = Some((page, last_spend));
        }
        let done = self.edit(&mut slots, old, height, base, edits);
        self.slots = slots;
        done
    }

    fn edit(
        &mut self,
        slots: &mut Vec<Slot<T::Record>>,
        old: Option<(Extent, u32)>,
        height: u32,
        base: u128,
        edits: Edits<'_, T>,
    ) -> Result<Child, Error> {
        let mut last_spend = old.map_or(0, |o| o.1);
        for k in edits.flips {
            let key: u128 = (*k).into();
            match slots.binary_search_by_key(&key, |s| s.key).ok().map(|i| &mut slots[i]) {
                Some(s) if s.live != edits.revive => {
                    s.live = edits.revive;
                    self.count += if edits.revive { 1 } else { -1 };
                }
                _ => return Err(T::refuse(key, if edits.revive { Fault::NotDead } else { Fault::NotLive })),
            }
        }
        if !edits.flips.is_empty() {
            last_spend = if edits.revive { last_spend.min(self.height) } else { self.height };
        }
        // If only the bits changed, the page stands.
        let mut rewrite = false;
        let keep = slots.partition_point(|s| s.key < edits.truncate);
        if keep < slots.len() {
            self.count -= slots[keep..].iter().filter(|s| s.live).count() as i64;
            slots.truncate(keep);
            rewrite = true;
        }
        for k in edits.removes {
            let key: u128 = (*k).into();
            let i = slots.binary_search_by_key(&key, |s| s.key).map_err(|_| T::refuse(key, Fault::Absent))?;
            self.count -= slots.remove(i).live as i64;
            rewrite = true;
        }
        for (k, record, replace) in edits.puts {
            let key: u128 = (*k).into();
            match (slots.binary_search_by_key(&key, |s| s.key), replace) {
                (Ok(i), true) => slots[i].record = *record,
                (Err(i), false) => {
                    slots.insert(i, Slot { key, record: *record, live: true });
                    self.count += 1;
                }
                (Ok(_), false) => return Err(T::refuse(key, Fault::Present)),
                (Err(_), true) => return Err(T::refuse(key, Fault::Absent)),
            }
            rewrite = true;
        }
        if !edits.run.is_empty() {
            if slots.last().is_some_and(|s| s.key >= edits.run_from) {
                return Err(T::refuse(edits.run_from, Fault::Order));
            }
            slots.extend(edits.run.iter().enumerate().map(|(i, r)| Slot {
                key: edits.run_from + i as u128,
                record: *r,
                live: true,
            }));
            self.count += edits.run.len() as i64;
            rewrite = true;
        }
        match old {
            Some((page, _)) if !rewrite => Ok(Child::Leaf {
                page,
                part: leaf_part::<T>(slots, height),
                records: slots.len() as u8,
                live: live_bits(slots),
                last_spend,
            }),
            _ => {
                if let Some((page, _)) = old {
                    self.txn.free(page);
                }
                self.build(slots, height, base, last_spend)
            }
        }
    }

    /// Sweeps the subtree `child` from key `sweep.from` on, while the
    /// budget lasts. Returns the subtree after it.
    fn sweep(&mut self, child: Child, height: u32, base: u128, sweep: &mut Sweep) -> Result<Child, Error> {
        let end = base + (1u128 << height);
        if end <= sweep.from || sweep.budget == 0 {
            return Ok(child);
        }
        match child {
            Child::Empty => {
                sweep.from = end;
                Ok(child)
            }
            Child::Leaf { page, records, live, last_spend, .. } => {
                sweep.budget -= 1;
                sweep.from = end;
                let dead = records as u32 - live.count_ones();
                // Everything dead here died before the horizon, and
                // there is enough of it to be worth a page.
                if dead == 0 || last_spend >= sweep.horizon || (live != 0 && dead * 4 < records as u32) {
                    return Ok(child);
                }
                self.txn.free(page);
                if live == 0 {
                    return Ok(Child::Empty);
                }
                let mut slots = std::mem::take(&mut self.slots);
                slots.clear();
                let mut buf = [0u8; PAGE];
                read_leaf::<T>(self.txn.read(page, &mut buf)?, base, height, records, live, &mut slots)?;
                slots.retain(|s| s.live);
                let built = self.build(&slots, height, base, 0);
                self.slots = slots;
                built
            }
            Child::Node { page, .. } => {
                let mut buf = [0u8; PAGE];
                let mut children = read_node(self.txn.read(page, &mut buf)?, height)?;
                let low = below(height);
                let mut changed = false;
                for (k, c) in children.iter_mut().enumerate().take(1 << (height - low)) {
                    let swept = self.sweep(*c, low, base + ((k as u128) << low), sweep)?;
                    changed |= swept != *c;
                    *c = swept;
                }
                // Swept to its end, a node that has thinned to a page's
                // worth of live records becomes that page.
                if sweep.from >= end
                    && let Some(leaf) = self.collapse(&children, height, base)?
                {
                    self.txn.free(page);
                    return Ok(leaf);
                }
                if !changed {
                    return Ok(child);
                }
                self.txn.free(page);
                if children.iter().all(|c| *c == Child::Empty) {
                    return Ok(Child::Empty);
                }
                self.write_node(&children, height, base)
            }
        }
    }

    /// The one leaf that holds all of a node's records, if its children
    /// are leaves with nothing dead in them and few enough records; the
    /// children's pages are then freed.
    fn collapse(&mut self, children: &[Child; FANOUT], height: u32, base: u128) -> Result<Option<Child>, Error> {
        let mut total = 0usize;
        for c in children {
            match c {
                Child::Empty => {}
                Child::Leaf { records, live, .. } if live.count_ones() == *records as u32 => total += *records as usize,
                _ => return Ok(None),
            }
        }
        // Well under a full page, so that the leaf does not at once
        // become a node again.
        if total == 0 || total > LEAF_RECORDS * 3 / 4 {
            return Ok(None);
        }
        let mut slots = Vec::with_capacity(total);
        let low = below(height);
        let mut buf = [0u8; PAGE];
        for (k, c) in children.iter().enumerate() {
            if let Child::Leaf { page, records, live, .. } = c {
                let at = base + ((k as u128) << low);
                read_leaf::<T>(self.txn.read(*page, &mut buf)?, at, low, *records, *live, &mut slots)?;
            }
        }
        if !fits::<T>(&slots, base) {
            return Ok(None);
        }
        for c in children {
            if let Child::Leaf { page, .. } = c {
                self.txn.free(*page);
            }
        }
        self.build(&slots, height, base, 0).map(Some)
    }

    /// The subtree of `height` levels from `base` holding `slots`, all
    /// of it written anew: a leaf if they fit one, else a node over the
    /// sixteen parts of them.
    fn build(&mut self, slots: &[Slot<T::Record>], height: u32, base: u128, last_spend: u32) -> Result<Child, Error> {
        if slots.is_empty() {
            return Ok(Child::Empty);
        }
        if fits::<T>(slots, base) {
            write_leaf::<T>(slots, base, &mut self.out);
            let page = self.txn.write(&self.out)?;
            // Only a leaf with something dead has a last spend.
            let last_spend = if slots.iter().all(|s| s.live) { 0 } else { last_spend };
            return Ok(Child::Leaf {
                page,
                part: leaf_part::<T>(slots, height),
                records: slots.len() as u8,
                live: live_bits(slots),
                last_spend,
            });
        }
        // Keys differ, so a subtree of one key always fits.
        assert!(height > 0, "records of one key do not fit a page");
        let low = below(height);
        let mut children = [Child::Empty; FANOUT];
        let mut rest = slots;
        for (k, c) in children.iter_mut().enumerate().take(1 << (height - low)) {
            let at = base + ((k as u128) << low);
            let n = rest.partition_point(|s| s.key < at + (1u128 << low));
            *c = self.build(&rest[..n], low, at, last_spend)?;
            rest = &rest[n..];
        }
        self.write_node(&children, height, base)
    }
}

/// The trie of root `root` after `edits`, made at block `height`, and
/// the change in the number of its live records.
pub fn update<T: Tree, B: Backend>(
    txn: &mut Txn<'_, B>,
    root: Child,
    height: u32,
    edits: Edits<'_, T>,
) -> Result<(Child, i64), Error> {
    let mut pass = Pass::<T, B> { txn, height, count: 0, slots: Vec::new(), out: Vec::new() };
    let root = pass.update(root, T::HEIGHT, 0, edits.within(0, T::HEIGHT))?;
    Ok((root, pass.count))
}

/// Sweeps part of the trie: from key `from`, looks at up to `budget`
/// leaves and drops what is dead in them if all of it died before
/// `horizon` and it is a quarter of the leaf or more. Returns the root,
/// whose part is as it was, and the key the sweep reached.
pub fn sweep<T: Tree, B: Backend>(
    txn: &mut Txn<'_, B>,
    root: Child,
    from: u128,
    budget: usize,
    horizon: u32,
) -> Result<(Child, u128), Error> {
    let mut pass = Pass::<T, B> { txn, height: 0, count: 0, slots: Vec::new(), out: Vec::new() };
    let mut state = Sweep { from, budget, horizon };
    let swept = pass.sweep(root, T::HEIGHT, 0, &mut state)?;
    debug_assert_eq!(swept.part(), root.part(), "a sweep changes no hash");
    Ok((swept, state.from))
}

/// The children of the node in `page`, of `height` levels.
pub fn load_node(pages: &impl ReadPages, page: Extent, height: u32) -> io::Result<[Child; FANOUT]> {
    let mut buf = [0u8; PAGE];
    read_node(pages.read_page(page, &mut buf)?, height)
}

/// The records of the leaf `child`, of `height` levels from `base`; none
/// if it is not a leaf.
pub fn load_leaf<T: Tree>(
    pages: &impl ReadPages,
    child: Child,
    height: u32,
    base: u128,
) -> io::Result<Vec<Slot<T::Record>>> {
    let Child::Leaf { page, records, live, .. } = child else { return Ok(Vec::new()) };
    let mut slots = Vec::with_capacity(records as usize);
    let mut buf = [0u8; PAGE];
    read_leaf::<T>(pages.read_page(page, &mut buf)?, base, height, records, live, &mut slots)?;
    Ok(slots)
}

/// A step of the way down to a key.
pub enum Step<'a, T: Tree> {
    /// A node of `height` levels from `base`, and its children.
    Node { height: u32, base: u128, children: &'a [Child; FANOUT] },
    /// The leaf the way ends in, and its records.
    Leaf { height: u32, base: u128, slots: &'a [Slot<T::Record>] },
    /// The empty subtree the way ends in.
    Empty { height: u32, base: u128 },
}

/// Goes down from `root` to `key`, calling `f` with each step.
pub fn walk_to<T: Tree>(
    pages: &impl ReadPages,
    root: Child,
    key: u128,
    f: &mut dyn FnMut(Step<'_, T>),
) -> io::Result<()> {
    let (mut child, mut height, mut base) = (root, T::HEIGHT, 0u128);
    let mut buf = [0u8; PAGE];
    loop {
        match child {
            Child::Empty => {
                f(Step::Empty { height, base });
                return Ok(());
            }
            Child::Node { page, .. } => {
                let children = read_node(pages.read_page(page, &mut buf)?, height)?;
                f(Step::Node { height, base, children: &children });
                let low = below(height);
                let k = (key - base) >> low;
                child = children[k as usize];
                base += k << low;
                height = low;
            }
            Child::Leaf { page, records, live, .. } => {
                let mut slots = Vec::with_capacity(records as usize);
                read_leaf::<T>(pages.read_page(page, &mut buf)?, base, height, records, live, &mut slots)?;
                f(Step::Leaf { height, base, slots: &slots });
                return Ok(());
            }
        }
    }
}

/// The record at `key` and whether it is live; `None` if none is kept.
pub fn get<T: Tree>(pages: &impl ReadPages, root: Child, key: u128) -> io::Result<Option<(T::Record, bool)>> {
    let mut found = None;
    walk_to::<T>(pages, root, key, &mut |step| {
        if let Step::Leaf { slots, .. } = step {
            found = slots.iter().find(|s| s.key == key).map(|s| (s.record, s.live));
        }
    })?;
    Ok(found)
}

/// Marks every page of the trie in `file`'s map of free space, as must
/// be done when the file is opened. Reads the nodes, not the leaves.
pub fn mark<T: Tree, B: Backend>(file: &PageFile<B>, root: Child) -> io::Result<()> {
    fn walk<B: Backend>(file: &PageFile<B>, child: Child, height: u32) -> io::Result<()> {
        match child {
            Child::Empty => Ok(()),
            Child::Leaf { page, .. } => file.mark(page),
            Child::Node { page, .. } => {
                file.mark(page)?;
                let mut buf = [0u8; PAGE];
                let children = read_node(file.read(page, &mut buf)?, height)?;
                children.iter().try_for_each(|c| walk(file, *c, below(height)))
            }
        }
    }
    walk(file, root, T::HEIGHT)
}

/// Calls `f` with every record kept, in key order: its key, the record
/// and whether it is live.
pub fn for_each<T: Tree>(
    pages: &impl ReadPages,
    root: Child,
    f: &mut dyn FnMut(u128, &T::Record, bool),
) -> io::Result<()> {
    fn walk<T: Tree>(
        pages: &impl ReadPages,
        child: Child,
        height: u32,
        base: u128,
        f: &mut dyn FnMut(u128, &T::Record, bool),
    ) -> io::Result<()> {
        let mut buf = [0u8; PAGE];
        match child {
            Child::Empty => Ok(()),
            Child::Leaf { page, records, live, .. } => {
                let mut slots = Vec::with_capacity(records as usize);
                read_leaf::<T>(pages.read_page(page, &mut buf)?, base, height, records, live, &mut slots)?;
                slots.iter().for_each(|s| f(s.key, &s.record, s.live));
                Ok(())
            }
            Child::Node { page, .. } => {
                let children = read_node(pages.read_page(page, &mut buf)?, height)?;
                let low = below(height);
                for (k, c) in children.iter().enumerate() {
                    walk::<T>(pages, *c, low, base + ((k as u128) << low), f)?;
                }
                Ok(())
            }
        }
    }
    walk::<T>(pages, root, T::HEIGHT, 0, f)
}
