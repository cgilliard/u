//! The unspent outputs: a trie over positions that is also their Merkle
//! tree.
//!
//! Every output ever made has a position, the next of a counter, and its
//! leaf in a binary Merkle tree of height [`HEIGHT`] over all positions
//! ([`crate::output::leaf`]); a spent output's leaf is empty again. This
//! module stores the unspent ones so that the tree's root, any output and
//! any path can be had from a few pages, and so that a block changes few.
//!
//! # Shape
//!
//! A node covers a subtree of the Merkle tree and has [`FANOUT`]
//! children, each covering a sixteenth of it. A child is empty, another
//! node, or a leaf: a page of the outputs under it, when they fit one.
//! Beside each child the node keeps the child's Merkle hash, so a node's
//! own hash follows from its page alone, and the path of any output from
//! the pages on the way down to it.
//!
//! ```text
//! node page := height (1) | children (1) | child ...
//! child     := slot (1) | kind (1) | hash (32) | page (6) | leaf's
//! leaf's    := records (1) | live (8) | last spend (4)
//! leaf page := records (1) | record ...
//! record    := distance from the position before (varint) | commitment (32)
//!              | memo (20) | amount (8) | height (4)
//! ```
//!
//! # A spend does not touch the output's page
//!
//! Which records of a leaf are unspent is a bit each in the node above
//! (`live`). Spending an output clears its bit and changes the hashes
//! above it: the nodes on the way are written anew, as they must be, and
//! the page of records is left as it is. So a block writes about a
//! kilobyte for an output it spends, not the four of the page, and the
//! record of a spent output is still there to be had: undoing the block
//! sets the bit again.
//!
//! A leaf's page is written when outputs are added to it (only ever at
//! the end of the positions, where new outputs go) and when its dead
//! records are dropped.
//!
//! # The sweep
//!
//! Dead records are dropped by a sweep ([`Outputs::sweep`]) that goes
//! round the trie a little with every block. Beside a leaf the node
//! keeps `last spend`, the height of the latest spend under it, so the
//! sweep can tell without reading the page that everything dead in it is
//! older than the window in which blocks may still be undone. Such a
//! leaf is written anew without its dead records if they are a quarter
//! of it or more (so a record is written at most a few times in its
//! life), or dropped if nothing in it is unspent; and a node whose
//! outputs have thinned until they fit one page becomes a leaf.
//!
//! # Changes
//!
//! A block's changes are made in one pass in position order
//! ([`Outputs::apply`]): each page on the way is read once, and written
//! once when the pass leaves it. Nothing is changed in place; the pages
//! replaced are named to the transaction, and the new root is returned to
//! be committed with it.

use std::io;

use super::pagefile::{Extent, PageFile, ReadPages, Txn};
use super::sparse::{EMPTY, empty, root, root_with_path};
use crate::error::Error;
use crate::hash::Digest;
use crate::output::{Commitment, MEMO_BYTES, Memo, memo_from_bytes, memo_to_bytes, output_leaf};
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::store::backend::Backend;

/// Height of the outputs' tree: positions are below `2^HEIGHT`.
pub const HEIGHT: u32 = 41;
/// Levels of the tree a node spans.
pub const BITS: u32 = 4;
/// Children of a node.
pub const FANOUT: usize = 1 << BITS;
/// The height of the lowest leaves: 32 positions, which always fit a page.
const LEAF_HEIGHT: u32 = 5;
const _: () = assert!((HEIGHT - LEAF_HEIGHT) % BITS == 0);

/// Serialized size of a [`Record`].
pub const RECORD_BYTES: usize = 32 + MEMO_BYTES + 8 + 4;
/// The most records a leaf holds: a bit each in its `live`.
const LEAF_RECORDS: usize = 64;
/// The most bytes of a leaf page's payload: eight units.
const LEAF_BYTES: usize = Extent::capacity(8);
const PAGE: usize = 4096;
const _: () = assert!(1 + (1 << LEAF_HEIGHT) * (RECORD_BYTES + 6) <= LEAF_BYTES);

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// An output as the set keeps it: what its leaf is made of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Record {
    pub commitment: Commitment,
    pub memo: Memo,
    pub amount: u64,
    /// The height of the block that made it.
    pub height: u32,
}

impl Record {
    /// Its leaf in the tree while it is unspent.
    pub fn leaf(&self) -> Digest {
        output_leaf(&self.commitment, &self.memo, self.amount, self.height)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&digest_to_bytes(&self.commitment));
        out.extend_from_slice(&memo_to_bytes(&self.memo));
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
    }

    fn read(b: &[u8]) -> io::Result<Record> {
        let bad = || corrupt("an output's record is not one");
        let (commitment, rest) = b.split_at_checked(32).ok_or_else(bad)?;
        let (memo, rest) = rest.split_at_checked(MEMO_BYTES).ok_or_else(bad)?;
        if rest.len() != 12 {
            return Err(bad());
        }
        Ok(Record {
            commitment: digest_from_bytes(commitment).ok_or_else(bad)?,
            memo: memo_from_bytes(memo).map_err(|_| bad())?,
            amount: u64::from_le_bytes(rest[..8].try_into().unwrap()),
            height: u32::from_le_bytes(rest[8..].try_into().unwrap()),
        })
    }
}

/// A child of a node, or the root: a subtree, and its Merkle hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Child {
    /// No output under it, spent or unspent.
    Empty,
    /// A node's page.
    Node { page: Extent, hash: Digest },
    /// A page of records.
    Leaf {
        page: Extent,
        hash: Digest,
        /// Records in the page.
        records: u8,
        /// Which of them are unspent, the first the lowest bit.
        live: u64,
        /// The height of the latest spend among them, 0 if none.
        last_spend: u32,
    },
}

/// Bytes of a child's encoding, less its slot: the longest, a leaf's.
const CHILD_BYTES: usize = 1 + 32 + 6 + 13;

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
    /// The Merkle hash of the subtree, which has `height` levels.
    pub fn hash(&self, height: u32) -> Digest {
        match self {
            Child::Empty => *empty(height as usize),
            Child::Node { hash, .. } | Child::Leaf { hash, .. } => *hash,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Child::Empty => out.push(0),
            Child::Node { page, hash } => {
                out.push(1);
                out.extend_from_slice(&digest_to_bytes(hash));
                put_extent(out, *page);
            }
            Child::Leaf { page, hash, records, live, last_spend } => {
                out.push(2);
                out.extend_from_slice(&digest_to_bytes(hash));
                put_extent(out, *page);
                out.push(*records);
                out.extend_from_slice(&live.to_le_bytes());
                out.extend_from_slice(&last_spend.to_le_bytes());
            }
        }
    }

    /// Reads a child from the front of `b`, and returns the rest.
    fn read(b: &[u8]) -> io::Result<(Child, &[u8])> {
        let bad = || corrupt("a node's child is not one");
        let (&kind, b) = b.split_first().ok_or_else(bad)?;
        if kind == 0 {
            return Ok((Child::Empty, b));
        }
        let (head, b) = b.split_at_checked(38).ok_or_else(bad)?;
        let hash = digest_from_bytes(&head[..32]).ok_or_else(bad)?;
        let page = get_extent(&head[32..]);
        if page.units == 0 {
            return Err(bad());
        }
        match kind {
            1 => Ok((Child::Node { page, hash }, b)),
            2 => {
                let (tail, b) = b.split_at_checked(13).ok_or_else(bad)?;
                let records = tail[0];
                let live = u64::from_le_bytes(tail[1..9].try_into().unwrap());
                if records == 0 || records as usize > LEAF_RECORDS || (records < 64 && live >> records != 0) {
                    return Err(bad());
                }
                let last_spend = u32::from_le_bytes(tail[9..].try_into().unwrap());
                Ok((Child::Leaf { page, hash, records, live, last_spend }, b))
            }
            _ => Err(bad()),
        }
    }
}

/// A node's children, read from its page.
fn read_node(payload: &[u8], height: u32) -> io::Result<[Child; FANOUT]> {
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

fn write_node(children: &[Child; FANOUT], height: u32, out: &mut Vec<u8>) {
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

/// A node's hash, from its children's: `base` is its first position.
fn node_hash(children: &[Child; FANOUT], height: u32, base: u64) -> Digest {
    let below = height - BITS;
    let mut nodes = [(0u64, EMPTY); FANOUT];
    let mut n = 0;
    for (k, c) in children.iter().enumerate() {
        if let Child::Node { hash, .. } | Child::Leaf { hash, .. } = c {
            nodes[n] = ((base >> below) + k as u64, *hash);
            n += 1;
        }
    }
    root(below as usize, height as usize, &mut nodes[..n])
}

/// A record of a leaf, with its position and whether it is unspent.
#[derive(Clone, Copy, Debug)]
struct Slot {
    position: u64,
    record: Record,
    live: bool,
}

fn put_varint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push(x as u8 | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

fn get_varint(b: &[u8]) -> Option<(u64, &[u8])> {
    let (mut x, mut shift) = (0u64, 0);
    for (i, &byte) in b.iter().enumerate().take(6) {
        x |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte < 0x80 {
            return Some((x, &b[i + 1..]));
        }
    }
    None
}

/// A leaf page's records, appended to `out`: those of the leaf whose
/// subtree of `height` levels starts at `base`.
fn read_leaf(payload: &[u8], base: u64, height: u32, records: u8, live: u64, out: &mut Vec<Slot>) -> io::Result<()> {
    let bad = || corrupt("a leaf's page is not one");
    let (&count, mut b) = payload.split_first().ok_or_else(bad)?;
    if count != records {
        return Err(bad());
    }
    let end = base + (1u64 << height);
    let mut position = base;
    for i in 0..count as usize {
        let (delta, rest) = get_varint(b).ok_or_else(bad)?;
        // Positions ascend, and stay under the leaf.
        if i > 0 && delta == 0 {
            return Err(bad());
        }
        position = position.checked_add(delta).filter(|p| *p < end).ok_or_else(bad)?;
        let (rec, rest) = rest.split_at_checked(RECORD_BYTES).ok_or_else(bad)?;
        out.push(Slot { position, record: Record::read(rec)?, live: live >> i & 1 == 1 });
        b = rest;
    }
    if !b.is_empty() {
        return Err(bad());
    }
    Ok(())
}

fn write_leaf(slots: &[Slot], base: u64, out: &mut Vec<u8>) {
    out.clear();
    out.push(slots.len() as u8);
    let mut prev = base;
    for s in slots {
        put_varint(out, s.position - prev);
        s.record.write(out);
        prev = s.position;
    }
}

/// Whether `slots`, under one subtree starting at `base`, fit a leaf.
fn fits(slots: &[Slot], base: u64) -> bool {
    if slots.len() > LEAF_RECORDS {
        return false;
    }
    let mut bytes = 1;
    let mut prev = base;
    for s in slots {
        let delta = s.position - prev;
        bytes += RECORD_BYTES + (64 - delta.leading_zeros()).div_ceil(7).max(1) as usize;
        prev = s.position;
    }
    bytes <= LEAF_BYTES
}

/// The hash of a subtree of `height` levels from its unspent records.
fn leaf_hash(slots: &[Slot], height: u32) -> Digest {
    let mut nodes = [(0u64, EMPTY); LEAF_RECORDS];
    let mut n = 0;
    for s in slots.iter().filter(|s| s.live) {
        nodes[n] = (s.position, s.record.leaf());
        n += 1;
    }
    root(0, height as usize, &mut nodes[..n])
}

fn live_bits(slots: &[Slot]) -> u64 {
    slots.iter().enumerate().fold(0, |bits, (i, s)| bits | (s.live as u64) << i)
}

/// What one pass changes, as it applies to a subtree: every part of it
/// is cut down to the subtree's positions as the pass descends, at no
/// cost.
#[derive(Clone, Copy)]
struct Edits<'a> {
    /// Positions whose outputs are spent, or (`unspend`) unspent again:
    /// ascending.
    flips: &'a [u64],
    unspend: bool,
    /// New outputs, at the positions from `add_from` on.
    adds: &'a [Record],
    add_from: u64,
    /// Every output at this position or after is removed.
    truncate: u64,
}

impl<'a> Edits<'a> {
    /// The part that falls in `base..base + 2^height`.
    fn within(&self, base: u64, height: u32) -> Edits<'a> {
        let end = base + (1u64 << height);
        let from = self.flips.partition_point(|p| *p < base);
        let to = self.flips.partition_point(|p| *p < end);
        let add_end = self.add_from + self.adds.len() as u64;
        let lo = self.add_from.max(base).min(add_end);
        let hi = add_end.min(end).max(lo);
        Edits {
            flips: &self.flips[from..to],
            unspend: self.unspend,
            adds: &self.adds[(lo - self.add_from) as usize..(hi - self.add_from) as usize],
            add_from: lo,
            truncate: self.truncate,
        }
    }

    /// Whether nothing of it falls in `base..base + 2^height`: `self` is
    /// already cut down to that.
    fn is_empty(&self, base: u64, height: u32) -> bool {
        self.flips.is_empty() && self.adds.is_empty() && self.truncate >= base + (1u64 << height)
    }
}

/// A sweep under way.
struct Sweep {
    /// The position it has reached.
    from: u64,
    /// Leaves it may still look at.
    budget: usize,
    /// A leaf whose last spend is below this height has nothing dead that
    /// a block still to be undone could want back.
    horizon: u32,
}

/// One pass over the trie, inside a transaction.
struct Pass<'t, 'f, B: Backend> {
    txn: &'t mut Txn<'f, B>,
    /// The height of the block the pass applies, or of the tip a pass
    /// that undoes one leaves.
    height: u32,
    /// The change in the number of unspent outputs.
    count: i64,
    slots: Vec<Slot>,
    out: Vec<u8>,
}

impl<B: Backend> Pass<'_, '_, B> {
    /// The subtree `child` (of `height` levels from `base`) after `edits`.
    fn update(&mut self, child: Child, height: u32, base: u64, edits: Edits<'_>) -> Result<Child, Error> {
        if edits.is_empty(base, height) {
            return Ok(child);
        }
        let Child::Node { page, .. } = child else { return self.update_leaf(child, height, base, edits) };
        let mut buf = [0u8; PAGE];
        let mut children = read_node(self.txn.read(page, &mut buf)?, height)?;
        let below = height - BITS;
        for (k, c) in children.iter_mut().enumerate() {
            let at = base + ((k as u64) << below);
            *c = self.update(*c, below, at, edits.within(at, below))?;
        }
        self.txn.free(page);
        if children.iter().all(|c| *c == Child::Empty) {
            return Ok(Child::Empty);
        }
        self.write_node(&children, height, base)
    }

    fn write_node(&mut self, children: &[Child; FANOUT], height: u32, base: u64) -> Result<Child, Error> {
        write_node(children, height, &mut self.out);
        let page = self.txn.write(&self.out)?;
        Ok(Child::Node { page, hash: node_hash(children, height, base) })
    }

    /// A leaf, or an empty subtree, after `edits`.
    fn update_leaf(&mut self, child: Child, height: u32, base: u64, edits: Edits<'_>) -> Result<Child, Error> {
        let mut slots = std::mem::take(&mut self.slots);
        slots.clear();
        let mut old = None;
        if let Child::Leaf { page, records, live, last_spend, .. } = child {
            let mut buf = [0u8; PAGE];
            read_leaf(self.txn.read(page, &mut buf)?, base, height, records, live, &mut slots)?;
            old = Some((page, last_spend));
        }
        let done = self.edit(&mut slots, old, height, base, edits);
        self.slots = slots;
        done
    }

    fn edit(
        &mut self,
        slots: &mut Vec<Slot>,
        old: Option<(Extent, u32)>,
        height: u32,
        base: u64,
        edits: Edits<'_>,
    ) -> Result<Child, Error> {
        let mut last_spend = old.map_or(0, |o| o.1);
        for p in edits.flips {
            let slot = slots.binary_search_by_key(p, |s| s.position).ok().map(|i| &mut slots[i]);
            match slot {
                Some(s) if s.live != edits.unspend => {
                    s.live = edits.unspend;
                    self.count += if edits.unspend { 1 } else { -1 };
                }
                // A spend of what is not there to spend is the block's
                // fault; an unspend of what was not spent is ours.
                _ if !edits.unspend => return Err(Error::NoSuchOutput(*p)),
                _ => return Err(corrupt("an output to unspend is not a spent one").into()),
            }
        }
        if !edits.flips.is_empty() {
            last_spend = if edits.unspend { last_spend.min(self.height) } else { self.height };
        }
        // Only the bits changed: the page stands.
        let mut rewrite = false;
        let keep = slots.partition_point(|s| s.position < edits.truncate);
        if keep < slots.len() {
            self.count -= slots[keep..].iter().filter(|s| s.live).count() as i64;
            slots.truncate(keep);
            rewrite = true;
        }
        if !edits.adds.is_empty() {
            if slots.last().is_some_and(|s| s.position >= edits.add_from) {
                return Err(corrupt("a new output's position is not past the last").into());
            }
            slots.extend(edits.adds.iter().enumerate().map(|(i, r)| Slot {
                position: edits.add_from + i as u64,
                record: *r,
                live: true,
            }));
            self.count += edits.adds.len() as i64;
            rewrite = true;
        }
        match old {
            Some((page, _)) if !rewrite => Ok(Child::Leaf {
                page,
                hash: leaf_hash(slots, height),
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

    /// Sweeps the subtree `child` from position `sweep.from` on, while
    /// the budget lasts. Returns the subtree after it.
    fn sweep(&mut self, child: Child, height: u32, base: u64, sweep: &mut Sweep) -> Result<Child, Error> {
        let end = base + (1u64 << height);
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
                // Everything dead here was spent before the horizon, and
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
                read_leaf(self.txn.read(page, &mut buf)?, base, height, records, live, &mut slots)?;
                slots.retain(|s| s.live);
                let built = self.build(&slots, height, base, 0);
                self.slots = slots;
                built
            }
            Child::Node { page, .. } => {
                let mut buf = [0u8; PAGE];
                let mut children = read_node(self.txn.read(page, &mut buf)?, height)?;
                let below = height - BITS;
                let mut changed = false;
                for (k, c) in children.iter_mut().enumerate() {
                    let swept = self.sweep(*c, below, base + ((k as u64) << below), sweep)?;
                    changed |= swept != *c;
                    *c = swept;
                }
                // Swept to its end, a node that has thinned to a page's
                // worth of unspent outputs becomes that page.
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

    /// The one leaf that holds all of a node's outputs, if its children
    /// are leaves with nothing dead in them and few enough records; the
    /// children's pages are then freed.
    fn collapse(&mut self, children: &[Child; FANOUT], height: u32, base: u64) -> Result<Option<Child>, Error> {
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
        let below = height - BITS;
        let mut buf = [0u8; PAGE];
        for (k, c) in children.iter().enumerate() {
            if let Child::Leaf { page, records, live, .. } = c {
                let at = base + ((k as u64) << below);
                read_leaf(self.txn.read(*page, &mut buf)?, at, below, *records, *live, &mut slots)?;
            }
        }
        if !fits(&slots, base) {
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
    fn build(&mut self, slots: &[Slot], height: u32, base: u64, last_spend: u32) -> Result<Child, Error> {
        if slots.is_empty() {
            return Ok(Child::Empty);
        }
        if fits(slots, base) {
            write_leaf(slots, base, &mut self.out);
            let page = self.txn.write(&self.out)?;
            // Only a leaf with something spent has a last spend.
            let last_spend = if slots.iter().all(|s| s.live) { 0 } else { last_spend };
            return Ok(Child::Leaf {
                page,
                hash: leaf_hash(slots, height),
                records: slots.len() as u8,
                live: live_bits(slots),
                last_spend,
            });
        }
        debug_assert!(height > LEAF_HEIGHT, "the lowest leaves always fit");
        let below = height - BITS;
        let mut children = [Child::Empty; FANOUT];
        let mut rest = slots;
        for (k, c) in children.iter_mut().enumerate() {
            let at = base + ((k as u64) << below);
            let n = rest.partition_point(|s| s.position < at + (1u64 << below));
            *c = self.build(&rest[..n], below, at, last_spend)?;
            rest = &rest[n..];
        }
        self.write_node(&children, height, base)
    }
}

/// The set of unspent outputs, as a root record holds it: the root of
/// the trie, the next position, and how many outputs are unspent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Outputs {
    pub root: Child,
    /// The position the next new output takes.
    pub next: u64,
    /// Unspent outputs.
    pub count: u64,
}

impl Outputs {
    /// No output yet.
    pub const EMPTY: Outputs = Outputs { root: Child::Empty, next: 0, count: 0 };
    /// Serialized size.
    pub const BYTES: usize = CHILD_BYTES + 16;

    /// The root of the outputs' tree.
    pub fn hash(&self) -> Digest {
        self.root.hash(HEIGHT)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut v = Vec::with_capacity(Self::BYTES);
        self.root.write(&mut v);
        v.resize(CHILD_BYTES, 0);
        v.extend_from_slice(&self.next.to_le_bytes());
        v.extend_from_slice(&self.count.to_le_bytes());
        v.try_into().unwrap()
    }

    pub fn from_bytes(b: &[u8]) -> io::Result<Outputs> {
        let bad = || corrupt("the outputs' root is not one");
        if b.len() != Self::BYTES {
            return Err(bad());
        }
        let (root, rest) = Child::read(&b[..CHILD_BYTES])?;
        if rest.iter().any(|x| *x != 0) {
            return Err(bad());
        }
        let next = u64::from_le_bytes(b[CHILD_BYTES..CHILD_BYTES + 8].try_into().unwrap());
        let count = u64::from_le_bytes(b[CHILD_BYTES + 8..].try_into().unwrap());
        if next > 1 << HEIGHT || count > next {
            return Err(bad());
        }
        Ok(Outputs { root, next, count })
    }

    fn pass<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        height: u32,
        edits: Edits<'_>,
        next: u64,
    ) -> Result<Outputs, Error> {
        debug_assert!(edits.flips.windows(2).all(|w| w[0] <= w[1]), "positions ascend");
        let mut pass = Pass { txn, height, count: 0, slots: Vec::new(), out: Vec::new() };
        let root = pass.update(self.root, HEIGHT, 0, edits.within(0, HEIGHT))?;
        let count =
            self.count.checked_add_signed(pass.count).ok_or_else(|| corrupt("the count of outputs is wrong"))?;
        Ok(Outputs { root, next, count })
    }

    /// The set after a block at `height` that spends the outputs at
    /// `spends` (ascending) and makes `outputs`, which take the next
    /// positions in order. [`Error::NoSuchOutput`] if a spent position
    /// holds no unspent output (or is spent twice); the transaction is
    /// then to be dropped.
    pub fn apply<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        height: u32,
        spends: &[u64],
        outputs: &[Record],
    ) -> Result<Outputs, Error> {
        let next = self.next + outputs.len() as u64;
        assert!(next <= 1 << HEIGHT, "more outputs than the tree has positions");
        if let Some(p) = spends.iter().find(|p| **p >= self.next) {
            return Err(Error::NoSuchOutput(*p));
        }
        let edits = Edits { flips: spends, unspend: false, adds: outputs, add_from: self.next, truncate: u64::MAX };
        self.pass(txn, height, edits, next)
    }

    /// The set before a block that spent `spends` (ascending) and made
    /// the outputs from position `next` on: those are removed, and the
    /// spent ones are unspent again. `height` is the block's less one.
    pub fn undo<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        height: u32,
        spends: &[u64],
        next: u64,
    ) -> Result<Outputs, Error> {
        assert!(next <= self.next);
        let edits = Edits { flips: spends, unspend: true, adds: &[], add_from: next, truncate: next };
        self.pass(txn, height, edits, next)
    }

    /// Sweeps part of the trie: from position `from`, looks at up to
    /// `budget` leaves and drops what is dead in them and spent before
    /// `horizon` (the height of the oldest block that may still be
    /// undone). Returns the set, whose tree and counts are as they were,
    /// and the position to sweep from next: 0 once the end is reached.
    pub fn sweep<B: Backend>(
        &self,
        txn: &mut Txn<'_, B>,
        from: u64,
        budget: usize,
        horizon: u32,
    ) -> Result<(Outputs, u64), Error> {
        let mut pass = Pass { txn, height: 0, count: 0, slots: Vec::new(), out: Vec::new() };
        let mut sweep = Sweep { from, budget, horizon };
        let root = pass.sweep(self.root, HEIGHT, 0, &mut sweep)?;
        debug_assert_eq!(root.hash(HEIGHT), self.hash(), "a sweep changes no hash");
        let next = if sweep.from >= self.next { 0 } else { sweep.from };
        Ok((Outputs { root, ..*self }, next))
    }

    /// The output at `position` and whether it is unspent; `None` if no
    /// record of one is kept (there never was one, or it was spent and
    /// its record has since been dropped).
    pub fn get(&self, pages: &impl ReadPages, position: u64) -> io::Result<Option<(Record, bool)>> {
        let (mut child, mut height, mut base) = (self.root, HEIGHT, 0u64);
        let mut buf = [0u8; PAGE];
        loop {
            match child {
                Child::Empty => return Ok(None),
                Child::Node { page, .. } => {
                    let children = read_node(pages.read_page(page, &mut buf)?, height)?;
                    height -= BITS;
                    let k = (position - base) >> height;
                    child = children[k as usize];
                    base += k << height;
                }
                Child::Leaf { page, records, live, .. } => {
                    let mut slots = Vec::with_capacity(records as usize);
                    read_leaf(pages.read_page(page, &mut buf)?, base, height, records, live, &mut slots)?;
                    return Ok(slots.iter().find(|s| s.position == position).map(|s| (s.record, s.live)));
                }
            }
        }
    }

    /// The path of `position` in the outputs' tree: its leaf (empty if no
    /// unspent output is there) and the sibling at each level up to the
    /// root, which [`super::sparse::root_of_path`] recomputes from them.
    pub fn prove(&self, pages: &impl ReadPages, position: u64) -> io::Result<(Digest, [Digest; HEIGHT as usize])> {
        let mut path = [EMPTY; HEIGHT as usize];
        let (mut child, mut height, mut base) = (self.root, HEIGHT, 0u64);
        let mut buf = [0u8; PAGE];
        loop {
            match child {
                // Nothing below: the siblings are those of an empty tree.
                Child::Empty => {
                    for (l, s) in path[..height as usize].iter_mut().enumerate() {
                        *s = *empty(l);
                    }
                    return Ok((EMPTY, path));
                }
                Child::Node { page, .. } => {
                    let children = read_node(pages.read_page(page, &mut buf)?, height)?;
                    let below = height - BITS;
                    let mut nodes = [(0u64, EMPTY); FANOUT];
                    let mut n = 0;
                    for (k, c) in children.iter().enumerate() {
                        if *c != Child::Empty {
                            nodes[n] = ((base >> below) + k as u64, c.hash(below));
                            n += 1;
                        }
                    }
                    let siblings = &mut path[below as usize..height as usize];
                    root_with_path(
                        below as usize,
                        height as usize,
                        &mut nodes[..n],
                        Some((position >> below, siblings)),
                    );
                    let k = (position - base) >> below;
                    child = children[k as usize];
                    base += k << below;
                    height = below;
                }
                Child::Leaf { page, records, live, .. } => {
                    let mut slots = Vec::with_capacity(records as usize);
                    read_leaf(pages.read_page(page, &mut buf)?, base, height, records, live, &mut slots)?;
                    let mut nodes = [(0u64, EMPTY); LEAF_RECORDS];
                    let (mut n, mut leaf) = (0, EMPTY);
                    for s in slots.iter().filter(|s| s.live) {
                        nodes[n] = (s.position, s.record.leaf());
                        if s.position == position {
                            leaf = nodes[n].1;
                        }
                        n += 1;
                    }
                    root_with_path(0, height as usize, &mut nodes[..n], Some((position, &mut path[..height as usize])));
                    return Ok((leaf, path));
                }
            }
        }
    }

    /// Marks every page of the set in `file`'s map of free space, as must
    /// be done when the file is opened. Reads the nodes, not the leaves.
    pub fn mark<B: Backend>(&self, file: &PageFile<B>) -> io::Result<()> {
        fn walk<B: Backend>(file: &PageFile<B>, child: Child, height: u32) -> io::Result<()> {
            match child {
                Child::Empty => Ok(()),
                Child::Leaf { page, .. } => file.mark(page),
                Child::Node { page, .. } => {
                    file.mark(page)?;
                    let mut buf = [0u8; PAGE];
                    let children = read_node(file.read(page, &mut buf)?, height)?;
                    children.iter().try_for_each(|c| walk(file, *c, height - BITS))
                }
            }
        }
        walk(file, self.root, HEIGHT)
    }

    /// Calls `f` with every output kept, in position order: its position,
    /// its record and whether it is unspent.
    pub fn for_each(&self, pages: &impl ReadPages, f: &mut dyn FnMut(u64, &Record, bool)) -> io::Result<()> {
        fn walk(
            pages: &impl ReadPages,
            child: Child,
            height: u32,
            base: u64,
            f: &mut dyn FnMut(u64, &Record, bool),
        ) -> io::Result<()> {
            let mut buf = [0u8; PAGE];
            match child {
                Child::Empty => Ok(()),
                Child::Leaf { page, records, live, .. } => {
                    let mut slots = Vec::with_capacity(records as usize);
                    read_leaf(pages.read_page(page, &mut buf)?, base, height, records, live, &mut slots)?;
                    slots.iter().for_each(|s| f(s.position, &s.record, s.live));
                    Ok(())
                }
                Child::Node { page, .. } => {
                    let children = read_node(pages.read_page(page, &mut buf)?, height)?;
                    let below = height - BITS;
                    for (k, c) in children.iter().enumerate() {
                        walk(pages, *c, below, base + ((k as u64) << below), f)?;
                    }
                    Ok(())
                }
            }
        }
        walk(pages, self.root, HEIGHT, 0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sparse::root_of_path;
    use crate::store::testing::{Lost, MemBackend};
    use crate::test_util::Rng;
    use std::collections::BTreeMap;

    fn record(rng: &mut Rng, height: u32) -> Record {
        Record {
            commitment: core::array::from_fn(|_| rng.fp()),
            memo: core::array::from_fn(|_| rng.fp()),
            amount: rng.next_u64(),
            height,
        }
    }

    /// The set as a map, and the tree's root by the definition.
    #[derive(Clone, Default, PartialEq, Debug)]
    struct Model {
        outputs: BTreeMap<u64, (Record, bool)>,
        next: u64,
    }

    impl Model {
        fn hash(&self) -> Digest {
            let mut nodes: Vec<(u64, Digest)> =
                self.outputs.iter().filter(|(_, v)| v.1).map(|(p, v)| (*p, v.0.leaf())).collect();
            root(0, HEIGHT as usize, &mut nodes)
        }

        fn live(&self) -> Vec<u64> {
            self.outputs.iter().filter(|(_, v)| v.1).map(|(p, _)| *p).collect()
        }
    }

    struct World {
        file: PageFile<MemBackend>,
        set: Outputs,
        model: Model,
        tip: u32,
        /// For each block: the set and the model before it, and what it spent.
        history: Vec<(Outputs, Model, Vec<u64>)>,
    }

    impl World {
        fn new() -> World {
            let file = PageFile::create(MemBackend::new()).unwrap();
            World { file, set: Outputs::EMPTY, model: Model::default(), tip: 0, history: Vec::new() }
        }

        /// A block that spends `spends` of the unspent outputs, picked by
        /// `rng`, and makes `adds`. Returns the bytes of pages it wrote.
        fn block(&mut self, rng: &mut Rng, spends: usize, adds: usize) -> Result<u64, Error> {
            let mut live = self.model.live();
            let mut picked = Vec::new();
            for _ in 0..spends.min(live.len()) {
                picked.push(live.swap_remove(rng.next_u64() as usize % live.len()));
            }
            picked.sort_unstable();
            let height = self.tip + 1;
            let records: Vec<Record> = (0..adds).map(|_| record(rng, height)).collect();
            self.apply(&picked, &records)
        }

        fn apply(&mut self, spends: &[u64], records: &[Record]) -> Result<u64, Error> {
            let height = self.tip + 1;
            let mut txn = self.file.begin()?;
            let set = self.set.apply(&mut txn, height, spends, records)?;
            let written = txn.written();
            txn.commit(&set.to_bytes())?;
            self.history.push((self.set, self.model.clone(), spends.to_vec()));
            for p in spends {
                self.model.outputs.get_mut(p).unwrap().1 = false;
            }
            for r in records {
                self.model.outputs.insert(self.model.next, (*r, true));
                self.model.next += 1;
            }
            (self.set, self.tip) = (set, height);
            Ok(written)
        }

        /// Undoes the last block.
        fn undo(&mut self) {
            let (before, model, spends) = self.history.pop().unwrap();
            let mut txn = self.file.begin().unwrap();
            let set = self.set.undo(&mut txn, self.tip - 1, &spends, before.next).unwrap();
            txn.commit(&set.to_bytes()).unwrap();
            (self.set, self.model, self.tip) = (set, model, self.tip - 1);
            assert_eq!(set.hash(), before.hash());
            assert_eq!((set.next, set.count), (before.next, before.count));
        }

        /// The set is the model: root, counts, every record and whether it
        /// is spent, and paths that lead to the root.
        fn check(&self, rng: &mut Rng) {
            let hash = self.model.hash();
            assert_eq!(self.set.hash(), hash);
            assert_eq!(self.set.next, self.model.next);
            assert_eq!(self.set.count as usize, self.model.live().len());
            let mut seen = Vec::new();
            self.set.for_each(&self.file, &mut |p, r, live| seen.push((p, (*r, live)))).unwrap();
            assert!(
                seen.iter().copied().eq(self.model.outputs.iter().map(|(p, v)| (*p, *v))),
                "every record, in order"
            );
            let mut probes: Vec<u64> = (0..12).map(|_| rng.next_u64() % (self.model.next + 3)).collect();
            probes.extend([0, self.model.next.saturating_sub(1), self.model.next, (1 << HEIGHT) - 1]);
            for p in probes {
                let want = self.model.outputs.get(&p).copied();
                assert_eq!(self.set.get(&self.file, p).unwrap(), want, "position {p}");
                let (leaf, path) = self.set.prove(&self.file, p).unwrap();
                let want_leaf = want.filter(|v| v.1).map_or(EMPTY, |v| v.0.leaf());
                assert_eq!(leaf, want_leaf, "position {p}");
                assert_eq!(root_of_path(p, &leaf, &path), hash, "the path of {p}");
            }
        }

        /// Opened again from what is on disk: the same set, and every unit
        /// in use is one the set reaches (nothing is leaked).
        fn reopen(&mut self) {
            let file = PageFile::open(MemBackend::from_image(self.file.backend().image(Lost::All))).unwrap();
            let set = Outputs::from_bytes(file.root().payload()).unwrap();
            assert_eq!(set, self.set);
            set.mark(&file).unwrap();
            file.seal();
            assert_eq!(file.space().0, self.file.space().0, "units reached, and units in use");
            self.file = file;
        }
    }

    #[test]
    fn the_empty_set_and_one_output() {
        let mut w = World::new();
        let mut rng = Rng::new(1);
        assert_eq!(w.set.hash(), *empty(HEIGHT as usize));
        w.check(&mut rng);
        assert_eq!(Outputs::from_bytes(&Outputs::EMPTY.to_bytes()).unwrap(), Outputs::EMPTY);
        // One output: the root is a leaf, a page of one record.
        w.block(&mut rng, 0, 1).unwrap();
        assert!(matches!(w.set.root, Child::Leaf { records: 1, live: 1, last_spend: 0, .. }));
        w.check(&mut rng);
        // Spent: the tree is empty again, and the record is still kept.
        w.block(&mut rng, 1, 0).unwrap();
        assert!(matches!(w.set.root, Child::Leaf { records: 1, live: 0, last_spend: 2, .. }));
        assert_eq!((w.set.hash(), w.set.count, w.set.next), (*empty(HEIGHT as usize), 0, 1));
        w.check(&mut rng);
        w.reopen();
        w.undo();
        w.check(&mut rng);
        assert!(matches!(w.set.root, Child::Leaf { records: 1, live: 1, .. }));
        w.undo();
        assert_eq!(w.set, Outputs::EMPTY);
        w.reopen();
        assert_eq!(w.file.space().0, crate::store::pagefile::HEADER_UNITS);
    }

    /// Blocks of every size against the model: after each the set is the
    /// model, and after some it is opened again from disk.
    #[test]
    fn blocks_against_a_model() {
        let mut w = World::new();
        let mut rng = Rng::new(0x0575);
        let sizes =
            [(0, 5), (2, 60), (10, 3), (30, 300), (0, 0), (200, 40), (50, 1500), (700, 0), (300, 900), (900, 2)];
        for round in 0..3 {
            let sizes = if cfg!(debug_assertions) { &sizes[2 * round..2 * round + 6] } else { &sizes[..] };
            for (i, (spends, adds)) in sizes.iter().enumerate() {
                w.block(&mut rng, *spends, *adds).unwrap();
                w.check(&mut rng);
                if i % 4 == round {
                    w.reopen();
                }
            }
        }
        assert!(w.set.count > 1000 && w.model.next > 4000, "{} of {}", w.set.count, w.model.next);
        assert!(matches!(w.set.root, Child::Node { .. }));
        // Then every block undone, newest first, back to nothing.
        while !w.history.is_empty() {
            w.undo();
            if w.history.len() % 7 == 0 {
                w.check(&mut rng);
                w.reopen();
            }
        }
        assert_eq!(w.set, Outputs::EMPTY);
        assert_eq!(w.file.space().0, crate::store::pagefile::HEADER_UNITS);
    }

    /// A spend writes the nodes above its output and nothing else: not
    /// the page the output is in.
    #[test]
    fn a_spend_leaves_the_outputs_page_alone() {
        let mut w = World::new();
        let mut rng = Rng::new(0x1eaf);
        w.block(&mut rng, 0, 5000).unwrap();
        // Nine nodes lie between the root and a lowest leaf.
        let levels = ((HEIGHT - LEAF_HEIGHT) / BITS) as u64;
        assert_eq!(levels, 9);
        let one = w.block(&mut rng, 1, 0).unwrap();
        assert!(one <= levels * 1024, "{one} bytes for one spend");
        // A hundred spread over the set share the nodes near the root.
        let hundred = w.block(&mut rng, 100, 0).unwrap();
        assert!(hundred < 100 * 2 * 1024, "{hundred} bytes for a hundred spends");
        // Adding goes to the end: a page a few dozen outputs, and the
        // nodes above the end once.
        let added = w.block(&mut rng, 0, 320).unwrap();
        assert!(added < 320 * 80 + 12 * 1024, "{added} bytes for 320 outputs");
        w.check(&mut rng);
        // The file is about its outputs' size: what was replaced is reused.
        let (used, end) = w.file.space();
        assert!(used * 512 < 5420 * 120, "{used} units for 5,420 records");
        assert!(end < used + used / 4, "{used} of {end} units in use");
    }

    /// What a block may not spend, and that refusing leaves the set as
    /// it was.
    #[test]
    fn spends_of_nothing_are_refused() {
        let mut w = World::new();
        let mut rng = Rng::new(0xbad);
        w.block(&mut rng, 0, 300).unwrap();
        w.block(&mut rng, 40, 10).unwrap();
        let spent = *w.history[1].2.first().unwrap();
        let live = w.model.live();
        let used = w.file.space().0;
        for (spends, at) in [
            (vec![spent], spent),
            (vec![live[3], live[3]], live[3]),
            (vec![live[0], w.set.next], w.set.next),
            (vec![(1 << HEIGHT) - 1], (1 << HEIGHT) - 1),
            (vec![live[1], spent, live[200]], spent),
        ] {
            let mut sorted = spends.clone();
            sorted.sort_unstable();
            assert_eq!(w.apply(&sorted, &[record(&mut rng, 3)]).err(), Some(Error::NoSuchOutput(at)), "{spends:?}");
            // The transaction was dropped: nothing is taken, nothing changed.
            assert_eq!(w.file.space().0, used);
            w.check(&mut rng);
        }
        w.block(&mut rng, 5, 5).unwrap();
        w.check(&mut rng);
    }

    /// Outputs far apart: positions near both ends of the tree, by a
    /// counter set far ahead.
    #[test]
    fn positions_across_the_whole_tree() {
        let mut w = World::new();
        let mut rng = Rng::new(0xfa4);
        w.block(&mut rng, 0, 70).unwrap();
        for jump in [1u64 << 12, 1 << 20, 1 << 33, (1 << 40) + 12345, (1 << 41) - 200] {
            // As if every position between had been used and its record
            // dropped: the counter moves on.
            w.set.next = jump;
            w.model.next = jump;
            w.block(&mut rng, 20, 90).unwrap();
            w.check(&mut rng);
        }
        w.reopen();
        assert_eq!(w.set.next, (1 << 41) - 110);
        for _ in 0..4 {
            w.block(&mut rng, 100, 0).unwrap();
            w.check(&mut rng);
        }
    }

    /// Power lost at every write and sync of a run of blocks: what is
    /// opened afterwards is the set after one of them, whole.
    #[test]
    fn a_crash_leaves_the_set_of_a_block() {
        let run = |crash_at: Option<u64>| -> (World, Vec<Model>, u64) {
            let mut w = World::new();
            if let Some(n) = crash_at {
                w.file.backend().crash_at(n);
            }
            let mut rng = Rng::new(0xc4a5);
            let mut states = vec![w.model.clone()];
            for (spends, adds) in [(0, 100), (20, 40), (60, 0), (10, 150), (70, 70)] {
                if w.block(&mut rng, spends, adds).is_err() {
                    break;
                }
                states.push(w.model.clone());
            }
            let ops = w.file.backend().ops();
            (w, states, ops)
        };
        let (_, states, ops) = run(None);
        assert!(ops > 12, "{ops}");
        for crash_at in 1..=ops {
            let (w, done, _) = run(Some(crash_at));
            for lost in [Lost::All, Lost::None, Lost::Some(crash_at)] {
                let file = PageFile::open(MemBackend::from_image(w.file.backend().image(lost))).unwrap();
                let seq = file.root().seq as usize;
                assert!(seq + 1 == done.len() || seq == done.len(), "crash at {crash_at}: {seq} of {}", done.len());
                let set = if seq == 0 { Outputs::EMPTY } else { Outputs::from_bytes(file.root().payload()).unwrap() };
                set.mark(&file).unwrap();
                file.seal();
                let mut after = World { file, set, model: states[seq].clone(), tip: seq as u32, history: Vec::new() };
                let mut rng = Rng::new(crash_at);
                after.check(&mut rng);
                after.block(&mut rng, 25, 25).unwrap();
                after.check(&mut rng);
                after.reopen();
            }
        }
    }

    /// The decoders of pages and roots take any bytes without panicking,
    /// and what they accept they write back the same.
    #[test]
    fn decoders_refuse_what_is_not_theirs() {
        let mut rng = Rng::new(0xdec);
        let mut w = World::new();
        w.block(&mut rng, 0, 400).unwrap();
        w.block(&mut rng, 90, 30).unwrap();
        let Child::Node { page, .. } = w.set.root else { panic!("a node") };
        let mut buf = [0u8; PAGE];
        let node = w.file.read(page, &mut buf).unwrap().to_vec();
        let children = read_node(&node, HEIGHT).unwrap();
        assert!(read_node(&node, HEIGHT - BITS).is_err(), "a node of another height");
        // A leaf's page and its entry, found on the way down.
        let (mut child, mut height) = (w.set.root, HEIGHT);
        let mut base = 0u64;
        while let Child::Node { page, .. } = child {
            let kids = read_node(w.file.read(page, &mut buf).unwrap(), height).unwrap();
            height -= BITS;
            let k = kids.iter().position(|c| *c != Child::Empty).unwrap();
            (child, base) = (kids[k], base + ((k as u64) << height));
        }
        let Child::Leaf { page, records, live, .. } = child else { panic!("a leaf") };
        let leaf = w.file.read(page, &mut buf).unwrap().to_vec();
        let mut slots = Vec::new();
        read_leaf(&leaf, base, height, records, live, &mut slots).unwrap();
        assert!(read_leaf(&leaf, base, height, records - 1, live, &mut Vec::new()).is_err());
        assert!(read_leaf(&leaf, base + (1 << height), height, records, live, &mut Vec::new()).is_ok());
        assert!(read_leaf(&leaf, base, 1, records, live, &mut Vec::new()).is_err(), "positions past the leaf");
        let mut again = Vec::new();
        write_leaf(&slots, base, &mut again);
        assert_eq!(again, leaf);
        write_node(&children, HEIGHT, &mut again);
        assert_eq!(again, node);

        let root = w.set.to_bytes();
        for bytes in [&node[..], &leaf[..], &root[..]] {
            for _ in 0..crate::test_util::fuzz_params(3000, 0).0 {
                let mut b = bytes.to_vec();
                match rng.next_u64() % 4 {
                    0 => b.truncate(rng.next_u64() as usize % (b.len() + 1)),
                    1 => b.push(rng.next_u64() as u8),
                    _ => {
                        let at = rng.next_u64() as usize % b.len();
                        b[at] = rng.next_u64() as u8;
                    }
                }
                if let Ok(kids) = read_node(&b, HEIGHT) {
                    write_node(&kids, HEIGHT, &mut again);
                    assert_eq!(again, b);
                }
                let mut s = Vec::new();
                if read_leaf(&b, base, height, records, live, &mut s).is_ok() {
                    write_leaf(&s, base, &mut again);
                    assert_eq!(again, b);
                }
                if let Ok(set) = Outputs::from_bytes(&b) {
                    assert_eq!(set.to_bytes()[..], b[..]);
                }
            }
        }
    }

    impl World {
        /// Sweeps the whole trie once, in steps of `budget` leaves, with
        /// `horizon`; returns how many steps it took.
        fn sweep_round(&mut self, budget: usize, horizon: u32) -> usize {
            let (mut from, mut steps) = (0, 0);
            loop {
                let mut txn = self.file.begin().unwrap();
                let (set, next) = self.set.sweep(&mut txn, from, budget, horizon).unwrap();
                txn.commit(&set.to_bytes()).unwrap();
                assert_eq!((set.hash(), set.count, set.next), (self.set.hash(), self.set.count, self.set.next));
                self.set = set;
                steps += 1;
                if next == 0 {
                    return steps;
                }
                assert!(next > from, "a sweep moves on");
                from = next;
            }
        }

        /// The records kept: every unspent one, and of the spent ones
        /// only such as the model has; returns how many spent are kept.
        fn check_swept(&self, spent_since: u32) -> usize {
            let mut kept = BTreeMap::new();
            self.set.for_each(&self.file, &mut |p, r, live| assert!(kept.insert(p, (*r, live)).is_none())).unwrap();
            let mut dead = 0;
            for (p, v) in &self.model.outputs {
                match kept.get(p) {
                    Some(k) => assert_eq!(k, v, "position {p}"),
                    None => assert!(!v.1, "an unspent output at {p} was dropped"),
                }
                dead += (!v.1 && kept.contains_key(p)) as usize;
            }
            assert!(kept.keys().all(|p| self.model.outputs.contains_key(p)));
            // Nothing spent at `spent_since` or later is dropped.
            for (_, _, spends) in self.history.iter().skip(spent_since.saturating_sub(1) as usize) {
                assert!(spends.iter().all(|p| kept.contains_key(p)), "a record a block may want back was dropped");
            }
            dead
        }
    }

    /// The sweep drops what is dead and old, keeps what a block still to
    /// be undone may want back, changes no hash, and gives the space back;
    /// outputs thinned out end up a few pages.
    #[test]
    fn the_sweep_drops_what_is_dead_and_old() {
        let mut w = World::new();
        let mut rng = Rng::new(0x5ee9);
        w.block(&mut rng, 0, 4000).unwrap();
        // Blocks 2 to 4 spend in the first half of the positions, blocks
        // 5 to 7 in the second: 550 each.
        for k in 0..6u64 {
            let half: Vec<u64> = w.model.live().into_iter().filter(|p| (*p >= 2000) == (k >= 3)).collect();
            let mut picked: Vec<u64> = half.iter().copied().filter(|p| (p * 7 + k) % 3 != 0).take(550).collect();
            picked.sort_unstable();
            assert_eq!(picked.len(), 550);
            w.apply(&picked, &[]).unwrap();
        }
        let before = w.file.space().0;
        assert_eq!(w.check_swept(0), 3300);

        // With the horizon at block 5, what blocks 5 to 7 spent stays.
        let steps = w.sweep_round(40, 5);
        assert!(steps > 2, "{steps} steps");
        let kept = w.check_swept(5);
        assert!((1650..2000).contains(&kept), "{kept} spent records kept");
        assert_eq!(w.set.hash(), w.model.hash());
        // Those three blocks can still be undone, and done again.
        let redo: Vec<Vec<u64>> = w.history[4..].iter().map(|h| h.2.clone()).collect();
        for _ in 0..3 {
            w.undo();
        }
        for spends in &redo {
            w.apply(spends, &[]).unwrap();
        }

        // With the horizon past every block, a leaf keeps its dead only
        // while they are under a quarter of it.
        w.sweep_round(1000, w.tip + 1);
        let kept = w.check_swept(u32::MAX);
        assert!(kept < 700 / 3, "{kept} spent records kept of 3,300");
        let after = w.file.space().0;
        assert!(after * 3 < before, "{before} units before the sweep, {after} after");
        w.reopen();

        // Spent down to a handful, the set is a handful of pages: nodes
        // whose outputs fit one page have become that page.
        while w.set.count > 30 {
            w.block(&mut rng, 200, 0).unwrap();
        }
        w.sweep_round(64, w.tip + 1);
        w.sweep_round(64, w.tip + 1);
        w.check_swept(u32::MAX);
        let (used, _) = w.file.space();
        assert!(used < crate::store::pagefile::HEADER_UNITS + 40, "{used} units for {} outputs", w.set.count);
        w.reopen();
        // And it goes on taking blocks.
        w.block(&mut rng, 10, 500).unwrap();
        w.block(&mut rng, 100, 0).unwrap();
        w.check_swept(u32::MAX);
        assert_eq!(w.set.hash(), w.model.hash());
        // Everything spent and swept: nothing is left in the file.
        while w.set.count > 0 {
            w.block(&mut rng, 300, 0).unwrap();
        }
        w.sweep_round(64, w.tip + 1);
        assert_eq!(w.set.root, Child::Empty);
        assert_eq!(w.file.space().0, crate::store::pagefile::HEADER_UNITS);
    }

    /// A file that counts what is asked of it.
    struct Counting {
        file: crate::store::backend::FileBackend,
        reads: std::sync::atomic::AtomicU64,
        read_bytes: std::sync::atomic::AtomicU64,
        writes: std::sync::atomic::AtomicU64,
        written: std::sync::atomic::AtomicU64,
    }

    impl Backend for Counting {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.read_bytes.fetch_add(buf.len() as u64, std::sync::atomic::Ordering::Relaxed);
            self.file.read_at(offset, buf)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.written.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
            self.file.write_at(offset, data)
        }
        fn sync(&self) -> io::Result<()> {
            self.file.sync()
        }
        fn len(&self) -> io::Result<u64> {
            self.file.len()
        }
    }

    /// What a worst-case block costs on a real file: 25,000 outputs
    /// spent, picked evenly among those unspent, and 25,000 made, in a
    /// set built by blocks like it.
    /// `cargo test --release --lib store::outputs::tests::cost -- --ignored --nocapture`
    /// (`TABMINER_STORE_OUTPUTS` sets the outputs made in all, 4,000,000
    /// unless given.)
    #[test]
    #[ignore = "slow: builds a set of millions of outputs on disk"]
    fn cost() {
        use std::sync::atomic::Ordering::Relaxed;
        let total: u64 = std::env::var("TABMINER_STORE_OUTPUTS").ok().and_then(|s| s.parse().ok()).unwrap_or(4_000_000);
        let dir = crate::store::testing::temp_dir("outputs-cost");
        let backend = Counting {
            file: crate::store::backend::FileBackend::open(&dir.join("state")).unwrap(),
            reads: 0.into(),
            read_bytes: 0.into(),
            writes: 0.into(),
            written: 0.into(),
        };
        let file = PageFile::create(backend).unwrap();
        let mut rng = Rng::new(0xc057);
        let mut set = Outputs::EMPTY;
        // The unspent positions, to pick spends from evenly.
        let mut live: Vec<u64> = Vec::new();
        const BLOCK: usize = 25_000;
        let mut height = 0u32;
        let mut block = |set: &mut Outputs, live: &mut Vec<u64>, spends: usize, rng: &mut Rng| {
            height += 1;
            let mut picked: Vec<u64> = (0..spends.min(live.len()))
                .map(|_| {
                    let i = rng.next_u64() as usize % live.len();
                    live.swap_remove(i)
                })
                .collect();
            picked.sort_unstable();
            let records: Vec<Record> = (0..BLOCK).map(|_| record(rng, height)).collect();
            let before = (
                file.backend().reads.load(Relaxed),
                file.backend().written.load(Relaxed),
                file.backend().read_bytes.load(Relaxed),
                file.backend().writes.load(Relaxed),
            );
            let t = std::time::Instant::now();
            let mut txn = file.begin().unwrap();
            let next = set.apply(&mut txn, height, &picked, &records).unwrap();
            let applied = t.elapsed();
            txn.commit(&next.to_bytes()).unwrap();
            let committed = t.elapsed();
            live.extend(set.next..next.next);
            *set = next;
            let b = file.backend();
            (
                picked.len(),
                applied,
                committed,
                b.reads.load(Relaxed) - before.0,
                b.read_bytes.load(Relaxed) - before.2,
                b.writes.load(Relaxed) - before.3,
                b.written.load(Relaxed) - before.1,
            )
        };
        // Built with seven of every eight outputs spent on the way, so
        // that the set is spread thin over its positions.
        let t = std::time::Instant::now();
        while set.next < total {
            block(&mut set, &mut live, BLOCK * 7 / 8, &mut rng);
        }
        let (used, end) = file.space();
        println!(
            "built in {:.1?}: {} unspent of {} positions; file {} MB, {} MB in use ({} bytes an unspent output)",
            t.elapsed(),
            set.count,
            set.next,
            end * 512 >> 20,
            used * 512 >> 20,
            used * 512 / set.count
        );
        for (name, spends) in
            [("25,000 spends and 25,000 new", BLOCK), ("the same again", BLOCK), ("25,000 new only", 0)]
        {
            let (n, applied, committed, reads, read_bytes, writes, written) =
                block(&mut set, &mut live, spends, &mut rng);
            println!(
                "{name}: {n} spent | applied in {applied:.1?}, durable in {committed:.1?} | read {reads} pages, {} MB | wrote {} MB in {writes} writes",
                read_bytes >> 20,
                written >> 20
            );
        }
        // Opening: every node read to mark what is in use.
        drop(block);
        let path = dir.join("state");
        let seq = file.root().seq;
        drop(file);
        let t = std::time::Instant::now();
        let file = PageFile::open(crate::store::backend::FileBackend::open(&path).unwrap()).unwrap();
        assert_eq!(file.root().seq, seq);
        let again = Outputs::from_bytes(file.root().payload()).unwrap();
        again.mark(&file).unwrap();
        file.seal();
        println!("opened and marked in {:.1?}; map of free space {} KB", t.elapsed(), file.space().1 / 8 / 1024);
        assert_eq!(again, set);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
