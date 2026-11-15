//! The window: for each of the last blocks, what is needed to undo it.
//!
//! A block spends outputs and makes outputs. Undoing it unspends the
//! first and removes the second, and the set of outputs keeps a spent
//! output's record ([`super::outputs`]), so all that must be kept of a
//! block is which positions it spent and where its own outputs began:
//! a few bytes a spend. That is a block's record here, kept for the
//! window's length of blocks and then dropped.
//!
//! The records are pages of the state's file like any others, written in
//! the block's transaction and reached from the root record through one
//! page that lists them. Only that list is held in memory (sixteen bytes
//! a block); a record is read when its block is undone.
//!
//! ```text
//! record page := next page (6) | bytes
//! record      := height (4) | block (32) | block before (32)
//!                | first new position (8) | spends (4) | distance (varint) ...
//! list page   := blocks (2) | (height (4) | first page (6)) ...
//! ```

use std::collections::VecDeque;
use std::io;

use super::backend::Backend;
use super::pagefile::{Extent, MAX_UNITS, PageFile, ReadPages, Txn, UNIT};
use crate::hash::Digest;
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};

/// The most blocks a window holds: what one page lists.
pub const MAX_BLOCKS: usize = (Extent::capacity(MAX_UNITS) - 2) / 10;
/// Bytes of a record a page holds, after the next page's place.
const CHUNK: usize = Extent::capacity(MAX_UNITS) - 6;
const NONE: Extent = Extent { start: 0, units: 0 };

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

fn put_extent(out: &mut Vec<u8>, e: Extent) {
    out.extend_from_slice(&e.start.to_le_bytes()[..5]);
    out.push(e.units as u8);
}

fn get_extent(b: &[u8]) -> Extent {
    let mut start = [0u8; 8];
    start[..5].copy_from_slice(&b[..5]);
    Extent { start: u64::from_le_bytes(start), units: b[5] as u32 }
}

/// What undoing a block needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockRecord {
    pub height: u32,
    /// The block's id.
    pub block: Digest,
    /// The id of the block before it: the tip once this one is undone.
    pub before: Digest,
    /// The position its first new output took: the next position before
    /// it.
    pub first_new: u64,
    /// The positions it spent, ascending.
    pub spends: Vec<u64>,
}

impl BlockRecord {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + 3 * self.spends.len());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&digest_to_bytes(&self.block));
        out.extend_from_slice(&digest_to_bytes(&self.before));
        out.extend_from_slice(&self.first_new.to_le_bytes());
        out.extend_from_slice(&(self.spends.len() as u32).to_le_bytes());
        let mut prev = 0;
        for p in &self.spends {
            let mut x = p - prev;
            while x >= 0x80 {
                out.push(x as u8 | 0x80);
                x >>= 7;
            }
            out.push(x as u8);
            prev = *p;
        }
        out
    }

    fn from_bytes(b: &[u8]) -> io::Result<BlockRecord> {
        let bad = || corrupt("a block's record is not one");
        let (head, mut b) = b.split_at_checked(80).ok_or_else(bad)?;
        let count = u32::from_le_bytes(head[76..80].try_into().unwrap()) as usize;
        if count > b.len() {
            return Err(bad());
        }
        let mut spends = Vec::with_capacity(count);
        let mut prev = 0u64;
        for i in 0..count {
            let (mut x, mut shift) = (0u64, 0);
            loop {
                let (&byte, rest) = b.split_first().ok_or_else(bad)?;
                b = rest;
                if shift > 56 {
                    return Err(bad());
                }
                x |= u64::from(byte & 0x7f) << shift;
                shift += 7;
                if byte < 0x80 {
                    break;
                }
            }
            // Positions ascend: no distance but the first is zero.
            if i > 0 && x == 0 {
                return Err(bad());
            }
            prev = prev.checked_add(x).ok_or_else(bad)?;
            spends.push(prev);
        }
        if !b.is_empty() {
            return Err(bad());
        }
        Ok(BlockRecord {
            height: u32::from_le_bytes(head[..4].try_into().unwrap()),
            block: digest_from_bytes(&head[4..36]).ok_or_else(bad)?,
            before: digest_from_bytes(&head[36..68]).ok_or_else(bad)?,
            first_new: u64::from_le_bytes(head[68..76].try_into().unwrap()),
            spends,
        })
    }

    /// Writes the record as a chain of pages and returns the first.
    fn write<B: Backend>(&self, txn: &mut Txn<'_, B>) -> io::Result<Extent> {
        let bytes = self.to_bytes();
        // The last page first: each names the one after it.
        let mut next = NONE;
        let mut page = Vec::with_capacity(6 + CHUNK.min(bytes.len()));
        for chunk in bytes.chunks(CHUNK).rev() {
            page.clear();
            put_extent(&mut page, next);
            page.extend_from_slice(chunk);
            next = txn.write(&page)?;
        }
        Ok(next)
    }

    /// Reads the record whose first page is `first`, and its pages.
    fn read(pages: &impl ReadPages, first: Extent) -> io::Result<(BlockRecord, Vec<Extent>)> {
        let (mut bytes, mut chain) = (Vec::new(), Vec::new());
        each_page(pages, first, &mut |e, data| {
            chain.push(e);
            bytes.extend_from_slice(data);
        })?;
        Ok((BlockRecord::from_bytes(&bytes)?, chain))
    }
}

/// Calls `f` with each page of the chain from `first`, and its bytes.
fn each_page(pages: &impl ReadPages, first: Extent, f: &mut dyn FnMut(Extent, &[u8])) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_UNITS as usize * UNIT];
    let mut at = first;
    // A chain is a few pages: a record of a block.
    for _ in 0..1024 {
        let payload = pages.read_page(at, &mut buf)?;
        let (next, data) = payload.split_at_checked(6).ok_or_else(|| corrupt("a record's page is not one"))?;
        f(at, data);
        at = get_extent(next);
        if at.units == 0 {
            return Ok(());
        }
    }
    Err(corrupt("a record's pages do not end"))
}

/// The records of the last blocks, oldest first: the list in memory, the
/// records in the file.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Window {
    blocks: VecDeque<(u32, Extent)>,
    /// The page the list is written in, if it is not empty.
    list: Option<Extent>,
}

impl Window {
    /// Bytes of a window's place in the root record: its list's page.
    pub const BYTES: usize = 6;

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The height of the oldest block that can be undone.
    pub fn oldest(&self) -> Option<u32> {
        self.blocks.front().map(|b| b.0)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = Vec::with_capacity(6);
        put_extent(&mut out, self.list.unwrap_or(NONE));
        out.try_into().unwrap()
    }

    /// Reads the window whose list's page the root record gives.
    pub fn read(pages: &impl ReadPages, b: &[u8]) -> io::Result<Window> {
        let bad = || corrupt("the window's list is not one");
        let list = get_extent(b.get(..6).ok_or_else(bad)?);
        if list.units == 0 {
            return Ok(Window::default());
        }
        let mut buf = vec![0u8; MAX_UNITS as usize * UNIT];
        let payload = pages.read_page(list, &mut buf)?;
        let (count, body) = payload.split_at_checked(2).ok_or_else(bad)?;
        let count = u16::from_le_bytes([count[0], count[1]]) as usize;
        if count == 0 || body.len() != 10 * count {
            return Err(bad());
        }
        let mut blocks = VecDeque::with_capacity(count);
        for e in body.chunks_exact(10) {
            let (height, page) = (u32::from_le_bytes(e[..4].try_into().unwrap()), get_extent(&e[4..]));
            // Heights follow one another.
            if page.units == 0 || blocks.back().is_some_and(|b: &(u32, Extent)| b.0 + 1 != height) {
                return Err(bad());
            }
            blocks.push_back((height, page));
        }
        Ok(Window { blocks, list: Some(list) })
    }

    /// Marks every page of the window in `file`'s map of free space.
    pub fn mark<B: Backend>(&self, file: &PageFile<B>) -> io::Result<()> {
        if let Some(list) = self.list {
            file.mark(list)?;
        }
        for (_, first) in &self.blocks {
            let mut chain = Vec::new();
            each_page(file, *first, &mut |e, _| chain.push(e))?;
            chain.into_iter().try_for_each(|e| file.mark(e))?;
        }
        Ok(())
    }

    /// Frees a record's pages.
    fn drop_record<B: Backend>(txn: &mut Txn<'_, B>, first: Extent) -> io::Result<()> {
        let mut chain = Vec::new();
        each_page(txn, first, &mut |e, _| chain.push(e))?;
        chain.into_iter().for_each(|e| txn.free(e));
        Ok(())
    }

    /// Writes the list anew.
    fn write_list<B: Backend>(&mut self, txn: &mut Txn<'_, B>) -> io::Result<()> {
        if let Some(old) = self.list.take() {
            txn.free(old);
        }
        if self.blocks.is_empty() {
            return Ok(());
        }
        let mut page = Vec::with_capacity(2 + 10 * self.blocks.len());
        page.extend_from_slice(&(self.blocks.len() as u16).to_le_bytes());
        for (height, first) in &self.blocks {
            page.extend_from_slice(&height.to_le_bytes());
            put_extent(&mut page, *first);
        }
        self.list = Some(txn.write(&page)?);
        Ok(())
    }

    /// Adds the newest block's record, and drops those of blocks more
    /// than `keep` back.
    pub fn push<B: Backend>(&mut self, txn: &mut Txn<'_, B>, record: &BlockRecord, keep: usize) -> io::Result<()> {
        assert!(keep <= MAX_BLOCKS, "a window holds at most {MAX_BLOCKS} blocks");
        debug_assert!(self.blocks.back().is_none_or(|b| b.0 + 1 == record.height));
        if keep > 0 {
            let first = record.write(txn)?;
            self.blocks.push_back((record.height, first));
        }
        while self.blocks.len() > keep {
            let (_, first) = self.blocks.pop_front().unwrap();
            Window::drop_record(txn, first)?;
        }
        self.write_list(txn)
    }

    /// Takes the newest block's record out, to undo the block with:
    /// `None` if the window is empty.
    pub fn pop<B: Backend>(&mut self, txn: &mut Txn<'_, B>) -> io::Result<Option<BlockRecord>> {
        let Some((_, first)) = self.blocks.pop_back() else { return Ok(None) };
        let (record, chain) = BlockRecord::read(txn, first)?;
        chain.into_iter().for_each(|e| txn.free(e));
        self.write_list(txn)?;
        Ok(Some(record))
    }

    /// The record of the block at `height`, if the window has it.
    pub fn get(&self, pages: &impl ReadPages, height: u32) -> io::Result<Option<BlockRecord>> {
        let Some(oldest) = self.oldest() else { return Ok(None) };
        let Some((_, first)) = height.checked_sub(oldest).and_then(|i| self.blocks.get(i as usize)) else {
            return Ok(None);
        };
        Ok(Some(BlockRecord::read(pages, *first)?.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::Fp;
    use crate::store::testing::{Lost, MemBackend};
    use crate::test_util::Rng;

    fn record(rng: &mut Rng, height: u32, spends: usize) -> BlockRecord {
        let mut at = 0u64;
        let spends = (0..spends)
            .map(|i| {
                at += if i == 0 { rng.next_u64() % 3 } else { 1 + rng.next_u64() % 100_000 };
                at
            })
            .collect();
        BlockRecord {
            height,
            block: [Fp::new(height); 8],
            before: [Fp::new(height - 1); 8],
            first_new: rng.next_u64() >> 24,
            spends,
        }
    }

    #[test]
    fn records_are_read_as_written() {
        let mut rng = Rng::new(0x41d0);
        for spends in [0usize, 1, 2, 300, 25_000, 60_000] {
            let r = record(&mut rng, 7, spends);
            let bytes = r.to_bytes();
            assert_eq!(BlockRecord::from_bytes(&bytes).unwrap(), r);
            // About three bytes a spend.
            assert!(bytes.len() <= 80 + 3 * spends, "{} bytes for {spends} spends", bytes.len());
            for cut in [0, 79, bytes.len().saturating_sub(1)] {
                if cut < bytes.len() {
                    assert!(BlockRecord::from_bytes(&bytes[..cut]).is_err());
                }
            }
            let mut longer = bytes.clone();
            longer.push(1);
            assert!(BlockRecord::from_bytes(&longer).is_err());
        }
        // Positions at both ends of what a position can be.
        let wide = BlockRecord { spends: vec![0, 1, (1 << 41) - 1], ..record(&mut rng, 3, 0) };
        assert_eq!(BlockRecord::from_bytes(&wide.to_bytes()).unwrap(), wide);
        // Any byte changed: refused, or another record, never a panic.
        let bytes = record(&mut rng, 5, 40).to_bytes();
        for _ in 0..2000 {
            let mut b = bytes.clone();
            let at = rng.next_u64() as usize % b.len();
            b[at] = rng.next_u64() as u8;
            let _ = BlockRecord::from_bytes(&b);
        }
    }

    /// A window of five blocks through thirty: the newest five are had,
    /// popped newest first, and nothing older; what is dropped is freed.
    #[test]
    fn a_window_keeps_the_last_blocks() {
        let file = PageFile::create(MemBackend::new()).unwrap();
        let mut rng = Rng::new(0x51de);
        let mut window = Window::default();
        let mut records = Vec::new();
        let keep = 5;
        for height in 1..=30u32 {
            // Some records of several pages.
            let r = record(&mut rng, height, if height % 7 == 0 { 70_000 } else { 50 * height as usize });
            let mut txn = file.begin().unwrap();
            window.push(&mut txn, &r, keep).unwrap();
            txn.commit(&window.to_bytes()).unwrap();
            records.push(r);
            assert_eq!(window.len(), (height as usize).min(keep));
            assert_eq!(window.oldest(), Some(height.saturating_sub(keep as u32 - 1).max(1)));
            // Read from the file alone, it is the same window.
            let read = Window::read(&file, file.root().payload()).unwrap();
            assert_eq!(read, window);
            for h in 0..=height + 1 {
                let want = (h + keep as u32 > height && h >= 1 && h <= height).then(|| records[h as usize - 1].clone());
                assert_eq!(window.get(&file, h).unwrap(), want, "block {h} at {height}");
            }
        }
        // Opened again: every unit in use is one the window reaches.
        let again = PageFile::open(MemBackend::from_image(file.backend().image(Lost::All))).unwrap();
        let read = Window::read(&again, again.root().payload()).unwrap();
        read.mark(&again).unwrap();
        again.seal();
        assert_eq!(again.space().0, file.space().0);
        // Popped newest first, then there is none.
        for height in (26..=30u32).rev() {
            let mut txn = file.begin().unwrap();
            assert_eq!(window.pop(&mut txn).unwrap().as_ref(), Some(&records[height as usize - 1]));
            txn.commit(&window.to_bytes()).unwrap();
        }
        let mut txn = file.begin().unwrap();
        assert_eq!(window.pop(&mut txn).unwrap(), None);
        txn.commit(&window.to_bytes()).unwrap();
        assert!(window.is_empty());
        assert_eq!(file.space().0, crate::store::pagefile::HEADER_UNITS);
        assert_eq!(Window::read(&file, file.root().payload()).unwrap(), Window::default());
        // A window of no blocks keeps nothing.
        let mut txn = file.begin().unwrap();
        window.push(&mut txn, &records[0], 0).unwrap();
        assert!(window.is_empty() && txn.written() == 0);
    }

    #[test]
    fn the_most_blocks_fit_one_list() {
        assert_eq!(MAX_BLOCKS, 6552);
        const { assert!(MAX_BLOCKS >= 7 * 144) };
    }
}
