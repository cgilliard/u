//! The state: the unspent outputs, the window of blocks that can be
//! undone, and the block they are the state after, under one root record.
//!
//! A block is applied in one transaction: its spends and its outputs go
//! into the set, its record into the window, and the root record that
//! commits both names the block as the tip. Either all of it is on disk
//! or none is. Undoing the tip is the same in reverse.
//!
//! The state's root is the hash the block's header commits to: the
//! outputs' tree and the names' tree under one node. (The names are not
//! stored yet: their half is the empty tree.)
//!
//! ```text
//! root record := version (1) | height (4) | tip (32) | outputs (68) | window (6)
//!                | sweep (8)
//! ```
//!
//! With every block the sweep of the outputs goes a little further round
//! ([`super::outputs`]): twice as many leaves as the block spent outputs,
//! so that records of spent outputs are dropped as fast as they are made,
//! once the blocks that spent them have left the window.
//!
//! A [`Snapshot`] is the state after some block, held while later blocks
//! are applied: whoever reads through it sees that state, whole.

use std::io;
use std::sync::Mutex;

use super::backend::Backend;
use super::outputs::{Outputs, Record};
use super::pagefile::{PageFile, Pin, Root};
use super::sparse::{STATE_HEIGHT, empty};
use super::window::{BlockRecord, Window};
use crate::error::Error;
use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, compress, digest_from_bytes, digest_to_bytes};

const VERSION: u8 = 1;
const RECORD: usize = 1 + 4 + 32 + Outputs::BYTES + Window::BYTES + 8;
/// Leaves the sweep looks at with a block, at least.
const SWEEP_MIN: usize = 64;
/// The window's length unless another is asked for: a week of blocks.
pub const DEFAULT_WINDOW: usize = 7 * 144;

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// What a root record says the state is.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Meta {
    /// The height of the block the state is the state after; 0 with
    /// `tip` zero before any block.
    height: u32,
    tip: Digest,
    outputs: Outputs,
    window: Window,
    /// The position the sweep of the outputs has reached.
    sweep: u64,
}

impl Meta {
    fn empty() -> Meta {
        Meta { height: 0, tip: [Fp::ZERO; DIGEST], outputs: Outputs::EMPTY, window: Window::default(), sweep: 0 }
    }

    fn to_bytes(&self) -> [u8; RECORD] {
        let mut out = Vec::with_capacity(RECORD);
        out.push(VERSION);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&digest_to_bytes(&self.tip));
        out.extend_from_slice(&self.outputs.to_bytes());
        out.extend_from_slice(&self.window.to_bytes());
        out.extend_from_slice(&self.sweep.to_le_bytes());
        out.try_into().unwrap()
    }

    /// The outputs and the tip of a root record: what a reader needs.
    fn head(root: &Root) -> io::Result<(u32, Digest, Outputs)> {
        let b = root.payload();
        if b.is_empty() && root.seq == 0 {
            return Ok((0, [Fp::ZERO; DIGEST], Outputs::EMPTY));
        }
        if b.len() != RECORD || b[0] != VERSION {
            return Err(corrupt("the state's root record is not one"));
        }
        let height = u32::from_le_bytes(b[1..5].try_into().unwrap());
        let tip = digest_from_bytes(&b[5..37]).ok_or_else(|| corrupt("the state's tip is not a digest"))?;
        Ok((height, tip, Outputs::from_bytes(&b[37..37 + Outputs::BYTES])?))
    }
}

/// The state's root: the outputs' tree and the names' under one node.
fn state_root(outputs: &Outputs) -> Digest {
    compress(&outputs.hash(), empty(STATE_HEIGHT - 1))
}

/// A block, as the state takes it.
pub struct BlockEdit<'a> {
    pub height: u32,
    /// The block's id.
    pub block: Digest,
    /// The positions of the outputs it spends, ascending.
    pub spends: &'a [u64],
    /// The outputs it makes, in order.
    pub outputs: &'a [Record],
    /// The state root its header commits to. If given and the state after
    /// the block is another, the block is refused.
    pub state_root: Option<Digest>,
}

/// The state, in a file of pages.
pub struct State<B: Backend> {
    file: PageFile<B>,
    meta: Mutex<Meta>,
    /// Blocks whose records the window keeps.
    keep: usize,
}

impl<B: Backend> State<B> {
    /// Opens the state in `backend`, making an empty one if there is
    /// none, with a window of `keep` blocks. Opening reads every node of
    /// the outputs' trie and every page of the window, to know what of
    /// the file is in use.
    pub fn open(backend: B, keep: usize) -> io::Result<State<B>> {
        let file = PageFile::open_or_create(backend)?;
        let root = file.root();
        let meta = if root.payload().is_empty() && root.seq == 0 {
            Meta::empty()
        } else {
            let (height, tip, outputs) = Meta::head(&root)?;
            let rest = &root.payload()[RECORD - Window::BYTES - 8..];
            let window = Window::read(&file, &rest[..Window::BYTES])?;
            let sweep = u64::from_le_bytes(rest[Window::BYTES..].try_into().unwrap());
            outputs.mark(&file)?;
            window.mark(&file)?;
            Meta { height, tip, outputs, window, sweep }
        };
        file.seal();
        Ok(State { file, meta: Mutex::new(meta), keep })
    }

    fn meta(&self) -> std::sync::MutexGuard<'_, Meta> {
        self.meta.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn file(&self) -> &PageFile<B> {
        &self.file
    }

    /// The height and id of the block the state is the state after.
    pub fn tip(&self) -> (u32, Digest) {
        let m = self.meta();
        (m.height, m.tip)
    }

    /// The state's root.
    pub fn root(&self) -> Digest {
        state_root(&self.meta().outputs)
    }

    /// The height of the oldest block that can be undone, if any can.
    pub fn oldest_undo(&self) -> Option<u32> {
        self.meta().window.oldest()
    }

    /// The state as it is now, held: see [`Snapshot`].
    pub fn snapshot(&self) -> io::Result<Snapshot<'_, B>> {
        let pin = self.file.pin();
        let (height, tip, outputs) = Meta::head(pin.root())?;
        Ok(Snapshot { pin, height, tip, outputs })
    }

    /// Applies the next block, and returns the state's root after it.
    /// Refused, with the state as it was: a block that spends what is not
    /// there ([`Error::NoSuchOutput`]) or whose header commits to another
    /// state ([`Error::StateRoot`]).
    pub fn apply(&self, block: &BlockEdit<'_>) -> Result<Digest, Error> {
        let mut txn = self.file.begin()?;
        let mut meta = self.meta().clone();
        assert_eq!(block.height, meta.height + 1, "blocks are applied in order");
        let first_new = meta.outputs.next;
        meta.outputs = meta.outputs.apply(&mut txn, block.height, block.spends, block.outputs)?;
        let root = state_root(&meta.outputs);
        if block.state_root.is_some_and(|want| want != root) {
            return Err(Error::StateRoot);
        }
        let record = BlockRecord {
            height: block.height,
            block: block.block,
            before: meta.tip,
            first_new,
            spends: block.spends.to_vec(),
        };
        meta.window.push(&mut txn, &record, self.keep)?;
        // What was spent before the oldest block of the window is dead
        // for good.
        let horizon = (block.height + 1).saturating_sub(self.keep as u32);
        let budget = SWEEP_MIN.max(2 * block.spends.len());
        (meta.outputs, meta.sweep) = meta.outputs.sweep(&mut txn, meta.sweep, budget, horizon)?;
        (meta.height, meta.tip) = (block.height, block.block);
        txn.commit(&meta.to_bytes())?;
        *self.meta() = meta;
        Ok(root)
    }

    /// Undoes the tip: the state is again the one after the block before
    /// it, whose height and id are returned. [`Error::NoUndoRecord`] if
    /// the tip's record is no longer kept.
    pub fn undo(&self) -> Result<(u32, Digest), Error> {
        let mut txn = self.file.begin()?;
        let mut meta = self.meta().clone();
        let record = meta.window.pop(&mut txn)?.ok_or(Error::NoUndoRecord)?;
        if record.height != meta.height || record.block != meta.tip {
            return Err(corrupt("the newest record is not the tip's").into());
        }
        meta.outputs = meta.outputs.undo(&mut txn, record.height - 1, &record.spends, record.first_new)?;
        (meta.height, meta.tip) = (record.height - 1, record.before);
        txn.commit(&meta.to_bytes())?;
        let tip = (meta.height, meta.tip);
        *self.meta() = meta;
        Ok(tip)
    }
}

/// The state after one block, held: reads through it see that state
/// however many blocks are applied or undone meanwhile. While it is held
/// the pages of that state are not reused, so it should not be held long.
pub struct Snapshot<'a, B: Backend> {
    pin: Pin<'a, B>,
    height: u32,
    tip: Digest,
    outputs: Outputs,
}

impl<B: Backend> Snapshot<'_, B> {
    pub fn tip(&self) -> (u32, Digest) {
        (self.height, self.tip)
    }

    pub fn root(&self) -> Digest {
        state_root(&self.outputs)
    }

    /// The outputs: their count, the next position, and their tree's root.
    pub fn outputs(&self) -> &Outputs {
        &self.outputs
    }

    /// The output at `position` and whether it is unspent.
    pub fn output(&self, position: u64) -> io::Result<Option<(Record, bool)>> {
        self.outputs.get(&self.pin, position)
    }

    /// Whether `position` holds an unspent output.
    pub fn is_unspent(&self, position: u64) -> io::Result<bool> {
        Ok(self.output(position)?.is_some_and(|(_, live)| live))
    }

    /// The path of `position` up to the state's root: its leaf, and the
    /// sibling at each of the [`STATE_HEIGHT`] levels.
    pub fn prove(&self, position: u64) -> io::Result<(Digest, [Digest; STATE_HEIGHT])> {
        let (leaf, below) = self.outputs.prove(&self.pin, position)?;
        let mut path = [*empty(STATE_HEIGHT - 1); STATE_HEIGHT];
        path[..STATE_HEIGHT - 1].copy_from_slice(&below);
        Ok((leaf, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sparse::{EMPTY, root_of_path};
    use crate::store::testing::{Lost, MemBackend, temp_dir};
    use crate::test_util::Rng;

    fn record(rng: &mut Rng, height: u32) -> Record {
        Record {
            commitment: core::array::from_fn(|_| rng.fp()),
            memo: core::array::from_fn(|_| rng.fp()),
            amount: rng.next_u64(),
            height,
        }
    }

    fn id(height: u32, fork: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(height * 1000 + fork * 10 + i as u32))
    }

    /// A chain of blocks made as they are applied: what each spent and
    /// made, and the root after it.
    struct Chain {
        rng: Rng,
        /// Unspent positions.
        live: Vec<u64>,
        next: u64,
        /// Per block: its id, spends, outputs, and the root after it.
        blocks: Vec<(Digest, Vec<u64>, Vec<Record>, Digest)>,
    }

    impl Chain {
        fn new(seed: u64) -> Chain {
            Chain { rng: Rng::new(seed), live: Vec::new(), next: 0, blocks: Vec::new() }
        }

        /// Makes the next block and applies it to `state`.
        fn extend<B: Backend>(
            &mut self,
            state: &State<B>,
            spends: usize,
            adds: usize,
            fork: u32,
        ) -> Result<Digest, Error> {
            let height = self.blocks.len() as u32 + 1;
            let mut picked: Vec<u64> = (0..spends.min(self.live.len()))
                .map(|_| {
                    let i = self.rng.next_u64() as usize % self.live.len();
                    self.live.swap_remove(i)
                })
                .collect();
            picked.sort_unstable();
            let outputs: Vec<Record> = (0..adds).map(|_| record(&mut self.rng, height)).collect();
            let block =
                BlockEdit { height, block: id(height, fork), spends: &picked, outputs: &outputs, state_root: None };
            let root = state.apply(&block)?;
            self.live.extend(self.next..self.next + adds as u64);
            self.next += adds as u64;
            self.blocks.push((id(height, fork), picked, outputs, root));
            Ok(root)
        }

        /// Forgets the last block, as the state does when it undoes it.
        fn forget(&mut self) {
            let (_, spends, outputs, _) = self.blocks.pop().unwrap();
            self.next -= outputs.len() as u64;
            self.live.retain(|p| *p < self.next);
            self.live.extend(spends);
        }

        fn tip(&self) -> (u32, Digest) {
            (self.blocks.len() as u32, self.blocks.last().map_or([Fp::ZERO; DIGEST], |b| b.0))
        }
    }

    #[test]
    fn an_empty_state() {
        let state = State::open(MemBackend::new(), 10).unwrap();
        assert_eq!(state.tip(), (0, [Fp::ZERO; DIGEST]));
        assert_eq!(state.root(), *empty(STATE_HEIGHT));
        assert_eq!(state.oldest_undo(), None);
        assert_eq!(state.undo().err(), Some(Error::NoUndoRecord));
        let snap = state.snapshot().unwrap();
        assert_eq!((snap.tip().0, snap.root()), (0, *empty(STATE_HEIGHT)));
        assert_eq!(snap.output(0).unwrap(), None);
        let (leaf, path) = snap.prove(5).unwrap();
        assert_eq!(root_of_path(5, &leaf, &path), *empty(STATE_HEIGHT));
        // Opened again before any block, it is still empty.
        let again = State::open(MemBackend::from_image(state.file().backend().image(Lost::All)), 10).unwrap();
        assert_eq!(again.root(), *empty(STATE_HEIGHT));
    }

    /// Blocks applied, the tip undone and another chain taken from there,
    /// the state opened again between: tips, roots and paths all agree
    /// with the chain, and undoing returns to the root there was.
    #[test]
    fn blocks_are_applied_and_undone() {
        let mut chain = Chain::new(0x57a7e);
        let mut state = State::open(MemBackend::new(), 8).unwrap();
        for (spends, adds) in [(0, 300), (40, 100), (100, 20), (0, 0), (150, 500), (300, 300), (20, 0)] {
            let root = chain.extend(&state, spends, adds, 0).unwrap();
            assert_eq!((state.root(), state.tip()), (root, chain.tip()));
        }
        assert_eq!(state.oldest_undo(), Some(1));
        // A path of an unspent output, of a spent one, and of none.
        let snap = state.snapshot().unwrap();
        let spent = chain.blocks[1].1[0];
        for (position, unspent) in [(chain.live[0], true), (spent, false), (chain.next, false)] {
            let (leaf, path) = snap.prove(position).unwrap();
            assert_eq!(root_of_path(position, &leaf, &path), state.root(), "position {position}");
            assert_eq!(leaf != EMPTY, unspent);
            assert_eq!(snap.is_unspent(position).unwrap(), unspent);
        }
        drop(snap);

        // A reorganisation three blocks deep.
        let roots: Vec<Digest> = chain.blocks.iter().map(|b| b.3).collect();
        for back in 1..=3 {
            let tip = state.undo().unwrap();
            chain.forget();
            assert_eq!(tip, chain.tip());
            assert_eq!(state.root(), roots[roots.len() - 1 - back]);
        }
        // Opened again in the middle of it.
        state = State::open(MemBackend::from_image(state.file().backend().image(Lost::All)), 8).unwrap();
        assert_eq!((state.tip(), state.root()), (chain.tip(), roots[3]));
        for (spends, adds) in [(10, 10), (200, 50), (0, 400), (90, 90)] {
            let root = chain.extend(&state, spends, adds, 1).unwrap();
            assert_eq!(state.root(), root);
        }
        assert_eq!(state.tip(), (8, id(8, 1)));
        // The other chain's blocks at those heights gave other roots.
        assert_ne!(chain.blocks[4].3, roots[4]);

        // Everything undone, back to nothing: all eight are in the window.
        while state.tip().0 > 0 {
            state.undo().unwrap();
            chain.forget();
            assert_eq!(state.tip(), chain.tip());
        }
        assert_eq!(state.root(), *empty(STATE_HEIGHT));
        assert_eq!(state.file().space().0, crate::store::pagefile::HEADER_UNITS);
    }

    /// A block is refused whole: one that spends what is not there, and
    /// one whose header commits to another state.
    #[test]
    fn a_refused_block_changes_nothing() {
        let mut chain = Chain::new(0xbad5);
        let state = State::open(MemBackend::new(), 4).unwrap();
        chain.extend(&state, 0, 200, 0).unwrap();
        chain.extend(&state, 50, 50, 0).unwrap();
        let (root, tip, used) = (state.root(), state.tip(), state.file().space().0);
        let spent = chain.blocks[1].1[3];
        let outputs = [record(&mut chain.rng, 3)];
        let block = |spends: &'static [u64], state_root| BlockEdit {
            height: 3,
            block: id(3, 0),
            spends,
            outputs: &outputs,
            state_root,
        };
        let gone: &'static [u64] = Box::leak(vec![spent].into_boxed_slice());
        assert_eq!(state.apply(&block(gone, None)).err(), Some(Error::NoSuchOutput(spent)));
        assert_eq!(state.apply(&block(&[], Some(root))).err(), Some(Error::StateRoot));
        assert_eq!((state.root(), state.tip(), state.file().space().0), (root, tip, used));
        // With the root the block really leaves, it is taken.
        let after = state.apply(&block(&[], None)).unwrap();
        state.undo().unwrap();
        assert_eq!(state.apply(&block(&[], Some(after))).unwrap(), after);
    }

    /// Only the window's blocks can be undone, and the records of older
    /// ones are gone from the file.
    #[test]
    fn the_window_bounds_what_can_be_undone() {
        let mut chain = Chain::new(0x1d0);
        let state = State::open(MemBackend::new(), 3).unwrap();
        for _ in 0..10 {
            chain.extend(&state, 30, 60, 0).unwrap();
        }
        assert_eq!(state.oldest_undo(), Some(8));
        for height in (7..10).rev() {
            assert_eq!(state.undo().unwrap().0, height);
        }
        assert_eq!(state.undo().err(), Some(Error::NoUndoRecord));
        assert_eq!(state.tip().0, 7);
        // A window of no blocks: nothing can be undone.
        let none = State::open(MemBackend::new(), 0).unwrap();
        let mut chain = Chain::new(1);
        chain.extend(&none, 0, 5, 0).unwrap();
        assert_eq!(none.undo().err(), Some(Error::NoUndoRecord));
    }

    /// A snapshot goes on reading the state it was taken of.
    #[test]
    fn a_snapshot_is_the_state_it_was_taken_of() {
        let mut chain = Chain::new(0x54a9);
        let state = State::open(MemBackend::new(), 4).unwrap();
        chain.extend(&state, 0, 400, 0).unwrap();
        chain.extend(&state, 100, 100, 0).unwrap();
        let snap = state.snapshot().unwrap();
        let (root, live) = (state.root(), chain.live.clone());
        for _ in 0..6 {
            chain.extend(&state, 80, 120, 0).unwrap();
        }
        state.undo().unwrap();
        assert_ne!(state.root(), root);
        assert_eq!((snap.root(), snap.tip()), (root, (2, id(2, 0))));
        assert_eq!(snap.outputs().count as usize, live.len());
        for p in live.iter().step_by(7) {
            assert!(snap.is_unspent(*p).unwrap(), "position {p}");
            let (leaf, path) = snap.prove(*p).unwrap();
            assert_eq!(root_of_path(*p, &leaf, &path), root);
        }
    }

    /// Power lost at every write and sync of a chain with a
    /// reorganisation in it: what is opened afterwards is the state after
    /// one of its steps, and goes on from there.
    #[test]
    fn a_crash_leaves_the_state_after_a_block() {
        // Each step applies a block or undoes the tip.
        let steps: &[Option<(usize, usize)>] = &[
            Some((0, 120)),
            Some((30, 40)),
            Some((50, 0)),
            None,
            None,
            Some((20, 60)),
            Some((40, 40)),
            None,
            Some((5, 90)),
        ];
        let run = |crash_at: Option<u64>| {
            let backend = MemBackend::new();
            if let Some(n) = crash_at {
                backend.crash_at(n);
            }
            let mut chain = Chain::new(0xc4a5);
            // The tip and root after each step that completed.
            let mut done = Vec::new();
            let state = match State::open(backend, 4) {
                Ok(state) => state,
                Err(_) => return (None, done),
            };
            done.push((state.tip(), state.root()));
            for (fork, step) in steps.iter().enumerate() {
                let ok = match step {
                    Some((spends, adds)) => chain.extend(&state, *spends, *adds, fork as u32).is_ok(),
                    None => {
                        let undone = state.undo().is_ok();
                        if undone {
                            chain.forget();
                        }
                        undone
                    }
                };
                if !ok {
                    break;
                }
                done.push((state.tip(), state.root()));
            }
            (Some(state), done)
        };
        let (whole, all) = run(None);
        let ops = whole.unwrap().file().backend().ops();
        assert_eq!(all.len(), steps.len() + 1);
        for crash_at in 1..=ops {
            let (state, done) = run(Some(crash_at));
            let Some(state) = state else { continue };
            for lost in [Lost::All, Lost::None, Lost::Some(crash_at)] {
                let again = State::open(MemBackend::from_image(state.file().backend().image(lost)), 4).unwrap();
                let at = (again.tip(), again.root());
                // The last step that returned, or the one under way.
                assert!(
                    at == all[done.len() - 1] || all.get(done.len()) == Some(&at),
                    "crash at {crash_at} of {ops}, {lost:?}: {:?} after {} steps",
                    at.0,
                    done.len() - 1
                );
                // It goes on: a block, and that block undone.
                let height = again.tip().0 + 1;
                let outputs = [record(&mut Rng::new(crash_at), height)];
                let block =
                    BlockEdit { height, block: id(height, 99), spends: &[], outputs: &outputs, state_root: None };
                again.apply(&block).unwrap();
                assert_eq!(again.undo().unwrap(), at.0);
                assert_eq!(again.root(), at.1);
            }
        }
    }

    /// Over a long chain whose blocks spend as much as they make, the
    /// file stays the size of what is unspent and what the window keeps:
    /// the sweep drops the rest as it goes. And at any point the whole
    /// window can still be undone.
    #[test]
    fn the_file_does_not_grow_with_the_chain() {
        let mut chain = Chain::new(0x9a0);
        let keep = 5;
        let state = State::open(MemBackend::new(), keep).unwrap();
        chain.extend(&state, 0, 3000, 0).unwrap();
        let mut sizes = Vec::new();
        for round in 0..60 {
            chain.extend(&state, 300, 300, 0).unwrap();
            sizes.push(state.file().space().0);
            if round % 20 == 19 {
                // The whole window undone and made again: the records the
                // sweep dropped were none of those blocks'.
                let roots: Vec<Digest> = chain.blocks.iter().map(|b| b.3).collect();
                for back in 1..=keep {
                    state.undo().unwrap();
                    chain.forget();
                    assert_eq!(state.root(), roots[roots.len() - 1 - back]);
                }
                assert_eq!(state.undo().err(), Some(Error::NoUndoRecord));
                for _ in 0..keep {
                    chain.extend(&state, 300, 300, 1).unwrap();
                }
            }
        }
        // 18,000 outputs were spent on the way; 3,000 are unspent.
        assert_eq!(state.snapshot().unwrap().outputs().count, 3000);
        let (early, late) = (sizes[15], *sizes.last().unwrap());
        assert!(late < early + early / 3, "{early} units after 16 blocks, {late} after 60");
        assert!(late * 512 < 3000 * 66 * 4, "{late} units for 3,000 unspent outputs and a window of five blocks");
        // Opened again, every unit in use is reached.
        let again = State::open(MemBackend::from_image(state.file().backend().image(Lost::All)), keep).unwrap();
        assert_eq!(again.file().space().0, state.file().space().0);
        assert_eq!(again.root(), state.root());
    }

    /// On a real file, closed and opened.
    #[test]
    fn on_a_real_file() {
        use crate::store::backend::{DirLock, FileBackend};
        let dir = temp_dir("state");
        let _lock = DirLock::acquire(&dir).unwrap();
        let path = dir.join("state");
        let mut chain = Chain::new(0xf11e);
        let state = State::open(FileBackend::open(&path).unwrap(), DEFAULT_WINDOW).unwrap();
        for _ in 0..12 {
            chain.extend(&state, 60, 200, 0).unwrap();
        }
        let (tip, root) = (state.tip(), state.root());
        drop(state);
        let state = State::open(FileBackend::open(&path).unwrap(), DEFAULT_WINDOW).unwrap();
        assert_eq!((state.tip(), state.root()), (tip, root));
        assert_eq!(state.oldest_undo(), Some(1));
        state.undo().unwrap();
        chain.forget();
        chain.extend(&state, 10, 10, 1).unwrap();
        assert_eq!(state.tip(), (12, id(12, 1)));
        drop(state);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
