//! Memory-hard proof of work in the style of Ethash, seeded by a text that
//! the chain exists to preserve.
//!
//! The seed is the American King James Bible as the gzip file
//! `resources/akjv.txt.gz` ([`SEED_TEXT_LEN`] bytes), embedded in the
//! binary and used as it is: nothing is decompressed. Its bytes are read in
//! [`WINDOW`]-byte windows on 24-byte boundaries, the last ending at the
//! file's end (it overlaps the one before), so every byte is in one: 53,795
//! of them. Aligned windows keep small the table a proof of the work looks
//! them up in (a row a window, the work in the chain proof).
//!
//! Every dataset item is derived from the windows: starting from a state
//! seeded with the item index, each of [`PowParams::parents`] sequential
//! steps uses the state to pick a window, absorbs it and applies the
//! Poseidon2 permutation. Miners keep the items in a table of 64-byte
//! items. The proof ([`hashimoto`]) seeds a 32-element mix from the header
//! hash and nonce and makes [`PowParams::accesses`] reads, each folding in
//! two adjacent items and one window of the file itself, picked by a second
//! selector; it then folds the mix to 8 elements and hashes it with the seed.
//!
//! **Validating a block requires the entire seed file.** Checking a
//! header's work reads windows spread over the whole file: computing its 128
//! items from the file reads about 32,500 of them, and the direct reads take
//! 64 more however the items are had. So neither the dataset nor any hash of
//! the file substitutes for it, and a node missing any window soon meets a
//! block it cannot validate. Every validating node stores it.
//!
//! # Verifiers and miners
//!
//! Verifiers compute only the items a proof touches, from the file
//! ([`SeedText::at`]): 128 of them, each the same work whatever the size of
//! the table, since an item is made from its index and the text and from no
//! other item. So a verifier needs the file, a little stack and nothing
//! else, and what it costs to check a header never changes.
//!
//! A hash costs a few permutations with the table and about
//! `2 * accesses * parents` without it, a gap no cheaper arithmetic closes,
//! so a miner keeps the table. Part of it is of little use: with a fraction
//! `f` of the pairs stored, a hash still computes `1 - f` of its 64 pairs,
//! each a hundred times the cost of the rest of the hash.
//!
//! # The table grows
//!
//! The chain is divided into epochs of [`PowParams::epoch_blocks`] blocks.
//! The table has `2^log_dataset_items` items in the first and twice as many
//! in each one after, until it has `2^max_log_dataset_items`: on mainnet
//! 1 GB, doubling each year to 32 GB in the sixth, and 32 GB from then on.
//! A small table at the start lets any machine mine; a large one later is
//! more than a chip can hold beside its logic, so that what a miner pays
//! for is mostly memory.
//!
//! An item is the same in every epoch: a table that grows keeps the items
//! it has and gains as many again. So a miner computes each item once, a
//! table's file serves every epoch after the one it was saved in, and
//! which table a block's work is of depends on the block's height and on
//! nothing else in the chain.
//!
//! # A miner's table
//!
//! [`LazyDataset`] holds a whole table, its memory taken when it is made,
//! and fills it as it is read: an item not yet there is computed from
//! the file and kept. At the next epoch it is grown where it is
//! ([`LazyDataset::grow`]): what it has stays, and the new half fills as
//! it is read in its turn. Mining with it starts at once, as slow as a verifier,
//! and quickens as the table fills; every item computed on the way is one
//! the table needed. [`Dataset`] is a table computed whole, for the small
//! ones of tests and the dev networks.
//!
//! All arithmetic is in BabyBear: the Ethash FNV step used in the mixing
//! loop becomes `a * FNV_PRIME + b` in the field, and the hashes are the
//! Poseidon2 permutation. Items are 16 field elements.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::codec::pack3;
pub use crate::difficulty::Target;
pub use crate::hash::Digest;
use crate::poseidon2::{DIGEST, Fp, P, RATE, WIDTH, compress, permute_in_place};

/// One dataset item: 16 field elements, 64 bytes.
pub type Item = [Fp; WIDTH];
/// Proof-of-work nonce: 32 arbitrary bytes.
pub type Nonce = [u8; 32];
/// Elements a nonce packs into, three bytes each.
const NONCE_FPS: usize = 32usize.div_ceil(3);

/// The seed file: the text gzipped, embedded at build time and used as it
/// is.
pub const SEED_TEXT_GZ: &[u8] = include_bytes!("../../resources/akjv.txt.gz");

/// The dev dataset ([`PowParams::DEV`]), generated once
/// from the seed text and built in (with the `dev` feature), so a dev node
/// starts at once. `dev_dataset_is_built_in` checks it; `write_dev_dataset`
/// (an ignored test) regenerates it.
#[cfg(feature = "dev")]
pub const DEV_DATASET: &[u8] = include_bytes!("../../resources/dev_dataset.bin");

/// Size of the seed file, checked when loading.
pub const SEED_TEXT_LEN: usize = 1_291_059;

/// Bytes of text absorbed per derivation step: one sponge block.
pub const WINDOW: usize = 3 * RATE;

const FNV_PRIME: Fp = Fp::new(0x0100_0193);
const DOM_ITEM: u32 = 0x5041;
const DOM_SEED: u32 = 0x5042;
const MIX_WORDS: usize = 2 * WIDTH;

/// Serialized size of one item.
const ITEM_BYTES: usize = WIDTH * 4;

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// The proof of work's parameters: how large the table is in each epoch,
/// and how much work an item and a proof are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowParams {
    /// The table has `2^log_dataset_items` items in the first epoch.
    pub log_dataset_items: u32,
    /// It doubles each epoch until it has `2^max_log_dataset_items`.
    pub max_log_dataset_items: u32,
    /// Blocks in an epoch.
    pub epoch_blocks: u32,
    /// Sequential permutation steps, each absorbing one text window, per
    /// dataset item.
    pub parents: usize,
    /// Dataset reads (of two adjacent items each) per proof.
    pub accesses: usize,
}

impl PowParams {
    /// A table of 1 GB that doubles each year (52,560 blocks of ten
    /// minutes) to 32 GB.
    pub const MAINNET: PowParams = PowParams {
        log_dataset_items: 24,
        max_log_dataset_items: 29,
        epoch_blocks: 144 * 365,
        parents: 254,
        accesses: 64,
    };

    /// The dev networks' (`--network dev`): a 64 KB table that does not
    /// grow, built into the binary ([`DEV_DATASET`]).
    pub const DEV: PowParams = PowParams { log_dataset_items: 10, max_log_dataset_items: 10, ..Self::MAINNET };

    /// The epoch of the block at `height`.
    pub const fn epoch_of(&self, height: u64) -> u32 {
        let e = height / self.epoch_blocks as u64;
        if e > u32::MAX as u64 { u32::MAX } else { e as u32 }
    }

    /// `log2` of the table's items in epoch `epoch`: one more each epoch,
    /// to the most there are.
    pub const fn log_items(&self, epoch: u32) -> u32 {
        let room = self.max_log_dataset_items - self.log_dataset_items;
        self.log_dataset_items + if epoch < room { epoch } else { room }
    }

    /// `log2` of the items in the table the work of the block at `height`
    /// is of.
    pub const fn log_items_at(&self, height: u64) -> u32 {
        self.log_items(self.epoch_of(height))
    }

    /// The parameters make sense: tables of whole words of pairs, that an
    /// index of one field element reaches.
    const fn check(&self) {
        assert!(self.log_dataset_items >= 7 && self.log_dataset_items <= self.max_log_dataset_items);
        assert!(self.max_log_dataset_items <= 30, "an item's index is one field element");
        assert!(self.epoch_blocks > 0);
    }

    /// Whether a table of `2^log_items` items is one of the schedule's.
    const fn has_table(&self, log_items: u32) -> bool {
        log_items >= self.log_dataset_items && log_items <= self.max_log_dataset_items
    }
}

const _: () = PowParams::MAINNET.check();
const _: () = PowParams::DEV.check();

/// Bytes of a table of `2^log_items` items.
pub const fn table_bytes(log_items: u32) -> u64 {
    (ITEM_BYTES as u64) << log_items
}

/// `a * FNV_PRIME + b`.
#[inline(always)]
fn fnv(a: Fp, b: Fp) -> Fp {
    a.mul(&FNV_PRIME).add(&b)
}

/// The seed file's bytes, as they are: the file in the binary, not a copy.
pub fn seed_text() -> &'static [u8] {
    assert_eq!(SEED_TEXT_GZ.len(), SEED_TEXT_LEN, "embedded seed file has unexpected length");
    SEED_TEXT_GZ
}

/// The window a direct read takes for a canonical selector value `v`, with
/// `n` windows: the low `L` bits of `v`, where `2^L` is the least power of
/// two at least `n`, less `n` once if that is `n` or more. Every window can
/// be taken; those below `2^L - n` twice as often.
pub fn direct_window(v: u32, n: usize) -> usize {
    let bits = (n as u32).next_power_of_two() - 1;
    let low = (v & bits) as usize;
    if low >= n { low - n } else { low }
}

/// Packs a text window into one sponge block, three bytes per element.
#[inline]
fn pack_window(window: &[u8]) -> [Fp; RATE] {
    let mut block = [Fp::ZERO; RATE];
    for (b, chunk) in block.iter_mut().zip(window.chunks(3)) {
        *b = pack3(chunk);
    }
    block
}

/// A nonce with the integer in its first eight bytes, for sequential search.
pub fn nonce_from_u64(n: u64) -> Nonce {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// The seed text and where items come from
// ---------------------------------------------------------------------------

/// Anything that can supply a table's items, and the seed file's windows:
/// a table beside the file ([`LazyDataset`], [`Dataset`]), or the file
/// alone computing items on demand ([`SeedItems`]).
pub trait ItemSource {
    fn params(&self) -> &PowParams;
    /// `log2` of the items in the table these are the items of.
    fn log_items(&self) -> u32;
    /// Pairs of adjacent items in the table: what a proof reads.
    fn pairs(&self) -> usize {
        1 << (self.log_items() - 1)
    }
    fn item(&self, index: usize) -> Item;
    /// The seed file, which [`hashimoto`] reads directly.
    fn seed(&self) -> &SeedText<'_>;
}

/// The seed file, from which every dataset item is derived. It borrows the
/// file's bytes (the embedded file's are in the binary), so it costs no
/// memory and copies freely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedText<'a> {
    params: PowParams,
    text: &'a [u8],
}

impl SeedText<'static> {
    /// The embedded seed file.
    pub fn new(params: PowParams) -> SeedText<'static> {
        Self::from_bytes(params, seed_text())
    }
}

impl<'a> SeedText<'a> {
    /// Uses arbitrary bytes as the seed (tests). Must be at least
    /// [`WINDOW`] bytes long.
    pub fn from_bytes(params: PowParams, text: &'a [u8]) -> SeedText<'a> {
        params.check();
        assert!(text.len() >= WINDOW, "seed text shorter than one window");
        SeedText { params, text }
    }

    pub fn params(&self) -> &PowParams {
        &self.params
    }

    pub fn text(&self) -> &'a [u8] {
        self.text
    }

    /// The text's windows: one every [`WINDOW`] bytes, the last one ending
    /// at the text's end.
    pub fn windows(&self) -> usize {
        self.text.len().div_ceil(WINDOW)
    }

    /// Where window `w` starts: `w * WINDOW`, but the last one a window's
    /// length before the text's end.
    pub fn window_offset(&self, w: usize) -> usize {
        (w * WINDOW).min(self.text.len() - WINDOW)
    }

    /// Window `w`, packed into one sponge block.
    pub fn window(&self, w: usize) -> [Fp; RATE] {
        let at = self.window_offset(w);
        pack_window(&self.text[at..at + WINDOW])
    }

    /// Computes dataset item `index`: `parents` sequential permutations,
    /// each preceded by absorbing the text window selected by the current
    /// state, which starts from the index. No other item enters, and
    /// neither does the table's size: an item costs the same, and is the
    /// same, in every table that has it.
    pub fn calc_dataset_item(&self, index: usize) -> Item {
        assert!(index >> self.params.max_log_dataset_items == 0, "no table has such an item");
        let windows = self.windows() as u64;
        let mut mix = [Fp::ZERO; WIDTH];
        mix[0] = Fp::from_u32(index as u32);
        mix[1] = Fp::new(DOM_ITEM);
        permute_in_place(&mut mix);
        for _ in 0..self.params.parents {
            let r = mix[0].to_canonical() as u64 | (mix[1].to_canonical() as u64) << 31;
            let offset = self.window_offset((r % windows) as usize);
            let block = pack_window(&self.text[offset..offset + WINDOW]);
            for (m, b) in mix.iter_mut().zip(&block) {
                *m = m.add(b);
            }
            permute_in_place(&mut mix);
        }
        mix
    }

    /// The items of the table the block at `height` is mined with, each
    /// computed from the file when asked for: what a verifier checks a
    /// header's work with. Nothing is kept.
    pub fn at(&self, height: u64) -> SeedItems<'a> {
        self.table(self.params.log_items_at(height))
    }

    /// The items of the table of `2^log_items` items, computed on demand.
    pub fn table(&self, log_items: u32) -> SeedItems<'a> {
        assert!(self.params.has_table(log_items), "no epoch has a table of 2^{log_items} items");
        SeedItems { seed: *self, log_items }
    }
}

/// A table's items computed from the seed file on demand
/// ([`SeedText::at`]): a verifier's source. It holds the file's bytes by
/// reference and the table's size, and no item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedItems<'a> {
    seed: SeedText<'a>,
    log_items: u32,
}

impl ItemSource for SeedItems<'_> {
    fn params(&self) -> &PowParams {
        &self.seed.params
    }

    fn log_items(&self) -> u32 {
        self.log_items
    }

    fn item(&self, index: usize) -> Item {
        self.seed.calc_dataset_item(index)
    }

    fn seed(&self) -> &SeedText<'_> {
        &self.seed
    }
}

// ---------------------------------------------------------------------------
// A table computed whole
// ---------------------------------------------------------------------------

/// A whole table, computed at once: for the small tables of tests and of
/// the dev networks. A miner's is a [`LazyDataset`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dataset<'a> {
    log_items: u32,
    items: Vec<Item>,
    seed: SeedText<'a>,
}

/// An item from its [`ITEM_BYTES`] bytes; `None` for an element not below
/// the modulus.
fn item_from_bytes(bytes: &[u8]) -> Option<Item> {
    let mut item = [Fp::ZERO; WIDTH];
    for (x, b) in item.iter_mut().zip(bytes.chunks_exact(4)) {
        *x = Fp::from_le_bytes(b.try_into().unwrap())?;
    }
    Some(item)
}

fn item_to_bytes(item: &Item) -> [u8; ITEM_BYTES] {
    let mut out = [0u8; ITEM_BYTES];
    for (b, x) in out.chunks_exact_mut(4).zip(item) {
        b.copy_from_slice(&x.to_le_bytes());
    }
    out
}

impl<'a> Dataset<'a> {
    /// Generates every item of the table of `2^log_items` items from the
    /// text, using all available threads.
    pub fn generate(seed: &SeedText<'a>, log_items: u32) -> Dataset<'a> {
        assert!(seed.params.has_table(log_items), "no epoch has a table of 2^{log_items} items");
        let mut items = vec![[Fp::ZERO; WIDTH]; 1 << log_items];
        crate::parallel::par_fill_min(&mut items, 1, |i| seed.calc_dataset_item(i));
        Dataset { log_items, items, seed: *seed }
    }

    /// The dataset built into the binary for `seed`, if any: the dev
    /// networks', from the embedded file, in a build with the `dev`
    /// feature.
    pub fn built_in(seed: &SeedText<'a>) -> Option<Dataset<'a>> {
        #[cfg(feature = "dev")]
        if seed.params == PowParams::DEV && seed.text == SEED_TEXT_GZ {
            return Self::from_bytes(seed, PowParams::DEV.log_dataset_items, DEV_DATASET);
        }
        let _ = seed;
        None
    }

    /// The items' bytes.
    #[cfg(test)]
    fn to_bytes(&self) -> Vec<u8> {
        self.items.iter().flat_map(item_to_bytes).collect()
    }

    /// A dataset from its items' bytes.
    #[cfg(any(test, feature = "dev"))]
    fn from_bytes(seed: &SeedText<'a>, log_items: u32, bytes: &[u8]) -> Option<Dataset<'a>> {
        if bytes.len() != ITEM_BYTES << log_items {
            return None;
        }
        let items = bytes.chunks_exact(ITEM_BYTES).map(item_from_bytes).collect::<Option<Vec<Item>>>()?;
        Some(Dataset { log_items, items, seed: *seed })
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl ItemSource for Dataset<'_> {
    fn params(&self) -> &PowParams {
        &self.seed.params
    }

    fn log_items(&self) -> u32 {
        self.log_items
    }

    #[inline]
    fn item(&self, index: usize) -> Item {
        self.items[index]
    }

    fn seed(&self) -> &SeedText<'_> {
        &self.seed
    }
}

// ---------------------------------------------------------------------------
// A miner's table, filled as it is read
// ---------------------------------------------------------------------------

/// What begins a table's file.
const FILE_MAGIC: &[u8; 8] = b"tabtable";
/// Bytes of a table file before its bitmap: the magic, `log2` of its
/// items, and the parents of an item.
const FILE_HEADER: usize = 8 + 4 + 4;
/// Bytes of the checksum that ends a table's file.
const CHECKSUM_BYTES: usize = 8;

/// A checksum of a table's file against corruption (not forgery: the
/// sampled items guard the contents, the chain's blocks the rest): 64-bit
/// FNV-1a, taken a part of the file at a time, the same whatever compiler
/// built the node.
struct Checksum(u64);

impl Checksum {
    fn new() -> Checksum {
        Checksum(0xcbf2_9ce4_8422_2325)
    }

    fn update(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ *b as u64).wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn finish(&self) -> [u8; CHECKSUM_BYTES] {
        self.0.to_le_bytes()
    }
}

/// A table as a miner holds it: all of its memory taken when it is made,
/// and its items computed from the seed file as they are first read, a
/// pair at a time, and kept. Threads share one by reference: reading and
/// filling need no lock, and two threads that fill the same pair write
/// the same values.
pub struct LazyDataset<'a> {
    seed: SeedText<'a>,
    log_items: u32,
    /// The items' elements in Montgomery form, 16 an item.
    words: Vec<AtomicU32>,
    /// A bit for each pair of items that is there: set after its elements
    /// are written.
    present: Vec<AtomicU64>,
    /// How many pairs are there.
    filled: AtomicUsize,
}

impl<'a> LazyDataset<'a> {
    /// An empty table of `2^log_items` items: its whole memory
    /// ([`table_bytes`]) is allocated and written to now, so that a machine
    /// without room for it fails here and not while mining.
    pub fn new(seed: &SeedText<'a>, log_items: u32) -> std::io::Result<LazyDataset<'a>> {
        assert!(seed.params.has_table(log_items), "no epoch has a table of 2^{log_items} items");
        let no_room = |_| std::io::Error::new(std::io::ErrorKind::OutOfMemory, "no memory for the dataset");
        let (n, pairs) = (WIDTH << log_items, 1usize << (log_items - 1));
        let mut words = Vec::new();
        words.try_reserve_exact(n).map_err(no_room)?;
        // Every word is written: the memory is the process's from here on,
        // not a promise of it. (The value is hidden from the compiler, or a
        // zero written to zeroed memory could be left out.)
        words.extend((0..n).map(|_| AtomicU32::new(std::hint::black_box(0))));
        let mut present = Vec::new();
        present.try_reserve_exact(pairs / 64).map_err(no_room)?;
        present.extend((0..pairs / 64).map(|_| AtomicU64::new(0)));
        Ok(LazyDataset { seed: *seed, log_items, words, present, filled: AtomicUsize::new(0) })
    }

    /// A table of `2^log_items` items with what the file at `path` holds
    /// of it ([`LazyDataset::save`]): a file of a smaller table, of an
    /// earlier epoch, holds its first items. With the built-in dataset, if
    /// this build has one for the seed; empty if there is neither.
    pub fn open(seed: &SeedText<'a>, log_items: u32, path: &std::path::Path) -> std::io::Result<LazyDataset<'a>> {
        let table = Self::new(seed, log_items)?;
        if let Some(built_in) = Dataset::built_in(seed) {
            for (i, item) in built_in.items.iter().enumerate() {
                table.write(i, item);
            }
            for pair in 0..built_in.items.len() / 2 {
                table.mark(pair);
            }
        } else {
            // A file that is not a table's leaves it empty: no pair is
            // marked as there until the whole file is known to be good.
            table.load(path);
        }
        Ok(table)
    }

    /// Makes the table one of `2^log_items` items, for a later epoch: the
    /// items it has stay where they are, and room for the rest is taken
    /// and written to now, to be filled as it is read.
    pub fn grow(&mut self, log_items: u32) -> std::io::Result<()> {
        assert!(self.seed.params.has_table(log_items), "no epoch has a table of 2^{log_items} items");
        assert!(log_items >= self.log_items, "a table does not shrink");
        let no_room = |_| std::io::Error::new(std::io::ErrorKind::OutOfMemory, "no memory for the dataset");
        let (n, pairs) = (WIDTH << log_items, 1usize << (log_items - 1));
        self.words.try_reserve_exact(n - self.words.len()).map_err(no_room)?;
        self.present.try_reserve_exact(pairs / 64 - self.present.len()).map_err(no_room)?;
        let have = self.words.len();
        self.words.extend((have..n).map(|_| AtomicU32::new(std::hint::black_box(0))));
        let have = self.present.len();
        self.present.extend((have..pairs / 64).map(|_| AtomicU64::new(0)));
        self.log_items = log_items;
        Ok(())
    }

    /// Pairs of items that are there.
    pub fn filled(&self) -> usize {
        self.filled.load(Ordering::Acquire)
    }

    /// Whether every item is there: the table is as fast as it gets.
    pub fn is_complete(&self) -> bool {
        self.filled() == self.pairs()
    }

    fn has(&self, pair: usize) -> bool {
        self.present[pair / 64].load(Ordering::Acquire) >> (pair % 64) & 1 == 1
    }

    /// Records that `pair`'s elements are written.
    fn mark(&self, pair: usize) {
        let bit = 1u64 << (pair % 64);
        if self.present[pair / 64].fetch_or(bit, Ordering::AcqRel) & bit == 0 {
            self.filled.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn write(&self, index: usize, item: &Item) {
        for (w, x) in self.words[index * WIDTH..(index + 1) * WIDTH].iter().zip(item) {
            w.store(x.to_mont(), Ordering::Relaxed);
        }
    }

    fn read(&self, index: usize) -> Item {
        let words = &self.words[index * WIDTH..(index + 1) * WIDTH];
        core::array::from_fn(|k| Fp::from_mont(words[k].load(Ordering::Relaxed)))
    }

    /// Computes `pair`'s two items from the file and keeps them, if they
    /// are not there.
    fn ensure(&self, pair: usize) {
        if !self.has(pair) {
            for index in [2 * pair, 2 * pair + 1] {
                self.write(index, &self.seed.calc_dataset_item(index));
            }
            self.mark(pair);
        }
    }

    /// Computes every item not yet there, using all available threads.
    pub fn fill(&self) {
        crate::parallel::par_map_min(self.pairs(), 1, |pair| self.ensure(pair));
    }

    /// Writes the table to `path`, by way of a file beside it: its size,
    /// which pairs are there, every item, and a checksum. A table can be
    /// saved while it is mined with; pairs filled meanwhile may be left
    /// for next time.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        let mut file = std::io::BufWriter::with_capacity(1 << 16, std::fs::File::create(&tmp)?);
        let mut sum = Checksum::new();
        let mut put = |file: &mut std::io::BufWriter<std::fs::File>, bytes: &[u8]| {
            sum.update(bytes);
            file.write_all(bytes)
        };
        put(&mut file, &file_header(self.log_items, self.seed.params.parents))?;
        // The bitmap first: a pair it says is there was whole before it was
        // read, and stays whole.
        for w in &self.present {
            put(&mut file, &w.load(Ordering::Acquire).to_le_bytes())?;
        }
        for index in 0..1usize << self.log_items {
            put(&mut file, &item_to_bytes(&self.read(index)))?;
        }
        file.write_all(&sum.finish())?;
        file.flush()?;
        drop(file);
        std::fs::rename(&tmp, path)
    }

    /// Takes in the pairs the file at `path` holds, if it is a table's of
    /// this size or a smaller one of the schedule's: with a table's
    /// header, of the size that says, every element one, the checksum
    /// right, and a few of its pairs as the seed file makes them. Returns
    /// whether it was. Pairs are marked as there only at the end, so a
    /// file refused part way leaves the table as it was.
    fn load(&self, path: &std::path::Path) -> bool {
        let params = &self.seed.params;
        let read = || -> Option<()> {
            let file = std::fs::File::open(path).ok()?;
            let size = file.metadata().ok()?.len();
            let mut file = std::io::BufReader::with_capacity(1 << 16, file);
            let mut sum = Checksum::new();
            let mut header = [0u8; FILE_HEADER];
            file.read_exact(&mut header).ok()?;
            sum.update(&header);
            // The file's table: one of the schedule's, no larger than this.
            let log_items = u32::from_le_bytes(header[8..12].try_into().unwrap());
            if !params.has_table(log_items) || log_items > self.log_items {
                return None;
            }
            let pairs = 1usize << (log_items - 1);
            if header != file_header(log_items, params.parents)
                || size != (FILE_HEADER + pairs / 8 + CHECKSUM_BYTES) as u64 + table_bytes(log_items)
            {
                return None;
            }
            // Which pairs the file has: marked here only once the whole
            // file is known to be good.
            let mut there = vec![0u64; pairs / 64];
            for w in there.iter_mut() {
                let mut b = [0u8; 8];
                file.read_exact(&mut b).ok()?;
                sum.update(&b);
                *w = u64::from_le_bytes(b);
            }
            let mut buf = [0u8; ITEM_BYTES];
            for index in 0..2 * pairs {
                file.read_exact(&mut buf).ok()?;
                sum.update(&buf);
                self.write(index, &item_from_bytes(&buf)?);
            }
            let mut stored = [0u8; CHECKSUM_BYTES];
            file.read_exact(&mut stored).ok()?;
            if stored != sum.finish() {
                return None;
            }
            // Up to eight of the pairs it has, spread through them.
            let has = |pair: usize| there[pair / 64] >> (pair % 64) & 1 == 1;
            let held = (0..pairs).filter(|p| has(*p)).count();
            let mut seen = 0;
            for pair in (0..pairs).filter(|p| has(*p)) {
                if held <= 8 || seen % (held / 8) == 0 || seen == held - 1 {
                    for index in [2 * pair, 2 * pair + 1] {
                        if self.read(index) != self.seed.calc_dataset_item(index) {
                            return None;
                        }
                    }
                }
                seen += 1;
            }
            for pair in (0..pairs).filter(|p| has(*p)) {
                self.mark(pair);
            }
            Some(())
        };
        read().is_some()
    }
}

/// What begins the file of a table of `2^log_items` items of `parents`
/// steps each.
fn file_header(log_items: u32, parents: usize) -> [u8; FILE_HEADER] {
    let mut h = [0u8; FILE_HEADER];
    h[..8].copy_from_slice(FILE_MAGIC);
    h[8..12].copy_from_slice(&log_items.to_le_bytes());
    h[12..].copy_from_slice(&(parents as u32).to_le_bytes());
    h
}

impl core::fmt::Debug for LazyDataset<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LazyDataset")
            .field("log_items", &self.log_items)
            .field("filled", &self.filled())
            .field("pairs", &self.pairs())
            .finish_non_exhaustive()
    }
}

impl ItemSource for LazyDataset<'_> {
    fn params(&self) -> &PowParams {
        &self.seed.params
    }

    fn log_items(&self) -> u32 {
        self.log_items
    }

    /// Item `index`: read if its pair is there, computed with its pair and
    /// kept if not.
    #[inline]
    fn item(&self, index: usize) -> Item {
        self.ensure(index / 2);
        self.read(index)
    }

    fn seed(&self) -> &SeedText<'_> {
        &self.seed
    }
}

// ---------------------------------------------------------------------------
// The proof of work
// ---------------------------------------------------------------------------

/// Seed state from the header hash and nonce: the header hash and a domain
/// tag fill the first block, the 32 nonce bytes (11 elements) follow.
fn seed(header_hash: &Digest, nonce: &Nonce) -> Item {
    let mut s = [Fp::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(header_hash);
    s[DIGEST] = Fp::new(DOM_SEED);
    permute_in_place(&mut s);
    let mut packed = [Fp::ZERO; NONCE_FPS];
    for (x, chunk) in packed.iter_mut().zip(nonce.chunks(3)) {
        *x = pack3(chunk);
    }
    for block in packed.chunks(RATE) {
        for (x, b) in s.iter_mut().zip(block) {
            *x = x.add(b);
        }
        permute_in_place(&mut s);
    }
    s
}

/// The final result for a claimed `mix`: two permutations, no dataset. Used
/// as a cheap pre-check before the full evaluation.
pub fn result_from_mix(header_hash: &Digest, nonce: &Nonce, mix: &Digest) -> Digest {
    let seed = seed(header_hash, nonce);
    let seed_head: Digest = seed[..DIGEST].try_into().unwrap();
    compress(mix, &seed_head)
}

/// Result of one proof-of-work evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowOutput {
    /// Folded mix, stored in the header so verifiers can check it.
    pub mix: Digest,
    /// Final hash compared against the target.
    pub result: Digest,
}

/// The memory-hard hash of `(header_hash, nonce)` using `source` for the
/// table's items and the seed file. Each access folds in two adjacent
/// items, picked by `fnv(i + seed[0], mix[i % 32])` among the table's
/// pairs, and one window of the file, picked by
/// `fnv(i + seed[1], mix[(i + 16) % 32])` ([`direct_window`]): window
/// element `k % 8` is added to mix word `k` after its item's fold.
///
/// The pair is the selector's low bits, and a selector is one field
/// element, of a little under 31 bits: in a table of `2^29` items the
/// lower half of the pairs is picked eight times for the upper half's
/// seven. In smaller tables every pair is picked alike, to within one
/// selector value.
pub fn hashimoto<S: ItemSource>(source: &S, header_hash: &Digest, nonce: &Nonce) -> PowOutput {
    let params = source.params();
    let text = source.seed();
    let windows = text.windows();
    let seed = seed(header_hash, nonce);
    let mut mix = [Fp::ZERO; MIX_WORDS];
    mix[..WIDTH].copy_from_slice(&seed);
    mix[WIDTH..].copy_from_slice(&seed);
    let pairs = source.pairs();
    for i in 0..params.accesses {
        let sel = fnv(Fp::from_u32(i as u32).add(&seed[0]), mix[i % MIX_WORDS]);
        let sel2 = fnv(Fp::from_u32(i as u32).add(&seed[1]), mix[(i + WIDTH) % MIX_WORDS]);
        let idx = (sel.to_canonical() as usize % pairs) * 2;
        let x = text.window(direct_window(sel2.to_canonical(), windows));
        let a = source.item(idx);
        let b = source.item(idx + 1);
        for (k, (m, d)) in mix.iter_mut().zip(a.iter().chain(&b)).enumerate() {
            *m = fnv(*m, *d).add(&x[k % RATE]);
        }
    }
    let mut cmix = [Fp::ZERO; DIGEST];
    for (k, c) in cmix.iter_mut().enumerate() {
        let w = &mix[4 * k..4 * k + 4];
        *c = fnv(fnv(fnv(w[0], w[1]), w[2]), w[3]);
    }
    let seed_head: Digest = seed[..DIGEST].try_into().unwrap();
    PowOutput { mix: cmix, result: compress(&cmix, &seed_head) }
}

/// Checks a proof of work from `source`: a table with the seed file
/// (microseconds), or the file alone (tens of milliseconds). The mix must be
/// the true one and the result must meet the target.
pub fn verify<S: ItemSource>(source: &S, header_hash: &Digest, nonce: &Nonce, mix: &Digest, target: &Target) -> bool {
    let out = hashimoto(source, header_hash, nonce);
    out.mix == *mix && target.is_met_by(&out.result)
}

/// Tries nonces in `nonces` until one meets `target`.
pub fn mine<S: ItemSource>(
    source: &S,
    header_hash: &Digest,
    target: &Target,
    nonces: impl IntoIterator<Item = Nonce>,
) -> Option<(Nonce, PowOutput)> {
    nonces.into_iter().map(|n| (n, hashimoto(source, header_hash, &n))).find(|(_, o)| target.is_met_by(&o.result))
}

const _: () = assert!(P > 0x0100_0193);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// A table that does not grow, as small as the dev networks'.
    const SMALL: PowParams = PowParams::DEV;
    /// One that grows: 16 KB doubling to 64 KB, in epochs of 100 blocks.
    const GROWING: PowParams = PowParams { log_dataset_items: 8, max_log_dataset_items: 10, epoch_blocks: 100, ..SMALL };

    fn small_seed() -> &'static SeedText<'static> {
        static SEED: OnceLock<SeedText<'static>> = OnceLock::new();
        SEED.get_or_init(|| SeedText::new(SMALL))
    }

    /// The table's items from the file alone: a verifier's source.
    fn small_items() -> SeedItems<'static> {
        small_seed().at(0)
    }

    fn small_dataset() -> &'static Dataset<'static> {
        static DATASET: OnceLock<Dataset<'static>> = OnceLock::new();
        DATASET.get_or_init(|| Dataset::generate(small_seed(), 10))
    }

    fn d(n: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(n + i as u32))
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tabminer-pow-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The built-in dev dataset is the one the seed text gives.
    #[test]
    #[cfg(feature = "dev")]
    fn dev_dataset_is_built_in() {
        let seed = SeedText::new(PowParams::DEV);
        let built = Dataset::built_in(&seed).expect("the dev dataset decodes");
        assert_eq!(built, Dataset::generate(&seed, 10), "regenerate it: write_dev_dataset");
        assert!(Dataset::built_in(&SeedText::new(PowParams::MAINNET)).is_none());
        // A miner's table starts whole, with no file.
        let table = LazyDataset::open(&seed, 10, std::path::Path::new("/nonexistent/table")).unwrap();
        assert!(table.is_complete());
        assert_eq!(table.item(1023), built.item(1023));
    }

    /// Writes `resources/dev_dataset.bin` from the seed text.
    #[test]
    #[ignore = "writes resources/dev_dataset.bin"]
    fn write_dev_dataset() {
        let d = Dataset::generate(&SeedText::new(PowParams::DEV), 10);
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/dev_dataset.bin"), d.to_bytes()).unwrap();
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x0100_0000_01b3))
    }

    /// The seed is the gzip file as shipped, and it is the King James text.
    #[test]
    fn seed_file_is_the_king_james_text() {
        let file = seed_text();
        assert_eq!(file.len(), SEED_TEXT_LEN);
        assert_eq!(fnv1a64(file), SEED_FILE_FNV);
        assert_eq!(small_seed().text(), file);
        let text = crate::inflate::gunzip(file).expect("the seed file is gzip");
        assert_eq!(text.len(), 4_340_917);
        assert_eq!(fnv1a64(&text), 0xb128_7e0a_c9ad_c1c6);
        assert!(text.starts_with(b"### Genesis"));
    }

    const SEED_FILE_FNV: u64 = 0x9810_ea1c_2d2d_6c21;

    /// Mainnet's table: 1 GB in the first year, twice as much each year to
    /// 32 GB in the sixth, and 32 GB ever after.
    #[test]
    fn the_table_doubles_each_epoch_to_its_ceiling() {
        let m = PowParams::MAINNET;
        let year = 52_560u64;
        assert_eq!(m.epoch_blocks as u64, year);
        for (height, epoch) in [(0, 0), (1, 0), (year - 1, 0), (year, 1), (2 * year - 1, 1), (5 * year, 5), (1007 * year, 1007)] {
            assert_eq!(m.epoch_of(height), epoch, "height {height}");
        }
        assert_eq!(m.epoch_of(u64::MAX), u32::MAX);
        let gb = 1u64 << 30;
        for (epoch, size) in [(0, gb), (1, 2 * gb), (2, 4 * gb), (3, 8 * gb), (4, 16 * gb), (5, 32 * gb), (6, 32 * gb), (1000, 32 * gb), (u32::MAX, 32 * gb)] {
            assert_eq!(table_bytes(m.log_items(epoch)), size, "epoch {epoch}");
        }
        for (height, size) in [(0, gb), (year - 1, gb), (year, 2 * gb), (5 * year - 1, 16 * gb), (5 * year, 32 * gb), (u64::MAX, 32 * gb)] {
            assert_eq!(table_bytes(m.log_items_at(height)), size, "height {height}");
            let items = SeedText::new(m).at(height);
            assert_eq!((table_bytes(items.log_items()), items.pairs() as u64 * 128), (size, size));
        }
        // The dev networks' table stays as it is.
        assert_eq!(table_bytes(PowParams::DEV.log_items_at(u64::MAX)), 64 << 10);
        assert_eq!(WINDOW, 24);
        // Every byte of the file is in a window: the last one ends at its end.
        let seed = small_seed();
        assert_eq!(seed.windows(), 53_795);
        assert_eq!(seed.window_offset(53_793), 53_793 * WINDOW);
        assert_eq!(seed.window_offset(53_794) + WINDOW, SEED_TEXT_LEN);
        assert!(seed.window_offset(53_794) < 53_794 * WINDOW, "the last window overlaps the one before");
        // Parameters that make no table are refused, and so is a table no epoch has.
        for bad in [
            PowParams { log_dataset_items: 6, ..SMALL },
            PowParams { max_log_dataset_items: 9, ..SMALL },
            PowParams { max_log_dataset_items: 31, ..SMALL },
            PowParams { epoch_blocks: 0, ..SMALL },
        ] {
            assert!(std::panic::catch_unwind(|| SeedText::new(bad)).is_err(), "{bad:?}");
        }
        let growing = SeedText::new(GROWING);
        for log_items in [7, 11] {
            assert!(std::panic::catch_unwind(|| growing.table(log_items)).is_err());
            assert!(std::panic::catch_unwind(|| Dataset::generate(&growing, log_items)).is_err());
            assert!(std::panic::catch_unwind(|| LazyDataset::new(&growing, log_items).map(|_| ())).is_err());
        }
    }

    /// An item is made from its index and the text, and from nothing else:
    /// it is the same in every epoch, so a table that grows keeps its items
    /// and gains as many again. A proof of work is of one table all the
    /// same: the same header and nonce hash otherwise in each.
    #[test]
    fn a_larger_table_keeps_the_items_it_had() {
        let seed = SeedText::new(GROWING);
        let tables: Vec<Dataset> = (8..=10).map(|log| Dataset::generate(&seed, log)).collect();
        assert_eq!(tables.iter().map(Dataset::len).collect::<Vec<_>>(), [256, 512, 1024]);
        for i in 0..256 {
            assert_eq!(tables[0].item(i), tables[2].item(i), "item {i}");
        }
        for i in 0..512 {
            assert_eq!(tables[1].item(i), tables[2].item(i), "item {i}");
        }
        // The same items under other parameters of the same work.
        let wide = SeedText::new(PowParams { log_dataset_items: 10, ..GROWING });
        for i in [0, 5, 255, 1023] {
            assert_eq!(wide.calc_dataset_item(i), tables[2].item(i));
        }
        // No two alike; none past the largest table.
        let mut all: Vec<[u32; WIDTH]> = tables[2].items.iter().map(|x| x.map(|v| v.to_canonical())).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 1024);
        assert!(std::panic::catch_unwind(|| seed.calc_dataset_item(1024)).is_err());
        // Which table a block's work is of is its height's: epochs of 100 blocks.
        for (height, log_items) in [(0, 8), (99, 8), (100, 9), (199, 9), (200, 10), (10_000, 10)] {
            assert_eq!(seed.at(height).log_items(), log_items, "height {height}");
        }
        // A proof of work from the file and from the table, in each epoch.
        let h = d(900);
        let mut results = Vec::new();
        for (table, height) in tables.iter().zip([0u64, 100, 200]) {
            for nonce in [0u64, 1, 99] {
                let nonce = nonce_from_u64(nonce);
                let out = hashimoto(table, &h, &nonce);
                assert_eq!(out, hashimoto(&seed.at(height), &h, &nonce));
                assert!(verify(&seed.at(height), &h, &nonce, &out.mix, &Target::MAX));
                // The work of one epoch is not the work of another.
                let other = seed.at((height + 100) % 300);
                assert!(!verify(&other, &h, &nonce, &out.mix, &Target::MAX));
                results.push(out.result);
            }
            assert_eq!((table.log_items(), table.params(), table.pairs()), (seed.at(height).log_items(), &GROWING, table.len() / 2));
        }
        let n = results.len();
        results.sort_by_key(|r| r.map(|x| x.to_canonical()));
        results.dedup();
        assert_eq!(results.len(), n);
    }

    /// The direct reads' windows: every one reachable, the lowest twice.
    #[test]
    fn direct_windows_cover_the_file() {
        let n = 53_795;
        let mut hit = vec![0u8; n];
        for v in 0..1u32 << 16 {
            hit[direct_window(v, n)] += 1;
        }
        assert!(hit.iter().all(|&h| h >= 1));
        assert_eq!(hit.iter().filter(|&&h| h == 2).count(), (1 << 16) - n);
        assert_eq!(direct_window(0xffff, n), 0xffff - n);
        assert_eq!(direct_window(0x7000_0000 | 0x1234, n), 0x1234);
        assert_eq!(direct_window(12345, 1), 0);
        assert_eq!(direct_window(5, 8), 5);
    }

    /// Validating needs the entire file: the full dataset with any part of
    /// the file missing (zeroed) checks almost no proof of work, and
    /// computing items from a file with a single window changed fails some
    /// of sixteen headers (13 of 64 with this small dataset; more on
    /// mainnet, whose many items repeat less).
    #[test]
    fn validation_needs_the_entire_file() {
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(31 + i as u32));
        let nonces: Vec<Nonce> = (0..64u64).map(nonce_from_u64).collect();
        let honest: Vec<PowOutput> = nonces.iter().map(|n| hashimoto(dataset, &h, n)).collect();
        // The honest items beside another file.
        let agree = |file: &[u8]| {
            let d = Dataset { log_items: 10, items: dataset.items.clone(), seed: SeedText::from_bytes(SMALL, file) };
            nonces.iter().zip(&honest).filter(|(n, o)| hashimoto(&d, &h, n) == **o).count()
        };
        // The dataset without the file.
        assert_eq!(agree(&vec![0u8; SEED_TEXT_LEN]), 0);
        // A tenth of it missing.
        let mut tenth = seed_text().to_vec();
        tenth[SEED_TEXT_LEN / 2..SEED_TEXT_LEN / 2 + SEED_TEXT_LEN / 10].fill(0);
        assert!(agree(&tenth) <= 1);
        // One window changed, items computed from the file.
        let mut one = seed_text().to_vec();
        one[24 * 20_000] ^= 1;
        let damaged = SeedText::from_bytes(SMALL, &one).at(0);
        let failed = nonces[..16].iter().zip(&honest).filter(|(n, o)| hashimoto(&damaged, &h, n) != **o).count();
        eprintln!("one window changed: {failed} of 16 fail");
        assert!(failed >= 1, "one window changed, and every header still checks");
    }

    #[test]
    fn items_depend_on_every_part_of_the_text() {
        // A short synthetic text of 42 windows (the last overlapping the one
        // before) is covered densely by 254 windows per item: every byte
        // lies in a window, so flipping any byte, the last ones included,
        // changes nearly every item.
        let base: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let a = SeedText::from_bytes(SMALL, &base);
        let items: Vec<Item> = (0..64).map(|i| a.calc_dataset_item(i)).collect();
        assert_eq!(items[..4], (0..4).map(|i| a.calc_dataset_item(i)).collect::<Vec<_>>()[..]);
        let changed = |pos: usize, count: usize| {
            let mut t = base.clone();
            t[pos] ^= 1;
            let b = SeedText::from_bytes(SMALL, &t);
            (0..count).filter(|&i| b.calc_dataset_item(i) != items[i]).count()
        };
        assert_eq!(a.windows(), 42);
        assert_eq!(a.window_offset(41), 1000 - WINDOW);
        for pos in [0usize, 30, 499, 969, 999] {
            let c = changed(pos, 8);
            assert!(c >= 7, "byte {pos}: only {c} of 8 items changed");
        }
        // A text shorter than one window is rejected.
        assert!(std::panic::catch_unwind(|| SeedText::from_bytes(SMALL, &[0u8; WINDOW - 1])).is_err());
        // Exactly one window works and uses it every step.
        let one = SeedText::from_bytes(SMALL, &[1u8; WINDOW]);
        assert_ne!(one.calc_dataset_item(0), one.calc_dataset_item(1));
    }

    #[test]
    fn dataset_matches_text_computation() {
        let seed = small_seed();
        let dataset = small_dataset();
        assert_eq!(dataset.len(), 1 << SMALL.log_dataset_items);
        assert!(!dataset.is_empty());
        for i in [0usize, 1, 2, 77, 1000, 1023] {
            assert_eq!(dataset.item(i), seed.calc_dataset_item(i), "item {i}");
            assert_eq!(dataset.item(i), small_items().item(i));
        }
        assert_ne!(dataset.item(0), dataset.item(1));
        // The items' bytes alone, as the built-in dataset is kept.
        assert_eq!(Dataset::from_bytes(seed, 10, &dataset.to_bytes()).as_ref(), Some(dataset));
        assert!(Dataset::from_bytes(seed, 10, &dataset.to_bytes()[1..]).is_none());
        let mut bad = dataset.to_bytes();
        bad[64..68].copy_from_slice(&P.to_le_bytes());
        assert!(Dataset::from_bytes(seed, 10, &bad).is_none());
        assert!(Dataset::built_in(&SeedText::new(PowParams::MAINNET)).is_none());
        assert_eq!((small_items().seed(), small_items().params(), seed.params()), (seed, &SMALL, &SMALL));
    }

    #[test]
    fn dataset_and_file_evaluation_agree() {
        let seed = small_items();
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(100 + i as u32));
        let mut prev = None;
        for nonce in [0u64, 1, 2, u64::MAX, 1 << 40] {
            let nonce = nonce_from_u64(nonce);
            let full = hashimoto(dataset, &h, &nonce);
            let from_file = hashimoto(&seed, &h, &nonce);
            assert_eq!(full, from_file, "nonce {nonce:?}");
            assert_ne!(Some(full.result), prev);
            prev = Some(full.result);
            assert_eq!(result_from_mix(&h, &nonce, &full.mix), full.result);
        }
        let zero = nonce_from_u64(0);
        let mut h2 = h;
        h2[7] += Fp::ONE;
        assert_ne!(hashimoto(dataset, &h2, &zero), hashimoto(dataset, &h, &zero));
        // All 32 nonce bytes matter.
        let mut tail = zero;
        tail[31] = 1;
        assert_ne!(hashimoto(dataset, &h, &tail), hashimoto(dataset, &h, &zero));
    }

    /// A miner's table starts empty and fills as it is read: every hash is
    /// the one a whole table gives, the pairs a hash read are there after
    /// it, and several threads mining with one table fill it between them.
    #[test]
    fn a_lazy_table_fills_as_it_is_read() {
        let seed = small_seed();
        let whole = small_dataset();
        let table = LazyDataset::new(seed, 10).unwrap();
        assert_eq!((table.pairs(), table.filled(), table.is_complete()), (512, 0, false));
        assert_eq!((table.log_items(), table.params(), table.seed()), (10, &SMALL, seed));
        assert!(format!("{table:?}").contains("filled: 0"));
        // One item asked for brings its pair.
        assert_eq!(table.item(77), whole.item(77));
        assert_eq!(table.filled(), 1);
        assert!(table.has(38) && !table.has(39));
        assert_eq!((table.item(76), table.filled()), (whole.item(76), 1));
        // A hash reads at most 64 pairs, and gives what the whole table gives.
        let h = d(700);
        let out = hashimoto(&table, &h, &nonce_from_u64(5));
        assert_eq!(out, hashimoto(whole, &h, &nonce_from_u64(5)));
        let after_one = table.filled();
        assert!((2..=65).contains(&after_one), "{after_one} pairs after one hash");
        // The same hash again reads only what is there.
        assert_eq!(hashimoto(&table, &h, &nonce_from_u64(5)), out);
        assert_eq!(table.filled(), after_one);
        // Threads mining together: each hash right, the table filling.
        std::thread::scope(|s| {
            for t in 0..4u64 {
                let table = &table;
                s.spawn(move || {
                    for n in 0..60 {
                        let nonce = nonce_from_u64(t << 32 | n);
                        assert_eq!(hashimoto(table, &h, &nonce), hashimoto(whole, &h, &nonce));
                    }
                });
            }
        });
        assert!(table.filled() > 500, "{} of 512 pairs after 240 hashes", table.filled());
        // What is left is computed outright, and nothing is counted twice.
        table.fill();
        assert!(table.is_complete());
        assert_eq!(table.filled(), 512);
        for i in 0..1024 {
            assert_eq!(table.item(i), whole.item(i), "item {i}");
        }
        table.fill();
        assert_eq!(table.filled(), 512);
        // Mining with it finds what mining with a whole table finds.
        let target = Target::from_leading_zero_bits(6);
        assert_eq!(
            mine(&table, &h, &target, (0..10_000).map(nonce_from_u64)),
            mine(whole, &h, &target, (0..10_000).map(nonce_from_u64))
        );
    }

    /// At the next epoch a table is grown where it is: the items it had
    /// are still there, the new half is empty and fills as it is read, and
    /// a hash is the larger table's.
    #[test]
    fn a_table_grows_where_it_is() {
        let seed = SeedText::new(GROWING);
        let whole = Dataset::generate(&seed, 10);
        let h = d(55);
        let mut table = LazyDataset::new(&seed, 8).unwrap();
        table.fill();
        assert_eq!((table.pairs(), table.filled()), (128, 128));
        let nonce = nonce_from_u64(3);
        let small = hashimoto(&table, &h, &nonce);
        assert_eq!(small, hashimoto(&seed.table(8), &h, &nonce));
        // Grown for the next epoch: the first half as it was, the second to come.
        table.grow(9).unwrap();
        assert_eq!((table.log_items(), table.pairs(), table.filled(), table.is_complete()), (9, 256, 128, false));
        assert!((0..128).all(|p| table.has(p)) && (128..256).all(|p| !table.has(p)));
        for i in 0..256 {
            assert_eq!(table.read(i), whole.item(i), "item {i}");
        }
        // Mined with: the new epoch's hashes, the new half filling.
        let large = hashimoto(&table, &h, &nonce);
        assert_eq!(large, hashimoto(&seed.table(9), &h, &nonce));
        assert_ne!(large, small);
        assert!(table.filled() > 128 && table.filled() < 256, "{} pairs", table.filled());
        for n in 0..20 {
            let nonce = nonce_from_u64(n);
            assert_eq!(hashimoto(&table, &h, &nonce), hashimoto(&seed.table(9), &h, &nonce));
        }
        // And again from a table part filled; growing to the size it is changes nothing.
        let part = table.filled();
        table.grow(10).unwrap();
        table.grow(10).unwrap();
        assert_eq!((table.pairs(), table.filled()), (512, part));
        assert_eq!(hashimoto(&table, &h, &nonce), hashimoto(&seed.table(10), &h, &nonce));
        table.fill();
        assert!(table.is_complete());
        for i in 0..1024 {
            assert_eq!(table.item(i), whole.item(i), "item {i}");
        }
        // A table does not shrink, nor grow past the last epoch's.
        let quiet = crate::test_util::Quiet::new();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| LazyDataset::new(&seed, 9).unwrap().grow(8))).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| LazyDataset::new(&seed, 9).unwrap().grow(11))).is_err());
        drop(quiet);
    }

    /// A table is saved as far as it is filled and taken up again from its
    /// file, by a table of its size or by the larger one of a later epoch;
    /// a file of a larger table, of other work, with a byte changed or
    /// with an item that is not the text's is not taken, and the table
    /// starts empty.
    #[test]
    fn lazy_tables_are_saved_and_loaded() {
        // Sizes no build has built in: 32 KB growing to 128 KB.
        const SAVED: PowParams = PowParams { log_dataset_items: 9, max_log_dataset_items: 11, parents: 16, ..SMALL };
        let seed = SeedText::new(SAVED);
        let whole = Dataset::generate(&seed, 11);
        let dir = temp_dir("tables");
        let path = dir.join("table.bin");
        // No file: an empty table.
        let table = LazyDataset::open(&seed, 9, &path).unwrap();
        assert_eq!(table.filled(), 0);
        // Part filled, saved, and taken up again.
        let h = d(1);
        for n in 0..3 {
            hashimoto(&table, &h, &nonce_from_u64(n));
        }
        let part = table.filled();
        assert!(part > 60 && part < 256, "{part} pairs");
        table.save(&path).unwrap();
        assert!(!dir.join("table.tmp").exists());
        let size = FILE_HEADER + 256 / 8 + 512 * ITEM_BYTES + CHECKSUM_BYTES;
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size as u64);
        let again = LazyDataset::open(&seed, 9, &path).unwrap();
        assert_eq!(again.filled(), part);
        for pair in 0..256 {
            assert_eq!(again.has(pair), table.has(pair), "pair {pair}");
        }
        for i in 0..512 {
            assert_eq!(again.item(i), whole.item(i), "item {i}");
        }
        assert!(again.is_complete());
        // Whole, saved, and loaded whole.
        again.save(&path).unwrap();
        let good = std::fs::read(&path).unwrap();
        assert_eq!(good.len(), size);
        assert_eq!(&good[..8], FILE_MAGIC);
        assert_eq!(good[FILE_HEADER + 32..size - CHECKSUM_BYTES], whole.to_bytes()[..512 * ITEM_BYTES]);
        assert_eq!(good[size - CHECKSUM_BYTES..], fnv1a64(&good[..size - CHECKSUM_BYTES]).to_le_bytes());
        let loaded = LazyDataset::open(&seed, 9, &path).unwrap();
        assert!(loaded.is_complete());
        assert_eq!(hashimoto(&loaded, &h, &nonce_from_u64(9)), hashimoto(&seed.table(9), &h, &nonce_from_u64(9)));
        // The next epoch's table, twice the size, starts from that file:
        // the items it had are there and the new half is to come.
        let grown = LazyDataset::open(&seed, 10, &path).unwrap();
        assert_eq!((grown.pairs(), grown.filled()), (512, 256));
        assert!(grown.has(0) && grown.has(255) && !grown.has(256));
        assert_eq!(hashimoto(&grown, &h, &nonce_from_u64(9)), hashimoto(&seed.table(10), &h, &nonce_from_u64(9)));
        grown.fill();
        for i in 0..1024 {
            assert_eq!(grown.item(i), whole.item(i), "item {i}");
        }
        // And the one after that, from the first epoch's file or the second's.
        assert_eq!(LazyDataset::open(&seed, 11, &path).unwrap().filled(), 256);
        let second = dir.join("second.bin");
        grown.save(&second).unwrap();
        assert_eq!(LazyDataset::open(&seed, 11, &second).unwrap().filled(), 512);
        // A larger table's file is of no use to a smaller table.
        assert_eq!(LazyDataset::open(&seed, 9, &second).unwrap().filled(), 0);
        // A file that is not this table's: nothing is taken from it.
        let refused = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = good.clone();
            change(&mut bytes);
            std::fs::write(&path, &bytes).unwrap();
            let t = LazyDataset::open(&seed, 9, &path).unwrap();
            let empty = t.filled() == 0;
            // It works all the same, from the seed file.
            assert_eq!(t.item(3), whole.item(3));
            empty
        };
        // With the checksum made to fit, so that it is what was changed that is refused.
        let refit = |b: &mut Vec<u8>| {
            let n = b.len() - CHECKSUM_BYTES;
            let sum = fnv1a64(&b[..n]).to_le_bytes();
            b[n..].copy_from_slice(&sum);
        };
        assert!(refused(&|b| b.truncate(b.len() - 1)), "a byte short");
        assert!(refused(&|b| b.push(0)), "a byte long");
        assert!(refused(&|b| b[FILE_HEADER + 32 + 1000] ^= 1), "an item changed");
        assert!(refused(&|b| *b.last_mut().unwrap() ^= 1), "the checksum changed");
        assert!(refused(&|b| { b[0] ^= 1; refit(b) }), "not a table's file");
        assert!(refused(&|b| { b[8] = 8; refit(b) }), "a size no epoch has");
        assert!(refused(&|b| { b[8] = 10; refit(b) }), "a size the file is not");
        assert!(refused(&|b| { b[12] ^= 1; refit(b) }), "other parents");
        assert!(refused(&|b| { b[FILE_HEADER + 32..][..4].copy_from_slice(&P.to_le_bytes()); refit(b) }), "an element that is none");
        assert!(refused(&|b| { b[FILE_HEADER + 32] ^= 1; refit(b) }), "the first item is not the text's");
        assert!(refused(&|b| { let at = b.len() - CHECKSUM_BYTES - 4; b[at] ^= 1; refit(b) }), "the last item is not the text's");
        // Another network's table of that size is of other work.
        std::fs::write(&path, &good).unwrap();
        let other = SeedText::new(PowParams { log_dataset_items: 9, ..SMALL });
        assert_eq!(LazyDataset::open(&other, 9, &path).unwrap().filled(), 0);
        assert_eq!(LazyDataset::open(&seed, 9, &path).unwrap().filled(), 256);
        // A pair the bitmap does not have is not taken, whatever its bytes.
        let mut holed = good.clone();
        holed[FILE_HEADER] &= !1;
        refit(&mut holed);
        std::fs::write(&path, &holed).unwrap();
        let t = LazyDataset::open(&seed, 9, &path).unwrap();
        assert_eq!((t.filled(), t.has(0), t.has(1)), (255, false, true));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Timings at mainnet's first size. Run with
    /// `cargo test --release pow::tests::mainnet_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn mainnet_timing() {
        use std::time::Instant;
        let seed = SeedText::new(PowParams::MAINNET);
        let log_items = PowParams::MAINNET.log_items_at(0);
        let h: Digest = core::array::from_fn(|i| Fp::new(i as u32));
        // A verifier: one header's work from the file alone.
        let items = seed.at(0);
        let t = Instant::now();
        for n in 0..5u64 {
            let _ = hashimoto(&items, &h, &nonce_from_u64(n));
        }
        println!("hashimoto from the file: {:?} per hash", t.elapsed() / 5);
        // A miner: the table's memory taken, then filled as it mines.
        let t = Instant::now();
        let table = LazyDataset::new(&seed, log_items).unwrap();
        println!("table of {} MB allocated and written to: {:?}", table_bytes(log_items) >> 20, t.elapsed());
        let t = Instant::now();
        let hashes = 2_000u64;
        crate::parallel::par_map_min(hashes as usize, 1, |n| hashimoto(&table, &h, &nonce_from_u64(n as u64)));
        let took = t.elapsed();
        let filled = table.filled();
        println!(
            "mining with it empty: {hashes} hashes in {took:?} on {} threads filled {filled} of {} pairs; \
             all of them at that rate: {:.0} s",
            crate::parallel::threads(),
            table.pairs(),
            took.as_secs_f64() * table.pairs() as f64 / filled as f64
        );
        // With every item a hash reads there: the same nonces again.
        let t = Instant::now();
        for n in 0..hashes {
            let _ = hashimoto(&table, &h, &nonce_from_u64(n));
        }
        println!("hashimoto with its items there: {:?} per hash", t.elapsed() / hashes as u32);
        let five = nonce_from_u64(5);
        assert_eq!(hashimoto(&table, &h, &five), hashimoto(&items, &h, &five));
    }

    #[test]
    fn mine_and_verify() {
        let seed = small_items();
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(7 * i as u32 + 1));
        let target = Target::from_leading_zero_bits(6);
        let (nonce, out) = mine(dataset, &h, &target, (0..10_000).map(nonce_from_u64)).expect("a nonce within range");
        assert!(target.is_met_by(&out.result));
        assert!(verify(&seed, &h, &nonce, &out.mix, &target));
        let mut other = nonce;
        other[9] ^= 1;
        assert!(!verify(&seed, &h, &other, &out.mix, &target));
        let mut bad_mix = out.mix;
        bad_mix[0] += Fp::ONE;
        assert!(!verify(&seed, &h, &nonce, &bad_mix, &target));
        assert!(!verify(&seed, &h, &nonce, &out.mix, &Target::from_leading_zero_bits(200)));
    }
}
