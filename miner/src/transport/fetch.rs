//! One object being fetched from one peer.
//!
//! A [`Fetch`] is told the time and what arrived, and says what to ask
//! for and when to come back:
//!
//! * [`Fetch::poll`] says what to do now: ask for these chunks, wait
//!   until then, or stop because the object is here or will not be.
//! * [`Fetch::chunk`] takes a chunk that arrived.
//!
//! # What it keeps
//!
//! The object's bytes, a bit for each chunk that has arrived, and the
//! chunks asked for and not yet here, in the order they were asked: the
//! *flight*. The serving side sends in the order it is asked, so the
//! flight is also the order chunks are expected in, and its front is
//! always the chunk waited for longest.
//!
//! Each ask has a number, one more than the ask before. When a chunk
//! arrives, the asks at the front of the flight numbered
//! [`super::REORDER`] or more below it have been overtaken: they are taken for
//! lost, leave the flight, and are asked for again before anything new.
//! That is the whole of fast retransmission, and because the flight is
//! in order it looks only at the front.
//!
//! A chunk asked for twice may arrive twice, and either copy is taken;
//! the second is counted and dropped. A chunk asked for more than once
//! gives no round-trip measurement (which ask did it answer?) and does
//! not overtake anything, for the same reason.
//!
//! # Rounds
//!
//! A round is a window's worth of arrivals. At its end the window is
//! halved if more than one chunk in [`LOSS_TOLERANCE`] was lost, and
//! grows if none of that happened and the window had been full: a
//! window that was never filled has shown nothing about the path.
//! A silence halves it at once. It is halved once a round at most.

use std::collections::VecDeque;

use super::path::Path;
use super::wire::{Chunk, Ranges};
use super::{CHUNK_BYTES, LOSS_TOLERANCE, MAX_RETRIES, MAX_WINDOW, MIN_RATE, Micros, REFILL, SLOW_GRACE, chunk_count};
use crate::error::Error;

/// What to do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Ask for the chunks put in the ranges, and poll again.
    Ask,
    /// Nothing until a chunk arrives or this time comes.
    Wait(Micros),
    /// Every chunk is here.
    Done,
    /// The object will not come from this peer.
    Failed(Why),
}

/// Why a fetch was given up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// Nothing arrived, [`MAX_RETRIES`] times over.
    Silent,
    /// It came too slowly to be worth waiting for.
    Slow,
    /// The peer said it does not have it.
    Gone,
    /// The peer sent a chunk no honest peer would.
    Bad,
}

/// What became of a chunk given to [`Fetch::chunk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// Its bytes were new.
    New,
    /// It was here already, or the fetch is over.
    Spare,
}

/// A chunk asked for.
#[derive(Clone, Copy, Debug)]
struct Asked {
    index: u32,
    at: Micros,
    /// Asked for before as well.
    again: bool,
    /// Still awaited: false once it has arrived, or was found to be
    /// past the object's end.
    flying: bool,
}

/// What a fetch did, for the tests and for whoever watches the network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Chunks asked for, counting each time.
    pub asked: u64,
    /// Of those, asks for a chunk asked for before.
    pub asked_again: u64,
    /// Chunks that arrived and were here already.
    pub spare: u64,
    /// Chunks taken for lost because later ones arrived.
    pub overtaken: u64,
    /// Of those, ones that then turned up.
    pub disorders: u64,
    /// Silences.
    pub silences: u64,
    /// Requests sent.
    pub requests: u64,
}

pub struct Fetch {
    transfer: u64,
    max_len: u32,
    /// Zero until known.
    len: u32,
    /// Chunks of the object; before its length is known, the chunks
    /// that may be asked for blind.
    count: u32,
    buf: Vec<u8>,
    /// A bit a chunk: here.
    have: Vec<u64>,
    /// A bit a chunk: asked for at least once.
    asked: Vec<u64>,
    /// A bit a chunk: taken for lost because it was overtaken, and not
    /// yet seen to have been.
    passed: Vec<u64>,
    got: u32,
    /// For each chunk, the number of its ask in the flight and one; zero
    /// if it is not in the flight.
    slot: Vec<u64>,
    flight: VecDeque<Asked>,
    /// The number of the ask at the front of the flight.
    base: u64,
    /// How many in the flight are still awaited.
    flying: u32,
    /// The greatest number of an ask that has been answered, and one.
    highest: u64,
    /// Chunks taken for lost, to ask again, the first lost first.
    lost: VecDeque<u32>,
    /// The first chunk never asked for.
    fresh: u32,
    path: Path,
    // This round.
    delivered: u32,
    losses: u32,
    filled: bool,
    cut: bool,
    disordered: bool,
    // Silence.
    last_progress: Micros,
    last_request: Micros,
    retries: u32,
    started: Micros,
    over: Option<Poll>,
    stats: Stats,
}

impl Fetch {
    /// A fetch numbered `transfer` (a number nobody else can guess) of
    /// an object of `len` bytes if that is known, and `max_len` at most
    /// in any case, over a path of which `path` has been learned.
    ///
    /// A known length that is zero or over `max_len` is no length: the
    /// fetch is of nothing, and [`Fetch::poll`] says so.
    pub fn new(transfer: u64, len: Option<u32>, max_len: u32, path: Path, now: Micros) -> Fetch {
        let mut f = Fetch {
            transfer,
            max_len,
            len: 0,
            count: 0,
            buf: Vec::new(),
            have: Vec::new(),
            asked: Vec::new(),
            passed: Vec::new(),
            got: 0,
            slot: Vec::new(),
            flight: VecDeque::with_capacity(MAX_WINDOW as usize),
            base: 0,
            flying: 0,
            highest: 0,
            lost: VecDeque::with_capacity(MAX_WINDOW as usize),
            fresh: 0,
            path,
            delivered: 0,
            losses: 0,
            filled: false,
            cut: false,
            disordered: false,
            last_progress: now,
            last_request: now,
            retries: 0,
            started: now,
            over: None,
            stats: Stats::default(),
        };
        match len {
            Some(l) if l == 0 || l > max_len => f.over = Some(Poll::Failed(Why::Bad)),
            Some(l) => f.learn(l),
            // Blind: the first window's worth, of which the peer sends
            // those there are.
            None => {
                f.count = chunk_count(max_len).min(f.path.window());
                f.size(f.count);
            }
        }
        f
    }

    pub fn transfer(&self) -> u64 {
        self.transfer
    }

    /// What has been learned of the path, for the next fetch from this
    /// peer.
    pub fn path(&self) -> Path {
        self.path
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The object's length, once known.
    pub fn length(&self) -> Option<u32> {
        (self.len != 0).then_some(self.len)
    }

    /// Chunks here, and chunks in all (once the length is known).
    pub fn progress(&self) -> (u32, Option<u32>) {
        (self.got, (self.len != 0).then_some(self.count))
    }

    /// Chunks asked for and awaited.
    pub fn in_flight(&self) -> u32 {
        self.flying
    }

    /// The object, once [`Poll::Done`].
    pub fn finish(self) -> Option<Vec<u8>> {
        (self.over == Some(Poll::Done)).then_some(self.buf)
    }

    /// The peer does not have the object.
    pub fn gone(&mut self) {
        if self.over.is_none() {
            self.over = Some(Poll::Failed(Why::Gone));
        }
    }

    fn size(&mut self, count: u32) {
        let words = (count as usize).div_ceil(64);
        self.have.resize(words, 0);
        self.asked.resize(words, 0);
        self.passed.resize(words, 0);
        self.slot.resize(count as usize, 0);
    }

    /// The length is `len`: room for it, and for a bit a chunk.
    fn learn(&mut self, len: u32) {
        self.len = len;
        self.count = chunk_count(len);
        self.buf = vec![0; len as usize];
        self.size(self.count);
        // What was asked for blind past the end is not coming, and was
        // not lost.
        for a in self.flight.iter_mut().filter(|a| a.flying && a.index >= self.count) {
            a.flying = false;
            self.flying -= 1;
        }
        self.fresh = self.fresh.min(self.count);
        let count = self.count;
        self.lost.retain(|&i| i < count);
    }

    fn has(&self, i: u32) -> bool {
        self.have[i as usize / 64] >> (i % 64) & 1 == 1
    }

    /// The time after which silence is a loss, from the later of the
    /// last arrival and the last request.
    fn silence(&self) -> Micros {
        self.last_progress.max(self.last_request) + (self.path.retry() << self.retries.min(3))
    }

    /// Ends a round: the window halves if too much was lost, and grows
    /// if nothing went wrong while it was full.
    fn end_round(&mut self) {
        let sent = self.delivered + self.losses;
        if self.losses * LOSS_TOLERANCE > sent {
            self.halve();
        } else if self.filled && !self.cut {
            self.path.grow();
        }
        if !self.disordered {
            self.path.ordered();
        }
        self.disordered = false;
        self.cut = false;
        self.delivered = 0;
        self.losses = 0;
        self.filled = self.flying >= self.path.window();
    }

    /// Halves the window, once a round.
    fn halve(&mut self) {
        if !self.cut {
            self.cut = true;
            self.path.cut();
        }
    }

    /// Drops from the front of the flight what is no longer awaited.
    fn trim(&mut self) {
        while self.flight.front().is_some_and(|a| !a.flying) {
            self.flight.pop_front();
            self.base += 1;
        }
    }

    /// What to do at `now`. On [`Poll::Ask`], `ranges` (cleared first)
    /// holds the chunks to ask for in one request; poll again at once,
    /// for there may be more than one request's worth.
    pub fn poll(&mut self, now: Micros, ranges: &mut Ranges) -> Poll {
        ranges.clear();
        if let Some(over) = self.over {
            return over;
        }
        // Too slow to be worth it.
        let elapsed = now.saturating_sub(self.started);
        // (A peer that has sent nothing at all is silent, not slow.)
        if elapsed >= SLOW_GRACE && self.got > 0 {
            let bytes = self.got as u64 * CHUNK_BYTES as u64;
            if bytes * 1_000_000 / elapsed < MIN_RATE {
                return self.fail(Why::Slow);
            }
        }
        // Silence: all that is awaited is lost.
        if self.flying > 0 && now >= self.silence() {
            self.retries += 1;
            self.stats.silences += 1;
            if self.retries > MAX_RETRIES {
                return self.fail(Why::Silent);
            }
            for a in self.flight.drain(..) {
                self.base += 1;
                if a.flying {
                    self.slot[a.index as usize] = 0;
                    self.lost.push_back(a.index);
                }
            }
            self.flying = 0;
            self.halve();
        }
        // Ask: the lost first, then what was never asked for.
        let window = self.path.window();
        let room = window.saturating_sub(self.flying);
        while self.lost.front().is_some_and(|&i| self.has(i) || self.slot[i as usize] != 0) {
            self.lost.pop_front();
        }
        let waiting = self.lost.len() as u64 + (self.count - self.fresh) as u64;
        // In batches: when there is room for a batch, or for all there
        // is, or when nothing is awaited at all.
        if waiting > 0 && room > 0 && (room >= REFILL || waiting <= room as u64 || self.flying == 0) {
            let mut n = 0;
            while n < room {
                let i = match self.lost.front() {
                    Some(&i) if self.has(i) || self.slot[i as usize] != 0 => {
                        self.lost.pop_front();
                        continue;
                    }
                    Some(&i) => i,
                    None if self.fresh < self.count => self.fresh,
                    None => break,
                };
                if !ranges.push(i) {
                    break;
                }
                if self.lost.pop_front().is_none() {
                    self.fresh += 1;
                }
                let word = &mut self.asked[i as usize / 64];
                let again = *word >> (i % 64) & 1 == 1;
                *word |= 1 << (i % 64);
                self.slot[i as usize] = self.base + self.flight.len() as u64 + 1;
                self.flight.push_back(Asked { index: i, at: now, again, flying: true });
                self.flying += 1;
                self.stats.asked += 1;
                self.stats.asked_again += again as u64;
                n += 1;
            }
            if n > 0 {
                if self.flying >= window {
                    self.filled = true;
                }
                self.last_request = now;
                self.stats.requests += 1;
                return Poll::Ask;
            }
        }
        // Back when silence would be a loss, or when slowness would be
        // seen, whichever is first.
        let slow = if elapsed < SLOW_GRACE { self.started + SLOW_GRACE } else { now + SLOW_GRACE };
        Poll::Wait(self.silence().min(slow).max(now + 1))
    }

    fn fail(&mut self, why: Why) -> Poll {
        let over = Poll::Failed(why);
        self.over = Some(over);
        over
    }

    /// Takes a chunk that arrived for this fetch.
    ///
    /// An error is a chunk of another fetch's number, which changes
    /// nothing here, or one no honest peer sends (another length than
    /// before, a length over the greatest, an index past the end): then
    /// the fetch is over, and [`Fetch::poll`] says the peer is bad.
    pub fn chunk(&mut self, now: Micros, c: &Chunk<'_>) -> Result<Taken, Error> {
        const BAD: Error = Error::Malformed("chunk");
        if c.transfer != self.transfer {
            return Err(BAD);
        }
        if self.over.is_some() {
            return Ok(Taken::Spare);
        }
        let known = self.len != 0;
        if c.len == 0 || c.len > self.max_len || (known && c.len != self.len) {
            self.fail(Why::Bad);
            return Err(BAD);
        }
        if !known {
            self.learn(c.len);
        }
        // Decoding saw that the index is within the length it carries
        // and the bytes as many as that place has; a chunk built
        // otherwise is refused here.
        let i = c.index;
        let start = i as usize * CHUNK_BYTES;
        if i >= self.count || super::chunk_len(self.len, i) != Some(c.data.len()) {
            self.fail(Why::Bad);
            return Err(BAD);
        }
        // Its ask, if it is in the flight.
        let ask = match self.slot[i as usize] {
            0 => None,
            s => {
                self.slot[i as usize] = 0;
                let a = &mut self.flight[(s - 1 - self.base) as usize];
                a.flying = false;
                self.flying -= 1;
                Some((s, *a))
            }
        };
        // Taken for lost, and here it is: before it was even asked for
        // again, or for the second time. It had only been overtaken.
        let bit = 1u64 << (i % 64);
        if self.passed[i as usize / 64] & bit != 0 && (ask.is_none() || self.has(i)) {
            self.passed[i as usize / 64] &= !bit;
            self.path.disordered();
            self.disordered = true;
            self.stats.disorders += 1;
        }
        let taken = if self.has(i) {
            self.stats.spare += 1;
            Taken::Spare
        } else {
            self.buf[start..start + c.data.len()].copy_from_slice(c.data);
            self.have[i as usize / 64] |= 1 << (i % 64);
            self.got += 1;
            self.last_progress = now;
            self.retries = 0;
            self.delivered += 1;
            Taken::New
        };
        // Asked for once only: it measures the round trip, and it has
        // overtaken the asks well before it.
        if let Some((s, a)) = ask
            && !a.again
        {
            if taken == Taken::New {
                self.path.sample(now.saturating_sub(a.at));
            }
            self.highest = self.highest.max(s);
        }
        self.trim();
        while let Some(a) = self.flight.front().copied()
            && self.base + 1 + self.path.reorder() <= self.highest
        {
            // The front is awaited (the flight was trimmed) and has been
            // overtaken.
            self.slot[a.index as usize] = 0;
            self.passed[a.index as usize / 64] |= 1 << (a.index % 64);
            self.lost.push_back(a.index);
            self.flying -= 1;
            self.losses += 1;
            self.stats.overtaken += 1;
            self.flight.pop_front();
            self.base += 1;
            self.trim();
        }
        if self.got == self.count {
            // An object smaller than the window: what it lost counts too.
            self.end_round();
            self.over = Some(Poll::Done);
        } else if self.delivered >= self.path.window() {
            self.end_round();
        }
        Ok(taken)
    }
}
