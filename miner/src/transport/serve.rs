//! The side that holds objects: who is sent which chunk, and when.
//!
//! [`Serve`] does not hold the objects. It takes requests
//! ([`Serve::get`]) and says, a chunk at a time, what to send next
//! ([`Serve::next`]): the caller finds the object by its name and sends
//! the chunk, or says that there is none ([`Serve::cancel`]).
//!
//! # What it keeps, and its bounds
//!
//! A request waits here until its chunks are sent: [`MAX_JOBS`] requests
//! in all, [`MAX_JOBS_EACH`] and [`MAX_CHUNKS_EACH`] chunks for any one
//! address. A request over a bound is dropped. Nothing is said: the
//! asking side sees silence, takes it for loss and asks for less.
//!
//! A request for more of the fetch its address asked for last is joined
//! to that one while there is room in it, so that a fetch asking a
//! little at a time, as chunks arrive, is one request here and not
//! many.
//!
//! # Order, and turns
//!
//! The chunks of one address go out in the order it asked for them, over
//! all its requests: the asking side tells what was lost by what was
//! overtaken, and that holds only if nothing here overtakes.
//! Between addresses, turns are taken a chunk at a time, so one large
//! fetch does not hold up a small one.
//!
//! # Pace
//!
//! Chunks go out at a rate ([`Serve::new`]), with a short burst allowed
//! after idleness. A window of two megabytes written to a socket at once
//! overruns the first small buffer on the path, and the losses look to
//! the asking side like a path that carries less than it does.

use std::net::SocketAddr;

use super::token::Tokens;
use super::wire::{Get, MAX_NAME, MAX_RANGES, Range};
use super::{MAX_WINDOW, Micros, SECOND};

/// Requests waiting, at most.
pub const MAX_JOBS: usize = 64;
/// Requests of one address waiting, at most.
pub const MAX_JOBS_EACH: usize = 8;
/// Chunks of one address waiting, at most: two full windows.
pub const MAX_CHUNKS_EACH: u32 = 2 * MAX_WINDOW;
/// Chunks sent at once after idleness, before the pace holds.
pub const BURST: u64 = 32;

struct Job {
    to: SocketAddr,
    transfer: u64,
    name: [u8; MAX_NAME],
    name_len: u8,
    /// The runs still to send, the first of them from where it has got
    /// to, each with the number of its first chunk's ask.
    runs: [(Range, u32); MAX_RANGES],
    n: usize,
    /// The run being sent.
    run: usize,
    /// Chunks still to send.
    left: u32,
}

impl Job {
    /// Adds a run after the others: joined to the last if it follows it
    /// both as chunks and as asks. False, and nothing added, when there
    /// is no room.
    fn push(&mut self, r: Range, seq: u32) -> bool {
        if self.n > self.run {
            let (last, last_seq) = &mut self.runs[self.n - 1];
            if last.start.checked_add(last.count as u32) == Some(r.start)
                && last_seq.wrapping_add(last.count as u32) == seq
                && let Some(count) = last.count.checked_add(r.count)
            {
                last.count = count;
                self.left += r.count as u32;
                return true;
            }
        }
        if self.n == MAX_RANGES {
            return false;
        }
        self.runs[self.n] = (r, seq);
        self.n += 1;
        self.left += r.count as u32;
        true
    }

    /// Adds a request's runs, all or none.
    fn extend(&mut self, get: &Get<'_>) -> bool {
        let before = (self.runs, self.n, self.left);
        // Sent runs make room for new ones.
        self.runs.copy_within(self.run..self.n, 0);
        (self.n, self.run) = (self.n - self.run, 0);
        let mut seq = get.seq;
        for r in get.ranges.as_slice() {
            if !self.push(*r, seq) {
                (self.runs, self.n, self.left) = before;
                return false;
            }
            seq = seq.wrapping_add(r.count as u32);
        }
        true
    }
}

/// A chunk to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Send {
    pub to: SocketAddr,
    pub transfer: u64,
    name: [u8; MAX_NAME],
    name_len: u8,
    pub index: u32,
    /// The number of the ask this chunk answers.
    pub seq: u32,
}

impl Send {
    /// The name the object was asked for by.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// What to do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Send this chunk, and ask again.
    Send(Send),
    /// Nothing may be sent before this time.
    Wait(Micros),
    /// Nothing is waiting.
    Idle,
}

/// Why a request was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// It does not carry the token its address was given.
    Token,
    /// Too much is waiting already, for this address or for all.
    Full,
}

pub struct Serve {
    /// In the order they came.
    jobs: Vec<Job>,
    /// Where the turn has got to: the next is the first job of an
    /// address at or after this place, or failing that the first of all.
    after: usize,
    /// Microseconds a chunk.
    cost: Micros,
    /// The time the next chunk may go, were there no burst: it runs
    /// ahead of the clock by a chunk's cost for each chunk sent, and is
    /// never let fall more than a burst behind it.
    due: Micros,
}

impl Serve {
    /// Serving `rate` chunks a second at most.
    pub fn new(rate: u32) -> Serve {
        assert!(rate > 0);
        Serve { jobs: Vec::with_capacity(MAX_JOBS), after: 0, cost: (SECOND / rate as u64).max(1), due: 0 }
    }

    /// Requests waiting.
    pub fn waiting(&self) -> usize {
        self.jobs.len()
    }

    /// Takes a request from `from`, if it carries `from`'s token and
    /// there is room.
    pub fn get(&mut self, tokens: &Tokens, from: SocketAddr, get: &Get<'_>) -> Result<(), Refused> {
        if !tokens.check(&from, get.token) {
            return Err(Refused::Token);
        }
        let (mut jobs, mut chunks) = (0, 0u32);
        for j in self.jobs.iter().filter(|j| j.to == from) {
            jobs += 1;
            chunks += j.left;
        }
        if self.jobs.len() == MAX_JOBS || jobs == MAX_JOBS_EACH || chunks + get.ranges.chunks() > MAX_CHUNKS_EACH {
            return Err(Refused::Full);
        }
        // More of what its address asked for last: one request with it,
        // while there is room in that one.
        if let Some(j) = self.jobs.iter_mut().rev().find(|j| j.to == from)
            && j.transfer == get.transfer
            && j.name[..j.name_len as usize] == *get.name
            && j.extend(get)
        {
            return Ok(());
        }
        let mut name = [0; MAX_NAME];
        name[..get.name.len()].copy_from_slice(get.name);
        let mut job = Job {
            to: from,
            transfer: get.transfer,
            name,
            name_len: get.name.len() as u8,
            runs: [(Range::default(), 0); MAX_RANGES],
            n: 0,
            run: 0,
            left: 0,
        };
        job.extend(get);
        self.jobs.push(job);
        Ok(())
    }

    /// Forgets what `to` is still to be sent of the fetch `transfer`:
    /// there is no such object, or no more of it.
    pub fn cancel(&mut self, to: SocketAddr, transfer: u64) {
        self.jobs.retain(|j| !(j.to == to && j.transfer == transfer));
    }

    /// The job whose turn it is. Only the first job of an address may
    /// be sent from, and addresses are in the order of their first jobs.
    fn turn(&self) -> Option<usize> {
        let first_of = |i: usize| !self.jobs[..i].iter().any(|j| j.to == self.jobs[i].to);
        let mut firsts = (0..self.jobs.len()).filter(|&i| first_of(i));
        let first = firsts.next()?;
        Some(if first >= self.after { first } else { firsts.find(|&i| i >= self.after).unwrap_or(first) })
    }

    /// What to send at `now`.
    pub fn next(&mut self, now: Micros) -> Next {
        let Some(i) = self.turn() else {
            return Next::Idle;
        };
        // Never more than a burst behind the clock.
        let due = self.due.max(now.saturating_sub((BURST - 1) * self.cost));
        if due > now {
            return Next::Wait(due);
        }
        self.due = due + self.cost;
        let j = &mut self.jobs[i];
        let (r, seq) = &mut j.runs[j.run];
        let send =
            Send { to: j.to, transfer: j.transfer, name: j.name, name_len: j.name_len, index: r.start, seq: *seq };
        // The run is what is left of it.
        r.start = r.start.wrapping_add(1);
        r.count -= 1;
        *seq = seq.wrapping_add(1);
        j.left -= 1;
        if r.count == 0 {
            j.run += 1;
        }
        let (to, done) = (j.to, j.left == 0);
        self.after = i + 1;
        if done {
            self.jobs.remove(i);
            // Its address's next request takes its place, so that the
            // address keeps its turn and no other loses one.
            match self.jobs[i..].iter().position(|j| j.to == to) {
                Some(p) => {
                    let next = self.jobs.remove(i + p);
                    self.jobs.insert(i, next);
                }
                None => self.after = i,
            }
        }
        Next::Send(send)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::wire::Ranges;

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 4000))
    }

    fn ranges(indexes: impl IntoIterator<Item = u32>) -> Ranges {
        let mut r = Ranges::new();
        for i in indexes {
            assert!(r.push(i));
        }
        r
    }

    fn get<'a>(tokens: &Tokens, from: SocketAddr, transfer: u64, name: &'a [u8], r: Ranges) -> Get<'a> {
        // Asks numbered as the chunks are, so that chunks that follow are
        // asks that follow.
        Get { token: tokens.issue(&from), transfer, seq: r.as_slice()[0].start, name, ranges: r }
    }

    /// Everything waiting, with the clock far enough on that the pace
    /// never holds.
    fn drain(s: &mut Serve) -> Vec<(u8, u64, u32)> {
        let mut out = Vec::new();
        let mut now = 1 << 40;
        loop {
            match s.next(now) {
                Next::Send(x) => {
                    out.push((x.to.ip().to_string().rsplit('.').next().unwrap().parse().unwrap(), x.transfer, x.index))
                }
                Next::Wait(t) => now = t,
                Next::Idle => return out,
            }
        }
    }

    #[test]
    fn a_request_without_its_token_is_not_served() {
        let tokens = Tokens::new([1; 32]);
        let mut s = Serve::new(1000);
        let g = get(&tokens, addr(1), 5, b"x", ranges(0..4));
        // The token of another address, and none.
        assert_eq!(s.get(&tokens, addr(2), &g), Err(Refused::Token));
        assert_eq!(s.get(&tokens, addr(1), &Get { token: 0, ..g }), Err(Refused::Token));
        assert_eq!((s.waiting(), s.next(0)), (0, Next::Idle));
        assert_eq!(s.get(&tokens, addr(1), &g), Ok(()));
        let sent = drain(&mut s);
        assert_eq!(sent, [(1, 5, 0), (1, 5, 1), (1, 5, 2), (1, 5, 3)]);
    }

    #[test]
    fn an_addresss_chunks_go_in_the_order_asked() {
        let tokens = Tokens::new([1; 32]);
        let mut s = Serve::new(1000);
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 5, b"x", ranges([7, 8, 2, 30, 31, 32]))).unwrap();
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 5, b"x", ranges([3, 4]))).unwrap();
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 6, b"y", ranges([0]))).unwrap();
        let sent = drain(&mut s);
        assert_eq!(
            sent,
            [(1, 5, 7), (1, 5, 8), (1, 5, 2), (1, 5, 30), (1, 5, 31), (1, 5, 32), (1, 5, 3), (1, 5, 4), (1, 6, 0)]
        );
    }

    #[test]
    fn more_of_the_same_fetch_is_one_request() {
        let tokens = Tokens::new([1; 32]);
        let mut s = Serve::new(1000);
        // A fetch asking eight at a time, far more often than requests
        // may wait.
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 5, b"x", ranges(0..64))).unwrap();
        let Next::Send(first) = s.next(1 << 40) else { panic!() };
        assert_eq!(first.index, 0);
        for k in 8..100 {
            s.get(&tokens, addr(1), &get(&tokens, addr(1), 5, b"x", ranges(8 * k..8 * k + 8))).unwrap();
            assert_eq!(s.waiting(), 1);
        }
        // Lost ones asked again among them: still in the order asked.
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 5, b"x", ranges([3, 4]))).unwrap();
        // Another fetch, or another name, is another request; and what
        // comes after it does not join what came before it.
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 6, b"x", ranges(0..2))).unwrap();
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 6, b"y", ranges(0..2))).unwrap();
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 5, b"x", ranges([9]))).unwrap();
        assert_eq!(s.waiting(), 4);
        let sent: Vec<(u64, u32)> = drain(&mut s).iter().map(|x| (x.1, x.2)).collect();
        let mut want: Vec<(u64, u32)> = (1..800).map(|i| (5, i)).collect();
        want.extend([(5, 3), (5, 4), (6, 0), (6, 1), (6, 0), (6, 1), (5, 9)]);
        assert_eq!(sent, want);
        // Each chunk goes with the number of its ask: the request's, and
        // one more for each chunk after its first, over all its runs.
        let g = |seq, r| Get { seq, ..get(&tokens, addr(2), 1, b"x", r) };
        s.get(&tokens, addr(2), &g(100, ranges([7, 8, 3]))).unwrap();
        s.get(&tokens, addr(2), &g(103, ranges([4, 5]))).unwrap();
        // Chunks that follow, asks that do not: not one run.
        s.get(&tokens, addr(2), &g(200, ranges([6]))).unwrap();
        s.get(&tokens, addr(2), &g(u32::MAX, ranges([0, 1]))).unwrap();
        assert_eq!(s.waiting(), 1);
        let mut sent = Vec::new();
        while let Next::Send(x) = s.next(1 << 41) {
            sent.push((x.index, x.seq));
        }
        assert_eq!(sent, [(7, 100), (8, 101), (3, 102), (4, 103), (5, 104), (6, 200), (0, u32::MAX), (1, 0)]);
        // More runs than one request holds: another request.
        for k in 0..MAX_RANGES as u32 + 1 {
            s.get(&tokens, addr(3), &get(&tokens, addr(3), 1, b"x", ranges([2 * k]))).unwrap();
        }
        assert_eq!(s.waiting(), 2);
        assert_eq!(drain(&mut s).len(), MAX_RANGES + 1);
    }

    #[test]
    fn addresses_take_turns() {
        let tokens = Tokens::new([1; 32]);
        let mut s = Serve::new(1000);
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 1, b"x", ranges(0..6))).unwrap();
        s.get(&tokens, addr(2), &get(&tokens, addr(2), 2, b"x", ranges(0..2))).unwrap();
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 1, b"x", ranges(6..8))).unwrap();
        s.get(&tokens, addr(3), &get(&tokens, addr(3), 3, b"x", ranges(0..3))).unwrap();
        let sent = drain(&mut s);
        let who: Vec<u8> = sent.iter().map(|x| x.0).collect();
        assert_eq!(who, [1, 2, 3, 1, 2, 3, 1, 3, 1, 1, 1, 1, 1]);
        // And each one's own are in order.
        for a in 1..=3 {
            let mine: Vec<u32> = sent.iter().filter(|x| x.0 == a).map(|x| x.2).collect();
            assert!(mine.is_sorted(), "{mine:?}");
        }
    }

    #[test]
    fn what_waits_is_bounded() {
        let tokens = Tokens::new([1; 32]);
        let mut s = Serve::new(1000);
        // Requests of one address.
        for i in 0..MAX_JOBS_EACH as u64 {
            assert_eq!(s.get(&tokens, addr(1), &get(&tokens, addr(1), i, b"x", ranges(0..1))), Ok(()));
        }
        assert_eq!(s.get(&tokens, addr(1), &get(&tokens, addr(1), 99, b"x", ranges(0..1))), Err(Refused::Full));
        // Chunks of one address: two windows, and not one more.
        let window = ranges(0..MAX_WINDOW);
        assert_eq!(s.get(&tokens, addr(2), &get(&tokens, addr(2), 1, b"x", window)), Ok(()));
        assert_eq!(s.get(&tokens, addr(2), &get(&tokens, addr(2), 2, b"x", ranges(0..MAX_WINDOW - 1))), Ok(()));
        assert_eq!(s.get(&tokens, addr(2), &get(&tokens, addr(2), 3, b"x", ranges(0..2))), Err(Refused::Full));
        assert_eq!(s.get(&tokens, addr(2), &get(&tokens, addr(2), 3, b"x", ranges(0..1))), Ok(()));
        // Requests in all.
        let mut n = s.waiting();
        let mut a = 10;
        while n < MAX_JOBS {
            assert_eq!(s.get(&tokens, addr(a), &get(&tokens, addr(a), 1, b"x", ranges(0..1))), Ok(()));
            n += 1;
            a += 1;
        }
        assert_eq!(s.get(&tokens, addr(200), &get(&tokens, addr(200), 1, b"x", ranges(0..1))), Err(Refused::Full));
        // Once sent, there is room again.
        let sent = drain(&mut s);
        assert_eq!(sent.len(), MAX_JOBS_EACH + 2 * MAX_WINDOW as usize + (MAX_JOBS - MAX_JOBS_EACH - 3));
        assert_eq!(s.get(&tokens, addr(200), &get(&tokens, addr(200), 1, b"x", ranges(0..1))), Ok(()));
    }

    #[test]
    fn a_cancelled_fetch_sends_no_more() {
        let tokens = Tokens::new([1; 32]);
        let mut s = Serve::new(1000);
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 1, b"x", ranges(0..50))).unwrap();
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 2, b"y", ranges(0..2))).unwrap();
        s.get(&tokens, addr(2), &get(&tokens, addr(2), 1, b"x", ranges(0..2))).unwrap();
        let Next::Send(first) = s.next(1 << 40) else { panic!() };
        assert_eq!((first.to, first.transfer, first.index, first.name()), (addr(1), 1, 0, b"x".as_slice()));
        s.cancel(addr(1), 1);
        let sent = drain(&mut s);
        assert_eq!(sent, [(2, 1, 0), (1, 2, 0), (2, 1, 1), (1, 2, 1)]);
    }

    #[test]
    fn chunks_go_at_the_rate_after_a_short_burst() {
        let tokens = Tokens::new([1; 32]);
        // A thousand a second: one a millisecond.
        let mut s = Serve::new(1000);
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 1, b"x", ranges(0..1000))).unwrap();
        let start = 5 * SECOND;
        let mut now = start;
        let mut times = Vec::new();
        loop {
            match s.next(now) {
                Next::Send(_) => times.push(now - start),
                Next::Wait(t) => {
                    assert!(t > now);
                    now = t;
                }
                Next::Idle => break,
            }
        }
        assert_eq!(times.len(), 1000);
        // The burst at once, then one each millisecond.
        assert!(times[..BURST as usize].iter().all(|&t| t == 0));
        for (k, &t) in times.iter().enumerate().skip(BURST as usize) {
            assert_eq!(t, (k as u64 + 1 - BURST) * 1000, "chunk {k}");
        }
        // Idle for a long while earns one burst, not the whole while.
        s.get(&tokens, addr(1), &get(&tokens, addr(1), 1, b"x", ranges(0..100))).unwrap();
        let later = now + 60 * SECOND;
        let mut at_once = 0;
        while let Next::Send(_) = s.next(later) {
            at_once += 1;
        }
        assert_eq!(at_once, BURST);
        assert_eq!(s.next(later), Next::Wait(later + 1000));
        // Nor is a caller that comes late owed what it missed.
        let much_later = later + 60 * SECOND;
        let mut at_once = 0;
        while let Next::Send(_) = s.next(much_later) {
            at_once += 1;
        }
        assert_eq!(at_once, BURST);
    }
}
