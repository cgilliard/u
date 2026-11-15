//! What has been learned of the path to one peer: how long an answer
//! takes, and how much the path carries at once.
//!
//! It outlives a fetch. The next object from the same peer starts with
//! the window the last one ended with, so a peer already measured sends
//! a block in as few round trips as its path allows.

use super::{INITIAL_WINDOW, MAX_REORDER, MAX_RETRY, MAX_WINDOW, MIN_RETRY, MIN_WINDOW, Micros, REORDER, RETRY};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    window: u32,
    /// Where the window was last halved to: below it the window doubles
    /// each round, at and above it grows by an eighth. Zero before any
    /// loss.
    threshold: u32,
    /// The smoothed round trip and its variation, in microseconds; no
    /// round trip measured while `measured` is false.
    srtt: u32,
    rttvar: u32,
    measured: bool,
    /// How many places a chunk must be overtaken by to be taken for
    /// lost: more on a path seen to deliver out of order.
    reorder: u32,
}

impl Default for Path {
    fn default() -> Path {
        Path::new()
    }
}

impl Path {
    pub const fn new() -> Path {
        Path { window: INITIAL_WINDOW, threshold: 0, srtt: 0, rttvar: 0, measured: false, reorder: REORDER as u32 }
    }

    /// Chunks that may be asked for and not yet here.
    pub fn window(&self) -> u32 {
        self.window
    }

    /// The smoothed round trip, once one has been measured.
    pub fn round_trip(&self) -> Option<Micros> {
        self.measured.then_some(self.srtt as Micros)
    }

    /// Takes a measured round trip (RFC 6298): the smoothed round trip
    /// moves an eighth of the way to it, the variation a quarter of the
    /// way to how far off it was.
    pub fn sample(&mut self, rtt: Micros) {
        // An hour is as good as forever, and keeps the sums in range.
        let r = rtt.min(3_600_000_000) as u32;
        if !self.measured {
            self.srtt = r;
            self.rttvar = r / 2;
            self.measured = true;
        } else {
            let off = self.srtt.abs_diff(r);
            self.rttvar = ((3 * self.rttvar as u64 + off as u64) / 4) as u32;
            self.srtt = ((7 * self.srtt as u64 + r as u64) / 8) as u32;
        }
    }

    /// How long a silence is a loss: the smoothed round trip and four
    /// times its variation, within [`MIN_RETRY`] and [`MAX_RETRY`];
    /// [`RETRY`] before any round trip is measured.
    pub fn retry(&self) -> Micros {
        if !self.measured {
            return RETRY;
        }
        (self.srtt as Micros + 4 * self.rttvar as Micros).clamp(MIN_RETRY, MAX_RETRY)
    }

    /// How many places a chunk must be overtaken by to be taken for
    /// lost.
    pub fn reorder(&self) -> u64 {
        self.reorder as u64
    }

    /// A chunk taken for lost had only been overtaken: the path
    /// delivers further out of order than was allowed for. Twice as
    /// much is allowed, up to [`MAX_REORDER`].
    pub fn disordered(&mut self) {
        self.reorder = (2 * self.reorder).min(MAX_REORDER);
    }

    /// A round passed in which that did not happen: a sixteenth less
    /// (one less, at the least) is allowed, down to [`REORDER`].
    pub fn ordered(&mut self) {
        self.reorder = (self.reorder - (self.reorder / 16).max(1)).max(REORDER as u32);
    }

    /// The window halves, and grows slowly from there.
    pub fn cut(&mut self) {
        self.window = (self.window / 2).max(MIN_WINDOW);
        self.threshold = self.window;
    }

    /// A round went well with the window full: it doubles while it has
    /// never been cut or is under where it was cut to, and grows by an
    /// eighth otherwise.
    pub fn grow(&mut self) {
        let w = self.window;
        let grown = if self.threshold != 0 && w >= self.threshold { w + w / 8 } else { 2 * w };
        self.window = grown.min(MAX_WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MILLI;

    #[test]
    fn the_retry_time_is_the_round_trip_and_four_times_its_variation() {
        let mut p = Path::new();
        assert_eq!((p.retry(), p.round_trip()), (RETRY, None));
        // The first sample: itself, and half of itself as the variation.
        p.sample(200 * MILLI);
        assert_eq!((p.round_trip(), p.retry()), (Some(200 * MILLI), 600 * MILLI));
        // A steady path: the variation dies away to the floor.
        for _ in 0..40 {
            p.sample(200 * MILLI);
        }
        assert_eq!(p.round_trip(), Some(200 * MILLI));
        assert!(p.retry() < 201 * MILLI);
        // One slow answer moves the round trip an eighth, the variation a
        // quarter of the difference.
        p.sample(1000 * MILLI);
        assert_eq!(p.round_trip(), Some(300 * MILLI));
        assert_eq!(p.retry(), 300 * MILLI + 4 * (800 * MILLI / 4));
        // Within its bounds, whatever is measured.
        let mut fast = Path::new();
        fast.sample(50);
        assert_eq!(fast.retry(), MIN_RETRY);
        let mut slow = Path::new();
        slow.sample(u64::MAX);
        assert_eq!(slow.retry(), MAX_RETRY);
        for _ in 0..100 {
            slow.sample(u64::MAX);
        }
        assert_eq!(slow.retry(), MAX_RETRY);
    }

    #[test]
    fn disorder_is_allowed_for_quickly_and_forgotten_slowly() {
        let mut p = Path::new();
        assert_eq!(p.reorder(), REORDER);
        p.ordered();
        assert_eq!(p.reorder(), REORDER);
        p.disordered();
        p.disordered();
        assert_eq!(p.reorder(), 4 * REORDER);
        p.ordered();
        assert_eq!(p.reorder(), 4 * REORDER - REORDER / 4);
        p.ordered();
        assert_eq!(p.reorder(), 4 * REORDER - REORDER / 4 - 1);
        for _ in 0..20 {
            p.disordered();
        }
        assert_eq!(p.reorder(), MAX_REORDER as u64);
        for _ in 0..200 {
            p.ordered();
        }
        assert_eq!(p.reorder(), REORDER);
    }

    #[test]
    fn the_window_doubles_then_halves_then_creeps() {
        let mut p = Path::new();
        assert_eq!(p.window(), INITIAL_WINDOW);
        p.grow();
        p.grow();
        assert_eq!(p.window(), 4 * INITIAL_WINDOW);
        p.cut();
        assert_eq!(p.window(), 2 * INITIAL_WINDOW);
        p.grow();
        assert_eq!(p.window(), 2 * INITIAL_WINDOW + INITIAL_WINDOW / 4);
        // Never under the least, never over the most.
        for _ in 0..10 {
            p.cut();
        }
        assert_eq!(p.window(), MIN_WINDOW);
        for _ in 0..100 {
            p.grow();
        }
        assert_eq!(p.window(), MAX_WINDOW);
    }
}
