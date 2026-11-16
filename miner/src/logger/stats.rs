//! How the node is doing, written down every few seconds.
//!
//! A [`Stats`] is a list of numbers the node keeps as it goes: so many
//! requests, so many bytes sent, so many peers live. Whoever does a
//! thing adds to its number ([`Stats::add`]), which costs one atomic
//! add and nothing else. A thread of its own ([`StatsLog`]) reads them
//! and writes the stats log, a line at a time, in columns:
//!
//! ```text
//! Uptime: 300:00:00         Requests_______BytesSent_________PeersLive
//! [2026-10-17 19:30:44:000] 3,000          1,000,003         14
//! Interval (10 seconds)     43             1,030             13
//! Interval (10 seconds)     51             1,224             15
//! Interval (10 seconds)     48             1,152             15
//! Interval (10 seconds)     40             960               14
//! Interval (10 seconds)     62             1,488             16
//! Interval (10 seconds)     89             2,136             15
//! Uptime: 300:01:00         Requests_______BytesSent_________PeersLive
//! [2026-10-17 19:31:44:000] 3,333          1,007,993         15
//! Interval (10 seconds)     43             1,030             13
//! ```
//!
//! * Every ten seconds (unless set otherwise): what happened in those
//!   seconds.
//! * Every minute (unless set otherwise), after the interval's line
//!   that ends it: the columns' names, with how long the node has been
//!   up, and under them the whole since it started, with the time.
//!
//! # What the numbers are
//!
//! A number that is **counted** (requests, bytes) shows in an
//! interval's line how many there were in it, and in a line of the
//! whole how many there have been in all. The two agree: a whole is the
//! whole before it and the intervals between them, added up. (In the
//! lines above, 3,000 and the six intervals' 333 are 3,333.) The same
//! reading of the numbers is used for the last interval's line and the
//! whole that follows it, so that this is exact, and the two are
//! written at one moment.
//!
//! A number that is a **level** (peers live) is not added up: it shows,
//! in every line, what it was at that moment.
//!
//! Intervals are counted from when the node started, not each from the
//! one before, so they do not drift: so many of them make a whole (six,
//! as set by default), always. When the node stops, what happened since
//! the last interval's line is written as a last, shorter interval,
//! and then the whole, so that the last whole adds up as every other.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::fmt::{column, commas, seconds, uptime};
use super::{Logger, Moment};

/// What kind of number a stat is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Things counted.
    Count,
    /// Bytes counted: a wider column, for they are many.
    Bytes,
    /// How much of something there is now (peers, fetches under way).
    Level,
}

/// How wide the first column is: the time before a line, and a space.
const FIRST: usize = 26;

/// The numbers a node keeps of itself.
pub struct Stats {
    /// Each one's name, kind, and the width of its column.
    names: Vec<(String, Kind, usize)>,
    values: Vec<AtomicU64>,
}

impl Stats {
    /// Stats of these names and kinds, in the order of their columns.
    /// A name is one word (`BytesSent`), since columns are told apart
    /// by the space between them.
    pub fn new(names: &[(&str, Kind)]) -> Stats {
        let width = |name: &str, kind: Kind| {
            // Room for a number in the billions (bytes: in the
            // trillions), and for the name and two more.
            let least = if kind == Kind::Bytes { 18 } else { 15 };
            least.max(name.chars().count() + 2)
        };
        Stats {
            names: names.iter().map(|(n, k)| (n.to_string(), *k, width(n, *k))).collect(),
            values: names.iter().map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Adds `n` to the stat at `index` (its place in the names given).
    pub fn add(&self, index: usize, n: u64) {
        self.values[index].fetch_add(n, Ordering::Relaxed);
    }

    /// Sets the stat at `index`: for a [`Kind::Level`].
    pub fn set(&self, index: usize, value: u64) {
        self.values[index].store(value, Ordering::Relaxed);
    }

    /// Every stat as it stands.
    pub fn read(&self) -> Vec<u64> {
        self.values.iter().map(|v| v.load(Ordering::Relaxed)).collect()
    }

    /// A line: `first` in the first column, then `cell` of each stat in
    /// its own, filled out with `fill`; the last is not filled out, so
    /// that no line ends in spaces.
    fn line(&self, first: &str, fill: char, cell: impl Fn(usize) -> String) -> String {
        let mut out = column(first, FIRST, ' ');
        for (i, (_, _, width)) in self.names.iter().enumerate() {
            match i + 1 == self.names.len() {
                true => out += &cell(i),
                false => out += &column(&cell(i), *width, fill),
            }
        }
        out.push('\n');
        out
    }

    /// The columns' names, after how long the node has been up:
    /// `Uptime: 300:00:00         Requests_______BytesSent_________PeersLive`.
    pub fn names(&self, up_seconds: u64) -> String {
        self.line(&format!("Uptime: {}", uptime(up_seconds)), '_', |i| self.names[i].0.clone())
    }

    /// The whole since the start, after the time:
    /// `[2026-10-17 19:30:44:000] 3,000          1,000,003         14`.
    pub fn whole(&self, moment: &Moment, now: &[u64]) -> String {
        self.line(&moment.header(), ' ', |i| commas(now[i]))
    }

    /// What happened in an interval of `millis`, from the stats as they
    /// were `before` it to as they are `now`:
    /// `Interval (5 seconds)      43             1,030             13`.
    pub fn interval(&self, millis: u64, before: &[u64], now: &[u64]) -> String {
        self.line(&format!("Interval ({})", seconds(millis)), ' ', |i| match self.names[i].1 {
            Kind::Level => commas(now[i]),
            Kind::Count | Kind::Bytes => commas(now[i].saturating_sub(before[i])),
        })
    }
}

/// When the stats are written down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Every {
    /// How often what happened since the last time is written, in
    /// milliseconds.
    pub interval: u64,
    /// How often the names and the whole since the start are, in
    /// milliseconds: taken to the nearest whole number of intervals,
    /// one at the least.
    pub summary: u64,
}

impl Default for Every {
    /// Every ten seconds, and the whole every minute: six intervals to
    /// a whole.
    fn default() -> Every {
        Every { interval: 10_000, summary: 60_000 }
    }
}

/// The thread that writes the stats log.
pub struct StatsLog {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl StatsLog {
    /// Starts writing `stats` to `logger`, as often as `every` says:
    /// the names and the whole at once, and then as time passes.
    pub fn start(logger: Logger, stats: Arc<Stats>, every: Every) -> io::Result<StatsLog> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new().name("log stats".into()).spawn(move || write(&logger, &stats, every, &stop))?
        };
        Ok(StatsLog { stop, thread: Some(thread) })
    }
}

impl Drop for StatsLog {
    /// The whole since the start is written once more, and the thread
    /// ends.
    fn drop(&mut self) {
        *self.stop.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.stop.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn write(logger: &Logger, stats: &Stats, every: Every, stop: &(Mutex<bool>, Condvar)) {
    let interval = every.interval.max(1);
    // So many intervals to a whole.
    let to_a_whole = ((every.summary + interval / 2) / interval).max(1);
    let started = logger.now();
    let whole = |now: u64, values: &[u64]| {
        let up = now.saturating_sub(started) / 1000;
        logger.write_at(now, &(stats.names(up) + &stats.whole(&Moment::of(now), values)));
    };
    // The stats as of the last interval's line, when that was, and how
    // many intervals have been written.
    let (mut last, mut last_at, mut written) = (stats.read(), started, 0u64);
    whole(started, &last);
    loop {
        // Until the next interval is over, counted from the start, or
        // until told to stop.
        let due = started + (written + 1) * interval;
        let stopped = stop.0.lock().unwrap_or_else(|e| e.into_inner());
        let wait = Duration::from_millis(due.saturating_sub(logger.now()).max(1));
        let (stopped, _) =
            stop.1.wait_timeout_while(stopped, wait, |stopped| !*stopped).unwrap_or_else(|e| e.into_inner());
        // One reading, for the interval's line and for the whole that
        // may follow it: so that the wholes add up.
        let (now, values) = (logger.now(), stats.read());
        if *stopped {
            // What happened since the last line, as a last interval of
            // whatever length it was; and the whole.
            if now > last_at {
                logger.write_at(now, &stats.interval(now - last_at, &last, &values));
            }
            return whole(now, &values);
        }
        drop(stopped);
        if now < due {
            continue;
        }
        logger.write_at(now, &stats.interval(interval, &last, &values));
        written += 1;
        if written.is_multiple_of(to_a_whole) {
            whole(now, &values);
        }
        logger.rotate_if_due();
        (last, last_at) = (values, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::Rotation;

    /// 2026-10-17 19:30:44.000 UTC.
    const T: u64 = 1_792_265_444_000;

    fn stats() -> Stats {
        Stats::new(&[("Requests", Kind::Count), ("BytesSent", Kind::Bytes), ("PeersLive", Kind::Level)])
    }

    /// The lines of `docs/stat_sample.log`.
    #[test]
    fn the_lines_are_in_columns() {
        let s = stats();
        let lines = [
            s.names(300 * 3600),
            s.whole(&Moment::of(T), &[3000, 1_000_003, 14]),
            s.interval(5000, &[3000, 1_000_003, 14], &[3043, 1_001_033, 13]),
            s.interval(5000, &[3043, 1_001_033, 13], &[3086, 1_002_063, 15]),
            s.names(300 * 3600 + 60),
            s.whole(&Moment::of(T + 60_000), &[3333, 1_300_000, 15]),
        ];
        assert_eq!(
            lines.concat(),
            "Uptime: 300:00:00         Requests_______BytesSent_________PeersLive\n\
             [2026-10-17 19:30:44:000] 3,000          1,000,003         14\n\
             Interval (5 seconds)      43             1,030             13\n\
             Interval (5 seconds)      43             1,030             15\n\
             Uptime: 300:01:00         Requests_______BytesSent_________PeersLive\n\
             [2026-10-17 19:31:44:000] 3,333          1,300,000         15\n"
        );
        // Each column begins at the same place in every line, and no
        // line ends in spaces.
        for line in lines.iter().map(|l| l.trim_end_matches('\n')) {
            assert!(!line.ends_with(' '));
            for at in [26, 41, 59] {
                assert!(
                    line.is_char_boundary(at) && &line[at - 1..at] != "," && !line[at..].starts_with([' ', '_']),
                    "{line}"
                );
            }
        }
    }

    #[test]
    fn a_column_is_as_wide_as_its_name_and_its_numbers_need() {
        let s = Stats::new(&[
            ("N", Kind::Count),
            ("AVeryLongNameForAColumn", Kind::Level),
            ("B", Kind::Bytes),
            ("Last", Kind::Count),
        ]);
        assert_eq!(
            s.names(7),
            "Uptime: 0:00:07           N______________AVeryLongNameForAColumn__B_________________Last\n"
        );
        // A number too wide for its column moves the rest of its line
        // over, and is not run into.
        let line = s.interval(250, &[0; 4], &[u64::MAX, 5, 12_345_678_901_234, 1]);
        assert_eq!(
            line,
            "Interval (0.25 seconds)   18,446,744,073,709,551,615 5                        12,345,678,901,234 1\n"
        );
    }

    /// The thread writes the names and the whole at once, then so many
    /// intervals to each whole, and every whole is the one before it
    /// and the intervals between, added up: to the last, written when
    /// it is stopped.
    #[test]
    fn the_wholes_are_the_intervals_added_up() {
        let dir = std::env::temp_dir().join(format!("tabminer-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stats = Arc::new(stats());
        let logger = Logger::open(dir.join("stats.log"), Rotation::default()).unwrap();
        // Three intervals to a whole.
        let log = StatsLog::start(logger, Arc::clone(&stats), Every { interval: 30, summary: 90 }).unwrap();
        let adding = {
            let stats = Arc::clone(&stats);
            std::thread::spawn(move || {
                for n in 0..4000u64 {
                    stats.add(0, 1);
                    stats.add(1, 24);
                    stats.set(2, 9 + n % 5);
                    if n % 10 == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            })
        };
        adding.join().unwrap();
        drop(log);
        let text = std::fs::read_to_string(dir.join("stats.log")).unwrap();
        let lines: Vec<&str> = text.lines().skip(1).collect();
        let number = |word: &str| word.replace(',', "").parse::<u64>().unwrap();
        // The lines in order: what is expected of a whole from the one
        // before it and the intervals since.
        let (mut requests, mut bytes, mut since_whole, mut wholes) = (0u64, 0u64, 0, 0);
        let mut at = 0;
        while at < lines.len() {
            let words: Vec<&str> = lines[at].split_whitespace().collect();
            if lines[at].starts_with("Uptime: ") {
                assert!(lines[at].ends_with("Requests_______BytesSent_________PeersLive"));
                let whole: Vec<&str> = lines[at + 1].split_whitespace().collect();
                assert!(whole[0].starts_with('[') && whole.len() == 5, "{}", lines[at + 1]);
                // (The first is whatever there was when the thread began:
                // from it on, each is the one before and what came between.)
                if wholes == 0 {
                    (requests, bytes) = (number(whole[2]), number(whole[3]));
                }
                assert_eq!((number(whole[2]), number(whole[3])), (requests, bytes), "the whole at line {at}\n{text}");
                // Three intervals to a whole: but before the first,
                // which has none, and the last, which has what there
                // was time for and one shorter.
                let last = at + 2 == lines.len();
                assert!(wholes == 0 || since_whole == 3 || (last && since_whole <= 3), "{since_whole}\n{text}");
                (since_whole, wholes, at) = (0, wholes + 1, at + 2);
            } else {
                assert_eq!(words[0], "Interval", "{}", lines[at]);
                // (Its last word but two: the label is of two words or
                // three.)
                let n = words.len();
                requests += number(words[n - 3]);
                bytes += number(words[n - 2]);
                // A level is what it was then, and is not added up.
                assert!((9..14).contains(&number(words[n - 1])));
                (since_whole, at) = (since_whole + 1, at + 1);
            }
        }
        // The last whole is everything.
        assert_eq!((requests, bytes), (4000, 96_000));
        assert!(wholes >= 3, "{text}");
        assert!(lines.iter().filter(|l| l.starts_with("Interval (0.03 seconds) ")).count() >= 6, "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
