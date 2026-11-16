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
//! Interval (5 seconds)      43             1,030             13
//! Interval (5 seconds)      43             1,030             15
//! Uptime: 300:01:00         Requests_______BytesSent_________PeersLive
//! [2026-10-17 19:31:44:000] 3,333          1,300,000         15
//! Interval (5 seconds)      43             1,030             13
//! ```
//!
//! * Every minute (unless set otherwise): the columns' names, with how
//!   long the node has been up, and under them the whole since it
//!   started, with the time.
//! * Every five seconds (unless set otherwise): what happened in those
//!   seconds.
//!
//! A number that is counted (requests, bytes) shows in a line of the
//! whole how many there have been, and in an interval's line how many
//! there were in it. A number that is a level (peers live) shows in
//! both what it is at that moment.
//!
//! The names and the whole are written in one piece, so that nothing
//! comes between them.

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
    /// milliseconds.
    pub summary: u64,
}

impl Default for Every {
    /// Every five seconds, and the whole every minute.
    fn default() -> Every {
        Every { interval: 5_000, summary: 60_000 }
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
    let (interval, summary) = (every.interval.max(1), every.summary.max(1));
    let started = logger.now();
    let whole = |now: u64, values: &[u64]| {
        let up = now.saturating_sub(started) / 1000;
        logger.write_at(now, &(stats.names(up) + &stats.whole(&Moment::of(now), values)));
    };
    let (mut last, mut last_at, mut summed_at) = (stats.read(), started, started);
    whole(started, &last);
    loop {
        // Until the next time, or until told to stop.
        let stopped = stop.0.lock().unwrap_or_else(|e| e.into_inner());
        let wait = Duration::from_millis(interval.saturating_sub(logger.now().saturating_sub(last_at)).max(1));
        let (stopped, _) =
            stop.1.wait_timeout_while(stopped, wait, |stopped| !*stopped).unwrap_or_else(|e| e.into_inner());
        let (now, values) = (logger.now(), stats.read());
        if *stopped {
            return whole(now, &values);
        }
        drop(stopped);
        if now.saturating_sub(last_at) < interval {
            continue;
        }
        // (Its length as set, not as it fell to the millisecond: the
        // line says which interval it is, and they are all the one.)
        logger.write_at(now, &stats.interval(interval, &last, &values));
        if now.saturating_sub(summed_at) >= summary {
            whole(now, &values);
            summed_at = now;
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

    /// The thread writes the names and the whole at once, what happened
    /// in each interval, the names and the whole again every so often,
    /// and once more when it is stopped.
    #[test]
    fn the_stats_are_written_as_often_as_set() {
        let dir = std::env::temp_dir().join(format!("tabminer-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stats = Arc::new(stats());
        let logger = Logger::open(dir.join("stats.log"), Rotation::default()).unwrap();
        let log = StatsLog::start(logger, Arc::clone(&stats), Every { interval: 40, summary: 150 }).unwrap();
        for _ in 0..10 {
            stats.add(0, 30);
            stats.add(1, 4000);
            stats.set(2, 9);
            std::thread::sleep(Duration::from_millis(35));
        }
        drop(log);
        let text = std::fs::read_to_string(dir.join("stats.log")).unwrap();
        let lines: Vec<&str> = text.lines().skip(1).collect();
        // It begins with the names and the whole, which is little yet.
        assert!(lines[0].starts_with("Uptime: 0:00:00 "));
        assert!(lines[0].ends_with("Requests_______BytesSent_________PeersLive"));
        assert!(lines[1].starts_with('[') && lines[1].split_whitespace().count() == 5, "{}", lines[1]);
        // (How many of each, on a machine that may be busy, is not to
        // be counted on: some, and no more than there was time for.)
        let intervals: Vec<&&str> = lines.iter().filter(|l| l.starts_with("Interval (0.04 seconds) ")).collect();
        let wholes = lines.iter().filter(|l| l.starts_with("Uptime: ")).count();
        assert!((2..=10).contains(&intervals.len()), "{text}");
        assert!((2..=5).contains(&wholes), "{text}");
        assert_eq!(lines.len(), intervals.len() + 2 * wholes);
        // The last word is the whole, and it is the whole.
        let last: Vec<&str> = lines[lines.len() - 1].split_whitespace().skip(2).collect();
        assert_eq!(last, ["300", "40,000", "9"]);
        // The intervals add up to no more than it.
        let counted: u64 = intervals.iter().map(|l| l.split_whitespace().nth(3).unwrap().parse::<u64>().unwrap()).sum();
        assert!((30..=300).contains(&counted), "{counted}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
