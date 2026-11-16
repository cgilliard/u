//! How the node is doing, written down every few seconds.
//!
//! A [`Stats`] is a list of numbers the node keeps as it goes: so many
//! requests, so many bytes sent, so many peers live. Whoever does a
//! thing adds to its number ([`Stats::add`]), which costs one atomic
//! add and nothing else. A thread of its own ([`StatsLog`]) reads them
//! and writes two kinds of block to the stats log:
//!
//! * every few seconds (five, unless set otherwise), what happened in
//!   those seconds;
//! * every minute (unless set otherwise), the whole since the node
//!   started.
//!
//! ```text
//! [2026-10-17 19:49:35:000] last 5.0 s
//!     requests                    1,204          240.8 /s
//!     bytes sent            105,735,600           21.1 MB/s
//!     peers live                     14
//! [2026-10-17 19:50:00:000] since start, 2 h 14 m 05 s
//!     requests               41,022,117          5,099.4 /s
//!     bytes sent          9,812,004,551              1.2 MB/s
//!     peers live                     14
//! ```
//!
//! A block is written in one piece, so nothing comes between its lines.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::{Logger, Moment};

/// What kind of number a stat is: how it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Things counted: shown with how many a second.
    Count,
    /// Bytes counted: shown with bytes a second, in the unit that fits.
    Bytes,
    /// How much of something there is now (peers, fetches under way):
    /// shown as it stands, with no rate.
    Level,
}

/// The numbers a node keeps of itself.
pub struct Stats {
    names: Vec<(String, Kind)>,
    values: Vec<AtomicU64>,
}

impl Stats {
    /// Stats of these names and kinds, in the order they are shown.
    pub fn new(names: &[(&str, Kind)]) -> Stats {
        Stats {
            names: names.iter().map(|(n, k)| (n.to_string(), *k)).collect(),
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

    /// A block: `title` on a line with the time before it, then a line
    /// a stat. A counted stat shows how much it grew from `before` to
    /// `now` and that over `seconds`; a level shows what it is in
    /// `now`.
    pub fn block(&self, moment: &Moment, title: &str, seconds: f64, before: &[u64], now: &[u64]) -> String {
        let wide = self.names.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
        let mut out = format!("{} {title}\n", moment.header());
        for (i, (name, kind)) in self.names.iter().enumerate() {
            let pad = " ".repeat(wide - name.chars().count());
            match kind {
                Kind::Level => out += &format!("    {name}{pad}  {:>18}\n", grouped(now[i])),
                Kind::Count | Kind::Bytes => {
                    let grew = now[i].saturating_sub(before[i]);
                    let rate = if seconds > 0.0 { grew as f64 / seconds } else { 0.0 };
                    let (rate, unit) = match kind {
                        Kind::Bytes => bytes_a_second(rate),
                        _ => (rate, "/s"),
                    };
                    out += &format!("    {name}{pad}  {:>18}  {:>14} {unit}\n", grouped(grew), decimal(rate));
                }
            }
        }
        out
    }
}

/// A whole number with a comma between each three digits.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A number to one place of decimals, its whole part grouped.
fn decimal(x: f64) -> String {
    let tenths = (x * 10.0).round() as u64;
    format!("{}.{}", grouped(tenths / 10), tenths % 10)
}

/// A rate of bytes in the unit that fits it.
fn bytes_a_second(rate: f64) -> (f64, &'static str) {
    match rate {
        r if r >= 1e9 => (r / 1e9, "GB/s"),
        r if r >= 1e6 => (r / 1e6, "MB/s"),
        r if r >= 1e3 => (r / 1e3, "KB/s"),
        r => (r, "B/s"),
    }
}

/// A length of time as it is said: `2 h 14 m 05 s`, `3 d 00 h 00 m 12 s`.
pub fn lasting(seconds: u64) -> String {
    let (d, h, m, s) = (seconds / 86_400, seconds % 86_400 / 3600, seconds % 3600 / 60, seconds % 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s} s"),
        (0, 0, _) => format!("{m} m {s:02} s"),
        (0, _, _) => format!("{h} h {m:02} m {s:02} s"),
        _ => format!("{d} d {h:02} h {m:02} m {s:02} s"),
    }
}

/// When the stats are written down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Every {
    /// How often what happened since the last time is written, in
    /// milliseconds.
    pub interval: u64,
    /// How often the whole since the start is, in milliseconds.
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
    /// Starts writing `stats` to `logger`, as often as `every` says.
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
    let zero = vec![0; stats.values.len()];
    let (mut last, mut last_at, mut summed_at) = (stats.read(), started, started);
    let since_start = |now: u64, values: &[u64]| {
        let seconds = now.saturating_sub(started) as f64 / 1000.0;
        let title = format!("since start, {}", lasting(now.saturating_sub(started) / 1000));
        logger.write_at(now, &stats.block(&Moment::of(now), &title, seconds, &zero, values));
    };
    loop {
        // Until the next time, or until told to stop.
        let stopped = stop.0.lock().unwrap_or_else(|e| e.into_inner());
        let wait = Duration::from_millis(interval.saturating_sub(logger.now().saturating_sub(last_at)).max(1));
        let (stopped, _) =
            stop.1.wait_timeout_while(stopped, wait, |stopped| !*stopped).unwrap_or_else(|e| e.into_inner());
        let (now, values) = (logger.now(), stats.read());
        if *stopped {
            return since_start(now, &values);
        }
        drop(stopped);
        if now.saturating_sub(last_at) < interval {
            continue;
        }
        let seconds = now.saturating_sub(last_at) as f64 / 1000.0;
        let title = format!("last {seconds:.1} s");
        logger.write_at(now, &stats.block(&Moment::of(now), &title, seconds, &last, &values));
        if now.saturating_sub(summed_at) >= summary {
            since_start(now, &values);
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

    /// 2026-10-17 19:49:35.000 UTC.
    const T: u64 = 1_792_266_575_000;

    fn stats() -> Stats {
        Stats::new(&[
            ("requests", Kind::Count),
            ("bytes sent", Kind::Bytes),
            ("peers live", Kind::Level),
            ("blocks", Kind::Count),
        ])
    }

    #[test]
    fn a_block_is_laid_out_to_be_read() {
        let s = stats();
        let before = [1000, 5_000_000, 12, 7];
        let now = [2204, 110_735_600, 14, 7];
        assert_eq!(
            s.block(&Moment::of(T), "last 5.0 s", 5.0, &before, &now),
            "[2026-10-17 19:49:35:000] last 5.0 s\n\
             \x20   requests                 1,204           240.8 /s\n\
             \x20   bytes sent         105,735,600            21.1 MB/s\n\
             \x20   peers live                  14\n\
             \x20   blocks                       0             0.0 /s\n"
        );
        // The whole since the start: from nothing.
        let whole = s.block(
            &Moment::of(T + 25_000),
            "since start, 2 h 14 m 05 s",
            8045.0,
            &[0; 4],
            &[41_022_117, 9_812_004_551, 14, 13],
        );
        assert_eq!(
            whole,
            "[2026-10-17 19:50:00:000] since start, 2 h 14 m 05 s\n\
             \x20   requests            41,022,117         5,099.1 /s\n\
             \x20   bytes sent       9,812,004,551             1.2 MB/s\n\
             \x20   peers live                  14\n\
             \x20   blocks                      13             0.0 /s\n"
        );
        // The numbers of a column end under one another, whatever
        // their size.
        let ends =
            |l: &str, n: usize| l.split_whitespace().take(n + 1).map(|w| l.find(w).unwrap() + w.len()).last().unwrap();
        let lines: Vec<&str> = whole.lines().skip(1).collect();
        assert!(
            lines
                .iter()
                .all(|l| ends(l, 1 + (l.starts_with("    bytes") || l.starts_with("    peers")) as usize) == 34)
        );
    }

    #[test]
    fn numbers_and_times_are_written_as_they_are_said() {
        assert_eq!([grouped(0), grouped(999), grouped(1000), grouped(1_234_567)], ["0", "999", "1,000", "1,234,567"]);
        assert_eq!(grouped(u64::MAX), "18,446,744,073,709,551,615");
        assert_eq!([decimal(0.0), decimal(0.04), decimal(0.05), decimal(17_622.56)], ["0.0", "0.0", "0.1", "17,622.6"]);
        assert_eq!(bytes_a_second(999.0), (999.0, "B/s"));
        assert_eq!(bytes_a_second(1500.0), (1.5, "KB/s"));
        assert_eq!(bytes_a_second(21_147_120.0).1, "MB/s");
        assert_eq!(bytes_a_second(3e9), (3.0, "GB/s"));
        assert_eq!([lasting(0), lasting(59), lasting(60), lasting(3599)], ["0 s", "59 s", "1 m 00 s", "59 m 59 s"]);
        assert_eq!([lasting(8045), lasting(259_212)], ["2 h 14 m 05 s", "3 d 00 h 00 m 12 s"]);
    }

    /// The thread writes what happened in each interval, the whole
    /// every so often, and the whole once more when it is stopped.
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
        let (intervals, wholes) = (text.matches("] last ").count(), text.matches("] since start, ").count());
        // (How many, on a machine that may be busy, is not to be
        // counted on: some of each, and no more than there was time for.)
        assert!((2..=10).contains(&intervals), "{intervals}\n{text}");
        assert!((1..=4).contains(&wholes), "{wholes}\n{text}");
        // The last word is the whole, and it is the whole: three
        // hundred requests.
        let last = &text[text.rfind("] since start, ").unwrap()..];
        let requests: Vec<&str> = last.lines().nth(1).unwrap().split_whitespace().collect();
        assert_eq!((requests[0], requests[1]), ("requests", "300"));
        assert!(last.lines().nth(3).unwrap().ends_with(" 9"));
        // The intervals add up to it.
        let counted: u64 = text
            .split("] last ")
            .skip(1)
            .map(|block| block.lines().nth(1).unwrap().split_whitespace().nth(1).unwrap().parse::<u64>().unwrap())
            .sum();
        assert!(counted <= 300 && counted >= 30, "{counted}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
