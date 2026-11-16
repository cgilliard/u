//! Logs: lines written to a file, with the time before each, and the
//! file put aside for a new one when it has grown too large or too old.
//!
//! A [`Logger`] is one log. A node has several (what it does, what it
//! is asked, how it is doing), each its own `Logger` on its own file.
//!
//! # Writing
//!
//! * [`Logger::log`] writes a line with the time before it:
//!   `[2026-10-17 19:49:31:471] the line`.
//! * [`Logger::log_no_header`] writes the line as it is given, for a log
//!   whose lines are laid out by whoever writes them.
//! * [`Logger::log_all`] is [`Logger::log`], and the same line to the
//!   terminal (standard error) as well.
//!
//! Each call is one line and one write: lines from several threads are
//! never mixed into one another, and what was written before a crash
//! is in the file.
//!
//! The time is by the universal clock (UTC), not the place's: the
//! standard library knows of no time zones, and a log that is compared
//! with another node's is better off without them.
//!
//! # Rotation
//!
//! Before a line is written, the file is put aside if either limit of
//! [`Rotation`] is passed: it has been written to for longer than
//! [`Rotation::max_age`], or the line would take it over
//! [`Rotation::max_size`]. Put aside means renamed, with the time it
//! was put aside in its name, and a new file begun under the old name:
//!
//! ```text
//! tabernacle.log  ->  tabernacle_R_02_03_2026_10_00.log
//!                     (month, day, year, hour, minute)
//! ```
//!
//! A line is never split between two files. If two files are put aside
//! within one minute, the second and later have a count after the
//! minute (`..._10_00_2.log`), so that none is written over.
//!
//! # A log must not bring the node down
//!
//! Nothing here returns an error or panics once the log is open. A line
//! that cannot be written is counted ([`Logger::failures`]), and the
//! first such failure is said once on the terminal.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// When a log's file is put aside for a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// The longest a file is written to, in seconds; zero for no limit.
    pub max_age: u64,
    /// The most bytes a file holds; zero for no limit. A single line
    /// longer than this is written all the same, to a file of its own.
    pub max_size: u64,
}

impl Default for Rotation {
    /// An hour, or a mebibyte, whichever comes first.
    fn default() -> Rotation {
        Rotation { max_age: 3600, max_size: 1 << 20 }
    }
}

/// A time by the calendar and the clock, in UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Moment {
    pub year: u64,
    pub month: u64,
    pub day: u64,
    pub hour: u64,
    pub minute: u64,
    pub second: u64,
    pub milli: u64,
}

impl Moment {
    /// The moment `millis` milliseconds after the start of 1970.
    pub fn of(millis: u64) -> Moment {
        let (seconds, milli) = (millis / 1000, millis % 1000);
        let (days, of_day) = (seconds / 86_400, seconds % 86_400);
        // Days to a date, by the calendar's cycle of four hundred years
        // (146,097 days), counted from the first of March so that the
        // day a leap year adds is the last of its year.
        let z = days + 719_468;
        let (era, day_of_era) = (z / 146_097, z % 146_097);
        let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let march_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * march_month + 2) / 5 + 1;
        let month = if march_month < 10 { march_month + 3 } else { march_month - 9 };
        let year = year_of_era + era * 400 + (month <= 2) as u64;
        Moment { year, month, day, hour: of_day / 3600, minute: of_day % 3600 / 60, second: of_day % 60, milli }
    }

    /// What goes before a line: `[2026-10-17 19:49:31:471]`.
    pub fn header(&self) -> String {
        format!(
            "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}:{:03}]",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.milli
        )
    }

    /// What goes into the name of a file put aside at this moment:
    /// `_R_02_03_2026_10_00` (month, day, year, hour, minute).
    pub fn rotated(&self) -> String {
        format!("_R_{:02}_{:02}_{:04}_{:02}_{:02}", self.month, self.day, self.year, self.hour, self.minute)
    }
}

/// The clock: milliseconds since the start of 1970.
type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

struct Inner {
    /// The file being written to; none if it could not be opened after
    /// the last was put aside, and is to be tried again.
    file: Option<File>,
    /// Bytes in it.
    size: u64,
    /// When it began to be written to, by this logger.
    since: u64,
}

/// One log.
pub struct Logger {
    path: PathBuf,
    rotation: Rotation,
    clock: Clock,
    inner: Mutex<Inner>,
    failures: AtomicU64,
}

impl Logger {
    /// Opens the log at `path`, which is made if it is not there and
    /// added to if it is. Its directory must exist.
    ///
    /// A file found there counts as begun now: how long it had been
    /// written to before is not known. What it holds counts towards
    /// its size.
    pub fn open(path: impl Into<PathBuf>, rotation: Rotation) -> io::Result<Logger> {
        Logger::with_clock(path, rotation, Box::new(system_clock))
    }

    fn with_clock(path: impl Into<PathBuf>, rotation: Rotation, clock: Clock) -> io::Result<Logger> {
        let path = path.into();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        let since = clock();
        Ok(Logger {
            path,
            rotation,
            clock,
            inner: Mutex::new(Inner { file: Some(file), size, since }),
            failures: AtomicU64::new(0),
        })
    }

    /// The file being written to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lines that could not be written.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Writes `line` with the time before it.
    pub fn log(&self, line: &str) {
        let now = (self.clock)();
        self.write(now, &format!("{} {line}\n", Moment::of(now).header()));
    }

    /// Writes `line` as it is, with nothing before it.
    pub fn log_no_header(&self, line: &str) {
        self.write((self.clock)(), &format!("{line}\n"));
    }

    /// Writes `line` with the time before it, to the log and to the
    /// terminal (standard error) alike.
    pub fn log_all(&self, line: &str) {
        let now = (self.clock)();
        let text = format!("{} {line}\n", Moment::of(now).header());
        // (The terminal may be gone; the log is what matters.)
        let _ = io::stderr().write_all(text.as_bytes());
        self.write(now, &text);
    }

    /// Puts the file aside if it has been written to for longer than it
    /// may be, though nothing is being written: for a caller that looks
    /// to it now and then, so that a quiet log is still put aside on
    /// time.
    pub fn rotate_if_due(&self) {
        let now = (self.clock)();
        let mut inner = self.lock();
        if inner.size > 0 && self.aged(&inner, now) {
            self.rotate_locked(&mut inner, now);
        }
    }

    /// Puts the file aside now, whatever its age and size, and begins a
    /// new one. The name it was given: none if it held nothing (an
    /// empty file is not worth keeping) or could not be renamed.
    pub fn rotate(&self) -> Option<PathBuf> {
        let now = (self.clock)();
        let mut inner = self.lock();
        self.rotate_locked(&mut inner, now)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn aged(&self, inner: &Inner, now: u64) -> bool {
        self.rotation.max_age > 0 && now.saturating_sub(inner.since) >= self.rotation.max_age.saturating_mul(1000)
    }

    fn failed(&self, what: &str, e: &io::Error) {
        if self.failures.fetch_add(1, Ordering::Relaxed) == 0 {
            let _ = writeln!(io::stderr(), "the log {} cannot be {what}: {e}", self.path.display());
        }
    }

    fn write(&self, now: u64, text: &str) {
        let mut inner = self.lock();
        let over = self.rotation.max_size > 0 && inner.size + text.len() as u64 > self.rotation.max_size;
        // (An empty file is not put aside: for its age there is nothing
        // to keep, and a line too long for any file goes into this one.)
        if inner.size > 0 && (over || self.aged(&inner, now)) {
            self.rotate_locked(&mut inner, now);
        }
        if inner.file.is_none() {
            match OpenOptions::new().create(true).append(true).open(&self.path) {
                Ok(file) => {
                    inner.size = file.metadata().map_or(0, |m| m.len());
                    inner.since = now;
                    inner.file = Some(file);
                }
                Err(e) => return self.failed("opened", &e),
            }
        }
        match inner.file.as_mut().expect("opened above").write_all(text.as_bytes()) {
            Ok(()) => inner.size += text.len() as u64,
            Err(e) => self.failed("written to", &e),
        }
    }

    /// The name a file put aside at `moment` is given: the log's own,
    /// with the moment before its ending, and a count after that if
    /// the name is taken.
    fn aside(&self, moment: &Moment) -> PathBuf {
        let stem = self.path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let ending = self.path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
        let named = |count: u32| {
            let count = if count == 1 { String::new() } else { format!("_{count}") };
            self.path.with_file_name(format!("{stem}{}{count}{ending}", moment.rotated()))
        };
        (1..).map(named).find(|p| !p.exists()).expect("some count is free")
    }

    fn rotate_locked(&self, inner: &mut Inner, now: u64) -> Option<PathBuf> {
        if inner.size == 0 {
            inner.since = now;
            return None;
        }
        // Closed before it is renamed: some systems will not rename a
        // file that is open.
        inner.file = None;
        let aside = self.aside(&Moment::of(now));
        let renamed = std::fs::rename(&self.path, &aside);
        if let Err(e) = &renamed {
            // The same file goes on being written to.
            self.failed("put aside", e);
        }
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(file) => {
                inner.size = file.metadata().map_or(0, |m| m.len());
                inner.since = now;
                inner.file = Some(file);
            }
            Err(e) => self.failed("opened", &e),
        }
        renamed.ok().map(|()| aside)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A directory of this test's own, removed when it is done.
    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Dir {
            static COUNT: AtomicU64 = AtomicU64::new(0);
            let unique =
                format!("tabminer-log-{name}-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed));
            let path = std::env::temp_dir().join(unique);
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Dir(path)
        }

        /// The names of the files in it, in order.
        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.0.join(name)).unwrap()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A clock the test moves.
    fn clock(start: u64) -> (Arc<AtomicU64>, Clock) {
        let now = Arc::new(AtomicU64::new(start));
        let read = Arc::clone(&now);
        (now, Box::new(move || read.load(Ordering::Relaxed)))
    }

    /// 2026-10-17 19:49:31.471 UTC.
    const T: u64 = 1_792_266_571_471;

    #[test]
    fn a_moment_is_its_date_and_time() {
        let m = |millis| {
            let m = Moment::of(millis);
            (m.year, m.month, m.day, m.hour, m.minute, m.second, m.milli)
        };
        assert_eq!(m(0), (1970, 1, 1, 0, 0, 0, 0));
        assert_eq!(m(T), (2026, 10, 17, 19, 49, 31, 471));
        // The last and the first moment of a year; the day a leap year
        // adds, in a year that has it, one that does not, and the two
        // centuries that differ.
        assert_eq!(m(1_767_225_599_999), (2025, 12, 31, 23, 59, 59, 999));
        assert_eq!(m(1_767_225_600_000), (2026, 1, 1, 0, 0, 0, 0));
        assert_eq!(m(1_709_164_800_000), (2024, 2, 29, 0, 0, 0, 0));
        assert_eq!(m(1_677_628_800_000), (2023, 3, 1, 0, 0, 0, 0));
        assert_eq!(m(951_782_400_000), (2000, 2, 29, 0, 0, 0, 0));
        assert_eq!(m(4_107_542_400_000), (2100, 3, 1, 0, 0, 0, 0));
        // Every day for four hundred years follows the one before.
        let (mut last, mut seen) = ((1969u64, 12u64, 31u64), 0u64);
        for day in 0..146_097u64 {
            let d = Moment::of(day * 86_400_000);
            let leap = d.year % 4 == 0 && (d.year % 100 != 0 || d.year % 400 == 0);
            let days_in = [31, 28 + leap as u64, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][d.month as usize - 1];
            assert!(d.day >= 1 && d.day <= days_in, "{d:?}");
            let next = match (d.day, d.month) {
                (1, 1) => (d.year - 1, 12, 31) == last,
                (1, _) => (d.year, d.month - 1) == (last.0, last.1),
                _ => (d.year, d.month, d.day - 1) == last,
            };
            assert!(next, "{last:?} then {d:?}");
            last = (d.year, d.month, d.day);
            seen += 1;
        }
        assert_eq!((seen, last), (146_097, (2369, 12, 31)));
    }

    #[test]
    fn the_header_and_the_name_put_aside_are_as_laid_down() {
        assert_eq!(Moment::of(T).header(), "[2026-10-17 19:49:31:471]");
        assert_eq!(Moment::of(5).header(), "[1970-01-01 00:00:00:005]");
        // Month, day, year, hour, minute.
        assert_eq!(Moment::of(T).rotated(), "_R_10_17_2026_19_49");
        assert_eq!(Moment::of(1_770_112_800_000).rotated(), "_R_02_03_2026_10_00");
    }

    #[test]
    fn lines_are_written_with_the_time_or_as_they_are() {
        let dir = Dir::new("lines");
        let (now, clock) = clock(T);
        let log = Logger::with_clock(dir.0.join("tabernacle.log"), Rotation::default(), clock).unwrap();
        log.log("started");
        now.store(T + 1529, Ordering::Relaxed);
        log.log_no_header("peers 14 blocks 3");
        log.log("a line\nof two lines");
        log.log_all("to the terminal as well");
        log.log("");
        assert_eq!(
            dir.read("tabernacle.log"),
            "[2026-10-17 19:49:31:471] started\n\
             peers 14 blocks 3\n\
             [2026-10-17 19:49:33:000] a line\nof two lines\n\
             [2026-10-17 19:49:33:000] to the terminal as well\n\
             [2026-10-17 19:49:33:000] \n"
        );
        assert_eq!((log.failures(), dir.files()), (0, vec!["tabernacle.log".to_string()]));
        // Opened again, it is added to.
        drop(log);
        let log = Logger::open(dir.0.join("tabernacle.log"), Rotation::default()).unwrap();
        log.log_no_header("again");
        assert!(dir.read("tabernacle.log").ends_with("[2026-10-17 19:49:33:000] \nagain\n"));
    }

    #[test]
    fn a_file_grown_too_large_is_put_aside() {
        let dir = Dir::new("size");
        let (now, clock) = clock(T);
        let rotation = Rotation { max_age: 0, max_size: 100 };
        let log = Logger::with_clock(dir.0.join("node.log"), rotation, clock).unwrap();
        // Forty bytes a line: two fit in a hundred, a third does not.
        let line = |n: u32| format!("{n:039}");
        for n in 0..5 {
            log.log_no_header(&line(n));
        }
        assert_eq!(dir.files(), ["node.log", "node_R_10_17_2026_19_49.log", "node_R_10_17_2026_19_49_2.log"]);
        // No line is lost, none is split, and they are in order: the
        // first put aside, then the second, then the file itself.
        let all =
            [dir.read("node_R_10_17_2026_19_49.log"), dir.read("node_R_10_17_2026_19_49_2.log"), dir.read("node.log")];
        assert_eq!(all.iter().map(|f| f.len()).collect::<Vec<_>>(), [80, 80, 40]);
        assert_eq!(all.concat(), (0..5).map(|n| line(n) + "\n").collect::<String>());
        // Another minute, another name.
        now.store(T + 60_000, Ordering::Relaxed);
        log.log_no_header(&line(5));
        log.log_no_header(&line(6));
        assert!(dir.files().contains(&"node_R_10_17_2026_19_50.log".to_string()));
        // A line longer than any file may be is written all the same, to
        // a file of its own.
        let long = "x".repeat(300);
        log.log_no_header(&long);
        assert_eq!(dir.read("node.log"), format!("{long}\n"));
        log.log_no_header("after");
        assert_eq!(dir.read("node.log"), "after\n");
        assert_eq!(log.failures(), 0);
    }

    #[test]
    fn a_file_written_to_for_too_long_is_put_aside() {
        let dir = Dir::new("age");
        let (now, clock) = clock(T);
        let rotation = Rotation { max_age: 3600, max_size: 0 };
        let log = Logger::with_clock(dir.0.join("stats.log"), rotation, clock).unwrap();
        log.log("first");
        now.store(T + 3_599_999, Ordering::Relaxed);
        log.log("within the hour");
        assert_eq!(dir.files(), ["stats.log"]);
        // The hour is up: the next line begins a new file.
        now.store(T + 3_600_000, Ordering::Relaxed);
        log.log("the next hour");
        assert_eq!(dir.files(), ["stats.log", "stats_R_10_17_2026_20_49.log"]);
        assert!(dir.read("stats_R_10_17_2026_20_49.log").ends_with("within the hour\n"));
        assert_eq!(dir.read("stats.log"), "[2026-10-17 20:49:31:471] the next hour\n");
        // A quiet log is put aside when it is looked to, though nothing
        // is written; an empty one is not.
        now.store(T + 2 * 3_600_000, Ordering::Relaxed);
        log.rotate_if_due();
        assert_eq!(dir.files().len(), 3);
        assert_eq!(dir.read("stats.log"), "");
        now.store(T + 9 * 3_600_000, Ordering::Relaxed);
        log.rotate_if_due();
        log.log("after a long quiet");
        assert_eq!(dir.files().len(), 3, "an empty file was not worth keeping");
        // And when asked to, whatever its age.
        assert!(log.rotate().is_some_and(|p| p.ends_with("stats_R_10_18_2026_04_49.log")));
        assert_eq!(log.rotate(), None);
    }

    #[test]
    fn a_name_without_an_ending_is_put_aside_without_one() {
        let dir = Dir::new("plain");
        let (_, clock) = clock(T);
        let log = Logger::with_clock(dir.0.join("requests"), Rotation::default(), clock).unwrap();
        log.log_no_header("one");
        assert!(log.rotate().is_some());
        assert_eq!(dir.files(), ["requests", "requests_R_10_17_2026_19_49"]);
    }

    #[test]
    fn lines_from_many_threads_are_whole() {
        let dir = Dir::new("threads");
        let rotation = Rotation { max_age: 0, max_size: 20_000 };
        let log = Arc::new(Logger::open(dir.0.join("busy.log"), rotation).unwrap());
        let threads: Vec<_> = (0..8u32)
            .map(|t| {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    for n in 0..500u32 {
                        log.log(&format!("thread {t} line {n:04} {}", "=".repeat(20)));
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        // Four thousand lines over many files, each whole, each thread's
        // in the order it wrote them.
        let files = dir.files();
        assert!(files.len() > 10);
        let mut seen = vec![Vec::new(); 8];
        let mut paths: Vec<PathBuf> = files.iter().map(|f| dir.0.join(f)).collect();
        paths.sort_by_key(|p| std::fs::metadata(p).unwrap().modified().unwrap());
        let mut lines = 0;
        for path in &paths {
            let text = std::fs::read_to_string(path).unwrap();
            assert!(text.len() <= 20_000 && text.ends_with('\n'));
            for line in text.lines() {
                assert!(line.starts_with('[') && line.ends_with(&"=".repeat(20)), "{line}");
                let words: Vec<&str> = line.split(' ').collect();
                seen[words[3].parse::<usize>().unwrap()].push(words[5].parse::<u32>().unwrap());
                lines += 1;
            }
        }
        assert_eq!(lines, 4000);
        for mine in &mut seen {
            mine.sort();
            assert_eq!(*mine, (0..500).collect::<Vec<u32>>());
        }
        assert_eq!(log.failures(), 0);
    }

    #[test]
    fn a_log_that_cannot_be_written_does_not_stop_anything() {
        let dir = Dir::new("gone");
        assert!(Logger::open(dir.0.join("no-such-directory").join("x.log"), Rotation::default()).is_err());
        let (now, clock) = clock(T);
        let rotation = Rotation { max_age: 60, max_size: 0 };
        let log = Logger::with_clock(dir.0.join("node.log"), rotation, clock).unwrap();
        log.log("one");
        // Its directory goes: the file cannot be put aside, nor a new
        // one begun.
        std::fs::remove_dir_all(&dir.0).unwrap();
        now.store(T + 61_000, Ordering::Relaxed);
        log.log("two");
        log.log_all("three");
        log.rotate_if_due();
        assert!(log.failures() >= 1);
        // It comes back: so does the log.
        std::fs::create_dir_all(&dir.0).unwrap();
        log.log("four");
        assert!(dir.read("node.log").ends_with("four\n"));
    }
}
