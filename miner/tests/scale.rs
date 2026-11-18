//! The program at the size of a chain that has run for years: what a
//! node needs, measured.
//!
//! A state of `TABMINER_SCALE_OUTPUTS` unspent outputs is made at once
//! behind a chain's first block (`--debug-fill-outputs`, with blocks'
//! proofs unchecked), and then: full blocks are made and applied on it;
//! and a new node takes the state from the one that has it. The size is
//! 2,000,000 where nothing is said, as every push runs it, and
//! 180,000,000, somewhat more than Bitcoin's, nightly
//! (`.github/workflows/scale.yml`). The data directories are under the
//! system's temporary directory (`TMPDIR`), which needs room for the
//! state: twice, when it is taken by a second node.
//!
//! Each test prints what it measured as `SCALE` lines, one fact a line,
//! to be read and compared between runs: `SCALE <test> <what> <value>`.
//! The last of them say what the machine had left, of disk and of
//! memory: so that a run on a machine with little says so.
//!
//! What is not measured here is proving: a node that makes blocks needs
//! what these say and, besides, the memory of a proof and of the table
//! of the proof of work.

#![cfg(all(feature = "dev", unix))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const TABMINER: &str = env!("CARGO_BIN_EXE_tabminer");
/// The blocks a node of these tests keeps the bodies of, and how far
/// under its last block a new node takes the state.
const KEPT: &str = "8";
const SYNC_POINT: &str = "4";

fn number(name: &str, or: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(or)
}

/// The size of the state: `TABMINER_SCALE_OUTPUTS`, or 2,000,000.
fn outputs() -> u64 {
    number("TABMINER_SCALE_OUTPUTS", 2_000_000)
}

/// One output every this many positions: `TABMINER_SCALE_SPACING`, or 5
/// (the rest as if spent, as on a chain with a history).
fn spacing() -> u64 {
    number("TABMINER_SCALE_SPACING", 5)
}

/// How long a step that grows with the state may take: an hour, and a
/// minute for every million outputs.
fn scaled(n: u64) -> Duration {
    Duration::from_secs(3600 + 60 * (n / 1_000_000))
}

fn report(test: &str, what: &str, value: impl std::fmt::Display) {
    println!("SCALE {test} {what} {value}");
}

/// A node run by a test: ended with the test, however that ends, and
/// its data directory removed.
struct Node {
    name: &'static str,
    child: Child,
    dir: PathBuf,
    listen: String,
    /// The most memory it was seen to have: all of it, and what of it
    /// is its own (not the files it reads), in megabytes.
    resident: Arc<AtomicU64>,
    own: Arc<AtomicU64>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Node {
    fn start(name: &'static str, test: &str, port: u32, args: &[&str]) -> Node {
        let dir = std::env::temp_dir().join(format!("tabminer-scale-{test}-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let listen = format!("127.0.0.1:{port}");
        let child = Command::new(TABMINER)
            .args(["--network", "dev", "--debug-no-validate-proofs", "--no-prompt"])
            .args(["--max-undo-blocks", KEPT, "--sync-point", SYNC_POINT])
            .args(["--stat-interval-seconds", "1", "--stat-summary-seconds", "60"])
            .args(["--data-dir", &dir.display().to_string(), "--listen", &listen])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        // Its memory as the system sees it, looked at every second for
        // as long as it runs (Linux only).
        let (resident, own) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let (r, o, path) = (Arc::clone(&resident), Arc::clone(&own), format!("/proc/{}/status", child.id()));
        std::thread::spawn(move || {
            while let Ok(status) = std::fs::read_to_string(&path) {
                let kb = |what: &str| {
                    status
                        .lines()
                        .find(|l| l.starts_with(what))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                };
                let (Some(all), Some(anon)) = (kb("VmHWM:"), kb("RssAnon:")) else { break };
                r.fetch_max(all / 1000, Ordering::Relaxed);
                o.fetch_max(anon / 1000, Ordering::Relaxed);
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        Node { name, child, dir, listen, resident, own }
    }

    /// The lines of its main log that have `text` in them.
    fn lines(&self, text: &str) -> Vec<String> {
        let log = std::fs::read_to_string(self.dir.join("tabernacle.log")).unwrap_or_default();
        log.lines().filter(|l| l.contains(text)).map(str::to_string).collect()
    }

    /// Waits until its log has `count` lines with `text` in them, and
    /// gives them: the test fails if `within` passes first, or the node
    /// ends, or says of anything that it is an error.
    fn wait(&mut self, text: &str, count: usize, within: Duration) -> Vec<String> {
        let (began, mut told) = (Instant::now(), Instant::now());
        loop {
            let lines = self.lines(text);
            if lines.len() >= count {
                return lines;
            }
            let errors = self.lines("Error: ");
            assert!(errors.is_empty(), "{}: {errors:?}", self.name);
            assert!(
                !self.lines("Refused block").iter().any(|_| true),
                "{}: {:?}",
                self.name,
                self.lines("Refused block")
            );
            if let Some(ended) = self.child.try_wait().unwrap() {
                panic!("{} ended ({ended}) before its log said '{text}' {count} times", self.name);
            }
            assert!(began.elapsed() < within, "{}: '{text}' {} of {count} times in {within:?}", self.name, lines.len());
            // (Something is said every minute, of a wait that is long.)
            if told.elapsed() >= Duration::from_secs(60) {
                told = Instant::now();
                let last = self.lines("").pop().unwrap_or_default();
                println!("PROGRESS {} {:.0}s {last}", self.name, began.elapsed().as_secs_f64());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The most memory the node said it held ([`tabminer::heap`]), in
    /// megabytes: from the lines of its stat log.
    fn peak_heap(&self) -> u64 {
        let log = std::fs::read_to_string(self.dir.join("stat.log")).unwrap_or_default();
        // (The column sixth from the last: after it come the peers, the
        // height and the blocks.)
        let peak = |l: &str| l.split_whitespace().rev().nth(5)?.replace(',', "").parse::<u64>().ok();
        log.lines().filter_map(peak).max().unwrap_or(0)
    }

    /// Says what the node used: memory, and disk.
    fn report(&self, test: &str, who: &str) {
        report(test, &format!("{who}_peak_heap_mb"), self.peak_heap());
        for (what, seen) in [("peak_own_memory_mb", &self.own), ("peak_resident_mb", &self.resident)] {
            if seen.load(Ordering::Relaxed) > 0 {
                report(test, &format!("{who}_{what}"), seen.load(Ordering::Relaxed));
            }
        }
        report(test, &format!("{who}_disk_mb"), dir_size(&self.dir) / 1_000_000);
    }
}

/// The seconds a line says after `label` (`applied in 0.427s`).
fn secs_after(line: &str, label: &str) -> Option<f64> {
    let rest = &line[line.find(label)? + label.len()..];
    rest.split(|c: char| !(c.is_ascii_digit() || c == '.')).find(|s| !s.is_empty())?.parse().ok()
}

/// The bytes on disk of what is under `dir`.
fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let size = |e: std::fs::DirEntry| match e.metadata() {
        Ok(m) if m.is_dir() => dir_size(&e.path()),
        Ok(m) => std::os::unix::fs::MetadataExt::blocks(&m) * 512,
        Err(_) => 0,
    };
    entries.flatten().map(size).sum()
}

/// Says what the machine has left, of disk where the data directories
/// were and of memory: so that a run on a machine with little says so.
fn report_left(test: &str) {
    let df = Command::new("df").arg("-Pk").arg(std::env::temp_dir()).output().ok();
    let free = df.and_then(|o| {
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        text.lines().nth(1)?.split_whitespace().nth(3)?.parse::<u64>().ok()
    });
    if let Some(kb) = free {
        report(test, "left_disk_mb", kb / 1000);
    }
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let kb = |what: &str| {
        meminfo.lines().find(|l| l.starts_with(what)).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
    };
    if let (Some(total), Some(available)) = (kb("MemTotal:"), kb("MemAvailable:")) {
        report(test, "machine_memory_mb", total / 1000);
        report(test, "left_memory_mb", available / 1000);
    }
}

/// A node that has the state of `n` outputs, making full blocks on it
/// up to the height `blocks`: each of as many outputs, and as many
/// spends of the state's outputs chosen at random, as fit a block. How
/// long it took until it was ready.
fn filled(test: &'static str, port: u32, n: u64, blocks: u64) -> (Node, Duration) {
    let began = Instant::now();
    let (state, blocks) = (format!("{n},{}", spacing()), blocks.to_string());
    let args = ["--debug-fill-outputs", &state, "--debug-fill", "100000,100000", "--blocks", &blocks, "--threads", "2"];
    let mut node = Node::start("server", test, port, &args);
    node.wait("Server is ready!", 1, scaled(n));
    (node, began.elapsed())
}

/// Full blocks, each of two million bytes with tens of thousands of
/// spends, are made and applied on a state of `TABMINER_SCALE_OUTPUTS`:
/// how long applying one takes, and what the node needed.
#[test]
#[ignore = "slow: a job of its own in .github/workflows/test.yml, and nightly at full size"]
fn a_full_block_applies_on_a_large_state() {
    const T: &str = "full-block";
    let (n, blocks) = (outputs(), 10);
    let port = 47_000 + std::process::id() % 15_000;
    let (mut node, ready) = filled(T, port, n, blocks);
    report(T, "outputs", n);
    report(T, "spacing", spacing());
    report(T, "fill_secs", format!("{:.1}", ready.as_secs_f64()));
    report(T, "filled_disk_mb", dir_size(&node.dir) / 1_000_000);
    let applied = node.wait("applied in ", blocks as usize, scaled(n));
    let built = node.lines("debug fill: block ");
    assert_eq!(built.len(), blocks as usize);
    // Every one of them full: within a part in a hundred of the most a
    // block may be, and of spends as of outputs.
    for line in &built {
        let after =
            |label: &str| line[..line.find(label).unwrap()].split_whitespace().last().unwrap().parse::<u64>().unwrap();
        assert!(after(" bytes") > 1_980_000 && after(" spends") > 20_000 && after(" outputs") > 20_000, "{line}");
    }
    report(T, "block_bytes", built[0][..built[0].find(" bytes").unwrap()].split_whitespace().last().unwrap());
    report(T, "block_spends", built[0][..built[0].find(" spends").unwrap()].split_whitespace().last().unwrap());
    for (what, lines, label) in [("build", &built, "built in "), ("apply", &applied, "applied in ")] {
        let mut secs: Vec<f64> = lines.iter().map(|l| secs_after(l, label).unwrap()).collect();
        secs.sort_by(f64::total_cmp);
        report(T, &format!("{what}_median_secs"), format!("{:.3}", secs[secs.len() / 2]));
        report(T, &format!("{what}_max_secs"), format!("{:.3}", secs[secs.len() - 1]));
        // (Only a guard: the times are for reading. Machines differ by
        // too much for them to be held to a number.)
        assert!(secs[secs.len() - 1] < 300.0, "{what} took {:.1}s", secs[secs.len() - 1]);
    }
    node.report(T, "node");
    report_left(T);
}

/// A new node takes a state of `TABMINER_SCALE_OUTPUTS` from the one
/// node that has it, and the full blocks after it: how long it takes,
/// and what both needed. That neither holds the state in memory is what
/// the memory lines say: at full size the state is many times what a
/// node may hold.
#[test]
#[ignore = "slow: a job of its own in .github/workflows/test.yml, and nightly at full size"]
fn a_fresh_node_fast_syncs_a_large_state() {
    const T: &str = "fast-sync";
    // (More blocks than a node keeps: the first of them can no longer
    // be had, and the new node must take the state.)
    let (n, blocks) = (outputs(), 12);
    let port = 48_000 + std::process::id() % 15_000;
    let (mut server, ready) = filled(T, port, n, blocks);
    report(T, "outputs", n);
    report(T, "spacing", spacing());
    report(T, "fill_secs", format!("{:.1}", ready.as_secs_f64()));
    server.wait("applied in ", blocks as usize, scaled(n));
    let last = server.wait(&format!("Won block {blocks} ("), 1, scaled(n)).pop().unwrap();
    let id = &last[last.find('(').unwrap()..last.find(')').unwrap()];

    let began = Instant::now();
    let state = format!("{n},{}", spacing());
    let args = ["--no-mine", "--debug-genesis-outputs", &state, "--peer", &server.listen];
    let mut new = Node::start("new", T, port + 1, &args);
    new.wait("Server is ready!", 1, scaled(n));
    let ready = began.elapsed();
    new.wait("Headers synced to ", 1, Duration::from_secs(600));
    let headers = began.elapsed();
    let taking = new.wait("Taking the state as of block ", 1, Duration::from_secs(600));
    new.wait("State taken as of block ", 1, scaled(n));
    let taken = began.elapsed();
    // Taken once, and as of the block that far under the last.
    assert_eq!(taking.len(), 1, "{taking:?}");
    assert!(taking[0].contains(&format!("as of block {} ", blocks - SYNC_POINT.parse::<u64>().unwrap())), "{taking:?}");
    // And then the blocks after it, full ones, to the same last block.
    new.wait(&format!("Synced at block {blocks}"), 1, scaled(n));
    let synced = began.elapsed();
    assert_eq!(new.lines(&format!("Received block {blocks} {id}")).len(), 1, "the two are on one block");
    assert_eq!(new.lines("applied in ").len(), SYNC_POINT.parse::<usize>().unwrap());

    report(T, "first_block_secs", format!("{:.1}", ready.as_secs_f64()));
    report(T, "headers_secs", format!("{:.1}", headers.as_secs_f64()));
    report(T, "state_taken_secs", format!("{:.1}", taken.as_secs_f64()));
    report(T, "state_fetch_secs", format!("{:.1}", (taken - headers).as_secs_f64()));
    report(T, "synced_secs", format!("{:.1}", synced.as_secs_f64()));
    server.report(T, "server");
    new.report(T, "new");
    report_left(T);
}
