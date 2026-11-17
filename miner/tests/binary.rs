//! The program itself, run as whoever keeps a node runs it.

#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

const TABMINER: &str = env!("CARGO_BIN_EXE_tabminer");

/// A node run by a test: ended with the test, however that ends.
#[cfg(unix)]
struct Running(std::process::Child);

#[cfg(unix)]
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tabminer-binary-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The help asked for is the help, and no failure; an option that is
/// not one is named, the help follows, and that is a failure. Neither
/// makes anything.
#[test]
fn help_is_no_failure_and_an_unknown_option_is() {
    let dir = scratch("help");
    let data = dir.display().to_string();
    let help = Command::new(TABMINER).args(["--data-dir", &data, "--help"]).output().unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(text.starts_with("tabminer: a node of the Tabernacle network.") && text.contains("\nLogging\n"));
    assert!(help.stderr.is_empty());

    let unknown = Command::new(TABMINER).args(["--data-dir", &data, "--prot", "1"]).output().unwrap();
    let said = String::from_utf8(unknown.stderr).unwrap();
    // (-1, as the system has it: 255 where a code is one byte.)
    assert!(matches!(unknown.status.code(), Some(-1 | 255)), "{:?}", unknown.status);
    assert_eq!(said, format!("Error: unknown configuration option: '--prot'\n\n{text}"));
    assert!(unknown.stdout.is_empty());
    assert!(!dir.exists());

    // Making blocks needs a wallet for their rewards: a node told to
    // have none and to make blocks says so, and does not start.
    let purseless = Command::new(TABMINER).args(["--data-dir", &data, "--no-wallet"]).output().unwrap();
    assert!(matches!(purseless.status.code(), Some(-1 | 255)));
    let said = String::from_utf8(purseless.stderr).unwrap();
    let why = "--no-wallet needs --no-mine: the rewards of blocks made here are paid to the wallet";
    assert_eq!(said, format!("Error: {why}\n\n{text}"));
    assert!(!dir.exists());
}

/// A node that starts says how it is configured and then, in the very
/// next line, that it is ready; and from then it answers. Told to
/// stop, it says so and stops, at once and without failure.
#[cfg(unix)]
#[test]
fn a_node_starts_says_it_is_ready_and_ends_when_told() {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};
    let dir = scratch("run");
    let data = dir.display().to_string();
    // (A port of our own, as likely as not.)
    let port = 20_000 + std::process::id() % 20_000;
    let listen = format!("127.0.0.1:{port}");
    let node = Command::new(TABMINER)
        .args(["--no-mine", "--no-wallet", "--no-prompt"])
        .args(["--data-dir", &data, "--listen", &listen, "--max-peers", "2000"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut node = Running(node);
    let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
    let mut said = Vec::new();
    for line in lines.by_ref() {
        said.push(line.unwrap());
        if said.last().unwrap().ends_with("Server is ready!") {
            break;
        }
    }
    let rule = "-".repeat(105);
    assert!(said[0][26..].starts_with("Server started ") && said[0].ends_with(" UTC"), "{said:#?}");
    assert_eq!((&said[1], &said[said.len() - 2]), (&rule, &rule));
    assert_eq!(&said[2][26..], format!("UDP Server Listening on: '{listen}'"));
    // (By its end: the lines are not all of one millisecond.)
    assert!(said.iter().any(|l| l.ends_with(&format!("Main Log:                '{data}/tabernacle.log'"))));
    assert!(said.iter().any(|l| l.ends_with("Max Peers:               '2,000'")));
    // How many threads, as a number: one a core, nothing being said.
    let cores = tabminer::parallel::cores();
    assert!(said.iter().any(|l| l.ends_with(&format!("Threads:                 '{cores}'"))), "{said:#?}");

    // It is ready: a datagram that is no message is taken, and has its
    // line in the request log.
    let us = UdpSocket::bind("127.0.0.1:0").unwrap();
    us.send_to(b"is anybody there", &listen).unwrap();
    let start = Instant::now();
    let requests = dir.join("request.log");
    while !std::fs::read_to_string(&requests).unwrap().contains("malformed (16 bytes) -> malformed") {
        assert!(start.elapsed() < Duration::from_secs(20), "{:?}", std::fs::read_to_string(&requests));
        std::thread::sleep(Duration::from_millis(20));
    }

    // Told to stop. (With the signal to end, not an interrupt: a
    // program a shell started in the background, as these tests are
    // when coverage is measured, is started ignoring interrupts, and
    // a node does nothing to change that.)
    let told = Instant::now();
    assert!(Command::new("kill").args(["-TERM", &node.0.id().to_string()]).status().unwrap().success());
    let status = node.0.wait().unwrap();
    // (Ended by the signal itself: the node does nothing about it.)
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&status), Some(15));
    assert!(told.elapsed() < Duration::from_secs(5));
    // Nothing more was said once it was ready, on the terminal or in
    // the main log.
    assert_eq!(lines.count(), 0);
    let main = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
    let logged: Vec<&str> = main.lines().collect();
    assert_eq!(logged[..said.len()], said.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(logged.len(), said.len());
    assert!(std::fs::read_to_string(dir.join("stat.log")).unwrap().contains("AvgLatency(us)"));

    // A second node on the same port cannot start: it says why, and
    // never that it is ready.
    let first = Command::new(TABMINER)
        .args(["--no-mine", "--no-prompt", "--data-dir", &data, "--listen", &listen])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let other = scratch("other");
    let mut first = Running(first);
    let mut lines = BufReader::new(first.0.stderr.take().unwrap()).lines();
    assert!(lines.by_ref().any(|l| l.unwrap().ends_with("Server is ready!")));
    let second = Command::new(TABMINER)
        .args(["--no-mine", "--no-prompt", "--data-dir", &other.display().to_string(), "--listen", &listen])
        .output()
        .unwrap();
    let said = String::from_utf8(second.stderr).unwrap();
    assert!(matches!(second.status.code(), Some(-1 | 255)));
    assert!(
        said.contains(&format!("] Error: cannot listen on {listen}: ")) && !said.contains("Server is ready"),
        "{said}"
    );
    assert_eq!(said.lines().count(), 1);
    assert!(Command::new("kill").args(["-TERM", &first.0.id().to_string()]).status().unwrap().success());
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&first.0.wait().unwrap()), Some(15));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}

/// Two nodes of the dev network, each making blocks and each told of
/// the other: both chains grow, each takes the other's blocks, and
/// they are of one mind.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn two_nodes_make_blocks_and_take_each_others() {
    use std::time::{Duration, Instant};
    let dirs = [scratch("mine-a"), scratch("mine-b")];
    let port = 41_000 + std::process::id() % 20_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let start = |i: usize| {
        let node = Command::new(TABMINER)
            .args(["--network", "dev", "--threads", "2", "--stat-interval-seconds", "1", "--stat-summary-seconds", "2"])
            .args(["--data-dir", &dirs[i].display().to_string(), "--listen", &at(i as u32)])
            .args(["--peer", &at(1 - i as u32), "--no-prompt"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut node = Running(node);
        let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
        assert!(lines.by_ref().any(|l| l.unwrap().ends_with("Server is ready!")));
        node
    };
    let mut nodes = [start(0), start(1)];
    // What the stats log last said of a node: its height, the blocks
    // that joined its chain, and those it made itself.
    let last = |i: usize| -> Option<(u64, u64, u64)> {
        let stats = std::fs::read_to_string(dirs[i].join("stat.log")).ok()?;
        let whole = stats.lines().rev().find(|l| l.starts_with('['))?;
        let n: Vec<u64> = whole[26..].split_whitespace().map(|n| n.replace(',', "").parse().unwrap_or(0)).collect();
        Some((n[n.len() - 3], n[n.len() - 2], n[n.len() - 1]))
    };
    // Until each has made blocks, and holds more than it made.
    let began = Instant::now();
    loop {
        let all: Vec<_> = (0..2).filter_map(last).collect();
        if all.len() == 2 && all.iter().all(|(height, joined, made)| *height >= 4 && *made >= 1 && joined > made) {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(240), "{all:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    for node in &mut nodes {
        assert!(Command::new("kill").args(["-TERM", &node.0.id().to_string()]).status().unwrap().success());
        assert_eq!(std::os::unix::process::ExitStatusExt::signal(&node.0.wait().unwrap()), Some(15));
    }
    // Each was told of the other's blocks and asked for them; and
    // nothing went wrong that the main log would say.
    for dir in &dirs {
        let requests = std::fs::read_to_string(dir.join("request.log")).unwrap();
        assert!(requests.contains(" block height ") && requests.contains(" get block, "), "{requests}");
        // The main log says of each block that it was being made, that
        // it was won, or that it came from the other.
        let main = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
        assert!(!main.contains("Error"), "{main}");
        let told = ["] Proving block 1 on ", "] Mining block 1 on ", ": proved in ", "] Won block ", " hashes in "];
        let told = told.into_iter().chain(["] Received block ", ") from 127.0.0.1:"]);
        for said in told.chain(["] Peer 127.0.0.1:", " connected (height "]) {
            assert!(main.contains(said), "{said}: {main}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Two nodes of the dev network, each with a wallet and a prompt: one
/// makes blocks, whose rewards are its wallet's, and pays the other by
/// a slate passed between them as a file. The payment is mined, and the
/// other's wallet has it.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_payment_is_made_at_the_prompt_and_mined() {
    use std::io::{Read, Write};
    use std::process::{ChildStdin, ChildStdout};
    use std::time::{Duration, Instant};
    let dirs = [scratch("pay-a"), scratch("pay-b")];
    let port = 43_000 + std::process::id() % 20_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    // What a node says up to its next prompt.
    fn until_prompt(out: &mut ChildStdout) -> String {
        let (mut said, mut byte) = (Vec::new(), [0u8; 1]);
        while !(said.ends_with(b"> ") && (said.len() == 2 || said[said.len() - 3] == b'\n')) {
            assert_eq!(out.read(&mut byte).unwrap(), 1, "the node stopped: {}", String::from_utf8_lossy(&said));
            said.push(byte[0]);
        }
        String::from_utf8(said[..said.len() - 2].to_vec()).unwrap()
    }
    fn ask(node: &mut (Running, ChildStdin, ChildStdout), command: &str) -> String {
        writeln!(node.1, "{command}").unwrap();
        until_prompt(&mut node.2)
    }
    let start = |i: usize, mines: bool| {
        let mut command = Command::new(TABMINER);
        command
            .args(["--network", "dev", "--threads", "2", "--min-confirmations", "1"])
            .args(["--data-dir", &dirs[i].display().to_string(), "--listen", &at(i as u32)])
            .args(["--peer", &at(1 - i as u32)]);
        if !mines {
            command.arg("--no-mine");
        }
        let node = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut node = Running(node);
        let (mut stdin, mut stdout) = (node.0.stdin.take().unwrap(), node.0.stdout.take().unwrap());
        // A new wallet: no password. Its words are said, once, and then
        // the node is ready.
        writeln!(stdin).unwrap();
        let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
        let said: Vec<String> =
            lines.by_ref().map(|l| l.unwrap()).take_while(|l| !l.ends_with("Server is ready!")).collect();
        let words = said.iter().find(|l| l.starts_with("    ")).expect("the wallet's words");
        assert_eq!(words.split_whitespace().count(), 12, "{said:#?}");
        assert!(dirs[i].join("wallet.tab").exists());
        // (What it says on that side from here on is not waited for.)
        std::thread::spawn(move || lines.for_each(drop));
        assert_eq!(until_prompt(&mut stdout), "");
        (node, stdin, stdout)
    };
    let mut maker = start(0, true);
    let mut other = start(1, false);
    let confirmed = |node: &mut (Running, ChildStdin, ChildStdout)| {
        let said = ask(node, "balance");
        said.lines().next().unwrap().trim_start_matches("confirmed").trim().to_string()
    };
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(240), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    assert!(ask(&mut maker, "help").starts_with("commands:"));
    assert_eq!(ask(&mut maker, "nonsense"), "error: nonsense: no such command (see help)\n");
    assert_eq!(confirmed(&mut other), "0");
    // Rewards come to the maker's wallet as its blocks join the chain.
    wait("the maker has no rewards", &mut || confirmed(&mut maker) != "0");
    assert!(ask(&mut maker, "outputs").contains("confirmed"));
    // The payment: begun by the maker, answered by the other, signed by
    // the maker.
    let slate = dirs[0].join("payment.slate").display().to_string();
    let begun = ask(&mut maker, &format!("send-file 12.5 {slate}"));
    assert!(begun.contains("begun: 12.5 and a fee of"), "{begun}");
    assert!(ask(&mut maker, "slates").contains("12.5"));
    let answered = ask(&mut other, &format!("receive {slate}"));
    assert!(answered.contains("answered: 12.5 to this wallet"), "{answered}");
    assert!(ask(&mut other, "balance").contains("unverified  12.5"));
    let signed = ask(&mut maker, &format!("finalize {slate}.received"));
    assert!(signed.contains("signed and pooled"), "{signed}");
    assert_eq!(ask(&mut maker, "slates"), "no payments begun\n");
    // Mined: the other has it, confirmed, and the maker's log says a
    // block carried it.
    wait("the payment is not confirmed", &mut || confirmed(&mut other) == "12.5");
    let log = std::fs::read_to_string(dirs[0].join("tabernacle.log")).unwrap();
    assert!(log.contains("carries 1 transactions of the pool (1 signatures)"), "{log}");
    // And each node's log says what its own wallet did, and nothing of
    // the other's.
    let theirs = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
    assert!(log.contains("] Payment ") && log.contains(" begun: 12.5 and a fee of "), "{log}");
    assert!(log.contains(" signed and pooled: transaction ") && !log.contains(" answered: "), "{log}");
    assert!(theirs.contains(" answered: 12.5 to this wallet") && !theirs.contains(" begun: "), "{theirs}");
    assert!(!theirs.contains("signed and pooled"), "{theirs}");
    let status = ask(&mut other, "status");
    assert!(status.contains("wallet: 12.5 confirmed") && status.contains("pool: 0 transactions"), "{status}");
    // A second payment, taken back before a block has it: another
    // spend of the same takes its place in both pools, and the other
    // never has it.
    let begun = ask(&mut maker, &format!("send-file 3 {slate}"));
    assert!(begun.contains("begun: 3 and a fee of"), "{begun}");
    assert!(ask(&mut other, &format!("receive {slate}")).contains("answered: 3 to this wallet"));
    let signed = ask(&mut maker, &format!("finalize {slate}.received"));
    let id = signed.split("transaction ").nth(1).unwrap()[..8].to_string();
    let back = ask(&mut maker, &format!("cancel {id}"));
    println!("{}", back.trim_end());
    // (Unless a block had it already: then it is not to be taken back.)
    if back.contains("taken back: transaction") {
        let after = "The transaction has been cancelled, but it could still end up in a block. \
                     Call prune to remove the stale transaction from your wallet.";
        assert!(back.contains(after), "{back}");
        assert!(ask(&mut maker, "sent").contains("pooled") || ask(&mut maker, "sent").starts_with("no payments"));
        wait("the payment taken back is not mined", &mut || ask(&mut maker, "sent").starts_with("no payments"));
        assert!(ask(&mut other, "prune").starts_with("1 outputs expected"));
        assert_eq!(confirmed(&mut other), "12.5");
        let log = std::fs::read_to_string(dirs[0].join("tabernacle.log")).unwrap();
        assert!(log.contains(" taken back: transaction "), "{log}");
    } else {
        assert!(back.contains("a block has it already"), "{back}");
    }
    assert!(ask(&mut maker, "bump 00").starts_with("error: no payment sent"));
    // Told to stop, each does, without failure.
    for mut node in [maker, other] {
        writeln!(node.1, "quit").unwrap();
        assert_eq!(node.0.0.wait().unwrap().code(), Some(0));
    }
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}

/// A node of the dev network with a wallet and a prompt, as a test
/// drives it: what is typed to it, and what it says.
#[cfg(all(unix, feature = "dev"))]
struct Prompted {
    node: Running,
    typed: std::process::ChildStdin,
    said: std::process::ChildStdout,
}

#[cfg(all(unix, feature = "dev"))]
impl Prompted {
    /// Starts a node in `dir` listening on `listen`, with these peers,
    /// making blocks or not: `new` if it has no wallet yet, when its
    /// words are looked for.
    fn start(dir: &std::path::Path, listen: &str, peers: &[String], mines: bool, new: bool) -> Prompted {
        use std::io::Write;
        let mut command = Command::new(TABMINER);
        command.args(["--network", "dev", "--threads", "2", "--data-dir", &dir.display().to_string()]);
        // (Its wallet spends what one block has: these chains are short.)
        command.args(["--min-confirmations", "1"]);
        command.args(["--listen", listen]);
        for peer in peers {
            command.args(["--peer", peer]);
        }
        if !mines {
            command.arg("--no-mine");
        }
        let node = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut node = Running(node);
        let (mut typed, said) = (node.0.stdin.take().unwrap(), node.0.stdout.take().unwrap());
        // (A new wallet: no password.)
        if new {
            writeln!(typed).unwrap();
        }
        let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
        let before: Vec<String> =
            lines.by_ref().map(|l| l.unwrap()).take_while(|l| !l.ends_with("Server is ready!")).collect();
        assert_eq!(before.iter().any(|l| l.starts_with("    ")), new, "{before:#?}");
        std::thread::spawn(move || lines.for_each(drop));
        let mut node = Prompted { node, typed, said };
        assert_eq!(node.until_prompt(), "");
        node
    }

    /// What it says up to its next prompt.
    fn until_prompt(&mut self) -> String {
        use std::io::Read;
        let (mut said, mut byte) = (Vec::new(), [0u8; 1]);
        while !(said.ends_with(b"> ") && (said.len() == 2 || said[said.len() - 3] == b'\n')) {
            assert_eq!(self.said.read(&mut byte).unwrap(), 1, "the node stopped: {}", String::from_utf8_lossy(&said));
            said.push(byte[0]);
        }
        String::from_utf8(said[..said.len() - 2].to_vec()).unwrap()
    }

    fn ask(&mut self, command: &str) -> String {
        use std::io::Write;
        writeln!(self.typed, "{command}").unwrap();
        self.until_prompt()
    }

    fn confirmed(&mut self) -> String {
        self.ask("balance").lines().next().unwrap().trim_start_matches("confirmed").trim().to_string()
    }

    fn height(&mut self) -> u64 {
        let status = self.ask("status");
        status.split_whitespace().nth(1).unwrap().replace(',', "").parse().unwrap()
    }

    fn stop(mut self) {
        use std::io::Write;
        writeln!(self.typed, "quit").unwrap();
        assert_eq!(self.node.0.wait().unwrap().code(), Some(0));
    }
}

/// The chain goes over to another branch under two wallets, between
/// nodes that are running. A payment mined on the branch given up is
/// in no block: its sender's node says so, as its recipient's does of
/// what it was paid; the payment goes back to the pools, and from them
/// to the node whose branch it is now, which never had it; mined there,
/// each wallet has what it had. A payment that no block has is put back
/// in the pool of a node that was stopped and started; and one that
/// spent what only the branch given up had is never mined.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_payment_survives_the_chain_going_over_to_another_branch() {
    use std::time::{Duration, Instant};
    let dirs = [scratch("reorg-a"), scratch("reorg-b"), scratch("reorg-c")];
    let port = 45_000 + std::process::id() % 15_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(300), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let log = |i: usize| std::fs::read_to_string(dirs[i].join("tabernacle.log")).unwrap();
    let slate = dirs[0].join("payment.slate").display().to_string();
    let pay = |maker: &mut Prompted, other: &mut Prompted, amount: &str| {
        assert!(maker.ask(&format!("send-file {amount} {slate}")).contains("begun"));
        assert!(other.ask(&format!("receive {slate}")).contains("answered"));
        let signed = maker.ask(&format!("finalize {slate}.received"));
        assert!(signed.contains("signed and pooled"), "{signed}");
    };

    // A makes blocks, and B follows it. C takes the first of them, and
    // is stopped: what it has is where the branches will part.
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], true, true);
    let mut other = Prompted::start(&dirs[1], &at(1), &[at(0)], false, true);
    wait("the maker has made no blocks", &mut || maker.height() >= 4);
    let shared = maker.height();
    let mut third = Prompted::start(&dirs[2], &at(2), &[at(0)], false, true);
    wait("the third has not the first blocks", &mut || third.height() >= shared);
    third.stop();

    // A pays B, in a block of its own branch; and stops making blocks.
    pay(&mut maker, &mut other, "12.5");
    wait("the payment is not confirmed", &mut || other.confirmed() == "12.5");
    maker.stop();
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], false, false);
    let ours = maker.height();
    // A second payment, which no block has, since nobody makes any: it
    // is not in the pool of a node stopped and started, and is put
    // back there.
    pay(&mut maker, &mut other, "3");
    maker.stop();
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], false, false);
    wait("the payment that no block has is not pooled again", &mut || {
        log(0).contains("was in no block and not pooled: pooled again")
    });
    assert!(maker.ask("sent").contains("pooled"));

    // C makes blocks on what it has, where nobody knows of it, until
    // its branch is the longer; then it is where A and B find it.
    let mut third = Prompted::start(&dirs[2], &at(3), &[], true, false);
    wait("the third's branch is not the longer", &mut || third.height() > ours + 3);
    third.stop();
    let mut third = Prompted::start(&dirs[2], &at(3), &[at(0), at(1)], true, false);

    // The first payment is mined again, on that branch: the other has
    // it, where it now is.
    wait("the payment is not mined on the other branch", &mut || {
        log(1).contains("outputs that were lost are in the chain again")
    });
    assert_eq!(other.confirmed(), "12.5");
    assert!(third.height() > ours);
    let (a, b) = (log(0), log(1));
    assert!(a.contains("Reorganized to block"), "{a}");
    assert!(a.contains("The wallet: 1 payments sent are in no block any more"), "{a}");
    assert!(b.contains("The wallet: 1 outputs are in no block any more"), "{b}");
    assert!(log(2).contains("carries 1 transactions"), "{}", log(2));
    // The second spent the reward of a block of the branch given up
    // (the largest the maker had, with the first payment's fee): there
    // is no such output now, and no block will ever have that payment.
    // Its sender has nothing waiting; its recipient has what was never
    // more than expected, until it is pruned.
    assert_eq!(maker.ask("sent"), "no payments sent that are not in a block\n");
    assert!(other.ask("balance").contains("unverified  3"));
    assert!(other.ask("prune").starts_with("1 outputs expected"));
    assert_eq!(other.ask("balance"), "confirmed   12.5\n");
    for node in [maker, other, third] {
        node.stop();
    }
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}

/// A name, between running nodes: committed to, revealed when its
/// commit has waited, changed, and given to the wallet of another node;
/// each step a transaction the wallet makes and a block carries.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_name_is_registered_changed_and_given_at_the_prompt() {
    use std::time::{Duration, Instant};
    let dirs = [scratch("name-a"), scratch("name-b")];
    let port = 47_000 + std::process::id() % 15_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(240), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], true, true);
    let mut other = Prompted::start(&dirs[1], &at(1), &[at(0)], false, true);
    wait("the maker has no rewards", &mut || maker.confirmed() != "0");
    assert_eq!(maker.ask("names"), "no names\n");
    assert_eq!(maker.ask("name alice"), "alice is not registered\n");
    assert!(maker.ask("name-commit Alice").starts_with("error: Alice is not a valid name"));

    // Committed to: which says nothing of the name. Revealed once the
    // commit has been in the chain for as long as the network asks.
    let committed = maker.ask("name-commit alice");
    assert!(committed.starts_with("Name alice: committed to: transaction "), "{committed}");
    assert!(maker.ask("names").contains("committed, not yet revealed"));
    assert!(maker.ask("name-commit alice").starts_with("error: the wallet has already committed"));
    let mut early = false;
    wait("the name is not revealed", &mut || {
        let said = maker.ask("name-reveal alice");
        early |= said.contains("not on chain yet") || said.contains("blocks old; wait");
        said.starts_with("Name alice: revealed: transaction ")
    });
    assert!(early, "it was revealed without waiting");
    wait("the name is not registered", &mut || maker.ask("names").contains("  owned  "));
    let nothing = "0".repeat(64);
    assert!(maker.ask("name alice").starts_with(&format!("alice says {nothing}\n")));
    assert_eq!(other.ask("name alice"), maker.ask("name alice"));

    // Changed: what it says, as every node then has it.
    let says = "01000000".repeat(8);
    assert!(maker.ask("name-update alice nonsense").starts_with("error: 'nonsense' is not what a name says"));
    assert!(maker.ask(&format!("name-update alice {says}")).starts_with("Name alice: changed: transaction "));
    assert!(maker.ask("names").contains("owned, a change signed"));
    wait("the name is not changed", &mut || other.ask("name alice").starts_with(&format!("alice says {says}\n")));
    wait("the wallet has not seen the change", &mut || maker.ask("names").contains(&format!("  owned  says {says}")));

    // Given to the other node's wallet: which writes the record, for
    // the owner to sign over.
    let offer = dirs[1].join("alice.offer").display().to_string();
    assert!(other.ask(&format!("name-offer alice {offer}")).starts_with("Name alice: an offer written"));
    assert!(other.ask("names").contains("offered to this wallet"));
    assert!(maker.ask(&format!("name-transfer {offer}")).starts_with("Name alice: signed over: transaction "));
    assert!(maker.ask("names").contains("being given away"));
    wait("the name has not been given", &mut || other.ask("names").contains("  owned  "));
    wait("the name has not left its giver", &mut || maker.ask("names") == "no names\n");
    assert!(other.ask("name alice").starts_with(&format!("alice says {nothing}\n")));
    let log = std::fs::read_to_string(dirs[0].join("tabernacle.log")).unwrap();
    for step in ["committed to", "revealed", "changed", "signed over"] {
        assert!(log.contains(&format!("] Name alice: {step}: transaction ")), "{step}: {log}");
    }
    maker.stop();
    other.stop();
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}
