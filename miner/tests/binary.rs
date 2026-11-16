//! The program itself, run as whoever keeps a node runs it.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
}

/// A node that starts says how it is configured and then, in the very
/// next line, that it is ready; and from then it answers. Told to
/// stop, it says so and stops, at once and without failure.
#[cfg(unix)]
#[test]
fn a_node_starts_says_it_is_ready_and_halts_when_told() {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};
    let dir = scratch("run");
    let data = dir.display().to_string();
    // (A port of our own, as likely as not.)
    let port = 20_000 + std::process::id() % 20_000;
    let listen = format!("127.0.0.1:{port}");
    let node = Command::new(TABMINER)
        .args(["--no-mine", "--data-dir", &data, "--listen", &listen, "--max-peers", "2000"])
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
    assert!(said.contains(&format!("{}Main Log:                '{data}/tabernacle.log'", &said[2][..26])));
    assert!(said.iter().any(|l| l.ends_with("Max Peers:               '2,000'")));
    // How many threads, as a number: one a core, nothing being said.
    let cores = std::thread::available_parallelism().unwrap().get();
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

    // Told to stop.
    let told = Instant::now();
    assert!(Command::new("kill").args(["-INT", &node.0.id().to_string()]).status().unwrap().success());
    let status = node.0.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(told.elapsed() < Duration::from_secs(5));
    let rest: Vec<String> = lines.map(|l| l.unwrap()).collect();
    assert_eq!(rest.len(), 1, "{rest:#?}");
    assert!(rest[0].ends_with("] Received shut down signal, halting!"));
    // The main log holds what the terminal was told, after its first
    // line, and says it was ready once.
    let main = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
    let logged: Vec<&str> = main.lines().skip(1).collect();
    assert_eq!(logged, said.iter().chain(&rest).map(String::as_str).collect::<Vec<_>>());
    assert!(std::fs::read_to_string(dir.join("stat.log")).unwrap().contains("AvgLatency(us)"));

    // A second node on the same port cannot start: it says why, and
    // never that it is ready.
    let first = Command::new(TABMINER)
        .args(["--no-mine", "--data-dir", &data, "--listen", &listen])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let other = scratch("other");
    let mut first = Running(first);
    let mut lines = BufReader::new(first.0.stderr.take().unwrap()).lines();
    assert!(lines.by_ref().any(|l| l.unwrap().ends_with("Server is ready!")));
    let second = Command::new(TABMINER)
        .args(["--no-mine", "--data-dir", &other.display().to_string(), "--listen", &listen])
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
    assert_eq!(first.0.wait().unwrap().code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}
