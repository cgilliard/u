//! `tabminer [options]`: a node of the Tabernacle network.
//!
//! What it is told is read and checked ([`Configuration`]); then
//! everything it needs is opened: the logs, the store, the port. Only
//! when all of that is done does it say how it is configured and, in
//! the next line, that it is ready: from then on it takes requests,
//! until it is told to stop ([`interrupt`]).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use tabminer::aggregate::{AggregateVerifier, AggregatorParams, Genesis};
use tabminer::chain::Chain;
use tabminer::chain::params::ChainParams;
use tabminer::configuration::{Configuration, Network};
use tabminer::interrupt;
use tabminer::logger::Logger;
use tabminer::logger::queued::Queued;
use tabminer::logger::stats::{Stats, StatsLog};
use tabminer::net::node::Node;
use tabminer::net::socket::{self, Watch};
use tabminer::pow::SeedText;
use tabminer::store::backend::FileBackend;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let read = |path: &Path| std::fs::read_to_string(path);
    let configuration = match Configuration::read(&args, home.as_deref(), &here, &read) {
        // A thread to a core, unless told how many: and from here on
        // it is that many, so that the log says the number.
        Ok(mut configuration) => {
            if configuration.threads == 0 {
                configuration.threads = std::thread::available_parallelism().map_or(1, |n| n.get());
            }
            configuration
        }
        Err(refused) => {
            // The help asked for is what was asked for; the help after
            // something wrong is a failure.
            let (said, code) = refused.said();
            match code {
                0 => print!("{said}"),
                _ => eprint!("{said}"),
            }
            std::process::exit(code);
        }
    };
    let mut main_log = None;
    let Err(what) = run(&configuration, &mut main_log);
    // In the main log too, if it got as far as being opened.
    match &main_log {
        Some(main) => main.log_all(&format!("Error: {what}")),
        None => eprintln!("Error: {what}"),
    }
    std::process::exit(-1);
}

/// Runs the node: it returns only with why it could not start, or
/// could not go on. Told to stop, the program ends where that is
/// heard ([`interrupt::halt_when_told`]).
fn run(c: &Configuration, main_log: &mut Option<Arc<Logger>>) -> Result<std::convert::Infallible, String> {
    if c.mine {
        return Err("mining is not built into this node yet: give --no-mine".into());
    }
    if c.network != Network::Mainnet && !cfg!(feature = "dev") {
        return Err(format!("this build has no {} network: it is built with --features dev", c.network.name()));
    }
    tabminer::parallel::set_threads(c.threads);
    let mut net = c.net.clone();
    net.workers = c.threads;

    // Somewhere to keep things, and the logs: the main one first, so
    // that whatever else goes wrong is said there.
    let made = |dir: &Path| {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot make the directory {}: {e}", dir.display()))
    };
    made(&c.data_dir)?;
    let open = |path: &Path| -> Result<Logger, String> {
        if let Some(dir) = path.parent() {
            made(dir)?;
        }
        Logger::open(path, c.rotation).map_err(|e| format!("cannot open the log {}: {e}", path.display()))
    };
    let main = Arc::new(open(&c.main_log)?);
    *main_log = Some(Arc::clone(&main));
    let threads = |e: std::io::Error| format!("cannot start a thread: {e}");
    let requests = open(&c.request_log)?.report_rotations_to(Arc::clone(&main));
    let requests = Queued::start(requests, c.request_log_queue, Arc::clone(&main)).map_err(threads)?;
    let stats = Arc::new(Stats::new(socket::STATS));
    let stat_log = open(&c.stat_log)?.report_rotations_to(Arc::clone(&main));

    // The chain.
    let (params, proofs) = match c.network {
        Network::Mainnet => (ChainParams::MAINNET, AggregatorParams::MAINNET),
        Network::Dev => (ChainParams::DEV, AggregatorParams::DEV),
        Network::DevRecursive => (ChainParams::DEV_RECURSIVE, AggregatorParams::DEV_RECURSIVE),
    };
    let seed = SeedText::new(params.pow);
    let verifier = AggregateVerifier::new(proofs, params.emission, Genesis::of(&params.genesis().header, &seed));
    let store = c.data_dir.join("chain.store");
    let backend = FileBackend::open(&store).map_err(|e| format!("cannot open the store {}: {e}", store.display()))?;
    let chain = Chain::open(backend, c.keep, params, seed, verifier)
        .map_err(|e| format!("cannot open the store {}: {e}", store.display()))?;

    // The port.
    let socket = UdpSocket::bind(c.listen).map_err(|e| format!("cannot listen on {}: {e}", c.listen))?;
    let mut secret = [0u8; 32];
    tabminer::random::fill(&mut secret).map_err(|e| format!("the system gave no random bytes: {e}"))?;
    let clock = Instant::now();
    let now = || clock.elapsed().as_micros() as u64;
    let mut node = Node::new(net, c.network.magic(), Arc::new(chain), secret, now()).threaded();
    for peer in &c.peers {
        node.add_peer(*peer, true, now());
    }
    // A seed that cannot be found now is one fewer to begin from.
    for seed in &c.seeds {
        for found in seed.to_socket_addrs().into_iter().flatten() {
            if let SocketAddr::V4(found) = found {
                node.add_peer(found, true, now());
            }
        }
    }

    // Everything is open: from here the node can do what it is for.
    let _stats_log = StatsLog::start(stat_log, Arc::clone(&stats), c.stats).map_err(threads)?;
    interrupt::halt_when_told(Arc::clone(&main)).map_err(|e| format!("cannot listen for being told to stop: {e}"))?;
    c.announce(&main);
    Configuration::ready(&main);

    let watch = Watch { requests: Some(&requests), stats: Some(&stats), main: Some(&main) };
    let never = AtomicBool::new(false);
    match socket::run_watched(&mut node, &socket, &never, clock, &socket::unix, &watch) {
        Ok(()) => Err("the node stopped of itself".into()),
        Err(e) => Err(format!("the port can no longer be listened on: {e}")),
    }
}
