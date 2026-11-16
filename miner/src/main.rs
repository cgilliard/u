//! `tabminer [options]`: a node of the Tabernacle network.
//!
//! What it is told is read and checked ([`Configuration`]); then
//! everything it needs is opened: the logs, the store, the port. Only
//! when all of that is done does it say how it is configured and, in
//! the next line, that it is ready: from then on it takes requests,
//! until it is told to stop ([`interrupt`]).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tabminer::aggregate::{AggregateVerifier, AggregatorParams, Genesis};
use tabminer::chain::Chain;
use tabminer::chain::params::ChainParams;
use tabminer::configuration::{Configuration, Network, hex};
use tabminer::interrupt;
use tabminer::logger::Logger;
use tabminer::logger::fmt::{bytes, commas, seconds, short_seconds};
use tabminer::logger::queued::Queued;
use tabminer::logger::stats::{Stats, StatsLog};
use tabminer::miner::{self, HoldOff, Mined, Now};
use tabminer::net::node::{Behind, Event, Handle, Node};
use tabminer::net::socket::{self, Watch};
use tabminer::pow::{Dataset, ItemSource, LazyDataset, SeedText};
use tabminer::store::backend::FileBackend;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let read = |path: &Path| std::fs::read_to_string(path);
    let configuration = match Configuration::read(&args, home.as_deref(), &here, &read) {
        // A thread to a core, unless told how many (a core, not each of
        // the two threads a core may run): and from here on it is that
        // many, so that the log says the number.
        Ok(mut configuration) => {
            if configuration.threads == 0 {
                configuration.threads = tabminer::parallel::cores();
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

/// Where the dev network's rewards go when no key is given: to a key
/// nobody has. They are for trying the network, not for keeping.
const DEV_REWARD: tabminer::hash::Digest = [tabminer::poseidon2::Fp::ZERO; 8];

/// What the main log says of something that happened to the node, if
/// anything.
fn said(event: &Event) -> Option<String> {
    let n = |height: u32| commas(height as u64);
    let whose = |from: &Option<std::net::SocketAddrV4>| {
        from.map_or_else(|| "made here".to_string(), |from| format!("from {from}"))
    };
    Some(match event {
        Event::PeerConnected { peer, height } => format!("Peer {peer} connected (height {})", n(*height)),
        Event::PeerLost { peer } => format!("Peer {peer} lost"),
        Event::Banned { peer } => format!("Banned {}: it sent what no honest peer sends, too often", peer.ip()),
        Event::HeadersWanted { from, to, peer } => {
            format!("Syncing headers {} to {} from {peer}", n(*from), n(*to))
        }
        Event::HeadersKept { height } => format!("Headers synced to {}", n(*height)),
        Event::HeadersRefused { peer } => format!("Headers from {peer} refused"),
        // (A block made here that joins the chain was said when won.)
        Event::Block { from: None, undone: 0, .. } => return None,
        Event::Block { header, from, undone: 0, .. } => {
            format!("Received block {} ({}) {}", n(header.height), short(&header.hash()), whose(from))
        }
        // The chain went over to another branch.
        Event::Block { header, from, undone, taken } => {
            let blocks = |k: u32| if k == 1 { "1 block".to_string() } else { format!("{} blocks", n(k)) };
            format!(
                "Reorganized to block {} ({}) {}: {} undone, {} taken, above block {}",
                n(header.height),
                short(&header.hash()),
                whose(from),
                blocks(*undone),
                blocks(*taken),
                n(header.height - taken)
            )
        }
        Event::Side { header, from: None } => {
            format!("Block {} ({}) made here is on a side branch", n(header.height), short(&header.hash()))
        }
        Event::Side { header, from: Some(from) } => {
            format!("Received block {} ({}) from {from}, on a side branch", n(header.height), short(&header.hash()))
        }
        Event::BlockRefused { header, from, why } => {
            format!("Refused block {} ({}) {}: {why}", n(header.height), short(&header.hash()), whose(from))
        }
        Event::Synced { height } => format!("Synced at block {}", n(*height)),
        Event::StateWanted { height, id, again: false } => {
            format!("Taking the state as of block {} ({})", n(*height), short(id))
        }
        Event::StateWanted { height, id, again: true } => {
            format!("Taking the state as of a later block, {} ({})", n(*height), short(id))
        }
        Event::StateTaken { height } => format!("State taken as of block {}", n(*height)),
    })
}

/// The first of a block's id, as the logs say it.
fn short(id: &tabminer::hash::Digest) -> String {
    hex(&tabminer::poseidon2::digest_to_bytes(id)[..4])
}

/// Makes blocks, one after another, on whatever the chain's last block
/// is: begun again whenever that changes, and not while the node is
/// catching up with a chain ahead of its own.
fn make_blocks(
    hold: &Handle<FileBackend, AggregateVerifier>,
    seed: SeedText<'static>,
    kept: &Path,
    prebuild: bool,
    reward: &tabminer::hash::Digest,
    main: &Arc<Logger>,
    stats: &Stats,
) {
    // The table of the proof of work, for the height blocks are now
    // made at: what a file of it from an earlier run holds, and the
    // rest filled as it is read, and by a thread that does nothing
    // else until it is whole.
    let pow = hold.chain().params().pow;
    let size = |log_items: u32| bytes(tabminer::pow::table_bytes(log_items));
    let next = hold.chain().tip().map_or(1, |tip| tip.height as u64 + 1);
    let table = match LazyDataset::open(&seed, pow.log_items_at(next), kept) {
        Ok(table) => Arc::new(RwLock::new(table)),
        Err(e) => {
            let needed = size(pow.log_items_at(next));
            return main.log(&format!("Error: no blocks are made: the table of the proof of work ({needed}): {e}"));
        }
    };
    // What a file kept from an earlier run gave, if it gave the whole.
    if Dataset::built_in(&seed).is_none() && table.read().unwrap_or_else(|e| e.into_inner()).is_complete() {
        let whole = size(pow.log_items_at(next));
        main.log(&format!("The table of the proof of work ({whole}) was read from '{}'", kept.display()));
    }
    fill_table(&table, kept, main, prebuild);
    // Where this miner's nonces begin: its own, as likely as not.
    let mut start = [0u8; 8];
    let _ = tabminer::random::fill(&mut start);
    let mut start = u64::from_le_bytes(start);
    let mut hold_off = HoldOff::new(hold.chain().params().schedule.block_time.max(1) as u64);
    loop {
        let seen = hold.moves();
        // Not while the state is being taken; and not, for a while,
        // while a chain known to be ahead of ours is coming in.
        let ahead = match hold.behind() {
            Behind::State => {
                hold.wait_moved(seen, Duration::from_secs(1));
                continue;
            }
            Behind::Blocks { best, height } => Some((best, height)),
            Behind::No => None,
        };
        match (hold_off.ask(ahead.map(|(best, _)| best), Instant::now()), ahead) {
            (Now::Wait { first }, Some((best, height))) => {
                if first {
                    main.log(&format!(
                        "Not mining: a chain ahead is coming in, to block {} ({})",
                        commas(height as u64),
                        short(&best)
                    ));
                }
                hold.wait_moved(seen, Duration::from_secs(1));
                continue;
            }
            (Now::MineAnyway { first: true }, Some((best, height))) => main.log(&format!(
                "Mining again: the blocks of the chain ahead, to block {} ({}), have not come in {}",
                commas(height as u64),
                short(&best),
                seconds(hold_off.limit().as_millis() as u64)
            )),
            _ => {}
        }
        // Given up when the chain has another last block; or when a
        // chain ahead turns up that is to be waited for (looked for a
        // few times a second, not at every hash).
        let watch = ahead.is_none();
        let looked = std::sync::Mutex::new(Instant::now());
        let cancel = || {
            if hold.moves() != seen {
                return true;
            }
            let mut looked = looked.lock().unwrap_or_else(|e| e.into_inner());
            if !watch || looked.elapsed() < Duration::from_millis(250) {
                return false;
            }
            *looked = Instant::now();
            hold.behind() != Behind::No
        };
        start = start.wrapping_add(1 << 32);
        // Two steps, each said as it is begun: the block's proof is
        // made, and then the nonce is looked for.
        let on = hold.chain().tip().map(|tip| (commas(tip.height as u64 + 1), short(&tip.hash())));
        if let Ok((height, parent)) = &on {
            main.log(&format!("Proving block {height} on {parent}"));
        }
        let proved = |took: Duration| {
            if let Ok((height, parent)) = &on {
                let took = short_seconds(took.as_millis() as u64);
                main.log(&format!("Mining block {height} on {parent}: proved in {took}"));
            }
        };
        // The table grows with the chain, a year at a time: what it
        // has stays, and the rest is filled as the first was.
        let wanted = hold.chain().tip().map_or(0, |tip| pow.log_items_at(tip.height as u64 + 1));
        if table.read().unwrap_or_else(|e| e.into_inner()).log_items() < wanted {
            main.log(&format!("The table of the proof of work grows to {}", size(wanted)));
            if let Err(e) = table.write().unwrap_or_else(|e| e.into_inner()).grow(wanted) {
                return main.log(&format!("Error: no more blocks are made: the table of the proof of work: {e}"));
            }
            fill_table(&table, kept, main, prebuild);
        }
        let dataset = table.read().unwrap_or_else(|e| e.into_inner());
        match miner::mine(hold.chain(), &*dataset, reward, socket::unix(), start, &proved, &cancel) {
            Ok(Mined::Block { block, header, hashes, solved, .. }) => {
                main.log(&format!(
                    "Won block {} ({}): {} hashes in {}",
                    commas(header.height as u64),
                    short(&header.hash()),
                    commas(hashes),
                    short_seconds(solved.as_millis() as u64)
                ));
                stats.add(socket::MINED, 1);
                // Until what came of it is heard: it is the chain's
                // last, or another got there first. Either way the next
                // is begun at once, on whatever the last then is.
                let settled = hold.settled();
                hold.mined(block, socket::unix());
                hold.wait_settled(settled, Duration::from_secs(10));
            }
            Ok(Mined::Cancelled) => {}
            Ok(Mined::Finished) => return,
            Err(e) => {
                main.log(&format!("Error: making a block: {e}"));
                hold.wait_moved(seen, Duration::from_secs(1));
            }
        }
    }
}

/// Fills what is missing of the table of the proof of work, on a thread
/// of its own, and keeps it in the file `kept` when it is whole: so
/// that the next run begins with it. (Blocks are made meanwhile: what
/// they read of the table is filled as they read it.)
fn fill_table(table: &Arc<RwLock<LazyDataset<'static>>>, kept: &Path, main: &Arc<Logger>, first: bool) {
    // Said here, before any thread is begun: so that it is always said
    // before what the caller goes on to say.
    {
        let table = table.read().unwrap_or_else(|e| e.into_inner());
        if table.is_complete() {
            return;
        }
        let whole = tabminer::pow::table_bytes(table.log_items());
        let there = whole / table.pairs() as u64 * table.filled() as u64;
        main.log(&format!(
            "Making the table of the proof of work: {} of {} are there. This may take a while{}",
            bytes(there),
            bytes(whole),
            if first { ": no blocks are made until it is whole" } else { "" }
        ));
    }
    let (shared, kept, told) = (Arc::clone(table), kept.to_path_buf(), Arc::clone(main));
    let fill = move || {
        let main = told;
        let table = shared.read().unwrap_or_else(|e| e.into_inner());
        let whole = tabminer::pow::table_bytes(table.log_items());
        let began = Instant::now();
        // How far it has got, at every twentieth.
        miner::fill_table(&table, Duration::from_millis(500), &|percent| {
            let there = bytes(whole / 100 * percent as u64);
            main.log(&format!("The table of the proof of work: {percent}% ({there} of {})", bytes(whole)));
        });
        main.log(&format!(
            "The table of the proof of work is whole: made in {}",
            seconds(began.elapsed().as_millis() as u64)
        ));
        // Kept, for the next run to begin with.
        match table.save(&kept) {
            Ok(()) => main.log(&format!("The table of the proof of work is kept in '{}'", kept.display())),
            Err(e) => main
                .log(&format!("Error: the table of the proof of work could not be kept in '{}': {e}", kept.display())),
        }
    };
    // Before any block is made, if so set; else beside the making of them.
    if first {
        return fill();
    }
    if let Err(e) = std::thread::Builder::new().name("pow table".into()).spawn(fill) {
        main.log(&format!("Error: the table of the proof of work is not being made ahead: {e}"));
    }
}

/// Runs the node: it returns only with why it could not start, or
/// could not go on. Told to stop, the program ends where that is
/// heard ([`interrupt::halt_when_told`]).
fn run(c: &Configuration, main_log: &mut Option<Arc<Logger>>) -> Result<std::convert::Infallible, String> {
    // On mainnet the rewards of blocks made here need somewhere to go:
    // there is no wallet yet to make a key for them.
    if c.mine && c.network == Network::Mainnet && c.reward.is_none() {
        return Err(
            "making blocks on mainnet needs --reward-key (the key their rewards are paid to), or --no-mine".into()
        );
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
    // The table of the proof of work, where the network's is built in:
    // headers are checked against it, and blocks made with it.
    if let Some(dataset) = Dataset::built_in(&seed) {
        chain.set_dataset(Arc::new(dataset));
    }
    // Blocks are made with a table of their own, which fills as it is
    // read and is kept in the data directory from one run to the next.
    let mining = c.mine.then(|| (seed, c.data_dir.join("pow.table"), c.reward.unwrap_or(DEV_REWARD)));

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

    // The stats: how the node stands is read afresh for every line.
    let hold = node.hold();
    let stats = {
        let hold = hold.clone();
        Arc::new(socket::stats().refreshed_by(Box::new(move |stats| socket::set_levels(stats, &hold))))
    };

    // Everything is open: from here the node can do what it is for.
    let _stats_log = StatsLog::start(stat_log, Arc::clone(&stats), c.stats).map_err(threads)?;
    interrupt::halt_when_told(Arc::clone(&main)).map_err(|e| format!("cannot listen for being told to stop: {e}"))?;
    c.announce(&main);
    Configuration::ready(&main);

    // Blocks are made on a thread of their own, for as long as the
    // node runs.
    {
        let main = Arc::clone(&main);
        hold.on_event(Box::new(move |event| {
            if let Some(line) = said(event) {
                main.log(&line);
            }
        }));
    }
    if let Some((seed, table, reward)) = mining {
        let (main, stats, prebuild) = (Arc::clone(&main), Arc::clone(&stats), c.prebuild_table);
        std::thread::Builder::new()
            .name("miner".into())
            .spawn(move || make_blocks(&hold, seed, &table, prebuild, &reward, &main, &stats))
            .map_err(threads)?;
    }

    let watch = Watch { requests: Some(&requests), stats: Some(&stats), main: Some(&main) };
    let never = AtomicBool::new(false);
    match socket::run_watched(&mut node, &socket, &never, clock, &socket::unix, &watch) {
        Ok(()) => Err("the node stopped of itself".into()),
        Err(e) => Err(format!("the port can no longer be listened on: {e}")),
    }
}
