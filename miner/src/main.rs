//! `tabminer [options]`: a node of the Tabernacle network.
//!
//! What it is told is read and checked ([`Configuration`]); then
//! everything it needs is opened: the logs, the store, the port. Only
//! when all of that is done does it say how it is configured and, in
//! the next line, that it is ready: from then on it takes requests,
//! until it is ended: nothing is done about being told to stop, since
//! nothing has to be put in order first (`docs/RUNNING.md`).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tabminer::aggregate::{AggregateVerifier, AggregatorParams, Genesis};
use tabminer::chain::Chain;
use tabminer::chain::params::ChainParams;
use tabminer::configuration::{Configuration, Network, hex};
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
    max_signatures: usize,
    reward: &tabminer::hash::Digest,
    main: &Arc<Logger>,
    stats: &Arc<Stats>,
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
    // Blocks given up that have not yet let go.
    let mut letting_go: std::collections::VecDeque<std::thread::JoinHandle<()>> = Default::default();
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
        start = start.wrapping_add(1 << 32);
        // Two steps, each said as it is begun: the block's proof is
        // made, and then the nonce is looked for.
        let on = hold.chain().tip().ok().map(|tip| (commas(tip.height as u64 + 1), short(&tip.hash())));
        if let Some((height, parent)) = &on {
            main.log(&format!("Proving block {height} on {parent}"));
        }
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
        // The block is made on a thread of its own, which is not
        // waited for when the chain has another last block: the next
        // block is begun at once, and the one given up lets go where
        // it next asks whether to go on, seconds later at the most.
        // One may be letting go beside the one being made, and no
        // more: an older one is waited for.
        letting_go.retain(|attempt| !attempt.is_finished());
        while letting_go.len() > 1 {
            if let Some(old) = letting_go.pop_front() {
                let _ = old.join();
            }
        }
        let (done, ended) = std::sync::mpsc::channel::<bool>();
        let attempt = {
            let (hold, table, main, stats) = (hold.clone(), Arc::clone(&table), Arc::clone(main), Arc::clone(stats));
            let (reward, watch) = (*reward, ahead.is_none());
            std::thread::Builder::new().name("block".into()).spawn(move || {
                let finished =
                    make_block(&hold, &table, &reward, &main, &stats, max_signatures, seen, watch, start, on);
                let _ = done.send(finished);
            })
        };
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(e) => return main.log(&format!("Error: no more blocks are made: no thread to make one on: {e}")),
        };
        // Until it has come to its end, or the chain has moved.
        let ended = loop {
            match ended.try_recv() {
                Ok(finished) => break Some(finished),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break Some(false),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if hold.moves() != seen {
                break None;
            }
            hold.wait_moved(seen, Duration::from_millis(250));
        };
        match ended {
            Some(true) => return,
            Some(false) => {
                if attempt.join().is_err() {
                    return main.log("Error: no more blocks are made: making one failed");
                }
            }
            None => letting_go.push_back(attempt),
        }
    }
}

/// Makes one block on the chain's last, which was the last when the
/// chain had moved `seen` times: given up when it has another, or
/// (`watch`) when a chain ahead turns up that is to be waited for.
/// Won, it is handed to the node, and what comes of it waited for.
/// True if the chain has had its last block.
#[allow(clippy::too_many_arguments)]
fn make_block(
    hold: &Handle<FileBackend, AggregateVerifier>,
    table: &RwLock<LazyDataset<'static>>,
    reward: &tabminer::hash::Digest,
    main: &Logger,
    stats: &Stats,
    max_signatures: usize,
    seen: u64,
    watch: bool,
    start: u64,
    on: Option<(String, String)>,
) -> bool {
    // (A chain ahead is looked for a few times a second, not at every
    // hash.)
    let looked = std::sync::Mutex::new(Instant::now());
    // (When the chain was first seen to have another last block: for
    // how long the letting go then took, which `TABMINER_TIMING` has
    // said.)
    let noticed = std::sync::Mutex::new(None::<Instant>);
    let cancel = || {
        if hold.moves() != seen {
            noticed.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(Instant::now);
            return true;
        }
        let mut looked = looked.lock().unwrap_or_else(|e| e.into_inner());
        if !watch || looked.elapsed() < Duration::from_millis(250) {
            return false;
        }
        *looked = Instant::now();
        hold.behind() != Behind::No
    };
    let proved = |took: Duration| {
        if let Some((height, parent)) = &on {
            let took = short_seconds(took.as_millis() as u64);
            main.log(&format!("Mining block {height} on {parent}: proved in {took}"));
        }
    };
    // What the block carries of the pool: none, if it cannot be
    // chosen.
    let (pooled, sweeps) = match miner::choose(hold.chain(), &|f| hold.pool(f), max_signatures) {
        Ok(chosen) => chosen,
        Err(e) => {
            main.log(&format!("Error: choosing a block's transactions: {e}"));
            (Vec::new(), Vec::new())
        }
    };
    if let Some((height, _)) = &on
        && !pooled.is_empty()
    {
        let signatures: usize = pooled.iter().map(|tx| tx.weight()).sum();
        main.log(&format!(
            "Block {height} carries {} transactions of the pool ({} signatures)",
            commas(pooled.len() as u64),
            commas(signatures as u64)
        ));
    }
    let dataset = table.read().unwrap_or_else(|e| e.into_inner());
    let unix = socket::unix();
    match miner::mine_with(hold.chain(), &*dataset, reward, unix, start, &pooled, &sweeps, &proved, &cancel) {
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
        Ok(Mined::Cancelled) => {
            let noticed = *noticed.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(at) = noticed
                && std::env::var_os("TABMINER_TIMING").is_some()
            {
                main.log(&format!("Let go {} ms after the chain was seen to move", at.elapsed().as_millis()));
            }
        }
        // What was chosen no longer applies: again, in a moment, with
        // what is chosen then.
        Ok(Mined::Stale) => hold.wait_moved(seen, Duration::from_millis(200)),
        Ok(Mined::Finished) => return true,
        Err(e) => {
            main.log(&format!("Error: making a block: {e}"));
            hold.wait_moved(seen, Duration::from_secs(1));
        }
    }
    false
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
/// could not go on. Told to stop, the program is ended by the
/// operating system, where it stands.
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
        let most = c.max_block_signatures;
        std::thread::Builder::new()
            .name("miner".into())
            .spawn(move || make_blocks(&hold, seed, &table, prebuild, most, &reward, &main, &stats))
            .map_err(threads)?;
    }

    let watch = Watch { requests: Some(&requests), stats: Some(&stats), main: Some(&main) };
    match socket::run_for_ever(&mut node, &socket, clock, &socket::unix, &watch) {
        Ok(()) => Err("the node stopped of itself".into()),
        Err(e) => Err(format!("the port can no longer be listened on: {e}")),
    }
}
