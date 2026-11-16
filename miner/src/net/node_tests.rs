//! Nodes and the datagrams between them, every datagram's fate chosen.

use super::*;
use crate::block::BlockRef;
use crate::chain::apply::tests::{grow, next_block};
use crate::chain::headers::tests::{NOW, easy, seed, table};
use crate::chain::params::ChainParams;
use crate::chain::verify::AcceptAllProofs;
use crate::net::message::Addrs;
use crate::store::testing::MemBackend;
use crate::test_util::Rng;
use crate::transport::{MILLI, SECOND};
use std::net::Ipv4Addr;

const NET: [u8; 4] = *b"TEST";

type TestChain = Chain<MemBackend, AcceptAllProofs>;
type TestNode = Node<MemBackend, AcceptAllProofs>;

/// A chain that keeps the bodies of its last `KEEP` blocks.
const KEEP: usize = 64;

fn chain_of(params: ChainParams) -> Arc<TestChain> {
    let chain = Chain::open(MemBackend::new(), KEEP, params, seed(), AcceptAllProofs).unwrap();
    chain.set_dataset(table());
    Arc::new(chain)
}

/// Gives `chain` these blocks, made on another.
fn give(chain: &TestChain, blocks: &[Vec<u8>]) {
    for b in blocks {
        chain.apply_block(&BlockRef::from_bytes(b).unwrap(), NOW).unwrap();
    }
}

/// The address of node `n`: each a host and a network of its own.
fn at(n: usize) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(20 + (n / 200) as u8, (n % 200) as u8, 0, 1), 3737)
}

/// Nodes and the datagrams between them: every one takes twenty
/// milliseconds, some are lost, and one sent to an address that is no
/// node's is kept to be looked at.
struct World {
    nodes: Vec<TestNode>,
    /// When each node wants to be called.
    wake: Vec<Micros>,
    now: Micros,
    flying: Vec<(Micros, SocketAddrV4, SocketAddrV4, Vec<u8>)>,
    /// Lost, in a thousand.
    loss: u64,
    rng: Rng,
    /// To addresses that are no node's: from, to, what.
    strays: Vec<(SocketAddrV4, SocketAddrV4, Vec<u8>)>,
    /// Nodes of which nothing but pings and pongs gets out.
    mute: Vec<usize>,
    /// Times the nodes were told the time.
    ticks: u64,
}

impl World {
    fn new(n: usize, cfg: &Config) -> World {
        World::with((0..n).map(|_| chain_of(easy())).collect(), cfg)
    }

    fn with(chains: Vec<Arc<TestChain>>, cfg: &Config) -> World {
        let n = chains.len();
        let nodes = chains.into_iter().enumerate().map(|(i, c)| Node::new(cfg.clone(), NET, c, [i as u8 + 1; 32], 0));
        World {
            nodes: nodes.collect(),
            wake: vec![0; n],
            now: 0,
            flying: Vec::new(),
            loss: 0,
            rng: Rng::new(5),
            strays: Vec::new(),
            mute: Vec::new(),
            ticks: 0,
        }
    }

    fn post(&mut self, from: SocketAddrV4, to: SocketAddrV4, bytes: &[u8]) {
        if self.rng.next_u64() % 1000 >= self.loss {
            self.flying.push((self.now + 20 * MILLI, from, to, bytes.to_vec()));
        }
    }

    /// A datagram from `from`, which may be anyone's claim.
    fn inject(&mut self, from: SocketAddrV4, to: usize, message: &Message<'_>) {
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = message.encode(NET, &mut buf);
        self.flying.push((self.now, from, at(to), buf[..n].to_vec()));
    }

    /// Lets `time` pass: each node is called when it asks to be, and
    /// when a datagram has come for it.
    fn run(&mut self, time: Micros) {
        let end = self.now + time;
        loop {
            // Everything due at this moment, until nothing is.
            for round in 0.. {
                assert!(round < 100_000, "a moment that does not end");
                let mut sent = Vec::new();
                let (due, later): (Vec<_>, Vec<_>) = self.flying.drain(..).partition(|d| d.0 <= self.now);
                self.flying = later;
                let mut busy = !due.is_empty();
                for (_, from, to, bytes) in due {
                    match (0..self.nodes.len()).find(|&i| at(i) == to) {
                        Some(i) => {
                            self.nodes[i].handle(self.now, SocketAddr::V4(from), &bytes, &mut |to, b| {
                                sent.push((i, to, b.to_vec()))
                            });
                            self.wake[i] = self.now;
                        }
                        None => self.strays.push((from, to, bytes)),
                    }
                }
                for i in 0..self.nodes.len() {
                    if self.wake[i] <= self.now {
                        busy = true;
                        self.ticks += 1;
                        self.wake[i] = self.nodes[i].tick(self.now, NOW, &mut |to, b| sent.push((i, to, b.to_vec())));
                        // (At once means as soon as time has moved.)
                        self.wake[i] = self.wake[i].max(self.now + 1);
                    }
                }
                for (i, to, bytes) in sent {
                    let small_talk = matches!(Message::decode(NET, &bytes), Ok(Message::Ping(_) | Message::Pong(_)));
                    if small_talk || !self.mute.contains(&i) {
                        self.post(at(i), to, &bytes);
                    }
                }
                if !busy {
                    break;
                }
            }
            let next = self.flying.iter().map(|d| d.0).chain(self.wake.iter().copied()).min().unwrap_or(end);
            if next >= end {
                self.now = end;
                return;
            }
            self.now = next.max(self.now + 1);
        }
    }

    fn live(&self, i: usize) -> Vec<SocketAddrV4> {
        self.nodes[i].peers().live(self.now).map(|p| p.addr).collect()
    }

    fn best(&self, i: usize) -> Header {
        self.nodes[i].chain().best_header().unwrap().header
    }
}

/// A status as some address might claim it.
fn claim(nonce: u64, genesis: Digest) -> Status {
    Status {
        nonce,
        version: VERSION,
        token: 0,
        genesis,
        height: 1,
        oldest: 0,
        window: 0,
        tip: genesis,
        work: U256::ZERO,
    }
}

// -- Finding and keeping peers

#[test]
fn two_nodes_that_one_knows_of_come_to_know_each_other() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[1], 3, 1);
    let mut w = World::with(chains, &Config::default());
    assert!(w.nodes[0].add_peer(at(1), true, 0));
    w.run(500 * MILLI);
    assert_eq!((w.live(0), w.live(1)), (vec![at(1)], vec![at(0)]));
    // Each holds what the other says of itself, and the token the
    // other gave it; and each has timed the other.
    let (a, b) = (*w.nodes[0].peers().get(&at(1)).unwrap(), *w.nodes[1].peers().get(&at(0)).unwrap());
    let tip = w.nodes[1].chain().tip().unwrap();
    assert_eq!((a.status.unwrap().height, a.status.unwrap().tip, b.status.unwrap().height), (3, tip.hash(), 0));
    assert_eq!((a.status.unwrap().oldest, a.status.unwrap().window), (0, 0));
    assert_eq!(a.status.unwrap().work, w.nodes[1].chain().tip_work().unwrap());
    assert!(w.nodes[1].tokens.check(&SocketAddr::V4(at(0)), a.token().unwrap()));
    assert!(w.nodes[0].tokens.check(&SocketAddr::V4(at(1)), b.token().unwrap()));
    assert_eq!((a.path.round_trip(), b.path.round_trip()), (Some(40 * MILLI), Some(40 * MILLI)));
    assert_eq!((w.nodes[0].counts().unheard, w.nodes[0].counts().malformed), (0, 0));
}

/// Thirty nodes that know one seed between them: each comes to have
/// the peers it wants, though a fifth of all datagrams are lost.
#[test]
fn nodes_that_know_one_seed_find_each_other() {
    for loss in [0, 200] {
        let mut w = World::new(30, &Config::default());
        w.loss = loss;
        for i in 1..30 {
            assert!(w.nodes[i].add_peer(at(0), true, 0));
        }
        w.run(60 * SECOND);
        for i in 0..30 {
            assert!(w.live(i).len() >= 8, "loss {loss}: node {i} has {}", w.live(i).len());
        }
        // Having what they want, they ask no more, and only ping: a
        // ping and a pong to each peer every thirty seconds.
        let before: u64 = w.nodes.iter().map(|n| n.counts().sent).sum();
        let peers: usize = (0..30).map(|i| w.nodes[i].peers().len()).sum();
        w.run(60 * SECOND);
        let sent = w.nodes.iter().map(|n| n.counts().sent).sum::<u64>() - before;
        assert!(sent <= 2 * 2 * peers as u64 + 60, "loss {loss}: {sent} for {peers}");
    }
}

#[test]
fn a_forged_ping_costs_its_victim_no_more_than_the_forger() {
    let mut w = World::new(1, &Config::default());
    let genesis = w.nodes[0].genesis;
    w.run(10 * MILLI);
    let forged = |n: u16| SocketAddrV4::new(Ipv4Addr::new(99, (n / 4) as u8, 0, (n % 4) as u8 + 1), 1000 + n);
    // A hundred pings in one tick, each claiming another address.
    for n in 0..100 {
        w.inject(forged(n), 0, &Message::Ping(claim(n as u64, genesis)));
    }
    w.run(500 * MILLI);
    // Each got its pong; our own pings went to eight of them.
    let (mut pongs, mut pings) = (0, 0);
    for (_, _, bytes) in &w.strays {
        match Message::decode(NET, bytes).unwrap() {
            Message::Pong(_) => pongs += 1,
            Message::Ping(_) => pings += 1,
            other => panic!("{other:?}"),
        }
        assert_eq!(bytes.len(), 133, "as much as a ping, no more");
    }
    assert_eq!((pongs, pings), (100, 8));
    // The same address again and again gets pongs, and no second ping
    // until its turn.
    w.strays.clear();
    for _ in 0..50 {
        w.inject(forged(0), 0, &Message::Ping(claim(7, genesis)));
    }
    w.run(400 * MILLI);
    assert_eq!(w.strays.len(), 50);
    // None of them is anyone: none is live, none is told of, and in
    // three minutes all are gone. (Three minutes from when each was
    // first pinged, and the last had its first ping some seconds in.)
    let now = w.now;
    assert!(w.live(0).is_empty() && w.nodes[0].peers.sample(None, now).as_slice().is_empty());
    let seconds = w.now / SECOND;
    w.run(200 * SECOND);
    assert_eq!(w.nodes[0].peers().len(), 0);
    // In all that time our pings to them were rationed: eight
    // addresses a second at the most.
    let pings = w.strays.iter().filter(|s| matches!(Message::decode(NET, &s.2), Ok(Message::Ping(_)))).count() as u64;
    assert!(pings <= 8 * (200 + seconds + 2), "{pings}");
}

#[test]
fn a_pong_that_answers_no_ping_of_ours_proves_nothing() {
    let mut w = World::new(2, &Config::default());
    let genesis = w.nodes[0].genesis;
    w.nodes[0].add_peer(at(1), false, 0);
    // Before node 0 has pinged at all: a pong claiming the earth.
    let boast = Status { height: 1 << 30, work: U256::MAX, ..claim(1, genesis) };
    w.flying.clear();
    w.wake[0] = Micros::MAX;
    w.inject(at(1), 0, &Message::Pong(boast));
    w.wake[1] = Micros::MAX;
    w.run(10 * MILLI);
    assert!(!w.nodes[0].peers().proven(&at(1)));
    assert_eq!(w.nodes[0].counts().unheard, 1);
    // Nor does anything else from an address not proven count: a list
    // of peers to try is not taken.
    let mut addrs = Addrs::new();
    addrs.push(at(7));
    w.inject(at(5), 0, &Message::Peers(addrs));
    w.wake[0] = Micros::MAX;
    w.run(10 * MILLI);
    assert!(w.nodes[0].peers().get(&at(7)).is_none());
    assert_eq!(w.nodes[0].counts().unheard, 2);
}

#[test]
fn a_request_is_answered_only_with_its_token() {
    let mut cfg = Config::default();
    // (Content with one peer, so that nothing is sent here but pings
    // and what the test sends.)
    (cfg.serve.token_life, cfg.peers.target) = (60 * SECOND, 1);
    let mut w = World::new(3, &cfg);
    w.nodes[0].add_peer(at(1), false, 0);
    w.nodes[0].add_peer(at(2), false, 0);
    w.run(SECOND);
    let token = w.nodes[0].peers().get(&at(1)).unwrap().token().unwrap();
    let answers = |w: &World| w.nodes[1].counts().sent;
    // The token node 1 gave node 0: answered.
    let before = answers(&w);
    w.inject(at(0), 1, &Message::GetPeers { token });
    w.run(50 * MILLI);
    assert_eq!(answers(&w), before + 1);
    // Without it, with another's, or from another address: nothing.
    let other = w.nodes[0].peers().get(&at(2)).unwrap().token().unwrap();
    let locator = Locator::new(&[w.nodes[0].genesis]).unwrap();
    for (from, t) in [(at(0), 0), (at(0), other), (at(0), token ^ 1), (at(9), token)] {
        w.inject(from, 1, &Message::GetPeers { token: t });
        w.inject(from, 1, &Message::Goodbye { token: t });
        w.inject(from, 1, &Message::FindFork { token: t, locator });
        let mut ranges = Ranges::new();
        ranges.push(0);
        let mut name = [0u8; MAX_NAME];
        let n = Object::Headers { from: 0, count: 1, on: w.nodes[0].genesis }.encode(&mut name);
        w.inject(from, 1, &Message::Get(Get { token: t, transfer: 1, seq: 0, name: &name[..n], ranges }));
    }
    w.run(50 * MILLI);
    assert_eq!(answers(&w), before + 1);
    assert_eq!(w.nodes[1].counts().unheard, 16);
    assert!(w.nodes[1].peers().proven(&at(0)));
    // A token lasts one change of the secret, and not two: an old one
    // kept and used long after is refused. (Pings carry the new one
    // every half minute, so a peer's is never old.)
    w.run(60 * SECOND);
    w.inject(at(0), 1, &Message::GetPeers { token });
    w.run(50 * MILLI);
    assert_eq!(w.nodes[1].counts().unheard, 16, "heard, the secret having changed once");
    w.run(70 * SECOND);
    w.inject(at(0), 1, &Message::GetPeers { token });
    w.run(50 * MILLI);
    assert_eq!(w.nodes[1].counts().unheard, 17);
    // While the one its pings have brought since is good.
    let fresh = w.nodes[0].peers().get(&at(1)).unwrap().token().unwrap();
    assert_ne!(fresh, token);
    w.inject(at(0), 1, &Message::GetPeers { token: fresh });
    w.run(50 * MILLI);
    assert_eq!(w.nodes[1].counts().unheard, 17);
}

#[test]
fn a_node_of_another_chain_or_version_is_answered_and_left_alone() {
    // Node 1 is of another chain.
    let other = ChainParams { genesis_timestamp: easy().genesis_timestamp + 1, ..easy() };
    let mut w = World::with(vec![chain_of(easy()), chain_of(other)], &Config::default());
    let genesis = w.nodes[0].genesis;
    w.nodes[0].add_peer(at(1), false, 0);
    w.run(SECOND);
    // Each answered the other, and neither keeps the other.
    assert_eq!((w.nodes[0].peers().len(), w.nodes[1].peers().len()), (0, 0));
    assert!(w.nodes[0].counts().strangers >= 1 && w.nodes[1].counts().strangers >= 1);
    // A ping of another version: a pong, and nothing kept.
    let stranger = SocketAddrV4::new(Ipv4Addr::new(77, 1, 1, 1), 9);
    w.inject(stranger, 0, &Message::Ping(Status { version: VERSION + 1, ..claim(3, genesis) }));
    w.run(100 * MILLI);
    assert_eq!(w.strays.len(), 1);
    assert!(
        matches!(Message::decode(NET, &w.strays[0].2), Ok(Message::Pong(s)) if s.nonce == 3 && s.version == VERSION)
    );
    assert_eq!(w.nodes[0].peers().len(), 0);
    // A datagram of another network, and one that is nothing: not
    // answered at all.
    let mut buf = [0u8; MAX_DATAGRAM];
    let n = Message::Ping(claim(3, genesis)).encode(*b"ELSE", &mut buf);
    w.flying.push((w.now, stranger, at(0), buf[..n].to_vec()));
    w.flying.push((w.now, stranger, at(0), b"hello".to_vec()));
    w.run(100 * MILLI);
    assert_eq!((w.strays.len(), w.nodes[0].counts().malformed), (1, 2));
}

#[test]
fn a_node_told_its_own_address_finds_out() {
    let mut w = World::new(2, &Config::default());
    w.nodes[0].add_peer(at(0), true, 0);
    w.nodes[0].add_peer(at(1), false, 0);
    w.run(SECOND);
    assert_eq!(w.live(0), [at(1)]);
    assert!(w.nodes[0].peers().get(&at(0)).is_none());
    // Told of again by a peer: not taken again.
    let mut addrs = Addrs::new();
    addrs.push(at(0));
    w.inject(at(1), 0, &Message::Peers(addrs));
    w.run(100 * MILLI);
    let now = w.now;
    assert!(w.nodes[0].peers().get(&at(0)).is_none() && !w.nodes[0].add_peer(at(0), false, now));
}

#[test]
fn a_node_that_says_goodbye_is_known_at_once_to_be_gone() {
    let mut cfg = Config::default();
    cfg.peers.target = 1;
    let mut w = World::new(3, &cfg);
    w.nodes[0].add_peer(at(1), false, 0);
    w.nodes[0].add_peer(at(2), false, 0);
    w.run(SECOND);
    assert_eq!(w.live(1), [at(0)]);
    let mut sent = Vec::new();
    let now = w.now;
    w.nodes[0].goodbye(now, &mut |to, b| sent.push((to, b.to_vec())));
    assert_eq!(sent.len(), 2);
    for (to, bytes) in sent {
        w.post(at(0), to, &bytes);
    }
    w.run(30 * MILLI);
    assert!(w.live(1).is_empty() && w.live(2).is_empty());
    // Its place is kept, and when it answers a ping again it is back.
    assert!(w.nodes[1].peers().get(&at(0)).is_some());
    w.run(31 * SECOND);
    assert_eq!(w.live(1), [at(0)]);
}

// -- Headers
//
// With `sync.blocks` at nothing where a test is of headers alone.

/// Settings under which a few dozen blocks are many runs of headers.
fn small_runs() -> Config {
    let mut cfg = Config::default();
    cfg.sync.headers = 10;
    cfg
}

#[test]
fn a_node_behind_takes_the_headers_of_one_ahead() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[0], 45, 1);
    let mut w = World::with(chains, &small_runs());
    w.nodes[1].add_peer(at(0), false, 0);
    // (Headers only, for this: nobody is asked for a body.)
    w.nodes[1].cfg.sync.blocks = 0;
    w.run(10 * SECOND);
    let tip = w.nodes[0].chain().tip().unwrap();
    assert_eq!(w.best(1), tip);
    // Asked once where the chains part; five runs of headers fetched
    // (four of ten and one of five), none given up.
    let c = w.nodes[1].counts();
    assert_eq!((c.forks_asked, c.fetched, c.fetches_failed, c.headers), (1, 5, 0, 45));
    assert!(w.nodes[1].aim.is_none() && w.nodes[1].fetching() == 0);
    // Headers only: its chain is where it was, and the bodies are
    // what it lacks.
    assert_eq!(w.nodes[1].chain().tip().unwrap().height, 0);
    let mut missing = [tip; 8];
    assert_eq!(w.nodes[1].chain().missing_bodies(&mut missing).unwrap(), 8);
    assert_eq!(missing[0].height, 1);
    // Having them, it asks for no more; and the one ahead never asked.
    w.run(60 * SECOND);
    assert_eq!((w.nodes[1].counts().forks_asked, w.nodes[0].counts().forks_asked), (1, 0));
    assert_eq!(w.nodes[0].peers().get(&at(1)).unwrap().delivered, 0);
    assert_eq!(w.nodes[1].peers().get(&at(0)).unwrap().delivered, 5);
}

/// Two chains that part: the node with less work takes the headers of
/// the other's branch from where they part, and the other takes none.
#[test]
fn headers_are_taken_from_where_two_chains_part() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    let shared = grow(&chains[0], 24, 1);
    give(&chains[1], &shared);
    grow(&chains[0], 14, 2);
    grow(&chains[1], 3, 3);
    let mut w = World::with(chains, &small_runs());
    w.nodes[0].add_peer(at(1), false, 0);
    w.nodes[1].cfg.sync.blocks = 0;
    w.run(10 * SECOND);
    assert_eq!(w.best(1), w.nodes[0].chain().tip().unwrap());
    // Fourteen headers, not thirty-eight: in two runs.
    let c = w.nodes[1].counts();
    assert_eq!((c.forks_asked, c.fetched, c.headers), (1, 2, 14));
    assert_eq!((w.nodes[0].counts().forks_asked, w.best(0).height), (0, 38));
    // Its own chain is still its own, until it has the bodies.
    assert_eq!(w.nodes[1].chain().tip().unwrap().height, 27);
}

/// With several peers ahead the runs come from several of them, and
/// with a fifth of all datagrams lost they come all the same.
#[test]
fn runs_of_headers_come_from_several_peers() {
    for loss in [0, 200] {
        let chains: Vec<_> = (0..4).map(|_| chain_of(easy())).collect();
        let blocks = grow(&chains[0], 45, 1);
        give(&chains[1], &blocks);
        give(&chains[2], &blocks);
        let mut w = World::with(chains, &small_runs());
        w.loss = loss;
        for i in 0..3 {
            w.nodes[3].add_peer(at(i), false, 0);
        }
        w.nodes[3].cfg.sync.blocks = 0;
        w.run(60 * SECOND);
        assert_eq!(w.best(3).height, 45, "loss {loss}");
        assert_eq!(w.nodes[3].counts().headers, 45);
        let served: Vec<u32> = (0..3).map(|i| w.nodes[3].peers().get(&at(i)).unwrap().delivered).collect();
        assert_eq!(served.iter().sum::<u32>(), 5, "loss {loss}");
        // From all three; where datagrams are lost, from whichever of
        // them had answered a ping by then, two at the least.
        let most_idle = if loss == 0 { 0 } else { 1 };
        assert!(served.iter().filter(|n| **n == 0).count() <= most_idle, "loss {loss}: {served:?}");
    }
}

/// A peer that claims more work than anyone and answers nothing for it
/// is doubted, and the headers come from the one that has them.
#[test]
fn a_false_claim_of_work_does_not_hold_a_node_up() {
    let chains: Vec<_> = (0..3).map(|_| chain_of(easy())).collect();
    grow(&chains[0], 12, 1);
    let mut w = World::with(chains, &small_runs());
    // Node 1 has nothing, says it has everything, and says no more.
    w.nodes[1].boast = Some(U256::MAX);
    w.mute = vec![1];
    w.nodes[2].add_peer(at(0), false, 0);
    w.nodes[2].add_peer(at(1), false, 0);
    w.nodes[2].cfg.sync.blocks = 0;
    w.run(10 * SECOND);
    // Asked first, as the one claiming most, and asked again every
    // two seconds; nothing came of it.
    assert_eq!((w.best(2).height, w.nodes[2].counts().forks_asked), (0, 5));
    assert_eq!(w.nodes[0].counts().unheard, 0, "the one that has them was not asked");
    // Fifteen seconds, and it is passed over for the one that answers.
    w.run(10 * SECOND);
    assert_eq!(w.best(2), w.nodes[0].chain().tip().unwrap());
    let now = w.now;
    assert!(!w.nodes[2].peers().may_ask(&at(1), now) && w.nodes[2].peers().may_ask(&at(0), now));
    // And one that answers where the chains part and then has no
    // headers to show is passed over the same.
    w.mute.clear();
    let mut w2 = World::with(vec![chain_of(easy()), chain_of(easy())], &small_runs());
    w2.nodes[0].boast = Some(U256::MAX);
    w2.nodes[1].add_peer(at(0), false, 0);
    w2.run(5 * SECOND);
    let now = w2.now;
    assert_eq!((w2.best(1).height, w2.nodes[1].counts().forks_asked), (0, 1));
    assert!(!w2.nodes[1].peers().may_ask(&at(0), now));
}

/// A peer that serves headers that are not the chain's takes a strike
/// each time, and is refused in the end; the headers come from another.
#[test]
fn a_peer_that_serves_wrong_headers_is_struck() {
    let chains: Vec<_> = (0..3).map(|_| chain_of(easy())).collect();
    let blocks = grow(&chains[0], 12, 1);
    give(&chains[1], &blocks);
    let mut cfg = small_runs();
    // (Asked again sooner than ten minutes on, so that the strikes
    // come within the time they are counted over.)
    cfg.sync.pass_over = 2 * SECOND;
    let mut w = World::with(chains, &cfg);
    w.nodes[0].spoil = true;
    w.nodes[2].add_peer(at(0), false, 0);
    w.run(4 * SECOND);
    // One wrong run: a strike, nothing kept from it, and the aim let go.
    assert_eq!(w.best(2).height, 0);
    assert!(w.nodes[2].counts().fetched >= 1 && w.nodes[2].aim.is_none());
    assert!(w.nodes[2].peers().get(&at(0)).is_some());
    // Five, and its host is refused.
    w.run(60 * SECOND);
    let now = w.now;
    assert!(w.nodes[2].peers().get(&at(0)).is_none());
    assert_eq!(w.nodes[2].peers.add(at(0), false, now), Err(crate::net::peers::Refused::Banned));
    assert_eq!(w.best(2).height, 0);
    // An honest peer turns up: from it they are taken.
    w.nodes[2].add_peer(at(1), false, now);
    w.run(10 * SECOND);
    assert_eq!(w.best(2), w.nodes[1].chain().tip().unwrap());
}

/// Where two chains part is taken only as the answer to our own
/// question, from whom it was put to; and an answer that names a block
/// we do not have, or not at that height, is a lie and a strike.
#[test]
fn where_chains_part_is_believed_only_as_an_answer() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[0], 12, 1);
    let mut w = World::with(chains, &small_runs());
    let genesis = w.nodes[1].genesis;
    w.nodes[1].add_peer(at(0), false, 0);
    // Unasked, before any question; and from one who was not asked.
    w.inject(at(0), 1, &Message::Fork { height: 0, id: genesis });
    w.inject(at(9), 1, &Message::Fork { height: 0, id: genesis });
    w.wake = vec![Micros::MAX; 2];
    w.run(10 * MILLI);
    assert_eq!((w.nodes[1].counts().unheard, w.nodes[1].aim.is_none()), (2, true));
    // Node 0 claims much and its true answers are lost; what arrives
    // in their place names a block nobody has, or the first block at
    // a height that is not its own.
    w.wake = vec![0; 2];
    w.nodes[0].boast = Some(U256::MAX);
    w.mute = vec![0];
    for k in 0..5u32 {
        assert!(w.nodes[1].peers().get(&at(0)).is_some() || k == 0, "after {k}");
        w.run(2100 * MILLI);
        let lie = if k % 2 == 0 {
            Message::Fork { height: 3, id: [crate::poseidon2::Fp::new(77 + k); 8] }
        } else {
            Message::Fork { height: 3, id: genesis }
        };
        w.inject(at(0), 1, &lie);
        w.run(50 * MILLI);
        assert!(w.nodes[1].aim.is_none() && w.best(1).height == 0);
    }
    let now = w.now;
    assert_eq!(w.nodes[1].peers.add(at(0), false, now), Err(crate::net::peers::Refused::Banned));
}

/// What a node serves is of one chain, by its name: headers past the
/// block named, or on a chain that block is not on, are not served.
#[test]
fn headers_are_served_only_of_the_chain_named() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[0], 20, 1);
    let mut w = World::with(chains, &Config::default());
    let node = &mut w.nodes[0];
    let at_height = |n: &TestNode, h: u32| n.chain().header_at(h).unwrap().unwrap();
    let (ten, tip) = (at_height(node, 10).hash(), at_height(node, 20).hash());
    let headers = |from, count, on| Object::Headers { from, count, on };
    let made = node.make(&headers(5, 6, ten)).unwrap();
    assert_eq!(made.len(), 6 * HEADER_SIZE);
    assert_eq!(Header::from_bytes(&made[..HEADER_SIZE]).unwrap(), at_height(node, 5));
    assert_eq!(Header::from_bytes(&made[5 * HEADER_SIZE..]).unwrap(), at_height(node, 10));
    // The same bytes under the tip's name, where they overlap.
    assert_eq!(node.make(&headers(5, 6, tip)).unwrap(), made);
    // Past the block named; a block not on the chain; a block unknown.
    assert!(node.make(&headers(5, 7, ten)).is_none());
    assert!(node.make(&headers(20, 2, tip)).is_none());
    assert!(node.make(&headers(1, 1, [crate::poseidon2::Fp::new(5); 8])).is_none());
    let side = chain_of(easy());
    let branch = grow(&side, 3, 9);
    // A block whose header is kept, and that is on no chain of ours.
    let stray = *BlockRef::from_bytes(&branch[0]).unwrap().header();
    assert_eq!(node.chain().accept_headers(&[stray], NOW, false), (1, None));
    assert!(node.chain().known(&stray.hash()).unwrap().is_some());
    assert!(node.make(&headers(1, 1, stray.hash())).is_none());
    // Kept while it is asked for, and the same each time.
    assert!(Arc::ptr_eq(&node.object(&headers(5, 6, ten)).unwrap(), &node.object(&headers(5, 6, ten)).unwrap()));
}

/// Two nodes on this machine's own sockets and clock: one comes to know
/// the other and takes its headers and then its blocks.
#[test]
fn over_real_sockets() {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let mut cfg = small_runs();
    cfg.tick = 50 * MILLI;
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[0], 45, 1);
    let tip = chains[0].tip().unwrap();
    let sockets: Vec<UdpSocket> = (0..2).map(|_| UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
    let SocketAddr::V4(first) = sockets[0].local_addr().unwrap() else { unreachable!() };
    let stop = Arc::new(AtomicBool::new(false));
    let behind = Arc::clone(&chains[1]);
    let threads: Vec<_> = sockets
        .into_iter()
        .zip(chains)
        .enumerate()
        .map(|(i, (socket, chain))| {
            let (cfg, stop) = (cfg.clone(), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut node = Node::new(cfg, NET, chain, [i as u8 + 1; 32], 0).threaded();
                if i == 1 {
                    node.add_peer(first, true, 0);
                }
                // (These headers' times are held against the time they
                // were made for, not this machine's.)
                crate::net::socket::run_until(&mut node, &socket, &stop, Instant::now(), &|| NOW).unwrap();
                node.counts()
            })
        })
        .collect();
    let start = Instant::now();
    while behind.tip().unwrap() != tip {
        assert!(start.elapsed() < Duration::from_secs(60), "at {}", behind.tip().unwrap().height);
        std::thread::sleep(Duration::from_millis(20));
    }
    // (A moment for the node to hear of the last block from the thread
    // that applied it.)
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    let counts: Vec<Counts> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    // Five runs of headers and forty-five bodies, the blocks applied on
    // a thread of their own.
    assert_eq!((counts[1].fetched, counts[1].headers, counts[1].fetches_failed), (50, 45, 0));
    assert_eq!((counts[1].blocks, counts[1].blocks_refused), (45, 0));
}

// -- Blocks

fn tip(w: &World, i: usize) -> Header {
    w.nodes[i].chain().tip().unwrap()
}

/// A node behind takes the blocks of one ahead: its chain and its
/// state end as the other's.
#[test]
fn a_node_behind_takes_the_blocks_of_one_ahead() {
    for loss in [0, 200] {
        let chains = vec![chain_of(easy()), chain_of(easy())];
        grow(&chains[0], 30, 1);
        let mut w = World::with(chains, &small_runs());
        w.loss = loss;
        w.nodes[1].add_peer(at(0), false, 0);
        w.run(40 * SECOND);
        assert_eq!(tip(&w, 1), tip(&w, 0), "loss {loss}");
        assert_eq!(w.nodes[1].chain().state().root(), w.nodes[0].chain().state().root());
        let c = w.nodes[1].counts();
        assert_eq!((c.headers, c.blocks, c.blocks_refused), (30, 30, 0), "loss {loss}");
        assert!(w.nodes[1].held.is_empty() && w.nodes[1].applying.is_empty() && w.nodes[1].fetching() == 0);
        if loss == 0 {
            // Three runs of headers and thirty bodies, each once.
            assert_eq!((c.fetched, c.fetches_failed), (33, 0));
        }
        // It told the other of each block as it joined, and the other,
        // having them, fetched none.
        assert_eq!((w.nodes[0].counts().fetched, w.nodes[0].counts().blocks), (0, 0));
    }
}

/// A block made on one node is on all of them in a moment, fetched by
/// each once.
#[test]
fn a_new_block_crosses_the_network() {
    let mut w = World::new(8, &Config::default());
    for i in 1..8 {
        w.nodes[i].add_peer(at(0), true, 0);
    }
    w.run(20 * SECOND);
    assert!((0..8).all(|i| w.live(i).len() == 7));
    for round in 1..=3u32 {
        // Made on another node each time.
        let maker = round as usize * 2;
        let block = next_block(w.nodes[maker].chain(), round, true);
        w.nodes[maker].mined(block);
        w.wake[maker] = w.now;
        w.run(500 * MILLI);
        let made = tip(&w, maker);
        assert_eq!(made.height, round);
        for i in 0..8 {
            assert_eq!(tip(&w, i), made, "round {round}, node {i}");
        }
    }
    for i in 0..8 {
        let c = w.nodes[i].counts();
        // Three blocks joined each chain; a node fetched those it did
        // not make, each once, and announced each to the others.
        let made = [2, 4, 6].contains(&i) as u64;
        assert_eq!((c.blocks, c.blocks_refused, c.fetches_failed), (3, 0, 0), "node {i}");
        assert_eq!(c.fetched, 3 - made, "node {i}");
        assert!(c.announced >= 3 * 6 && c.announced <= 3 * 7, "node {i}: {}", c.announced);
    }
}

/// A node on a branch with less work goes over to the branch with
/// more, undoing its own blocks.
#[test]
fn a_node_goes_over_to_the_branch_with_more_work() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    let shared = grow(&chains[0], 10, 1);
    give(&chains[1], &shared);
    grow(&chains[0], 6, 2);
    let own = grow(&chains[1], 2, 3);
    let mut w = World::with(chains, &small_runs());
    w.nodes[1].add_peer(at(0), false, 0);
    w.run(10 * SECOND);
    assert_eq!((tip(&w, 1), tip(&w, 1).height), (tip(&w, 0), 16));
    assert_eq!(w.nodes[1].chain().state().root(), w.nodes[0].chain().state().root());
    // Its own two blocks are kept, off the chain; the other never
    // wanted them.
    let was = BlockRef::from_bytes(&own[1]).unwrap().header().hash();
    assert!(w.nodes[1].chain().known(&was).unwrap().is_some() && w.nodes[1].on_chain(&was).is_none());
    assert_eq!(w.nodes[0].counts().fetched, 0);
}

/// A node that hears of a block whose parent it does not know asks for
/// the headers at once, without waiting for the next ping to say how
/// far the other has got.
#[test]
fn an_announcement_from_far_ahead_is_followed_at_once() {
    let mut cfg = small_runs();
    cfg.peers.target = 1;
    let chains = vec![chain_of(easy()), chain_of(easy())];
    let mut w = World::with(chains, &cfg);
    w.nodes[1].add_peer(at(0), false, 0);
    w.run(2 * SECOND);
    // Node 0 gets seven blocks that node 1 hears nothing of.
    w.mute = vec![0];
    for k in 0..7 {
        let block = next_block(w.nodes[0].chain(), 10 + k, true);
        w.nodes[0].mined(block);
        w.wake[0] = w.now;
        w.run(10 * MILLI);
    }
    assert_eq!((tip(&w, 0).height, tip(&w, 1).height), (7, 0));
    // The eighth it hears of: within a second it has all eight, half a
    // minute before the next ping would have told it.
    w.mute.clear();
    let block = next_block(w.nodes[0].chain(), 99, true);
    w.nodes[0].mined(block);
    w.wake[0] = w.now;
    w.run(SECOND);
    assert_eq!(tip(&w, 1), tip(&w, 0));
    // Its last ping said nothing of them: it was the announcement.
    assert_eq!(w.nodes[1].peers().get(&at(0)).unwrap().status.unwrap().work, U256::ZERO);
}

/// A peer that serves a body that is not its header's is struck, and
/// the body is taken from another.
#[test]
fn a_wrong_body_is_refused_and_fetched_elsewhere() {
    let chains: Vec<_> = (0..3).map(|_| chain_of(easy())).collect();
    let blocks = grow(&chains[0], 4, 1);
    give(&chains[1], &blocks);
    let mut w = World::with(chains, &small_runs());
    w.nodes[0].spoil = true;
    w.nodes[2].add_peer(at(0), false, 0);
    w.run(5 * SECOND);
    // Its headers were spoiled too, so nothing came of it at all.
    assert_eq!((tip(&w, 2).height, w.best(2).height), (0, 0));
    // Headers from the honest one; bodies asked of both.
    w.nodes[0].spoil = false;
    let now = w.now;
    w.nodes[2].add_peer(at(1), false, now);
    w.run(3 * SECOND);
    assert_eq!(w.best(2).height, 4);
    w.nodes[0].spoil = true;
    w.nodes[0].served.clear();
    w.run(20 * SECOND);
    assert_eq!(tip(&w, 2), tip(&w, 1));
    assert_eq!(w.nodes[2].chain().state().root(), w.nodes[1].chain().state().root());
}

/// A block that breaks a rule is refused, remembered, and held against
/// whoever served it; told of it again, a node does not fetch it again.
#[test]
fn a_block_that_breaks_a_rule_is_refused_once() {
    let mut cfg = small_runs();
    cfg.peers.target = 1;
    let mut w = World::new(2, &cfg);
    w.nodes[1].add_peer(at(0), false, 0);
    w.run(2 * SECOND);
    // Node 0 announces, and serves, a block whose state root is not
    // what its body gives: nothing its own chain would take.
    let bad = next_block(w.nodes[0].chain(), 5, false);
    let header = *BlockRef::from_bytes(&bad).unwrap().header();
    w.nodes[0].foist = Some((header.hash(), bad[HEADER_SIZE..].to_vec()));
    let announce = |w: &mut World| {
        let now = w.now;
        let mut sent = Vec::new();
        w.nodes[0]
            .announce(now, header, (bad.len() - HEADER_SIZE) as u32, None, &mut |to, b| sent.push((to, b.to_vec())));
        for (to, bytes) in sent {
            w.post(at(0), to, &bytes);
        }
    };
    announce(&mut w);
    w.run(SECOND);
    let c = w.nodes[1].counts();
    assert_eq!((c.fetched, c.blocks, c.blocks_refused, tip(&w, 1).height), (1, 0, 1, 0));
    let known = w.nodes[1].chain().known(&header.hash()).unwrap().unwrap();
    assert!(known.invalid());
    // Told again: not fetched again.
    announce(&mut w);
    w.run(SECOND);
    assert_eq!(w.nodes[1].counts().fetched, 1);
    // And a good block after it, from the same peer, is passed over
    // for a while: it has a strike, and failed us.
    let now = w.now;
    assert!(!w.nodes[1].peers().may_ask(&at(0), now));
}

/// Bodies are kept only for the blocks that can be undone. A node says
/// from where it has them, and is asked for nothing below; one too far
/// behind for anyone's bodies has the headers and waits for the state.
#[test]
fn bodies_are_asked_only_of_those_that_hold_them() {
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[0], KEEP + 6, 1);
    let mut w = World::with(chains, &small_runs());
    w.nodes[1].add_peer(at(0), false, 0);
    w.run(20 * SECOND);
    let said = w.nodes[1].peers().get(&at(0)).unwrap().status.unwrap();
    assert_eq!((said.height, said.oldest, said.window), (KEEP as u32 + 6, 7, 6));
    // Every header, no body: the first it needs is the first block's,
    // which nobody holds.
    let c = w.nodes[1].counts();
    assert_eq!((w.best(1).height, tip(&w, 1).height), (KEEP as u32 + 6, 0));
    assert_eq!((c.headers, c.blocks, c.fetches_failed), (KEEP as u64 + 6, 0, 0));
    assert_eq!(c.fetched, 7, "seven runs of headers, and nothing else");
    // What a node is asked for and does not hold, it says it has not.
    let first = w.nodes[0].chain().header_at(1).unwrap().unwrap().hash();
    assert!(w.nodes[0].make(&Object::Block(first)).is_none());
    let seventh = w.nodes[0].chain().header_at(7).unwrap().unwrap().hash();
    assert!(w.nodes[0].make(&Object::Block(seventh)).is_some());
}

// -- The state, in pieces

/// The state as of a block is served in pieces, each checked against
/// the one above it, and the pieces put together are that state: what
/// a joining node does, by hand.
#[test]
fn a_state_is_served_in_pieces_that_check_and_make_it_whole() {
    use crate::net::snapshot::{Manifest, decode_part, decode_roots};
    use crate::store::receive::{Receiving, Target};
    let mut cfg = small_runs();
    // (Nothing fetched but what the test asks for.)
    (cfg.sync.blocks, cfg.peers.target) = (0, 1);
    let chains = vec![chain_of(easy()), chain_of(easy())];
    grow(&chains[0], 20, 1);
    let mut w = World::with(chains, &cfg);
    w.nodes[1].add_peer(at(0), false, 0);
    w.run(3 * SECOND);
    // As of a block some way back, which the headers vouch for.
    let header =
        w.nodes[1].chain().known(&w.nodes[0].chain().header_at(15).unwrap().unwrap().hash()).unwrap().unwrap().header;
    let block = header.hash();
    let fetch = |w: &mut World, object: Object, most: usize| -> Option<Vec<u8>> {
        let now = w.now;
        assert!(w.nodes[1].fetch_object(now, object, at(0), most as u32));
        w.wake[1] = now;
        w.run(SECOND);
        let mut got = w.nodes[1].take_fetched();
        assert_eq!(got.len(), 1);
        let (what, from, bytes) = got.remove(0);
        assert_eq!((what, from), (object, at(0)));
        bytes
    };
    // The manifest, against the header.
    let bytes = fetch(&mut w, Object::Manifest(block), snapshot::MAX_MANIFEST).unwrap();
    let manifest = Manifest::decode(&bytes).unwrap();
    assert!(manifest.check(&header.state_root));
    assert_eq!((manifest.next, manifest.ranges.len(), manifest.name_parts.len()), (15, 1, 0));
    // Each range's roots, against the manifest.
    let mut parts = Vec::new();
    for (range, root) in &manifest.ranges {
        let bytes = fetch(&mut w, Object::Roots { block, index: *range }, snapshot::MAX_ROOTS).unwrap();
        parts.extend(decode_roots(&bytes, *range, root).unwrap());
    }
    assert_eq!(parts.len(), 1);
    // Each part, against its root: the store checks that as it keeps it.
    let target = Target { height: header.height, block, state_root: header.state_root, next: manifest.next };
    let mut receiving = Receiving::open(MemBackend::new(), target, &parts, &manifest.name_parts).unwrap();
    for index in receiving.missing() {
        let bytes = fetch(&mut w, Object::Part { block, index }, snapshot::MAX_PART).unwrap();
        let (outputs, commits) = decode_part(&bytes, index).unwrap();
        assert_eq!(outputs.len(), 15);
        // A part with an output's amount changed is not the part.
        let mut wrong = outputs.clone();
        wrong[3].1.amount += 1;
        assert_eq!(receiving.put_with(index, &wrong, &commits), Err(Error::PartRoot));
        receiving.put_with(index, &outputs, &commits).unwrap();
    }
    let state = receiving.finish(KEEP).unwrap();
    assert_eq!((state.root(), state.tip()), (header.state_root, (15, block)));
    // What there is none of, the peer says it has not: a range and a
    // part that hold nothing, a part of the names, the state as of a
    // block it does not have or that is not on its chain.
    for object in [
        Object::Roots { block, index: 1 },
        Object::Part { block, index: 1 },
        Object::Names { block, index: 0 },
        Object::Manifest([crate::poseidon2::Fp::new(1); 8]),
    ] {
        assert_eq!(fetch(&mut w, object, 1 << 20), None, "{object:?}");
    }
    // And the state as of a block too old to go back to: a node says
    // how far back it can, in its pings.
    let said = w.nodes[1].peers().get(&at(0)).unwrap().status.unwrap();
    assert_eq!((said.window, said.height), (0, 20));
}

/// A state can be handed over as of the blocks a node can still undo,
/// and it says in its pings from which.
#[test]
fn a_state_is_served_as_far_back_as_can_be_undone() {
    let chain = chain_of(easy());
    grow(&chain, KEEP + 9, 1);
    let mut w = World::with(vec![chain], &Config::default());
    let node = &mut w.nodes[0];
    let id = |n: &TestNode, h: u32| n.chain().header_at(h).unwrap().unwrap().hash();
    let said = node.status(&at(1), 0);
    assert_eq!((said.height, said.window, said.oldest), (KEEP as u32 + 9, 9, 10));
    for (height, served) in [(8, false), (9, true), (40, true), (KEEP as u32 + 9, true)] {
        let made = node.make(&Object::Manifest(id(node, height)));
        assert_eq!(made.is_some(), served, "as of {height}");
        if let Some(bytes) = made {
            let header = node.chain().header_at(height).unwrap().unwrap();
            let manifest = snapshot::Manifest::decode(&bytes).unwrap();
            assert!(manifest.check(&header.state_root));
            assert_eq!(manifest.next, height as u64);
        }
    }
    // What is kept to be served is bounded by its bytes, not its count.
    for height in 9..40 {
        node.object(&Object::Manifest(id(node, height))).unwrap();
        node.object(&Object::Part { block: id(node, height), index: 0 }).unwrap();
    }
    assert!(node.served.len() == 62 && node.served.iter().map(|s| s.1.len()).sum::<usize>() <= SERVED_BYTES);
}
