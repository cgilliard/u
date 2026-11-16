//! A node among its peers: what it does with each datagram that
//! arrives, and what it does as time passes.
//!
//! Like the layers under it, [`Node`] touches no socket and reads no
//! clock. It is given the time and each datagram, and hands back the
//! datagrams to send: over a socket ([`super::socket`]), or over the
//! network of its tests, where every datagram's fate is chosen.
//!
//! # Who is listened to
//!
//! A datagram says where it is from, and can lie. So (`docs/WIRE.md`,
//! 1.2):
//!
//! 1. A ping is answered whoever sends it, with a pong of the same
//!    size: answering a forged one sends its victim no more than the
//!    forger spent. Pings of our own to an address that has not proven
//!    itself are rationed, so that forged pings cannot make this node
//!    ping at the forger's pace.
//! 2. A request is answered only if it carries the token this node gave
//!    its address.
//! 3. Anything else is taken only from a peer that has answered one of
//!    our pings.
//!
//! # What is here so far
//!
//! Finding and keeping peers: pings and pongs, "whom else do you know?"
//! and its answer, and "I am going". What a node does about headers,
//! blocks and the state comes on top of this.

use std::net::{IpAddr, SocketAddr, SocketAddrV4};

use super::config::Config;
use super::message::{Message, Status};
use super::peers::Peers;
use super::{MAX_DATAGRAM, VERSION};
use crate::hash::Digest;
use crate::sha256::Sha256;
use crate::transport::Micros;
use crate::transport::token::Tokens;
use crate::u256::U256;

/// What a node says of its own chain, in every ping and pong: the
/// chain's part of a [`Status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ours {
    pub height: u32,
    pub oldest: u32,
    pub window: u32,
    pub tip: Digest,
    pub work: U256,
}

/// What has happened, for whoever watches a node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Datagrams that were no message of this network.
    pub malformed: u64,
    /// Messages not listened to: a request without its token, or
    /// something unasked from an address that has not proven itself.
    pub unheard: u64,
    /// Pings from a node of another version, or of another chain.
    pub strangers: u64,
    /// Datagrams sent.
    pub sent: u64,
}

pub struct Node {
    cfg: Config,
    /// The network's four bytes.
    network: [u8; 4],
    /// Its genesis block's id.
    genesis: Digest,
    peers: Peers,
    tokens: Tokens,
    /// What the tokens' secrets and the pings' numbers are made from.
    secret: [u8; 32],
    /// How many of each have been made.
    secrets: u64,
    numbers: u64,
    /// When the tokens' secret was last replaced.
    rotated: Micros,
    /// Pings to unproven addresses still allowed before the next tick.
    budget: usize,
    /// When a peer was last asked whom else it knows.
    asked: Option<Micros>,
    counts: Counts,
}

/// A datagram to send goes to this.
pub type Out<'a> = &'a mut dyn FnMut(SocketAddrV4, &[u8]);

impl Node {
    /// A node of the network `network`, whose first block is `genesis`,
    /// with these settings. `secret` is from the operating system's
    /// random source: the tokens this node gives and the numbers of its
    /// pings come of it, and nobody is to foretell either.
    pub fn new(cfg: Config, network: [u8; 4], genesis: Digest, secret: [u8; 32], now: Micros) -> Node {
        let seed = u64::from_le_bytes(derive(&secret, b's', 0)[..8].try_into().unwrap());
        Node {
            peers: Peers::new(&cfg, seed),
            budget: cfg.peers.unproven_pings,
            cfg,
            network,
            genesis,
            tokens: Tokens::new(derive(&secret, b't', 0)),
            secret,
            secrets: 0,
            numbers: 0,
            rotated: now,
            asked: None,
            counts: Counts::default(),
        }
    }

    pub fn peers(&self) -> &Peers {
        &self.peers
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// Takes `addr` as an address to try: a seed, a peer given by hand
    /// (both kept whatever they do), or one saved from an earlier run.
    pub fn add_peer(&mut self, addr: SocketAddrV4, seed: bool, now: Micros) -> bool {
        self.peers.add(addr, seed, now).is_ok()
    }

    /// A number for a ping: one nobody can foretell, since a pong that
    /// carries it is taken to show its sender received the ping.
    fn number(secret: &[u8; 32], numbers: &mut u64) -> u64 {
        *numbers += 1;
        u64::from_le_bytes(derive(secret, b'n', *numbers)[..8].try_into().unwrap())
    }

    fn status(&self, to: &SocketAddrV4, nonce: u64, ours: &Ours) -> Status {
        Status {
            nonce,
            version: VERSION,
            token: self.tokens.issue(&SocketAddr::V4(*to)),
            genesis: self.genesis,
            height: ours.height,
            oldest: ours.oldest,
            window: ours.window,
            tip: ours.tip,
            work: ours.work,
        }
    }

    fn send(&mut self, to: SocketAddrV4, message: &Message<'_>, out: Out<'_>) {
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = message.encode(self.network, &mut buf);
        self.counts.sent += 1;
        out(to, &buf[..n]);
    }

    /// Whether a request from `from` carries the token `from` was given.
    fn asked_rightly(&mut self, from: &SocketAddrV4, token: u64) -> bool {
        let ok = self.tokens.check(&SocketAddr::V4(*from), token);
        self.counts.unheard += !ok as u64;
        ok
    }

    /// What passes with time: called every second or so, and at the
    /// start. Pings whoever is due, drops whoever has been silent too
    /// long, looks for more peers while there are too few, and replaces
    /// the tokens' secret when it has had its time.
    pub fn tick(&mut self, now: Micros, ours: &Ours, out: Out<'_>) {
        if now.saturating_sub(self.rotated) >= self.cfg.serve.token_life {
            self.secrets += 1;
            self.tokens.rotate(derive(&self.secret, b't', self.secrets));
            self.rotated = now;
        }
        self.peers.prune(now, |_| {});
        self.budget = self.cfg.peers.unproven_pings;
        let mut due = Vec::new();
        let (secret, numbers) = (&self.secret, &mut self.numbers);
        self.peers.pings_due(now, || Node::number(secret, numbers), |addr, number| due.push((addr, number)));
        for (addr, number) in due {
            let ping = Message::Ping(self.status(&addr, number, ours));
            self.send(addr, &ping, out);
        }
        if self.peers.wants_more(now) && self.asked.is_none_or(|t| now.saturating_sub(t) >= self.cfg.peers.discover) {
            let one = self.peers.sample(None, now).as_slice().first().copied();
            if let Some(addr) = one
                && let Some(token) = self.peers.get(&addr).and_then(|p| p.token())
            {
                self.asked = Some(now);
                self.send(addr, &Message::GetPeers { token }, out);
            }
        }
    }

    /// Takes a datagram that arrived from `from`.
    pub fn handle(&mut self, now: Micros, from: SocketAddr, bytes: &[u8], ours: &Ours, out: Out<'_>) {
        // Addresses of the older kind only (`docs/WIRE.md`, 1.1).
        let from = match from {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
                Some(ip) => SocketAddrV4::new(ip, a.port()),
                None => return,
            },
        };
        let Ok(message) = Message::decode(self.network, bytes) else {
            self.counts.malformed += 1;
            return;
        };
        match message {
            Message::Ping(theirs) => self.on_ping(now, from, theirs, ours, out),
            Message::Pong(theirs) => self.on_pong(now, from, theirs),
            Message::GetPeers { token } => {
                if self.asked_rightly(&from, token) {
                    self.peers.seen(&from, now);
                    let sample = self.peers.sample(Some(from), now);
                    self.send(from, &Message::Peers(sample), out);
                }
            }
            Message::Peers(addrs) => {
                // Unasked, as far as its sender can show: only from a
                // peer, and each is only an address to try.
                if !self.peers.proven(&from) {
                    self.counts.unheard += 1;
                    return;
                }
                self.peers.seen(&from, now);
                for a in addrs.as_slice() {
                    let _ = self.peers.add(*a, false, now);
                }
            }
            Message::Goodbye { token } => {
                if self.asked_rightly(&from, token) {
                    self.peers.gone(&from);
                }
            }
            // What a node does about headers, blocks and the state is
            // not here yet.
            _ => self.counts.unheard += 1,
        }
    }

    fn on_ping(&mut self, now: Micros, from: SocketAddrV4, theirs: Status, ours: &Ours, out: Out<'_>) {
        // Another version, another chain: answered, so that the other
        // side can see why, and nothing more. (It is its pong to a ping
        // of ours, which shows it is there, that drops it.)
        if theirs.version != VERSION || theirs.genesis != self.genesis {
            self.counts.strangers += 1;
            let pong = Message::Pong(self.status(&from, theirs.nonce, ours));
            return self.send(from, &pong, out);
        }
        // Our own ping to this address, come back: the address is ours.
        if self.peers.is_own_ping(&from, theirs.nonce) {
            return self.peers.mark_self(from);
        }
        if self.peers.proven(&from) {
            self.peers.seen(&from, now);
            self.peers.set_status(&from, theirs);
        } else {
            // An address to try, if there is room for it.
            let _ = self.peers.add(from, false, now);
        }
        let pong = Message::Pong(self.status(&from, theirs.nonce, ours));
        self.send(from, &pong, out);
        // And our own ping at once, so that it need not wait its turn
        // to be proven: within what unproven addresses are allowed.
        if self.budget > 0 && !self.peers.proven(&from) {
            let number = Node::number(&self.secret, &mut self.numbers);
            if self.peers.ping_now(&from, number, now) {
                self.budget -= 1;
                let ping = Message::Ping(self.status(&from, number, ours));
                self.send(from, &ping, out);
            }
        }
    }

    fn on_pong(&mut self, now: Micros, from: SocketAddrV4, theirs: Status) {
        // Only the answer to a ping of ours counts for anything.
        if !self.peers.pong(&from, theirs, now) {
            self.counts.unheard += 1;
            return;
        }
        // It is there, and it is no peer of ours.
        if theirs.version != VERSION || theirs.genesis != self.genesis {
            self.counts.strangers += 1;
            self.peers.remove(&from);
        }
    }

    /// "I am going", to every live peer: when a node stops, so that
    /// they need not find it out by its silence.
    pub fn goodbye(&mut self, now: Micros, out: Out<'_>) {
        let mut all = Vec::new();
        all.extend(self.peers.live(now).filter_map(|p| p.token().map(|t| (p.addr, t))));
        for (addr, token) in all {
            self.send(addr, &Message::Goodbye { token }, out);
        }
    }
}

/// Thirty-two bytes from the node's secret, for a purpose and a count:
/// what one such shows tells nothing of another.
fn derive(secret: &[u8; 32], purpose: u8, count: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(&[purpose]);
    h.update(&count.to_le_bytes());
    h.finish()
}

/// The address a datagram is sent to, as the socket wants it.
pub fn socket_addr(addr: SocketAddrV4) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(*addr.ip()), addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::message::Addrs;
    use crate::poseidon2::Fp;
    use crate::test_util::Rng;
    use crate::transport::{MILLI, SECOND};
    use std::net::Ipv4Addr;

    const NET: [u8; 4] = *b"TEST";
    const GENESIS: Digest = [Fp::new(9); 8];

    fn ours(height: u32) -> Ours {
        Ours {
            height,
            oldest: 0,
            window: height.saturating_sub(10),
            tip: [Fp::new(height); 8],
            work: U256::from_u64(height as u64),
        }
    }

    /// The address of node `n`: each a host and a network of its own.
    fn at(n: usize) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(20 + (n / 200) as u8, (n % 200) as u8, 0, 1), 3737)
    }

    /// Nodes and the datagrams between them: every one takes twenty
    /// milliseconds, some are lost, and one sent to an address that is
    /// no node's is kept to be looked at.
    struct World {
        nodes: Vec<Node>,
        heights: Vec<u32>,
        now: Micros,
        flying: Vec<(Micros, SocketAddrV4, SocketAddrV4, Vec<u8>)>,
        /// Lost, in a thousand.
        loss: u64,
        rng: Rng,
        /// To addresses that are no node's: from, to, what.
        strays: Vec<(SocketAddrV4, SocketAddrV4, Vec<u8>)>,
        ticks: u64,
    }

    impl World {
        fn new(n: usize, cfg: &Config) -> World {
            let nodes = (0..n).map(|i| Node::new(cfg.clone(), NET, GENESIS, [i as u8 + 1; 32], 0)).collect();
            World {
                nodes,
                heights: (0..n as u32).map(|i| 100 + i).collect(),
                now: 0,
                flying: Vec::new(),
                loss: 0,
                rng: Rng::new(5),
                strays: Vec::new(),
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

        /// Ten milliseconds at a time for `time`: what has arrived is
        /// handed over, and every second each node is told the time.
        fn run(&mut self, time: Micros) {
            let end = self.now + time;
            while self.now < end {
                let mut sent = Vec::new();
                if self.now.is_multiple_of(SECOND) {
                    self.ticks += 1;
                    for (i, node) in self.nodes.iter_mut().enumerate() {
                        node.tick(self.now, &ours(self.heights[i]), &mut |to, b| sent.push((at(i), to, b.to_vec())));
                    }
                }
                let (due, later): (Vec<_>, Vec<_>) = self.flying.drain(..).partition(|d| d.0 <= self.now);
                self.flying = later;
                for (_, from, to, bytes) in due {
                    match (0..self.nodes.len()).find(|&i| at(i) == to) {
                        Some(i) => self.nodes[i].handle(
                            self.now,
                            SocketAddr::V4(from),
                            &bytes,
                            &ours(self.heights[i]),
                            &mut |to, b| sent.push((at(i), to, b.to_vec())),
                        ),
                        None => self.strays.push((from, to, bytes)),
                    }
                }
                for (from, to, bytes) in sent {
                    self.post(from, to, &bytes);
                }
                self.now += 10 * MILLI;
            }
        }

        fn live(&self, i: usize) -> Vec<SocketAddrV4> {
            self.nodes[i].peers().live(self.now).map(|p| p.addr).collect()
        }
    }

    #[test]
    fn two_nodes_that_one_knows_of_come_to_know_each_other() {
        let mut w = World::new(2, &Config::default());
        assert!(w.nodes[0].add_peer(at(1), true, 0));
        w.run(SECOND);
        assert_eq!((w.live(0), w.live(1)), (vec![at(1)], vec![at(0)]));
        // Each holds what the other says of itself, and the token the
        // other gave it; and each has timed the other.
        let (a, b) = (*w.nodes[0].peers().get(&at(1)).unwrap(), *w.nodes[1].peers().get(&at(0)).unwrap());
        assert_eq!((a.status.unwrap().height, b.status.unwrap().height), (101, 100));
        assert_eq!(a.status.unwrap().tip, ours(101).tip);
        assert!(w.nodes[1].tokens.check(&SocketAddr::V4(at(0)), a.token().unwrap()));
        assert!(w.nodes[0].tokens.check(&SocketAddr::V4(at(1)), b.token().unwrap()));
        assert_eq!((a.path.round_trip(), b.path.round_trip()), (Some(40 * MILLI), Some(40 * MILLI)));
        // Four datagrams did it: a ping and its pong, each way.
        assert_eq!(w.nodes[0].counts().sent + w.nodes[1].counts().sent, 4);
        // And each goes on hearing of the other's chain.
        w.heights[1] = 500;
        w.run(31 * SECOND);
        assert_eq!(w.nodes[0].peers().get(&at(1)).unwrap().status.unwrap().height, 500);
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
            // Having what they want, they ask no more, and only ping:
            // a ping and a pong to each peer every thirty seconds.
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
        w.run(10 * MILLI);
        let forged = |n: u16| SocketAddrV4::new(Ipv4Addr::new(99, (n / 4) as u8, 0, (n % 4) as u8 + 1), 1000 + n);
        let status = |nonce| Status {
            nonce,
            version: VERSION,
            token: 0,
            genesis: GENESIS,
            height: 1,
            oldest: 0,
            window: 0,
            tip: GENESIS,
            work: U256::ZERO,
        };
        // A hundred pings in one tick, each claiming another address.
        for n in 0..100 {
            w.inject(forged(n), 0, &Message::Ping(status(n as u64)));
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
        // The same address again and again gets pongs, and no second
        // ping until its turn.
        w.strays.clear();
        for _ in 0..50 {
            w.inject(forged(0), 0, &Message::Ping(status(7)));
        }
        w.run(400 * MILLI);
        assert_eq!(w.strays.len(), 50);
        // None of them is anyone: none is live, none is told of, and
        // in three minutes all are gone.
        assert!(w.live(0).is_empty() && w.nodes[0].peers.sample(None, w.now).as_slice().is_empty());
        // (Three minutes from when each was first pinged, and the last
        // of the hundred had its first ping some seconds in.)
        w.run(200 * SECOND);
        assert_eq!(w.nodes[0].peers().len(), 0);
        // In all that time our pings to them were rationed: eight
        // addresses a tick at the most.
        let pings =
            w.strays.iter().filter(|s| matches!(Message::decode(NET, &s.2), Ok(Message::Ping(_)))).count() as u64;
        assert!(pings <= 8 * w.ticks, "{pings}");
    }

    #[test]
    fn a_pong_that_answers_no_ping_of_ours_proves_nothing() {
        let mut w = World::new(2, &Config::default());
        w.nodes[0].add_peer(at(1), false, 0);
        // Before node 0 has pinged at all, and with a number it never
        // sent after it has.
        let status = Status {
            nonce: 1,
            version: VERSION,
            token: 5,
            genesis: GENESIS,
            height: 1 << 30,
            oldest: 0,
            window: 0,
            tip: GENESIS,
            work: U256::MAX,
        };
        w.inject(at(1), 0, &Message::Pong(status));
        w.run(10 * MILLI);
        assert!(!w.nodes[0].peers().proven(&at(1)));
        assert_eq!(w.nodes[0].counts().unheard, 1);
        // Nor does anything else from an address not proven count:
        // a list of peers to try is not taken.
        let mut addrs = Addrs::new();
        addrs.push(at(7));
        w.inject(at(5), 0, &Message::Peers(addrs));
        w.run(10 * MILLI);
        assert!(w.nodes[0].peers().get(&at(7)).is_none());
        assert_eq!(w.nodes[0].counts().unheard, 2);
    }

    #[test]
    fn a_request_is_answered_only_with_its_token() {
        let mut cfg = Config::default();
        // (Content with one peer, so that nothing is sent here but
        // pings and what the test sends.)
        (cfg.serve.token_life, cfg.peers.target) = (60 * SECOND, 1);
        let mut w = World::new(3, &cfg);
        w.nodes[0].add_peer(at(1), false, 0);
        w.nodes[0].add_peer(at(2), false, 0);
        w.run(SECOND);
        let token = w.nodes[0].peers().get(&at(1)).unwrap().token().unwrap();
        let answers = |w: &World| w.nodes[1].counts().sent;
        // The token node 1 gave node 0: answered, with whom node 1
        // knows other than the asker.
        let before = answers(&w);
        w.inject(at(0), 1, &Message::GetPeers { token });
        w.run(50 * MILLI);
        assert_eq!(answers(&w), before + 1);
        // Without it, with another's, or from another address: nothing.
        let other = w.nodes[0].peers().get(&at(2)).unwrap().token().unwrap();
        for (from, t) in [(at(0), 0), (at(0), other), (at(0), token ^ 1), (at(9), token)] {
            w.inject(from, 1, &Message::GetPeers { token: t });
            w.inject(from, 1, &Message::Goodbye { token: t });
        }
        w.run(50 * MILLI);
        assert_eq!(answers(&w), before + 1);
        assert_eq!(w.nodes[1].counts().unheard, 8);
        assert!(w.nodes[1].peers().proven(&at(0)));
        // A token lasts one change of the secret, and not two: an old
        // one kept and used long after is refused. (Pings carry the new
        // one every half minute, so a peer's is never old.)
        w.run(60 * SECOND);
        w.inject(at(0), 1, &Message::GetPeers { token });
        w.run(50 * MILLI);
        assert_eq!(w.nodes[1].counts().unheard, 8, "heard, the secret having changed once");
        w.run(70 * SECOND);
        let unheard = w.nodes[1].counts().unheard;
        w.inject(at(0), 1, &Message::GetPeers { token });
        w.run(50 * MILLI);
        assert_eq!(w.nodes[1].counts().unheard, unheard + 1);
        // While the one its pings have brought since is good.
        let fresh = w.nodes[0].peers().get(&at(1)).unwrap().token().unwrap();
        assert_ne!(fresh, token);
        w.inject(at(0), 1, &Message::GetPeers { token: fresh });
        w.run(50 * MILLI);
        assert_eq!(w.nodes[1].counts().unheard, unheard + 1);
    }

    #[test]
    fn a_node_of_another_chain_or_version_is_answered_and_left_alone() {
        let mut w = World::new(2, &Config::default());
        // Node 1 is of another chain.
        w.nodes[1] = Node::new(Config::default(), NET, [Fp::new(8); 8], [2; 32], 0);
        w.nodes[0].add_peer(at(1), false, 0);
        w.run(SECOND);
        // Each answered the other, and neither keeps the other.
        assert_eq!((w.nodes[0].peers().len(), w.nodes[1].peers().len()), (0, 0));
        assert!(w.nodes[0].counts().strangers >= 1 && w.nodes[1].counts().strangers >= 1);
        // A ping of another version: a pong, and nothing kept.
        let stranger = SocketAddrV4::new(Ipv4Addr::new(77, 1, 1, 1), 9);
        let status = Status {
            nonce: 3,
            version: VERSION + 1,
            token: 0,
            genesis: GENESIS,
            height: 1,
            oldest: 0,
            window: 0,
            tip: GENESIS,
            work: U256::ZERO,
        };
        w.inject(stranger, 0, &Message::Ping(status));
        w.run(100 * MILLI);
        assert_eq!(w.strays.len(), 1);
        assert!(
            matches!(Message::decode(NET, &w.strays[0].2), Ok(Message::Pong(s)) if s.nonce == 3 && s.version == VERSION)
        );
        assert_eq!(w.nodes[0].peers().len(), 0);
        // A datagram of another network, and one that is nothing: not
        // answered at all.
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = Message::Ping(Status { version: VERSION, ..status }).encode(*b"ELSE", &mut buf);
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
        assert!(w.nodes[0].peers().get(&at(0)).is_none() && !w.nodes[0].add_peer(at(0), false, w.now));
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
        // Node 0 stops: its datagrams are no longer handed to it. (Here
        // it goes on running; what matters is what the others think.)
        w.run(30 * MILLI);
        assert!(w.live(1).is_empty() && w.live(2).is_empty());
        // Its place is kept, and when it answers a ping again it is back.
        assert!(w.nodes[1].peers().get(&at(0)).is_some());
        w.run(31 * SECOND);
        assert_eq!(w.live(1), [at(0)]);
    }

    /// Six nodes on this machine's own sockets and clock, five of them
    /// knowing only the first: all come to know all.
    #[test]
    fn over_real_sockets() {
        use std::net::UdpSocket;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        let mut cfg = Config::default();
        (cfg.peers.target, cfg.peers.discover) = (5, 100 * MILLI);
        let sockets: Vec<UdpSocket> = (0..6).map(|_| UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        let addrs: Vec<SocketAddrV4> = sockets
            .iter()
            .map(|s| match s.local_addr().unwrap() {
                SocketAddr::V4(a) => a,
                _ => unreachable!(),
            })
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let live: Vec<Arc<AtomicUsize>> = (0..6).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let threads: Vec<_> = sockets
            .into_iter()
            .enumerate()
            .map(|(i, socket)| {
                let (cfg, stop, live, seed) = (cfg.clone(), Arc::clone(&stop), Arc::clone(&live[i]), addrs[0]);
                std::thread::spawn(move || {
                    let mut node = Node::new(cfg, NET, GENESIS, [i as u8 + 1; 32], 0);
                    if i != 0 {
                        node.add_peer(seed, true, 0);
                    }
                    // In short runs, so that what the node holds can be
                    // looked at between them.
                    let clock = Instant::now();
                    while !stop.load(Ordering::Relaxed) {
                        let pause = AtomicBool::new(false);
                        std::thread::scope(|s| {
                            s.spawn(|| {
                                std::thread::sleep(Duration::from_millis(100));
                                pause.store(true, Ordering::Relaxed);
                            });
                            crate::net::socket::run_until(
                                &mut node,
                                &socket,
                                &|| ours(100 + i as u32),
                                &pause,
                                Duration::from_millis(50),
                                clock,
                            )
                            .unwrap();
                        });
                        live.store(node.peers().live(clock.elapsed().as_micros() as Micros).count(), Ordering::Relaxed);
                    }
                })
            })
            .collect();
        let start = Instant::now();
        while live.iter().any(|l| l.load(Ordering::Relaxed) < 5) {
            assert!(start.elapsed() < Duration::from_secs(30), "{:?}", live);
            std::thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::Relaxed);
        for t in threads {
            t.join().unwrap();
        }
    }
}
