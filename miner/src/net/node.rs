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
//!    our pings, and a chunk only for a fetch of ours, by its number.
//!
//! # Headers
//!
//! Every peer says in its pings how much work its chain has. While a
//! live peer claims more than the best header here, its headers are
//! fetched:
//!
//! 1. The peer is asked which of our blocks is the newest on its chain
//!    ([`Message::FindFork`]): from there its chain is news to us.
//! 2. From there to its tip, its headers are fetched as objects of up
//!    to [`super::config::Sync::headers`] each, several at once, each
//!    from another peer whose chain reaches that far. Every one is
//!    named with the tip aimed at, so that all are of one chain.
//! 3. They are checked and kept in order ([`Chain::accept_headers`]).
//!    A peer whose headers are refused takes a strike.
//!
//! A peer that claims work and does not answer for it within
//! [`super::config::Sync::header_wait`] is passed over for a while, so
//! that a false claim cannot hold a node up.
//!
//! # What is here so far
//!
//! Finding and keeping peers, and headers. Bodies and the state come
//! on top of this.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;

use super::config::Config;
use super::message::{Locator, Message, Status};
use super::object::{MAX_NAME, Object};
use super::peers::Peers;
use super::{MAX_DATAGRAM, VERSION};
use crate::block::{HEADER_SIZE, Header};
use crate::chain::Chain;
use crate::chain::headers::LOCATOR;
use crate::hash::Digest;
use crate::sha256::Sha256;
use crate::store::backend::Backend;
use crate::transport::fetch::{Fetch, Poll, Why};
use crate::transport::serve::{Next, Serve};
use crate::transport::token::Tokens;
use crate::transport::wire::{Chunk, Get, Gone, Ranges};
use crate::transport::{Micros, chunk_of};
use crate::u256::U256;

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
    /// Times a peer was asked where its chain leaves ours.
    pub forks_asked: u64,
    /// Objects fetched whole, and fetches given up.
    pub fetched: u64,
    pub fetches_failed: u64,
    /// Headers kept that were new.
    pub headers: u64,
}

/// Objects made to be served, kept while they are being asked for.
const SERVED: usize = 16;
/// Chunks sent in one go before the node looks to what else there is.
const SERVE_BATCH: usize = 256;

/// An object being fetched.
struct Fetching {
    object: Object,
    from: SocketAddrV4,
    fetch: Fetch,
}

/// The chain being caught up with: a tip some peer has, and its headers
/// from where its chain leaves ours.
struct Aim {
    /// The tip, and its height.
    tip: Digest,
    height: u32,
    /// The first heights of the runs of headers not yet asked for.
    todo: BTreeSet<u32>,
    /// Runs fetched and waiting for those before them: by first height,
    /// with who served each.
    done: BTreeMap<u32, (Vec<Header>, SocketAddrV4)>,
    /// The first height not yet kept.
    next: u32,
}

pub struct Node<B: Backend + 'static, V> {
    cfg: Config,
    /// The network's four bytes.
    network: [u8; 4],
    /// Its genesis block's id.
    genesis: Digest,
    chain: Arc<Chain<B, V>>,
    peers: Peers,
    tokens: Tokens,
    /// What the tokens' secrets, the pings' numbers and the fetches'
    /// are made from.
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
    /// The time by the calendar, in seconds: what a header's time is
    /// held against.
    unix: u64,
    /// When what passes with time is next looked to.
    due: Micros,
    serve: Serve,
    /// Objects lately made to be served, the latest first.
    served: VecDeque<(Object, Arc<Vec<u8>>)>,
    fetches: Vec<Fetching>,
    /// The peer asked where its chain leaves ours, and when.
    probe: Option<(SocketAddrV4, Micros)>,
    aim: Option<Aim>,
    counts: Counts,
    /// Tests: a chain's work claimed that is not there; objects served
    /// with a byte wrong.
    #[cfg(test)]
    pub(crate) boast: Option<U256>,
    #[cfg(test)]
    pub(crate) spoil: bool,
}

/// A datagram to send goes to this.
pub type Out<'a> = &'a mut dyn FnMut(SocketAddrV4, &[u8]);

impl<B: Backend + 'static, V: Sync> Node<B, V> {
    /// A node of the network `network` keeping `chain`, with these
    /// settings. `secret` is from the operating system's random source:
    /// the tokens this node gives, the numbers of its pings and those
    /// of its fetches come of it, and nobody is to foretell any.
    pub fn new(cfg: Config, network: [u8; 4], chain: Arc<Chain<B, V>>, secret: [u8; 32], now: Micros) -> Node<B, V> {
        let seed = u64::from_le_bytes(derive(&secret, b's', 0)[..8].try_into().unwrap());
        Node {
            peers: Peers::new(&cfg, seed),
            budget: cfg.peers.unproven_pings,
            serve: Serve::with(cfg.serve.limits()),
            cfg,
            network,
            genesis: chain.params().genesis().header.hash(),
            chain,
            tokens: Tokens::new(derive(&secret, b't', 0)),
            secret,
            secrets: 0,
            numbers: 0,
            rotated: now,
            asked: None,
            unix: 0,
            due: now,
            served: VecDeque::new(),
            fetches: Vec::new(),
            probe: None,
            aim: None,
            counts: Counts::default(),
            #[cfg(test)]
            boast: None,
            #[cfg(test)]
            spoil: false,
        }
    }

    pub fn peers(&self) -> &Peers {
        &self.peers
    }

    pub fn chain(&self) -> &Arc<Chain<B, V>> {
        &self.chain
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// Objects being fetched now.
    pub fn fetching(&self) -> usize {
        self.fetches.len()
    }

    /// Takes `addr` as an address to try: a seed, a peer given by hand
    /// (both kept whatever they do), or one saved from an earlier run.
    pub fn add_peer(&mut self, addr: SocketAddrV4, seed: bool, now: Micros) -> bool {
        self.peers.add(addr, seed, now).is_ok()
    }

    /// A number nobody can foretell: for a ping, since a pong that
    /// carries it is taken to show its sender received the ping; for a
    /// fetch, since a chunk that carries it is taken to be its answer.
    fn number(secret: &[u8; 32], numbers: &mut u64) -> u64 {
        *numbers += 1;
        u64::from_le_bytes(derive(secret, b'n', *numbers)[..8].try_into().unwrap())
    }

    /// What this node says of itself to `to`, answering or asking with
    /// `nonce`.
    fn status(&self, to: &SocketAddrV4, nonce: u64) -> Status {
        // A store that cannot be read says the least there is to say.
        let tip = self.chain.tip().unwrap_or_else(|_| self.chain.params().genesis().header);
        let work = self.chain.tip_work().unwrap_or(U256::ZERO);
        #[cfg(test)]
        let work = self.boast.unwrap_or(work);
        Status {
            nonce,
            version: VERSION,
            token: self.tokens.issue(&SocketAddr::V4(*to)),
            genesis: self.genesis,
            height: tip.height,
            oldest: 0,
            window: tip.height.saturating_sub(self.chain.keep() as u32),
            tip: tip.hash(),
            work,
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

    /// Looks to everything that is due at `now`, and says when to be
    /// called again at the latest: sooner if a datagram arrives.
    /// `unix` is the time by the calendar, in seconds.
    ///
    /// Every [`Config::tick`]: pings whoever is due, drops whoever has
    /// been silent too long, looks for more peers while there are too
    /// few, replaces the tokens' secret when it has had its time, and
    /// sees whether there are headers to catch up with. Every call:
    /// what the fetches under way and the chunks being served want
    /// done.
    pub fn tick(&mut self, now: Micros, unix: u64, out: Out<'_>) -> Micros {
        self.unix = unix;
        if now >= self.due {
            self.due = now + self.cfg.tick;
            self.periodic(now, out);
        }
        self.pump(now, out).min(self.due)
    }

    fn periodic(&mut self, now: Micros, out: Out<'_>) {
        if now.saturating_sub(self.rotated) >= self.cfg.serve.token_life {
            self.secrets += 1;
            self.tokens.rotate(derive(&self.secret, b't', self.secrets));
            self.rotated = now;
        }
        self.peers.prune(now, |_| {});
        self.budget = self.cfg.peers.unproven_pings;
        let mut due = Vec::new();
        let (secret, numbers) = (&self.secret, &mut self.numbers);
        self.peers.pings_due(now, || Self::number(secret, numbers), |addr, number| due.push((addr, number)));
        for (addr, number) in due {
            let ping = Message::Ping(self.status(&addr, number));
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
        self.sync_headers(now, out);
    }

    /// Takes a datagram that arrived from `from`. Call [`Node::tick`]
    /// after it.
    pub fn handle(&mut self, now: Micros, from: SocketAddr, bytes: &[u8], out: Out<'_>) {
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
            Message::Ping(theirs) => self.on_ping(now, from, theirs, out),
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
            Message::FindFork { token, locator } => {
                if self.asked_rightly(&from, token) {
                    self.peers.seen(&from, now);
                    let (height, id) = self.newest_of_ours(&locator);
                    self.send(from, &Message::Fork { height, id }, out);
                }
            }
            Message::Fork { height, id } => self.on_fork(now, from, height, id),
            Message::Get(get) => self.on_get(now, from, &get),
            Message::Chunk(chunk) => self.on_chunk(now, from, &chunk),
            Message::Gone(gone) => {
                match self.fetches.iter_mut().find(|f| f.from == from && f.fetch.transfer() == gone.transfer) {
                    Some(f) => f.fetch.gone(),
                    None => self.counts.unheard += 1,
                }
            }
            // Blocks, transactions and aux leaves are not here yet.
            _ => self.counts.unheard += 1,
        }
    }

    fn on_ping(&mut self, now: Micros, from: SocketAddrV4, theirs: Status, out: Out<'_>) {
        // Another version, another chain: answered, so that the other
        // side can see why, and nothing more. (It is its pong to a ping
        // of ours, which shows it is there, that drops it.)
        if theirs.version != VERSION || theirs.genesis != self.genesis {
            self.counts.strangers += 1;
            let pong = Message::Pong(self.status(&from, theirs.nonce));
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
        let pong = Message::Pong(self.status(&from, theirs.nonce));
        self.send(from, &pong, out);
        // And our own ping at once, so that it need not wait its turn
        // to be proven: within what unproven addresses are allowed.
        if self.budget > 0 && !self.peers.proven(&from) {
            let number = Self::number(&self.secret, &mut self.numbers);
            if self.peers.ping_now(&from, number, now) {
                self.budget -= 1;
                let ping = Message::Ping(self.status(&from, number));
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

    // -- Headers

    /// The header of the block `id`, if it is on the chain here.
    fn on_chain(&self, id: &Digest) -> Option<Header> {
        let known = self.chain.known(id).ok()??;
        (self.chain.header_at(known.header.height).ok()? == Some(known.header)).then_some(known.header)
    }

    /// The newest block of `locator` that is on the chain here: the
    /// first block of all, if none is.
    fn newest_of_ours(&self, locator: &Locator) -> (u32, Digest) {
        locator.as_slice().iter().find_map(|id| self.on_chain(id).map(|h| (h.height, *id))).unwrap_or((0, self.genesis))
    }

    /// Whether there are headers to catch up with, and the next step
    /// towards them.
    fn sync_headers(&mut self, now: Micros, out: Out<'_>) {
        let Ok(best) = self.chain.best_header() else {
            return;
        };
        // Those that claimed work and have sent nothing for it.
        self.peers.doubt_silent_claimants(best.work, now, |_| {});
        if let Some((addr, _)) = self.probe
            && !self.peers.may_ask(&addr, now)
        {
            self.probe = None;
        }
        if self.aim.is_some() {
            return self.fetch_headers(now);
        }
        if self.probe.is_some_and(|(_, at)| now.saturating_sub(at) < self.cfg.sync.header_spacing) {
            return;
        }
        // Ask whoever claims most where its chain leaves ours.
        let next = self.chain.tip().map_or(0, |t| t.height + 1);
        let Some(source) = self.peers.best_source(best.work, next, now) else {
            return;
        };
        let (addr, Some(token)) = (source.addr, source.token()) else {
            return;
        };
        let mut ids = [self.genesis; LOCATOR];
        let Ok(n) = self.chain.header_locator(&mut ids) else {
            return;
        };
        let Some(locator) = Locator::new(&ids[..n]) else {
            return;
        };
        self.probe = Some((addr, now));
        self.peers.asked_headers(&addr, now);
        self.counts.forks_asked += 1;
        self.send(addr, &Message::FindFork { token, locator }, out);
    }

    fn on_fork(&mut self, now: Micros, from: SocketAddrV4, height: u32, id: Digest) {
        // Only the answer to our question, from whom it was put to.
        if self.probe.map(|p| p.0) != Some(from) || !self.peers.proven(&from) {
            self.counts.unheard += 1;
            return;
        }
        self.probe = None;
        self.peers.seen(&from, now);
        // A block we hold, at the height it says: or it is no answer.
        let ours = self.chain.known(&id).ok().flatten();
        if ours.is_none_or(|k| k.header.height != height) {
            self.peers.strike(&from, now);
            return;
        }
        let Some(status) = self.peers.get(&from).and_then(|p| p.status) else {
            return;
        };
        if status.height <= height {
            // Nothing past what we share: its claim was of nothing.
            self.peers.failed(&from, now);
            return;
        }
        let run = self.cfg.sync.headers as u32;
        self.aim = Some(Aim {
            tip: status.tip,
            height: status.height,
            todo: (height + 1..=status.height).step_by(run as usize).collect(),
            done: BTreeMap::new(),
            next: height + 1,
        });
        self.fetch_headers(now);
    }

    /// Asks for the runs of headers not yet asked for, as many at once
    /// as may be, each of another peer.
    fn fetch_headers(&mut self, now: Micros) {
        let Some(aim) = self.aim.as_mut() else {
            return;
        };
        let (most, run) = (self.cfg.sync.header_fetches, self.cfg.sync.headers as u32);
        // No further ahead of what is kept than can wait in memory.
        let ahead = aim.next.saturating_add(2 * most as u32 * run);
        loop {
            let busy = self.fetches.iter().filter(|f| matches!(f.object, Object::Headers { .. })).count();
            let Some(&from) = aim.todo.iter().next().filter(|h| **h < ahead && busy < most) else {
                break;
            };
            let count = run.min(aim.height - from + 1) as u16;
            // A peer whose chain reaches the tip aimed at, and that is
            // not at a run of headers for us already.
            let free = self
                .peers
                .reaching(aim.height, now)
                .find(|p| !self.fetches.iter().any(|f| f.from == p.addr && matches!(f.object, Object::Headers { .. })));
            let Some(peer) = free else {
                break;
            };
            aim.todo.remove(&from);
            let transfer = Self::number(&self.secret, &mut self.numbers);
            let len = count as u32 * HEADER_SIZE as u32;
            self.fetches.push(Fetching {
                object: Object::Headers { from, count, on: aim.tip },
                from: peer.addr,
                fetch: Fetch::new(transfer, Some(len), len, peer.path, now),
            });
        }
        // Nothing under way, and nobody to ask: the aim is let go, and
        // another is taken from whoever claims most then.
        if !self.fetches.iter().any(|f| matches!(f.object, Object::Headers { .. })) && !aim.todo.is_empty() {
            self.aim = None;
        }
    }

    /// A run of headers has arrived whole from `from`.
    fn headers_arrived(&mut self, now: Micros, from: SocketAddrV4, first: u32, bytes: &[u8]) {
        let Some(aim) = self.aim.as_mut() else {
            return;
        };
        // Headers, of the heights asked for, each the child of the one
        // before: or its sender made them up.
        let mut headers = Vec::with_capacity(bytes.len() / HEADER_SIZE);
        for (k, b) in bytes.chunks(HEADER_SIZE).enumerate() {
            match Header::from_bytes(b) {
                Ok(h)
                    if h.height == first + k as u32
                        && headers.last().is_none_or(|p: &Header| h.prev_hash == p.hash()) =>
                {
                    headers.push(h)
                }
                _ => return self.headers_refused(now, from),
            }
        }
        aim.done.insert(first, (headers, from));
        // Kept in order, as far as they join up.
        while let Some((headers, from)) = aim.done.remove(&aim.next) {
            let (new, error) = self.chain.accept_headers(&headers, self.unix, false);
            self.counts.headers += new as u64;
            if error.is_some() {
                return self.headers_refused(now, from);
            }
            self.peers.headers_arrived(&from);
            aim.next += headers.len() as u32;
            // The last of them is the tip that was aimed at, or the
            // peers that served them are of two minds.
            if aim.next > aim.height {
                if headers.last().map(|h| h.hash()) != Some(aim.tip) {
                    return self.headers_refused(now, from);
                }
                self.aim = None;
                return;
            }
        }
        self.fetch_headers(now);
    }

    /// `from` served headers that are not what was asked for, or that
    /// the chain refuses: a strike, and the aim is let go. What was
    /// kept stays kept.
    fn headers_refused(&mut self, now: Micros, from: SocketAddrV4) {
        self.peers.strike(&from, now);
        self.peers.failed(&from, now);
        self.aim = None;
        self.fetches.retain(|f| !matches!(f.object, Object::Headers { .. }));
    }

    // -- Objects

    fn on_get(&mut self, now: Micros, from: SocketAddrV4, get: &Get<'_>) {
        // A name of nothing is asked for by nobody honest.
        if Object::decode(get.name).is_err() {
            self.counts.malformed += 1;
            return;
        }
        match self.serve.get(&self.tokens, SocketAddr::V4(from), get) {
            Ok(()) => self.peers.seen(&from, now),
            // Without its token, or more than may wait: not heard.
            Err(_) => self.counts.unheard += 1,
        }
    }

    fn on_chunk(&mut self, now: Micros, from: SocketAddrV4, chunk: &Chunk<'_>) {
        // For a fetch of ours, from whom it was asked of, by its number.
        let Some(f) = self.fetches.iter_mut().find(|f| f.from == from && f.fetch.transfer() == chunk.transfer) else {
            self.counts.unheard += 1;
            return;
        };
        self.peers.seen(&from, now);
        // (A chunk no honest peer sends ends the fetch, and the fetch
        // says so when it is next looked to.)
        let _ = f.fetch.chunk(now, chunk);
    }

    /// The bytes of the object named, if this node has it. Kept a
    /// while, since every chunk of it is asked for by name.
    fn object(&mut self, object: &Object) -> Option<Arc<Vec<u8>>> {
        if let Some(at) = self.served.iter().position(|(o, _)| o == object) {
            let hit = self.served.remove(at).expect("it is there");
            self.served.push_front(hit);
            return Some(Arc::clone(&self.served[0].1));
        }
        let bytes = self.make(object)?;
        #[cfg(test)]
        let bytes = if self.spoil {
            let mut b = bytes;
            let at = b.len() / 2;
            b[at] ^= 1;
            b
        } else {
            bytes
        };
        self.served.push_front((*object, Arc::new(bytes)));
        self.served.truncate(SERVED);
        Some(Arc::clone(&self.served[0].1))
    }

    fn make(&self, object: &Object) -> Option<Vec<u8>> {
        match *object {
            Object::Headers { from, count, on } => {
                // Of the chain `on` is on, and no higher than it: so
                // that the name is of the same bytes whoever serves it.
                let top = self.on_chain(&on)?;
                if from.checked_add(count as u32 - 1)? > top.height {
                    return None;
                }
                let mut headers = vec![top; count as usize];
                if self.chain.headers_from(from, &mut headers).ok()? != count as usize {
                    return None;
                }
                let mut bytes = Vec::with_capacity(count as usize * HEADER_SIZE);
                headers.iter().for_each(|h| bytes.extend_from_slice(&h.to_bytes()));
                Some(bytes)
            }
            // Bodies and the state are not served yet.
            _ => None,
        }
    }

    /// Does what the fetches under way and the chunks being served want
    /// done at `now`, and says when either next wants doing.
    fn pump(&mut self, now: Micros, out: Out<'_>) -> Micros {
        let mut wake = Micros::MAX;
        let mut ranges = Ranges::new();
        let mut name = [0u8; MAX_NAME];
        let mut i = 0;
        while i < self.fetches.len() {
            let (object, from) = (self.fetches[i].object, self.fetches[i].from);
            match self.fetches[i].fetch.poll(now, &mut ranges) {
                Poll::Ask(seq) => {
                    // Asked with the token the peer gave us: one that has
                    // given none, or is gone, is not asked.
                    let Some(token) = self.peers.get(&from).and_then(|p| p.token()) else {
                        self.fetches.swap_remove(i);
                        self.fetch_failed(now, object, from);
                        continue;
                    };
                    let n = object.encode(&mut name);
                    let transfer = self.fetches[i].fetch.transfer();
                    let get = Get { token, transfer, seq, name: &name[..n], ranges };
                    self.send(from, &Message::Get(get), out);
                    // (Again at once: there may be more to ask.)
                    continue;
                }
                Poll::Wait(at) => wake = wake.min(at),
                Poll::Done => {
                    let done = self.fetches.swap_remove(i);
                    self.counts.fetched += 1;
                    self.peers.delivered(&from, done.fetch.path());
                    let bytes = done.fetch.finish().expect("it is done");
                    self.arrived(now, object, from, &bytes);
                    continue;
                }
                Poll::Failed(why) => {
                    let failed = self.fetches.swap_remove(i);
                    self.peers.set_path(&from, failed.fetch.path());
                    if why == Why::Bad {
                        self.peers.strike(&from, now);
                    }
                    self.fetch_failed(now, object, from);
                    continue;
                }
            }
            i += 1;
        }
        // The chunks asked of us: some, and then back to the rest.
        for _ in 0..SERVE_BATCH {
            match self.serve.next(now) {
                Next::Send(x) => {
                    let SocketAddr::V4(to) = x.to else { continue };
                    let bytes = Object::decode(x.name()).ok().and_then(|o| self.object(&o));
                    match bytes.as_deref().and_then(|b| chunk_of(b, x.index).map(|data| (b.len() as u32, data))) {
                        Some((len, data)) => {
                            let chunk = Chunk { transfer: x.transfer, seq: x.seq, len, index: x.index, data };
                            self.send(to, &Message::Chunk(chunk), out);
                        }
                        // No such object, or no such chunk of it.
                        None => {
                            self.serve.cancel(x.to, x.transfer);
                            self.send(to, &Message::Gone(Gone { transfer: x.transfer }), out);
                        }
                    }
                }
                Next::Wait(at) => return wake.min(at),
                Next::Idle => return wake,
            }
        }
        // More to send: at once.
        now
    }

    /// An object fetched whole from `from`.
    fn arrived(&mut self, now: Micros, object: Object, from: SocketAddrV4, bytes: &[u8]) {
        // Nothing else is fetched yet.
        if let Object::Headers { from: first, .. } = object {
            self.headers_arrived(now, from, first, bytes)
        }
    }

    /// A fetch from `from` was given up: the peer is passed over, and
    /// what was wanted is wanted again, of another.
    fn fetch_failed(&mut self, now: Micros, object: Object, from: SocketAddrV4) {
        self.counts.fetches_failed += 1;
        self.peers.failed(&from, now);
        if let (Object::Headers { from: first, .. }, Some(aim)) = (object, self.aim.as_mut()) {
            aim.todo.insert(first);
            self.fetch_headers(now);
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
    SocketAddr::V4(addr)
}

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
