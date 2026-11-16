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
//! # Blocks
//!
//! The headers kept say which bodies are wanted: those of the best
//! header's branch that the chain does not have
//! ([`Chain::missing_bodies`]). They are fetched several at once, from
//! whoever announced each or from a peer whose chain holds it, and
//! join the chain in order; one that arrives before the block below it
//! waits. A block that joins the chain is announced to every live
//! peer but the one it came from ([`Message::Block`]): each checks the
//! header, fetches the body, and announces it in turn, so that a new
//! block crosses the network in a few hops.
//!
//! A peer that serves a body that is not its header's, or a block that
//! breaks a rule, takes a strike.
//!
//! # The state, taken whole
//!
//! A node keeps bodies only for the blocks it can undo. One that is
//! further behind than its peers' bodies reach cannot be given the
//! blocks it lacks, and takes the state instead, as of a block a little
//! under the best header: that block and the top of its state, the
//! block's proof, then the state's parts, several at once from every
//! peer that can serve them, each checked against the header's root
//! before it is kept ([`crate::chain::receive`], [`super::snapshot`]).
//! Headers go on being taken throughout. If the peers can no longer go
//! back to the block, a later one is taken in its place, and the parts
//! that are the same are kept.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::config::Config;
use super::message::{Locator, Message, Status};
use super::object::{MAX_NAME, Object};
use super::peers::Peers;
use super::snapshot::{self, Manifest};
use super::{MAX_DATAGRAM, VERSION};
use crate::block::{BlockRef, HEADER_SIZE, Header};
use crate::chain::Chain;
use crate::chain::apply::{Applied, condemns};
use crate::chain::headers::LOCATOR;
use crate::chain::verify::ProofVerifier;
use crate::error::Error;
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
    /// Blocks that joined the chain here, and blocks refused.
    pub blocks: u64,
    pub blocks_refused: u64,
    /// Announcements of a block sent.
    pub announced: u64,
    /// States taken whole from other nodes, and times the block one was
    /// being taken as of was given up for another.
    pub states: u64,
    pub states_moved: u64,
}

/// Objects made to be served are kept while they are being asked for:
/// so many bytes of them, the latest made or asked for first. Every
/// chunk is asked for by its object's name, and a part of the state
/// takes reading back through the blocks since to make.
const SERVED_BYTES: usize = 32 << 20;
/// Chunks sent in one go before the node looks to what else there is.
const SERVE_BATCH: usize = 256;

/// An object being fetched.
struct Fetching {
    object: Object,
    from: SocketAddrV4,
    fetch: Fetch,
}

/// Announcements remembered: who said it had which block.
const ANNOUNCED: usize = 256;

/// Work on the chain that takes time: given to be done, and what came
/// of it heard later ([`Applier`]).
enum Job {
    /// A block to apply: whole, and who it came from (nobody, if it
    /// was made here).
    Block { block: Vec<u8>, from: Option<SocketAddrV4>, unix: u64 },
    /// A run of headers to check and keep: from the height `first`.
    Headers { first: u32, headers: Vec<Header>, from: SocketAddrV4, unix: u64 },
    /// The block a state is to be taken as of, to check by its proof.
    Check { block: Vec<u8>, next: u64 },
    /// A state to begin to receive, as of the block of `target`.
    Begin { target: Header, next: u64, parts: Vec<(u64, Digest)>, name_parts: Vec<(u32, crate::store::trie::Part)> },
    /// A part of the outputs or of the names of that state, as it
    /// arrived, to check and keep.
    Piece { object: Object, bytes: Vec<u8>, from: SocketAddrV4 },
    /// The state, every part of it in, to make whole: with the body of
    /// its block.
    Finish { target: Digest, body: Vec<u8> },
}

/// What became of one.
enum Outcome {
    Block {
        header: Header,
        /// The length of its body.
        len: u32,
        from: Option<SocketAddrV4>,
        result: Result<Applied, Error>,
    },
    Headers {
        first: u32,
        count: u32,
        /// The id of the last of them.
        last: Digest,
        from: SocketAddrV4,
        /// How many were new, and what stopped the run, if anything.
        new: usize,
        error: Option<Error>,
    },
    Checked {
        target: Digest,
        result: Result<(), Error>,
    },
    Begun {
        target: Digest,
        result: Result<(), Error>,
    },
    Piece {
        object: Object,
        from: SocketAddrV4,
        result: Result<(), Error>,
    },
    Finished {
        target: Digest,
        result: Result<(), Error>,
    },
    /// Work that was no work: nothing came of it.
    Nothing,
}

fn apply<B: Backend + 'static, V: ProofVerifier + Sync>(chain: &Chain<B, V>, job: Job) -> Option<Outcome> {
    Some(match job {
        Job::Block { block, from, unix } => {
            let view = BlockRef::from_bytes(&block).ok()?;
            let result = chain.apply_block(&view, unix);
            Outcome::Block { header: *view.header(), len: (block.len() - HEADER_SIZE) as u32, from, result }
        }
        Job::Headers { first, headers, from, unix } => {
            let (new, error) = chain.accept_headers(&headers, unix, false);
            Outcome::Headers { first, count: headers.len() as u32, last: headers.last()?.hash(), from, new, error }
        }
        Job::Check { block, next } => {
            let view = BlockRef::from_bytes(&block).ok()?;
            Outcome::Checked { target: view.header().hash(), result: chain.check_state_block(&view, next) }
        }
        Job::Begin { target, next, parts, name_parts } => {
            Outcome::Begun { target: target.hash(), result: chain.begin_receiving(&target, next, &parts, &name_parts) }
        }
        Job::Piece { object, bytes, from } => {
            let result = match object {
                Object::Part { index, .. } => snapshot::decode_part(&bytes, index)
                    .and_then(|(outputs, commits)| chain.put_part(index, &outputs, &commits)),
                Object::Names { index, .. } => {
                    snapshot::decode_names(&bytes).and_then(|records| chain.put_names(index, &records))
                }
                _ => return None,
            };
            Outcome::Piece { object, from, result }
        }
        Job::Finish { target, body } => Outcome::Finished { target, result: chain.finish_receiving(&body) },
    })
}

/// Where work on the chain is done. Applying a block takes as long as
/// checking its proof does; a run of headers, their proofs of work; a
/// part of a state, a write to the store. A node that did any of it
/// between datagrams would answer nobody meanwhile: so a node over a
/// socket gives it to a thread of its own ([`Node::threaded`]), one
/// piece of work after another in the order given. In the tests it is
/// done in place, so that a run is the same every time.
enum Applier {
    Here(VecDeque<Outcome>),
    Thread(Mutex<std::sync::mpsc::Sender<Job>>, Mutex<std::sync::mpsc::Receiver<Outcome>>),
}

/// A state being taken whole from other nodes, in place of the blocks
/// nobody holds any more ([`crate::chain::receive`]).
pub(crate) struct Join {
    /// The block it is the state after.
    target: Header,
    id: Digest,
    /// That block, whole, once fetched.
    block: Option<Vec<u8>>,
    /// The top of the state in parts, checked against the block's
    /// header, and who served it.
    manifest: Option<(Manifest, SocketAddrV4)>,
    /// The block's proof has been checked, with what the manifest says
    /// of where its outputs end; or is being.
    checked: bool,
    checking: bool,
    /// The roots of the parts of each range fetched so far.
    roots: BTreeMap<u32, Vec<(u64, Digest)>>,
    /// The chain has begun to receive the state; or is beginning to.
    begun: bool,
    beginning: bool,
    /// Pieces that have arrived and are being checked and kept.
    putting: Vec<Object>,
    /// Every part is in, and the state is being made whole.
    finishing: bool,
    /// Peers that did not serve something of it: asked again only if
    /// no other can be.
    unserved: Vec<SocketAddrV4>,
    /// Which peer is asked next.
    turn: usize,
    /// Manifests that the block's proof refused.
    refused: u32,
    /// Since when no peer has been able to serve it.
    orphaned: Option<Micros>,
}

/// The chain being caught up with: a tip some peer has, and its headers
/// from where its chain leaves ours.
pub(crate) struct Aim {
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
    /// A run is with the applier, being checked and kept.
    keeping: bool,
    /// Who told us of it: asked for its headers though its last ping
    /// said its chain was shorter.
    source: SocketAddrV4,
}

/// What the node is after, and what is being done about it: the chain
/// being caught up with, the bodies in hand, the state being taken,
/// and the work given to be done on the chain.
///
/// This is all that is about no one peer (`docs/THREADS.md`, 4.2). It
/// is behind a lock, taken where a decision about what to fetch is
/// made or what came of one is heard: not to answer a ping, take a
/// chunk or serve one.
pub(crate) struct List {
    /// The peer asked where its chain leaves ours, when, and the block
    /// it announced that made us ask, with its height: its tip, as far
    /// as we know, though its last ping said less.
    probe: Option<(SocketAddrV4, Micros, Option<(Digest, u32)>)>,
    pub(crate) aim: Option<Aim>,
    applier: Applier,
    /// Work given to be done and not yet heard of.
    outstanding: usize,
    /// Blocks given to be applied and not yet heard of.
    pub(crate) applying: Vec<Digest>,
    /// Bodies fetched and waiting for the blocks before them: the
    /// block whole, and who served it.
    pub(crate) held: Vec<(Digest, Vec<u8>, SocketAddrV4)>,
    /// The state being taken whole from others, if one is.
    pub(crate) join: Option<Join>,
    /// What is being fetched, and of whom: whoever begins a fetch of
    /// something the node is after says so here, so that nobody else
    /// fetches the same, and so that how many are under way is known
    /// to all.
    fetching: Vec<(Object, SocketAddrV4)>,
}

/// A run of headers.
fn headers(object: &Object) -> bool {
    matches!(object, Object::Headers { .. })
}

/// A piece of a state, but for its block.
fn of_state(object: &Object) -> bool {
    matches!(object, Object::Manifest(_) | Object::Roots { .. } | Object::Part { .. } | Object::Names { .. })
}

/// Takes `object` of `from` off what is being fetched.
fn fetched(fetching: &mut Vec<(Object, SocketAddrV4)>, object: &Object, from: &SocketAddrV4) {
    if let Some(at) = fetching.iter().position(|(o, a)| o == object && a == from) {
        fetching.swap_remove(at);
    }
}

/// What a datagram was, and what was done about it: for whoever keeps
/// a record of what a node is asked ([`Node::handle`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heard {
    /// Who sent it, if its address is of a kind we speak to.
    pub from: Option<SocketAddrV4>,
    /// The message, by its name: `ping`, `get`, `block`; or
    /// `malformed`, for a datagram that was none.
    pub request: &'static str,
    /// What of it is worth a word.
    pub about: About,
    /// What was done: the answer's name where one was sent (`pong`,
    /// `peers`, `fork`); `queued` for chunks asked for, which are sent
    /// as the node's pace allows; `taken` for what needs no answer;
    /// `unheard`, `stranger` or `malformed` for what was not listened
    /// to.
    pub answer: &'static str,
    /// Datagrams sent in answering, and their bytes.
    pub sent: u32,
    pub sent_bytes: u32,
}

/// What is said of a request besides its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum About {
    Nothing,
    /// The height of the sender's chain, or of the block spoken of.
    Height(u32),
    /// How many addresses.
    Peers(usize),
    /// A block announced: its height, and its body's length.
    Block {
        height: u32,
        bytes: u32,
    },
    /// Chunks asked for, and of what kind of object.
    Chunks {
        of: &'static str,
        chunks: u32,
    },
}

/// A chunk of something this node is fetching: by far the most of what
/// arrives while it is, and each much like the last.
pub const CHUNK: &str = "chunk";

impl Heard {
    /// The line of the request log: who asked, how long answering took
    /// in microseconds, what was asked (in a datagram of `bytes`), and
    /// what was done.
    ///
    /// ```text
    /// 203.0.113.7:3737      41 micros       ping height 88,214 (133 bytes) -> pong (133 bytes)
    /// ```
    pub fn line(&self, bytes: usize, micros: u64) -> String {
        use crate::logger::fmt::{column, commas};
        let from = self.from.map_or_else(|| "-".to_string(), |a| a.to_string());
        let about = match self.about {
            About::Nothing => String::new(),
            About::Height(height) => format!(" height {}", commas(height as u64)),
            About::Peers(n) => format!(" of {}", commas(n as u64)),
            About::Block { height, bytes } => {
                format!(" height {} of {} bytes", commas(height as u64), commas(bytes as u64))
            }
            About::Chunks { of, chunks } => format!(" {of}, {} chunks", commas(chunks as u64)),
        };
        let sent = match self.sent {
            0 => String::new(),
            1 => format!(" ({} bytes)", commas(self.sent_bytes as u64)),
            n => format!(" ({} datagrams, {} bytes)", commas(n as u64), commas(self.sent_bytes as u64)),
        };
        format!(
            "{}{}{}{about} ({} bytes) -> {}{sent}",
            column(&from, 22, ' '),
            column(&format!("{} micros", commas(micros)), 16, ' '),
            self.request,
            commas(bytes as u64),
            self.answer
        )
    }
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
    /// What is about no one peer.
    list: Arc<RwLock<List>>,
    /// Who announced which block, and how long its body is: the newest
    /// last.
    announced: VecDeque<(Digest, SocketAddrV4, u32)>,
    /// What came of the fetches asked for from outside
    /// ([`Node::fetch_object`]).
    inbox: Vec<(Object, SocketAddrV4, Option<Vec<u8>>)>,
    counts: Counts,
    /// Tests: a chain's work claimed that is not there; objects served
    /// with a byte wrong.
    #[cfg(test)]
    pub(crate) boast: Option<U256>,
    #[cfg(test)]
    pub(crate) spoil: bool,
    /// Tests: a block served that is on no chain here.
    #[cfg(test)]
    pub(crate) foist: Option<(Digest, Vec<u8>)>,
}

/// A datagram to send goes to this.
pub type Out<'a> = &'a mut dyn FnMut(SocketAddrV4, &[u8]);

impl<B: Backend + 'static, V: ProofVerifier + Sync> Node<B, V> {
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
            list: Arc::new(RwLock::new(List {
                probe: None,
                aim: None,
                applier: Applier::Here(VecDeque::new()),
                outstanding: 0,
                applying: Vec::new(),
                held: Vec::new(),
                join: None,
                fetching: Vec::new(),
            })),
            announced: VecDeque::new(),
            inbox: Vec::new(),
            counts: Counts::default(),
            #[cfg(test)]
            boast: None,
            #[cfg(test)]
            spoil: false,
            #[cfg(test)]
            foist: None,
        }
    }

    /// Has blocks applied on a thread of their own from here on: for a
    /// node over a socket.
    pub fn threaded(self) -> Node<B, V>
    where
        Chain<B, V>: Send + Sync,
        V: 'static,
    {
        let (jobs, todo) = std::sync::mpsc::channel::<Job>();
        let (done, outcomes) = std::sync::mpsc::channel();
        let chain = Arc::clone(&self.chain);
        std::thread::Builder::new()
            .name("applier".into())
            .spawn(move || {
                // Until the node is dropped, and its end of either with it.
                for job in todo {
                    // (Something is always said of a job, so that the
                    // node knows it is done with.)
                    let outcome = apply(&chain, job).unwrap_or(Outcome::Nothing);
                    if done.send(outcome).is_err() {
                        break;
                    }
                }
            })
            .expect("a thread");
        self.write().applier = Applier::Thread(Mutex::new(jobs), Mutex::new(outcomes));
        self
    }

    /// A block made here: applied, and if it joins the chain, announced.
    pub fn mined(&mut self, block: Vec<u8>) {
        let list = Arc::clone(&self.list);
        self.give(&mut write(&list), block, None);
    }

    /// The list, to look at.
    pub(crate) fn list(&self) -> RwLockReadGuard<'_, List> {
        self.list.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Tests: does `f` with the list in hand, as the node itself does
    /// what it does about what to fetch.
    #[cfg(test)]
    pub(crate) fn with_list<T>(&mut self, f: impl FnOnce(&mut Self, &mut List) -> T) -> T {
        let list = Arc::clone(&self.list);
        f(self, &mut write(&list))
    }

    fn write(&self) -> RwLockWriteGuard<'_, List> {
        write(&self.list)
    }

    /// Gives a block to be applied.
    fn give(&mut self, l: &mut List, block: Vec<u8>, from: Option<SocketAddrV4>) {
        let Ok(header) = BlockRef::from_bytes(&block).map(|b| *b.header()) else {
            return;
        };
        l.applying.push(header.hash());
        self.work(l, Job::Block { block, from, unix: self.unix });
    }

    /// Gives work to be done on the chain: what comes of it is heard
    /// in [`Node::applied`].
    fn work(&mut self, l: &mut List, job: Job) {
        l.outstanding += 1;
        match &mut l.applier {
            Applier::Here(done) => match apply(&self.chain, job) {
                Some(outcome) => done.push_back(outcome),
                None => l.outstanding -= 1,
            },
            Applier::Thread(jobs, _) => {
                let _ = jobs.get_mut().unwrap_or_else(|e| e.into_inner()).send(job);
            }
        }
    }

    /// Whether work given to be done on the chain is still to be heard
    /// of: whoever drives the node then looks to it again soon, without
    /// waiting for a datagram.
    pub fn busy(&self) -> bool {
        self.list().outstanding > 0
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
            // Bodies are kept for the blocks that can be undone, and no
            // further back: below those a node has headers only.
            oldest: (tip.height + 1).saturating_sub(self.chain.keep() as u32),
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
        // What there is to catch up with: with the list in hand.
        let list = Arc::clone(&self.list);
        let l = &mut *write(&list);
        self.sync_headers(l, now, out);
        self.sync_blocks(l, now);
        self.sync_state(l, now);
    }

    /// Takes a datagram that arrived from `from`, and says what it was
    /// and what was done about it. Call [`Node::tick`] after it.
    pub fn handle(&mut self, now: Micros, from: SocketAddr, bytes: &[u8], out: Out<'_>) -> Heard {
        let unheard =
            |from, request| Heard { from, request, about: About::Nothing, answer: "malformed", sent: 0, sent_bytes: 0 };
        // Addresses of the older kind only (`docs/WIRE.md`, 1.1).
        let from = match from {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
                Some(ip) => SocketAddrV4::new(ip, a.port()),
                None => return unheard(None, "ipv6"),
            },
        };
        let Ok(message) = Message::decode(self.network, bytes) else {
            self.counts.malformed += 1;
            return unheard(Some(from), "malformed");
        };
        let (request, about, answers) = match &message {
            Message::Ping(theirs) => ("ping", About::Height(theirs.height), "pong"),
            Message::Pong(theirs) => ("pong", About::Height(theirs.height), "answered"),
            Message::GetPeers { .. } => ("get-peers", About::Nothing, "peers"),
            Message::Peers(addrs) => ("peers", About::Peers(addrs.as_slice().len()), "answered"),
            Message::Goodbye { .. } => ("goodbye", About::Nothing, "answered"),
            Message::FindFork { .. } => ("find-fork", About::Nothing, "fork"),
            Message::Fork { height, .. } => ("fork", About::Height(*height), "answered"),
            Message::Block { header, len } => {
                ("block", About::Block { height: header.height, bytes: *len }, "answered")
            }
            Message::Get(get) => {
                let of = Object::decode(get.name).map_or("nothing", |o| o.kind());
                ("get", About::Chunks { of, chunks: get.ranges.chunks() }, "answered")
            }
            Message::Chunk(_) => (CHUNK, About::Nothing, "answered"),
            Message::Gone(_) => ("gone", About::Nothing, "answered"),
            Message::Tx { .. } => ("tx", About::Nothing, "answered"),
            Message::GetLeaves { .. } => ("get-leaves", About::Nothing, "answered"),
            Message::Leaves { .. } => ("leaves", About::Nothing, "answered"),
        };
        // What was done is read off what it left behind: what was sent,
        // and what was counted as not listened to.
        let before = self.counts;
        let (mut sent, mut sent_bytes) = (0u32, 0u32);
        self.act(now, from, message, &mut |to, bytes: &[u8]| {
            sent += 1;
            sent_bytes += bytes.len() as u32;
            out(to, bytes)
        });
        let answer = match () {
            () if self.counts.malformed > before.malformed => "malformed",
            () if self.counts.unheard > before.unheard => "unheard",
            () if self.counts.strangers > before.strangers => "stranger",
            () if sent > 0 => answers,
            () if request == "get" => "queued",
            () => "taken",
        };
        Heard { from: Some(from), request, about, answer, sent, sent_bytes }
    }

    fn act(&mut self, now: Micros, from: SocketAddrV4, message: Message<'_>, out: Out<'_>) {
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
            Message::Fork { height, id } => {
                let list = Arc::clone(&self.list);
                self.on_fork(&mut write(&list), now, from, height, id)
            }
            Message::Block { header, len } => {
                let list = Arc::clone(&self.list);
                self.on_block(&mut write(&list), now, from, header, len, out)
            }
            Message::Get(get) => self.on_get(now, from, &get),
            Message::Chunk(chunk) => self.on_chunk(now, from, &chunk),
            Message::Gone(gone) => {
                match self.fetches.iter_mut().find(|f| f.from == from && f.fetch.transfer() == gone.transfer) {
                    Some(f) => f.fetch.gone(),
                    None => self.counts.unheard += 1,
                }
            }
            // Transactions and aux leaves are not here yet.
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
    fn sync_headers(&mut self, l: &mut List, now: Micros, out: Out<'_>) {
        let Ok(best) = self.chain.best_header() else {
            return;
        };
        // Those that claimed work and have sent nothing for it.
        self.peers.doubt_silent_claimants(best.work, now, |_| {});
        if let Some((addr, _, _)) = l.probe
            && !self.peers.may_ask(&addr, now)
        {
            l.probe = None;
        }
        if l.aim.is_some() {
            return self.fetch_headers(l, now);
        }
        if l.probe.is_some_and(|(_, at, _)| now.saturating_sub(at) < self.cfg.sync.header_spacing) {
            return;
        }
        // Ask whoever claims most where its chain leaves ours.
        let next = self.chain.tip().map_or(0, |t| t.height + 1);
        let Some(source) = self.peers.best_source(best.work, next, now) else {
            return;
        };
        let addr = source.addr;
        self.ask_fork(l, now, addr, None, out);
    }

    /// Asks `addr` where its chain leaves ours. `tip` is the block it
    /// announced, if that is why.
    fn ask_fork(&mut self, l: &mut List, now: Micros, addr: SocketAddrV4, tip: Option<(Digest, u32)>, out: Out<'_>) {
        let Some(token) = self.peers.get(&addr).and_then(|p| p.token()) else {
            return;
        };
        let mut ids = [self.genesis; LOCATOR];
        let Ok(n) = self.chain.header_locator(&mut ids) else {
            return;
        };
        let Some(locator) = Locator::new(&ids[..n]) else {
            return;
        };
        l.probe = Some((addr, now, tip));
        self.peers.asked_headers(&addr, now);
        self.counts.forks_asked += 1;
        self.send(addr, &Message::FindFork { token, locator }, out);
    }

    fn on_fork(&mut self, l: &mut List, now: Micros, from: SocketAddrV4, height: u32, id: Digest) {
        // Only the answer to our question, from whom it was put to.
        let Some((_, _, announced)) = l.probe.filter(|p| p.0 == from && self.peers.proven(&from)) else {
            self.counts.unheard += 1;
            return;
        };
        l.probe = None;
        self.peers.seen(&from, now);
        // A block we hold, at the height it says: or it is no answer.
        let ours = self.chain.known(&id).ok().flatten();
        if ours.is_none_or(|k| k.header.height != height) {
            self.peers.strike(&from, now);
            return;
        }
        // Its tip: the block it announced, or what its last ping said.
        let Some(tip) = announced.or_else(|| self.peers.get(&from).and_then(|p| p.status).map(|s| (s.tip, s.height)))
        else {
            return;
        };
        if tip.1 <= height {
            // Nothing past what we share: its claim was of nothing.
            self.peers.failed(&from, now);
            return;
        }
        let run = self.cfg.sync.headers as u32;
        l.aim = Some(Aim {
            tip: tip.0,
            height: tip.1,
            todo: (height + 1..=tip.1).step_by(run as usize).collect(),
            done: BTreeMap::new(),
            next: height + 1,
            keeping: false,
            source: from,
        });
        self.fetch_headers(l, now);
    }

    /// Asks for the runs of headers not yet asked for, as many at once
    /// as may be, each of another peer.
    fn fetch_headers(&mut self, l: &mut List, now: Micros) {
        let Some(aim) = l.aim.as_mut() else {
            return;
        };
        let (most, run) = (self.cfg.sync.header_fetches, self.cfg.sync.headers as u32);
        // No further ahead of what is kept than can wait in memory.
        let ahead = aim.next.saturating_add(2 * most as u32 * run);
        loop {
            let busy = l.fetching.iter().filter(|f| headers(&f.0)).count();
            let Some(&from) = aim.todo.iter().next().filter(|h| **h < ahead && busy < most) else {
                break;
            };
            let count = run.min(aim.height - from + 1) as u16;
            // A peer whose chain reaches the tip aimed at, and that is
            // not at a run of headers for us already.
            let idle = |addr: &SocketAddrV4| {
                !self.fetches.iter().any(|f| f.from == *addr && matches!(f.object, Object::Headers { .. }))
            };
            let source = self.peers.get(&aim.source).filter(|p| self.peers.may_ask(&p.addr, now) && idle(&p.addr));
            let Some(peer) = self.peers.reaching(aim.height, now).find(|p| idle(&p.addr)).or(source) else {
                break;
            };
            aim.todo.remove(&from);
            let transfer = Self::number(&self.secret, &mut self.numbers);
            let len = count as u32 * HEADER_SIZE as u32;
            let object = Object::Headers { from, count, on: aim.tip };
            l.fetching.push((object, peer.addr));
            self.fetches.push(Fetching {
                object,
                from: peer.addr,
                fetch: Fetch::new(transfer, Some(len), len, peer.path, now),
            });
        }
        // Nothing under way, and nobody to ask: the aim is let go, and
        // another is taken from whoever claims most then.
        if !l.fetching.iter().any(|f| headers(&f.0)) && !aim.todo.is_empty() {
            l.aim = None;
        }
    }

    /// A run of headers has arrived whole from `from`.
    fn headers_arrived(&mut self, l: &mut List, now: Micros, from: SocketAddrV4, first: u32, bytes: &[u8]) {
        let Some(aim) = l.aim.as_mut() else {
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
                _ => return self.headers_refused(l, now, from),
            }
        }
        aim.done.insert(first, (headers, from));
        self.keep_headers(l);
        self.fetch_headers(l, now);
    }

    /// Gives the next run of headers to be checked and kept, if it is
    /// here and none is being: in order, one at a time.
    fn keep_headers(&mut self, l: &mut List) {
        let Some(aim) = l.aim.as_mut().filter(|aim| !aim.keeping) else {
            return;
        };
        if let Some((headers, from)) = aim.done.remove(&aim.next) {
            aim.keeping = true;
            let first = aim.next;
            self.work(l, Job::Headers { first, headers, from, unix: self.unix });
        }
    }

    /// A run of headers has been checked and kept, or refused.
    fn headers_kept(
        &mut self,
        l: &mut List,
        now: Micros,
        first: u32,
        count: u32,
        last: Digest,
        from: SocketAddrV4,
        error: bool,
    ) {
        // Of the aim there is now, at the place it has got to: or it
        // was let go meanwhile, and this is of no account.
        let Some(aim) = l.aim.as_mut().filter(|aim| aim.keeping && aim.next == first) else {
            return;
        };
        aim.keeping = false;
        if error {
            return self.headers_refused(l, now, from);
        }
        self.peers.headers_arrived(&from);
        aim.next += count;
        // The last of them is the tip that was aimed at, or the peers
        // that served them are of two minds.
        if aim.next > aim.height {
            if last != aim.tip {
                return self.headers_refused(l, now, from);
            }
            l.aim = None;
            return self.sync_blocks(l, now);
        }
        self.keep_headers(l);
        self.fetch_headers(l, now);
    }

    /// `from` served headers that are not what was asked for, or that
    /// the chain refuses: a strike, and the aim is let go. What was
    /// kept stays kept.
    fn headers_refused(&mut self, l: &mut List, now: Micros, from: SocketAddrV4) {
        self.peers.strike(&from, now);
        self.peers.failed(&from, now);
        l.aim = None;
        self.fetches.retain(|f| !headers(&f.object));
        l.fetching.retain(|f| !headers(&f.0));
    }

    // -- Blocks

    /// "Here is a new block", from `from`.
    fn on_block(&mut self, l: &mut List, now: Micros, from: SocketAddrV4, header: Header, len: u32, out: Out<'_>) {
        // Unasked: only from a peer.
        if !self.peers.proven(&from) {
            self.counts.unheard += 1;
            return;
        }
        self.peers.seen(&from, now);
        let id = header.hash();
        // Its chain reaches there, whatever its last ping said.
        self.peers.reaches(&from, header.height, id);
        // One we have, body and all, is no news.
        if self.chain.known(&id).ok().flatten().is_some_and(|k| !k.header_only()) || l.applying.contains(&id) {
            return;
        }
        match self.chain.accept_header(&header, self.unix) {
            Ok(_) => {
                if self.announced.len() == ANNOUNCED {
                    self.announced.pop_front();
                }
                self.announced.push_back((id, from, len));
                self.sync_blocks(l, now);
            }
            // Its parent is unknown: we are more than a block behind it.
            // Its headers are asked for now, without waiting for its
            // next ping to say how far it has got.
            Err(Error::UnknownParent) => {
                let lately = l.probe.is_some_and(|(_, at, _)| now.saturating_sub(at) < self.cfg.sync.header_spacing);
                if l.aim.is_none() && !lately && self.peers.may_ask(&from, now) {
                    self.ask_fork(l, now, from, Some((id, header.height)), out);
                }
            }
            // Not the announcer's fault, or not yet known to be.
            Err(Error::KnownInvalid | Error::SetAside | Error::TimestampTooNew { .. } | Error::Io(_)) => {}
            // A header that breaks a rule.
            Err(_) => {
                self.peers.strike(&from, now);
            }
        }
    }

    /// Tells every live peer but `except` of a block: its header, and
    /// how long its body is.
    pub(crate) fn announce(
        &mut self,
        now: Micros,
        header: Header,
        len: u32,
        except: Option<SocketAddrV4>,
        out: Out<'_>,
    ) {
        let mut all = Vec::new();
        all.extend(self.peers.live(now).map(|p| p.addr).filter(|a| Some(*a) != except));
        for addr in all {
            self.counts.announced += 1;
            self.send(addr, &Message::Block { header, len }, out);
        }
    }

    /// The bodies the best header's branch still lacks: fetches those
    /// not yet asked for, as many at once as may be, and gives the
    /// first to be applied once it is here. Blocks join the chain in
    /// order, so a body that arrives before the one below it waits.
    fn sync_blocks(&mut self, l: &mut List, now: Micros) {
        // While the state is being taken, no block can join.
        if self.chain.receiving() {
            return;
        }
        let mut need = vec![self.chain.params().genesis().header; self.cfg.sync.lookahead];
        let n = self.chain.missing_bodies(&mut need).unwrap_or(0);
        let ids: Vec<Digest> = need[..n].iter().map(Header::hash).collect();
        // What is held and no longer wanted is let go.
        l.held.retain(|(id, _, _)| ids.contains(id));
        if l.applying.is_empty()
            && let Some(first) = ids.first()
            && let Some(at) = l.held.iter().position(|(id, _, _)| id == first)
        {
            let (_, block, from) = l.held.swap_remove(at);
            self.give(l, block, Some(from));
        }
        let most = (self.chain.params().max_block_size - HEADER_SIZE) as u32;
        for (id, header) in ids.iter().zip(&need[..n]) {
            let fetching = |f: &Fetching| matches!(f.object, Object::Block(_));
            if l.fetching.iter().filter(|f| matches!(f.0, Object::Block(_))).count() >= self.cfg.sync.blocks {
                break;
            }
            let wanted = Object::Block(*id);
            if l.applying.contains(id)
                || l.held.iter().any(|(held, _, _)| held == id)
                || l.fetching.iter().any(|f| f.0 == wanted)
            {
                continue;
            }
            let free = |addr: &SocketAddrV4| {
                self.fetches.iter().filter(|f| fetching(f) && f.from == *addr).count() < self.cfg.sync.blocks_per_peer
            };
            // Whoever announced it, with the length it gave; else a peer
            // whose chain holds that height, the length to be learned.
            let told = self
                .announced
                .iter()
                .rev()
                .find(|(told, addr, _)| told == id && self.peers.may_ask(addr, now) && free(addr));
            let source = match told {
                Some((_, addr, len)) => Some((*addr, Some(*len).filter(|l| *l > 0 && *l <= most))),
                None => self.peers.holders(header.height, now).find(|p| free(&p.addr)).map(|p| (p.addr, None)),
            };
            // In order: a body nobody holds is not to be had, and those
            // above it could not join the chain without it.
            let Some((addr, len)) = source else {
                break;
            };
            let path = self.peers.get(&addr).map(|p| p.path).unwrap_or_default();
            let transfer = Self::number(&self.secret, &mut self.numbers);
            l.fetching.push((wanted, addr));
            self.fetches.push(Fetching {
                object: wanted,
                from: addr,
                fetch: Fetch::new(transfer, len, most, path, now),
            });
        }
    }

    /// A body has arrived whole from `from`.
    fn body_arrived(&mut self, l: &mut List, now: Micros, from: SocketAddrV4, id: Digest, body: &[u8]) {
        let Some(known) = self.chain.known(&id).ok().flatten() else {
            return;
        };
        let mut block = Vec::with_capacity(HEADER_SIZE + body.len());
        block.extend_from_slice(&known.header.to_bytes());
        block.extend_from_slice(body);
        l.held.push((id, block, from));
        self.sync_blocks(l, now);
    }

    /// What became of the blocks given to be applied.
    fn applied(&mut self, l: &mut List, now: Micros, out: Out<'_>) {
        loop {
            let outcome = match &mut l.applier {
                Applier::Here(done) => done.pop_front(),
                Applier::Thread(_, done) => done.get_mut().unwrap_or_else(|e| e.into_inner()).try_recv().ok(),
            };
            let Some(outcome) = outcome else {
                return;
            };
            l.outstanding = l.outstanding.saturating_sub(1);
            match outcome {
                Outcome::Block { header, len, from, result } => {
                    self.block_applied(l, now, header, len, from, result, out)
                }
                Outcome::Headers { first, count, last, from, new, error } => {
                    self.counts.headers += new as u64;
                    self.headers_kept(l, now, first, count, last, from, error.is_some());
                }
                Outcome::Nothing => {}
                Outcome::Checked { target, result } => self.state_block_checked(l, now, target, result),
                Outcome::Begun { target, result } => {
                    if let Some(join) = l.join.as_mut().filter(|j| j.id == target) {
                        join.beginning = false;
                        match result {
                            Ok(()) => join.begun = true,
                            Err(_) => l.join = None,
                        }
                    }
                    self.advance_join(l, now);
                }
                Outcome::Piece { object, from, result } => {
                    if self.of_join(l, &object)
                        && let Some(join) = l.join.as_mut()
                    {
                        join.putting.retain(|o| *o != object);
                        // Not the part of its root, or no part at all:
                        // its sender's doing. Anything else is ours.
                        if matches!(result, Err(Error::PartRoot | Error::Malformed(_))) {
                            self.peers.strike(&from, now);
                            join.unserved.push(from);
                        }
                    }
                    self.advance_join(l, now);
                }
                Outcome::Finished { target, result } => {
                    if l.join.as_ref().is_some_and(|j| j.id == target) {
                        // Whole, or not: either way this taking is over.
                        // (Not whole, the chain is receiving still, and
                        // another is begun when time is next looked to.)
                        l.join = None;
                        if result.is_ok() {
                            self.counts.states += 1;
                        }
                    }
                    self.sync_blocks(l, now);
                }
            }
        }
    }

    /// What became of a block given to be applied.
    fn block_applied(
        &mut self,
        l: &mut List,
        now: Micros,
        header: Header,
        len: u32,
        from: Option<SocketAddrV4>,
        result: Result<Applied, Error>,
        out: Out<'_>,
    ) {
        let id = header.hash();
        l.applying.retain(|a| *a != id);
        match result {
            // The chain's new last block: every peer is told, but the
            // one it came from.
            Ok(Applied::Extended | Applied::Reorganized { .. }) => {
                self.counts.blocks += 1;
                self.announce(now, header, len, from, out);
            }
            Ok(Applied::Known | Applied::Side) => {}
            Err(e) => {
                self.counts.blocks_refused += 1;
                // A body that is not the header's, or a block that
                // breaks a rule: whoever served it answers for it.
                if let Some(from) = from
                    && (e == Error::BadBodyCommitment || condemns(&e))
                {
                    self.peers.strike(&from, now);
                    self.peers.failed(&from, now);
                    self.announced.retain(|(told, addr, _)| !(*told == id && *addr == from));
                }
            }
        }
        self.sync_blocks(l, now);
    }

    // -- The state, taken whole

    /// Whether `object` is a piece of the state being taken.
    fn of_join(&self, l: &List, object: &Object) -> bool {
        let Some(join) = &l.join else {
            return false;
        };
        match object {
            Object::Block(id) | Object::Manifest(id) => *id == join.id,
            Object::Roots { block, .. } | Object::Part { block, .. } | Object::Names { block, .. } => *block == join.id,
            _ => false,
        }
    }

    /// Takes the state whole when the blocks cannot be had: the bodies
    /// the chain needs next are held by nobody, and some peer can still
    /// go back to a block [`super::config::Sync::sync_point`] under the
    /// best header. Then, step by step: that block and the top of its
    /// state; the block's proof; the roots of the state's parts; the
    /// parts. Each piece from whichever peer's turn it is, several at
    /// once, each checked before the next is believed.
    fn sync_state(&mut self, l: &mut List, now: Micros) {
        if l.join.is_none() && !self.begin_join(l, now) {
            return;
        }
        let Some(join) = l.join.as_mut() else {
            return;
        };
        // Who can serve it: those that can still go back to its block.
        let mut servers: Vec<SocketAddrV4> =
            self.peers.servers_of_state(join.target.height, now).map(|p| p.addr).collect();
        if servers.is_empty() {
            // Nobody, for long enough: the block is given up for a
            // later one, and what was taken of its state that is the
            // same in the later one's is kept.
            let since = *join.orphaned.get_or_insert(now);
            if now.saturating_sub(since) >= self.cfg.sync.header_wait {
                l.join = None;
                self.fetches.retain(|f| !of_state(&f.object));
                l.fetching.retain(|f| !of_state(&f.0));
                // (Begun anew, the chain goes on with what it has
                // received: `Chain::begin_receiving`.)
                if self.begin_join(l, now) {
                    self.counts.states_moved += 1;
                }
            }
            return;
        }
        join.orphaned = None;
        // Those that have not failed us in this first, while there are.
        if servers.iter().any(|a| !join.unserved.contains(a)) {
            servers.retain(|a| !join.unserved.contains(a));
        }
        // What is wanted now, in order of need.
        let id = join.id;
        let mut wanted: Vec<(Object, u32)> = Vec::new();
        if join.block.is_none() {
            wanted.push((Object::Block(id), (self.chain.params().max_block_size - HEADER_SIZE) as u32));
        }
        match &join.manifest {
            None => wanted.push((Object::Manifest(id), snapshot::MAX_MANIFEST as u32)),
            Some((manifest, _)) if join.checked && !join.begun => {
                for (range, _) in &manifest.ranges {
                    if !join.roots.contains_key(range) {
                        wanted.push((Object::Roots { block: id, index: *range }, snapshot::MAX_ROOTS as u32));
                    }
                }
            }
            Some(_) => {}
        }
        if join.begun
            && let Ok((parts, names)) = self.chain.missing_parts()
        {
            wanted.extend(parts.iter().map(|i| (Object::Part { block: id, index: *i }, snapshot::MAX_PART as u32)));
            wanted.extend(names.iter().map(|i| (Object::Names { block: id, index: *i }, snapshot::MAX_NAMES as u32)));
            // (But for those that are here, and being kept.)
            wanted.retain(|(object, _)| !join.putting.contains(object));
        }
        for (object, most) in wanted {
            let under_way = l.fetching.iter().filter(|f| f.0 != object && of_state(&f.0));
            if under_way.count() >= self.cfg.sync.parts {
                break;
            }
            if l.fetching.iter().any(|f| f.0 == object) {
                continue;
            }
            join.turn = join.turn.wrapping_add(1);
            let from = servers[join.turn % servers.len()];
            let path = self.peers.get(&from).map(|p| p.path).unwrap_or_default();
            let transfer = Self::number(&self.secret, &mut self.numbers);
            l.fetching.push((object, from));
            self.fetches.push(Fetching { object, from, fetch: Fetch::new(transfer, None, most, path, now) });
        }
    }

    /// Chooses the block to take the state as of, if it is to be taken
    /// at all. True if one was chosen.
    fn begin_join(&mut self, l: &mut List, now: Micros) -> bool {
        let point = self.cfg.sync.sync_point;
        if point == 0 || l.aim.is_some() || !l.applying.is_empty() {
            return false;
        }
        let Ok(best) = self.chain.best_header().map(|k| k.header) else {
            return false;
        };
        // Already receiving (and the block it was as of given up): on,
        // as of another. Else only where blocks cannot be had: the
        // first body wanted is held by nobody that is there to ask.
        if !self.chain.receiving() {
            let mut first = [best];
            if self.chain.missing_bodies(&mut first).unwrap_or(0) == 0
                || self.peers.live(now).next().is_none()
                || self.peers.holders(first[0].height, now).next().is_some()
                || l.fetching.iter().any(|f| matches!(f.0, Object::Block(_)))
                || !l.held.is_empty()
            {
                return false;
            }
        }
        // As far under the best header as is asked, if anyone can go
        // back so far; else as far back as anyone can.
        let Some(reach) = self.peers.state_reach(now) else {
            return false;
        };
        let height = best.height.saturating_sub(point).max(reach).max(1);
        if height > best.height {
            return false;
        }
        let Ok(Some(mut target)) = self.chain.ancestor(&best, height) else {
            return false;
        };
        // A state that was being received already (the node stopped
        // and started while it was): as of the same block, if that can
        // still be had, so that nothing received is asked for again.
        if let Some((was, id)) = self.chain.receiving_as_of()
            && (reach..=best.height).contains(&was)
            && let Ok(Some(same)) = self.chain.ancestor(&best, was)
            && same.hash() == id
        {
            target = same;
        }
        let height = target.height;
        // The work of that header and of those after it in full: no
        // proof to come vouches for it.
        if !matches!(self.chain.confirm_work(&best, height), Ok(Ok(_))) {
            return false;
        }
        l.join = Some(Join {
            id: target.hash(),
            target,
            block: None,
            manifest: None,
            checked: false,
            checking: false,
            roots: BTreeMap::new(),
            begun: false,
            beginning: false,
            putting: Vec::new(),
            finishing: false,
            unserved: Vec::new(),
            turn: 0,
            refused: 0,
            orphaned: None,
        });
        true
    }

    /// A piece of the state being taken has arrived whole from `from`.
    fn piece_arrived(&mut self, l: &mut List, now: Micros, object: Object, from: SocketAddrV4, bytes: &[u8]) {
        let Some(join) = l.join.as_mut() else {
            return;
        };
        // What a piece is checked against, and what is done with one
        // that is not what it should be: its sender is struck, and it
        // is asked of another.
        let good = match object {
            Object::Block(_) => {
                let mut block = join.target.to_bytes().to_vec();
                block.extend_from_slice(bytes);
                let good = BlockRef::from_bytes(&block).is_ok_and(|b| b.body_commitment_matches());
                if good {
                    join.block = Some(block);
                }
                good
            }
            Object::Manifest(_) => match Manifest::decode(bytes) {
                Ok(manifest) if manifest.check(&join.target.state_root) => {
                    join.manifest = Some((manifest, from));
                    true
                }
                _ => false,
            },
            Object::Roots { index, .. } => {
                let want =
                    join.manifest.as_ref().and_then(|(m, _)| m.ranges.iter().find(|r| r.0 == index)).map(|r| r.1);
                match want.map(|root| snapshot::decode_roots(bytes, index, &root)) {
                    Some(Ok(parts)) => {
                        join.roots.insert(index, parts);
                        true
                    }
                    Some(Err(_)) => false,
                    None => true,
                }
            }
            // Checked where it is kept, which takes a write to the store:
            // given to be done, and heard of later.
            Object::Part { .. } | Object::Names { .. } => {
                join.putting.push(object);
                self.work(l, Job::Piece { object, bytes: bytes.to_vec(), from });
                return;
            }
            _ => true,
        };
        if !good {
            self.peers.strike(&from, now);
            join.unserved.push(from);
        }
        self.advance_join(l, now);
    }

    /// The steps of taking a state that follow from what is in hand.
    fn advance_join(&mut self, l: &mut List, now: Micros) {
        let Some(join) = l.join.as_mut() else {
            return;
        };
        // The block and the top of its state: the block's proof, held to
        // where the manifest says its outputs end.
        if !join.checked
            && !join.checking
            && let (Some(block), Some((manifest, _))) = (&join.block, &join.manifest)
        {
            join.checking = true;
            let job = Job::Check { block: block.clone(), next: manifest.next };
            return self.work(l, job);
        }
        // Every range's roots: the state can begin to be received.
        if join.checked
            && !join.begun
            && !join.beginning
            && let Some((manifest, _)) = &join.manifest
            && manifest.ranges.iter().all(|(range, _)| join.roots.contains_key(range))
        {
            join.beginning = true;
            let job = Job::Begin {
                target: join.target,
                next: manifest.next,
                parts: join.roots.values().flatten().copied().collect(),
                name_parts: manifest.name_parts.clone(),
            };
            return self.work(l, job);
        }
        // Every part: the chain is to be made whole, at the block.
        if join.begun
            && !join.finishing
            && join.putting.is_empty()
            && self.chain.missing_parts().is_ok_and(|(parts, names)| parts.is_empty() && names.is_empty())
            && let Some(block) = &join.block
        {
            join.finishing = true;
            let job = Job::Finish { target: join.id, body: block[HEADER_SIZE..].to_vec() };
            return self.work(l, job);
        }
        self.sync_state(l, now);
    }

    /// The block a state is to be taken as of has been checked by its
    /// proof, or refused.
    fn state_block_checked(&mut self, l: &mut List, now: Micros, target: Digest, result: Result<(), Error>) {
        let Some(join) = l.join.as_mut().filter(|j| j.id == target && j.checking) else {
            return;
        };
        join.checking = false;
        match result {
            Ok(()) => join.checked = true,
            // The block is its header's, so it is the manifest's word
            // that failed: one peer's, unless one after another fails
            // the same way.
            Err(_) => {
                if let Some((_, served)) = join.manifest.take() {
                    join.unserved.push(served);
                    self.peers.strike(&served, now);
                }
                join.refused += 1;
                if join.refused >= self.cfg.sync.snapshot_attempts {
                    l.join = None;
                    return;
                }
            }
        }
        self.advance_join(l, now);
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
        // The oldest go, down to what may be kept: but never the one
        // just made.
        let mut kept = 0;
        let fit = self.served.iter().take_while(|(_, b)| {
            kept += b.len();
            kept <= SERVED_BYTES
        });
        let keep = fit.count().max(1);
        self.served.truncate(keep);
        Some(Arc::clone(&self.served[0].1))
    }

    fn make(&self, object: &Object) -> Option<Vec<u8>> {
        #[cfg(test)]
        if let (Object::Block(id), Some((foisted, body))) = (object, &self.foist)
            && id == foisted
        {
            return Some(body.clone());
        }
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
            Object::Block(id) => self.chain.body(&id).ok().flatten(),
            // The state as of a block of the chain that can still be
            // gone back to, in its pieces (`super::snapshot`).
            Object::Manifest(block) => self.past(&block, |past| Some(Manifest::of(past).encode())),
            Object::Roots { block, index } => self.past(&block, |past| snapshot::encode_roots(past, index)),
            Object::Part { block, index } => self.past(&block, |past| {
                let outputs = past.part(index).ok().filter(|o| !o.is_empty())?;
                Some(snapshot::encode_part(&outputs, &past.commits(index).ok()?))
            }),
            Object::Names { block, index } => self.past(&block, |past| {
                let records = past.names_part(index).ok().filter(|r| !r.is_empty())?;
                Some(snapshot::encode_names(&records))
            }),
            // Nothing else is served yet.
            _ => None,
        }
    }

    /// What `make` makes of the state as of the block `block`, if that
    /// is a block of the chain here recent enough to go back to, and
    /// the state here is whole.
    fn past<T>(&self, block: &Digest, make: impl FnOnce(&crate::store::state::Past<'_, B>) -> Option<T>) -> Option<T> {
        let height = self.on_chain(block)?.height;
        let state = self.chain.whole().ok()?;
        make(&state.past(height).ok()?)
    }

    /// Fetches `object`, of `most` bytes at the most, from `from`: what
    /// comes of it is in [`Node::take_fetched`] when it has. False if
    /// `from` is no peer to ask.
    pub fn fetch_object(&mut self, now: Micros, object: Object, from: SocketAddrV4, most: u32) -> bool {
        if !self.peers.may_ask(&from, now) {
            return false;
        }
        let path = self.peers.get(&from).map(|p| p.path).unwrap_or_default();
        let transfer = Self::number(&self.secret, &mut self.numbers);
        self.fetches.push(Fetching { object, from, fetch: Fetch::new(transfer, None, most, path, now) });
        true
    }

    /// The objects asked for with [`Node::fetch_object`] that have come
    /// whole, or been given up (no bytes), since this was last called.
    pub fn take_fetched(&mut self) -> Vec<(Object, SocketAddrV4, Option<Vec<u8>>)> {
        std::mem::take(&mut self.inbox)
    }

    /// Does what the fetches under way and the chunks being served want
    /// done at `now`, and says when either next wants doing.
    fn pump(&mut self, now: Micros, out: Out<'_>) -> Micros {
        let list = Arc::clone(&self.list);
        let wake = {
            let l = &mut *write(&list);
            let mut wake = self.fetch(l, now, out);
            // A body that arrived may have been applied in place, and
            // what came of that may want more fetched: until nothing
            // does.
            while matches!(&l.applier, Applier::Here(done) if !done.is_empty()) {
                wake = self.fetch(l, now, out);
            }
            wake
        };
        self.serve_some(now, out).min(wake)
    }

    /// What became of blocks applied, and what the fetches under way
    /// want done: when a fetch next wants looking to.
    fn fetch(&mut self, l: &mut List, now: Micros, out: Out<'_>) -> Micros {
        self.applied(l, now, out);
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
                        fetched(&mut l.fetching, &object, &from);
                        self.fetch_failed(l, now, object, from);
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
                    fetched(&mut l.fetching, &object, &from);
                    self.counts.fetched += 1;
                    self.peers.delivered(&from, done.fetch.path());
                    let bytes = done.fetch.finish().expect("it is done");
                    self.arrived(l, now, object, from, &bytes);
                    continue;
                }
                Poll::Failed(why) => {
                    let failed = self.fetches.swap_remove(i);
                    fetched(&mut l.fetching, &object, &from);
                    self.peers.set_path(&from, failed.fetch.path());
                    if why == Why::Bad {
                        self.peers.strike(&from, now);
                    }
                    self.fetch_failed(l, now, object, from);
                    continue;
                }
            }
            i += 1;
        }
        wake
    }

    /// Sends some of the chunks asked of us, and says when there are
    /// more to send.
    fn serve_some(&mut self, now: Micros, out: Out<'_>) -> Micros {
        for _ in 0..SERVE_BATCH {
            match self.serve.next(now) {
                Next::Send(x) => {
                    let SocketAddr::V4(to) = x.to else { continue };
                    let bytes = Object::decode(x.name()).ok().and_then(|o| self.object(&o));
                    match bytes.as_deref().map(|b| chunk_of(b, x.index).map(|data| (b.len() as u32, data))) {
                        Some(Some((len, data))) => {
                            let chunk = Chunk { transfer: x.transfer, seq: x.seq, len, index: x.index, data };
                            self.send(to, &Message::Chunk(chunk), out);
                        }
                        // No such chunk: asked for before its length was
                        // known, past its end. The rest of what was
                        // asked is past it too.
                        Some(None) => self.serve.cancel(x.to, x.transfer),
                        // No such object.
                        None => {
                            self.serve.cancel(x.to, x.transfer);
                            self.send(to, &Message::Gone(Gone { transfer: x.transfer }), out);
                        }
                    }
                }
                Next::Wait(at) => return at,
                Next::Idle => return Micros::MAX,
            }
        }
        // More to send: at once.
        now
    }

    /// An object fetched whole from `from`.
    fn arrived(&mut self, l: &mut List, now: Micros, object: Object, from: SocketAddrV4, bytes: &[u8]) {
        if self.of_join(l, &object) {
            return self.piece_arrived(l, now, object, from, bytes);
        }
        match object {
            Object::Headers { from: first, .. } => self.headers_arrived(l, now, from, first, bytes),
            Object::Block(id) => self.body_arrived(l, now, from, id, bytes),
            // Asked for by whoever drives this node.
            _ => self.inbox.push((object, from, Some(bytes.to_vec()))),
        }
    }

    /// A fetch from `from` was given up. Of headers or a body: the peer
    /// is passed over, and what was wanted is wanted again, of another.
    /// Of anything else: whoever asked for it is told, and decides.
    fn fetch_failed(&mut self, l: &mut List, now: Micros, object: Object, from: SocketAddrV4) {
        self.counts.fetches_failed += 1;
        // Of the state being taken: asked of another, and this peer
        // not again while another can be.
        if self.of_join(l, &object) {
            if let Some(join) = l.join.as_mut() {
                join.unserved.push(from);
            }
            // (Asked again when time is next looked to, not at once: if
            // nobody has it, asking as fast as they can say so helps
            // nobody.)
            return;
        }
        if matches!(object, Object::Headers { .. } | Object::Block(_)) {
            self.peers.failed(&from, now);
        }
        match (object, l.aim.as_mut()) {
            (Object::Headers { from: first, .. }, Some(aim)) => {
                aim.todo.insert(first);
                self.fetch_headers(l, now);
            }
            (Object::Block(id), _) => {
                self.announced.retain(|(told, addr, _)| !(*told == id && *addr == from));
                self.sync_blocks(l, now);
            }
            (Object::Headers { .. }, None) => {}
            _ => self.inbox.push((object, from, None)),
        }
    }
}

/// The list, to change: whoever held it and failed left it as it was.
fn write(list: &RwLock<List>) -> RwLockWriteGuard<'_, List> {
    list.write().unwrap_or_else(|e| e.into_inner())
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
