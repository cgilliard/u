//! Who is to be reached where: the sessions a node holds for wallets,
//! and the sessions a wallet keeps at nodes.
//!
//! A wallet that is to be reached says so to the nodes it is reached at
//! ([`crate::msg::points`]), now and then, for as long as it is to be:
//! "I am the wallet of this id, and what I last announced has this
//! number" ([`crate::net::message::Message::Session`]). A node that
//! holds sessions ([`Sessions`]) asks for the announcement if it has
//! not got it, checks it, and from then on knows where that wallet is:
//! what is offered for it is passed on there, and whoever asks is
//! given its announcement. A wallet that stops saying so is forgotten.
//! Nothing is kept for a wallet that is not there.
//!
//! A node holds only so many sessions, and only so many of one host:
//! ids cost nothing to make, and room for them is not given away to
//! whoever asks for most.

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

use crate::hash::Digest;
use crate::msg::{self, Announced};
use crate::poseidon2::digest_to_bytes;
use crate::transport::{Micros, SECOND};
use crate::{mldsa, mlkem};

/// How a node that holds sessions is bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Sessions held in all.
    pub most: usize,
    /// Sessions of one host.
    pub each_host: usize,
    /// How long a wallet may say nothing before it is forgotten.
    pub idle: Micros,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { most: 10_000, each_host: 16, idle: 90 * SECOND }
    }
}

/// Where a wallet a session is held for is: at an address, which it
/// says so from; or at the far end of a way through relays that ends
/// at this node, known by who is before this node on it
/// ([`super::circuits`]), and then this node does not know where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Where {
    Addr(SocketAddrV4),
    Way(SocketAddrV4, u64),
}

impl From<SocketAddrV4> for Where {
    fn from(addr: SocketAddrV4) -> Where {
        Where::Addr(addr)
    }
}

/// A wallet a node holds a session for.
#[derive(Clone, Debug)]
pub struct Session {
    pub at: Where,
    pub seq: u64,
    /// What it announced, as it said it.
    pub announce: Arc<Vec<u8>>,
    /// When it last said it was there.
    pub seen: Micros,
}

/// Why an announcement was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not an announcement, not signed by its key, or past its time.
    Unsound,
    /// Not made for this node to take from that address.
    NotBound,
    /// Older than the one held.
    Stale,
    /// No room: of that host, or at all.
    Full,
}

/// The sessions a node holds.
pub struct Sessions {
    limits: Limits,
    held: BTreeMap<[u8; 32], Session>,
}

impl Sessions {
    pub fn new(limits: Limits) -> Sessions {
        Sessions { limits, held: BTreeMap::new() }
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The wallet of id `id` says, from `addr`, that it is there and
    /// what it last announced has the number `seq`. True if that is the
    /// announcement held, from that address: the session goes on. If
    /// not, the announcement is to be asked for.
    pub fn seen(&mut self, id: &Digest, at: impl Into<Where>, seq: u64, now: Micros) -> bool {
        let at = at.into();
        match self.held.get_mut(&digest_to_bytes(id)) {
            Some(session) if session.at == at && session.seq == seq => {
                session.seen = now;
                true
            }
            _ => false,
        }
    }

    /// Takes an announcement that came from `addr`: at `unix` by the
    /// calendar, `now` by the clock. `bound` says whether a token is
    /// this node's for that address. The id of the wallet whose session
    /// it opens, or goes on with.
    pub fn admit(
        &mut self,
        announce: Vec<u8>,
        at: impl Into<Where>,
        bound: impl FnOnce(u64) -> bool,
        unix: u64,
        now: Micros,
    ) -> Result<Digest, Refused> {
        let at = at.into();
        let said = Announced::read(&announce, unix).ok_or(Refused::Unsound)?;
        if !bound(said.bind()) {
            return Err(Refused::NotBound);
        }
        let (id, seq) = (said.id(), said.seq());
        let key = digest_to_bytes(&id);
        self.prune(now);
        match self.held.get(&key) {
            Some(held) if held.seq >= seq => return Err(Refused::Stale),
            Some(_) => {}
            None => {
                // (Of one host: of those that say so from an address.
                // Who is at the end of a way is of no host this node
                // knows, and the ways are bounded where they are made.)
                let host = |at: &Where| match at {
                    Where::Addr(addr) => Some(*addr.ip()),
                    Where::Way(..) => None,
                };
                let of_host = match host(&at) {
                    Some(ip) => self.held.values().filter(|s| host(&s.at) == Some(ip)).count(),
                    None => 0,
                };
                if self.held.len() >= self.limits.most || of_host >= self.limits.each_host {
                    return Err(Refused::Full);
                }
            }
        }
        self.held.insert(key, Session { at, seq, announce: Arc::new(announce), seen: now });
        Ok(id)
    }

    /// The session held for the wallet of id `id`, if it has said it
    /// was there lately enough.
    pub fn get(&self, id: &Digest, now: Micros) -> Option<&Session> {
        self.held.get(&digest_to_bytes(id)).filter(|s| now.saturating_sub(s.seen) < self.limits.idle)
    }

    /// Forgets the wallets that have said nothing for too long.
    pub fn prune(&mut self, now: Micros) {
        let idle = self.limits.idle;
        self.held.retain(|_, s| now.saturating_sub(s.seen) < idle);
    }
}

/// How long a wallet's Kyber key is announced for before another is
/// made, and how long the one before it still opens what was sealed to
/// it.
const KEY_LIFE: Micros = 3600 * SECOND;
const KEY_GRACE: Micros = 600 * SECOND;
/// How long an announcement holds, in seconds: past a key's life, so
/// that what was sealed just before another was made is still answered.
const ANNOUNCE_HOLDS: u64 = 2 * 3600;
/// Between sayings to a node that does not yet hold the announcement.
const UNHELD_RETRY: Micros = 2 * SECOND;

/// A wallet's side: its keys, and what it has announced to each node it
/// is reached at.
pub struct Participant {
    identity: mldsa::SecretKey,
    id: Digest,
    kyber: mlkem::SecretKey,
    made: Micros,
    /// The key before, and until when it still opens.
    before: Option<(mlkem::SecretKey, Micros)>,
    /// To each node: the announcement made for it, the token it was
    /// bound to, its number, and the number that node last said it
    /// holds.
    said: BTreeMap<SocketAddrV4, Said>,
    /// The number of the last announcement made: the next is higher.
    last: u64,
}

struct Said {
    /// The node's token for this wallet's node: none (zero) until the
    /// node has said it.
    bind: u64,
    seq: u64,
    announce: Arc<Vec<u8>>,
    held: u64,
    asked: Micros,
}

impl Participant {
    /// The wallet whose Dilithium key is `identity`, at `now`. `chance`
    /// is 64 random bytes, for its first Kyber key.
    pub fn new(identity: mldsa::SecretKey, chance: &[u8; 64], now: Micros) -> Participant {
        let id = crate::address::id_of(identity.public_key());
        let kyber = mlkem::keygen(chance);
        Participant { identity, id, kyber, made: now, before: None, said: BTreeMap::new(), last: 0 }
    }

    pub fn id(&self) -> Digest {
        self.id
    }

    pub fn identity(&self) -> &mldsa::SecretKey {
        &self.identity
    }

    /// Makes another Kyber key if the one there is has been announced
    /// long enough: every announcement is then to be made again.
    /// `chance` is 64 random bytes.
    pub fn rotate(&mut self, chance: &[u8; 64], now: Micros) -> bool {
        if now.saturating_sub(self.made) < KEY_LIFE {
            return false;
        }
        let old = std::mem::replace(&mut self.kyber, mlkem::keygen(chance));
        self.before = Some((old, now + KEY_GRACE));
        self.made = now;
        self.said.clear();
        true
    }

    /// Whether it is time to say again to the node at `node` that this
    /// wallet is there: every `keepalive` while the node holds what was
    /// announced to it, and sooner until it does.
    pub fn due(&self, node: &SocketAddrV4, now: Micros, keepalive: Micros) -> bool {
        match self.said.get(node) {
            Some(said) if said.seq != 0 && said.held == said.seq => now.saturating_sub(said.asked) >= keepalive,
            Some(said) => now.saturating_sub(said.asked) >= UNHELD_RETRY,
            None => true,
        }
    }

    /// The token the node at `node` gave for this wallet's node: none
    /// (zero) before it has given one.
    pub fn token(&self, node: &SocketAddrV4) -> u64 {
        self.said.get(node).map_or(0, |s| s.bind)
    }

    /// The node at `node` is asked for its token, having given none
    /// yet: so that it is not asked again at once.
    pub fn greet(&mut self, node: SocketAddrV4, now: Micros) {
        let none = Said { bind: 0, seq: 0, announce: Arc::new(Vec::new()), held: u64::MAX, asked: now };
        self.said.entry(node).or_insert(none).asked = now;
    }

    /// What is to be said to the node at `node`, whose token for this
    /// wallet is `token`: the number of the announcement made for it,
    /// which is made now if there is none, or if the token is another
    /// than it was bound to. `unix` is the time by the calendar, in
    /// seconds: a number that only rises is made of it (so that it
    /// rises from one run of the node to the next, too).
    pub fn say(&mut self, node: SocketAddrV4, token: u64, unix: u64, now: Micros) -> u64 {
        let fresh = self.said.get(&node).is_none_or(|s| s.bind != token || s.seq == 0);
        if fresh {
            let stamp = (unix << 20).max(self.last + 1);
            self.last = stamp;
            let ek: [u8; mlkem::EK_LEN] = self.kyber.public_key().try_into().expect("a key's length");
            let announce = msg::announce(&self.identity, &ek, stamp, unix + ANNOUNCE_HOLDS, token);
            let said = Said { bind: token, seq: stamp, announce: Arc::new(announce), held: 0, asked: now };
            self.said.insert(node, said);
        }
        let said = self.said.get_mut(&node).expect("it was put there");
        said.asked = now;
        said.seq
    }

    /// The announcement of the number `seq`, for whoever asks: one made
    /// for some node, and still the one for it.
    pub fn announced(&self, seq: u64) -> Option<Arc<Vec<u8>>> {
        self.said.values().find(|s| s.seq == seq && seq != 0).map(|s| Arc::clone(&s.announce))
    }

    /// An announcement of this wallet's that holds now: what a message
    /// it sends carries, for the answer to be sealed to.
    pub fn announced_any(&self) -> Option<Arc<Vec<u8>>> {
        self.said.values().filter(|s| s.seq != 0).max_by_key(|s| s.seq).map(|s| Arc::clone(&s.announce))
    }

    /// The announcement made for the node at `node`, if one was.
    pub fn announced_to(&self, node: &SocketAddrV4) -> Option<Arc<Vec<u8>>> {
        self.said.get(node).filter(|s| s.seq != 0).map(|s| Arc::clone(&s.announce))
    }

    /// The node at `node` says it holds the announcement of number
    /// `seq` for this wallet, and that its token for this wallet's node
    /// is `token`. True if that token is another than it was known to
    /// have: it is then to be told again at once, with that one.
    pub fn held(&mut self, node: &SocketAddrV4, seq: u64, token: u64) -> bool {
        let Some(said) = self.said.get_mut(node) else { return false };
        // (Of an announcement made for another token it holds nothing
        // that counts.)
        said.held = if said.seq == 0 { u64::MAX } else { seq };
        let other = token != 0 && said.bind != token;
        if other {
            (said.bind, said.seq, said.held) = (token, 0, u64::MAX);
        }
        other
    }

    /// Whether the node at `node` holds what was last announced to it.
    pub fn is_held(&self, node: &SocketAddrV4) -> bool {
        self.said.get(node).is_some_and(|s| s.seq != 0 && s.held == s.seq)
    }

    /// The nodes this wallet is reached at now: those that hold what it
    /// last announced to them.
    pub fn reached_at(&self) -> impl Iterator<Item = SocketAddrV4> + '_ {
        self.said.iter().filter(|(_, s)| s.seq != 0 && s.held == s.seq).map(|(node, _)| *node)
    }

    /// The nodes it has said it is there to, whether or not they hold
    /// its announcement.
    pub fn said_to(&self) -> usize {
        self.said.len()
    }

    /// No longer says anything to the nodes that are not of `points`.
    pub fn keep(&mut self, points: &[SocketAddrV4]) {
        self.said.retain(|node, _| points.contains(node));
    }

    /// Opens a message sealed to this wallet, at `unix` by the calendar
    /// and `now` by the clock: with the key it announces, or the one
    /// before while that still opens.
    pub fn open(&self, sealed: &[u8], unix: u64, now: Micros) -> Option<msg::Opened> {
        let before = self.before.as_ref().filter(|(_, until)| now < *until).map(|(key, _)| key);
        [Some(&self.kyber), before].into_iter().flatten().find_map(|key| msg::open(key, &self.id, sealed, unix))
    }
}

/// How long a message is tried before it is given up, and how long
/// between tries.
pub const POST_HOLDS: Micros = 60 * SECOND;
pub const POST_RETRY: Micros = 3 * SECOND;
/// How long a node that passes a message on keeps it for the wallet it
/// is for to ask for, and how many bytes of such it keeps at the most.
const PASSING_HOLDS: Micros = 60 * SECOND;
const PASSING_BYTES: usize = 32 << 20;

/// What became of a message sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posted {
    /// Still being tried.
    Waiting,
    /// Passed on to the wallet it is for, by a node it is reached at.
    Passed,
    /// That wallet is not there to take it.
    Offline,
    /// No node it is reached at took it, in the time there was.
    Unsent,
}

/// A message this node's wallet is sending.
pub struct Post {
    pub to: Digest,
    pub kind: u8,
    pub body: Vec<u8>,
    /// What whoever posted it knows it by (a slate's id): given back
    /// with what became of it.
    pub tag: [u8; 32],
    /// The announcement of the wallet it is for, where that is known
    /// already (an answer is sealed to what the message answered
    /// carried); else it is asked for.
    pub known: Option<Vec<u8>>,
    /// Sealed, once it is: its id and its bytes.
    pub sealed: Option<(Digest, Arc<Vec<u8>>)>,
    /// When it was first looked to: not known to whoever posted it.
    pub began: Option<Micros>,
    /// When it was last tried, and of which of the wallet's nodes next.
    pub tried: Option<Micros>,
    pub turn: usize,
    /// Of how many of the wallet's nodes it has been asked what the
    /// wallet announced, and they had nothing.
    pub missed: usize,
    pub state: Posted,
}

/// The messages of a node: those its wallet sends, those it passes on
/// for others, and those that have come for its wallet.
#[derive(Default)]
pub struct Mail {
    pub posts: Vec<Post>,
    /// Sealed messages being passed on: id, whom for, the bytes, when
    /// taken.
    passing: std::collections::VecDeque<(Digest, Digest, Arc<Vec<u8>>, Micros)>,
    /// What has come for this node's wallet, opened.
    pub inbox: Vec<msg::Opened>,
    /// The ids of the sealed messages that have come, so that one is
    /// taken once.
    seen: std::collections::VecDeque<Digest>,
    /// What became of the messages sent, for whoever sent them.
    pub posted: Vec<(Digest, u8, [u8; 32], Posted)>,
}

impl Mail {
    /// A message to send.
    pub fn post(&mut self, to: Digest, kind: u8, tag: [u8; 32], body: Vec<u8>, known: Option<Vec<u8>>) {
        let (sealed, tried, turn, state) = (None, None, 0, Posted::Waiting);
        self.posts.push(Post { to, kind, body, tag, known, sealed, began: None, tried, turn, missed: 0, state });
    }

    /// Says what became of the post at `at`, and lets it go.
    pub fn settle(&mut self, at: usize, state: Posted) {
        let post = self.posts.swap_remove(at);
        self.posted.push((post.to, post.kind, post.tag, state));
    }

    /// Gives up the messages that have been tried for long enough.
    pub fn expire(&mut self, now: Micros) {
        self.posts.iter_mut().for_each(|p| p.began = p.began.or(Some(now)));
        let old = |p: &Post| p.began.is_some_and(|began| now.saturating_sub(began) >= POST_HOLDS);
        while let Some(at) = self.posts.iter().position(old) {
            self.settle(at, Posted::Unsent);
        }
        while self.passing.front().is_some_and(|p| now.saturating_sub(p.3) >= PASSING_HOLDS) {
            self.passing.pop_front();
        }
    }

    /// Keeps a sealed message to pass on to the wallet of id `to`.
    pub fn pass(&mut self, id: Digest, to: Digest, sealed: Vec<u8>, now: Micros) {
        if self.passing.iter().any(|p| p.0 == id) {
            return;
        }
        self.passing.push_back((id, to, Arc::new(sealed), now));
        while self.passing.iter().map(|p| p.2.len()).sum::<usize>() > PASSING_BYTES {
            self.passing.pop_front();
        }
    }

    /// The sealed message of id `id`: one this node sends, or passes on.
    pub fn sealed(&self, id: &Digest) -> Option<Arc<Vec<u8>>> {
        let own = self.posts.iter().filter_map(|p| p.sealed.as_ref()).find(|s| s.0 == *id).map(|s| Arc::clone(&s.1));
        own.or_else(|| self.passing.iter().find(|p| p.0 == *id).map(|p| Arc::clone(&p.2)))
    }

    /// Whether the sealed message of id `id` has come before; it has
    /// now.
    pub fn seen(&mut self, id: Digest) -> bool {
        if self.seen.contains(&id) {
            return true;
        }
        self.seen.push_back(id);
        if self.seen.len() > 1024 {
            self.seen.pop_front();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(host: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new([10, 0, 0, host].into(), port)
    }

    fn wallet(seed: u8) -> Participant {
        Participant::new(mldsa::keygen(&[seed; 32]), &[seed; 64], 0)
    }

    /// A node holds a session for a wallet once it has its announcement,
    /// made for that node and come from where the wallet is; goes on
    /// with it while the wallet says it is there; takes a newer
    /// announcement, never an older; and forgets a wallet that has
    /// said nothing for too long.
    #[test]
    fn a_session_is_opened_gone_on_with_and_forgotten() {
        let mut sessions = Sessions::new(Limits { most: 3, each_host: 2, idle: 90 * SECOND });
        let mut alice = wallet(1);
        let (node, home) = (at(9, 3737), at(1, 4000));
        let seq = alice.say(node, 77, 1000, 0);
        assert_eq!(alice.say(node, 77, 1001, SECOND), seq, "the same token: the same announcement");
        assert!(!alice.due(&node, 2 * SECOND, 30 * SECOND) && alice.due(&node, 3 * SECOND, 30 * SECOND));
        let said = alice.announced(seq).unwrap();
        // Not held yet: asked for, then taken.
        assert!(!sessions.seen(&alice.id(), home, seq, 0));
        assert_eq!(sessions.admit(said.to_vec(), home, |bind| bind == 77, 1000, 0), Ok(alice.id()));
        assert!(sessions.seen(&alice.id(), home, seq, 10 * SECOND));
        assert_eq!(sessions.get(&alice.id(), 20 * SECOND).unwrap().at, Where::Addr(home));
        assert_eq!(sessions.get(&alice.id(), 20 * SECOND).unwrap().announce, said);
        // From another address, or of another number: not that session.
        assert!(!sessions.seen(&alice.id(), at(2, 4000), seq, 20 * SECOND));
        assert!(!sessions.seen(&alice.id(), home, seq + 1, 20 * SECOND));
        // Not made for this node; said again, the same; past its time;
        // or changed: not taken.
        let taken = |sessions: &mut Sessions, bytes: &[u8], bind: u64, unix: u64| {
            sessions.admit(bytes.to_vec(), home, |b| b == bind, unix, 20 * SECOND)
        };
        assert_eq!(taken(&mut sessions, &said, 78, 1000), Err(Refused::NotBound));
        assert_eq!(taken(&mut sessions, &said, 77, 1000), Err(Refused::Stale));
        assert_eq!(taken(&mut sessions, &said, 77, 1000 + ANNOUNCE_HOLDS), Err(Refused::Unsound));
        assert_eq!(taken(&mut sessions, &said[1..], 77, 1000), Err(Refused::Unsound));
        // The node's token for it is another (the wallet moved, or the
        // node's tokens did): announced again, with a higher number,
        // and taken in place of the first.
        let again = alice.say(node, 80, 1100, 30 * SECOND);
        assert!(again > seq);
        let newer = alice.announced(again).unwrap();
        assert_eq!(taken(&mut sessions, &newer, 80, 1100), Ok(alice.id()));
        assert!(sessions.seen(&alice.id(), home, again, 30 * SECOND) && sessions.len() == 1);
        // Said nothing for too long: forgotten.
        assert!(sessions.get(&alice.id(), 119 * SECOND).is_some());
        assert!(sessions.get(&alice.id(), 120 * SECOND).is_none());
        sessions.prune(120 * SECOND);
        assert!(sessions.is_empty());
    }

    /// Room is not given away: so many sessions of one host, and so
    /// many in all; a wallet already there is not turned out by it.
    #[test]
    fn sessions_are_bounded_by_host_and_in_all() {
        let mut sessions = Sessions::new(Limits { most: 3, each_host: 2, idle: 90 * SECOND });
        let node = at(9, 3737);
        let open = |sessions: &mut Sessions, seed: u8, from: SocketAddrV4, unix: u64| {
            let mut w = wallet(seed);
            let seq = w.say(node, 1, unix, 0);
            sessions.admit(w.announced(seq).unwrap().to_vec(), from, |_| true, unix, 0).map(|_| ())
        };
        assert_eq!(open(&mut sessions, 1, at(1, 1), 1000), Ok(()));
        assert_eq!(open(&mut sessions, 2, at(1, 2), 1000), Ok(()));
        assert_eq!(open(&mut sessions, 3, at(1, 3), 1000), Err(Refused::Full), "a third of one host");
        assert_eq!(open(&mut sessions, 3, at(2, 3), 1000), Ok(()));
        assert_eq!(open(&mut sessions, 4, at(3, 1), 1000), Err(Refused::Full), "a fourth in all");
        // One that is there announces again: it has its place.
        assert_eq!(open(&mut sessions, 1, at(1, 1), 1001), Ok(()));
        assert_eq!(sessions.len(), 3);
    }

    /// A wallet opens what is sealed to the key it announces; makes
    /// another key in time, and still opens, for a while, what was
    /// sealed to the one before.
    #[test]
    fn a_wallet_opens_what_is_sealed_to_its_keys() {
        let (mut alice, mut bob) = (wallet(1), wallet(2));
        let node = at(9, 3737);
        let said = bob.say(node, 1, 1000, 0);
        let own = bob.announced(said).unwrap();
        let seq = alice.say(node, 2, 1000, 0);
        let to = alice.announced(seq).unwrap();
        let sealed =
            msg::seal(bob.identity(), &own, &Announced::read(&to, 1000).unwrap(), 1, b"hello", &[3; 32]).unwrap();
        assert_eq!(alice.open(&sealed, 1000, 0).unwrap().body, b"hello");
        assert_eq!(bob.open(&sealed, 1000, 0), None);
        // Not yet time for another key; then it is, and everything is
        // announced again.
        assert!(!alice.rotate(&[9; 64], KEY_LIFE - 1));
        assert!(alice.rotate(&[9; 64], KEY_LIFE));
        assert_eq!((alice.said_to(), alice.announced(seq)), (0, None));
        assert_ne!(alice.say(node, 2, 5000, KEY_LIFE), seq);
        assert_eq!(alice.open(&sealed, 1000, KEY_LIFE + KEY_GRACE - 1).unwrap().body, b"hello");
        assert_eq!(alice.open(&sealed, 1000, KEY_LIFE + KEY_GRACE), None);
        // Which nodes hold what it last said; and one that does is told
        // again only now and then.
        assert_eq!(alice.reached_at().count(), 0);
        let now = alice.say(node, 2, 5000, KEY_LIFE);
        assert!(!alice.held(&node, now, 2));
        assert_eq!(alice.reached_at().collect::<Vec<_>>(), [node]);
        assert!(!alice.due(&node, KEY_LIFE + 29 * SECOND, 30 * SECOND));
        assert!(alice.due(&node, KEY_LIFE + 30 * SECOND, 30 * SECOND));
        // The node's token for it is another: what it holds counts for
        // nothing until it has an announcement made for that one.
        assert!(alice.held(&node, now, 3));
        assert_eq!((alice.token(&node), alice.reached_at().count()), (3, 0));
        assert!(alice.due(&node, KEY_LIFE + 40 * SECOND, 30 * SECOND));
        let again = alice.say(node, 3, 5000, KEY_LIFE + 40 * SECOND);
        assert!(again > now && !alice.held(&node, again, 3));
        assert_eq!(alice.reached_at().collect::<Vec<_>>(), [node]);
        // And a node not yet heard from: asked for its token, and not
        // again at once.
        let (mut carol, far) = (wallet(3), at(8, 3737));
        assert!(carol.due(&far, 0, 30 * SECOND) && carol.token(&far) == 0);
        carol.greet(far, 0);
        assert!(!carol.due(&far, SECOND, 30 * SECOND) && carol.due(&far, 2 * SECOND, 30 * SECOND));
        assert_eq!((carol.said_to(), carol.reached_at().count(), carol.announced(0)), (1, 0, None));
        assert!(carol.held(&far, 0, 9));
        assert_eq!(carol.token(&far), 9);
        alice.keep(&[]);
        assert_eq!(alice.said_to(), 0);
    }
}
