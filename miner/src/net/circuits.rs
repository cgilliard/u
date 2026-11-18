//! Ways through relays: what a relay keeps of those that pass through
//! it, and what whoever opened one keeps of it.
//!
//! A way is opened a relay at a time ([`crate::circuit`]). Whoever
//! opens it ([`Way`]) agrees a key with the first relay; then tells it,
//! under that key, to go on to a second, and through it agrees a key
//! with the second, of which the first learns nothing; and so on to the
//! last. A relay ([`Relayed`]) keeps, of each way through it, who is
//! before it and who after, and the key of its own: it takes its
//! wrapping off what goes out and passes that on, puts its wrapping on
//! what comes back and passes that on, and reads only what is said to
//! it while it is the last.
//!
//! Nothing here sends anything: each thing done says what is to be
//! sent, to whom ([`Step`]), and the node sends it, as an object asked
//! for like any other. So the whole of it runs in a test with no
//! network at all.

use std::net::SocketAddrV4;

use crate::circuit::{self, Hop, Opening};
use crate::hash::Digest;
use crate::mldsa;
use crate::transport::{Micros, SECOND};

/// What is sent along a way, from one node of it to the next.
pub const OPEN: u8 = 1;
/// A relay's answer to an opening: to whoever asked it.
pub const OPENED: u8 = 2;
/// Something going out: wrapped for the relays still to come.
pub const FORWARD: u8 = 3;
/// Something coming back.
pub const BACK: u8 = 4;

/// What the last relay of a way is told, as the first byte of what is
/// said to it: to go on to another relay, at this address, with this
/// hello.
pub const TELL_EXTEND: u8 = 1;
/// And what it says back of that: the other relay's answer.
pub const SAID_EXTENDED: u8 = 1;
/// The first byte of anything else said either way: what follows is
/// for whoever uses the way, not for the way itself.
pub const SAID: u8 = 0x80;

/// What whoever opened a way says to its last relay to know that the
/// way still goes there, as the first byte of what is said; and what
/// the relay says back, with whatever followed it.
pub const PING: u8 = 1;
pub const PONG: u8 = 2;

/// The longest thing carried along a way.
pub const MAX_STEP: usize = crate::msg::MAX_SEALED + 256;

/// Where a relay's count of what it says back begins: a number of the
/// hello it answered, so that no two relays of a way count alike, and
/// none knows by its count how far along the way it is.
fn base(hello: &[u8]) -> u64 {
    let at = crate::mlkem::EK_LEN;
    (u32::from_le_bytes(hello[at..at + 4].try_into().expect("four bytes")) as u64) << 32
}

/// Something to send to a neighbour on a way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub to: SocketAddrV4,
    /// The number the two neighbours know the way by.
    pub circuit: u64,
    pub kind: u8,
    pub count: u64,
    pub bytes: Vec<u8>,
}

/// A way through this relay: who is before it, who after, its key.
struct Through {
    before: (SocketAddrV4, u64),
    after: Option<(SocketAddrV4, u64)>,
    hop: Hop,
    /// The highest count of anything that has gone out through here,
    /// and which of the 64 up to it have: what has been here before
    /// does not pass again, and what overtook another on the way does.
    out: u64,
    window: u64,
    /// How many things this relay itself has said back.
    said: u64,
    seen: Micros,
}

/// How a relay is bounded in the ways through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub most: usize,
    /// Ways that may come to this relay from one host.
    pub each_host: usize,
    /// How long nothing may pass along a way before it is forgotten.
    pub idle: Micros,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { most: 50_000, each_host: 64, idle: 1800 * SECOND }
    }
}

/// What came of something going out through a relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// Passed on, or an opening sent on to the next relay.
    Step(Step),
    /// Said to this relay, which is the last: for whoever uses the way,
    /// which is known by who is before this relay on it.
    Said { way: (SocketAddrV4, u64), said: Vec<u8> },
    /// Not of a way through here, or not in its turn: nothing.
    Nothing,
}

impl Through {
    /// Whether nothing of this count has gone out through here before;
    /// after which something has.
    fn fresh(&mut self, count: u64) -> bool {
        if count > self.out {
            let ahead = count - self.out;
            self.window = if ahead >= 64 { 1 } else { self.window << ahead | 1 };
            self.out = count;
            return true;
        }
        let behind = self.out - count;
        if behind >= 64 || self.window >> behind & 1 == 1 {
            return false;
        }
        self.window |= 1 << behind;
        true
    }
}

/// The ways through a relay.
pub struct Relayed {
    limits: Limits,
    through: Vec<Through>,
}

impl Relayed {
    pub fn new(limits: Limits) -> Relayed {
        Relayed { limits, through: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.through.len()
    }

    pub fn is_empty(&self) -> bool {
        self.through.is_empty()
    }

    fn of_before(&mut self, from: SocketAddrV4, circuit: u64) -> Option<&mut Through> {
        self.through.iter_mut().find(|t| t.before == (from, circuit))
    }

    /// Whoever is at `from` opens a way through this relay, known
    /// between the two as `circuit`, with `hello`: the answer, to be
    /// sent back. `identity` is the relay's key, `chance` 32 random
    /// bytes. None if it is no hello, the way is open already, or
    /// there is no room.
    pub fn open(
        &mut self,
        identity: &mldsa::SecretKey,
        from: SocketAddrV4,
        circuit: u64,
        hello: &[u8],
        chance: &[u8; 32],
        now: Micros,
    ) -> Option<Step> {
        self.prune(now);
        let of_host = self.through.iter().filter(|t| t.before.0.ip() == from.ip()).count();
        let room = self.through.len() < self.limits.most && of_host < self.limits.each_host;
        if !room || self.of_before(from, circuit).is_some() {
            return None;
        }
        let (hop, answer) = circuit::answer(identity, hello, chance)?;
        let (before, said) = ((from, circuit), base(hello));
        self.through.push(Through { before, after: None, hop, out: 0, window: 1, said, seen: now });
        Some(Step { to: from, circuit, kind: OPENED, count: 0, bytes: answer })
    }

    /// Something going out has come from `from` on `circuit`, the
    /// `count`-th of its way. Passed on to the next relay, less this
    /// one's wrapping; or, of a way this relay is the last of, opened:
    /// and gone on with to another relay, if that is what it says
    /// (`fresh` is a number to know that stretch by), or given to
    /// whoever uses the way.
    pub fn forward(
        &mut self,
        from: SocketAddrV4,
        circuit: u64,
        count: u64,
        mut bytes: Vec<u8>,
        fresh: u64,
        now: Micros,
    ) -> Out {
        let Some(way) = self.of_before(from, circuit) else { return Out::Nothing };
        if !way.fresh(count) {
            return Out::Nothing;
        }
        way.seen = now;
        if let Some((to, circuit)) = way.after {
            way.hop.peel(count, &mut bytes);
            return Out::Step(Step { to, circuit, kind: FORWARD, count, bytes });
        }
        let Some(said) = circuit::open(&way.hop, count, &bytes) else { return Out::Nothing };
        match said.split_first() {
            Some((&TELL_EXTEND, rest)) if rest.len() == 6 + circuit::HELLO_LEN => {
                let ip: [u8; 4] = rest[..4].try_into().expect("four bytes");
                let to = SocketAddrV4::new(ip.into(), u16::from_le_bytes([rest[4], rest[5]]));
                // (Not back the way it came, nor to itself.)
                if to == from {
                    return Out::Nothing;
                }
                way.after = Some((to, fresh));
                Out::Step(Step { to, circuit: fresh, kind: OPEN, count: 0, bytes: rest[6..].to_vec() })
            }
            Some((&SAID, rest)) => Out::Said { way: (from, circuit), said: rest.to_vec() },
            _ => Out::Nothing,
        }
    }

    /// The relay this one went on to, at `from` on `circuit`, has
    /// answered the opening: its answer, said back along the way.
    pub fn opened(&mut self, from: SocketAddrV4, circuit: u64, answer: &[u8], now: Micros) -> Option<Step> {
        let way = self.through.iter_mut().find(|t| t.after == Some((from, circuit)))?;
        let mut said = Vec::with_capacity(1 + answer.len());
        said.push(SAID_EXTENDED);
        said.extend_from_slice(answer);
        way.said += 1;
        way.seen = now;
        let bytes = circuit::seal_back(&way.hop, way.said, &said);
        Some(Step { to: way.before.0, circuit: way.before.1, kind: BACK, count: way.said, bytes })
    }

    /// Something coming back has come from `from` on `circuit`: passed
    /// on towards whoever opened the way, with this relay's wrapping.
    pub fn back(
        &mut self,
        from: SocketAddrV4,
        circuit: u64,
        count: u64,
        mut bytes: Vec<u8>,
        now: Micros,
    ) -> Option<Step> {
        let way = self.through.iter_mut().find(|t| t.after == Some((from, circuit)))?;
        way.seen = now;
        way.hop.cover(count, &mut bytes);
        Some(Step { to: way.before.0, circuit: way.before.1, kind: BACK, count, bytes })
    }

    /// This relay, the last of the way known by who is before it, says
    /// `said` back to whoever opened it.
    pub fn say(&mut self, way: (SocketAddrV4, u64), said: &[u8], now: Micros) -> Option<Step> {
        let way = self.of_before(way.0, way.1).filter(|t| t.after.is_none())?;
        let mut whole = Vec::with_capacity(1 + said.len());
        whole.push(SAID);
        whole.extend_from_slice(said);
        way.said += 1;
        way.seen = now;
        let bytes = circuit::seal_back(&way.hop, way.said, &whole);
        Some(Step { to: way.before.0, circuit: way.before.1, kind: BACK, count: way.said, bytes })
    }

    /// Whether the way known by who is before this relay on it is still
    /// here.
    pub fn holds(&self, way: &(SocketAddrV4, u64)) -> bool {
        self.through.iter().any(|t| t.before == *way)
    }

    /// Whether a way through here goes on to `after`, known between the
    /// two by that number.
    pub fn goes_on_to(&self, after: &(SocketAddrV4, u64)) -> bool {
        self.through.iter().any(|t| t.after == Some(*after))
    }

    /// Forgets the ways nothing has passed along for too long.
    pub fn prune(&mut self, now: Micros) {
        let idle = self.limits.idle;
        self.through.retain(|t| now.saturating_sub(t.seen) < idle);
    }
}

/// What came back along a way, to whoever opened it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Came {
    /// The way is a relay longer, and goes on: this is to be sent.
    Step(Step),
    /// The way is open to its end.
    Ready,
    /// Its last relay says this.
    Said(Vec<u8>),
    /// Not what this way was waiting for: the way is to be given up.
    Bad,
}

/// Something on its way to a neighbour, until that neighbour has asked
/// for it: it is told that it is there, again if it does not ask.
pub struct Leaving {
    /// What the neighbour asks for it by.
    pub name: u64,
    pub step: Step,
    pub bytes: std::sync::Arc<Vec<u8>>,
    pub told: Option<Micros>,
    pub asked: bool,
    pub since: Micros,
}

/// How often a neighbour that does not ask is told again, and how long
/// a thing is kept for it.
pub const TELL_AGAIN: Micros = SECOND;
pub const KEPT: Micros = 30 * SECOND;
/// How long a way may take to open.
pub const OPENING: Micros = 30 * SECOND;

/// The ways this node opened, and what has come back along them.
#[derive(Default)]
pub struct Ways {
    pub open: Vec<Way>,
    /// What the last relay of a way said: the way, and what.
    pub said: Vec<(u64, Vec<u8>)>,
    /// Ways asked for and not yet begun: the number each is to be
    /// known by, and its relays.
    pub wanted: Vec<(u64, Vec<(Digest, SocketAddrV4)>)>,
    /// What is to be said along a way, and has not yet been sent.
    pub to_say: Vec<(u64, Vec<u8>)>,
}

/// A way, as whoever opened it has it.
pub struct Way {
    circuit: u64,
    /// The relays of it, nearest first: each one's id and where it is.
    path: Vec<(Digest, SocketAddrV4)>,
    hops: Vec<Hop>,
    /// The opening of the relay being added, until it has answered.
    opening: Option<Opening>,
    /// How many things have been sent out along it.
    sent: u64,
    pub began: Micros,
    pub seen: Micros,
}

impl Way {
    /// Begins a way through `path` (nearest first, not empty), known to
    /// its first relay as `circuit`: the opening to send it. `chance`
    /// is 96 random bytes.
    pub fn begin(circuit: u64, path: Vec<(Digest, SocketAddrV4)>, chance: &[u8; 96], now: Micros) -> (Way, Step) {
        let opening = Opening::new(chance);
        let step = Step { to: path[0].1, circuit, kind: OPEN, count: 0, bytes: opening.hello().to_vec() };
        let hops = Vec::with_capacity(path.len());
        (Way { circuit, path, hops, opening: Some(opening), sent: 0, began: now, seen: now }, step)
    }

    pub fn circuit(&self) -> u64 {
        self.circuit
    }

    /// Where its first relay is.
    pub fn first(&self) -> SocketAddrV4 {
        self.path[0].1
    }

    /// The relay it ends at.
    pub fn end(&self) -> &(Digest, SocketAddrV4) {
        self.path.last().expect("a way has a relay")
    }

    /// Whether it is open to its end.
    pub fn ready(&self) -> bool {
        self.hops.len() == self.path.len()
    }

    /// The relay being added has answered with `answer`: the way is a
    /// relay longer, and goes on to the next if there is one.
    fn grown(&mut self, answer: &[u8], chance: &[u8; 96]) -> Came {
        let relay = self.path[self.hops.len()].0;
        let Some(hop) = self.opening.take().and_then(|o| o.agreed(&relay, answer)) else { return Came::Bad };
        self.hops.push(hop);
        if self.ready() {
            return Came::Ready;
        }
        let opening = Opening::new(chance);
        let next = self.path[self.hops.len()].1;
        let mut tell = Vec::with_capacity(7 + circuit::HELLO_LEN);
        tell.push(TELL_EXTEND);
        tell.extend_from_slice(&next.ip().octets());
        tell.extend_from_slice(&next.port().to_le_bytes());
        tell.extend_from_slice(opening.hello());
        self.opening = Some(opening);
        Came::Step(self.wrapped(&tell))
    }

    fn wrapped(&mut self, whole: &[u8]) -> Step {
        self.sent += 1;
        let bytes = circuit::wrap(&self.hops, self.sent, whole);
        Step { to: self.path[0].1, circuit: self.circuit, kind: FORWARD, count: self.sent, bytes }
    }

    /// The first relay has answered the opening.
    pub fn opened(&mut self, answer: &[u8], chance: &[u8; 96], now: Micros) -> Came {
        self.seen = now;
        match self.hops.is_empty() {
            true => self.grown(answer, chance),
            false => Came::Bad,
        }
    }

    /// Something has come back along the way, the `count`-th of
    /// whichever relay said it.
    pub fn back(&mut self, count: u64, bytes: &[u8], chance: &[u8; 96], now: Micros) -> Came {
        self.seen = now;
        let Some(said) = circuit::unwrap(&self.hops, count, bytes) else { return Came::Bad };
        match said.split_first() {
            Some((&SAID_EXTENDED, answer)) if !self.ready() => self.grown(answer, chance),
            Some((&SAID, rest)) if self.ready() => Came::Said(rest.to_vec()),
            _ => Came::Bad,
        }
    }

    /// Says `said` to the last relay of the way, which is open: what is
    /// to be sent.
    pub fn say(&mut self, said: &[u8]) -> Option<Step> {
        if !self.ready() {
            return None;
        }
        let mut whole = Vec::with_capacity(1 + said.len());
        whole.push(SAID);
        whole.extend_from_slice(said);
        Some(self.wrapped(&whole))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::id_of;

    fn at(host: u8) -> SocketAddrV4 {
        SocketAddrV4::new([10, 0, 0, host].into(), 3737)
    }

    /// Three relays and whoever opens a way through them, with nothing
    /// between them but what each says is to be sent.
    struct World {
        keys: Vec<mldsa::SecretKey>,
        relays: Vec<Relayed>,
        /// What each relay was given, as it was given: to see what each
        /// could know.
        given: Vec<Vec<Vec<u8>>>,
        fresh: u64,
    }

    const ME: u8 = 100;

    impl World {
        fn new() -> World {
            let keys: Vec<_> = (1..=3u8).map(|seed| mldsa::keygen(&[seed; 32])).collect();
            let relays = (0..3).map(|_| Relayed::new(Limits::default())).collect();
            World { keys, relays, given: vec![Vec::new(); 3], fresh: 1000 }
        }

        fn path(&self) -> Vec<(Digest, SocketAddrV4)> {
            (0..3).map(|i| (id_of(self.keys[i].public_key()), at(i as u8 + 1))).collect()
        }

        /// Carries `step`, sent by the node at `from`, to where it goes,
        /// and on, until something is for whoever opened the way (a
        /// step to `ME`) or for the last relay's user, or nothing is.
        fn carry(
            &mut self,
            mut from: SocketAddrV4,
            mut step: Step,
        ) -> (Option<Step>, Option<((SocketAddrV4, u64), Vec<u8>)>) {
            loop {
                if step.to == at(ME) {
                    return (Some(step), None);
                }
                let i = (step.to.ip().octets()[3] - 1) as usize;
                self.given[i].push(step.bytes.clone());
                self.fresh += 1;
                let (here, relay) = (step.to, &mut self.relays[i]);
                let next = match step.kind {
                    OPEN => relay.open(&self.keys[i], from, step.circuit, &step.bytes, &[i as u8; 32], 0),
                    OPENED => relay.opened(from, step.circuit, &step.bytes, 0),
                    BACK => relay.back(from, step.circuit, step.count, step.bytes, 0),
                    FORWARD => match relay.forward(from, step.circuit, step.count, step.bytes, self.fresh, 0) {
                        Out::Step(step) => Some(step),
                        Out::Said { way, said } => return (None, Some((way, said))),
                        Out::Nothing => None,
                    },
                    _ => None,
                };
                match next {
                    Some(next) => (from, step) = (here, next),
                    None => return (None, None),
                }
            }
        }

        /// Opens a way through all three.
        fn open(&mut self) -> Way {
            let (mut way, mut step) = Way::begin(7, self.path(), &[50; 96], 0);
            let mut chance = 51u8;
            loop {
                let (came, _) = self.carry(at(ME), step);
                let came = came.expect("an answer comes back");
                chance += 1;
                let next = match came.kind {
                    OPENED => way.opened(&came.bytes, &[chance; 96], 0),
                    _ => way.back(came.count, &came.bytes, &[chance; 96], 0),
                };
                match next {
                    Came::Step(next) => step = next,
                    Came::Ready => return way,
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    /// A way is opened through three relays, each added through those
    /// before it; what is said along it reaches the last and nobody
    /// before it; and what the last says comes back to whoever opened
    /// the way.
    #[test]
    fn a_way_is_opened_and_said_along() {
        let mut world = World::new();
        let mut way = world.open();
        assert!(way.ready() && way.first() == at(1) && way.end().1 == at(3));
        assert_eq!(world.relays.iter().map(Relayed::len).collect::<Vec<_>>(), [1, 1, 1]);
        // Said to the last.
        let secret = b"what is said to the node the wallet is reached at";
        world.given.iter_mut().for_each(Vec::clear);
        let step = way.say(secret).unwrap();
        let (_, said) = world.carry(at(ME), step);
        let (known_by, said) = said.expect("it reaches the last relay");
        assert_eq!((known_by.0, &said[..]), (at(2), &secret[..]));
        // Each relay was given something else, and none of it reads.
        let given: Vec<&Vec<u8>> = world.given.iter().map(|g| &g[0]).collect();
        assert!(given[0] != given[1] && given[1] != given[2] && given[0] != given[2]);
        assert!(given.iter().all(|g| !g.windows(secret.len()).any(|w| w == secret)));
        // Said back by the last: through the second and the first.
        let answer = b"and what it says back";
        let step = world.relays[2].say(known_by, answer, 0).unwrap();
        let (came, _) = world.carry(at(3), step);
        let came = came.unwrap();
        assert_eq!((came.to, came.circuit, came.kind), (at(ME), 7, BACK));
        assert_eq!(way.back(came.count, &came.bytes, &[0; 96], 0), Came::Said(answer.to_vec()));
        // Again, and again: each in its turn.
        for round in 0..3u8 {
            let step = way.say(&[round; 40]).unwrap();
            assert_eq!(world.carry(at(ME), step).1.unwrap().1, [round; 40]);
            let step = world.relays[2].say(known_by, &[round; 9], 0).unwrap();
            let came = world.carry(at(3), step).0.unwrap();
            assert_eq!(way.back(came.count, &came.bytes, &[0; 96], 0), Came::Said(vec![round; 9]));
        }
    }

    /// What does not belong on a way does nothing: said again, it has
    /// been here before; from elsewhere, it is of no way; changed, it
    /// opens to nothing. And a relay that is not the one named is not
    /// gone through.
    #[test]
    fn what_is_not_of_a_way_does_nothing() {
        let mut world = World::new();
        let mut way = world.open();
        let step = way.say(b"once").unwrap();
        assert!(world.carry(at(ME), step.clone()).1.is_some());
        // The same again: the first relay has seen that count.
        assert_eq!(world.carry(at(ME), step.clone()), (None, None));
        // One that overtook another: both pass, each once.
        let (first, second) = (way.say(b"a").unwrap(), way.say(b"b").unwrap());
        assert_eq!(world.carry(at(ME), second.clone()).1.unwrap().1, b"b");
        assert_eq!(world.carry(at(ME), first.clone()).1.unwrap().1, b"a");
        assert_eq!(world.carry(at(ME), first), (None, None));
        assert_eq!(world.carry(at(ME), second), (None, None));
        // From another address, or on another number.
        let later = way.say(b"twice").unwrap();
        assert_eq!(world.carry(at(99), later.clone()), (None, None));
        assert_eq!(world.carry(at(ME), Step { circuit: 8, ..later.clone() }), (None, None));
        // Changed on the way: the last relay opens nothing. (And the
        // count is spent: the true one, sent after, is too late.)
        let mut changed = later.clone();
        changed.bytes[0] ^= 1;
        assert_eq!(world.carry(at(ME), changed), (None, None));
        assert_eq!(world.carry(at(ME), later), (None, None));
        let after = way.say(b"thrice").unwrap();
        assert!(world.carry(at(ME), after).1.is_some());
        // The same way opened twice: once.
        let (_, again) = Way::begin(7, world.path(), &[50; 96], 0);
        assert_eq!(world.carry(at(ME), again), (None, None));
        // A way through a relay that is another than the list names:
        // its answer is not taken.
        let mut wrong = world.path();
        wrong[0].0 = id_of(world.keys[1].public_key());
        let (mut way, step) = Way::begin(9, wrong, &[60; 96], 0);
        let came = world.carry(at(ME), step).0.unwrap();
        assert_eq!(way.opened(&came.bytes, &[61; 96], 0), Came::Bad);
        // What comes back that is not of the way.
        let mut way = world.open_other(11);
        assert_eq!(way.back(1, b"nothing", &[0; 96], 0), Came::Bad);
        assert_eq!(way.say(b"x").map(|s| s.kind), Some(FORWARD));
        // A relay forgets a way nothing passes along.
        world.relays[0].prune(Limits::default().idle);
        assert!(world.relays[0].is_empty());
        assert!(!world.relays[0].holds(&(at(ME), 7)));
    }

    impl World {
        fn open_other(&mut self, circuit: u64) -> Way {
            let (mut way, mut step) = Way::begin(circuit, self.path(), &[70; 96], 0);
            loop {
                let came = self.carry(at(ME), step).0.expect("an answer comes back");
                let next = match came.kind {
                    OPENED => way.opened(&came.bytes, &[71; 96], 0),
                    _ => way.back(came.count, &came.bytes, &[72; 96], 0),
                };
                match next {
                    Came::Step(next) => step = next,
                    Came::Ready => return way,
                    other => panic!("{other:?}"),
                }
            }
        }
    }
}
