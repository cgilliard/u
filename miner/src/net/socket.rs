//! A node over the machine's own socket and clock.
//!
//! Everything a node decides is in [`super::node`]; this only carries
//! datagrams between it and a socket and tells it the time.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::MAX_DATAGRAM;
use super::node::{CHUNK, Heard, Node, socket_addr};
use crate::logger::queued::Queued;
use crate::logger::stats::{Kind, Stats};
use crate::store::backend::Backend;
use crate::transport::Micros;

/// The time by the calendar, in seconds.
pub fn unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Runs `node` over `socket` until `stop` is set, then says goodbye to
/// its peers.
pub fn run<B: Backend + 'static, V: crate::chain::verify::ProofVerifier + Sync>(
    node: &mut Node<B, V>,
    socket: &UdpSocket,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let clock = Instant::now();
    run_until(node, socket, stop, clock, &unix)?;
    node.goodbye(clock.elapsed().as_micros() as Micros, &mut |to, bytes: &[u8]| {
        let _ = socket.send_to(bytes, socket_addr(to));
    });
    Ok(())
}

/// [`run`] without the goodbye, on a clock begun at `clock` and a
/// calendar that says `unix`: a node run in stretches, its time going
/// on from one to the next; or one whose headers are of another day.
pub fn run_until<B: Backend + 'static, V: crate::chain::verify::ProofVerifier + Sync>(
    node: &mut Node<B, V>,
    socket: &UdpSocket,
    stop: &AtomicBool,
    clock: Instant,
    unix: &dyn Fn() -> u64,
) -> std::io::Result<()> {
    run_watched(node, socket, stop, clock, unix, &Watch::default())
}

/// The numbers a node keeps of itself for its stats log, in the order
/// of their columns.
pub const STATS: &[(&str, Kind)] = &[
    ("Requests", Kind::Count),
    ("AvgLatency(us)", Kind::Average(REQUESTS)),
    ("BytesIn", Kind::Bytes),
    ("BytesSent", Kind::Bytes),
    ("Peers", Kind::Level),
    ("PeersLive", Kind::Level),
    ("Height", Kind::Level),
    ("Blocks", Kind::Count),
    ("Fetching", Kind::Level),
];
/// Datagrams taken, of whatever kind.
pub const REQUESTS: usize = 0;
/// The microseconds taking them took: shown as the average of one.
pub const LATENCY: usize = 1;
pub const BYTES_IN: usize = 2;
pub const BYTES_SENT: usize = 3;
pub const PEERS: usize = 4;
pub const PEERS_LIVE: usize = 5;
pub const HEIGHT: usize = 6;
/// Blocks that joined the chain here.
pub const BLOCKS: usize = 7;
/// Objects being fetched.
pub const FETCHING: usize = 8;

/// Who is told what a node does as it runs: neither need be there.
#[derive(Clone, Copy, Default)]
pub struct Watch<'a> {
    /// The request log: a line for each datagram taken
    /// ([`Heard::line`]), but for the chunks of what the node itself is
    /// fetching, which are counted only.
    pub requests: Option<&'a Queued>,
    /// The stats ([`STATS`]).
    pub stats: Option<&'a Stats>,
}

impl Watch<'_> {
    /// A datagram of `bytes` was taken in `micros`.
    fn heard(&self, heard: &Heard, bytes: usize, micros: u64) {
        if let Some(stats) = self.stats {
            stats.add(REQUESTS, 1);
            stats.add(LATENCY, micros);
            stats.add(BYTES_IN, bytes as u64);
        }
        if let Some(requests) = self.requests
            && heard.request != CHUNK
        {
            requests.log(&heard.line(bytes, micros));
        }
    }

    /// How the node stands at `now`.
    fn levels<B: Backend + 'static, V: crate::chain::verify::ProofVerifier + Sync>(
        &self,
        node: &Node<B, V>,
        now: Micros,
    ) {
        let Some(stats) = self.stats else { return };
        let (peers, live) = node.peer_counts(now);
        stats.set(PEERS, peers as u64);
        stats.set(PEERS_LIVE, live as u64);
        if let Ok(tip) = node.chain().tip() {
            stats.set(HEIGHT, tip.height as u64);
        }
        stats.set(BLOCKS, node.counts().blocks);
        stats.set(FETCHING, node.fetching() as u64);
    }
}

/// [`run_until`], with `watch` told of each datagram taken and how the
/// node stands.
pub fn run_watched<B: Backend + 'static, V: crate::chain::verify::ProofVerifier + Sync>(
    node: &mut Node<B, V>,
    socket: &UdpSocket,
    stop: &AtomicBool,
    clock: Instant,
    unix: &dyn Fn() -> u64,
    watch: &Watch<'_>,
) -> std::io::Result<()> {
    let now = || clock.elapsed().as_micros() as Micros;
    // A datagram that cannot be sent is a datagram lost, as any may be.
    let mut out = |to, bytes: &[u8]| {
        if let Some(stats) = watch.stats {
            stats.add(BYTES_SENT, bytes.len() as u64);
        }
        let _ = socket.send_to(bytes, socket_addr(to));
    };
    // One byte more than any datagram of ours: what fills it is not one.
    let mut buf = [0u8; MAX_DATAGRAM + 1];
    // When how the node stands was last told: once a second is enough.
    let mut told: Option<Micros> = None;
    while !stop.load(Ordering::Relaxed) {
        let t = now();
        let wake = node.tick(t, unix(), &mut out);
        if told.is_none_or(|at| t.saturating_sub(at) >= 1_000_000) {
            watch.levels(node, t);
            told = Some(t);
        }
        // Until the node wants to be called, a twentieth of a second at
        // the most (to see `stop`), or a datagram comes.
        // Sooner while work given to the applier is still to be heard of.
        let most = if node.busy() { 1_000 } else { 50_000 };
        let wait = wake.saturating_sub(t).clamp(50, most);
        socket.set_read_timeout(Some(Duration::from_micros(wait)))?;
        // Nothing in time, or the machine's own complaint about a
        // datagram we sent, is no datagram.
        let mut take = |node: &mut Node<B, V>, bytes: &[u8], from| {
            let began = now();
            let heard = node.handle(began, from, bytes, &mut out);
            watch.heard(&heard, bytes.len(), now().saturating_sub(began));
        };
        if let Ok((n, from)) = socket.recv_from(&mut buf) {
            take(node, &buf[..n], from);
            // And whatever else is waiting, before looking to the time.
            socket.set_read_timeout(Some(Duration::from_micros(1)))?;
            for _ in 0..64 {
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => take(node, &buf[..n], from),
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}
