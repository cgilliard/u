//! A node over the machine's own socket and clock.
//!
//! Everything a node decides is in [`super::node`]; this only carries
//! datagrams between it and a socket and tells it the time.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::MAX_DATAGRAM;
use super::node::{Node, socket_addr};
use crate::store::backend::Backend;
use crate::transport::Micros;

/// The time by the calendar, in seconds.
fn unix() -> u64 {
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
    let now = || clock.elapsed().as_micros() as Micros;
    // A datagram that cannot be sent is a datagram lost, as any may be.
    let mut out = |to, bytes: &[u8]| {
        let _ = socket.send_to(bytes, socket_addr(to));
    };
    // One byte more than any datagram of ours: what fills it is not one.
    let mut buf = [0u8; MAX_DATAGRAM + 1];
    while !stop.load(Ordering::Relaxed) {
        let t = now();
        let wake = node.tick(t, unix(), &mut out);
        // Until the node wants to be called, a twentieth of a second at
        // the most (to see `stop`), or a datagram comes.
        // Sooner while work given to the applier is still to be heard of.
        let most = if node.busy() { 1_000 } else { 50_000 };
        let wait = wake.saturating_sub(t).clamp(50, most);
        socket.set_read_timeout(Some(Duration::from_micros(wait)))?;
        // Nothing in time, or the machine's own complaint about a
        // datagram we sent, is no datagram.
        if let Ok((n, from)) = socket.recv_from(&mut buf) {
            node.handle(now(), from, &buf[..n], &mut out);
            // And whatever else is waiting, before looking to the time.
            socket.set_read_timeout(Some(Duration::from_micros(1)))?;
            for _ in 0..64 {
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => node.handle(now(), from, &buf[..n], &mut out),
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}
