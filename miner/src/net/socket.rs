//! A node over the machine's own socket and clock.
//!
//! Everything a node decides is in [`super::node`]; this only carries
//! datagrams between it and a socket and tells it the time.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::MAX_DATAGRAM;
use super::node::{Node, Ours, socket_addr};
use crate::transport::Micros;

/// Runs `node` over `socket` until `stop` is set, then says goodbye to
/// its peers. `ours` is asked what to say of this node's chain;
/// `every` is how often the node is told that time has passed.
pub fn run(
    node: &mut Node,
    socket: &UdpSocket,
    ours: &dyn Fn() -> Ours,
    stop: &AtomicBool,
    every: Duration,
) -> std::io::Result<()> {
    let clock = Instant::now();
    run_until(node, socket, ours, stop, every, clock)?;
    node.goodbye(clock.elapsed().as_micros() as Micros, &mut |to, bytes: &[u8]| {
        let _ = socket.send_to(bytes, socket_addr(to));
    });
    Ok(())
}

/// [`run`] without the goodbye, on a clock begun at `clock`: a node run
/// in stretches, its time going on from one to the next.
pub fn run_until(
    node: &mut Node,
    socket: &UdpSocket,
    ours: &dyn Fn() -> Ours,
    stop: &AtomicBool,
    every: Duration,
    clock: Instant,
) -> std::io::Result<()> {
    let now = || clock.elapsed().as_micros() as Micros;
    // A datagram that cannot be sent is a datagram lost, as any may be.
    let mut out = |to, bytes: &[u8]| {
        let _ = socket.send_to(bytes, socket_addr(to));
    };
    // One byte more than any datagram of ours: what fills it is not one.
    let mut buf = [0u8; MAX_DATAGRAM + 1];
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let t = Instant::now();
        if t >= next {
            node.tick(now(), &ours(), &mut out);
            next = t + every;
        }
        let wait = next.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        socket.set_read_timeout(Some(wait))?;
        // Nothing in time, or the machine's own complaint about a
        // datagram we sent, is no datagram.
        if let Ok((n, from)) = socket.recv_from(&mut buf) {
            node.handle(now(), from, &buf[..n], &ours(), &mut out);
        }
    }
    Ok(())
}
