//! Being told to stop: Ctrl-C at the terminal, or the operating
//! system's own word that the program is to end.
//!
//! This is kept as simple as it can be, since the worst a node can do
//! on being told to stop is not to. What takes the signal sets a flag
//! and returns: nothing else is safe to do there. A thread that does
//! nothing else ([`halt_when_told`]) sees the flag, says so in the main
//! log and on the terminal, and ends the program. It waits for no other
//! thread, and nothing has to be put in order first: the store is
//! whole wherever it is cut off.
//!
//! Told a second time, the program ends at once, from where the signal
//! is taken: so that even a main log that cannot be written to does
//! not keep a node alive.
//!
//! The standard library has no way to take a signal, so the C
//! library's is called: `signal`, which is there on every platform the
//! node is built for.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::logger::Logger;

/// What the node says when it is told to stop.
pub const HALTING: &str = "Received shut down signal, halting!";

/// Whether the node has been told to stop.
static TOLD: AtomicBool = AtomicBool::new(false);

/// Ctrl-C, and "end": the same numbers wherever there is a C library.
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

unsafe extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
    fn _exit(code: i32) -> !;
    #[cfg(test)]
    fn raise(signum: i32) -> i32;
}

/// Takes a signal. Only what may be done while anything else in the
/// program is cut off in the middle: a flag is set; or, the second
/// time, the program is ended there and then.
extern "C" fn on_signal(_signum: i32) {
    if TOLD.swap(true, Ordering::SeqCst) {
        // SAFETY: `_exit` may be called from anywhere, and does not
        // return.
        unsafe { _exit(-1) }
    }
}

/// Begins to listen for being told to stop.
pub fn listen() -> io::Result<()> {
    let handler = on_signal as extern "C" fn(i32) as usize;
    for signum in [SIGINT, SIGTERM] {
        // SAFETY: `on_signal` is a function of the kind `signal` calls,
        // and does only what such a function may.
        if unsafe { signal(signum, handler) } == usize::MAX {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Whether the node has been told to stop.
pub fn told() -> bool {
    TOLD.load(Ordering::SeqCst)
}

/// Listens ([`listen`]), and starts the thread that ends the program
/// when it is told to stop: [`HALTING`] is said in `main` (and on the
/// terminal, if the node has not yet said it is ready), and the
/// program ends with 0. Meanwhile the thread sees to
/// it that the main log's file is put aside when it is due, though
/// nothing is being written to it.
pub fn halt_when_told(main: Arc<Logger>) -> io::Result<()> {
    listen()?;
    std::thread::Builder::new().name("interrupt".into()).spawn(move || {
        let mut naps = 0u32;
        loop {
            if told() {
                main.log_all(HALTING);
                std::process::exit(0);
            }
            std::thread::sleep(Duration::from_millis(20));
            naps += 1;
            if naps.is_multiple_of(50) {
                main.rotate_if_due();
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signal sets the flag and nothing else: the program goes on.
    /// (One only: a second would end the tests.)
    #[test]
    fn a_signal_is_heard() {
        listen().unwrap();
        assert!(!told());
        // SAFETY: a signal that is listened for, sent to ourselves.
        assert_eq!(unsafe { raise(SIGINT) }, 0);
        // (Where signals are taken on a thread of their own, a moment.)
        for _ in 0..500 {
            if told() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(told());
    }
}
