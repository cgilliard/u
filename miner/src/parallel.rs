//! Minimal data parallelism over scoped threads.
//!
//! Work is split into contiguous ranges, one per thread, so the helpers
//! suit loops whose iterations cost about the same. The thread count is
//! `available_parallelism`, overridable with the `TABMINER_THREADS`
//! environment variable; small inputs run on the calling thread.

use std::sync::OnceLock;

/// Number of worker threads.
pub fn threads() -> usize {
    static THREADS: OnceLock<usize> = OnceLock::new();
    *THREADS.get_or_init(|| {
        std::env::var("TABMINER_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
    })
}

/// Below this many items a loop runs serially.
const MIN_PARALLEL: usize = 1024;

/// Splits `0..n` into at most `threads()` contiguous ranges.
fn ranges(n: usize, min_per_thread: usize) -> Vec<std::ops::Range<usize>> {
    let t = threads().min(n / min_per_thread.max(1)).max(1);
    let per = n.div_ceil(t);
    (0..t).map(|k| (k * per).min(n)..((k + 1) * per).min(n)).filter(|r| !r.is_empty()).collect()
}

/// `(0..n).map(f)` evaluated in parallel.
pub fn par_map<T: Send, F: Fn(usize) -> T + Sync>(n: usize, f: F) -> Vec<T> {
    par_map_min(n, MIN_PARALLEL, f)
}

/// As [`par_map`], but with an explicit serial threshold: parallel only
/// when at least `min_per_thread` items fall to each thread.
pub fn par_map_min<T: Send, F: Fn(usize) -> T + Sync>(n: usize, min_per_thread: usize, f: F) -> Vec<T> {
    let ranges = ranges(n, min_per_thread);
    if ranges.len() <= 1 {
        return (0..n).map(f).collect();
    }
    let f = &f;
    let parts: Vec<Vec<T>> = std::thread::scope(|s| {
        let handles: Vec<_> = ranges.into_iter().map(|r| s.spawn(move || r.map(f).collect::<Vec<T>>())).collect();
        handles.into_iter().map(|h| h.join().expect("worker panicked")).collect()
    });
    let mut out = Vec::with_capacity(n);
    for p in parts {
        out.extend(p);
    }
    out
}

/// As [`par_map`], with per-thread state made by `init` and passed to
/// every call (scratch buffers, say).
pub fn par_map_with<S, T: Send, I: Fn() -> S + Sync, F: Fn(&mut S, usize) -> T + Sync>(
    n: usize,
    init: I,
    f: F,
) -> Vec<T> {
    let ranges = ranges(n, MIN_PARALLEL);
    if ranges.len() <= 1 {
        let mut state = init();
        return (0..n).map(|i| f(&mut state, i)).collect();
    }
    let (f, init) = (&f, &init);
    let parts: Vec<Vec<T>> = std::thread::scope(|s| {
        let handles: Vec<_> = ranges
            .into_iter()
            .map(|r| {
                s.spawn(move || {
                    let mut state = init();
                    r.map(|i| f(&mut state, i)).collect::<Vec<T>>()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("worker panicked")).collect()
    });
    let mut out = Vec::with_capacity(n);
    for p in parts {
        out.extend(p);
    }
    out
}

/// Runs `f(chunk_index, chunk)` over `data.chunks_mut(chunk)` in parallel.
pub fn par_chunks_mut<T: Send, F: Fn(usize, &mut [T]) + Sync>(data: &mut [T], chunk: usize, f: F) {
    assert!(chunk > 0);
    let chunks: Vec<(usize, &mut [T])> = data.chunks_mut(chunk).enumerate().collect();
    let n = chunks.len();
    let ranges = ranges(n, 1);
    if ranges.len() <= 1 {
        for (i, c) in chunks {
            f(i, c);
        }
        return;
    }
    let f = &f;
    let mut chunks = chunks.into_iter();
    std::thread::scope(|s| {
        for r in ranges {
            let mine: Vec<(usize, &mut [T])> = chunks.by_ref().take(r.len()).collect();
            s.spawn(move || {
                for (i, c) in mine {
                    f(i, c);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// `par_map` and `par_map_with` give `(0..n).map(f)` in order, below
    /// the serial threshold and above it. The state of `par_map_with` is
    /// made once per thread and carried from one item to the next: each
    /// thread sees its items in order, a contiguous run.
    #[test]
    fn par_map_with_carries_state_per_thread() {
        for n in [0, 1, 5, MIN_PARALLEL - 1, MIN_PARALLEL, 4 * MIN_PARALLEL + 3, 100_003] {
            let want: Vec<usize> = (0..n).map(|i| 3 * i + 1).collect();
            assert_eq!(par_map(n, |i| 3 * i + 1), want, "par_map of {n}");
            let made = AtomicUsize::new(0);
            let got = par_map_with(
                n,
                || {
                    made.fetch_add(1, Ordering::Relaxed);
                    None::<usize>
                },
                |last, i| {
                    assert!(last.is_none_or(|l| l + 1 == i), "item {i} after {last:?}");
                    *last = Some(i);
                    3 * i + 1
                },
            );
            assert_eq!(got, want, "par_map_with of {n}");
            let made = made.load(Ordering::Relaxed);
            let most = threads().min(n / MIN_PARALLEL).max(1);
            assert!((1..=most).contains(&made), "{made} states for {n} items, at most {most} threads");
        }
    }

    /// A panic in a worker reaches the caller: none is lost, whichever
    /// thread it happens on.
    #[test]
    fn a_panic_in_a_worker_reaches_the_caller() {
        for n in [10usize, 50_000] {
            for at in [0, n / 2, n - 1] {
                let hit = |i: usize| if i == at { panic!("item {i} fails") } else { i };
                assert!(catch_unwind(AssertUnwindSafe(|| par_map_min(n, 1, hit))).is_err(), "par_map_min {n} at {at}");
                assert!(catch_unwind(AssertUnwindSafe(|| par_map(n, hit))).is_err(), "par_map {n} at {at}");
                assert!(
                    catch_unwind(AssertUnwindSafe(|| par_map_with(n, || (), |_, i| hit(i)))).is_err(),
                    "par_map_with {n} at {at}"
                );
                let mut v = vec![0usize; n];
                let chunked = catch_unwind(AssertUnwindSafe(|| {
                    par_chunks_mut(&mut v, 7, |k, c| {
                        for (j, x) in c.iter_mut().enumerate() {
                            *x = hit(7 * k + j);
                        }
                    })
                }));
                assert!(chunked.is_err(), "par_chunks_mut {n} at {at}");
            }
        }
    }

    #[test]
    fn par_map_matches_serial() {
        for n in [0, 1, 5, 1000, 4096, 100_003] {
            let got = par_map_min(n, 1, |i| i * i + 1);
            let want: Vec<usize> = (0..n).map(|i| i * i + 1).collect();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn par_chunks_mut_touches_every_element_once() {
        let mut v = vec![0u32; 10_007];
        par_chunks_mut(&mut v, 100, |i, c| {
            for (k, x) in c.iter_mut().enumerate() {
                *x += (i * 100 + k) as u32;
            }
        });
        assert!(v.iter().enumerate().all(|(i, x)| *x == i as u32));
    }
}
