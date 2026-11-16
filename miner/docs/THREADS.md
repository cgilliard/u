# Threads

How a node's work is divided among threads, so that requests are
handled on every core.

**Decided**:

- Requests are handled by a pool of workers, one a core.
- Each datagram goes to the worker that owns its sender, chosen by the
  sender's address **and port**. Two nodes on one machine are two
  peers, with nothing to do with each other, and need not fall on the
  same worker.
- One thread reads the port and hands datagrams out. Portable, standard
  library only.
- A worker does everything for its peers itself. It does not block.
  What must block (writing the store) has its own thread already.
- There is no coordinator thread.
- A worker's queue that is full drops the datagram. The main log says
  so and the stats count it.
- A ban is of a host, every port of it. Other workers may learn of it
  a moment late.
- No more than four peers of one host (`--max-peers-per-host`), counted
  over all workers.
- Options: `--threads` and `--request-queue-size`.

Section 4 (what the workers share) is **proposed**. Nothing here is
built yet: section 1 is how the node runs today.

---

## 1. Today

| Thread | Does |
|---|---|
| The node | Reads the port, handles every datagram, decides everything, sends. Owns all of the node's state, with no locks. |
| The applier | What is slow and touches the store: checks and applies blocks, checks and keeps headers, takes the parts of a state. Given work and heard from over channels. |
| Request log, stats log, interrupt | Each its own (`RUNNING.md`). |

One thing that can block is still on the node's thread: making an
object to serve (reading a block, or a part of a state, from the
store).

---

## 2. The idea: each peer belongs to one worker

A lock is needed when two threads may touch the same thing. So no two
threads are given the same thing: everything the node keeps about one
peer is owned by one worker, and every datagram from that peer is
handed to that worker.

```
                          +--> worker 0 --+
 port --> receiver --hash-+--> worker 1 --+--> port (each sends for itself)
          (reads, hashes  +--> worker 2 --+
           address:port)  +--> worker 3 --+
                                  |
                          blocks, headers, parts
                                  v
                               applier --> store
```

`epoll` is not the tool for this: it tells a thread which of many
sockets is ready, and a node has one socket for everybody. What matters
is not who reads the datagram but who owns the state it touches.

---

## 3. The threads

### 3.1 The receiver (one)

Reads the port, and for each datagram:

1. hashes the sender's address and port to a worker;
2. puts the datagram on that worker's queue.

A worker's queue is a bounded queue with a lock of its own: the
receiver puts on at one end without waiting, the worker takes off at
the other, and waits there when it has nothing to do (until its next
timer is due). The worker handles each datagram as it takes it off:
nothing is kept of a datagram afterwards, only what it changed in what
the worker knows of that peer.

The receiver decodes nothing and decides nothing. There are no connections to
set up: the first datagram of a peer nobody has heard of goes to its
worker like any other, and the worker decides whether to keep the peer.

Each worker's queue holds `--request-queue-size` datagrams. A datagram
for a worker whose queue is full is dropped: the receiver never waits,
since it must never stop reading the port. When that happens:

- the main log says so, there and then, and not again for five seconds
  while it goes on (as the request log's queue does):

  ```
  [2026-10-17 19:49:31:471] dropped requests: a worker's queue is full
  ```

- the stats count every one, in a column of its own (`Dropped`).

The hash is keyed with a secret made at startup, so that nobody outside
can choose addresses that all fall on one worker.

### 3.2 The workers (`--threads`, one a core unless set)

A worker owns, for the peers that hash to it:

- the peer's entry: when it was last heard from, whether it has proven
  its address, its status as it last told it, and its strikes;
- what it has asked of us: its queue of chunks to be served;
- what we are fetching from it: the fetches, and the path's measure of
  the line (round trip, window).

It does everything for those peers:

- handles their datagrams from start to finish, and sends the answers
  on the port itself (sending on one socket from many threads is safe);
- pings them, drops them when they go silent, strikes them, and bans
  their host (section 5);
- asks them whom else they know;
- fetches from them, and serves them.

An address a worker learns of that belongs to another worker (a peer
told of in a `Peers` message, say) is put on that worker's queue as an
address to try.

A worker does not block. The two things it does that are not instant:

- reading the store to serve an object, under the store's read lock,
  which readers share without holding each other up;
- taking one of the short locks of section 4, held for a lookup and no
  longer.

It never writes the store: blocks, headers and parts of a state that
arrive are handed to the applier, as now.

A worker is, as the node is today, a thing that is given datagrams and
the time and gives back datagrams: no socket or clock inside it. So the
simulated network can still run a node deterministically, its workers
one after another on one thread.

### 3.3 The applier (one), as today

Everything that writes the store.

### 3.4 The logs and the interrupt, as today

Workers put request lines on the request log's queue and add to the
stats, both of which are already made for many threads.

---

## 4. What the workers share (proposed)

Most of what a node does is about one peer, and needs nothing shared.
Three things are about all of them:

### 4.1 How many peers there are

`--max-peers` is of the whole node. An atomic count: a worker adds one
to admit a peer, and gives it back if that went over.

The limits on peers of one host and of one network
(`--max-peers-per-host`, `--max-peers-per-network`) count across
workers, since two ports of one host may be on two workers. They keep
one machine from filling the table (**decided**: they stay). A small
table of counts by host and by network, behind a lock taken only when a
peer is admitted or dropped, which is rare.

### 4.2 What to fetch, and from whom

This is the one piece of real coordination. Syncing means choosing,
among all peers, who has the most work, and spreading fetches over
those who can serve them: 24 blocks at once, 8 of them from any one
peer; 32 parts of a state at once.

Without a thread to own it, it is a **board** the workers share:

- what the node is after: the best chain it has heard of, and the
  blocks, runs of headers or parts of a state still to fetch;
- which of those are being fetched now, and how many in all.

A worker, when it looks to its own peers, takes from the board what one
of them can serve ("block X: mine, from peer P"), and puts back what
failed. A worker that hears of more work from one of its peers writes
that on the board. The board is behind a lock held for the length of
that lookup: microseconds, and nothing is waited for inside it.

What arrives goes to the applier, and what the applier makes of it
(a block joined the chain, a header was bad) comes back to the board
and to the worker whose peer sent it.

### 4.3 The rest

| Shared | How |
|---|---|
| The chain and its store | Its own read/write lock, as now. Workers read; only the applier writes. |
| How fast chunks are served, in all | One budget of chunks a second, in an atomic number every worker draws on. |
| How many requests may wait, in all | An atomic count. |
| The tokens' secret | Read by every worker; replaced whole, from time to time. |
| Objects lately made to be served | Each worker keeps its own few. |
| The stats, the request log | Atomics and a queue, already. |

---

## 5. Bans

A peer that sends what no honest peer sends is struck by its worker,
and after `--ban-strikes` its **host** is banned for `--ban-seconds`:
every port of it, on every worker. Were a ban of one port only, a bad
peer would be back on the next port at once.

The bans are one list the workers share, behind a lock, with a number
beside it that goes up whenever the list changes. Each worker keeps its
own copy of the list and checks that against every datagram, with no
lock; it looks at the number (one atomic read) and takes the list
afresh only when the number has moved. So a ban holds at once on the
worker that made it, and on the others from their next datagram or
timer: a moment late, which is fine.

---

## 6. Order

Datagrams of one peer are handled in the order they were read, by one
worker. Between peers there is no order, and nothing depends on one.

---

## 7. Settings

| Option | Default | Is |
|---|---|---|
| `--threads N` | 0: one a core | Workers that handle requests. Also the threads for hashing and for checking proofs, as it is today: one number for how much of the machine the node uses. |
| `--request-queue-size N` | 4096 | Datagrams that may wait for one worker |

---

## 8. Building it

In steps, each of which leaves the tests passing:

1. **Split the node in place**, still on one thread: what is about one
   peer (a worker) and the board. The simulation runs one worker. This
   is most of the work, and where the sync tests earn their keep.
2. **Several workers on one thread** in the simulation, datagrams
   handed out by the hash: finds whatever still assumed one table.
3. **Real threads**: the receiver, the pool, the queues, the shared
   counts and budgets.
4. **Stats and settings**: datagrams dropped at a full queue; the two
   options.
