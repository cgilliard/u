# Threads

How a node's work is divided among threads, so that requests are
handled on every core.

**Decided**:

- Requests are handled by a pool of workers, one a core.
- Each datagram goes to the worker that owns its sender, chosen by the
  sender's **address** (not its port). So everything about one host,
  whatever its ports, is one worker's: its peers, how many of them
  there are, and whether it is banned. Several nodes on one machine all
  fall on one worker, which is accepted.
- One thread reads the port and hands datagrams out. Portable, standard
  library only.
- A worker does everything for its peers itself. It does not block.
  What must block (writing the store) has its own thread already.
- There is no coordinator thread.
- A worker's queue that is full drops the datagram. The main log says
  so and the stats count it.
- A ban is of a host, every port of it, kept by the worker that owns
  the host. No other worker needs to know.
- No more than four peers of one host (`--max-peers-per-host`), counted
  by that worker.
- Options: `--threads` and `--request-queue-size`.

- What is about all peers at once is shared without a thread of its
  own: counts in atomics, and one list of what is to be downloaded,
  behind a lock held only to take from it or put back (section 4).

Nothing here is built yet: section 1 is how the node runs today.

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
           the address)   +--> worker 3 --+
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

1. hashes the sender's address to a worker;
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

A worker owns, for the hosts that hash to it, and every peer of them:

- the peer's entry: when it was last heard from, whether it has proven
  its address, its status as it last told it, its strikes; how many
  peers its host has, and whether the host is banned;
- what it has asked of us: its queue of chunks to be served;
- what we are fetching from it: the fetches, and the path's measure of
  the line (round trip, window).

It does everything for those peers:

- handles their datagrams from start to finish, and sends the answers
  on the port itself (sending on one socket from many threads is safe);
- pings them, drops them when they go silent, strikes them, and bans
  their host;
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

## 4. What the workers share

Most of what a node does is about one peer, and needs nothing shared.
Three things are about all of them:

### 4.1 How many peers there are

`--max-peers` is of the whole node. An atomic count: a worker adds one
to admit a peer, and gives it back if that went over.

`--max-peers-per-host` is the owning worker's own count: nothing
shared.

`--max-peers-per-network` (peers of one /16) counts across workers,
since the hosts of one network are on many. There are 65,536 such
networks, so it is an array of that many atomic counts (64 KB), one a
network: a worker adds one to admit a peer and gives it back if that
went over. No lock.

### 4.2 What to fetch, and from whom

A fetch belongs to the worker that owns the peer it is from. It has to:
the chunks come back to our port and are handed out by the peer's
address, so they arrive at that worker and nowhere else, and the fetch
(which chunks are in, what to ask again, how the line is doing) must
be where they arrive. Any thread may *send* on the port (a datagram is
sent whole or not at all, and two sends never mix), but only the
owning worker would know what to do with the answer.

So there are two cases.

**A block is announced.** The worker that hears of it fetches it from
the peer that announced it: its own peer. Nothing is shared.

**The node is behind**, and wants many things at once from many peers:
24 blocks at a time, 8 of them from any one peer; 32 parts of a state.
The peers that can serve them are on every worker. For this there is
one **list of what is to be downloaded**, which the workers share:

1. The worker that finds the node is behind (a peer of its own shows
   more work) writes on the list what is needed.
2. Every worker, when it looks to its peers, takes from the list what
   one of them can serve, marks it as being fetched, and asks that peer
   itself.
3. The chunks arrive at that worker. When the object is whole, the
   worker hands it to the applier, which is the thread that writes the
   store.
4. What the applier makes of it comes back: kept, and the item is off
   the list; bad, and the worker strikes its peer and the item is on
   the list again for another. A fetch that fails goes back on the
   list the same way.

The list is behind a read/write lock. A worker looks at it under the
read lock, which workers share; only taking an item, putting one back
or adding to it takes the write lock, for the length of that change:
microseconds, with nothing waited for inside it.

What the list holds is what the node wants and what is being fetched,
no more. Which peer has which block is not on it: each worker knows
that of its own peers, and that is all it needs to take from the list.
Nor is it what keeps junk out: a worker takes chunks only for a fetch
it began itself, of a peer it asked, so what nobody asked for is never
kept, whoever sends it.

Blocks must join the chain in order though they arrive in any, from
any worker: the applier holds a body until the block before it is in,
as the node does today.

### 4.3 Nobody polls

A worker waits on its queue. What comes off it is a datagram, or a
**notice** from another thread, put there the same way:

| Notice | From | The worker then |
|---|---|---|
| There is more on the list | Whoever put it there (a worker, or the applier) | Looks whether a peer of its own can serve any of it |
| A block joined the chain | The applier, to every worker | Tells its peers of the block |
| What came of something you fetched | The applier, to the worker that fetched it | Strikes its peer if it was bad |
| An address to try | A worker that was told of it | Pings it |

The worker that found the node was behind (A, say) does not wait for
anything and is told nothing in particular: its part ended when it
wrote on the list. When a block another worker fetched joins the chain,
A hears as every worker does.

The list is kept filled the same way: when the applier takes a block
in, it takes that item off the list, puts on the next that is wanted,
and sends the notice.

A notice is never dropped for a full queue: notices are few, and have
room of their own.

(A worker does also wake by the clock, for what is about time itself:
a ping that is due, a chunk to ask for again, the pace of what it
serves. That is a timer, not a look to see whether something changed.)

### 4.4 The rest

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
every port of it. Were a ban of one port only, a bad peer would be back
on the next port at once.

Every port of a host is the same worker's, so the ban is that worker's
own: it holds at once, and nothing is shared or sent.

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

### 8.1 Where what the node keeps today goes

| Today, in the node | Goes to |
|---|---|
| The peers table; who is banned; peers of a host | Each worker, for its hosts |
| Peers in all, peers of a network | Atomic counts |
| Tokens (what an address is given to show it is there) | Each worker, from the one secret |
| What is being served: queues by address | Each worker |
| How fast chunks are served, how many may wait, in all | Atomic budgets |
| Objects lately made to be served | Each worker |
| Fetches under way | Each worker, for its peers |
| Who announced which block | Each worker |
| Where the header sync is aiming, what blocks are wanted, the state being taken | The list |
| Bodies fetched and waiting for the blocks before them | The applier |
| Work given to the applier and not yet heard of | The list |
| Counts of what has happened | Each worker; added up for the stats |

### 8.2 Steps

Each leaves the tests passing:

1. **Split the node in place**, still on one thread: what is about one
   peer (a worker) and the list. The simulation runs one worker. This
   is most of the work, and where the sync tests earn their keep.
2. **Several workers on one thread** in the simulation, datagrams
   handed out by the hash: finds whatever still assumed one table.
3. **Real threads**: the receiver, the pool, the queues, the shared
   counts and budgets.
4. **Stats and settings**: datagrams dropped at a full queue; the two
   options.
