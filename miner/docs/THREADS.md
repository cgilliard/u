# Threads

How a node's work is divided among threads, so that requests are
handled on every core without locks around the node's state.

**Decided**: requests are handled by a pool of workers, one a core;
each datagram goes to the worker that owns its sender, chosen by the
sender's address **and port**; one thread reads the port and hands
datagrams out (portable, standard library only). The rest of this is
**proposed**, to be changed before it is built. Nothing here is built
yet: section 1 is how the node runs today.

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

## 2. The idea: each sender belongs to one worker

A lock is needed when two threads may touch the same thing. So no two
threads are given the same thing: everything the node keeps about one
sender is owned by one worker, and every datagram from that sender is
handed to that worker.

```
                         +--> worker 0 --+
 port --> receiver --hash+--> worker 1 --+--> port (each sends for itself)
          (reads, hashes  +--> worker 2 --+
           the sender)    +--> worker 3 --+
                                 |  ^
                    what was     v  |  what to
                    learned    coordinator   fetch
                                 |  ^
                                 v  |
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

It decodes nothing and decides nothing, so it costs about a system
call a datagram. Each worker's queue is bounded: a datagram for a
worker whose queue is full is dropped, and counted, as a datagram lost
on the wire would be. The transport already retries.

The hash is keyed with a secret made at startup, so that nobody outside
can choose addresses that all fall on one worker.

### 3.2 The workers (one a core, unless set)

A worker owns, for the senders that hash to it:

- the peer's entry: when it was last heard from, whether it has proven
  its address, its status as it last told it;
- what it has asked of us: its queue of chunks to be served;
- what we are fetching from it: the fetches, and the path's measure of
  the line (round trip, window).

It handles a datagram from start to finish: decodes it, looks up its
own state, answers. It sends on the port itself (sending on one socket
from many threads is safe, and needs no lock of ours).

A worker does not wait. What it may do that takes time is read the
store to serve an object, under the store's read lock, which workers
share without holding each other up (section 4). It never writes the
store.

A worker is, as the node is today, a thing that is given datagrams and
the time and gives back datagrams: no socket or clock inside it. So the
simulated network can still run a node deterministically, its workers
one after another on one thread.

### 3.3 The coordinator (one)

Owns what is about no one sender:

- **Which peers are kept**: the limits on how many, of one host, of one
  network; who is refused (bans are of a host, whatever its port).
- **What to fetch, and from whom**: the header sync, the block sync,
  the taking of a state. It keeps a summary of every peer (height, work,
  oldest block, how it has served us), which the workers keep fresh.
- **What to look for**: asking peers whom else they know, pinging
  addresses to try.

Workers tell it what they learn ("this peer says height N", "this fetch
is done, here it is", "this peer sent what no honest peer sends"). It
tells workers what to do ("ping this address", "fetch this object from
this peer", "drop this peer"). Both ways are queues: nobody waits for
an answer.

The coordinator handles no datagrams, so a busy port does not hold it
up, and it does not hold the port up.

### 3.4 The applier (one), as today

Everything that writes the store. The coordinator gives it work and
hears what came of it.

### 3.5 The logs and the interrupt, as today

Workers put request lines on the request log's queue and add to the
stats, both of which are already made for many threads.

---

## 4. What is shared, and how

| Shared | How it is kept safe |
|---|---|
| The chain and its store | Its own read/write lock, as now. Workers and the coordinator read; only the applier writes. Readers do not hold each other up. |
| Who is refused (bans) | Decided by the coordinator; workers hold a copy they are sent when it changes, and check their own copy. A ban takes effect a moment late on other workers, which is harmless. |
| How fast chunks are served, in all | One budget of chunks a second, kept in an atomic number that every worker draws on. |
| How many requests may wait, in all | An atomic count. |
| The tokens' secret | Read by every worker; replaced by the coordinator, the new one swapped in whole. |
| Objects lately made to be served | Each worker keeps its own few. (Two workers may each read the same block once; cheaper than sharing.) |
| The stats, the request log | Atomics and a queue, already. |

There is no lock of the node's own in this list: the store's, which is
there today, and otherwise atomics and messages.

---

## 5. What follows from hashing the port too

Two connections from one host (same address, two ports) may fall on
two workers. That spreads a busy host over cores, which is why it was
chosen. It also means that what is counted **by host** cannot live in a
worker:

- peers of one host, peers of one network: counted by the coordinator,
  which is who admits a peer anyway;
- strikes and bans: a worker reports a strike, the coordinator counts
  them for the host and says when it is refused (section 4);
- chunks waiting for one address: this limit is per address and port
  already, so it stays in the worker.

---

## 6. Order

Datagrams of one sender are handled in the order they were read, by one
worker. Between senders there is no order, and nothing depends on one.

What a worker tells the coordinator arrives later than it happened, by
the length of a queue. So the coordinator's summary of a peer is always
slightly old, as a peer's own status in its last ping already is, and
everything that uses it already allows for a peer that no longer has
what it said (a fetch fails, and another peer is asked).

---

## 7. Settings

| Option | Default | Is |
|---|---|---|
| `--request-threads N` | 0: one a core | Workers |
| `--request-queue N` | 4096 | Datagrams that may wait for one worker |

`--threads` stays what it is: the threads for hashing and for checking
proofs, which is the applier's work.

---

## 8. Building it

In steps, each of which leaves the tests passing:

1. **Split the node in place**, still on one thread: the per-sender
   part (a worker) and the rest (the coordinator), talking only through
   the messages of 3.3. The simulation runs one worker. This is most of
   the work, and where the sync tests earn their keep.
2. **Several workers on one thread** in the simulation, datagrams
   handed out by the hash: finds whatever still assumed one table.
3. **Real threads**: the receiver, the pool, the queues, the shared
   budgets of section 4.
4. **Stats and settings**: datagrams dropped at a full queue, the
   longest queue, as columns; the two options.

---

## 9. To settle

1. **Bans a moment late** on other workers (section 4): acceptable?
2. **A full worker queue drops** the datagram (3.1), not the receiver
   waiting: the receiver must never stop reading. Agreed?
3. **The coordinator as its own thread**, or the receiver doing that
   work between reads? Its own is cleaner and is what is drawn here.
4. **`--request-threads`** as the option's name, and one a core as the
   default.
