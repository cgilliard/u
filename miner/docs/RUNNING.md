# Running a node

How a node is told what to do, what it says while it runs, and what it
says when it starts and stops.

Everything here is decided and built, except what section 4 lists.
Where the reference node (`tmp/miner`) does something different, that
is noted, with the reason for changing it.

---

## 1. Configuration

**Decided, and built** (`src/configuration.rs`).

### 1.1 One program, no commands

`tabminer` is the miner, and running it runs it:

```
tabminer [options]
```

There is no `mine`, `node` or `genesis` word after it. A node that does
not mine is `tabminer --no-mine`.

The tool that makes a genesis block is a program of its own, built by
its own Cargo package, so that the miner never has to tell the two
apart: `genesis/`, beside `miner/`. (It builds, and says it is not
written yet.)

### 1.2 Options

Every option is `--name` or `--name value`. They are one list in the
code, from which the help is written, the command line is read and the
startup lines are laid out, so the three cannot disagree. `tabminer
--help` is the list; it is in sections: General, Mining, Network,
Peers, Sync, Serving, Logging.

- **An option that is not one**: the node prints

  ```
  Error: unknown configuration option: '--<option>'
  ```

  then the help, and exits with **-1**. So does anything else wrong
  with what was given (1.4).
- **`--help` anywhere** on the command line: the help is printed and the
  node exits with **0**. Nothing else on the line is looked at.

### 1.3 Times, sizes, and a file of options

- **A time** is so many seconds, or a number and `s`, `m`, `h` or `d`:
  `--log-rotate-seconds 3600`, `60m` and `1h` are one setting.
- **A size** is so many bytes, or a number and `k`, `m` or `g`, each
  1,024 of the one before: `--log-rotate-bytes 1048576`, `1024k` and
  `1m` are one setting.
- A count is a count, and takes no unit.

**A file of options** is given as `@FILE`:

```
tabminer @my_config --max-peers 70
```

```
# my_config
--no-mine
--max-peers 2000            # a comment
--data-dir /srv/my tab      # the rest of the line is the value
--peer 203.0.113.7:3737
```

- One option to a line, written as on the command line. `#` begins a
  comment.
- **What the command line says is taken before what the file says**,
  wherever on the line the `@FILE` is. With several files, a later one
  before an earlier.
- An option that may be given many times (`--peer`, `--seed`) has the
  values of all of them.
- What is wrong in a file is said with the file and the line:
  `/work/my_config line 2: unknown configuration option: '--prot'`.
- A file cannot name another file, and `--help` is for the command
  line.

### 1.4 What is checked

One routine goes through everything given before anything is opened,
bound or written, and reports the first thing wrong as `Error: <what is
wrong>`, followed by the help.

| Wrong | Said as |
|---|---|
| An option that is not one | `unknown configuration option: '--prot'` |
| An option that needs a value and has none | `--max-peers needs a value` |
| A value that is not what the option takes | `--max-peers: 'many' is not a number` |
| | `--ping-seconds: '1.5' is not a time (as 90, 90s, 60m or 1h)` |
| A port out of range, or an address that is not one | `--listen: '0.0.0.0:70000' is not an address and port (as 203.0.113.7:3737)` |
| An option given twice in one place that may be given once | `--max-peers was given twice` |
| Limits that cannot both hold | `--target-peers (100) is over --max-peers (64)` |
| | `--sync-point (2000) is not under --max-undo-blocks (1008)` |
| Two logs in one file | `two logs cannot be one file: /a/x.log` |

Whether a directory can be written to is found when the node opens it,
and said then (3.2).

### 1.5 Where the logs go

For each of the three logs, the first of these that was given:

1. **Its own option**, the file's full name: `--main-log`,
   `--request-log`, `--stat-log`.
2. **`--log-dir`**: the log, under its usual name, in that directory.
3. **`--data-dir`**: the same, in the data directory. This is what
   happens if nothing is said.

The usual names are `tabernacle.log`, `request.log` and `stat.log`.

```
tabminer                                   ~/.tabernacle/tabminer/tabernacle.log
tabminer --data-dir /srv/tab               /srv/tab/tabernacle.log
tabminer --data-dir /srv/tab --log-dir /var/log/tab
                                           /var/log/tab/tabernacle.log
tabminer --log-dir /var/log/tab --stat-log /mnt/fast/stat.log
                                           /var/log/tab/tabernacle.log
                                           /var/log/tab/request.log
                                           /mnt/fast/stat.log
```

Every path the node keeps and prints is a whole path from the root: one
given otherwise is taken from the directory the node was started in.

---

## 2. The logs

**Decided, and built** (`src/logger`; what the node puts in them,
`src/net/node.rs` and `src/net/socket.rs`).

### 2.1 Three logs

| Log | Holds | Written by |
|---|---|---|
| Main | How the node was started and with what settings; then blocks (being made, won, received), errors, critical events and stopping; and each time another log's file was put aside, under what name | Whoever calls it, on their own thread |
| Request | Each request the node is asked | A thread of its own, from a queue |
| Stats | How the node is doing: every few seconds for those seconds, every minute for the whole since it started | A thread of its own |

There are no levels. What is logged is always logged.

### 2.2 A line

```
[2026-10-17 19:49:31:471] the line
```

The time is UTC. Three ways to write:

- `log`: the line with the time before it.
- `log_no_header`: the line as it is, for a log laid out by whoever
  writes it.
- `log_all`: `log`, and the same line to the terminal (standard error).
  The startup messages and the settings are written this way, so that
  how a run was configured is on the screen and in the file. Once the
  node has said "Server is ready!" it writes to the file alone: the
  terminal is left to whoever is at it.

### 2.3 Rotation

A log's file is put aside, and a new one begun, when either of two
settings is passed: the longest it may be written to (an hour, say) or
the most it may hold (a mebibyte, say).

```
tabernacle.log  ->  tabernacle_R_02_03_2026_10_00.log     month, day, year, hour, minute
                    tabernacle_R_02_03_2026_10_00_02.log  a second one in that minute
```

- Every number in a name has two digits (the year four).
- A line is never split between two files.
- A quiet log is put aside on time though nothing is being written.
- Files put aside are never deleted by the node: that is for whoever
  keeps the machine.

Every file begins with a line saying which log it is and when it was
begun, to the second:

```
tabernacle.log_02_03_2026_10_30_04
```

A file that holds nothing but that line is not put aside.

### 2.4 The request log's queue

Whoever answers a request does not wait for the disk: the line goes on
a queue with the time it was said, and the log's own thread writes it.
The queue's size is a setting. When it is full, lines are dropped, not
waited for, and the main log says so there and then, and not again for
five seconds while it goes on:

```
[2026-10-17 19:49:31:471] dropped request log queued items
```

How many were dropped is not said. As a rule the queue empties as fast
as the disk takes its lines, and the log goes on.

### 2.5 A request's line

Every datagram the node takes has a line: who sent it, how long taking
it took in microseconds, what it was (with its size), and what was done
about it.

```
[2026-11-16 05:27:56:237] 127.0.0.1:37412       780 micros      ping height 0 (133 bytes) -> pong (2 datagrams, 266 bytes)
[2026-11-16 05:27:57:239] 127.0.0.1:37412       56 micros       get-peers (13 bytes) -> peers (6 bytes)
[2026-11-16 05:27:58:239] 127.0.0.1:37412       7 micros        peers of 0 (6 bytes) -> taken
[2026-11-16 05:27:59:102] 203.0.113.7:3737      1,250 micros    get block, 1,712 chunks (96 bytes) -> queued
[2026-11-16 05:27:59:400] 203.0.113.7:3737      9 micros        block height 7 of 1,999,000 bytes (250 bytes) -> taken
[2026-11-16 05:27:59:731] 198.51.100.20:3738    4 micros        get-peers (13 bytes) -> unheard
```

- **The request** is the message's name (`ping`, `pong`, `get-peers`,
  `peers`, `find-fork`, `fork`, `block`, `get`, `gone`, `goodbye`), with
  what of it is worth a word: the sender's height, how many addresses,
  the kind of object asked for and how many chunks of it.
- **What was done** is the answer's name where one was sent, with what
  was sent; `queued` for chunks asked for, which go out as the node's
  pace allows; `taken` for what needs no answer; and `unheard`,
  `stranger` or `malformed` for what was not listened to (no token,
  another chain, no message at all).
- **The time** is from the datagram being handed to the node until the
  node is done with it.
- **Chunks of what the node itself is fetching have no line.** They are
  not requests, a block is some 1,700 of them, and each is like the
  last. They are counted in the stats.

### 2.6 The stats log

In columns, a line at a time. Under each whole a rule is drawn, to set
it off from the intervals that follow.

```
Uptime: 0:00:00           Requests___AvgLatency(us)_Peers_PeersLive_Height_Blocks_Mined
[2026-11-16 08:21:55:624] 0          -              0     0         0      0      0
---------------------------------------------------------------------------------------
10s ending 08:22:05:      18         12.4           1     1         3      3      3
10s ending 08:22:15:      156        12.9           1     1         5      2      0
...
Uptime: 0:01:00           Requests___AvgLatency(us)_Peers_PeersLive_Height_Blocks_Mined
[2026-11-16 08:22:55:624] 174        12.8           1     1         5      5      3
---------------------------------------------------------------------------------------
```

| Column | Is |
|---|---|
| Requests | Datagrams taken, chunks too (counted) |
| AvgLatency(us) | What taking one took, in microseconds, on average: of the interval in an interval's line, of the whole run in a whole's. `-` where there were none |
| Peers, PeersLive | Peers known, and those heard from lately (levels) |
| Height | The chain's height (level) |
| Blocks | Blocks that joined the chain here (counted) |
| Mined | Blocks made here (counted) |

Counted as well, and not shown: datagrams dropped at a full queue (the
main log says when that happens), bytes in and out, objects being
fetched.

- **Every ten seconds** (a setting): what happened in those seconds,
  after how long they were and the time they ended at.
- **Every minute** (a setting): the columns' names, with how long the
  node has been up, and under them the whole since it started, with
  the time. So six interval lines come between two wholes.
- **Counted numbers add up.** A whole is the whole before it and the
  intervals between. The last interval's line and the whole after it
  are written at the same moment from one reading of the numbers, so
  this is exact.
- **Levels and averages do not.** A level is, in every line, what it
  was at that moment; an average is of its own line's span.
- Intervals are counted from when the node started, not each from the
  one before, so they do not drift.
- A column is as wide as its name and its numbers need. A number too
  wide for its column moves the rest of that line over.

Numbers and times are written by the same few functions in every log
(`logger::fmt`): commas between thousands, bytes in the unit that fits,
uptime as hours, minutes and seconds.

### 2.7 Nothing here stops the node

A line that cannot be written is counted, and the first failure is said
once on the terminal. If the log's directory goes and comes back, so
does the log.

---

## 3. Starting and stopping

### 3.1 Starting

When the configuration has no errors, the node says when it started and
how it is configured, in the main log and on the terminal alike
(`log_all`): so that a log shows exactly how that run was set up.

```
[2026-10-17 19:30:44:000] Server started 10-17-2026 19:30:44 UTC
---------------------------------------------------------------------------------------------------------
[2026-10-17 19:30:44:000] UDP Server Listening on: '0.0.0.0:3737'
[2026-10-17 19:30:44:000] Configuration File:      '/work/my_config'
[2026-10-17 19:30:44:000] Network:                 'mainnet'
[2026-10-17 19:30:44:000] Mining:                  'yes'
[2026-10-17 19:30:44:000] Data Directory:          '/home/chris/.tabernacle/tabminer'
[2026-10-17 19:30:44:000] Main Log:                '/home/chris/.tabernacle/tabminer/tabernacle.log'
[2026-10-17 19:30:44:000] Request Log:             '/home/chris/.tabernacle/tabminer/request.log'
[2026-10-17 19:30:44:000] Stat Log:                '/home/chris/.tabernacle/tabminer/stat.log'
[2026-10-17 19:30:44:000] Log Rotation Time:       '3,600 seconds'
[2026-10-17 19:30:44:000] Log Rotation Size:       '1,048,576 bytes'
[2026-10-17 19:30:44:000] Max Peers:               '2,000'
...
---------------------------------------------------------------------------------------------------------
[2026-10-17 19:30:44:000] Server is ready!
```

Every setting is listed, by name, with what it is in quotes, the quotes
in one column. Paths are whole; numbers are written as in every log.
**"Server is ready!" is the mark that the node is running**, for whoever
reads the log and for programs that do. So:

- It is the very next line after the configuration. Nothing is said
  between them.
- It is said only when the node can do what it is for: the logs are
  open, the store is open, the port is bound, the threads are started.
  All of that is done before the first line above is written, so a
  node that cannot start never says how it is configured either.
- It is the last thing the node says on the terminal. Everything after
  it goes to the main log's file alone.
- No request is taken before it is said. (A datagram that comes
  between the port being bound and the line waits in the system's
  queue for those few moments.)

### 3.2 When it cannot start

A configuration error is as in 1.4. Anything else that stops a start is
one line, on the terminal and in the main log if that could be opened,
and the node exits with -1:

```
[2026-11-16 05:28:03:264] Error: cannot listen on 127.0.0.1:3737: Address already in use (os error 98)
```

### 3.3 After that

The main log holds what happens to the node: its peers, the chain it is
catching up with, its blocks; and errors, each file of another log put
aside, and stopping.

```
[2026-11-16 08:59:48:978] Peer 127.0.0.1:37411 connected (height 5)
[2026-11-16 08:59:48:978] Syncing headers 1 to 5 from 127.0.0.1:37411
[2026-11-16 08:59:48:980] Headers synced to 5
[2026-11-16 08:59:49:177] Received block 1 (39baef5c) from 127.0.0.1:37411
...
[2026-11-16 08:59:49:226] Received block 5 (e6760963) from 127.0.0.1:37411
[2026-11-16 08:59:49:226] Synced at block 5
[2026-11-16 08:59:50:299] Mining block 6 on e6760963
[2026-11-16 08:59:52:386] Won block 6 (e494f101): proved in 0.05s, 624,125 hashes in 1.57s
```

| Line | Says |
|---|---|
| `Peer A connected (height N)` | A peer answered and is live; its chain is that high |
| `Peer A lost` | It is live no longer: silent too long, gone, or refused |
| `Banned HOST: ...` | A host sent what no honest peer sends once too often, and is refused |
| `Syncing headers N to M from A` | A chain ahead of ours is being caught up with |
| `Headers synced to M` | Its headers are kept |
| `Headers from A refused` | They were not what they should be |
| `Received block N (id) from A` | A block of a peer's became the chain's last |
| `Received block N (id) from A, on a side branch` | A block of a peer's was kept, on a branch with no more work than the chain's: the chain is as it was. (`Block N (id) made here is on a side branch`, if it was ours: another got there first) |
| `Reorganized to block N (id) from A: K blocks undone, M blocks taken, above block F` | The chain went over to another branch: K of its blocks gave way to M of that branch, the two parting above block F |
| `Synced at block N` | The chain that was being caught up with has been |
| `Taking the state as of block N (id)` | The blocks cannot be had, and the state is taken whole (`as of a later block`, if the first could no longer be served) |
| `State taken as of block N` | It has been |
| `Mining block N on P` | A block is begun here, on the block of id P |
| `Won block N (id): ...` | Its proof of work was found here: how long its proof took, how many hashes and how long its nonce |
| `Refused block N (id) from A: why` | A block was refused (`made here`, if it was ours) |

A peer come or gone is said when the node next looks to its peers, so
up to a tick after it happened.

### 3.4 Stopping

On an interrupt (Ctrl-C, or the operating system's signal to end):

```
[2026-11-16 05:28:01:753] Received shut down signal, halting!
```

in the main log (not on the terminal, which is quiet once the node is
ready), and the node ends, with 0. That is all, on purpose: the worst a node
can do on being told to stop is not to, or to hang.

- What takes the signal only sets a flag. A thread that does nothing
  else sees it within a fiftieth of a second, writes the line to the
  main log (`log_all`, on its own thread, waiting for no other), and ends the program.
- Nothing is put in order first. The store is whole wherever it is cut
  off; lines still queued for the request log, and the stats since the
  last interval, are lost.
- A second interrupt ends the program at once, from where the signal is
  taken, whatever the first is waiting on.

Taking a signal needs a call the standard library does not have: the C
library's `signal`, the same on every platform the node is built for
(`src/interrupt.rs`).

---

## 4. Mining

A node makes blocks unless it is given `--no-mine`: on a thread of its
own (`src/miner.rs`), one block after another on the chain's last,
begun again whenever that changes, and not while the node is catching
up with a chain ahead of its own. A block made is given to the node,
which applies it and tells its peers.

**So far, on the dev network only**, and a block carries its reward and
nothing else:

- `--network dev` (a build with `--features dev`): a block about every
  second or two, its proof checked directly.
- `--reward-key HEX`: the hash of the key rewards are paid to. Without
  it, on the dev network, they are paid to a key nobody has.
- On mainnet and the recursive dev network a node that is not given
  `--no-mine` says that mining there is not built yet, and does not
  start: their blocks' proofs build on the proof of the block before,
  which the chain does not keep yet.

Two nodes to try it with:

```
tabminer --network dev --data-dir /tmp/a --listen 127.0.0.1:3737
tabminer --network dev --data-dir /tmp/b --listen 127.0.0.1:3738 --peer 127.0.0.1:3737
```

The stats log of each shows its height, the blocks that joined its
chain, and those it made (`Mined`).

---

## 5. Still to do

1. **Mining on mainnet**: the chain proof on the block before; the
   table of the proof of work, which is not built in; a wallet for the
   rewards; transactions in blocks.
2. **What is left of `THREADS.md`** (its 8.3).
3. **The peers file and the built-in seeds.** `--peer` and `--seed` are
   what a node begins from today.
4. **The genesis tool** itself, in its package.
