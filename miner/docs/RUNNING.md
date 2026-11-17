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

A file put aside begins with a line saying which log it is and when it
was begun, to the second:

```
tabernacle.log_02_03_2026_10_30_04
```

The file being written to has no such line: it is the log's lines and
nothing else. A file that holds nothing is not put aside.

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
Uptime: 0:00:00           Requests___Packets____AvgLatency(us)_Peers_PeersLive_Height_Blocks_Mined
[2026-11-16 21:25:22:952] 0          0          -              0     0         0      0      0
--------------------------------------------------------------------------------------------------
10s ending 21:25:32:      10         10         15.4           1     1         0      0      0
10s ending 21:25:42:      3          33         434.3          1     1         1      1      0
10s ending 21:25:52:      1          31         827.0          1     1         2      1      0
...
Uptime: 0:01:00           Requests___Packets____AvgLatency(us)_Peers_PeersLive_Height_Blocks_Mined
[2026-11-16 21:26:22:952] 22         82         108.6          1     1         4      4      2
--------------------------------------------------------------------------------------------------
```

| Column | Is |
|---|---|
| Requests | Requests taken: what the request log has a line for, one for one (counted) |
| Packets | Datagrams taken, of every kind (counted): the requests, and the chunks of what the node itself is fetching, of which a block is some seventy and more |
| AvgLatency(us) | What taking a request took, in microseconds, on average: of the interval in an interval's line, of the whole run in a whole's. `-` where there were none |
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
[2026-11-16 08:59:50:299] Proving block 6 on e6760963
[2026-11-16 08:59:50:349] Mining block 6 on e6760963: proved in 0.05s
[2026-11-16 08:59:51:919] Won block 6 (e494f101): 624,125 hashes in 1.57s
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
| `Proving block N on P` | A block is begun here, on the block of id P: its proof is being made |
| `Mining block N on P: proved in T` | Its proof is made, in that time, and its nonce is being looked for |
| `Not mining: a chain ahead is coming in, to block N (id)` | Headers that have been checked show a chain two blocks or more ahead, and its blocks are waited for (4.1) |
| `Mining again: the blocks of the chain ahead, to block N (id), have not come in T` | They were waited for long enough |
| `Won block N (id): H hashes in T` | Its proof of work was found here: how many hashes its nonce took, and how long |
| `Refused block N (id) from A: why` | A block was refused (`made here`, if it was ours) |

A peer gone is said when the node next looks to its peers, so up to a
tick after it happened.

### 3.4 Stopping

On an interrupt (Ctrl-C, or the operating system's signal to end) the
node is ended by the operating system, where it stands. The node does
nothing about it, on purpose:

- Nothing has to be put in order first. The store is whole wherever it
  is cut off; lines still queued for the request log, and the stats
  since the last interval, are lost.
- Nothing is said: the main log ends with whatever its last line was.
- A node started in the background by a shell (`tabminer ... &` in a
  script) is started ignoring interrupts, as any program is, and does
  nothing to change that: it is ended with the signal to end (`kill`),
  not with an interrupt (`kill -INT`).
- No thread wakes to see whether the node has been told to stop. A node
  with nothing to do does nothing: the receiver waits for a datagram,
  each worker for one or for its next tick, and the logs for what they
  next have to write.

---

## 4. Mining

A node makes blocks unless it is given `--no-mine`: on a thread of its
own (`src/miner.rs`), one block after another on the chain's last,
begun again whenever that changes, and not while the node is catching
up with a chain ahead of its own. A block made is given to the node,
which applies it and tells its peers.

A block's reward is paid to the node's wallet (section 5), to an
output made for that block: so a node that makes blocks has a wallet,
and `--no-wallet` goes with `--no-mine`.

- **Mainnet**: a block's proof builds on the proof of the block
  before, which is taken from the chain (the proof from that block's
  body, and what it speaks to made again from the body and the header
  before it).
- `--network dev-recursive` (a build with `--features dev`): the same,
  at the smallest parameters; a block about every ten seconds.
- `--network dev` (the same build): a block about every second, its
  proof checked directly.

**What a block carries.** A block made here carries transactions of
the node's pool: the longest waiting first, a tenth of it, and then
the best paying. How many is bounded by the signatures the block's
proof checks, one for each input: 256 unless
`--max-block-signatures` says otherwise (some hundred transactions; 0
for blocks of nothing but their reward). Proving them is what takes
the time, about as long again as a block of nothing for every 128, so
a machine with more to prove with may be given more; a block's size
allows a hundred times as many, which is for those who prove on many
machines (`POOL_SCALING.md`). When a block carries any, the main log
says so:

```
[2026-11-17 19:02:11:403] Block 7 carries 3 transactions of the pool (8 signatures)
```

**The table of the proof of work.** A miner hashes against a table: 1.1
GB on mainnet (it doubles each year, to 32 GB), 64 KB and built in on
the dev networks. Its memory is taken when the node starts making
blocks.

- **It is made once, and kept.** When it is whole it is written to
  `pow.table` in the data directory, and every later run reads it from
  there and says so.
- **Unless told otherwise it is made while blocks are**: what is read
  of it is filled as it is read, so blocks are made from the first
  moment, and a thread fills the rest. Until it is whole, looking for a
  nonce is slow (each hash has to make what it reads), and the first
  block after genesis, which needs some 65,000 hashes where later ones
  need a few hundred, can take many minutes.
- **`--prebuild-table`** makes it whole first, with every thread, and
  only then makes blocks.

The main log says how it goes, at every twentieth:

```
Making the table of the proof of work: 0 B of 1.1 GB are there. This may take a while
The table of the proof of work: 5% (53.7 MB of 1.1 GB)
...
The table of the proof of work: 95% (1.0 GB of 1.1 GB)
The table of the proof of work is whole: made in 617.66 seconds
The table of the proof of work is kept in '/home/chris/.tabernacle/tabminer/pow.table'
```

and on a later run:

```
The table of the proof of work (1.1 GB) was read from '/home/chris/.tabernacle/tabminer/pow.table'
```

**What it takes**, as measured on one machine of twelve threads, the
node alone on it:

| | Mainnet | dev-recursive | dev |
|---|---|---|---|
| The table, made once | about ten minutes, blocks being proven meanwhile | built in | built in |
| Proving a block | about 55 seconds (two to three minutes while the table is being made) | 6 to 10 seconds | under a tenth of a second |
| Checking a block | a fraction of a second | | |

### 4.1 When a node does not make blocks

A block made on a chain about to be replaced is work thrown away, so a
node that is well behind waits. But only on what it has checked, and
not for ever:

- **While the state is being taken whole**, no blocks are made: there
  is no chain here to build on.
- **While headers that have been checked show a chain two blocks or
  more ahead** whose blocks are still coming, none are made. A peer's
  word that its chain has more work stops nothing: it is asked for its
  headers, and blocks go on being made until those are here with their
  work in them. Else whoever cared to say so could stop a node.
- **One block ahead, or another block at the same height, stops
  nothing.** It may take long to arrive, it may not be what its header
  says, and a block of no more work than ours replaces nothing.
- **A chain ahead is waited for three blocks' time** (thirty minutes on
  mainnet; ten seconds at the least), counted from when its last
  header was last heard of. Then blocks are made again, and go on
  being made until a chain ahead with another last header is known of.

Waiting wrongly costs the network a miner; making blocks wrongly costs
the miner its own work and nobody else anything. So where it is not
clear, blocks are made.

Whatever came of a block made here (it is the chain's last, another
got there first, it was refused) is heard at once, and the next is
begun on whatever the chain's last then is.

### 4.2 Trying it

Two nodes to try it with:

```
tabminer --network dev --data-dir /tmp/a --listen 127.0.0.1:3737
tabminer --network dev --data-dir /tmp/b --listen 127.0.0.1:3738 --peer 127.0.0.1:3737
```

The stats log of each shows its height, the blocks that joined its
chain, and those it made (`Mined`).

---

## 5. The wallet and the prompt

A node has a wallet unless it is given `--no-wallet`: the file
`wallet.tab` in its data directory, made the first time the node
starts.

**Its twelve words.** A wallet is made of a phrase of twelve words
(BIP39). When a wallet is made the node says them on the terminal,
once, and nowhere else: not in any log. They are all of the wallet:
whoever has them has what it holds, and a wallet lost is made again
from them.

**Its password.** A new wallet asks for one (none, for no password),
and a wallet that has one asks for it each time the node starts. What
is typed is shown as it is typed. `--password-file FILE` gives it as
the first line of a file and nothing is asked. With `--no-prompt`
nothing can be asked: a new wallet has no password, and one that has
a password needs `--password-file`.

**The prompt.** Once the node is ready it takes commands on the
terminal, at `> `, and answers each there; nothing else is said on the
terminal (the logs are where the node says what happens). `quit`, or
the end of what it reads, stops the node. `--no-prompt` is for a node
run by another program, or in the background: it reads nothing.

```
commands:
  status                    the chain's last block, peers, the pool, the wallet's total
  peers                     how many peers are known, and how many are live
  mempool                   the transactions waiting to be mined
  balance                   confirmed, pending, unverified, reserved and locked funds
  outputs                   the wallet's outputs
  send-file AMOUNT [FEE] FILE
  receive FILE [OUT]
  finalize FILE
  slates                    the payments begun and not yet finalized
  sent                      the payments signed and not yet in a block
  cancel ID [FEE]
  bump ID [FEE]
  resend ID
  prune
  scan                      find this wallet's outputs on the chain (after a restore)
  help
  quit
```

**A payment** is agreed between the two wallets in a slate, which is
text in a file, passed between them however files are:

1. The sender: `send-file 12.5 payment.slate`. What it is to spend is
   reserved (`cancel` frees it).
2. The recipient: `receive payment.slate`, which writes
   `payment.slate.received` with its output added.
3. The sender: `finalize payment.slate.received`. The transaction is
   signed, pooled and told to the node's peers; a block carries it.

**A payment sent and not yet in a block** (`sent` lists them) can
still be changed, by another spend of the same outputs that pays
more, which pools take in place of the first:

- `cancel ID` takes it back: what it spent is paid to this wallet
  again, less a fee that is more than the payment's was.
- `bump ID` pays the same to the same recipient with a higher fee,
  taken from the change.
- `resend ID` pools it again as it was signed.

Each is signed from the next leaf of every key it spends from: a key
signs eight times at the most, so a payment can be replaced seven
times.

Taking a payment back does not settle it, and the node says so:

```
> cancel 8be2a771
payment sent 8be2a771 taken back: transaction 41c07d9e, with a fee of 0.000004966
The transaction has been cancelled, but it could still end up in a block. Call prune to remove the stale transaction from your wallet.
```

Until a block has one of the two, and that block is not undone, either
may still be mined. Meanwhile each wallet counts what the first was to
make as well: as pending on the sender's node, as unverified on the
recipient's. `prune` forgets what will never be made, on each node; it
is not done of itself, because only whoever runs the node can say when
a block is deep enough to rely on.

A wallet never signs twice from one leaf, and that is kept true even
of a wallet whose file has gone back to an earlier state (a copy
kept, a machine's snapshot): it watches the pool for spends of its
own outputs, and passes over every leaf it sees used.

The main log has a line for each step this node's own wallet takes
(and none for anybody else's transactions, which would fill it):

```
[2026-11-17 19:35:10:902] Payment 3f9a1c04 begun: 12.5 and a fee of 0.0000026, from 1 outputs
[2026-11-17 19:35:11:310] Payment 3f9a1c04 signed and pooled: transaction 8be2a771, 12.5 with a fee of 0.0000026
```

and, on the recipient's node, `Payment 3f9a1c04 answered: 12.5 to this
wallet`; a payment given up is said as that.

Amounts are in coins, with up to ten decimals. A fee is coins in all,
or `N/byte`; not given, it is the least the pool takes.

**When the chain goes over to another branch** the wallet goes with
it, and nothing has to be done:

- A payment sent whose block was undone is unconfirmed again. Its
  record is kept until its block is as deep as blocks can be undone,
  so the wallet has it to send again, and does: a payment of this
  wallet's that no block has is kept in the pool, put back there after
  a reorganization, a restart, or a pool too full to keep it.
- An output whose block was undone is lost: shown apart, not counted
  as coming, and not spent from. If a block makes it again it is found,
  wherever it then is; if none has by the time it has been gone as
  long as blocks can be undone, it is forgotten.
- What this costs is as much as the branch is long, not as much as
  the chain holds: the wallet remembers the blocks it last looked at,
  finds where the branches part, and goes through the blocks of the
  new branch from there. Only a wallet with no blocks to go through
  (restored from its words, or further behind than blocks' bodies are
  kept) looks through all the unspent outputs for its own.
- A payment that spent what only the branch given up had (the reward
  of a block that is no more) is never mined: it is no longer listed
  by `sent`, and what it was to make is forgotten by `prune`.
- The main log says what was taken and what came back:

```
[2026-11-17 21:04:10:318] The wallet: 1 payments sent are in no block any more: they are to be mined again
[2026-11-17 21:04:10:318] The wallet: 1 outputs are in no block any more: lost, unless a block makes them again
[2026-11-17 21:04:10:402] The wallet: payment sent 8be2a771 was in no block and not pooled: pooled again
[2026-11-17 21:14:51:977] The wallet: 1 outputs that were lost are in the chain again
```

**What a balance says.** Confirmed: unspent, and in the chain.
Pending: the wallet's own, not yet in the chain (change, the reward of
a block being made). Unverified: an output added to another's slate,
which is nothing until its sender finalizes and a block carries it.
Reserved: picked for a payment begun. Locked: signed away by a payment
not yet in a block. Lost: was in the chain, and is in no block now.

Not yet: paying an address or a name with no file passed (that needs
the message layer), names, restoring a wallet from its words by a
command of the program (the library can).

---

## 6. Still to do

1. **The rest of the wallet** (above).
2. **What is left of `THREADS.md`** (its 8.3).
3. **The peers file and the built-in seeds.** `--peer` and `--seed` are
   what a node begins from today.
4. **The genesis tool** itself, in its package.
