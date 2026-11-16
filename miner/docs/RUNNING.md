# Running a node

How a node is told what to do, what it says while it runs, and what it
says when it starts and stops.

The logs (section 2) are decided and built. The rest is being settled:
what is marked **decided** is, and what is marked **proposed** is here
to be changed before it is written. The binary is still empty. Where the
reference node (`tmp/miner`) does something different, that is noted,
with the reason for changing it.

---

## 1. Configuration

### 1.1 One program, no commands (decided)

`tabminer` is the miner, and running it runs it:

```
tabminer [options]
```

There is no `mine`, `node` or `genesis` word after it. A node that does
not mine is `tabminer --no-mine`.

The tool that makes a genesis block is a program of its own, built by
its own Cargo package, so that the miner never has to tell the two
apart. (Today it is a second binary of this package, `tools/genesis.rs`:
to be moved.)

### 1.2 Options (decided)

Every option is `--name` or `--name value`. All configuration is by
options.

- **An option that is not one**: the node prints

  ```
  Error: unknown configuration option: '--<option>'
  ```

  then the help, and exits.
- **`--help` anywhere** on the command line: the help is printed and the
  node exits with code -1. Nothing else on the line is looked at.
- **Every option is checked before anything is done** (1.4).

### 1.3 The help, in sections (proposed)

```
tabminer: a node of the Tabernacle network. It mines unless told not to.

usage: tabminer [options]

General
  --help                    print this and exit
  --network NAME            mainnet (default), dev or dev-recursive
  --data-dir DIR            where the chain, the peers file and the logs are
                            kept (default ~/.tabernacle/tabminer)
  --threads N               threads for hashing and checking proofs
                            (default: every core)

Mining
  --no-mine                 follow the chain without mining

Network
  --listen ADDR:PORT        the address datagrams are taken at
                            (default 0.0.0.0:3737)
  --peer ADDR:PORT          a peer to keep whatever it does; may be repeated
  --seed HOST:PORT          a seed to look up besides the built-in ones;
                            may be repeated
  --no-seeds                do not use the built-in seeds

Peers
  --max-peers N             peers kept (default 64)
  --target-peers N          live peers below which more are looked for
                            (default 8)
  --max-peers-per-host N    peers of one host, over all its ports (default 4)
  --max-peers-per-network N peers of one /16 network (default 8)
  --ping-seconds N          between pings of a peer (default 30)
  --peer-live-seconds N     a peer silent this long is not counted live
                            (default 65)
  --peer-drop-seconds N     a peer silent this long is dropped (default 180)
  --ban-strikes N           wrong answers before a host is refused (default 5)
  --ban-seconds N           how long it is refused (default 3600)

Sync
  --sync-point N            take the state whole as of the block N under the
                            best header when blocks cannot be had
                            (default 144; 0: never)
  --max-undo-blocks N       blocks that can be undone, and whose bodies and
                            states are served (default 1008)
  --header-fetches N        runs of headers fetched at once (default 16)
  --block-fetches N         blocks fetched at once (default 24)
  --block-fetches-per-peer N  of those, from one peer (default 8)
  --part-fetches N          parts of a state fetched at once (default 32)
  --header-wait-seconds N   how long a peer claiming more work may take to
                            send a header we lack (default 15)
  --pass-over-seconds N     how long a peer that failed us is passed over
                            (default 600)

Serving
  --serve-chunks-per-second N   chunks sent a second, in all (default 8192)
  --serve-queue N           requests for chunks that may wait (default 64)
  --serve-queue-per-peer N  of those, from one address (default 8)

Logging
  --log-dir DIR             where the logs are kept (default: --data-dir)
  --main-log FILE           the main log (default main.log in the log directory)
  --request-log FILE        the request log (default request.log there)
  --stat-log FILE           the stats log (default stat.log there)
  --log-rotate-seconds N    a log's file is put aside after this long
                            (default 3600)
  --log-rotate-bytes N      or when it holds this much (default 1048576)
  --request-log-queue N     lines that may wait to be written to the request
                            log (default 10000)
  --stat-interval-seconds N between lines of the stats log (default 10)
  --stat-summary-seconds N  between its wholes (default 60)
```

Everything a node can be told is in the help, with its default: there
are no settings that can only be found in the source. The few numbers
left out are the ones that are not a node's to choose (`docs/WIRE.md`,
2.9).

### 1.4 What is checked (decided that it is; the list is proposed)

One routine goes through every option before anything is opened, bound
or written, and reports the first thing wrong as

```
Error: <what is wrong>
```

followed by the help, and exits.

| Wrong | Said as |
|---|---|
| An option that is not one | `unknown configuration option: '--prot'` |
| An option that needs a value and has none | `--max-peers needs a value` |
| A value that is not what the option takes | `--max-peers: 'many' is not a number` |
| A port out of range, or an address that is not one | `--listen: '0.0.0.0:70000' is not an address and port` |
| An option given twice that may be given once | `--data-dir was given twice` |
| A value the node cannot run with | `--target-peers (100) is over --max-peers (64)` |
| A directory that cannot be used | `--log-dir: /var/log/tab cannot be written to: permission denied` |

The values a node cannot run with are the ones `net::config` already
refuses (a live silence under two pings, a serving queue under one
peer's share, and so on), said in terms of the options.

### 1.5 Where the logs go (decided)

For each of the three logs, the first of these that was given:

1. **Its own option**, the file's full name: `--main-log`,
   `--request-log`, `--stat-log`.
2. **`--log-dir`**: the log, under its default name, in that directory.
3. **`--data-dir`**: the log, under its default name, in the data
   directory. This is what happens if nothing is said.

```
tabminer                                   ~/.tabernacle/tabminer/main.log
tabminer --data-dir /srv/tab               /srv/tab/main.log
tabminer --data-dir /srv/tab --log-dir /var/log/tab
                                           /var/log/tab/main.log
tabminer --log-dir /var/log/tab --stat-log /mnt/fast/stat.log
                                           /var/log/tab/main.log
                                           /var/log/tab/request.log
                                           /mnt/fast/stat.log
```

A file put aside is put beside the file it was (section 2.3).

---

## 2. The logs

**Decided, and built** (`src/logger`), but for what goes in the request
and stats logs and the settings' names, which come with the node.

### 2.1 Three logs

| Log | Holds | Written by |
|---|---|---|
| Main | How the node was started and with what settings; then only errors, critical events and stopping; and each time another log's file was put aside, under what name | Whoever calls it, on their own thread |
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
  how a run was configured is on the screen and in the file.

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

### 2.5 The stats log

In columns, a line at a time. (The columns here are an example: which
there are, and how wide, follows from what the node counts.)

```
Uptime: 300:00:00         Requests_______BytesSent_________PeersLive
[2026-10-17 19:30:44:000] 3,000          1,000,003         14
10s ending 19:30:54:      3              100               13
10s ending 19:31:04:      4              105               15
10s ending 19:31:14:      5              200               12
10s ending 19:31:24:      10             1,000             12
10s ending 19:31:34:      1              900               15
10s ending 19:31:44:      0              30                15
Uptime: 300:01:00         Requests_______BytesSent_________PeersLive
[2026-10-17 19:31:44:000] 3,023          1,002,338         15
10s ending 19:31:54:      43             1,030             13
```

- **Every ten seconds** (a setting): what happened in those seconds,
  after how long they were and the time they ended at.
- **Every minute** (a setting): the columns' names, with how long the
  node has been up, and under them the whole since it started, with
  the time. So six interval lines come between two wholes.
- **Counted numbers add up.** A whole is the whole before it and the
  intervals between: above, 3,000 and the six intervals' 23 are 3,023.
  The last interval's line and the whole after it are written at the
  same moment from one reading of the numbers, so this is exact.
- **Levels do not.** Peers live is, in every line, what it was at that
  moment.
- Intervals are counted from when the node started, not each from the
  one before, so they do not drift.
- When the node stops, what happened since the last interval's line is
  written as a last, shorter interval, and then the whole: the last
  whole adds up as every other.
- A column is as wide as its name and its numbers need. A number too
  wide for its column moves the rest of that line over.

Numbers and times are written by the same few functions in every log
(`logger::fmt`): commas between thousands, bytes in the unit that fits,
uptime as hours, minutes and seconds.

### 2.6 Nothing here stops the node

A line that cannot be written is counted, and the first failure is said
once on the terminal. If the log's directory goes and comes back, so
does the log.

### 2.7 Still to settle

- Which requests are logged, and what a request's line holds.
- Which numbers the stats log shows.
- The settings for each log (file name, rotation age and size, queue
  size, the two stats intervals).

---

## 3. Starting and stopping

### 3.1 Starting (decided in outline; the lines are proposed)

When the configuration has no errors, the node says so in the main log
and on the terminal alike (`log_all`): first when it started, then how
it is configured, so that a log shows exactly how that run was set up.

```
[2026-10-17 19:30:44:000] tabminer 0.1.0 started
[2026-10-17 19:30:44:000] configuration:
[2026-10-17 19:30:44:000]   network                mainnet
[2026-10-17 19:30:44:000]   data-dir               /home/chris/.tabernacle/tabminer
[2026-10-17 19:30:44:000]   mine                   yes
[2026-10-17 19:30:44:000]   listen                 0.0.0.0:3737
[2026-10-17 19:30:44:000]   max-peers              2000          (default 64)
[2026-10-17 19:30:44:000]   ...
[2026-10-17 19:30:44:000]   main-log               /var/log/tab/main.log
[2026-10-17 19:30:44:000]   request-log            /var/log/tab/request.log
[2026-10-17 19:30:44:000]   stat-log               /mnt/fast/stat.log
```

Every option is listed with the value in force, and those that are not
the default say what the default is.

Then each step of starting, as it is done:

```
[2026-10-17 19:30:44:412] store opened: block 88213 (3fa9c1e2), 142,113,907 outputs unspent
[2026-10-17 19:30:46:530] proof of work table of epoch 3 loaded
[2026-10-17 19:30:46:531] listening on 0.0.0.0:3737
[2026-10-17 19:30:46:531] ready
```

### 3.2 When it cannot start (proposed)

A configuration error is as in 1.4. Anything else that stops a start is
one line, on the terminal and in the main log if that could be opened,
saying what is wrong and what can be done:

```
Error: cannot listen on 0.0.0.0:3737: the address is in use (is another tabminer running?)
Error: the store in /srv/tab is of another network (dev); this is mainnet
```

### 3.3 After that (decided)

The main log holds only errors, critical events, each file of another
log put aside, and stopping.

### 3.4 Stopping (proposed)

On an interrupt (Ctrl-C, or the operating system's signal to end):

```
[2026-10-17 21:02:10:118] stopping
[2026-10-17 21:02:10:240] stopped; tip 88214 (a01f33c9)
```

The node tells its peers it is going, finishes the work it has given
the applier, saves the peers it knows, writes the last of the stats and
request logs, and closes the store. A second interrupt ends it at once;
the store is safe to be cut off at any point.

Taking an interrupt needs a call into the operating system that the
standard library does not have, so it is written here for each
platform, as the random source already is.

---

## 4. Still to settle

1. **What comes after "the time the server started"** in the startup
   messages: the message that asked for it ended there.
2. **A settings file** as well as options, or options only? (Written
   here as options only.)
3. **Times in whole seconds and sizes in bytes**, with the unit in the
   option's name, as above: or values with units (`1h`, `1MiB`)?
4. **The default names** of the three logs: `main.log`, `request.log`,
   `stat.log`?
5. **`--help` exits with -1**, as asked. An unknown option and a bad
   value: -1 as well?
6. **What a request log line holds**, and **which columns the stats log
   has**.
