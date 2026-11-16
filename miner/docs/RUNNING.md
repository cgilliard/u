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

**Decided, and built** (`src/configuration.rs`), but for the binary that
calls it.

### 1.1 One program, no commands

`tabminer` is the miner, and running it runs it:

```
tabminer [options]
```

There is no `mine`, `node` or `genesis` word after it. A node that does
not mine is `tabminer --no-mine`.

The tool that makes a genesis block is a program of its own, built by
its own Cargo package, so that the miner never has to tell the two
apart. (Today it is a second binary of this package, `tools/genesis.rs`:
still to be moved.)

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

### 3.1 Starting (decided, and built but for the binary)

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
"Server is ready!" comes after the store is open and the port bound.

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

1. **What a request log line holds**, and **which columns the stats log
   has**.
2. **What the main log says between the configuration and "Server is
   ready!"**, and for critical events after.
3. **The genesis tool** as a package of its own.
