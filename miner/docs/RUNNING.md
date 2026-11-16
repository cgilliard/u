# Running a node

How a node is told what to do, what it says while it runs, and what it
says when it starts and stops.

**This is a proposal.** Nothing in it is built: the binary is empty.
It is here to be changed before any of it is written. Where the
reference node (`tmp/miner`) does something different, that is noted,
with the reason for changing it.

---

## 1. Settings

### 1.1 One name for each setting

Every setting has one name, and that name is used everywhere: on the
command line, in the settings file, in the documentation, and in the
message that refuses a bad value.

The names are the ones the code already uses (`net::config::Config`),
with a dot between group and setting:

```
peers.max            sync.sync_point        serve.rate
```

The reference has a flag for some settings (`--max-undo-blocks`), a
constant in the source for most, and no file. Changing "64 peers"
there means rebuilding.

### 1.2 Where settings come from

Three places, each overriding the one before:

1. **The defaults**, built in.
2. **The settings file**: `tabminer.conf` in the data directory, if
   there is one.
3. **The command line.**

No environment variables. They are a fourth place to look when a node
does something unexpected, and they are invisible in a process list.
(The reference reads `TABMINER_THREADS` from the environment; here it
is the setting `threads`.)

### 1.3 The settings file

Lines of `name = value`. `#` begins a comment. Nothing else: no
sections, no quoting, no includes.

```
# tabminer.conf
listen        = 0.0.0.0:3737
peers.max     = 2000          # this node is a seed
serve.waiting = 5000
sync.sync_point = 144
peer          = 203.0.113.7:3737
peer          = 198.51.100.20:3737
```

A setting that takes several values (`peer`, `seed`) is given once per
value. Any other setting given twice in one place is an error.

### 1.4 The command line

The same names, with two dashes:

```
tabminer node --peers.max 2000 --peer 203.0.113.7:3737
```

A few settings only make sense on the command line, because they say
where the file is: `--data`, `--network`, `--config`.

### 1.5 Values

| Kind | Written | Examples |
|---|---|---|
| Count | digits, `_` allowed | `64`, `8_192` |
| Time | a number and a unit: `ms`, `s`, `m`, `h`, `d` | `30s`, `10m`, `1h` |
| Size | a number and a unit: `B`, `KB`, `MB`, `GB` | `32MB` |
| Address | `host:port`; a seed may be a name, a peer and `listen` must be numbers | `0.0.0.0:3737` |
| Yes or no | `yes`, `no` | `mine = no` |

A time without a unit is refused, not guessed at: `sync.header_wait =
15` could be seconds or milliseconds, and the two are very different
nodes.

### 1.6 A bad setting stops the node before it starts

- A name that is no setting is an error, with the nearest name that is
  one: `peers.maxx: no such setting (peers.max?)`.
- A value that cannot be read is an error naming the setting, the value
  and the place: `tabminer.conf line 4: peers.ping = 30: a time needs a
  unit (30s?)`.
- A value the node cannot run with is an error from the existing check
  (`Config::check`): `peers.target is not between one and peers.max`.

Nothing is opened, bound or written before all settings are read and
checked.

### 1.7 Seeing what a node will run with

```
tabminer config [the same options as node]
```

prints every setting, its value, and where the value came from:

```
peers.max          2000     tabminer.conf line 3
peers.target       8        default
serve.rate         8192     default
sync.sync_point    0        command line
...
```

`tabminer config --changed` prints only those that are not the
default. The same list, of changed settings only, is in the startup
messages (section 3).

### 1.8 The settings there are

Everything in `docs/WIRE.md` section 2.9, under its name, plus:

| Setting | Default | What it is |
|---|---|---|
| `data` | `~/.tabernacle/tabminer` (`-dev`, `-dev-recursive` for those networks) | Where the store, the peers file, the settings file and the log are |
| `network` | `mainnet` | Which network |
| `config` | `tabminer.conf` in `data` | The settings file |
| `listen` | `0.0.0.0:3737` | The address datagrams are taken at |
| `seed` | the network's built-in names | Names to look up for first peers; several |
| `seeds` | `yes` | Whether the built-in seeds are used at all |
| `peer` | none | A peer given by hand, kept whatever it does; several |
| `keep` | `1008` (a week of blocks) | How many blocks can be undone, and so how far back bodies and states are served |
| `threads` | all cores | Threads for hashing and checking proofs |
| `tick` | `1s` | How often the node looks to what passes with time |
| `log.level` | `info` | Section 2 |
| `log.file` | `tabminer.log` in `data` | Section 2 |
| `log.terminal` | `yes` if started from a terminal | Section 2 |
| `log.keep` | `5` files of `20MB` | Section 2 |

Mining, the wallet and the mempool will add theirs when they exist.

**Not settings**, because every node of a network must agree on them:
anything in `ChainParams`, the sizes on the wire, the sizes of the
parts of a state.

---

## 2. What a node says while it runs

### 2.1 The node reports events; something else writes them down

The node proper (`net::node`) touches no socket and no clock, and it
should not touch a log file either. It reports what happened as
values:

```rust
enum Event {
    PeerProven { addr, height },
    PeerDropped { addr, why },
    PeerBanned { addr, strikes },
    HeadersKept { from, count, height },
    BlockJoined { height, id, from },
    BlockRefused { height, id, from, why },
    Reorganized { from_height, to_height, undone },
    StateBegun { height, parts },
    StateWhole { height },
    ...
}
```

and whoever drives it turns them into lines. Three things follow:

- The tests can say "exactly these events happened", which is firmer
  than counting, and nothing they assert on is a sentence that might
  be reworded.
- Wording, level and format are decided in one place.
- Something other than a log (a status command, a wallet's display)
  can listen to the same events later.

The reference builds a sentence with `format!` at each of some two
hundred places and writes it straight out.

### 2.2 A line

```
2026-11-15T20:24:51.203Z info  sync   block 88213 joined (3fa9c1e2), from 203.0.113.7:3737
```

- The time, in UTC, to the millisecond: a log is compared with other
  nodes' logs.
- The level: `error`, `warn`, `info`, `debug`, `trace`.
- The area: `node`, `peers`, `sync`, `chain`, `store`, `serve`.
- What happened, as a short sentence. Block ids are shortened to eight
  characters; addresses are written whole.

One event, one line. Nothing is spread over several.

### 2.3 What is said at each level

| Level | Shown by default | What |
|---|---|---|
| `error` | yes | The node cannot go on, or something is broken that it cannot mend: the store fails, the port cannot be bound |
| `warn` | yes | Something is wrong and the node goes on: a block refused, a peer banned, a state's block given up for a later one |
| `info` | yes | What someone running a node wants to see scroll by: section 2.4 |
| `debug` | no | Each thing fetched and served, each peer taken and dropped, each strike |
| `trace` | no | Each datagram |

`log.level` sets the least level shown. It can be set for one area:
`log.level.sync = debug`.

### 2.4 What `info` is, exactly

A node that is keeping up says about one line a block:

```
info  sync   block 88213 joined (3fa9c1e2), from 203.0.113.7:3737
```

A node that is catching up says where it has got to every ten seconds,
not once per thing fetched:

```
info  sync   headers: 412,000 of 880,000, from 6 peers
info  sync   state as of block 879,856: 1,204 of 165,300 parts (0.7%), from 14 peers, 9.2 MB/s
info  sync   blocks: 879,901 of 880,000
```

And once a minute, whatever it is doing, one line of where it stands:

```
info  node   tip 88213 (3fa9c1e2), best header 88213, 14 peers live of 37 known, serving 3
```

Besides those: starting and stopping (section 3), a reorganisation,
the state taken whole, and the count of live peers falling under or
rising to what is wanted.

### 2.5 The same thing over and over

A peer that sends bad datagrams sends many. A line about one peer's
trouble is written once, and then at most once in ten minutes with how
often it happened since:

```
warn  peers  203.0.113.7:3737 sent a datagram that is no message (212 times in 10 minutes)
```

### 2.6 Where the lines go

- **To the terminal**, if the node was started from one.
- **To a file** in the data directory, always: `tabminer.log`. When it
  reaches 20 MB it becomes `tabminer.log.1`, the old `.1` becomes
  `.2`, and so on to five; the oldest is deleted.

Both, when both apply. The reference writes to the file or the
terminal, never both, by a flag.

### 2.7 What is never written

Tokens, the node's secret, and anything of a wallet's keys.

---

## 3. Starting and stopping

### 3.1 What a start looks like

Each step says what it is doing before it does it, and how long it
took if that was more than a moment: a node that hangs on start then
shows where.

```
tabminer 0.1.0, mainnet
data: /home/chris/.tabernacle/tabminer
settings: tabminer.conf (3), command line (1); 4 not the default:
  peers.max = 2000            tabminer.conf line 3
  serve.waiting = 5000        tabminer.conf line 4
  peer = 203.0.113.7:3737     tabminer.conf line 6
  log.level = debug           command line
store: opened in 0.4 s; block 88213 (3fa9c1e2), 142,113,907 outputs unspent
proof of work: table of epoch 3 loaded in 2.1 s
listening on 0.0.0.0:3737
peers: 37 remembered, 2 seeds, 1 given
ready
```

If the store was being received when the node last stopped:

```
store: opened in 0.4 s; a state was being taken as of block 879,856, 1,204 of its parts received; going on
```

### 3.2 When it cannot start

One line saying what is wrong and, where there is something to do,
what:

```
error: cannot listen on 0.0.0.0:3737: the address is in use (is another tabminer running? set listen to another port)
error: the store in /home/chris/.tabernacle/tabminer is of another network (dev); this is mainnet
error: tabminer.conf line 4: peers.ping = 30: a time needs a unit (30s?)
```

and the process ends with a code that says which kind:

| Code | Meaning |
|---|---|
| 0 | Stopped as asked |
| 1 | Stopped by an error while running |
| 2 | A bad setting or command line |
| 3 | The data directory or the store cannot be used |
| 4 | The network cannot be used (the port) |

### 3.3 Stopping

On an interrupt (Ctrl-C, or the operating system's signal to end):

```
stopping: saying goodbye to 14 peers
stopping: the block being applied is finished first
stopped; tip 88214 (a01f33c9)
```

The node tells its peers it is going, finishes the work it has given
the applier, saves the peers it knows, and closes the store. A second
interrupt ends it at once; the store is safe to be cut off at any
point, so that loses nothing but the goodbye.

Taking an interrupt needs a call into the operating system that the
standard library does not have, so it is written here for each
platform, as the random source already is.

---

## 4. Commands

To begin with:

| Command | Does |
|---|---|
| `tabminer node` | Runs a node |
| `tabminer config` | Prints the settings a node would run with |
| `tabminer help [command]` | Says what there is |
| `tabminer version` | The version, and the networks this build has |

`tabminer` with no command prints the help, and does not start
anything. (The reference starts mining.)

Mining, the wallet and a way to ask a running node how it is are for
later.

---

## 5. Questions

1. **A settings file at all?** Or the command line only, as the
   reference has it?
2. **The dotted names** on the command line (`--peers.max`), the same
   as in the file: or shorter flags for the common ones?
3. **The log line**: a sentence, as above, or `name=value` pairs for
   programs to read, or both (a sentence, then the pairs)?
4. **Terminal and file both by default**, or one?
5. **A status line a minute** at `info`: wanted, too often, or not
   often enough?
6. **`keep`** defaults to 1,008 blocks, a week, as the reference's
   `--max-undo-blocks` does. Every node holds that many bodies: at two
   megabytes a block, about two gigabytes. Right?
7. **Starting from a terminal with no command**: help, as proposed, or
   run a node?
