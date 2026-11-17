# The wire

How nodes talk to each other: every datagram, who sends it, what comes
back, and what stops it being abused.

This document has two parts.

- **Part 1** describes what the reference node does (`tmp/miner`,
  `net.rs` and `node.rs`). It is a description, not a design.
- **Part 2** is the proposal for this node. Nothing in it is built
  except the transport (`src/transport`). It is here to be argued with.

The fam node (the small verification-only node) must speak whatever
part 2 ends up saying, so part 2 is the specification both are written
against.

---

# Part 1: the reference

## 1.1 Ground rules

- **UDP only, IPv4 only.** IPv6 addresses are never taken: they are
  cheap in bulk and would weaken the per-network limits on the peer
  table.
- **Every datagram fits in 1,232 bytes**, so no path fragments it.
- **A datagram is `TAB1`, a type byte, and a payload.** Integers are
  little-endian.
- **Nothing is encrypted or signed.** Blocks and headers carry their own
  proof of work and validity proof; a peer-table entry is only an
  address to try. (The private messaging layer, 1.7, is the exception:
  its channels are sealed.)
- **Default port 3737.**

## 1.2 Who is listened to

A source address can be forged, so three rules decide whether a
datagram is acted on:

1. **`Ping` and `Pong` are heard from anyone.** A pong is the same size
   as a ping, so answering a forged ping floods nobody.
2. **A request must carry a token.** Each node derives a 64-bit token
   for every address from a secret (a keyed hash of the address), and
   sends it in its `Ping`/`Pong` to that address. A request to that node
   must quote it. Whoever quotes it did receive a datagram at that
   address.
3. **Anything else unasked (headers, announcements, chunks) is heard
   only from a peer that has answered one of our pings** with the right
   nonce: a "handshaken" peer.

So the handshake is: A pings B; B pongs (echoing A's nonce, giving A its
token) and pings A back; A pongs. Both now hold each other's token and
have proved their addresses.

## 1.3 The messages

Type codes in brackets. "Token" means the message is a request under
rule 2.

### Liveness and discovery

| Message | Carries | Answered with | Notes |
|---|---|---|---|
| `Ping` [1] | `Status` | `Pong` | Every 30 s to every peer. A peer not yet answering is re-pinged after 2 s, doubling. |
| `Pong` [2] | `Status`, echoing the ping's nonce | | Proves the address. |
| `GetPeers` [3] | token | `Peers` | Sent while fewer than 8 peers are live. |
| `Peers` [4] | up to 32 addresses | | A random sample of live peers. Each is only an address to ping. |
| `Goodbye` [24] | token | | Sender is shutting down: dropped from the table at once rather than after 180 s of silence. |

`Status` is what a node says about itself, in every ping and pong:

| Field | Bytes | Meaning |
|---|---|---|
| nonce | 8 | Chosen by the pinger, echoed by the pong |
| version | 4 | Protocol version; a mismatch is answered (so the other side can see why) and then ignored |
| token | 8 | What the receiver must quote in requests to the sender |
| genesis | 32 | Genesis block id; another chain is answered and ignored |
| height | 4 | Height of its tip |
| oldest | 4 | Lowest height from which it holds every block body up to its tip (pruned and fast-synced nodes serve headers below this, not blocks) |
| tip | 32 | Its tip's id |
| work | 32 | Cumulative work of its chain |
| min_fee | 8 | It relays nothing paying less per byte |
| pool_fee | 8 | Its pool's current admission minimum |

### Headers

| Message | Carries | Answered with | Notes |
|---|---|---|---|
| `GetHeaders` [5] | token, locator (up to 32 block ids) | `Headers`, several | "What follows the newest of these that you have?" Used to find a fork point. |
| `GetHeadersFrom` [11] | token, height | `Headers`, several | Main-chain headers from a height. Used for bulk sync, many peers at once. |
| `Headers` [6] | up to 6 headers, oldest first | | A request is answered with at most 60 headers, over up to 10 datagrams. |

Header replies are not reliable: each `Headers` datagram stands alone,
and a batch that has not fully arrived in 4 s is asked of another peer.

### Blocks and transactions

| Message | Carries | Answered with | Notes |
|---|---|---|---|
| `Inv` [7] | a new block's header, and its size in bytes | (receiver fetches the block) | Sent to every live peer when a block extends or reorganises our chain. |
| `TxInv` [10] | a transaction id | (receiver fetches it) | Sent when a transaction enters the pool. Ignored by a node still catching up. |

### Object transfer

| Message | Carries | Answered with | Notes |
|---|---|---|---|
| `GetChunks` [8] | token, kind, id, chunk indexes (as ranges) | `Chunk`, one per index | At most 2,048 chunks a request. |
| `Chunk` [9] | kind, id, object length, index, up to 1,024 bytes | | |
| `NotHeld` [25] | kind, id | | "I do not have that": the asker tries another peer now. |

The kinds of object:

| Kind | Named by | What it is |
|---|---|---|
| Block | block id | A whole block |
| Tx | transaction id | A transaction |
| Manifest | block id | The list of parts of the state after that block |
| Part(i) | block id | Part `i` of that state: an output part or, after those, a name part |
| Consensus | file id | A consensus file |
| Lite | block id | A block without its proof, for the fam node |
| Object | object id | A private-messaging object; served only to whom it was offered |

Serving is limited per address to 8,192 chunks a second with a burst of
4,096.

### Light clients

| Message | Carries | Answered with | Notes |
|---|---|---|---|
| `GetProof` [12] | token, output position | `Proof`, two | For a client that holds headers only. |
| `Proof` [13] | position, tip id, the output (commitment, memo, amount, height), half of its Merkle path | | The path takes two datagrams. Checked against the state root of the header named. |

### Aux leaves

A header's `aux` field is the root of 16 leaves of 32 bytes that miners
use to vote (on consensus files, among other things).

| Message | Carries | Answered with | Notes |
|---|---|---|---|
| `GetAux` [14] | token, block id | `Aux` | Asked of the peer that sent the block first; retried every 2 s, 16 times. |
| `Aux` [15] | block id, the 16 leaves | | Checked against the header's `aux`; a mismatch is a strike. |

### Private messaging (not chain)

`Session` [16], `SessionState` [17], `GetAnnounce` [18], `Offer` [19],
`Notice` [20], `Handshake` [21], `Frame` [22], `ChannelGone` [23]. See
1.7.

## 1.4 The flows

### Joining

1. Resolve the seed names and load the peers saved last time.
2. Ping them. Each that pongs is a peer.
3. While fewer than 8 are live, ask peers for more (`GetPeers`) and
   ping what comes back, at most 8 unproven addresses per tick.

### Keeping up (normal sync)

1. Every status says how much work its sender's chain has. While any
   proven peer claims more than our best header, fetch headers.
2. **Headers** are fetched by height in batches of 60, up to 16 batches
   at once, each from a different peer. Complete batches are checked
   (proof of work, difficulty, timestamps) and stored in order. A batch
   that does not follow our best header means a fork: a locator
   (`GetHeaders`) finds where.
3. A peer that sends no header we lack within 15 s is not believed for
   10 minutes, so a false claim of work cannot stall the sync.
4. **Blocks** of the best header's branch are then fetched: up to 24 at
   once, at most 8 from one peer, no further than 32 past the first one
   missing. Each comes from the peer that announced it, else from one
   whose status shows it holds that height.
5. Blocks that arrive before their parent wait in memory and are
   applied in order, on a separate thread.

### A new block

1. The miner (or the node that just applied it) sends `Inv` to every
   live peer.
2. A receiver checks the header. If it is new and valid it fetches the
   block from the announcer, knowing the size from the `Inv`.
3. If the header's parent is unknown, the receiver is behind by more
   than one block and asks the announcer for headers.
4. Once applied, the receiver announces it in turn. A block floods the
   network in a few hops.

### A new transaction

The same shape: `TxInv`, then the receiver fetches it by id (up to 32 at
once, 4 from one peer), checks it into its pool, and announces it. A
peer new to us is told of up to 256 transactions already pooled.

### Fast sync (joining by snapshot)

1. Download every header from the peer claiming most work, checking
   only the quick proof of work.
2. Pick the block 144 below the best header (the sync point). Check the
   full proof of work of that header and every one after.
3. Fetch that block and its manifest. The block's proof is a chain
   proof: it shows that block and every block before it valid. It is
   checked against the manifest's output counter.
4. Fetch the parts, 32 at once, from every peer that can serve them.
   Each is checked against its root in the manifest and stored.
5. Install the state and go on with normal sync from there.

If the sync outlasts the serving peers' window, the target moves to a
later block and parts already stored are carried forward.

## 1.5 The peer table

| Limit | Value |
|---|---|
| Peers kept | 64 |
| Per host (all ports) | 4 |
| Per /16 network | 8 |
| Silence before a peer is not counted live | 65 s |
| Silence before it is dropped | 180 s |
| Strikes before a ban | 5 (forgotten after 10 min) |
| Ban | 1 hour, by host |

A strike is a bad reply to something we asked: a header that fails its
checks, aux leaves that do not match, a manifest the block's proof
rejects. Unasked datagrams never count against the address they claim
to be from.

## 1.6 What looks wrong or worth changing

1. **Headers are sent unreliably.** Ten loose datagrams per request,
   with a 4 s timer and re-asking of whole batches. It works, but it is
   a second, weaker transfer mechanism beside the chunked one.
2. **A proof takes two special datagrams** with their own reassembly
   table. Same remark.
3. **Chunks could be forged by a third party** (fixed in our transport:
   a fetch number).
4. **A slow download was abandoned and restarted from nothing** (fixed
   in our transport: no slow rule, and resume).
5. **The token never changes**, so an address that was once someone's
   is theirs to speak for until the node restarts (fixed in our
   transport: the secret rotates).
6. **Name parts are checked only all together**, at the end (fixed in
   our store: each has its own root).
7. **`min_fee` and `pool_fee` ride in every ping** though they concern
   only transaction relay.

## 1.7 Private messaging, for completeness

About a third of the type codes are not for the chain. They carry the
reference's private messaging: a participant keeps a *session* at a
relay (`Session`, `SessionState`), a sender asks the relay for the
participant's announce (`GetAnnounce`), objects are *offered* rather
than pushed (`Offer`, then fetched as `Object` chunks), outcomes are
reported (`Notice`), and onion channels are set up and used
(`Handshake`, `Frame`, `ChannelGone`). None of the code under these has
been ported. Part 2 reserves their codes and designs nothing for them.

---

# Part 2: this node (proposal)

## 2.1 Principle

**One way to move anything bigger than a datagram: the transport.**
The reference has three (chunks, header batches, proof halves). Here a
request either fits its answer in one datagram, or names an object and
the answer is fetched with `Get`/`Chunk`/`Gone`. Everything fetched
that way is reliable, paced, resumable and works on a bad line, with no
further code.

For that, **an object's bytes must not change while it is being
fetched**, so every object's name pins down its content exactly.

## 2.2 Framing

```
magic (4) | type (1) | body
```

- `magic` names the network (`TABM` main, `TABD` dev, `TABR`
  dev-recursive), so nodes of different networks drop each other's
  datagrams before parsing.
- The transport's chunk is 1,220 bytes at most and leaves 12 of the
  1,232; this uses 5.
- Rules 1 to 3 of 1.2 are kept as they are.
- IPv4 only, as the reference: decided, to keep things simple for now.

## 2.3 The messages

| Code | Message | Body | Answer |
|---|---|---|---|
| 1 | `Ping` | `Status` | `Pong` |
| 2 | `Pong` | `Status` | |
| 3 | `GetPeers` | token | `Peers` |
| 4 | `Peers` | up to 32 addresses (6 bytes each) | |
| 5 | `FindFork` | token, locator (up to 32 ids) | `Fork` |
| 6 | `Fork` | height and id of the newest locator entry on the sender's chain | |
| 7 | `Block` | header (204), body length (4) | (fetch) |
| 8 | `Tx` | transaction id, length | (fetch) |
| 9 | `GetLeaves` | token, block id | `Leaves` |
| 10 | `Leaves` | block id, 16 leaves (512 bytes) | |
| 11 | `Goodbye` | token | |
| 16 | `Get` | the transport's request | `Chunk`s or `Gone` |
| 17 | `Chunk` | the transport's chunk | |
| 18 | `Gone` | the transport's "I do not have it" | |
| 32 to 47 | reserved | private messaging | |

Differences from the reference:

- **`GetHeaders`, `GetHeadersFrom` and `Headers` are gone.** Headers
  are objects (2.4). Finding a fork point is a single small exchange,
  `FindFork` and `Fork`.
- **`GetProof` and `Proof` are gone.** A proof is an object.
- **`GetChunks`, `Chunk`, `NotHeld`** are the transport's three.
- **`Inv` is called `Block`** and `TxInv` `Tx`: they announce one.
- `Tx` is taken only from a peer, and only by a node that is not
  catching up. The transaction is fetched as an object, unless it is
  pooled already or as many are being fetched as may be (64 by one
  worker, 8 of one peer); pooled if the pool takes it
  (`src/mempool.rs`); and then announced to every other peer. One that
  is not the transaction of the id it was announced by, or is badly
  signed, is held against who served it.
- An announcement that cannot be fetched at once waits its turn (1,024
  wait at the most, by one worker).
- A peer new to a node is told of what the node pools, the best paying
  first, 256 at the most.
- Not yet: a peer is not told what a pool asks a byte, so it may
  announce what will be refused. (That is to be a message of the
  pool's own, not a field of `Status`: 2.6.)

## 2.4 The objects

A `Get` names its object in up to 64 bytes: a kind byte, then fields.

| Kind | Name | Content | Largest | Checked by |
|---|---|---|---|---|
| 1 Block | block id | The block's body | 2 MB (the chain's limit) | The header's body commitment |
| 2 Lite | block id | The body without its proof | under that | The fam node's own check |
| 3 Headers | first height (4), count (2), a block id (32) | `count` headers from that height on the chain that block is on | 512 headers, 104 KB | Each header's proof of work and link to the one before |
| 4 Manifest | block id | The top of the state's parts after that block (2.5) | about 150 KB | The block's state root |
| 10 Roots | block id, index (4) | The roots of the parts in one range of 2^25 positions (2.5) | 139 KB | Its root in the manifest |
| 5 Part | block id, index (8) | The unspent outputs in one range of 8,192 positions, and which are commits | under 1 MB | Its root in the manifest |
| 6 Names | block id, index (4) | The name records under one 12-bit key prefix | under 1 MB | Its root in the manifest |
| 7 Proof | block id, position (8) | The output at that position and its Merkle path | 1.4 KB | The block's state root |
| 8 File | file id | A consensus file | to be bounded | Its id (a hash) |
| 9 Tx | transaction id | A transaction | 128 KB | Its id |

Why `Headers` is named with a block id: "headers from height 5,000"
alone would change under a reorganisation while being fetched. "…on the
chain that block X is on" does not. The asker uses the id of the tip
the peer claimed in its status. A peer whose chain no longer holds X
answers `Gone`.

## 2.5 The manifest

What a joining node needs first, to know which parts to ask for and to
check each as it comes. It is fetched by the transport like everything
else; the question it raises is size, because whatever is fetched is
checked only once it is whole.

**How big it could be as one object.** One entry of 40 bytes for every
range of 8,192 positions that holds anything unspent. Positions are
handed out in order and never reused, so the number of ranges is at
most the outputs ever made, over 8,192:

| Outputs ever made | Ranges at most | As one object |
|---|---|---|
| 100 million | 12,000 | 0.5 MB |
| 1 billion | 122,000 | 4.9 MB |
| 10 billion | 1.2 million | 49 MB |

That grows without limit and passes a block's size early. So it is cut
in two levels, each piece checked on arrival against the level above:

| Object | Content | Largest | Checked against |
|---|---|---|---|
| Manifest | next position (8); for each range of 2^25 positions holding anything, its index (4) and root (32); the names' root (32); for each name part, its index (2), root (32) and whether it holds one record (1) | 144 KB for the names, and 36 bytes per 33 million positions ever used: 11 KB at 10 billion outputs | The block's state root |
| Roots | for one range of 2^25 positions: for each of its 4,096 parts holding anything, its index (2) and root (32) | 139 KB | That range's root in the manifest |

Nothing fetched is then bigger than a block, whatever the chain grows
to, and a node that serves a wrong piece is found out by that piece.

The store gives parts' roots at level 13 today; it has to give the
roots at level 25 as well, which the trie already keeps.

## 2.6 Status

| Field | Bytes | Change from the reference |
|---|---|---|
| nonce | 8 | |
| version | 4 | |
| token | 8 | Now changes when the sender's secret rotates; the old one is honoured for one more period |
| genesis | 32 | |
| height | 4 | |
| oldest | 4 | |
| window | 4 | New: the lowest height whose state it can still serve as a snapshot. The reference guessed this from `oldest`. |
| tip | 32 | |
| work | 32 | |

128 bytes. The two fee fields move to a message of the mempool's own,
when there is a mempool.

## 2.7 The flows, where they change

**Header sync.** Ask a peer `FindFork` with our locator; it answers
with the newest block we share. Then fetch `Headers` objects from there:
512 headers each, several at once from different peers, each named with
the tip id that peer claimed. A peer that sends headers which fail
their checks takes a strike and the range is fetched elsewhere.

**Block relay.** Unchanged in shape. `Block` carries the header and the
body's length; the receiver checks the header and fetches the body from
the announcer with a transport fetch of known length.

**How far back blocks can be had.** A node keeps the bodies of the
blocks it can still undo, and below those only headers. Its status
says from which height it holds bodies (`oldest`), and it is asked for
none below. So a node that is further behind than its peers' bodies
reach cannot catch up block by block at all: it has the headers, and
takes the state whole (below). With the reference this was a choice a
node made; here it is how every node is.

**Snapshot sync.** Unchanged in shape: headers, then the block at the
sync point and its manifest, then parts and name parts in parallel from
every peer that can serve them. A fetch that is given up continues with
another peer from where it stopped.

**A peer measured by pings starts measured.** The round trip from
ping and pong seeds the transport's path, so the first fetch from a peer
does not begin with a guessed retry time.

## 2.8 What each message costs the node that answers

| Message | Work | Sent back | Guard |
|---|---|---|---|
| `Ping` | none | 133 bytes for 133 | none needed |
| `GetPeers` | a sample of the table | up to 198 bytes | token |
| `FindFork` | up to 32 lookups | 41 bytes | token |
| `GetLeaves` | one lookup | 549 bytes | token |
| `Get` | read an object (cached) | up to a window of chunks, paced | token, and per-address bounds on what waits |

Nothing unasked is answered with more than it weighs, and nothing large
goes to an address that has not shown it is there.

## 2.9 Configuration

Every limit and time below is a setting with a default, not a constant.
The defaults are the reference's unless noted.

### Peers

| Setting | Default |
|---|---|
| Peers kept | 64 |
| Live peers below which more are looked for | 8 |
| Peers per host (all ports) | 4 |
| Peers per /16 network | 8 |
| Pings to unproven addresses per tick | 8 |
| While short of live peers, how often one is asked for more | 1 s |
| Ping interval | 30 s |
| First re-ping of a peer not yet answering | 2 s, doubling |
| Silence before a peer is not counted live | 65 s |
| Silence before it is dropped | 180 s |
| Silence before a host's place goes to a new port of it | 60 s |
| Strikes before a ban | 5 |
| Strikes forgotten after | 10 min |
| Ban | 1 hour |

### Sync

| Setting | Default |
|---|---|
| Headers in one object | 512 (new) |
| Header objects fetched at once, each from a different peer | 16 |
| Wait for a header we lack before a peer's claim is doubted | 15 s |
| How long a peer that failed us is passed over | 10 min |
| Least time between header requests to one peer | 2 s |
| Blocks fetched at once | 24 |
| Blocks fetched at once from one peer | 8 |
| How far past the first missing block to fetch | 32 |
| Sync point: blocks below the best header a snapshot is taken at | 144 |
| Parts fetched at once | 32 |
| Snapshot attempts before validating from genesis | 4 |
| Aux leaves: time between requests, and requests before giving up | 2 s, 16 |

### Serving and transfer

| Setting | Default |
|---|---|
| Chunks sent a second, in all | 8,192 (about 10 MB/s) |
| Requests for chunks waiting, in all | 64 |
| Requests waiting for one address | 8 |
| Chunks waiting for one address | 4,096 (two full windows; one at the least) |
| How often the token secret changes | 10 min (new) |

### Where a node is

| Setting | Default |
|---|---|
| Port | 3737 |
| Seeds | the network's built-in names |
| Peers given by hand | none |

The settings above are `net::config::Config` in the code (the last
group comes with the node itself). The transport's own numbers (window
bounds, retry bounds, how many places count as overtaken) stay
constants: they are how the mechanism
works, and a node that set them badly would hurt its peers as well as
itself.

A node many others lean on, a seed above all, sets the table and the
serving bounds higher: thousands of peers, thousands of requests
waiting. Both are kept by address, so that neither costs more per
datagram for being large.

A few things are not settings because the two ends must agree on them:
the datagram size, the chunk size, the part sizes, the most headers an
object may hold and the most addresses a `Peers` may carry (32).

## 2.10 Decided, and still open

Decided:

- IPv4 only for now.
- The manifest is cut in two levels (2.5).
- 512 headers an object.
- Limits and times are settings (2.9).
- Sync first. `Lite` blocks and `Proof` objects come after.

Open:

- **Private messaging.** Codes reserved, nothing designed.
