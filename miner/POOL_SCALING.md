# Proving full blocks: how a pool scales out

**Purpose of this document.** While the reference implementation will
not implement it, we contemplate how a mining pool or large miner might
scale out their implementation such that full blocks (2 MB) can work in
a reasonable and economical manner.

The reference node proves a block on one machine, one proof after
another, and then looks for its nonce. That is enough for the blocks of
a young network, which hold a reward and a few transactions. This note
is about the other end: what a full block's proof is made of, which
parts of it can be made before the block it stands on is known, which
cannot, how each part divides among machines, and what hardware that
comes to.

Nothing here asks anything of consensus. A block proven by a cluster
is the same block, with a proof a verifier cannot tell from one made on
a laptop.

## 1. Summary

- A block's proof is a tree of proofs. Every proof in it but the last
  three depends on a few others at most, so the tree is proven a level
  at a time, each level on as many machines as it has proofs.
- **Signatures are proven ahead.** Checking a signature is nine-tenths
  of the work of spending an output, and has nothing to do with the
  chain's state. Signature proofs are made as transactions arrive, kept,
  and used at whatever block the transactions end up in. For a full
  block this is about five-sixths of all the proving.
- **What must wait for the parent block** is the state's part: a full
  block's 30 or so state segments, the dozen proofs that gather them,
  and three proofs at the end. On the measuring laptop that is about
  nine minutes; on a server or a few, two to three; and there is a
  floor of six proofs one after another that more machines do not
  shorten.
- **A header does not commit to its proof.** A miner looks for the
  nonce while the proof is being made, so proving time costs it no
  hashing. A pool hashes on a block of its reward alone until the full
  block's proof is ready, and loses only the fees of the blocks it
  finds meanwhile; or, once fees are enough of a block's income, on
  the full block from the start.
- **The hardware is three servers of 64 cores**, for a proof ready
  about 2.3 minutes after the parent; one is enough to keep up. No
  GPUs. With that, about a fifth of blocks come without transactions
  while the reward is large, and none once it is small.
- No single proof needs more than about 4 GB of memory at the
  parameters measured here. A cluster is many small provers, not one
  large one.

Every figure for a full block below is worked out from the costs of
single proofs measured on one laptop (section 8). No full block has
been proven. A pool should measure its own hardware before it buys.

## 2. What a block's proof is made of

```text
signature segments ──► signature nodes ──► top of the signature tree ─┐
   (from transactions alone; made ahead)                              │
                                                                      ▼
state segments ──► nodes ──► ... ──────────────────────────────────► root ──► wrap ──► chain step
   (from the parent's state)        name segment, parent's work ──────┘                    ▲
                                                                         the parent's proof ┘
```

| Proof | What it shows | Depends on |
|---|---|---|
| Signature segment | Up to 128 signatures verify: for each, an entry of the key's hash, the message and the signing leaf | The transactions only |
| Signature node | Four signature segments, or four signature nodes, verify; and their entries' tree has this root | The proofs under it |
| State segment | Inputs are unspent and are removed from the state; outputs are added; amounts and lists agree with the block; every signature it needs is in the block's signed set | The state the parent left; the signed set's root |
| Node | Four state segments, or four nodes, verify and follow one another | The proofs under it |
| Name segment | The block's name operations | The state; the signed set's root |
| Work | The parent's proof of work | The parent's header |
| Root | Everything above is one block: the state segments, the name segment, the parent's work, and the top of the signature tree | All of them |
| Wrap | The root verifies; a small proof with zero knowledge | The root |
| Chain step | The wrap verifies, and the parent's chain proof | The wrap; the parent's proof |

A block with no signatures (a reward and nothing else) has no
signature tree, and its root verifies one proof fewer.

### Sizes

| | |
|---|---|
| Rows of a state segment, and of a signature segment | 2^17 |
| An input | 124 rows |
| An output | 12 rows, and a merge of 7 for most |
| A signature, in a signature segment | about 1,190 rows: 110 to a segment |
| Children of a node | 4 |
| Segments a block may have | 16,384 state, 16,384 signature |

A transaction of 2.5 inputs and 2.5 outputs is 165 bytes of a block and
about 360 rows of a state segment. A block is 2 MB, and its proof about
205 KB of that: the 1.795 MB left holds 10,878 such transactions, about
27,200 inputs and as many outputs.

| A full block | |
|---|---|
| State segments | about 30 |
| Nodes over them | about 10, in two levels |
| Signature segments | about 248 |
| Signature nodes | about 83, in four levels |

## 3. What can be made ahead

A signature segment says nothing of any block. Its proof is good from
the moment its transactions are known until they are in a block or
dropped, through any number of new tips and reorganizations.

**The signed set is a set.** A state segment shows that the signature
it needs is somewhere in the block's signed set, by a path to the set's
root. An entry nobody asks for is no harm. So:

- A pool proves signature segments as transactions arrive, in whatever
  groups suit it, without knowing which block they will be in.
- When another miner's block takes some of a segment's transactions,
  the segment still serves for the rest. It is made again only when
  enough of it is dead to be worth the room.
- Signature nodes are over whatever four proofs are under them. A pool
  keeps a tree of signature proofs, adds segments at its edge, and
  makes again only the nodes above what changed: about one node a
  level for each new segment, four levels for a full block's worth.

**What a block needs of the tree** is one proof at its top, whose
entries hold every signature the block uses. The top may be at any
level. Where a node has fewer than four children the rest are proofs of
nothing, of a segment with no signature or of a node over four such;
these never change and are made once.

**Empty slots cost nothing to carry but something to make.** A node
verifies four children whatever they are. A pool should fill nodes, and
size its tree to its pool of transactions, not to the largest block.

Also made ahead, as soon as the parent's header is known and before its
state is needed: the proof of the parent's work.

## 4. What must wait for the parent

A state segment begins from the state root the segment before it
ended at, and the first from the root the parent block left. Another
block changes that root, and with it every path in the tree, whichever
outputs it touched. So the state segments, the nodes over them, the
name segment, the root, the wrap and the chain step are proven for one
parent and are worth nothing on another.

Two things keep this part small.

**An input is a lookup, not a signature.** 124 rows, of which 84 are
its path out of the state tree and 31 the lookup of its signature.

**Outputs go into the tree together.** A segment's outputs are built
into subtrees as they come and set down in the tree when the segment
ends, a subtree at a time. So an output is about 19 rows, where a path
of its own would be 84 more.

Segments must be proven in order of the state they start from, but not
one after another: the witness of every segment (the paths it needs,
the state root it starts from) is computed first, from the state, in
well under a second a segment, and then all segments are proven at
once.

## 5. The critical path

With as many machines as proofs, what remains is the chain of proofs
that must follow one another:

```text
state segments  ──►  nodes  ──►  nodes  ──►  root  ──►  wrap  ──►  chain step
   (all at once)   (all at once)
```

For a full block that is six proofs in sequence: a segment, two levels
of nodes, the root, the wrap, the chain step. A block of up to four
state segments (about 1,400 transactions) has no level of nodes: four
proofs. The last three are the same for every block, a reward alone
included.

More machines shorten a level to the time of its slowest proof and no
further. What shortens the chain itself is making one proof faster:
more cores to a proof, or a prover on other hardware. Section 8 has
what one proof costs on six cores.

## 6. Dividing the work

A unit of work is one proof. Each is made from a witness of some
megabytes and returns a proof of some hundreds of kilobytes, so the
work travels well.

| Role | Does | Needs |
|---|---|---|
| Coordinator | Holds the mempool and the state; picks a block's transactions; computes every state segment's witness; hands out proofs to make and gathers them | The node's state; little computing |
| Signature provers | Signature segments and signature nodes, continuously, as transactions arrive | About 4 GB a proof |
| Block provers | State segments and nodes, in a burst when a parent arrives | About 4 GB a proof |
| The last three | Root, wrap and chain step, on the fastest machine there is: they are the floor | About 4 GB |

Signature proving is steady work and block proving is a burst every
block. A pool can give the burst machines of their own, or have the
signature provers drop what they are doing when a parent arrives and
take it up again after; the second is cheaper and costs a little of the
signature backlog.

**What to keep, and for how long**

| Kept | Until |
|---|---|
| Signature segment proofs, with which transactions each holds | Too few of its transactions are still unconfirmed |
| Signature node proofs | A child changes |
| The proofs of nothing | Forever |
| The proof of the parent's work | The parent is replaced |
| State segments and nodes | The parent is replaced: then they are worth nothing |

**When the tip changes** every state proof in progress is abandoned at
once and the coordinator starts again on the new parent. Signature
proofs go on untouched.

## 7. Mining while proving

A header commits to what its block does (the inputs, outputs and
operations, and the state after) and not to the proof. A miner knows
its header as soon as it has chosen the block and computed the state
root, well under a second, and looks for the nonce from then on. The
block can be sent when both the nonce and the proof are there.

So proving never costs hashing. What it costs depends on what a miner
hashes on while the proof is being made, and there are two ways to go
about it.

**Its reward's block first.** A block of the reward alone has the
shortest proof there is: the last three of section 5. A pool hashes on
that, and changes over to the full block when the full block's proof is
ready. It never loses a block to proving, and is never worse off than a
miner of empty blocks; the blocks it finds before the change carry no
transactions and earn no fees.

**The full block from the start.** A pool hashes on the full block at
once. If it finds the nonce before the proof is ready it must wait, and
another miner's block may arrive first: then it loses the block, reward
and fees.

Which is better is a matter of how long the proof takes and how much of
a block's income is fees: section 10.

## 8. What one proof costs

Measured on one laptop: an AMD Ryzen 5 7530U, six cores, with the
parameters of `AggregatorParams::MAINNET` as they are at the time of
writing (54 queries at rate 1/4 for segments and nodes, 22 at rate 1/32
for the wrap). A proof used all six cores unless it says otherwise.

| Proof | Time | Most memory |
|---|---|---|
| State segment | 10 to 12 s (two at once: 12.5 s each) | 3.2 GB |
| Signature segment, 100 signatures | 11.5 s (two at once) | about 2 GB each |
| Signature node | 16 to 19 s | 3.5 to 3.8 GB |
| Root, of a block with signatures | 26 to 28 s | 4.1 GB |
| Wrap | 22 to 26 s | 3.3 GB |

| A whole block, on that laptop | Proven in | Most memory |
|---|---|---|
| A reward alone | about 40 s | 3.8 GB |
| 300 transactions (600 signatures) | 180 s, of which about 65 s waits for the parent | 4.1 GB |

Not measured, and estimated below: a node over four state segments
(taken as 25 s, between a signature node and a root), and the chain
step (taken as 25 s, about a wrap).

Verifying a block's proof takes about 17 ms, and the proof is about
205 KB, whatever the block holds.

## 9. A full block

From the counts of section 2 and the costs of section 8.

| Work for one full block | Proofs | On the laptop |
|---|---|---|
| Signature segments | 248 | about 24 minutes |
| Signature nodes | 83 | about 24 minutes |
| **Made ahead** | | **about 48 minutes** |
| State segments | 30 | about 3 minutes |
| Nodes | 10 | about 4 minutes |
| Root, wrap, chain step | 3 | about 1.3 minutes |
| **After the parent** | | **about 9 minutes** |

A full block every ten minutes is therefore about 48 minutes of this
laptop's work on signatures, steadily, and about 9 on the state in a
burst: some 340 core-minutes a block, 34 cores kept busy.

| Hardware (laptop-class cores) | Signatures keep up with full blocks | Proof ready after the parent |
|---|---|---|
| The laptop, 6 cores | No: a fifth of them | 9 minutes |
| One server, 64 cores | Yes, with half to spare | about 3 minutes |
| Three such servers | Yes | about 2.3 minutes: the critical path |

The last line is the floor of section 5 at these costs: a segment, two
levels of nodes, the root, the wrap and the chain step in sequence,
each on six cores.

### The hardware, in full

Three servers of 64 cores and 128 GB each (a proof takes six cores and
about 4 GB, so a server makes about ten at once). One of them is
enough to keep up; three have the proof ready soonest and leave one
free to fail. Disks and network are of no account: witnesses and proofs
are megabytes.

No GPU is needed for any of it, and the prover has no GPU code.
Signatures are proven on the same CPUs, ahead of time.

This is the proving alone. The hashing is elsewhere, on the pool's
miners, each with the table of the proof of work (1.1 GB in the first
year) and nothing else of this list. The coordinator is the node
itself, with its mempool and state, and is light.

### How the cluster's time is spent

Signature proving does not stop for a block. The critical path is wide
only where it begins:

| Step | Proofs at once | Cores | For about |
|---|---|---|---|
| State segments | 30 | 180 | 12 s |
| Nodes, first level | 7 | 40 | 25 s |
| Nodes, second level | 2 | 12 | 25 s |
| Root, then wrap, then chain step | 1 | 6 | 75 s |

| In ten minutes, for full blocks | Core-minutes |
|---|---|
| Signatures, made ahead | about 290 |
| The critical path | about 50 |
| Three servers have | 1,920 |

The cluster is under a fifth busy. Its size is not for the amount of work,
which one server has room for, but for the twelve seconds in which 30
segments are proven at once.

### Below the floor

More machines do nothing for six proofs that follow one another. What
shortens them is making a single proof faster: more of a server's
cores to one proof, or a prover on a GPU. Neither has been measured,
and it is the first thing a pool should measure: everything in section
10 turns on it.

More than half the floor is the last three proofs, which every block
has, a reward alone included. They are where faster hardware counts
most.

## 10. What the delay costs, and who pays

Write `t` for how long after the parent a pool's full proof is ready,
and take the block time as ten minutes. The next block is found within
`t` of the last with probability `1 - e^(-t / 10 min)`: about `t / 10
min` while `t` is short.

| Proof ready after | Blocks found before it is |
|---|---|
| 2.3 minutes | 20% |
| 1 minute | 10% |
| 30 seconds | 5% |
| 15 seconds | 2.5% |

### The two ways compared

| | Its reward's block first | The full block from the start |
|---|---|---|
| Loses | The fees of the blocks found before the proof: `t / 10 min` of its fees | The whole of a block overtaken while it waits: `(t / 10 min)^2 / 2` of its blocks |
| At 2.3 minutes | 20% of its fees | 2.6% of its blocks |
| At 1 minute | 10% | 0.5% |
| At 30 seconds | 5% | 0.1% |
| The network sees | Blocks without transactions | Blocks with them, and a few more stale ones |

The full block from the start is the better way once fees are enough
of a block's income:

```text
fees / (reward + fees)  >  t / 20 minutes
```

(A pool with a large share of the hashing has a threshold a little
lower: the block that overtakes it is sometimes its own.)

### Across the emission

The reward is 1,500 coins a block for three and a half years, 500 for
the next three and a half, and 7 from then on.

| Proof ready after | Fees must be | With 1,500 a block | With 500 | With 7 |
|---|---|---|---|---|
| 2.3 minutes | 11% of income | 195 coins a block | 65 | 0.9 |
| 1 minute | 5% | 79 | 26 | 0.4 |
| 30 seconds | 2.5% | 38 | 13 | 0.2 |

- **While the reward is large**, fees are a small part of a block's
  income, and a pool does best to hash on its reward's block first. A
  share of blocks, `t / 10 min` of them, come without transactions.
  This is when blocks are least likely to be full, so the room that
  costs is room nobody was waiting for; a transaction that misses such
  a block is in the next.
- **Once the reward is 7**, fees are most of a block's income as soon
  as the chain is used at all: under one coin a block, a ten-thousandth
  of a coin a transaction of a full block. Pools mine full blocks from
  the start, with any hardware, and blocks without transactions are
  gone.

So the years in which empty blocks are the rational thing to mine are
the years in which the reward is what secures the chain; and by the
time fees must secure it, taking transactions is plainly the better
way.

### What it gives miners reason to do

- **To take transactions.** At the margin a transaction costs a pool
  close to nothing, either way of mining, so long as it pays a fee at
  all.
- **To prove faster.** In the first way, each minute off the delay is
  a tenth more of a pool's blocks with fees. In the second, the blocks
  lost to waiting fall with the square of the delay. Either way faster
  proving is paid for out of fees, and more of it is worth buying the
  more fees there are.
- **And it favours those who do.** When fees are nearly all of a
  block's income, a pool whose proof takes 2.3 minutes gives up 2.6%
  of its income to blocks overtaken, and one whose proof takes 30
  seconds a tenth of a percent. That is an edge to better proving
  hardware of the kind faster block relay gives elsewhere, and of
  about that size once proofs take well under a minute.

### What the network pays

With pools of commodity servers and the prover as it is, about a fifth
of blocks carry no transactions while the reward is large: capacity is
four-fifths of nominal when blocks are full, and unchanged when they
are not. Nothing is lost in security: a block without transactions is
as much work as any. The share falls as proving gets faster and as
fees grow, each of which gives pools reason for the other.

## 11. Limits and cautions

- **Memory is by the proof.** The figures above are the most one proof
  held. A machine proving `k` at once needs `k` times that. The
  coordinator keeps the witnesses and finished proofs of a block: a few
  megabytes a segment.
- **These parameters are not final.** The security parameters are to
  be raised before launch (`SECURITY.md`, when written). More queries
  cost the proofs that verify other proofs most: with about twice the
  queries, a signature node and a root took about twice as long and
  held about 7 GB, a segment the same as now, and the block's proof
  was about 400 KB and took 35 ms to verify.
- **A block cannot spend what it makes.** A segment's outputs are in
  the tree only when the segment ends, and a block's witnesses are of
  the state the parent left. A transaction that spends another's
  output waits for the next block.
- **A full block is the worst case.** A transaction's cost is in its
  inputs: 124 rows against an output's 19, and a signature to prove
  ahead. A block of the same bytes with fewer inputs is less work.
- **Nothing here has been built.** The reference node has no mempool
  yet and proves a block's signatures with the block. The counts are of
  the circuits as they are; the times are of single proofs on one
  machine.
