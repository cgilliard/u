# Proving signatures ahead of the block

A design, not yet built. It changes the circuits of a block's proof, so
it is a change to consensus, to be made before launch.

## 1. The problem

A block's proof is made of segments, and a segment proves two things
about each input it spends, in one circuit (`block_air`, with
`xmss_fragment` inside it):

1. that the input is **signed**: an XMSS signature by the output's key
   over the transaction's body hash;
2. that the input is **there to spend**: its leaf is in the state tree,
   and is taken out of it.

A segment's proof speaks of the state root before it and after it. The
root changes with every block, so every segment proof is void when the
tip changes, the signatures in it with the rest. Nothing of a block's
proof can be made before its parent is known, and nothing is kept from
one parent to the next.

The signature is nearly all of the work:

| Rows of the circuit, for a key of height 20 | |
|---|---|
| Signature (`xmss_fragment::rows(20)`) | 1,182 |
| The rest of an input: key hash, commitment, leaf, removal, body | 93 |
| An output | 93 |

So of the rows a miner must prove after it learns of its parent, more
than nine in ten for a transaction of as many inputs as outputs are
rows that have nothing to do with the parent.

**Why it is a defect and not only a cost.** Every transaction a miner
takes delays the moment it begins to hash, by work that could not be
done earlier and is lost at the next block. A miner that takes fewer
begins sooner. The fee must pay for that delay, where it should pay
only for the space and the little work that is truly the block's.

A block filled with transactions of 2.5 inputs and 2.5 outputs (9,696 of
them in 1.6 MB) is about 33 million rows, some 1,010 segments: by the
times measured on a laptop of six cores, more than an hour, against a
block time of ten minutes.

**What was lost.** An earlier design had this apart. Two circuits are
left of it and used by nothing: `xmss_air` (one signature, its public
values the key's root, its seed and the message: no state in it), and in
the reference `smt_air` (a run of updates to the state tree from one
root to another).

## 2. What is wanted

- A signature is proven **once**, when its transaction is first seen,
  and that proof is good at any tip, through any reorganization, until
  the transaction is in a block or dropped.
- What must be proven after the parent is known is the state's part
  only.
- The block, its header, its body and the statement its proof speaks to
  are what they are today. A verifier (the node, and the small verifier
  of 128 MB) checks one wrapped proof as now; only the constants that
  say which programs the proof was made of are new.
- A block of a reward and nothing else, which is every block of the
  first months, costs no more to prove than it does today.
- Policy inputs and name updates, which carry signatures too, are served
  by the same means.

## 3. The design

### 3.1 Signature segments

A new circuit, the **signature segment**: a trace of the segment's size
holding signature checks and nothing else, about 27 of them for keys of
height 20. It is `xmss_fragment` under a small schedule of its own, as
`xmss_air` was.

For each signature it checks, it makes an **entry**:

```text
entry = H(DOM_SIGNED, key hash[8] ‖ message[8])
```

and its one public value is the root of a small Merkle tree over its
entries (32 leaves, the unused ones a fixed empty digest). Nothing in it
is of any block: the key hash is of the key, and the message is whatever
was signed, a transaction's body hash or a policy's rebindable message
or a name update's message. All three are fixed by the transaction.

### 3.2 The signature tree

Signature segments are gathered as transaction segments are: nodes of
proofs of proofs, four children each. A node's public value is the hash
of its children's roots, so the root of the whole is the root of one
Merkle tree over every entry: the block's **signed set**, `S`.

A missing child is the empty tree of its depth, a constant, with no
proof. The tree has a fixed depth (five levels in a segment and two for
each level of nodes; seven levels of nodes hold 16,384 segments, more
than a block's bytes can spend), so a path through it has one length.

Because a node speaks only of what is under it, a node's proof is good
for as long as its children are among the miner's proofs, wherever they
stand beside others. A miner keeps a tree of signature proofs, adds to
it as transactions come, and makes again only the nodes above what is
new.

### 3.3 Transaction segments, without the signature

A transaction segment keeps everything it does but the signature. Where
it spent 1,182 rows checking one, it now shows that the signature is in
the signed set:

- it has the key hash already (the commitment is made of it) and the
  message already (it hashes the body itself, as now, so the message is
  the body of these inputs and these outputs and no other);
- it hashes them to the entry, and climbs a Merkle path from the entry
  to `S`: one row a level, 19 rows.

`S` is one more public value of a segment, the same in every segment of
a block. An input is then about 115 rows where it was 1,275.

The same serves the rest:

- **Policy inputs.** Each signature of a threshold condition, over the
  body or over the rebindable message, is a path to `S` in place of a
  fragment. The conditions themselves stay where they are: they are
  small, and two of them (`After`, `Older`) are of the block's height.
- **Name updates.** The name segment's signature becomes a path to `S`,
  and the name segment takes `S` as a public value too.

### 3.4 The root

The root of a block's proof verifies today the tree of transaction
segments, the name segment and the proof of the parent's work. It
verifies also the root of the signature tree, and checks that its `S`
is the `S` the transaction segments and the name segment were proven
against. `S` goes no further: it is not in the block's statement.

A block with no signature in it has the empty tree's root for `S`. Its
signature proof is of nothing, the same for every such block: see 5.1
for how it is kept from costing anything.

### 3.5 Why a set, and not a list

The segments could instead absorb the signatures into a sponge in the
block's order, as they do the inputs and outputs, and the signature
proofs be made to match it. That is less work in the circuit (no path),
and wrong for the purpose: a proof over a list is a proof of that list,
and a miner does not know the list until it chooses the block. Every
block that takes some of a miner's waiting transactions and not others
would void the proofs that held both.

With a set, an entry that no input asks for costs nothing and harms
nothing. A signature segment that held 27 signatures of which 20 are
now in someone else's block is still a proof of the 7, and stays in the
tree until the miner thinks it worth making again.

Nothing is opened by this that is not open now. A signature has always
been good wherever its key hash and message are: the body does not hold
positions, and what keeps a transaction from being taken twice is that
its inputs are removed from the state, which stays in the transaction
segment.

## 4. What it costs and saves

For the full block of section 1 (24,240 inputs, 24,240 outputs), by the
times measured on the laptop with today's parameters. These are worked
out from a block of 16 segments, not measured.

| | Today | With this |
|---|---|---|
| Rows after the parent is known | 33 million | 5 million |
| Segments after the parent is known | about 1,010 | about 155 |
| Proofs of proofs after the parent is known | about 340 | about 55 |
| Time after the parent is known | over an hour | about ten minutes |
| Rows that can be proven ahead | none | 29 million (about 900 segments, 300 nodes) |

The work in all is a little more than today's (the paths, and one more
proof at the root). What changes is when it can be done: five parts in
six of it as transactions arrive, kept across tips.

A block is not bigger, a proof is not bigger, and verifying is what it
was. The memory a prover needs is by the proof, not by how many there
are, and no proof here is bigger than today's largest.

After this the state's own rows are what is left, and 84 of an input's
and of an output's are the path through the state tree. Outputs of one
block take positions side by side and share most of their paths; that
is a saving to look for afterwards, and not part of this.

## 5. Not settled

1. **The empty block.** The root verifying one more proof may make the
   root's trace bigger, which a block of the first months would pay for
   in time and memory. Either the empty signature proof is made once and
   kept (it is a constant), which saves the proving but not the root's
   size; or the root has two programs, with and without signatures, and
   a verifier takes either. To be measured before choosing.
2. **Depth of the tree.** A fixed depth of 19 is simple and costs each
   input a few rows it seldom needs. The other way is a depth that is a
   witness, bound into `S`.
3. **Who proves.** A miner, from the moment it has a transaction. A
   sender or a relay could prove a signature segment too, and it would
   be good for any miner; whether proofs travel with transactions, and
   what a node does with one it cannot trust until it has verified it,
   is a question for the mempool, which is not built.
4. **Until there is a mempool,** a miner has no transaction before it
   makes a block, and proves signature segments when it proves the rest:
   no better than today, and little worse.
5. **Networks of quick blocks** (`block_proof`, which checks segment
   proofs one by one) need the same change: signature segment proofs
   beside the transaction segments' and `S` computed over their roots.
6. **Keys of other heights** make signatures of other lengths; how a
   signature segment is filled with them is the fragment's business as
   it is in a transaction segment today.

## 6. What it gives miners reason to do

What is left to prove after the parent is known still takes a miner
time, more for a block with more in it. A miner that waited for that
proof before hashing would lose a share of every block's reward to it,
and would do better to leave the transactions out. The design is sound
only if a miner has no reason to do that, and it has none:

A miner that is after fees makes two blocks on each parent. The first
is of its reward and nothing else, ready as soon as the root, the wrap
and the chain's step are proven; it hashes on that. Beside it, it
proves the block of its waiting transactions, and when that is ready it
hashes on that instead. Taking transactions then costs it no hashing,
and gains it their fees from the moment the second block is ready.

So what the rules reward is: taking transactions; proving signatures as
they arrive; and hardware that makes the second block ready sooner,
since the blocks a miner finds before then earn it no fees.

The network's cost is those blocks, which hold nothing: their share is
the share of the block time by which the second block is later than the
first. Where blocks are not full, what they would have held waits for
the next.

This node does not mine so. It is the reference: it proves one block
and hashes on it. A pool that wants the fees of large blocks will build
the rest, and nothing in consensus is in its way.

## 7. Order of work

1. The signature segment circuit and its tests, from `xmss_fragment`.
2. The transaction segment without the fragment, with the path and `S`;
   policy inputs the same.
3. The name segment the same.
4. `block_proof`, then the tree of signature proofs and the root.
5. The miner: a store of signature proofs, filled in the background.
6. The constants of the main network, made again once, with the change
   of security parameters that is waiting for the same moment.
