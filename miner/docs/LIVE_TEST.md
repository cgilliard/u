# A live test of payments, on mainnet's parameters

What to start and what to type to pay by address, by name and by a
name under a name, first at the seeds (init mode) and then by ways
through relays (onion mode). Six nodes on one machine. Every step
here has been run on the dev network, by `tools/live_dry_run.py`,
which starts the six nodes and types what follows (twenty-seven
checks, seven minutes): on mainnet's parameters it is to be tried
here for the first time.

Every node is given the same two seeds: where a wallet is reached is
found from them, by everyone alike. `--peer` is not enough.

## The nodes

| Node | Port | What it is |
|---|---|---|
| A | 3737 | seed, relay, the miner (your `node1`) |
| B | 3738 | seed, relay |
| C | 3739 | relay (a third: onion mode needs three) |
| H | 3741 | the wallet that holds the name `mailhub` |
| W1 | 3742 | a wallet |
| W2 | 3743 | a wallet |

Common to all: `--no-seeds --seed 127.0.0.1:3737 --seed 127.0.0.1:3738
--min-confirmations 1 --pow-table target/pow.table`.

    ./target/release/tabminer --data-dir target/live-a  --listen 127.0.0.1:3737 --relay            COMMON
    ./target/release/tabminer --data-dir target/live-b  --listen 127.0.0.1:3738 --relay --no-mine  COMMON
    ./target/release/tabminer --data-dir target/live-c  --listen 127.0.0.1:3739 --relay --no-mine  COMMON
    ./target/release/tabminer --data-dir target/live-h  --listen 127.0.0.1:3741 --no-mine          COMMON
    ./target/release/tabminer --data-dir target/live-w1 --listen 127.0.0.1:3742 --no-mine          COMMON
    ./target/release/tabminer --data-dir target/live-w2 --listen 127.0.0.1:3743 --no-mine          COMMON

A wallet's change is its to spend again only once a block has it: one
funded by a single payment makes one payment a block. Fund each
wallet with several payments before starting (step 1), or wait a
block between payments from the same wallet.

At each, `address` says its wallet's address (`tab1…`); `status` says
`reached at: 2 of 2 nodes` once it is reached at both seeds.

## 1. Init mode

1. Fund the wallets: at A, `send 20 <H>` and `send 20 <W1>`, five
   times each, a block apart (the miner's own change is as any
   wallet's); each is answered and pooled within a second, and mined
   with the next block.
2. By address: at W1, `send 5 <W2's address>`. W1's log says `payment …
   answered by tab1…, signed and pooled`; W2's `balance` has it after
   a block.
3. To itself: at W1, `send 1 <W1's address>`.
4. To nobody: at W1, `send 1 <any address nobody holds>`: an error in
   the log within a few seconds, `was not delivered (that wallet is
   not there): given up, nothing was spent`; `slates` is empty.
5. A name: at H, `name-commit mailhub`; after a block, `name-reveal
   mailhub`; when `names` says `owned`, `name-update mailhub <H's
   address>`. Then at W1, `send 2 @mailhub`.
6. A name under it: at H, `subname set alice@mailhub <W2's address>`.
   At W2, `subnames` says `this wallet is alice@mailhub … reached by it
   at 2 nodes`. At W1, `send 3 alice@mailhub`: W1's log says
   `alice@mailhub is tab1…` and then `signed and pooled`.
7. A name nobody was given: at W1, `send 1 bob@mailhub`: the error of
   step 4, naming `bob@mailhub`.
8. Another key signs for the name: at H, `subname delegate mailhub
   <W1's address> 10 /tmp/mailhub.word`; at W1, `subname signer
   /tmp/mailhub.word`, then `subname set desk@mailhub <H's address>`.
   At W2, `send 1 desk@mailhub`.
9. Stop B (one seed of two): payments still go, by A, a second or
   two slower when B is tried first. `status` says `reached at: 1 of
   2 nodes` after a minute and a half. Start it again.

## 2. Onion mode

1. Write `relays.txt` with the addresses of A, B and C's wallets:

       mode onion
       relay tab1…A 127.0.0.1:3737
       relay tab1…B 127.0.0.1:3738
       relay tab1…C 127.0.0.1:3739

2. At A (the miner): `set-leaf 0 relays.txt`. Its blocks vote for the
   file from then on; `consensus` says how the votes stand and at
   which block the next decision is made (the next multiple of 144).
3. From that block every node's log says `The message layer is in
   onion mode`, and `status` at the wallets says `reached at: 3 of 3
   nodes` within a few seconds.
4. Repeat steps 2 to 8 of part 1. A cold payment takes a second or two
   longer than at the seeds; what is said is the same.
5. Stop C. With three relays every way goes by all three, so every
   way is lost at once: the first payment after takes up to a minute
   (a wallet that is sending nothing finds out at its next word to
   its relays, every half minute) and may be given up with an error,
   to be sent again. From then on payments go as before, by ways of
   one relay less; `status` says `reached at: 2 of 3 nodes`. Start C
   again: 3 of 3 within a minute or two.
6. Leave it running over the next multiple of 144, paying as it
   passes: payments go throughout. (With three relays the wallet's
   three are the same before and after, and `status` says 3 of 3
   throughout; with more it says up to 6 for two blocks either side.)

A payment that is passed on and not answered within a minute is
given up with an error, as one that is not delivered is: nothing
stays begun.

To have onion mode at once instead of waiting for the vote, run every
node with `--network dev-main-work` in a build with `--features dev`
(mainnet's work and schedule, a chain of its own), and type
`debug-consensus relays.txt` at each.
