# Security of tabminer

This note is about the soundness of the proofs.

It estimates the soundness of the block proof: the transaction segment
proofs, the name segment proof and the signature segment proofs, the
recursive node proofs over each, the zero-knowledge wrap proof, and the
chain proof a block carries, which verifies the wrap and the previous
block's chain proof so that one proof covers the whole chain. It covers
the parameters in `AggregatorParams::MAINNET`. All numbers come from
`tools/soundness.py`, run on `tools/soundness_mainnet.json`. The table
dimensions in that file, and the grinding schedule the code derives, are
printed by the ignored test `aggregate::tree_tests::soundness_parameters`.

A forged block needs one forged proof somewhere in the tree. Each proof is a
separate Fiat-Shamir argument with its own transcript. The level of the whole
is therefore the level of the weakest proof type: an attacker gains nothing
by attacking many proofs at once that it would not gain by attacking one.

What a forged proof could buy is narrower than it was. Output amounts are
public: every node checks, outside the proof, that a
block's outputs sum to the amounts the state holds for the outputs it spends
plus its subsidy, and a fast-syncing node that the unspent amounts sum to
everything issued. A forged proof, or a circuit bug, could still spend
outputs without their keys, or break the name registry, but could not
create coins without every node seeing it.

## Summary

The target is 120 bits of conjectured classical security for every proof:
every Fiat-Shamir round of every proof has an error below 2^-121 per attempt.

| proof | queries | conjectured, every round | quantum | proven (Johnson regime) |
|---|---|---|---|---|
| segment (2^17 rows, rate 1/4) | 54 + 16 grinding bits | 120.0 | about 60 | 67.5 |
| name segment (2^15 rows, rate 1/4) | 54 + 16 | 120.0 | about 60 | 67.7 |
| signature segment (2^17 rows, rate 1/4) | 54 + 16 | 120.0 | about 60 | 67.5 |
| node, and signature node (up to 2^19 + 2^17 rows, rate 1/4) | 54 + 16 | 120.1 | about 60 | 67.1 |
| root of a block with signatures (2^20 + 2^17 rows, rate 1/4) | 54 + 16 | 120.2 | about 60 | 67.0 |
| wrap (2^17 + 2^15 rows, rate 1/32) | 22 + 16 | 120.3 | about 60 | 68.5 |
| chain step (2^17 + 2^15 rows, rate 1/32) | 22 + 16 | 120.3 | about 60 | 68.5 |

A chain proof at height h stands for h nested proofs, one per block. A
forger has to forge one of them, and each attempt costs the same as against
a single proof, so the chain is as sound as its weakest proof type: the
figures above, whatever h.

All figures are bits of classical security against a prover that may make
2^λ hash queries. Against a quantum attacker, Grover search over transcripts
roughly halves every figure, grinding included.

How the figures are counted:

- **Conjectured, every round.** The query phase uses the toy-problem
  conjecture of the ethSTARK documentation (v1.2, section 5.9): R bits per
  query, with R = log2(1/rate), plus the grinding. The model also counts
  every earlier Fiat-Shamir challenge:
  - the lookup challenges γ and δ;
  - the constraint combination α;
  - the out-of-domain point ζ;
  - the DEEP batching coefficients;
  - the FRI folding challenges.

  Each of those has an error of degree over |K| (Schwartz–Zippel, list size
  one). With |K| = 2^123.6 they are not negligible: at the parameters of
  2025 they held the proofs to 92–95 bits. The prover therefore grinds
  before each of them, as many bits as its error falls short of 121
  (`StarkConfig::commit_bits`, below). The result is the smallest round minus
  one, as in the documentation's equation 19.
- **ethSTARK formula.** The number usually quoted for STARKs counts the
  queries only: min(grinding + R·s, log2|K|) − 1, which is 122.6 here, the
  cap set by the field.
- **Proven.** This applies the round-by-round theorem of the ethSTARK
  documentation (Theorem 5, from BCIKS20 in the Johnson regime), with the
  same grinding, maximised over its parameter m.

## The field and the hash

- **Field.** BabyBear, p = 2^31 − 2^27 + 1. All challenges come from its
  quartic extension K, with |K| = p^4 ≈ 2^123.6. This one number caps every
  algebraic round.
- **Hash.** Poseidon2 with Plonky3's `default_babybear_poseidon2_16`
  parameters: width 16, x^7 S-box, 8 full and 13 partial rounds, Plonky3's
  constants. It is checked against Plonky3's known-answer test. Digests are 8
  elements, about 247 bits. That gives:
  - Merkle and commitment collisions at about 2^124 classically, and about
    2^82 quantumly (Brassard–Høyer–Tapp, with impractical quantum memory);
  - preimages at about 2^247 classically and about 2^124 quantumly.

  The compiler of [BCS16] needs digests of at least 2λ + 3 bits, which allows
  λ up to 122. The hash is not the limiting factor.
- **Signatures.** XMSS signatures (W-OTS+, w = 16, tweakable Poseidon2
  hashing, 247-bit digests) are far above 100 bits classical and above 100
  bits quantum. Their security reduces to second preimages of the tweaked
  hash.

## Round by round

Each entry is bits per attempt (−log2 of the error), with the grinding bits
before the challenge in parentheses.

| round | segment | root (the largest node) | wrap |
|---|---|---|---|
| lookup challenges (LogUp) | none | 121.6 (25) | 121.6 (22) |
| constraint combination (powers of α) | 121.3 (9) | 121.5 (7) | 121.5 (7) |
| out-of-domain point ζ (DEEP) | 121.0 (16) | 121.2 (20) | 121.3 (18) |
| batching (independent coefficients) | 121.6 (17) | 121.5 (20) | 121.3 (20) |
| FRI folding, first round (later rounds need 2 bits less each) | 121.6 (19) | 121.6 (22) | 121.6 (22) |
| queries, toy-problem conjecture | 124.0 | 124.0 | 126.0 |
| queries, list-decoding-capacity radius | 122.0 | 122.0 | 124.3 |

The signature segment has the segment's rows and rate, 661 columns
against 926 and 2,486 constraints against 2,592: its rounds are the
segment's. The name segment is a quarter the rows (2^15) with 911
columns and 2,958 constraints: its rounds are the segment's with two
bits less of grinding before ζ, the batching and the folding.

Without grinding and with powers of one challenge for the batching, the
same rounds gave the following bits (the parameters of 2025, on the
smaller tables of then: 42 queries, and a wrap of 16 queries plus 20
bits):

| round | segment | node | wrap |
|---|---|---|---|
| lookup challenges | none | 98.6 | 100.6 |
| constraint combination | 112.9 | 114.5 | 114.5 |
| out-of-domain point | 107.0 | 103.1 | 104.3 |
| batching | 96.1 | 93.6 | 92.5 |
| first fold | 104.6 | 101.6 | 100.6 |

What each error term counts:

- **Batching** uses one independent coefficient per committed column and
  per quotient chunk, sampled from the transcript after the openings
  (`stark::Deep`). BCIKS20's bound for affine spaces then gives the line
  error, |D|/|K| per FRI input, whatever the number of polynomials. Each
  column is opened at ζ and gζ through one quotient by (x − ζ)(x − gζ), so
  a row of the recursive verifier still costs one product per column; the
  verifier samples a few hundred extension elements more. Until this
  change the columns were combined with powers of one challenge β, as in
  Plonky3. The combination is then a curve of degree L, the number of
  opened polynomials (1,440 for a segment, 1,030 for a node, 1,118 for the
  wrap), and BCIKS20's bound for curves multiplies the line error by L.
  That cost about 10 bits, made batching the weakest round, and at 121 bits
  would have needed 25 to 30 bits of grinding, minutes per proof.
- **The lookup term** is the degree of the LogUp identity in (γ, δ):
  rows × Σ(tuple length + 1), over |K|.
- **The folding term** is arity × domain over |K|, per round.
- **DEEP** is (quotient degree + n)/|K|, summed over the tables.

This problem is not specific to tabminer. A 2026 audit of OpenVM by Cantina
found the same effect for BabyBear^4. There the commit phase reached 99.5
bits against a 100-bit claim, and OpenVM added a grinding step before
sampling ζ.

## Zero knowledge

The wrap and chain proofs hide their traces: the last `blind_rows` rows of
every trace and auxiliary trace are random, and the quotient chunks are
masked. A column is a polynomial over `Fp` opened at ζ and gζ, which lie in
the quartic extension, so each of those two openings reveals four
`Fp`-linear functions of the column, each query row one more, and the
quotient at a query row the next row's values. The blinding must exceed
all of that: `2 × queries + 8` rows (52 for the wrap, which has 22
queries). With fewer rows, as before (queries + 4), a few linear relations
on each column's real rows would leak per proof.

## Commit-phase grinding

Before each challenge of the commit phase, the prover finds a witness w such
that, after observing w, the transcript's next sample has its low g bits
zero. The verifier checks this with one permutation. The number of bits g is
computed in `fri::grinding_bits`: the smallest g that brings the challenge's
error term (above) to `commit_bits`. It is computed with integer arithmetic
only (the logarithms are fixed-point), so every verifier derives the same
schedule. The prover, the native verifier and the recursive verifier all
compute the schedule with `stark::grinding_of`, and FRI computes it per round
with `fri::fold_grinding`.

The cost is 2^g permutations per challenge, about 1 s at 21 bits on the
development laptop, all cores. Measured end to end at 121 bits, on the
smaller tables the proofs had before signatures were proven apart, grinding
adds about 6 s to a one-segment block and about 78 s to a 16-segment block
(five nodes at about 10 s each, mostly the 24 bits before the lookup
challenges); at 113 bits it added 2.7 s and 6 s.

## The 2025 counterexamples

The query phase's "R bits per query" rests on proximity gaps for
Reed–Solomon codes holding up to capacity. Crites and Stewart (ePrint
2025/2046) and Diamond and Gruen (ePrint 2025/2010) disproved the
up-to-capacity versions of the correlated-agreement and list-decoding
conjectures. Later work (ePrint 2026/782, arXiv 2604.09724) shows failures
within O(1/log n) of capacity over prime fields.

The repaired conjectures stop at the list-decoding capacity radius δ, with
H_q(δ) = 1 − ρ. Our FRI codewords are over K, so q = 2^123.6, and that radius
costs very little: 1.96 instead of 2 bits per query at rate 1/4, and 4.92
instead of 5 at rate 1/32. That is the "list-decoding capacity" row of the
round-by-round table, 1.5 to 1.9 bits below the toy-problem figure, and
still above the 121-bit rounds.

Whether the O(1/log n) failures cost more in practice is not settled. Their
constants are not known to us, so leave a few bits of margin above the
target.

## Proven security

In the Johnson regime, BCIKS20's correlated-agreement error is
(m + ½)^7·|D|² / (3ρ^{3/2}|K|). The |D|² factor leaves about 42 to 47 bits
before grinding over a 124-bit field (about 63 with it), and queries give
only log2(1/(√ρ(1 + 1/2m))) bits each.

**More queries do not reach the conjectured figure.** The proven figure
is the least of the rounds, and at these parameters the queries are the
least: about 68 bits. With about twice the queries (113 at rate 1/4, 45
at rate 1/32) the query round passes 100 bits, and the batching and the
folding become the least, at 80 to 88 bits by the size of the table;
they do not depend on the number of queries at all, so 400 queries give
the same. They are held where they are by the field against the square
of the domain.

| | conjectured | proven |
|---|---|---|
| These parameters | 120 | 67 to 68.5 |
| About twice the queries | 120 | 80 to 88 |
| Any number of queries | 120 | 80 to 88 |

What would take the proven figure further:

- **A combiner with a better bound.** The |D|² / |K| term is of the
  way FRI combines functions by a scalar. A 2026 result (Affine
  Combiners for Reed-Solomon Proximity Gaps, ePrint 2026/2863) claims an
  error of O(1/|K| + |D|²/|K|²) near the Johnson radius for an affine
  combiner, which over this field would leave the batching and the
  folding near the field's own bound, about 120 bits. It is recent and
  we have read its abstract only; nothing here relies on it.
- **A larger field** (below).

No deployed STARK on a 31-bit field claims proven security at these
sizes; Block et al. (ePrint 2024/1161) find provable levels 21 to 63
bits below the conjectured ones.

The parameters are held where they are until that result is settled:
raising the queries alone would double the proof and the time to verify
it for about 15 bits of proven security, and would be needed again,
with the combiner, to reach 120.

## Going further

Getting past 120 bits is held back by the field. |K| = 2^123.6 caps the
ethSTARK figure at 122.6, and every algebraic round at 123.6 minus its
degree, so at most two more bits are available, each doubling all the
grinding (the lookup challenges of a node already take 8 s). Beyond that:

- a larger extension field. The quintic extension of BabyBear, about 2^155,
  would add about 31 bits to every algebraic round, but the recursive
  machine works in Fp4 words;
- then the digest. The BCS compiler allows λ up to 122 with 247-bit
  digests, and collisions cost 2^124. A width-24 Poseidon2 (Plonky3's other
  BabyBear instance, 8 full and 21 partial rounds) with a 10-element digest
  gives 310 bits.

## Measured cost

Measured by `aggregate::tree_tests::security_configs` on the development
laptop (six cores), with two segment provers at a time, at the
parameters above.

| block | proven in | most memory | proof | verify |
|---|---|---|---|---|
| a reward alone | about 40 s | 3.8 GB | 205 KB | 17 ms |
| 300 transactions, 600 signatures | 180 s, of which about 65 s must follow the parent | 4.1 GB | 205 KB | 17 ms |

With about twice the queries (113 and 45), measured on the same blocks
before the prover's last saving of memory: the proof is about 400 KB and
takes 35 ms to verify; a proof that verifies other proofs takes about
twice as long to make and a segment the same; the second block took
about 330 s and 7 to 9 GB.

The grinding dominates the step from 112 to 120 bits of conjectured
security: each challenge needs 8 more bits, 256 times the work, and a
node's lookup challenges alone take 2^25 permutations.

What each proof costs on its own, and what a full block comes to, is in
`POOL_SCALING.md`.

## What the proofs are of

Signatures are not checked where they are used. A signature segment
checks up to 128 XMSS signatures and says, for each, an entry: the
key's hash, the message and the signing leaf's index, compressed. The
entries of a block's signature segments are the leaves of one tree, the
block's signed set, made by the signature nodes; and wherever a
transaction segment or the name segment rests on a signature, it shows
a path from the entry to the set's root, which the block's root holds
to what the top of the signature tree says (`docs/PREPROVING.md`).

- The fragment that verifies a signature takes keys of any height up to
  20, with the height a one-hot register hashed into the key hash and
  the tree tweaks keyed by level index and height, so a key's height
  cannot be misstated.
- The set is read as a set: an entry nobody asks for is no harm. What
  must hold is that an entry asked for is there, which is the path, and
  that every entry there is of a signature that verifies, which is the
  signature segments' and their nodes'.
- A path is compressions and nothing else. The tree hashes each entry,
  and each root a node is over, alone before pairing them; hashing a
  digest alone is compressing it with a fixed digest. A path that
  compresses up to the root went through the tree's own nodes, or two
  compressions collide.
- A policy spend's leaf, path and conditions are rows of the
  transaction segment, and its signatures are looked up as an input's
  is. A rebindable signature's leaf index, which a policy holds to the
  state number, is in the entry.

A segment's outputs are put in the state tree together when the segment
ends, from a stack whose digest is an entry's hash compressed with the
digest of what is under it. That each entry is set down where a subtree
of its size begins, in place of an empty one, is held where it is set
down (`docs/PREPROVING.md`, section 9).

## The header and the proof

A header commits to what its block does and not to the proof that comes
with it, so that a miner can look for its nonce while the proof is
made. One block can therefore come with one valid proof or another, or
with what is no proof at all. Two rules keep that harmless
(`src/chain/apply.rs`):

- A proof that is not accepted is never held against the block. The
  copy is dropped, its header kept, and the block taken when it comes
  with a proof that holds. Otherwise a peer could have a node refuse a
  good block for good by sending it first with a bad proof.
- Whoever sent the copy answers for it, including for a block kept on a
  side branch and found wanting only when the branch was tried.

Nobody but the block's maker can make another valid proof for it: that
takes the transactions, which only the maker has.

## References

- ethSTARK Documentation v1.2, StarkWare, ePrint 2021/582. Equation 19
  (conjectured), Theorem 5 and Section 7.1.1 (round by round), Theorem 7
  (BCS).
- Ben-Sasson, Carmon, Ishai, Kopparty, Saraf: Proximity Gaps for
  Reed–Solomon Codes (BCIKS20).
- Block et al.: Fiat–Shamir Security of FRI and Related SNARKs, ePrint
  2024/1161.
- Crites, Stewart: On Reed–Solomon Proximity Gaps Conjectures, ePrint
  2025/2046; Diamond, Gruen, ePrint 2025/2010.
- Failure of proximity gaps close to capacity, ePrint 2026/782; Proximity
  Gaps Conjecture Fails Near Capacity over Prime Fields, arXiv 2604.09724.
- Affine Combiners for Reed-Solomon Proximity Gaps, ePrint 2026/2863
  (abstract only read).
- Cantina, OpenVM v1.5.0 security review (2026): commit-phase grinding
  before ζ for BabyBear^4.
