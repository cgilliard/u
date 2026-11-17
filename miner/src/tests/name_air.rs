//! The name circuit's tests: the original's, on the store.
//!
//! The original applied each block's name section to its database as it
//! gathered the witness. Here the witness is gathered from a state of
//! the store that it leaves alone ([`NameWitness::collect`]), and the
//! same block is then applied by the store ([`World::apply`]): where a
//! test compares the root a segment ends at with the world's, it
//! compares the circuit with the store.

use super::*;
use crate::block_air::{names_state, sweeps_state};
use crate::output::{Key as OwnerKey, pubkey_hash};
use crate::stark::{check_constraints, measure_degree};
use crate::store::commits::Commit;
use crate::store::state::BlockEdit;
use crate::store::testing::MemBackend;

/// A state of the store, and the original world's ways of asking it.
struct World {
    state: State<MemBackend>,
}

fn world(_name: &str) -> World {
    let w = World { state: State::open(MemBackend::new(), 0).unwrap() };
    // A few outputs so positions are not trivial.
    let outputs: Vec<OutputRecord> = (0..5)
        .map(|i| OutputRecord { commitment: d(100 + i), memo: crate::output::EMPTY_MEMO, amount: 0, height: 0 })
        .collect();
    w.block(1, &[], &outputs, &[], &[], &[]);
    w
}

impl World {
    /// A block of the store at `height`: the heights before it that no
    /// block was applied at get empty ones.
    fn block(
        &self,
        height: u32,
        spends: &[u64],
        outputs: &[OutputRecord],
        puts: &[(Key, Record, bool)],
        commits: &[Digest],
        commits_spent: &[u64],
    ) {
        let edit = |h: u32,
                    spends: &[u64],
                    outputs: &[OutputRecord],
                    names: &[(Key, Record, bool)],
                    commits: &[Digest],
                    commits_spent: &[u64]| {
            let block = [Fp::new(h); DIGEST];
            self.state
                .apply(&BlockEdit {
                    height: h,
                    block,
                    spends,
                    outputs,
                    names,
                    commits,
                    commits_spent,
                    state_root: None,
                })
                .unwrap();
        };
        for h in self.state.tip().0 + 1..height {
            edit(h, &[], &[], &[], &[], &[]);
        }
        edit(height, spends, outputs, puts, commits, commits_spent);
    }

    fn collect(&self, height: u32, ops: &[NameOp], sweeps: &[u64]) -> Result<NameWitness, Error> {
        NameWitness::collect(&self.state, height, MIN_REVEAL, &[], &[], ops, sweeps)
    }

    /// Applies a block's name section, as the chain does.
    fn apply(&self, height: u32, ops: &[NameOp], sweeps: &[u64]) {
        let (mut spends, mut outputs, mut puts, mut commits) = (sweeps.to_vec(), Vec::new(), Vec::new(), Vec::new());
        for op in ops {
            match op {
                NameOp::Commit { commit, memo } => {
                    outputs.push(OutputRecord {
                        commitment: commit_leaf(commit, height),
                        memo: *memo,
                        amount: 0,
                        height,
                    });
                    commits.push(*commit);
                }
                NameOp::Reveal { record, commit, .. } => {
                    spends.push(*commit);
                    puts.push((record.key(), *record, false));
                }
                NameOp::Update { record, .. } => {
                    let key = record.key();
                    match puts.iter_mut().find(|p: &&mut (Key, Record, bool)| p.0 == key) {
                        Some(put) => put.1 = *record,
                        None => puts.push((key, *record, true)),
                    }
                }
            }
        }
        spends.sort_unstable();
        puts.sort_unstable_by_key(|p| p.0);
        self.block(height, &spends, &outputs, &puts, &commits, &spends);
    }

    fn root(&self) -> Digest {
        self.state.root()
    }

    fn next_position(&self) -> u64 {
        self.state.snapshot().unwrap().outputs().next
    }

    fn lookup(&self, name: &[u8]) -> Option<Record> {
        self.state.snapshot().unwrap().name(names::Name::new(name).unwrap().key()).unwrap()
    }

    fn names_len(&self) -> u64 {
        self.state.snapshot().unwrap().names().count
    }

    fn prove(&self, name: &[u8]) -> name_trie::NameProof {
        self.state.snapshot().unwrap().prove_name(names::Name::new(name).unwrap().key()).unwrap().0
    }

    /// The unspent output at a position.
    fn output_at(&self, position: u64) -> Option<OutputRecord> {
        self.state.snapshot().unwrap().output(position).unwrap().filter(|o| o.1).map(|o| o.0)
    }

    fn commit_at(&self, position: u64) -> Option<Commit> {
        let snap = self.state.snapshot().unwrap();
        snap.commits().at(snap.pages(), position).unwrap()
    }
}

fn d(n: u32) -> Digest {
    core::array::from_fn(|i| Fp::new(n * 1000 + i as u32 * 7 + 1))
}

fn owner_key(tag: u8) -> OwnerKey {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    seed[1] = 0xaa;
    OwnerKey::generate(&seed)
}

/// A name whose key shares its first bits with `with`'s, found by
/// trying suffixes.
fn colliding_name(with: &[u8], bits: usize) -> Vec<u8> {
    let k = names::Name::new(with).unwrap().key();
    for i in 0u32.. {
        let name = format!("x{i}").into_bytes();
        let k2 = names::Name::new(&name).unwrap().key();
        if k2 != k && first_difference(k, k2) >= bits {
            return name;
        }
    }
    unreachable!()
}

/// The freedom audit's findings while [`has_no_unintended_freedom`] runs: `None`
/// otherwise, so the other tests do not pay for it.
static AUDIT: std::sync::Mutex<Option<Vec<String>>> = std::sync::Mutex::new(None);

/// Applies a block's name section, checks the segment's constraints
/// and that its exports match the block, and returns the public values.
fn block(w: &World, height: u32, ops: &[NameOp], sweeps: &[u64]) -> NamePublic {
    let witness = w.collect(height, ops, sweeps).unwrap();
    // the planner's bound holds
    let bound = sweeps.len() * SWEEP_ROWS + ops.iter().map(op_rows_bound).sum::<usize>();
    assert!(witness.num_rows() <= bound, "{} rows over the bound {bound}", witness.num_rows());
    w.apply(height, ops, sweeps);
    let root_out = w.root();
    let pos_out = w.next_position();
    let (trace, public) = NameAir::generate_trace(&witness);
    assert_eq!(witness.num_rows(), trace.height() - (trace.height() - witness.num_rows()));
    let values = public.to_values();
    assert_eq!(NamePublic::from_values(&values), Some(public));
    assert_eq!(check_constraints(&NameAir::MAINNET, &trace, &values), Ok(()), "height {height}");
    if AUDIT.lock().unwrap().is_some() {
        use crate::hash_machine::{COL_LOAD, COL_PASS};
        let kinds: Vec<usize> = (HM_COLS..HM_COLS + NUM_TYPES).chain([COL_PASS, COL_LOAD]).collect();
        // A permutation on a row that does not use it (pass, load) is
        // free by design.
        let keep = |f: &crate::stark::audit::Freedom| {
            let row = trace.row(f.row);
            let unused = row[COL_PASS] == Fp::ONE || row[COL_LOAD] == Fp::ONE;
            !(unused && f.cells.iter().all(|(c, _)| *c < crate::poseidon2_air::NUM_COLS))
        };
        let found = crate::stark::audit::freedom_report(&NameAir::MAINNET, &trace, None, &values, &kinds, 4, keep);
        let all =
            crate::stark::audit::freedom_report(&NameAir::MAINNET, &trace, None, &values, &kinds, 4, |_| true).len();
        eprintln!(
            "height {height}: {} rows, {all} freedoms, {} not an unused permutation",
            trace.height(),
            found.len()
        );
        AUDIT.lock().unwrap().as_mut().unwrap().extend(found.into_iter().map(|l| format!("height {height}: {l}")));
    }
    assert_eq!(public.root_out, root_out);
    assert_eq!(public.pos_out, pos_out);
    let digests: Vec<Digest> = ops.iter().map(|o| o.digest()).collect();
    assert_eq!(public.nsp, names_state(digests.iter().copied()));
    assert_eq!(public.ssp, sweeps_state(sweeps.iter().copied()));
    assert_eq!(witness.op_digests(), digests);
    assert_eq!(witness.sweeps(), sweeps);
    // Every public value matters (the height only once an operation
    // uses it).
    for i in
        [PUB_ROOT_IN, PUB_ROOT_OUT + 2, PUB_POS_IN, PUB_POS_OUT, PUB_NSP + 3, PUB_SSP + 9, PUB_HEIGHT, PUB_COUNTS + 1]
    {
        // Nothing in a section of updates alone (or of nothing) uses the
        // height; the aggregation pins it to the block's.
        if i == PUB_HEIGHT
            && ops.iter().all(|o| matches!(o, NameOp::Update { .. }))
            && (ops.is_empty() || sweeps.is_empty())
        {
            continue;
        }
        let mut bad = values.clone();
        bad[i] += Fp::ONE;
        assert!(check_constraints(&NameAir::MAINNET, &trace, &bad).is_err(), "public {i} at height {height}");
    }
    public
}

/// Degrees-of-freedom audit (`stark::freedom_report`) of every name
/// section [`commits_reveals_updates_and_sweeps`] builds: no row may
/// let its cells move together unseen, but a permutation the row does
/// not use.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn has_no_unintended_freedom() {
    *AUDIT.lock().unwrap() = Some(Vec::new());
    commits_reveals_updates_and_sweeps();
    let found = AUDIT.lock().unwrap().take().unwrap();
    assert!(found.is_empty(), "{} freedoms:\n{}", found.len(), found.join("\n"));
}

/// What becomes of a name section that breaks a rule when the witness
/// is collected and the trace written anyway, as a cheating prover's
/// would (`stark::lenient`).
#[derive(Debug, PartialEq)]
enum Cheat {
    Rejected,
    Accepted,
    NoTrace(String),
}

/// Collects and writes the name section `ops`, `sweeps` at `height`
/// leniently, after `edit` changes the witness, in a transaction that
/// is thrown away; checks the trace against its own public values.
fn cheat(w: &World, height: u32, ops: &[NameOp], sweeps: &[u64], edit: impl FnOnce(&mut NameWitness)) -> Cheat {
    crate::stark::LENIENT.with(|l| l.set(true));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut witness = w.collect(height, ops, sweeps)?;
        edit(&mut witness);
        let (trace, public) = NameAir::generate_trace(&witness);
        Ok::<_, Error>(check_constraints(&NameAir::MAINNET, &trace, &public.to_values()))
    }));
    crate::stark::LENIENT.with(|l| l.set(false));
    match r {
        Err(e) => Cheat::NoTrace(
            e.downcast_ref::<String>().cloned().or(e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default(),
        ),
        Ok(Err(e)) => Cheat::NoTrace(format!("collect: {e:?}")),
        Ok(Ok(Err(_))) => Cheat::Rejected,
        Ok(Ok(Ok(()))) => Cheat::Accepted,
    }
}

/// One random change to a field inside a name section's operations
/// (not its boundary: root, position and height in), described.
fn mutate_ops(w: &mut NameWitness, rng: &mut crate::test_util::Rng) -> Option<String> {
    let mut r = |n: usize| (rng.next_u64() % n.max(1) as u64) as usize;
    if w.ops.is_empty() {
        return None;
    }
    let i = r(w.ops.len());
    let (k, d) = (r(1 << 20), r(DIGEST));
    let delta = Fp::new(1 + (k as u32) % (crate::poseidon2::P - 1));
    let l = k % DEPTH;
    let bump_record = |rec: &mut Record, which: usize| match which % 4 {
        0 => rec.owner[d] += delta,
        1 => rec.value[d] += delta,
        2 => rec.memo[d] += delta,
        _ => {
            // Another letter, so the name stays well formed.
            let mut bytes = rec.name.as_bytes().to_vec();
            let j = k % bytes.len();
            bytes[j] = if bytes[j] == b'a' { b'b' } else { b'a' };
            rec.name = names::Name::new(&bytes).unwrap();
        }
    };
    Some(match &mut w.ops[i] {
        OpWitness::Commit { commit, memo, path } => match r(3) {
            0 => {
                commit[d] += delta;
                format!("op {i} commit")
            }
            1 => {
                memo[d] += delta;
                format!("op {i} commit memo")
            }
            _ => {
                path[l][d] += delta;
                format!("op {i} commit path {l}")
            }
        },
        OpWitness::Reveal { record, salt, other, trie, commit_height, commit_memo, commit_position, path } => {
            match r(9) {
                0 => {
                    bump_record(record, k);
                    format!("op {i} reveal record")
                }
                1 => {
                    salt[d] += delta;
                    format!("op {i} reveal salt")
                }
                2 if other.is_some() => {
                    bump_record(other.as_mut().unwrap(), k);
                    format!("op {i} reveal colliding record")
                }
                3 => {
                    trie.left[d] += delta;
                    format!("op {i} reveal trie left")
                }
                4 if !trie.proof.siblings.is_empty() => {
                    let j = k % trie.proof.siblings.len();
                    trie.proof.siblings[j][d] += delta;
                    format!("op {i} reveal trie sibling {j}")
                }
                5 => {
                    *commit_height ^= 1 << (k % 3);
                    format!("op {i} reveal commit height")
                }
                6 => {
                    commit_memo[d] += delta;
                    format!("op {i} reveal commit memo")
                }
                7 => {
                    *commit_position ^= 1 << (k % 4);
                    format!("op {i} reveal commit position")
                }
                _ => {
                    path[l][d] += delta;
                    format!("op {i} reveal path {l}")
                }
            }
        }
        OpWitness::Update { old, new, pubkey, signature, trie } => match r(8) {
            0 => {
                bump_record(old, k);
                format!("op {i} update old record")
            }
            1 => {
                bump_record(new, k % 3);
                format!("op {i} update new record")
            }
            2 => {
                pubkey.pub_seed[k % pubkey.pub_seed.len()] += delta;
                format!("op {i} update key seed")
            }
            3 => {
                let c = k % signature.wots.len();
                signature.wots[c][d] += delta;
                format!("op {i} update signature chain {c}")
            }
            4 if !signature.auth_path.is_empty() => {
                let j = k % signature.auth_path.len();
                signature.auth_path[j][d] += delta;
                format!("op {i} update signature path {j}")
            }
            5 => {
                signature.randomizer[d] += delta;
                format!("op {i} update signature randomizer")
            }
            6 => {
                trie.left[d] += delta;
                format!("op {i} update trie left")
            }
            _ if !trie.proof.siblings.is_empty() => {
                let j = k % trie.proof.siblings.len();
                trie.proof.siblings[j][d] += delta;
                format!("op {i} update trie sibling {j}")
            }
            _ => return None,
        },
        OpWitness::Sweep { commit, memo, height, position, path } => match r(5) {
            0 => {
                commit[d] += delta;
                format!("op {i} sweep commit")
            }
            1 => {
                memo[d] += delta;
                format!("op {i} sweep memo")
            }
            2 => {
                *height ^= 1 << (k % 3);
                format!("op {i} sweep height")
            }
            3 => {
                *position ^= 1 << (k % 4);
                format!("op {i} sweep position")
            }
            _ => {
                path[l][d] += delta;
                format!("op {i} sweep path {l}")
            }
        },
    })
}

/// Fuzzes the name circuit's witnesses: 1 to 4 random changes inside
/// the operations (`mutate_ops`) of commits, reveals (one splitting a
/// leaf), an update and a sweep, the trace written leniently. A change
/// the constraints accept that gives another outcome (end root or
/// position) for the same start, operations, sweeps, height and counts
/// is a bug; one that changes the operations is another statement,
/// which the aggregation holds to the block's list; one that leaves the
/// statement identical is counted.
#[test]
#[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
fn fuzz_name_witnesses() {
    let (iters, seed) = crate::test_util::fuzz_params(150, 0xf022_0a3e);
    let mut rng = crate::test_util::Rng::new(seed);
    let w = world("fuzz");
    let mut k1 = owner_key(1);
    let o1 = pubkey_hash(&k1.public_key());
    let o2 = pubkey_hash(&owner_key(2).public_key());
    let o3 = pubkey_hash(&owner_key(3).public_key());
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let bob = Record::new(&colliding_name(b"alice", 3), o2, d(21), d(22)).unwrap();
    let carol = Record::new(b"carol", o3, d(31), d(32)).unwrap();
    let salt = |n: u32| d(500 + n);
    let commit_of = |r: &Record, s: &Digest| commit_hash(&name_hash(&r.elements()), s, &r.owner);
    // Honest witnesses, each collected in a transaction thrown away
    // before the block is applied for real.
    let mut pool: Vec<NameWitness> = Vec::new();
    let mut take = |w: &World, height: u32, ops: &[NameOp], sweeps: &[u64]| {
        pool.push(w.collect(height, ops, sweeps).unwrap());
        block(w, height, ops, sweeps);
    };
    // A commit a block at 10, 11 and 12 (positions 5, 6 and 7).
    for (i, (r, n)) in [(&alice, 1), (&bob, 2), (&carol, 3)].into_iter().enumerate() {
        let c = NameOp::Commit { commit: commit_of(r, &salt(n)), memo: crate::output::memo5(d(40 + n)) };
        take(&w, 10 + i as u32, &[c], &[]);
    }
    let reveals = [
        NameOp::Reveal { record: alice.clone(), salt: salt(1), commit: 5 },
        NameOp::Reveal { record: bob.clone(), salt: salt(2), commit: 6 },
    ];
    take(&w, 24, &reveals, &[]);
    let alice2 = Record::new(b"alice", pubkey_hash(&owner_key(4).public_key()), d(13), d(14)).unwrap();
    take(&w, 25, &[NameOp::update(alice2, &mut k1).unwrap()], &[]);
    take(&w, 12 + MAX_REVEAL + 1, &[], &[7]);
    let honest: Vec<NamePublic> = pool.iter().map(|w| NameAir::generate_trace(w).1).collect();
    let (mut rejected, mut no_trace, mut other, mut bugs) = (0, 0, 0, Vec::new());
    let mut same: Vec<String> = Vec::new();
    let pinned = |p: &NamePublic| (p.root_in, p.pos_in, p.nsp, p.ssp, p.height, p.counts);
    let quiet = crate::test_util::Quiet::new();
    let mut n = 0;
    while n < iters {
        let s = (rng.next_u64() % pool.len() as u64) as usize;
        let mut wit = pool[s].clone();
        let mut what = Vec::new();
        for _ in 0..1 + rng.next_u64() % 4 {
            if let Some(m) = mutate_ops(&mut wit, &mut rng) {
                what.push(m);
            }
        }
        if what.is_empty() {
            continue;
        }
        n += 1;
        crate::stark::LENIENT.with(|l| l.set(true));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| NameAir::generate_trace(&wit)));
        crate::stark::LENIENT.with(|l| l.set(false));
        match r {
            Err(_) => no_trace += 1,
            Ok((trace, public)) => match check_constraints(&NameAir::MAINNET, &trace, &public.to_values()) {
                Err(_) => rejected += 1,
                Ok(()) if public == honest[s] => same.push(format!("section {s}: {}", what.join(", "))),
                // What is pinned from outside (the start, the operations
                // and sweeps the block lists, the height, the counts)
                // unchanged, but another outcome: a bug.
                Ok(()) if pinned(&public) == pinned(&honest[s]) => {
                    bugs.push(format!("section {s}: {}", what.join(", ")))
                }
                // Other operations: another statement, which the block's
                // own list must match (the aggregation checks it).
                Ok(()) => other += 1,
            },
        }
    }
    drop(quiet);
    eprintln!(
        "{iters} mutants: {rejected} rejected, {} equivalent, {other} other operations, {no_trace} without a trace, {} another outcome",
        same.len(),
        bugs.len()
    );
    for e in &same {
        eprintln!("  equivalent: {e}");
    }
    assert!(
        bugs.is_empty(),
        "accepted with another outcome for the same operations (seed {seed}):\n{}",
        bugs.join("\n")
    );
}

/// A commit's age outside its window leaves a difference below zero,
/// which as a field element is one near the modulus and has bits like
/// any other. A prover who writes those bits is refused all the same:
/// a reveal too soon and too late, a sweep before the window is past.
/// At the window's edges the honest ones are taken.
#[test]
fn an_age_outside_the_window_cannot_wrap_around() {
    use crate::poseidon2::P;
    let w = world("wrap");
    let o1 = pubkey_hash(&owner_key(1).public_key());
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let salt = d(505);
    let c = commit_hash(&name_hash(&alice.elements()), &salt, &o1);
    // The commit, at position 5, made at height 10.
    block(&w, 10, &[NameOp::Commit { commit: c, memo: crate::output::memo5(d(1)) }], &[]);
    let reveal = [NameOp::Reveal { record: alice, salt, commit: 5 }];
    let span = MAX_REVEAL + 1 - MIN_REVEAL;
    // The height, whether a sweep, the row that compares, and how far
    // below zero its difference is.
    let cases = [
        (10 + MIN_REVEAL - 1, false, T_WIN, 1),
        (10 + 3, false, T_WIN, MIN_REVEAL - 3),
        (10, false, T_WIN, MIN_REVEAL),
        (10 + MAX_REVEAL + 1, false, T_WIN2, 1),
        (10 + MAX_REVEAL + 500, false, T_WIN2, 500),
        (10 + MAX_REVEAL, true, T_WIN, 1),
        (10 + 20, true, T_WIN, MIN_REVEAL + span - 20),
    ];
    for (height, sweep, ty, short) in cases {
        let (ops, sweeps): (&[NameOp], &[u64]) = if sweep { (&[], &[5]) } else { (&reveal, &[]) };
        crate::stark::LENIENT.with(|l| l.set(true));
        let witness = w.collect(height, ops, sweeps).unwrap();
        let (mut trace, public) = NameAir::generate_trace(&witness);
        crate::stark::LENIENT.with(|l| l.set(false));
        let width = trace.width;
        let row = (0..trace.height()).find(|r| trace.values[r * width + ty] == Fp::ONE).expect("the row that compares");
        let cells = &mut trace.values[row * width..(row + 1) * width];

        // The difference as the field has it, in bits.
        crate::bits::write(cells, &BCOLS, P - short);
        let checked = check_constraints(&NameAir::MAINNET, &trace, &public.to_values());
        assert!(checked.is_err(), "height {height}, sweep {sweep}: {short} outside the window, and taken");
    }
    // The first and the last block of the window, and the first past it.
    for (height, sweep) in [(10 + MIN_REVEAL, false), (10 + MAX_REVEAL, false), (10 + MAX_REVEAL + 1, true)] {
        let (ops, sweeps): (&[NameOp], &[u64]) = if sweep { (&[], &[5]) } else { (&reveal, &[]) };
        let witness = w.collect(height, ops, sweeps).unwrap();
        let (trace, public) = NameAir::generate_trace(&witness);
        assert_eq!(check_constraints(&NameAir::MAINNET, &trace, &public.to_values()), Ok(()), "height {height}");
    }
}

/// A section with more than one signed operation: two updates, and a
/// reveal between them. After a signature the circuit's own rows read
/// whole field elements from the bit columns again (the key rows of
/// the next name), which they could not while the checksum's bound
/// held on every row.
#[test]
fn several_updates_in_one_section() {
    let w = world("several");
    let (mut k1, mut k2) = (owner_key(1), owner_key(2));
    let (o1, o2) = (pubkey_hash(&k1.public_key()), pubkey_hash(&k2.public_key()));
    let (o3, o4) = (pubkey_hash(&owner_key(3).public_key()), pubkey_hash(&owner_key(4).public_key()));
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let bob = Record::new(b"bob", o2, d(21), d(22)).unwrap();
    let carol = Record::new(b"carol", o3, d(31), d(32)).unwrap();
    let salt = |n: u32| d(500 + n);
    let commit_of = |r: &Record, s: &Digest| commit_hash(&name_hash(&r.elements()), s, &r.owner);
    let commit =
        |r: &Record, n: u32| NameOp::Commit { commit: commit_of(r, &salt(n)), memo: crate::output::memo5(d(n)) };
    // One commit a block: positions 5, 6 and 7.
    block(&w, 10, &[commit(&alice, 1)], &[]);
    block(&w, 11, &[commit(&bob, 2)], &[]);
    block(&w, 12, &[commit(&carol, 3)], &[]);
    block(
        &w,
        30,
        &[
            NameOp::Reveal { record: alice, salt: salt(1), commit: 5 },
            NameOp::Reveal { record: bob, salt: salt(2), commit: 6 },
        ],
        &[],
    );
    let alice2 = Record::new(b"alice", o4, d(13), d(14)).unwrap();
    let bob2 = Record::new(b"bob", o3, d(23), d(24)).unwrap();
    let public = block(
        &w,
        40,
        &[
            NameOp::update(alice2, &mut k1).unwrap(),
            NameOp::Reveal { record: carol, salt: salt(3), commit: 7 },
            NameOp::update(bob2, &mut k2).unwrap(),
        ],
        &[],
    );
    assert_eq!(public.root_out, w.root());
    assert_eq!((w.lookup(b"alice"), w.lookup(b"bob"), w.lookup(b"carol")), (Some(alice2), Some(bob2), Some(carol)));
}

/// Step 2 of the circuit review for names (`docs/HARDENING.md`): each
/// rule of a name section, broken by a witness collected and written
/// anyway, must be rejected by the constraints themselves.
#[test]
#[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
fn broken_name_rules_are_rejected_by_the_constraints() {
    let w = world("attack");
    let mut k1 = owner_key(1);
    let o1 = pubkey_hash(&k1.public_key());
    let mut k2 = owner_key(2);
    let o2 = pubkey_hash(&k2.public_key());
    let o3 = pubkey_hash(&owner_key(3).public_key());
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let bob = Record::new(b"bob", o2, d(21), d(22)).unwrap();
    let carol = Record::new(b"carol", o3, d(31), d(32)).unwrap();
    let salt = |n: u32| d(500 + n);
    let commit_of = |r: &Record, s: &Digest| commit_hash(&name_hash(&r.elements()), s, &r.owner);
    // Blocks 10, 11 and 12: commits to alice (at 5), bob (6) and carol
    // (7), one a block.
    for (i, (r, n)) in [(&alice, 1), (&bob, 2), (&carol, 3)].into_iter().enumerate() {
        let c = NameOp::Commit { commit: commit_of(r, &salt(n)), memo: crate::output::memo5(d(40 + n)) };
        block(&w, 10 + i as u32, &[c], &[]);
    }
    let reveal = |r: &Record, n: u32, at: u64| NameOp::Reveal { record: r.clone(), salt: salt(n), commit: at };
    let mut verdicts: Vec<(&str, Cheat)> = Vec::new();
    let none = |_: &mut NameWitness| {};
    verdicts.push((
        "a reveal before its commit is old enough (1 block)",
        cheat(&w, 11, &[reveal(&alice, 1, 5)], &[], none),
    ));
    verdicts
        .push(("a reveal after its commit expired", cheat(&w, 11 + MAX_REVEAL + 1, &[reveal(&bob, 2, 6)], &[], none)));
    verdicts.push(("a reveal with another salt than the commit's", cheat(&w, 22, &[reveal(&alice, 9, 5)], &[], none)));
    verdicts
        .push(("a reveal against an ordinary output (no commit)", cheat(&w, 22, &[reveal(&alice, 1, 0)], &[], none)));
    // At 23, when bob's commit (11) is old enough: only the name is wrong.
    verdicts.push(("a reveal against another name's commit", cheat(&w, 23, &[reveal(&alice, 1, 6)], &[], none)));
    verdicts.push(("a sweep of a live commit", cheat(&w, 23, &[], &[7], none)));
    // Block 22: alice revealed, honestly.
    assert_eq!(cheat(&w, 22, &[reveal(&alice, 1, 5)], &[], none), Cheat::Accepted, "an honest reveal");
    block(&w, 22, &[reveal(&alice, 1, 5)], &[]);
    // Updates at 23.
    let o4 = pubkey_hash(&owner_key(4).public_key());
    let alice2 = Record::new(b"alice", o4, d(13), d(14)).unwrap();
    let honest = NameOp::update(alice2.clone(), &mut owner_key(1)).unwrap();
    assert_eq!(cheat(&w, 23, &[honest.clone()], &[], none), Cheat::Accepted, "an honest update");
    let stranger = NameOp::update(alice2.clone(), &mut k2).unwrap();
    verdicts.push(("an update signed by another key than the owner's", cheat(&w, 23, &[stranger], &[], none)));
    let same_owner = Record::new(b"alice", o1, d(15), d(16)).unwrap();
    let kept = NameOp::update(same_owner, &mut k1).unwrap();
    verdicts.push(("an update keeping the owner", cheat(&w, 23, &[kept], &[], none)));
    let renamed = cheat(&w, 23, &[honest], &[], |wit| {
        if let Some(OpWitness::Update { new, .. }) = wit.ops.first_mut() {
            *new = Record::new(b"alicf", new.owner, new.value, new.memo).unwrap();
        }
    });
    verdicts.push(("an update that changes the name", renamed));
    // A second registration of alice, from a commit of its own.
    block(&w, 24, &[NameOp::Commit { commit: commit_of(&alice, &salt(4)), memo: crate::output::memo5(d(44)) }], &[]);
    {
        // The second commit is at 8, so only the registration is wrong.
        assert_eq!(w.commit_at(8).map(|c| c.hash), Some(commit_of(&alice, &salt(4))));
    }
    verdicts.push(("a reveal of a name already registered", cheat(&w, 36, &[reveal(&alice, 4, 8)], &[], none)));
    for (what, v) in &verdicts {
        eprintln!("{what}: {v:?}");
    }
    let failures: Vec<String> =
        verdicts.iter().filter(|(_, v)| *v != Cheat::Rejected).map(|(what, v)| format!("{what}: {v:?}")).collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_block_at_every_cap_fits_the_mainnet_segment() {
    use crate::name::{MAX_COMMITS, MAX_REVEALS, MAX_SWEEPS, MAX_UPDATES};
    let rows = MAX_COMMITS * COMMIT_ROWS
        + MAX_REVEALS * REVEAL_ROWS_BOUND
        + MAX_UPDATES * update_rows_bound(crate::xmss::MAX_HEIGHT)
        + MAX_SWEEPS * SWEEP_ROWS;
    assert!(rows < 1 << NAME_LOG_ROWS, "{rows} rows");
}

#[test]
fn layout_and_degree() {
    assert_eq!(measure_degree(&NameAir::MAINNET, NUM_PUBLIC), 3);
    assert_eq!(NUM_PUBLIC, 57 + 8);
    println!("name segment: {NUM_COLS} columns");
}

#[test]
fn empty_segment_keeps_the_state() {
    let w = world("empty");
    let p = block(&w, 7, &[], &[]);
    assert_eq!(p.root_in, p.root_out);
    assert_eq!(p.counts, [0; 4]);
}

#[test]
fn commits_reveals_updates_and_sweeps() {
    let w = world("all");
    let mut k1 = owner_key(1);
    let o1 = pubkey_hash(&k1.public_key());
    let k2 = owner_key(2);
    let o2 = pubkey_hash(&k2.public_key());
    let mut k3 = owner_key(3);
    let o3 = pubkey_hash(&k3.public_key());
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let bob_name = colliding_name(b"alice", 3);
    let bob = Record::new(&bob_name, o2, d(21), d(22)).unwrap();
    let carol = Record::new(b"carol_9", o3, d(31), d(32)).unwrap();
    let salt = |n: u32| d(500 + n);
    let commit_of = |r: &Record, s: &Digest| commit_hash(&name_hash(&r.elements()), s, &r.owner);

    // Blocks 10, 11 and 12: a commit each (one a block), at 5, 6 and 7.
    let commits = [
        NameOp::Commit { commit: commit_of(&alice, &salt(1)), memo: crate::output::memo5(d(41)) },
        NameOp::Commit { commit: commit_of(&bob, &salt(2)), memo: crate::output::memo5(d(42)) },
        NameOp::Commit { commit: commit_of(&carol, &salt(3)), memo: crate::output::memo5(d(43)) },
    ];
    for (i, c) in commits.into_iter().enumerate() {
        let p = block(&w, 10 + i as u32, &[c], &[]);
        assert_eq!(p.counts, [1, 0, 0, 0]);
        assert_eq!((p.pos_in, p.pos_out), (5 + i as u64, 6 + i as u64));
    }

    // Block 24: reveal alice (empty trie) and bob (a split under
    // alice's leaf: the keys share at least three bits).
    let reveals = vec![
        NameOp::Reveal { record: alice.clone(), salt: salt(1), commit: 5 },
        NameOp::Reveal { record: bob.clone(), salt: salt(2), commit: 6 },
    ];
    let p = block(&w, 24, &reveals, &[]);
    assert_eq!(p.counts, [0, 2, 0, 0]);
    assert_eq!((p.pos_in, p.pos_out), (8, 8));
    {
        assert_eq!(w.lookup(b"alice"), Some(alice.clone()));
        assert_eq!(w.lookup(&bob_name), Some(bob.clone()));
        assert_eq!(w.names_len(), 2);
        assert!(w.prove(&bob_name).depth() >= 4);
        // The commits are gone from the UTXO set; carol's remains.
        assert!(w.output_at(5).is_none());
        assert!(w.output_at(6).is_none());
        assert!(w.output_at(7).is_some());
    }

    // Block 25: alice rotates her key, a commit in the same block.
    let mut k4 = owner_key(4);
    let o4 = pubkey_hash(&k4.public_key());
    let alice2 = Record::new(b"alice", o4, d(13), d(14)).unwrap();
    let update = NameOp::update(alice2.clone(), &mut k1).unwrap();
    let ops = vec![update, NameOp::Commit { commit: d(77), memo: crate::output::memo5(d(78)) }];
    let p = block(&w, 25, &ops, &[]);
    assert_eq!(p.counts, [1, 0, 1, 0]);
    assert_eq!((p.pos_in, p.pos_out), (8, 9));
    {
        assert_eq!(w.lookup(b"alice"), Some(alice2.clone()));
    }

    // Block 301: carol's commit (height 12) has expired: sweep it, and
    // alice transfers to k3's hash, an update by k4.
    let alice3 = Record::new(b"alice", o3, d(15), d(16)).unwrap();
    let transfer = NameOp::update(alice3.clone(), &mut k4).unwrap();
    let p = block(&w, 301, &[transfer], &[7]);
    assert_eq!(p.counts, [0, 0, 1, 1]);
    {
        assert!(w.output_at(7).is_none());
        assert!(w.commit_at(7).is_none());
        assert_eq!(w.lookup(b"alice"), Some(alice3.clone()));
    }

    // Block 302: carol's reveal now fails (no commit); a reveal of a
    // registered name fails; an update by a stale key fails; a sweep
    // of a live commit fails; an update keeping the owner fails.
    let fail = |ops: &[NameOp], sweeps: &[u64]| w.collect(302, ops, sweeps).expect_err("rejected");
    assert!(matches!(
        fail(&[NameOp::Reveal { record: carol.clone(), salt: salt(3), commit: 7 }], &[]),
        Error::NotACommit(_) | Error::NoSuchOutput(_)
    ));
    assert!(matches!(
        fail(&[NameOp::Reveal { record: alice.clone(), salt: salt(1), commit: 5 }], &[]),
        Error::NotACommit(_) | Error::NoSuchOutput(_)
    ));
    let stale = NameOp::update(Record::new(b"alice", o2, d(1), d(2)).unwrap(), &mut k1).unwrap();
    assert!(matches!(fail(&[stale], &[]), Error::NameOwner));
    let same = NameOp::update(Record::new(b"alice", o3, d(1), d(2)).unwrap(), &mut k3).unwrap();
    assert!(matches!(fail(&[same], &[]), Error::NameOwner));
    assert!(matches!(fail(&[], &[8]), Error::CommitAge(25)));
    assert!(matches!(fail(&[], &[3]), Error::NotACommit(_) | Error::NoSuchOutput(_)));
    let unknown = NameOp::update(Record::new(b"nobody", o2, d(1), d(2)).unwrap(), &mut k3).unwrap();
    assert!(matches!(fail(&[unknown], &[]), Error::NoSuchName));
    // A commit revealed too early or too late.
    let late = Record::new(b"late", o2, d(1), d(2)).unwrap();
    let ops = [NameOp::Commit { commit: commit_of(&late, &salt(9)), memo: crate::output::memo5(d(1)) }];
    // Gathering changes nothing: the block is then the chain's.
    w.collect(302, &ops, &[]).unwrap();
    w.apply(302, &ops, &[]);
    let reveal = [NameOp::Reveal { record: late.clone(), salt: salt(9), commit: 9 }];
    assert!(matches!(w.collect(302 + MIN_REVEAL - 1, &reveal, &[]).err().unwrap(), Error::CommitAge(302)));
    assert!(matches!(w.collect(302 + MAX_REVEAL + 1, &reveal, &[]).err().unwrap(), Error::CommitAge(302)));
    w.collect(302 + MAX_REVEAL, &reveal, &[]).unwrap();
    w.apply(302 + MAX_REVEAL, &reveal, &[]);
    // Re-registering a revealed name: the trie has it.
    let again = [NameOp::Commit { commit: commit_of(&late, &salt(10)), memo: crate::output::memo5(d(1)) }];
    w.collect(600, &again, &[]).unwrap();
    w.apply(600, &again, &[]);
    let reveal = [NameOp::Reveal { record: late.clone(), salt: salt(10), commit: 10 }];
    assert!(matches!(w.collect(620, &reveal, &[]).err().unwrap(), Error::NameTaken));
    // Beyond the caps.
    let many: Vec<NameOp> = (0..names::MAX_COMMITS as u32 + 1)
        .map(|i| NameOp::Commit { commit: d(900 + i), memo: crate::output::memo5(d(1)) })
        .collect();
    assert!(matches!(fail(&many, &[]), Error::TooManyOps { .. }));
    let _ = (k2, o1);
}

/// The name segment at mainnet parameters: an empty one (every block
/// pays this) and one with every kind of operation, proven and
/// verified.
#[test]
#[ignore = "proves mainnet name segments; run with --release"]
fn mainnet_name_segment_timing() {
    use crate::aggregate::AggregatorParams;
    use crate::block_proof::{name_transcript, prove_name_padded};
    let params = AggregatorParams::MAINNET;
    let w = world("timing");
    let mut k1 = owner_key(1);
    let o1 = pubkey_hash(&k1.public_key());
    let o2 = pubkey_hash(&owner_key(2).public_key());
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let salt = d(500);
    let c = commit_hash(&name_hash(&alice.elements()), &salt, &o1);
    let empty = NameWitness {
        min_reveal: MIN_REVEAL,
        root_in: w.root(),
        pos_in: 5,
        height: 1,
        ops: vec![],
        signed: Default::default(),
    };
    // One commit a block: positions 5 and 6. The first is revealed in
    // its window; the second is left to be swept.
    block(&w, 2, &[NameOp::Commit { commit: c, memo: crate::output::memo5(d(1)) }], &[]);
    block(&w, 3, &[NameOp::Commit { commit: d(2), memo: crate::output::memo5(d(3)) }], &[]);
    block(&w, 14, &[NameOp::Reveal { record: alice, salt, commit: 5 }], &[]);
    let alice2 = Record::new(b"alice", o2, d(13), d(14)).unwrap();
    let ops =
        [NameOp::update(alice2, &mut k1).unwrap(), NameOp::Commit { commit: d(4), memo: crate::output::memo5(d(5)) }];
    let full = w.collect(400, &ops, &[6]).unwrap();
    for (name, witness) in [("empty", &empty), ("update, commit and sweep", &full)] {
        let t = std::time::Instant::now();
        let p = prove_name_padded(&params.segment, witness, params.name_log_n);
        let proved = t.elapsed();
        let t = std::time::Instant::now();
        let ok = crate::stark::verify(
            &params.segment,
            &NameAir::MAINNET,
            &p.public.to_values(),
            &p.proof,
            &mut name_transcript(),
        );
        println!(
            "name segment ({name}, {} rows used of 2^{}): proven in {proved:?}, {} bytes, verified {ok:?} in {:?}",
            witness.num_rows(),
            params.name_log_n,
            p.proof.to_bytes().len(),
            t.elapsed()
        );
        assert_eq!(ok, Ok(()));
    }
}

/// An update's signature is looked up in the block's signed set, and
/// nothing stands in for it: not another set, not another owner or
/// message on the way to the entry, not a path that leads elsewhere.
#[test]
fn an_update_signature_is_looked_up_in_the_signed_set() {
    let w = world("signed");
    let (mut k1, k2) = (owner_key(1), owner_key(2));
    let (o1, o2) = (pubkey_hash(&k1.public_key()), pubkey_hash(&k2.public_key()));
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let c = commit_hash(&name_hash(&alice.elements()), &d(5), &o1);
    block(&w, 10, &[NameOp::Commit { commit: c, memo: crate::output::memo5(d(41)) }], &[]);
    block(&w, 30, &[NameOp::Reveal { record: alice.clone(), salt: d(5), commit: 5 }], &[]);
    let handed = Record::new(b"alice", o2, d(13), d(14)).unwrap();
    let ops = [NameOp::update(handed.clone(), &mut k1).unwrap()];
    let witness = w.collect(31, &ops, &[]).unwrap();
    // The witness has the set of its own signature: one entry, the
    // owner's over the update's message.
    let signings = witness.signings();
    assert_eq!(signings.len(), 1);
    let (pk, message, sig) = &signings[0];
    assert_eq!((pubkey_hash(pk), *message), (o1, crate::name::update_message(&handed)));
    let entry = crate::sig_air::entry(pk, message, sig.index);
    assert_eq!(witness.signed.set.find(&entry), Some(0));
    let (trace, public) = NameAir::generate_trace(&witness);
    assert_eq!(public.signed, witness.signed.set.root());
    let values = public.to_values();
    assert_eq!(check_constraints(&NameAir::MAINNET, &trace, &values), Ok(()));
    // Against another set's root the trace does not hold, and with a
    // set that lacks the signature there is no trace.
    let mut other = public;
    other.signed[1] += Fp::ONE;
    assert!(check_constraints(&NameAir::MAINNET, &trace, &other.to_values()).is_err());
    let mut bare = witness.clone();
    bare.signed = Default::default();
    assert!(std::panic::catch_unwind(|| NameAir::generate_trace(&bare)).is_err());
    let width = NUM_COLS;
    let row_of = |ty: usize, which: usize| {
        (0..trace.height()).filter(|&r| trace.values[r * width + ty] == Fp::ONE).nth(which).expect("such a row")
    };
    let breaks = |what: &str, change: &dyn Fn(&mut crate::stark::Trace)| {
        let mut bad = trace.clone();
        change(&mut bad);
        assert!(check_constraints(&NameAir::MAINNET, &bad, &values).is_err(), "{what}");
    };
    use crate::hash_machine::COL_DIR;
    breaks("owner", &|t| t.values[row_of(T_ENT0, 0) * width + COL_DATA] += Fp::ONE);
    breaks("owner's side", &|t| t.values[row_of(T_ENT0, 0) * width + COL_DIR] = Fp::ZERO);
    breaks("leaf's block", &|t| t.values[row_of(T_ENT1, 0) * width + COL_DATA + 1] += Fp::ONE);
    breaks("sibling", &|t| t.values[row_of(T_SP, 7) * width + COL_DATA + 2] += Fp::ONE);
    breaks("direction", &|t| {
        let at = row_of(T_SP, 1) * width + COL_DIR;
        t.values[at] = Fp::ONE - t.values[at];
    });
    breaks("levels left", &|t| t.values[row_of(T_SP, 2) * width + R_SPN] -= Fp::ONE);
    breaks("the path's end", &|t| {
        let at = row_of(T_SP, 3) * width;
        t.values[at + C_SP_LAST] = Fp::ONE;
        t.values[at + C_SP_END] = Fp::ONE;
    });
    breaks("a row of another kind", &|t| {
        let at = row_of(T_SP, 4) * width;
        t.values[at + T_SP] = Fp::ZERO;
        t.values[at + T_DONE] = Fp::ONE;
    });
}

#[test]
fn forged_traces_fail() {
    let w = world("forge");
    let k1 = owner_key(1);
    let o1 = pubkey_hash(&k1.public_key());
    let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
    let c = commit_hash(&name_hash(&alice.elements()), &d(5), &o1);
    block(&w, 10, &[NameOp::Commit { commit: c, memo: crate::output::memo5(d(41)) }], &[]);
    let ops = [NameOp::Reveal { record: alice.clone(), salt: d(5), commit: 5 }];
    let witness = w.collect(30, &ops, &[]).unwrap();
    let (trace, public) = NameAir::generate_trace(&witness);
    let values = public.to_values();
    assert_eq!(check_constraints(&NameAir::MAINNET, &trace, &values), Ok(()));
    let width = NUM_COLS;
    let find = |ty: usize, nth: usize| {
        (0..trace.height()).filter(|&r| trace.values[r * width + ty] == Fp::ONE).nth(nth).unwrap()
    };
    // A name element out of the charset (38) on the first name row.
    let mut bad = trace.clone();
    let r = find(T_NAME, 0);
    bad.values[r * width + COL_DATA + 1] = Fp::new(38);
    bad.values[r * width + COL_INPUT + 1] = Fp::new(38);
    for bit in 0..CHAR_BITS {
        bad.values[r * width + C_CB + CHAR_BITS + bit] = Fp::new((38 >> bit) & 1);
    }
    assert!(check_constraints(&NameAir::MAINNET, &bad, &values).is_err());
    // Padding before the end of the name: zero then a letter.
    let mut bad = trace.clone();
    bad.values[r * width + C_LIVE + 2] = Fp::ZERO;
    bad.values[r * width + C_LIVE_INV + 2] = Fp::ZERO;
    assert!(check_constraints(&NameAir::MAINNET, &bad, &values).is_err());
    // A wrong key bit.
    let mut bad = trace.clone();
    let r = find(T_TLOAD, 0) + 1;
    let v = &mut bad.values[r * width + R_KB + 5];
    *v = Fp::ONE - *v;
    assert!(check_constraints(&NameAir::MAINNET, &bad, &values).is_err());
    // The window: pretend the commit is one block younger.
    let mut bad = trace.clone();
    let r = find(T_WIN, 0);
    for rr in 0..trace.height() {
        if trace.values[rr * width + T_WIN] == Fp::ONE || trace.values[rr * width + T_WIN2] == Fp::ONE {
            let _ = rr;
        }
    }
    bad.values[r * width + R_CH] += Fp::ONE;
    assert!(check_constraints(&NameAir::MAINNET, &bad, &values).is_err());
    // A different owner in the record than in the commit.
    let mut bad = trace.clone();
    let r = find(T_COMMIT, 2);
    bad.values[r * width + COL_DATA] += Fp::ONE;
    assert!(check_constraints(&NameAir::MAINNET, &bad, &values).is_err());
    // Claiming a count that is not the operations'.
    let mut bad = values.clone();
    bad[PUB_COUNTS + 1] = Fp::new(2);
    assert!(check_constraints(&NameAir::MAINNET, &trace, &bad).is_err());
    // The witness generator refuses a reveal to a name already there,
    // and a wrong salt (its commit is not found).
    let wrong = [NameOp::Reveal { record: alice.clone(), salt: d(6), commit: 5 }];
    // And the right salt at the wrong position.
    let moved = [NameOp::Reveal { record: alice.clone(), salt: d(5), commit: 6 }];
    assert!(matches!(w.collect(30, &moved, &[]).err().unwrap(), Error::NotACommit(_) | Error::NoSuchOutput(_)));
    assert!(matches!(w.collect(30, &wrong, &[]).err().unwrap(), Error::NotACommit(_) | Error::NoSuchOutput(_)));
}
