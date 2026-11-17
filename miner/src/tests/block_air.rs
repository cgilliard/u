//! The transaction circuit's tests: the original's, on the store.
//!
//! The original gathered a segment's witnesses by changing its database
//! an item at a time; these go through [`TestSet`], which keeps a state
//! of the store and gathers them as a node does
//! ([`SegmentWitness::collect`]), then applies the same block to the
//! state natively. So wherever a test compares the root a circuit ends
//! at with the set's, it compares the circuit with the store.

use super::*;
use crate::challenger::Challenger;
use crate::output::{Key, Output};
use crate::stark::{StarkConfig, check_constraints, measure_degree, prove, verify};
use crate::store::outputs::Record;
use crate::store::state::{BlockEdit, State};
use crate::store::testing::MemBackend;
use crate::transaction::UnsignedTransaction;

/// A set of outputs in a store, with the original set's ways of adding
/// to it and of gathering witnesses from it.
pub(crate) struct TestSet {
    pub(crate) state: State<MemBackend>,
    blocks: std::cell::Cell<u32>,
}

impl TestSet {
    pub(crate) fn new() -> TestSet {
        TestSet { state: State::open(MemBackend::new(), 0).unwrap(), blocks: std::cell::Cell::new(0) }
    }

    /// A block of the store: these spends and these outputs.
    fn block(&self, spends: &[u64], outputs: &[Record]) {
        let height = self.blocks.get() + 1;
        self.blocks.set(height);
        let (names, commits, commits_spent, state_root) = (&[][..], &[][..], &[][..], None);
        let block = [Fp::new(height); DIGEST];
        self.state
            .apply(&BlockEdit { height, block, spends, outputs, names, commits, commits_spent, state_root })
            .unwrap();
    }

    /// Adds an output made at `height`; returns its position.
    pub(crate) fn add_output(&self, o: &BlockOutput, height: u32) -> Result<u64, Error> {
        let position = self.next_position();
        self.block(&[], &[Record { commitment: o.commitment, memo: o.memo, amount: o.amount, height }]);
        Ok(position)
    }

    pub(crate) fn next_position(&self) -> u64 {
        self.state.snapshot().unwrap().outputs().next
    }

    pub(crate) fn root(&self) -> Digest {
        self.state.root()
    }

    /// Whether `position` holds an unspent output of this commitment.
    fn holds(&self, position: u64, commitment: &Commitment) -> bool {
        matches!(self.state.snapshot().unwrap().output(position).unwrap(), Some((r, true)) if r.commitment == *commitment)
    }

    /// Applies what `txs` spend and make at `height`, natively: what
    /// gathering their witnesses did to the original's set.
    pub(crate) fn apply(&self, txs: &[Transaction], height: u32) {
        let mut spends: Vec<u64> = txs
            .iter()
            .flat_map(|t| t.inputs.iter().map(|i| i.position).chain(t.policy_inputs.iter().map(|p| p.position)))
            .collect();
        spends.sort_unstable();
        let outputs: Vec<Record> = txs
            .iter()
            .flat_map(|t| t.outputs.iter())
            .map(|o| Record { commitment: o.commitment, memo: o.memo, amount: o.amount, height })
            .collect();
        self.block(&spends, &outputs);
    }

    fn gathered(
        &self,
        txs: &[Transaction],
        height: u32,
        segments: Result<Vec<SegmentWitness>, Error>,
    ) -> Result<Vec<SegmentWitness>, Error> {
        // A lenient gathering goes on with what is not there to spend:
        // the store does not.
        if segments.is_ok() && !crate::stark::lenient() {
            self.apply(txs, height);
        }
        segments
    }

    fn collect(&self, txs: &[Transaction], txs_per_segment: usize, height: u32) -> Result<Vec<SegmentWitness>, Error> {
        let segments = SegmentWitness::collect(&self.state.snapshot().unwrap(), txs, txs_per_segment, height);
        self.gathered(txs, height, segments)
    }

    fn collect_parts(
        &self,
        txs: &[Transaction],
        parts: Vec<Vec<Part>>,
        height: u32,
    ) -> Result<Vec<SegmentWitness>, Error> {
        let segments = SegmentWitness::collect_parts(&self.state.snapshot().unwrap(), txs, parts, height);
        self.gathered(txs, height, segments)
    }

    pub(crate) fn collect_by_rows(
        &self,
        txs: &[Transaction],
        max_rows: usize,
        height: u32,
    ) -> Result<Vec<SegmentWitness>, Error> {
        let segments = SegmentWitness::collect_by_rows(&self.state.snapshot().unwrap(), txs, max_rows, height);
        self.gathered(txs, height, segments)
    }
}

fn key(tag: u8) -> Key {
    let mut s = [0u8; 32];
    s[0] = tag;
    Key::generate(&s)
}

/// A UTXO set with three outputs, then three transactions spending them,
/// split into segments of `per_segment` transactions. Returns the
/// segments, the final root, the positions and the outputs.
fn scenario(name: &str, per_segment: usize) -> (Vec<SegmentWitness>, Digest, Vec<u64>, Vec<Output>) {
    scenario_with(name, |utxo, txs| utxo.collect(txs, per_segment, 1).unwrap())
}

fn scenario_with(
    _name: &str,
    split: impl FnOnce(&TestSet, &[Transaction]) -> Vec<SegmentWitness>,
) -> (Vec<SegmentWitness>, Digest, Vec<u64>, Vec<Output>) {
    let utxo = TestSet::new();
    let mut a = key(1);
    let mut bk = key(2);
    let c = key(3).public_key();
    let miner = key(4).public_key();
    utxo.add_output(&Output::new(&a.public_key(), 100).block_output(), 0).unwrap();
    utxo.add_output(&Output::new(&bk.public_key(), 50).block_output(), 0).unwrap();
    utxo.add_output(&Output::new(&a.public_key(), 30).block_output(), 0).unwrap();

    let mut tx1 = UnsignedTransaction::new(
        vec![(a.public_key(), 100), (bk.public_key(), 50)],
        vec![Output::new(&c, 120), Output::new(&a.public_key(), 25)],
    )
    .sign(|i, _, m| if i == 0 { a.sign(m) } else { bk.sign(m) })
    .unwrap();
    tx1.set_positions(&[0, 1]);
    let reward =
        UnsignedTransaction::new(vec![], vec![Output::new(&miner, 55)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
    let mut tx3 = UnsignedTransaction::new(vec![(a.public_key(), 30)], vec![Output::new(&bk.public_key(), 30)])
        .sign_with(&mut a)
        .unwrap();
    tx3.set_positions(&[2]);
    assert!(tx1.verify_signatures() && tx3.verify_signatures());
    let txs = [tx1, reward, tx3];
    let positions = vec![0, 1, 2];
    let outputs: Vec<Output> = txs.iter().flat_map(|t| t.outputs.clone()).collect();

    let segments = split(&utxo, &txs);
    let new_root = utxo.root();
    (segments, new_root, positions, outputs)
}

/// Policy spends: 2-of-3 multisig, an HTLC claim, an eltoo update with
/// rebindable signatures and a covenant settlement, each a whole
/// transaction in a segment, satisfy the constraints; a tampered state
/// number does not.
#[test]
fn policy_spends_satisfy_constraints() {
    let (txs, segments) = policy_segments();
    assert_eq!(segments.len(), 4);
    for (k, seg) in segments.iter().enumerate() {
        assert_eq!(seg.num_rows(), tx_rows(&txs[k]), "rows of transaction {k}");
        let (trace, public) = BlockAir::generate_trace(seg);
        assert_eq!(check_constraints(&BlockAir, &trace, &public.to_values()), Ok(()), "transaction {k}");
        // Tampering with the state number breaks the update's rows.
        if k == 2 {
            let mut bad = trace.clone();
            let width = bad.width;
            for r in 0..bad.height() {
                if bad.values[r * width + R_PSTATE] == Fp::new(4) {
                    bad.values[r * width + R_PSTATE] = Fp::new(5);
                }
            }
            assert!(check_constraints(&BlockAir, &bad, &public.to_values()).is_err());
        }
    }
    assert_eq!(txs[2].weight(), 2);
    assert_eq!(txs[3].weight(), 0);
}

/// What becomes of a witness that breaks a rule when the generator
/// writes its trace anyway, as a cheating prover's would.
#[derive(Debug, PartialEq)]
enum Cheat {
    /// The constraints reject the trace: the rule holds in the circuit.
    Rejected,
    /// The constraints accept it: a soundness bug.
    Accepted,
    /// The generator cannot write a trace for it at all.
    NoTrace(String),
}

/// Whether every signature segment of a block has a trace that holds:
/// every signature verifies, by the circuit's own account.
fn signatures_hold(signed: &crate::signed::Signed) -> bool {
    use crate::sig_air::SigAir;
    signed.segments.iter().all(|signings| {
        let made = std::panic::catch_unwind(|| {
            let trace = SigAir::generate_trace(signings, crate::sig_air::log_rows(signings));
            let said: Vec<Fp> = crate::signed::Signed::entries(signings).iter().flatten().copied().collect();
            check_constraints(&SigAir, &trace, &said).is_ok()
        });
        made.unwrap_or(false)
    })
}

fn cheat(w: &SegmentWitness) -> Cheat {
    crate::stark::LENIENT.with(|l| l.set(true));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| BlockAir::generate_trace(w)));
    crate::stark::LENIENT.with(|l| l.set(false));
    match r {
        Err(e) => Cheat::NoTrace(
            e.downcast_ref::<String>().cloned().or(e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default(),
        ),
        Ok((trace, public)) => match check_constraints(&BlockAir, &trace, &public.to_values()) {
            Err(_) => Cheat::Rejected,
            Ok(()) => Cheat::Accepted,
        },
    }
}

/// A segment spending one output of `policy` (created at height 0,
/// amount 1000, memo `m`) by the transaction `spend` builds from the
/// input, at `height`.
fn policy_spend(
    _name: &str,
    policy: &crate::policy::Policy,
    height: u32,
    spend: impl FnOnce(crate::policy::PolicyInput) -> Transaction,
) -> SegmentWitness {
    let utxo = TestSet::new();
    let mut memo = EMPTY;
    memo[0] = Fp::new(42);
    let o = Output::with_memo(&policy.root(), 1000, crate::output::memo5(memo));
    utxo.add_output(&o.block_output(), 0).unwrap();
    let tx = spend(policy.spend(0, 1000, 0));
    let mut segments = utxo.collect(std::slice::from_ref(&tx), 1, height).unwrap();
    segments.remove(0)
}

/// A lock that has not passed leaves a difference below zero, which as
/// a field element is one near the modulus: it has bits like any other.
/// A prover who writes those bits is refused all the same, for each of
/// the three conditions that compare; and at the very height a lock
/// passes, the honest spend is taken.
#[test]
fn a_lock_not_passed_cannot_wrap_around() {
    use crate::policy::{Cond, Leaf, Policy};
    use crate::poseidon2::P;
    let spend = |cond: Cond, height: u32, state: u32| {
        let policy = Policy::new(vec![Leaf::new(vec![cond])]);
        policy_spend("lock", &policy, height, |mut i| {
            i.state = state;
            UnsignedTransaction::new(vec![], vec![Output::new(&key(9).public_key(), 1000)])
                .with_policy_inputs(vec![i])
                .sign(|_, _, _| Err::<Sig, ()>(()))
                .unwrap()
        })
    };
    // The condition, the height and state number of the spend, the row
    // that compares, and how far short of the lock the spend falls.
    let cases = [
        (Cond::After(100), 50, 0, T_AFTER, 50u32),
        (Cond::After(100), 99, 0, T_AFTER, 1),
        (Cond::Older(144), 100, 0, T_OLDER, 44),
        (Cond::State(7), 10, 3, T_STATE, 5),
        (Cond::State(7), 10, 7, T_STATE, 1),
        // As far below as a lock allows.
        (Cond::After(crate::policy::MAX_LOCK), 1, 0, T_AFTER, crate::policy::MAX_LOCK - 1),
    ];
    for (cond, height, state, ty, short) in cases {
        let w = spend(cond.clone(), height, state);
        crate::stark::LENIENT.with(|l| l.set(true));
        let (mut trace, public) = BlockAir::generate_trace(&w);
        crate::stark::LENIENT.with(|l| l.set(false));
        let width = trace.width;
        let row = (0..trace.height()).find(|r| trace.values[r * width + ty] == Fp::ONE).expect("the row that compares");
        let cells = &mut trace.values[row * width..(row + 1) * width];
        // The difference as the field has it, in bits.
        crate::bits::write(cells, &BCOLS, P - short);
        let checked = check_constraints(&BlockAir, &trace, &public.to_values());
        assert!(checked.is_err(), "{cond:?} at height {height}, state {state}: {short} short, and taken");
    }
    // Passed, by nothing and by much: taken.
    for (cond, height, state) in [
        (Cond::After(100), 100, 0),
        (Cond::After(100), 50_000_000, 0),
        (Cond::Older(144), 144, 0),
        (Cond::State(7), 10, 8),
        (Cond::State(0), 10, 1 << 28),
    ] {
        let w = spend(cond.clone(), height, state);
        let (trace, public) = BlockAir::generate_trace(&w);
        assert_eq!(
            check_constraints(&BlockAir, &trace, &public.to_values()),
            Ok(()),
            "{cond:?} at {height}, state {state}"
        );
    }
}

/// Step 2 of the circuit review (`docs/HARDENING.md`): each rule the
/// witness generator enforces, broken by a witness the generator then
/// writes anyway (as a cheating prover's would), must be rejected by
/// the constraints themselves.
#[test]
#[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
fn broken_rules_are_rejected_by_the_constraints() {
    use crate::output::pubkey_hash;
    use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer, hash_lock};
    let mut verdicts: Vec<(&str, Cheat)> = Vec::new();
    // The plain spends' forgeries.
    let (segments, ..) = scenario("attack", 10);
    let w = &segments[0];
    let mut greedy = w.clone();
    greedy.txs[0].inputs[0].amount += 1;
    verdicts.push(("an input claiming more than its output holds", cheat(&greedy)));
    let mut inflated = w.clone();
    let o = &mut inflated.txs[0].outputs[0].output;
    o.commitment = crate::output::key_commitment(&o.key_hash, o.amount + 1_000_000);
    verdicts.push(("an output hiding more than it counts", cheat(&inflated)));
    let mut wrong_msg = w.clone();
    wrong_msg.txs[2].message[0] += Fp::ONE;
    verdicts.push(("a signature over another message", cheat(&wrong_msg)));
    let mut wrong_memo = w.clone();
    wrong_memo.txs[0].inputs[0].memo[1] += Fp::ONE;
    verdicts.push(("an input with another memo than its leaf's", cheat(&wrong_memo)));
    let mut swapped = w.clone();
    swapped.txs[0].outputs[0].output.memo[0] += Fp::ONE;
    verdicts.push(("an output memo changed after signing", cheat(&swapped)));

    // Policy spends.
    let k = |t: u8| key(t);
    let pkh = |t: u8| pubkey_hash(&k(t).public_key());
    let dest = k(9).public_key();
    let signed = |input: crate::policy::PolicyInput, sign: &dyn Fn(&Digest) -> CondWitness| {
        let mut input = input;
        let body = UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)])
            .with_policy_inputs(vec![input.clone()])
            .body_hash();
        let last = input.witness.len() - 1;
        input.witness[last] = sign(&body);
        UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)])
            .with_policy_inputs(vec![input])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap()
    };
    let sig = |t: u8, key_index: u8, body: &Digest| {
        let mut sk = k(t);
        Signer { key: key_index, pubkey: sk.public_key(), signature: sk.sign(body).unwrap() }
    };
    let multisig =
        Policy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: vec![pkh(1), pkh(2), pkh(3)] }])]);
    // Honest first: the helper's segment holds.
    let honest = policy_spend("honest-multisig", &multisig, 10, |i| {
        signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b), sig(3, 2, b)]))
    });
    assert_eq!(cheat(&honest), Cheat::Accepted, "an honest 2-of-3");
    let outsider = policy_spend("outsider", &multisig, 10, |i| {
        signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b), sig(7, 1, b)]))
    });
    verdicts.push(("a 2-of-3 with a signer whose key is not the policy's", cheat(&outsider)));
    let twice = policy_spend("twice", &multisig, 10, |i| {
        signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b), sig(1, 0, b)]))
    });
    verdicts.push(("a 2-of-3 with one signer counted twice", cheat(&twice)));
    let mut pre = EMPTY;
    pre[0] = Fp::new(77);
    let htlc = Policy::new(vec![Leaf::new(vec![
        Cond::Hash(hash_lock(&pre)),
        Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![pkh(2)] },
    ])]);
    let wrong_pre = policy_spend("preimage", &htlc, 10, |mut i| {
        let mut other = pre;
        other[0] += Fp::ONE;
        i.witness[0] = CondWitness::Preimage(other);
        signed(i, &|b| CondWitness::Signatures(vec![sig(2, 0, b)]))
    });
    verdicts.push(("an HTLC claimed with the wrong preimage", cheat(&wrong_pre)));
    let refund = Policy::new(vec![Leaf::new(vec![
        Cond::After(100),
        Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![pkh(1)] },
    ])]);
    let early = policy_spend("after", &refund, 50, |i| signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b)])));
    verdicts.push(("a refund before its height (After 100 at 50)", cheat(&early)));
    let relative = Policy::new(vec![Leaf::new(vec![
        Cond::Older(144),
        Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![pkh(1)] },
    ])]);
    let young = policy_spend("older", &relative, 100, |i| signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b)])));
    verdicts.push(("a spend before its delay (Older 144, 100 blocks old)", cheat(&young)));

    // Covenant: a settlement paying other outputs than the covenant's.
    let mut m1 = EMPTY;
    m1[0] = Fp::new(101);
    let to = |t: u8, amount: u64| Output::with_memo(&pkh(t), amount, crate::output::memo5(EMPTY));
    let settle_to = [Output::with_memo(&pkh(1), 600, crate::output::memo5(m1)), to(2, 400)];
    let covered: Vec<(Commitment, Digest)> = settle_to.iter().map(|o| (o.commitment, o.slot())).collect();
    let covenant = Policy::new(vec![Leaf::new(vec![Cond::Outputs(covered)])]);
    let pay = |outs: Vec<Output>| {
        move |mut i: crate::policy::PolicyInput| {
            i.covered = (0, outs.len() as u8);
            UnsignedTransaction::new(vec![], outs.clone())
                .with_policy_inputs(vec![i])
                .sign(|_, _, _| Err::<Sig, ()>(()))
                .unwrap()
        }
    };
    let honest_settle = policy_spend("covenant-ok", &covenant, 10, pay(settle_to.to_vec()));
    assert_eq!(cheat(&honest_settle), Cheat::Accepted, "an honest settlement");
    let other = [to(1, 400), to(2, 600)];
    let robbed = policy_spend("covenant", &covenant, 10, pay(other.to_vec()));
    verdicts.push(("a settlement paying other outputs than the covenant's", cheat(&robbed)));
    // Eltoo: an update to a state no newer than the current one.
    let channel = {
        let mut c = EMPTY;
        c[0] = Fp::new(5);
        c
    };
    let state = Policy::new(vec![Leaf::new(vec![
        Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: vec![pkh(1), pkh(2)] },
        Cond::State(3),
    ])]);
    let state_root = state.root();
    let update = |to: u32| {
        move |mut i: crate::policy::PolicyInput| {
            let new_state = Output::with_memo(&state_root, 1000, crate::output::memo5(EMPTY));
            i.state = to;
            i.covered = (0, 1);
            let msg = crate::policy::rebind_message(&channel, to, &[(new_state.commitment, new_state.slot())]);
            let signer = |t: u8, key_index: u8| {
                let mut sk = key(t);
                sk.set_next_index(u64::from(to));
                Signer { key: key_index, pubkey: sk.public_key(), signature: sk.sign(&msg).unwrap() }
            };
            i.witness[0] = CondWitness::Signatures(vec![signer(1, 0), signer(2, 1)]);
            UnsignedTransaction::new(vec![], vec![new_state])
                .with_policy_inputs(vec![i])
                .sign(|_, _, _| Err::<Sig, ()>(()))
                .unwrap()
        }
    };
    let newer = policy_spend("eltoo-ok", &state, 10, update(4));
    assert_eq!(cheat(&newer), Cheat::Accepted, "an honest update to state 4");
    let stale = policy_spend("eltoo", &state, 10, update(3));
    verdicts.push(("an eltoo update to a state no newer (3 over 3)", cheat(&stale)));

    // A segment resuming a transaction with one input fewer left than
    // the previous segment carried out, checked against the honest
    // public values: the carry is bound to the resume row.
    let plan = vec![
        vec![Part { tx: 0, start: 0, end: 1 }],
        vec![Part { tx: 0, start: 1, end: 3 }],
        vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
    ];
    let (span, ..) = scenario_with("attack-span", |utxo, txs| utxo.collect_parts(txs, plan, 1).unwrap());
    let (_, honest_public) = BlockAir::generate_trace(&span[1]);
    let mut short = span[1].clone();
    short.txs[0].inputs.clear();
    short.txs[0].in_left -= 1;
    crate::stark::LENIENT.with(|l| l.set(true));
    let forged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| BlockAir::generate_trace(&short)));
    crate::stark::LENIENT.with(|l| l.set(false));
    verdicts.push((
        "a resumed transaction skipping an input, under the honest statement",
        match forged {
            Err(e) => Cheat::NoTrace(e.downcast_ref::<String>().cloned().unwrap_or_default()),
            Ok((trace, _)) => match check_constraints(&BlockAir, &trace, &honest_public.to_values()) {
                Err(_) => Cheat::Rejected,
                Ok(()) => Cheat::Accepted,
            },
        },
    ));
    // The same input spent twice in one segment (its path stale).
    let mut double = w.clone();
    let again = double.txs[2].clone();
    double.txs.push(again);
    verdicts.push(("an input spent twice in one segment", cheat(&double)));
    // An output inserted over an occupied position.
    let mut occupied = w.clone();
    occupied.pos_in = 2;
    verdicts.push(("outputs inserted from an occupied position", cheat(&occupied)));

    // Name operations a transaction carries: the digest absorbed into
    // the body (signed) and the operations list (the name segment's)
    // is one; changed or dropped after signing, the body breaks.
    let with_ops = name_ops_segment("attack-ops");
    assert_eq!(cheat(&with_ops), Cheat::Accepted, "an honest spend carrying name operations");
    let mut changed = with_ops.clone();
    changed.txs[0].ops[1][0] += Fp::ONE;
    verdicts.push(("a name operation changed after signing", cheat(&changed)));
    let mut dropped = with_ops.clone();
    dropped.txs[0].ops.pop();
    dropped.txs[0].ops_left -= 1;
    verdicts.push(("a name operation dropped from a signed transaction", cheat(&dropped)));

    let failures: Vec<String> =
        verdicts.iter().filter(|(_, v)| *v != Cheat::Rejected).map(|(what, v)| format!("{what}: {v:?}")).collect();
    for (what, v) in &verdicts {
        eprintln!("{what}: {v:?}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Step 3 of the circuit review (`docs/HARDENING.md`): the circuit
/// against the chain's own rules on random blocks. A valid block, its
/// transactions packed into segments of a random size (so they often
/// split), must give segments that hold, chain, and end where the
/// native set does: root, input and output lists, position and sums. A
/// block one random change makes invalid by the chain's checks must be
/// rejected by the constraints, its trace written by the lenient
/// generator (or refused already when the witness is collected).
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn the_circuit_agrees_with_the_chain_on_random_blocks() {
    use crate::test_util::Rng;
    // A fixed seed, or another for a wider search (TABMINER_DIFF_SEED).
    let seed = std::env::var("TABMINER_DIFF_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_b10c);
    let mut rng = Rng::new(seed);
    let mut pick = |n: u64| (rng.next_u64() % n.max(1)) as usize;
    // One set: the witnesses are gathered from it, and the block then
    // applied to it by the store, which is the chain's verdict here.
    let utxo = TestSet::new();
    // A fresh key per output, by counter.
    let mut next_key = 0u64;
    let mut fresh = || {
        next_key += 1;
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&next_key.to_le_bytes());
        seed[8] = 0xd1;
        Key::generate(&seed)
    };
    // Unspent: position, key, amount.
    let mut unspent: Vec<(u64, Key, u64)> = Vec::new();
    for _ in 0..24 {
        let k = fresh();
        let amount = 1000 + pick(9000) as u64;
        let o = Output::new(&k.public_key(), amount).block_output();
        let p = utxo.add_output(&o, 0).unwrap();
        unspent.push((p, k, amount));
    }
    let (mut valid, mut rejected, mut inconclusive) = (0, 0, 0);
    for round in 0..40u32 {
        let height = 1 + round;
        let broken = round % 2 == 1;
        // A random block of valid transactions.
        let mut txs: Vec<Transaction> = Vec::new();
        let mut spent_now: Vec<(u64, Key, u64)> = Vec::new();
        let mut made: Vec<(Key, u64)> = Vec::new();
        for _ in 0..1 + pick(3) {
            if unspent.len() < 2 {
                break;
            }
            let mut ins: Vec<(u64, Key, u64)> = Vec::new();
            for _ in 0..1 + pick(2) {
                let i = pick(unspent.len() as u64);
                ins.push(unspent.remove(i));
            }
            let total: u64 = ins.iter().map(|i| i.2).sum();
            let fee = pick(10) as u64;
            let n_out = 1 + pick(3);
            let mut outs: Vec<(Key, u64)> = Vec::new();
            let mut left = total - fee;
            for j in 0..n_out {
                let a = if j + 1 == n_out { left } else { 1 + pick(left / 2) as u64 };
                left -= a;
                outs.push((fresh(), a));
            }
            let outputs: Vec<Output> = outs.iter().map(|(k, a)| Output::new(&k.public_key(), *a)).collect();
            let inputs: Vec<(crate::xmss::PublicKey, u64)> = ins.iter().map(|(_, k, a)| (k.public_key(), *a)).collect();
            let mut keys: Vec<Key> = ins.iter().map(|i| i.1.clone()).collect();
            let mut tx = UnsignedTransaction::new(inputs, outputs).sign(|i, _, m| keys[i].sign(m)).unwrap();
            tx.set_positions(&ins.iter().map(|i| i.0).collect::<Vec<_>>());
            txs.push(tx);
            spent_now.extend(ins);
            made.extend(outs);
        }
        if txs.is_empty() {
            break;
        }
        // One change the chain rejects, in a random transaction.
        let mut what = "";
        if broken {
            let t = pick(txs.len() as u64);
            let tx = &mut txs[t];
            match pick(5) {
                0 => {
                    // Signed by a key that does not own the output.
                    let mut stranger = fresh();
                    let mut un = tx.unsigned();
                    un = UnsignedTransaction::new(
                        un.inputs
                            .iter()
                            .enumerate()
                            .map(|(i, x)| if i == 0 { (stranger.public_key(), x.1) } else { *x })
                            .collect(),
                        un.outputs.clone(),
                    );
                    let positions = tx.spent_positions();
                    let mut owners: Vec<Key> =
                        spent_now.iter().filter(|s| positions.contains(&s.0)).map(|s| s.1.clone()).collect();
                    let signed = un.sign(|i, _, m| if i == 0 { stranger.sign(m) } else { owners[i].sign(m) });
                    let Ok(mut forged) = signed else {
                        unspent.append(&mut spent_now);
                        continue;
                    };
                    forged.set_positions(&positions);
                    *tx = forged;
                    what = "signed by a stranger";
                }
                1 => {
                    // An input pointing at another unspent output.
                    let Some(other) = unspent.first() else {
                        unspent.append(&mut spent_now);
                        continue;
                    };
                    let mut ps = tx.spent_positions();
                    ps[0] = other.0;
                    tx.set_positions(&ps);
                    what = "another output's position";
                }
                2 => {
                    // An input claiming more than its output holds.
                    tx.inputs[0].amount += 1;
                    what = "an input claiming more";
                }
                3 => {
                    // An output changed after signing.
                    let o = &mut tx.outputs[0];
                    *o = Output::new(&fresh().public_key(), o.amount);
                    what = "an output changed after signing";
                }
                _ => {
                    // The same output spent by two transactions.
                    let first = txs[0].clone();
                    txs.push(first);
                    what = "an output spent twice";
                }
            }
        }
        // The chain's verdict: signatures, inputs held, no double spend.
        let native_ok = {
            let mut seen = std::collections::HashSet::new();
            txs.iter().all(|tx| {
                tx.verify_signatures()
                    && tx
                        .spent_positions()
                        .iter()
                        .zip(tx.spent_commitments())
                        .all(|(p, c)| seen.insert(*p) && utxo.holds(*p, &c))
            })
        };
        assert_eq!(native_ok, !broken, "round {round}: the chain's verdict on {what:?}");
        let max_rows = [2048, 4096, 8192][pick(3)];
        let positions: Vec<u64> = txs.iter().flat_map(|t| t.spent_positions()).collect();
        let block_outputs: Vec<BlockOutput> =
            txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.block_output())).collect();
        let root_in = utxo.root();
        let pos_in = utxo.next_position();
        // A broken block's witness is collected as a cheater would.
        crate::stark::LENIENT.with(|l| l.set(broken));
        let collected = SegmentWitness::collect_by_rows(&utxo.state.snapshot().unwrap(), &txs, max_rows, height);
        crate::stark::LENIENT.with(|l| l.set(false));
        if broken {
            // Nothing was spent: the inputs are still there.
            unspent.append(&mut spent_now);
            let Ok(segments) = collected else {
                inconclusive += 1;
                continue;
            };
            // Some segment's trace must fail: a transaction segment's,
            // or a signature segment's, where the signatures are held
            // to what they are over.
            if segments.iter().any(|w| cheat(w) != Cheat::Accepted) || !signatures_hold(&segments[0].signed) {
                rejected += 1;
            } else {
                panic!("round {round}: {what} accepted by every segment");
            }
            continue;
        }
        let segments = collected.unwrap();
        // The native block: the store applies it.
        utxo.apply(&txs, height);
        let publics: Vec<SegmentPublic> = segments
            .iter()
            .map(|w| {
                let (trace, public) = BlockAir::generate_trace(w);
                assert_eq!(check_constraints(&BlockAir, &trace, &public.to_values()), Ok(()), "round {round}");
                public
            })
            .collect();
        assert!(signatures_hold(&segments[0].signed), "round {round}: signatures");
        assert!(publics.iter().all(|p| p.signed == segments[0].signed.set.root()), "round {round}: one signed set");
        for p in publics.windows(2) {
            assert_eq!(
                (p[0].root_out, p[0].isp_out, p[0].osp_out, p[0].pos_out, p[0].carry_out),
                (p[1].root_in, p[1].isp_in, p[1].osp_in, p[1].pos_in, p[1].carry_in),
                "round {round}: segments chain"
            );
        }
        let (first, last) = (&publics[0], &publics[publics.len() - 1]);
        assert_eq!((first.root_in, first.pos_in, first.carry_in), (root_in, pos_in, Carry::CLOSED));
        assert_eq!(last.root_out, utxo.root(), "round {round}: roots");
        assert_eq!(last.isp_out, inputs_state(positions.iter().copied()), "round {round}: inputs list");
        assert_eq!(last.osp_out, outputs_state(block_outputs.iter().copied()), "round {round}: outputs list");
        assert_eq!(last.pos_out, utxo.next_position());
        assert_eq!(last.carry_out, Carry::CLOSED);
        let sum =
            |f: fn(&SegmentPublic) -> &[u32; LIMBS]| publics.iter().map(|p| SegmentPublic::total(f(p))).sum::<u128>();
        let ins: u128 = spent_now.iter().map(|s| s.2 as u128).sum();
        let outs: u128 = made.iter().map(|m| m.1 as u128).sum();
        assert_eq!((sum(|p| &p.sum_in), sum(|p| &p.sum_out)), (ins, outs), "round {round}: sums");
        // The new outputs join the unspent set.
        for (i, (k, a)) in made.into_iter().enumerate() {
            unspent.push((pos_in + i as u64, k, a));
        }
        valid += 1;
    }
    eprintln!("{valid} valid blocks agreed; {rejected} broken ones rejected, {inconclusive} refused when collected");
    assert!(valid >= 15 && rejected >= 8, "too few rounds ran: {valid} valid, {rejected} rejected");
}

/// A segment of one transaction spending an output to another and
/// carrying two name commits.
fn name_ops_segment(_name: &str) -> SegmentWitness {
    use crate::name::NameOp;
    let utxo = TestSet::new();
    let mut a = key(1);
    utxo.add_output(&Output::new(&a.public_key(), 100).block_output(), 0).unwrap();
    let d = |x: u32| {
        let mut v = EMPTY;
        v[0] = Fp::new(x);
        v
    };
    let ops = vec![
        NameOp::Commit { commit: d(7), memo: crate::output::memo5(d(8)) },
        NameOp::Commit { commit: d(9), memo: crate::output::memo5(d(10)) },
    ];
    let mut tx =
        UnsignedTransaction::with_ops(vec![(a.public_key(), 100)], vec![Output::new(&key(2).public_key(), 99)], ops)
            .sign_with(&mut a)
            .unwrap();
    tx.set_positions(&[0]);
    let mut segments = utxo.collect(std::slice::from_ref(&tx), 1, 1).unwrap();
    segments.remove(0)
}

/// One random change to a field inside a segment's witness (not its
/// boundary: root, position, list states and height in, which the
/// aggregation pins), described. `None` if the witness has no such
/// field to change this time.
fn mutate_segment(w: &mut SegmentWitness, rng: &mut crate::test_util::Rng) -> Option<String> {
    let mut r = |n: usize| (rng.next_u64() % n.max(1) as u64) as usize;
    let nz = |v: usize| Fp::new(1 + (v as u32) % (crate::poseidon2::P - 1));
    let t = r(w.txs.len());
    let k = r(1 << 20);
    let tx = &mut w.txs[t];
    let (ni, no) = (tx.inputs.len(), tx.outputs.len());
    let i = r(ni.max(1));
    let o = r(no.max(1));
    let d = r(DIGEST);
    let delta = nz(k);
    Some(match r(22) {
        0 if ni > 0 => {
            tx.inputs[i].amount = tx.inputs[i].amount.wrapping_add(1 + (k % 3) as u64);
            format!("tx {t} input {i} amount")
        }
        1 if ni > 0 => {
            tx.inputs[i].memo[d] += delta;
            format!("tx {t} input {i} memo[{d}]")
        }
        2 if ni > 0 => {
            tx.inputs[i].position ^= 1 << (k % 6);
            format!("tx {t} input {i} position")
        }
        3 if ni > 0 => {
            let l = k % DEPTH;
            tx.inputs[i].siblings[l][d] += delta;
            format!("tx {t} input {i} sibling {l}")
        }
        4 if ni > 0 => {
            let c = k % tx.inputs[i].signature.wots.len();
            tx.inputs[i].signature.wots[c][d] += delta;
            format!("tx {t} input {i} signature chain {c}")
        }
        5 if ni > 0 && !tx.inputs[i].signature.auth_path.is_empty() => {
            let l = k % tx.inputs[i].signature.auth_path.len();
            tx.inputs[i].signature.auth_path[l][d] += delta;
            format!("tx {t} input {i} signature path {l}")
        }
        6 if ni > 0 => {
            tx.inputs[i].signature.randomizer[d] += delta;
            format!("tx {t} input {i} signature randomizer")
        }
        7 if ni > 0 => {
            tx.inputs[i].signature.index ^= 1;
            format!("tx {t} input {i} signature index")
        }
        8 if ni > 0 => {
            tx.inputs[i].pubkey.root[d] += delta;
            format!("tx {t} input {i} key root")
        }
        9 if ni > 0 => {
            let j = k % tx.inputs[i].pubkey.pub_seed.len();
            tx.inputs[i].pubkey.pub_seed[j] += delta;
            format!("tx {t} input {i} key seed")
        }
        10 if ni > 0 => {
            tx.inputs[i].height ^= 1 << (k % 4);
            format!("tx {t} input {i} creation height")
        }
        11 if no > 0 => {
            tx.outputs[o].output.amount = tx.outputs[o].output.amount.wrapping_add(1 + (k % 3) as u64);
            format!("tx {t} output {o} amount")
        }
        12 if no > 0 => {
            let j = k % tx.outputs[o].output.memo.len();
            tx.outputs[o].output.memo[j] += delta;
            format!("tx {t} output {o} memo[{j}]")
        }
        13 if no > 0 => {
            tx.outputs[o].output.commitment[d] += delta;
            format!("tx {t} output {o} commitment")
        }
        14 if no > 0 => {
            tx.outputs[o].output.key_hash[d] += delta;
            format!("tx {t} output {o} key hash")
        }
        15 if no > 0 => {
            let l = k % DEPTH;
            tx.outputs[o].siblings[l][d] += delta;
            format!("tx {t} output {o} sibling {l}")
        }
        16 => {
            tx.message[d] += delta;
            format!("tx {t} message")
        }
        17 if !tx.ops.is_empty() => {
            let j = k % tx.ops.len();
            tx.ops[j][d] += delta;
            format!("tx {t} operation {j}")
        }
        18 => {
            match k % 3 {
                0 => tx.in_left = tx.in_left.wrapping_add(1),
                1 => tx.out_left = tx.out_left.wrapping_add(1),
                _ => tx.ops_left = tx.ops_left.wrapping_add(1),
            }
            format!("tx {t} items left")
        }
        19 if ni > 1 => {
            tx.inputs.swap(0, 1);
            format!("tx {t} inputs swapped")
        }
        20 if no > 1 => {
            tx.outputs.swap(0, 1);
            format!("tx {t} outputs swapped")
        }
        21 if tx.policy.is_some() => {
            let p = tx.policy.as_mut().unwrap();
            match k % 4 {
                0 => p.input.amount = p.input.amount.wrapping_add(1),
                1 => p.input.state = p.input.state.wrapping_add(1),
                2 => p.memo[d] += delta,
                _ => p.created ^= 1,
            }
            format!("tx {t} policy input")
        }
        _ => return None,
    })
}

/// A chain of segments (one block) rebuilt from `from` on, as a cheating
/// prover would: each later segment starts where the one before it
/// ended (root, lists, position) and takes over its open transaction
/// (message, body, items left), its trace written leniently. The
/// segments' public values, or why the chain fails: `Err(true)` when a
/// constraint rejects a segment, `Err(false)` when one has no trace.
fn rebuild_chain(
    chain: &mut [SegmentWitness],
    from: usize,
    before: &[SegmentPublic],
) -> Result<Vec<SegmentPublic>, bool> {
    let mut publics: Vec<SegmentPublic> = before[..from].to_vec();
    for k in from..chain.len() {
        if k > from {
            let prev = publics[k - 1];
            let w = &mut chain[k];
            (w.root_in, w.isp_in, w.osp_in, w.nsp_in, w.pos_in) =
                (prev.root_out, prev.isp_out, prev.osp_out, prev.nsp_out, prev.pos_out);
            if prev.carry_out.open {
                let c = prev.carry_out;
                let tx = &mut w.txs[0];
                (tx.message, tx.resume, tx.in_left, tx.out_left, tx.ops_left) =
                    (c.msg, Some(c.bsp), c.in_left, c.out_left, c.ops_left);
            }
        }
        crate::stark::LENIENT.with(|l| l.set(true));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| BlockAir::generate_trace(&chain[k])));
        crate::stark::LENIENT.with(|l| l.set(false));
        let (trace, public) = r.map_err(|_| false)?;
        check_constraints(&BlockAir, &trace, &public.to_values()).map_err(|_| true)?;
        publics.push(public);
    }
    Ok(publics)
}

/// Fuzzes the block circuit's witnesses: 1 to 4 random changes inside
/// one segment (`mutate_segment`) of a block, the block's later
/// segments rebuilt to follow it (`rebuild_chain`), traces written
/// leniently. A block every segment of which holds, whose start, lists,
/// closed ends and height are the honest block's, but which ends
/// elsewhere (root, position, sums) is a bug: the same body with another
/// outcome. Other lists are another body (the node checks the block's
/// own); the same outcome is counted as an equivalent witness.
#[test]
#[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
fn fuzz_segment_witnesses() {
    let (iters, seed) = crate::test_util::fuzz_params(150, 0xf022_b10c);
    let mut rng = crate::test_util::Rng::new(seed);
    let (plain, ..) = scenario("fuzz-plain", 3);
    let plan = vec![
        vec![Part { tx: 0, start: 0, end: 1 }],
        vec![Part { tx: 0, start: 1, end: 3 }],
        vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
    ];
    let (span, ..) = scenario_with("fuzz-span", |utxo, txs| utxo.collect_parts(txs, plan, 1).unwrap());
    let (_, policy) = policy_segments();
    // Blocks: the plain one, the spanning one, each policy spend, the
    // spend carrying name operations.
    let mut blocks: Vec<Vec<SegmentWitness>> = vec![plain, span];
    blocks.extend(policy.into_iter().map(|w| vec![w]));
    blocks.push(vec![name_ops_segment("fuzz-ops")]);
    let honest: Vec<Vec<SegmentPublic>> =
        blocks.iter().map(|b| b.iter().map(|w| BlockAir::generate_trace(w).1).collect()).collect();
    let pinned = |p: &[SegmentPublic]| {
        let (f, l) = (&p[0], &p[p.len() - 1]);
        (
            f.root_in,
            f.isp_in,
            f.osp_in,
            f.nsp_in,
            f.pos_in,
            f.carry_in,
            l.isp_out,
            l.osp_out,
            l.nsp_out,
            l.carry_out,
            f.height,
        )
    };
    let outcome = |p: &[SegmentPublic]| {
        let sum = |f: fn(&SegmentPublic) -> &[u32; LIMBS]| p.iter().map(|x| SegmentPublic::total(f(x))).sum::<u128>();
        (p[p.len() - 1].root_out, p[p.len() - 1].pos_out, sum(|x| &x.sum_in), sum(|x| &x.sum_out))
    };
    let (mut rejected, mut no_trace, mut other, mut bugs) = (0, 0, 0, Vec::new());
    let mut same: Vec<String> = Vec::new();
    // The lenient generator panics on witnesses it cannot write: quiet.
    let quiet = crate::test_util::Quiet::new();
    let mut n = 0;
    while n < iters {
        let b = (rng.next_u64() % blocks.len() as u64) as usize;
        let k = (rng.next_u64() % blocks[b].len() as u64) as usize;
        let mut chain = blocks[b].clone();
        let mut what = Vec::new();
        for _ in 0..1 + rng.next_u64() % 4 {
            if let Some(m) = mutate_segment(&mut chain[k], &mut rng) {
                what.push(m);
            }
        }
        if what.is_empty() {
            continue;
        }
        n += 1;
        let at = format!("block {b} segment {k}: {}", what.join(", "));
        match rebuild_chain(&mut chain, k, &honest[b]) {
            Err(true) => rejected += 1,
            Err(false) => no_trace += 1,
            Ok(p) if pinned(&p) != pinned(&honest[b]) => other += 1,
            Ok(p) if outcome(&p) == outcome(&honest[b]) => same.push(at),
            Ok(_) => bugs.push(at),
        }
    }
    drop(quiet);
    eprintln!(
        "{iters} mutants: {rejected} rejected, {} equivalent, {other} another body, {no_trace} without a trace, {} another outcome",
        same.len(),
        bugs.len()
    );
    for e in &same {
        eprintln!("  equivalent: {e}");
    }
    assert!(bugs.is_empty(), "the same body with another outcome (seed {seed}):\n{}", bugs.join("\n"));
}

/// The four policy spends of [`policy_spends_satisfy_constraints`]
/// (multisig, HTLC claim, eltoo update, covenant settlement), one
/// segment each.
fn policy_segments() -> (Vec<Transaction>, Vec<SegmentWitness>) {
    use crate::output::pubkey_hash;
    use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer, covered_digest, hash_lock, rebind_message};
    let utxo = TestSet::new();
    let (mut a, mut bk, mut c) = (key(1), key(2), key(3));
    let keys: Vec<Digest> = [&a, &bk, &c].iter().map(|k| pubkey_hash(&k.public_key())).collect();
    let dest = key(4).public_key();
    let height = 200;
    let d = |x: u32| {
        let mut v = EMPTY;
        v[0] = Fp::new(x);
        v
    };
    let memo = |x: u32| d(100 + x);

    // Outputs: a 2-of-3, an HTLC, an eltoo state (settling to a and b).
    let multisig = Policy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: keys.clone() }])]);
    let preimage = d(77);
    let htlc = Policy::new(vec![
        Leaf::new(vec![
            Cond::Hash(hash_lock(&preimage)),
            Cond::Thresh { mode: Mode::Body, m: 1, keys: keys[1..2].to_vec() },
        ]),
        Leaf::new(vec![Cond::After(100), Cond::Thresh { mode: Mode::Body, m: 1, keys: keys[..1].to_vec() }]),
    ]);
    let channel = d(5);
    let settle_outputs = [
        Output::with_memo(&keys[0], 600, crate::output::memo5(memo(1))),
        Output::with_memo(&keys[1], 400, crate::output::memo5(memo(2))),
    ];
    let settle: Vec<(Commitment, Digest)> = settle_outputs.iter().map(|o| (o.commitment, o.slot())).collect();
    let state = Policy::new(vec![
        Leaf::new(vec![
            Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: keys[..2].to_vec() },
            Cond::State(3),
        ]),
        Leaf::new(vec![Cond::Older(144), Cond::Outputs(settle.clone())]),
    ]);
    let outs = [
        (multisig.root(), 1000u64, memo(10)),
        (htlc.root(), 500, memo(11)),
        (state.root(), 1000, memo(12)),
        (state.root(), 1000, memo(13)),
    ];
    for (policy, amount, m) in &outs {
        let o = Output::with_memo(policy, *amount, crate::output::memo5(*m));
        utxo.add_output(&o.block_output(), 0).unwrap();
    }

    // 2-of-3 in body mode: a and c sign the body hash.
    let mut spend = multisig.spend(0, 1000, 0);
    let unsigned =
        UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)]).with_policy_inputs(vec![spend.clone()]);
    let body = unsigned.body_hash();
    spend.witness[0] = CondWitness::Signatures(vec![
        Signer { key: 0, pubkey: a.public_key(), signature: a.sign(&body).unwrap() },
        Signer { key: 2, pubkey: c.public_key(), signature: c.sign(&body).unwrap() },
    ]);
    let tx_multisig = UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)])
        .with_policy_inputs(vec![spend])
        .sign(|_, _, _| Err::<Sig, ()>(()))
        .unwrap();
    assert_eq!(tx_multisig.body_hash(), body);

    // HTLC claim: the preimage and b's signature.
    let mut claim = htlc.spend(0, 500, 1);
    let unsigned =
        UnsignedTransaction::new(vec![], vec![Output::new(&dest, 500)]).with_policy_inputs(vec![claim.clone()]);
    let body = unsigned.body_hash();
    claim.witness[0] = CondWitness::Preimage(preimage);
    claim.witness[1] =
        CondWitness::Signatures(vec![Signer { key: 0, pubkey: bk.public_key(), signature: bk.sign(&body).unwrap() }]);
    let tx_claim = UnsignedTransaction::new(vec![], vec![Output::new(&dest, 500)])
        .with_policy_inputs(vec![claim])
        .sign(|_, _, _| Err::<Sig, ()>(()))
        .unwrap();

    // Eltoo update to state 4: a and b sign the rebindable message with
    // leaf 4, over the new state output as the covered run.
    let new_state = Output::with_memo(&state.root(), 1000, crate::output::memo5(memo(14)));
    let mut update = state.spend(0, 1000, 2);
    update.state = 4;
    update.covered = (0, 1);
    let msg = rebind_message(&channel, 4, &[(new_state.commitment, new_state.slot())]);
    let mut a4 = key(1);
    a4.set_next_index(4);
    let mut b4 = key(2);
    b4.set_next_index(4);
    update.witness[0] = CondWitness::Signatures(vec![
        Signer { key: 0, pubkey: a4.public_key(), signature: a4.sign(&msg).unwrap() },
        Signer { key: 1, pubkey: b4.public_key(), signature: b4.sign(&msg).unwrap() },
    ]);
    let tx_update = UnsignedTransaction::new(vec![], vec![new_state])
        .with_policy_inputs(vec![update])
        .sign(|_, _, _| Err::<Sig, ()>(()))
        .unwrap();

    // Settlement of the other state output: no signature, the covered
    // run is the covenant's, after the delay (created at 0, height 200).
    let mut settlement = state.spend(1, 1000, 3);
    settlement.covered = (1, 2);
    let tx_settle = UnsignedTransaction::new(
        vec![],
        vec![Output::new(&dest, 7), settle_outputs[0], settle_outputs[1], Output::new(&dest, 9)],
    )
    .with_policy_inputs(vec![settlement])
    .sign(|_, _, _| Err::<Sig, ()>(()))
    .unwrap();
    assert_eq!(covered_digest(&settle), covered_digest(&settle));

    let txs = [tx_multisig, tx_claim, tx_update, tx_settle];
    for tx in &txs {
        let created = |_| Some(0);
        assert_eq!(tx.check_policy_inputs(height, created), Ok(()), "node-side check");
    }
    let segments = utxo.collect(&txs, 1, height).unwrap();
    (txs.to_vec(), segments)
}

/// The block circuit's columns by name: each column is named after the
/// constant at or below it, with an offset (for the audit's report).
fn column_name(c: usize) -> String {
    let named: &[(&str, usize)] = &[
        ("T_TX_START", T_TX_START),
        ("T_TX_END", T_TX_END),
        ("T_PKH0", T_PKH0),
        ("T_PKH1", T_PKH1),
        ("T_CM0", T_CM0),
        ("T_CM1", T_CM1),
        ("T_ILIST", T_ILIST),
        ("T_OLD", T_OLD),
        ("T_NEW", T_NEW),
        ("T_BODY_IN0", T_BODY_IN0),
        ("T_BODY_IN1", T_BODY_IN1),
        ("T_OCM0", T_OCM0),
        ("T_OCM1", T_OCM1),
        ("T_OLIST", T_OLIST),
        ("T_BODY_OUT0", T_BODY_OUT0),
        ("T_BODY_OUT1", T_BODY_OUT1),
        ("T_DONE", T_DONE),
        ("T_RESUME", T_RESUME),
        ("T_OLIST2", T_OLIST2),
        ("T_BODY_OUT2", T_BODY_OUT2),
        ("T_ILEAF", T_ILEAF),
        ("T_OLEAF", T_OLEAF),
        ("T_OP_BODY", T_OP_BODY),
        ("T_OP_LIST", T_OP_LIST),
        ("T_ILEAF2", T_ILEAF2),
        ("T_OLEAF2", T_OLEAF2),
        ("T_PSTART", T_PSTART),
        ("T_CVS", T_CVS),
        ("T_LHDR", T_LHDR),
        ("T_THR", T_THR),
        ("T_CHAN", T_CHAN),
        ("T_KEY", T_KEY),
        ("T_KSEL", T_KSEL),
        ("T_HL", T_HL),
        ("T_HASH", T_HASH),
        ("T_AFTER", T_AFTER),
        ("T_OLDER", T_OLDER),
        ("T_STATE", T_STATE),
        ("T_OUTS", T_OUTS),
        ("T_PP0", T_PP0),
        ("T_PP1", T_PP1),
        ("T_PP2", T_PP2),
        ("T_PP3", T_PP3),
        ("T_PSIG", T_PSIG),
        ("T_PEND", T_PEND),
        ("T_CVC", T_CVC),
        ("T_CVM", T_CVM),
        ("T_RB0", T_RB0),
        ("T_RB1", T_RB1),
        ("T_RB2", T_RB2),
        ("R_SIB", R_SIB),
        ("C_LEVEL", C_LEVEL),
        ("C_LEVEL_INV", C_LEVEL_INV),
        ("C_IS_LAST", C_IS_LAST),
        ("C_SMT_END", C_SMT_END),
        ("R_PBITS", R_PBITS),
        ("R_ROOT", R_ROOT),
        ("R_OLD", R_OLD),
        ("R_NEW", R_NEW),
        ("R_IS_OUT", R_IS_OUT),
        ("C_OUT_END", C_OUT_END),
        ("R_MSG", R_MSG),
        ("R_BSP", R_BSP),
        ("R_ISP", R_ISP),
        ("R_OSP", R_OSP),
        ("R_PKROOT", R_PKROOT),
        ("R_OCM", R_OCM),
        ("R_ABITS", R_ABITS),
        ("R_SUM_IN", R_SUM_IN),
        ("R_SUM_OUT", R_SUM_OUT),
        ("R_OPOS_LO", R_OPOS_LO),
        ("R_OPOS_HI", R_OPOS_HI),
        ("C_WRAP", C_WRAP),
        ("C_WRAP_INV", C_WRAP_INV),
        ("R_IN_LEFT", R_IN_LEFT),
        ("R_OUT_LEFT", R_OUT_LEFT),
        ("C_IN_ZERO", C_IN_ZERO),
        ("C_IN_INV", C_IN_INV),
        ("C_OUT_ZERO", C_OUT_ZERO),
        ("C_OUT_INV", C_OUT_INV),
        ("C_GO_OUT", C_GO_OUT),
        ("C_GO_END", C_GO_END),
        ("R_OPEN", R_OPEN),
        ("R_MEMO", R_MEMO),
        ("R_LEAF", R_LEAF),
        ("R_OPD", R_OPD),
        ("R_NSP", R_NSP),
        ("R_OPS_LEFT", R_OPS_LEFT),
        ("C_OPS_ZERO", C_OPS_ZERO),
        ("C_OPS_INV", C_OPS_INV),
        ("C_GO_OPS", C_GO_OPS),
        ("R_POL", R_POL),
        ("R_PIN", R_PIN),
        ("R_POL_LEFT", R_POL_LEFT),
        ("C_IN_DONE", C_IN_DONE),
        ("C_DISP", C_DISP),
        ("R_PSTATE", R_PSTATE),
        ("R_CVB", R_CVB),
        ("R_CVN", R_CVN),
        ("C_CVB_ZERO", C_CVB_ZERO),
        ("C_CVB_INV", C_CVB_INV),
        ("C_CVN_ZERO", C_CVN_ZERO),
        ("C_CVN_INV", C_CVN_INV),
        ("R_INRUN", R_INRUN),
        ("R_CREATED", R_CREATED),
        ("R_SMSG", R_SMSG),
        ("R_RMSG", R_RMSG),
        ("R_PIDX", R_PIDX),
        ("R_LLEN", R_LLEN),
        ("R_LCNT", R_LCNT),
        ("R_LSP", R_LSP),
        ("R_NC", R_NC),
        ("C_NC_ZERO", C_NC_ZERO),
        ("C_NC_INV", C_NC_INV),
        ("R_TAG", R_TAG),
        ("R_M", R_M),
        ("C_M_INV", C_M_INV),
        ("R_KREM", R_KREM),
        ("C_KLAST", C_KLAST),
        ("C_KLAST_INV", C_KLAST_INV),
        ("R_SREM", R_SREM),
        ("C_SREM_ZERO", C_SREM_ZERO),
        ("C_SREM_INV", C_SREM_INV),
        ("R_HADTHR", R_HADTHR),
        ("R_REBIND", R_REBIND),
        ("R_CHAN", R_CHAN),
        ("R_HASCOV", R_HASCOV),
        ("R_NEEDRUN", R_NEEDRUN),
        ("R_RUNDONE", R_RUNDONE),
        ("R_COV", R_COV),
        ("R_PROOT", R_PROOT),
        ("R_KSP", R_KSP),
        ("R_SSP", R_SSP),
        ("R_CSP", R_CSP),
        ("C_CEND", C_CEND),
        ("C_GO_POL", C_GO_POL),
        ("hm::COL_START", crate::hash_machine::COL_START),
        ("hm::COL_ABSORB", crate::hash_machine::COL_ABSORB),
        ("hm::COL_CHAIN", crate::hash_machine::COL_CHAIN),
        ("hm::COL_COMPRESS", crate::hash_machine::COL_COMPRESS),
        ("hm::COL_PASS", crate::hash_machine::COL_PASS),
        ("hm::COL_LOAD", crate::hash_machine::COL_LOAD),
        ("hm::COL_DIR", crate::hash_machine::COL_DIR),
        ("hm::COL_DATA", crate::hash_machine::COL_DATA),
        ("hm::COL_ACC", crate::hash_machine::COL_ACC),
        ("perm", 0),
        ("bits", BCOLS.bit(0)),
        ("bits::top", BCOLS.top()),
        ("R_SIB", R_SIB),
    ];
    let (name, at) = named.iter().filter(|(_, v)| *v <= c).max_by_key(|(_, v)| *v).unwrap();
    if *at == c { name.to_string() } else { format!("{name}+{}", c - at) }
}

/// Runs `f` over `items` in chunks on every core and gathers what it
/// returns.
fn on_cores<T: Sync, R: Send>(items: &[T], f: impl Fn(&[T]) -> Vec<R> + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = items.chunks(chunk).map(|c| s.spawn(|| f(c))).collect();
        handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
    })
}

/// The soundness audit of one segment (`stark::freedom_audit` and
/// `stark::run_audit`): every way its rows' cells can move together
/// unseen, but the two kinds the design allows, as lines naming the
/// segment, row and cells. Allowed: a hash permutation on a row whose
/// permutation is not used (`pass`, `load`), and a value with its
/// zero-test inverse (pinned by the product, so only to first order).
fn audit_segment(name: &str, seg: &SegmentWitness) -> Vec<String> {
    use crate::hash_machine::{COL_LOAD, COL_PASS};
    let (trace, public) = BlockAir::generate_trace(seg);
    let public = public.to_values();
    let types: Vec<usize> =
        (0..NUM_COLS).filter(|&c| column_name(c).starts_with("T_") && !column_name(c).contains('+')).collect();
    let row_type = |r: usize| types.iter().copied().find(|&c| trace.row(r)[c] == Fp::ONE);
    // Rows: all of a rare type, eight spread over a common one.
    let mut of_type: std::collections::BTreeMap<Option<usize>, Vec<usize>> = Default::default();
    for r in 0..trace.height() {
        of_type.entry(row_type(r)).or_default().push(r);
    }
    let mut rows = Vec::new();
    for list in of_type.values() {
        if list.len() <= 8 {
            rows.extend(list);
        } else {
            rows.extend((0..8).map(|k| list[k * (list.len() - 1) / 7]));
        }
    }
    let perm = crate::poseidon2_air::NUM_COLS;
    let zero_pair = |a: usize, b: usize| {
        let (na, nb) = (column_name(a), column_name(b));
        nb == format!("{na}_INV") || (na == "x::rem" && nb == "x::rem_inv")
    };
    let mut problems: Vec<String> =
        on_cores(&rows, |chunk| crate::stark::audit::freedom_audit(&BlockAir, &trace, None, &public, chunk))
            .into_iter()
            .filter(|f| {
                let unused_perm = f.cells.iter().all(|(c, _)| *c < perm)
                    && (trace.row(f.row)[COL_PASS] == Fp::ONE || trace.row(f.row)[COL_LOAD] == Fp::ONE);
                let inverse = !f.exact && f.cells.len() == 2 && zero_pair(f.cells[0].0, f.cells[1].0);
                !(unused_perm || inverse)
            })
            .map(|f| {
                let cells: Vec<String> = f.cells.iter().map(|(c, _)| column_name(*c)).collect();
                format!(
                    "{name} row {} {}: {} freedom: {}",
                    f.row,
                    row_type(f.row).map_or("(none)".into(), column_name),
                    if f.exact { "exact" } else { "first-order" },
                    cells.join(" ")
                )
            })
            .collect();
    // Runs of one type, two rows or more, every column.
    let mut runs = Vec::new();
    let mut start = 0;
    for r in 1..=trace.height() {
        if r == trace.height() || row_type(r) != row_type(start) {
            if r - start >= 2 {
                runs.extend((0..NUM_COLS).map(|c| (c, start, r)));
            }
            start = r;
        }
    }
    let shifted = on_cores(&runs, |chunk| crate::stark::audit::run_audit(&BlockAir, &trace, None, &public, chunk));
    for (col, first, end) in shifted {
        // A column nothing reads in the run can shift freely; one read
        // there and still unseen is a carried register unpinned. On the
        // done rows (padding) registers left over from the last item
        // are carried to the end and read by nothing: the shift was
        // checked against the last row's public values and every
        // lookup, so the statement does not change.
        if row_type(first) == Some(T_DONE) {
            continue;
        }
        if (first..end).any(|r| crate::stark::audit::cell_read(&BlockAir, &trace, None, &public, r, col)) {
            problems.push(format!(
                "{name} rows {first}..{end} {}: {} shifts unseen",
                row_type(first).map_or("(none)".into(), column_name),
                column_name(col)
            ));
        }
    }
    problems
}

/// The soundness audit of the block circuit over the transaction
/// shapes the tests build: plain spends and a reward in one segment, a
/// transaction split over three segments (resume rows, carries), and
/// the four policy spends. No row may have a freedom the design does
/// not allow, nor any run a register that shifts unseen.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn the_block_circuit_has_no_unintended_freedom() {
    let mut problems = Vec::new();
    let (plain, ..) = scenario("audit-plain", 3);
    let plan = vec![
        vec![Part { tx: 0, start: 0, end: 1 }],
        vec![Part { tx: 0, start: 1, end: 3 }],
        vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
    ];
    let (spanning, ..) = scenario_with("audit-span", |utxo, txs| utxo.collect_parts(txs, plan, 1).unwrap());
    let (_, policy) = policy_segments();
    let ops = vec![name_ops_segment("audit-ops")];
    let shapes = [("plain", plain), ("span", spanning), ("policy", policy), ("ops", ops)];
    for (shape, segments) in &shapes {
        for (k, seg) in segments.iter().enumerate() {
            let t = std::time::Instant::now();
            let found = audit_segment(&format!("{shape} segment {k}"), seg);
            eprintln!("{shape} segment {k}: {} problems in {:.0} s", found.len(), t.elapsed().as_secs_f64());
            problems.extend(found);
        }
    }
    assert!(problems.is_empty(), "{} problems:\n{}", problems.len(), problems.join("\n"));
}

/// Keys of any height up to the maximum verify; the fragment stops at
/// the key's last level and the rows count accordingly.
#[test]
fn keys_of_other_heights_verify() {
    let utxo = TestSet::new();
    let mut tall = Key::generate_with_height(&[9; 32], 10);
    let mut short = Key::generate_with_height(&[8; 32], 1);
    // The tall key signs from a high leaf: the index bits above a
    // plain key's height are in use.
    tall.set_next_index(1000);
    let dest = key(3).public_key();
    utxo.add_output(&Output::new(&tall.public_key(), 70).block_output(), 0).unwrap();
    utxo.add_output(&Output::new(&short.public_key(), 30).block_output(), 0).unwrap();
    let mut tx = UnsignedTransaction::new(
        vec![(tall.public_key(), 70), (short.public_key(), 30)],
        vec![Output::new(&dest, 100)],
    )
    .sign(|i, _, m| if i == 0 { tall.sign(m) } else { short.sign(m) })
    .unwrap();
    tx.set_positions(&[0, 1]);
    assert!(tx.verify_signatures());
    assert_eq!(tx.inputs[0].signature.height(), 10);
    assert_eq!(tx.inputs[1].signature.height(), 1);
    let segments = utxo.collect(std::slice::from_ref(&tx), 1, 1).unwrap();
    assert_eq!(segments[0].num_rows(), 2 + input_rows(10) + input_rows(1) + ROWS_PER_OUTPUT);
    let (trace, public) = BlockAir::generate_trace(&segments[0]);
    assert_eq!(trace.height(), segments[0].num_rows().next_power_of_two());
    assert_eq!(check_constraints(&BlockAir, &trace, &public.to_values()), Ok(()));
}

/// An output whose state leaf holds another amount than its
/// commitment hides cannot be spent: the amount the supply check
/// counted is the one the proof's sums use (`docs/AMOUNTS.md`).
#[test]
fn the_amount_in_the_leaf_is_the_committed_one() {
    let mut a = key(1);
    let dest = key(3).public_key();
    let spend = |recorded: u64, a: &mut Key| {
        let utxo = TestSet::new();
        let mut listed = Output::new(&a.public_key(), 100).block_output();
        listed.amount = recorded;
        utxo.add_output(&listed, 0).unwrap();
        let mut tx =
            UnsignedTransaction::new(vec![(a.public_key(), 100)], vec![Output::new(&dest, 100)]).sign_with(a).unwrap();
        tx.set_positions(&[0]);
        let segments = utxo.collect(std::slice::from_ref(&tx), 1, 1).unwrap();
        let (trace, public) = BlockAir::generate_trace(&segments[0]);
        check_constraints(&BlockAir, &trace, &public.to_values())
    };
    assert_eq!(spend(100, &mut a), Ok(()));
    // The leaf (so the state root) says 1, the commitment 100.
    let err = spend(1, &mut a).unwrap_err();
    assert_eq!(err.2, "key hash / commitment / amounts");
}

#[test]
fn layout_and_degree() {
    assert_eq!(measure_degree(&BlockAir, NUM_PUBLIC), 3);
    // A signature is looked up, not checked: two rows of its entry and
    // one a level of the signed set, whatever the key's height. Then
    // two rows a level of the state tree, of which there are forty-two.
    assert_eq!(ROWS_PER_SIGNATURE, 2 + 27);
    assert_eq!((input_rows(4), input_rows(20)), (ROWS_PER_INPUT, ROWS_PER_INPUT));
    assert_eq!(ROWS_PER_INPUT, 29 + 6 + 1 + 84 + 2);
    assert_eq!(ROWS_PER_OUTPUT, 93);
    assert_eq!(NUM_PUBLIC, 128 + 2 * 28 + 1 + 8);
}

#[test]
fn segments_satisfy_constraints_and_chain() {
    let (segments, expected_root, positions, outputs) = scenario("ok", 2);
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].txs.len(), 2);
    assert_eq!(segments[0].num_rows(), 2 * 2 + 2 * input_rows(4) + 3 * ROWS_PER_OUTPUT);
    let mut publics = Vec::new();
    for (k, seg) in segments.iter().enumerate() {
        let (trace, public) = BlockAir::generate_trace(seg);
        let values = public.to_values();
        assert_eq!(SegmentPublic::from_values(&values), Some(public));
        assert_eq!(check_constraints(&BlockAir, &trace, &values), Ok(()), "segment {k}");
        // Every public value matters.
        for i in [
            PUB_ROOT_IN,
            PUB_ROOT_OUT + 3,
            PUB_ISP_IN + 9,
            PUB_ISP_OUT,
            PUB_OSP_IN + 15,
            PUB_OSP_OUT + 2,
            PUB_POS_IN,
            PUB_POS_OUT,
            PUB_SUM_IN + 1,
            PUB_SUM_OUT,
        ] {
            let mut bad = values.clone();
            bad[i] += Fp::ONE;
            assert!(check_constraints(&BlockAir, &trace, &bad).is_err(), "segment {k} public {i}");
        }
        publics.push(public);
    }
    // Chaining and block-level binding.
    assert_eq!(publics[0].root_out, publics[1].root_in);
    assert_eq!(publics[0].isp_out, publics[1].isp_in);
    assert_eq!(publics[0].osp_out, publics[1].osp_in);
    assert_eq!(publics[0].pos_out, publics[1].pos_in);
    assert_eq!(publics[0].isp_in, initial_inputs_state());
    assert_eq!(publics[0].osp_in, initial_outputs_state());
    assert_eq!(publics[0].pos_in, 3);
    assert_eq!(publics[1].pos_out, 7);
    assert_eq!(publics[1].root_out, expected_root);
    assert_eq!(publics[1].isp_out, inputs_state(positions.iter().copied()));
    assert_eq!(publics[1].osp_out, outputs_state(outputs.iter().map(|o| o.block_output())));
    let total_in: u128 = publics.iter().map(|p| SegmentPublic::total(&p.sum_in)).sum();
    let total_out: u128 = publics.iter().map(|p| SegmentPublic::total(&p.sum_out)).sum();
    assert_eq!(total_in, 180);
    assert_eq!(total_out, 230);
    assert_eq!(total_in + 50, total_out);
    // The same transactions as one segment give the same endpoints.
    let (single, root1, _, _) = scenario("single", 10);
    assert_eq!(single.len(), 1);
    let (_, p) = BlockAir::generate_trace(&single[0]);
    assert_eq!(p.root_out, root1);
    assert_eq!(p.isp_out, publics[1].isp_out);
    assert_eq!(p.osp_out, publics[1].osp_out);
    assert_eq!(SegmentPublic::total(&p.sum_out), 230);
}

#[test]
fn transactions_span_segments() {
    // The first transaction (two inputs, two outputs) is split after
    // its first input and after its first output.
    let plan = vec![
        vec![Part { tx: 0, start: 0, end: 1 }],
        vec![Part { tx: 0, start: 1, end: 3 }],
        vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
    ];
    let (segments, expected_root, positions, outputs) =
        scenario_with("span", |utxo, txs| utxo.collect_parts(txs, plan, 1).unwrap());
    assert_eq!(segments.len(), 3);
    let mut publics = Vec::new();
    let mut traces = Vec::new();
    for (k, seg) in segments.iter().enumerate() {
        let (trace, public) = BlockAir::generate_trace(seg);
        let values = public.to_values();
        assert_eq!(SegmentPublic::from_values(&values), Some(public));
        assert_eq!(check_constraints(&BlockAir, &trace, &values), Ok(()), "segment {k}");
        publics.push(public);
        traces.push(trace);
    }
    let (c01, c12) = (publics[0].carry_out, publics[1].carry_out);
    assert_eq!(publics[0].carry_in, Carry::CLOSED);
    assert!(c01.open && c12.open);
    assert_eq!((c01.in_left, c01.out_left), (1, 2));
    assert_eq!((c12.in_left, c12.out_left), (0, 1));
    assert_eq!(publics[1].carry_in, c01);
    assert_eq!(publics[2].carry_in, c12);
    assert_eq!(publics[2].carry_out, Carry::CLOSED);
    for w in publics.windows(2) {
        assert_eq!((w[0].root_out, w[0].isp_out, w[0].osp_out), (w[1].root_in, w[1].isp_in, w[1].osp_in));
        assert_eq!(w[0].pos_out, w[1].pos_in);
    }
    assert_eq!(publics[2].root_out, expected_root);
    assert_eq!(publics[2].isp_out, inputs_state(positions.iter().copied()));
    assert_eq!(publics[2].osp_out, outputs_state(outputs.iter().map(|o| o.block_output())));
    let total =
        |f: fn(&SegmentPublic) -> &[u32; LIMBS]| -> u128 { publics.iter().map(|p| SegmentPublic::total(f(p))).sum() };
    assert_eq!(total(|p| &p.sum_in) + 50, total(|p| &p.sum_out));

    // Every carry value matters, on both sides.
    let mid = &traces[1];
    let values = publics[1].to_values();
    for c in [CARRY_OPEN, CARRY_MSG + 2, CARRY_BSP + 11, CARRY_IN_LEFT, CARRY_OUT_LEFT] {
        for at in [PUB_CARRY_IN, PUB_CARRY_OUT] {
            let mut bad = values.clone();
            bad[at + c] += Fp::ONE;
            assert!(check_constraints(&BlockAir, mid, &bad).is_err(), "carry {at} + {c}");
        }
    }
    // Claiming the open transaction closed.
    let mut bad = values.clone();
    bad[PUB_CARRY_OUT..PUB_CARRY_OUT + CARRY_LEN].fill(Fp::ZERO);
    assert!(check_constraints(&BlockAir, mid, &bad).is_err());
    // A resume row turned into a start: its header is not the carry.
    let mut bad = mid.clone();
    bad.values[T_RESUME] = Fp::ZERO;
    bad.values[T_TX_START] = Fp::ONE;
    assert!(check_constraints(&BlockAir, &bad, &values).is_err());
    // A transaction cannot be resumed with a different message: the
    // signatures then fail (the witness refuses to build).
    let mut forged = segments[1].clone();
    forged.txs[0].message[0] += Fp::ONE;
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&forged)).is_err());
}

#[test]
fn packing_splits_between_items() {
    // Inputs by keys of 4, 20 and 16 levels; the last transaction stays
    // whole.
    let items = |t: usize| {
        let (heights, n_out, n_ops, whole): (&[usize], usize, usize, bool) =
            [(&[][..], 1, 0, false), (&[4, 20, 16][..], 2, 1, false), (&[4][..], 2, 0, false), (&[][..], 5, 3, true)]
                [t];
        let mut rows: Vec<usize> = heights.iter().map(|&h| input_rows(h)).collect();
        rows.extend(std::iter::repeat_n(ROWS_PER_OUTPUT, n_out));
        rows.extend(std::iter::repeat_n(ROWS_PER_OP, n_ops));
        (rows, whole)
    };
    let max_rows = 512;
    let plan = pack(4, items, max_rows);
    // Parts cover every item once, in order.
    let mut next = [0usize; 4];
    let mut last_tx = 0;
    for seg in &plan {
        let mut rows = 0;
        for p in seg {
            assert!(p.tx >= last_tx);
            last_tx = p.tx;
            assert_eq!(p.start, next[p.tx]);
            next[p.tx] = p.end;
            let (item_rows, whole) = items(p.tx);
            assert!(!whole || (p.start == 0 && p.end == item_rows.len()));
            rows += 1 + item_rows[p.start..p.end].iter().sum::<usize>();
            rows += usize::from(p.end == item_rows.len());
        }
        assert!(rows < max_rows, "{rows}");
    }
    assert_eq!(next, [1, 6, 3, 8]);
    // The second transaction's inputs fit beside the first; its outputs
    // do not, and go on in the next segment, with the third whole. The
    // last must stay whole, and has a segment to itself.
    assert_eq!(plan[0], vec![Part { tx: 0, start: 0, end: 1 }, Part { tx: 1, start: 0, end: 3 }]);
    assert_eq!(plan[1], vec![Part { tx: 1, start: 3, end: 6 }, Part { tx: 2, start: 0, end: 3 }]);
    assert_eq!(plan[2], vec![Part { tx: 3, start: 0, end: 8 }]);
}

/// A signature is looked up in the block's signed set, and nothing
/// stands in for it: not another set, not a path that leads elsewhere,
/// not another message, leaf or key on the way to the entry.
#[test]
fn a_signature_is_looked_up_in_the_signed_set() {
    let (segments, _, _, _) = scenario("signed", 10);
    let w = &segments[0];
    assert!(!w.signed.segments.is_empty());
    let (trace, public) = BlockAir::generate_trace(w);
    assert_eq!(public.signed, w.signed.set.root());
    let values = public.to_values();
    assert_eq!(check_constraints(&BlockAir, &trace, &values), Ok(()));
    // Against another set's root the trace does not hold.
    let mut other = public;
    other.signed[3] += Fp::ONE;
    assert!(check_constraints(&BlockAir, &trace, &other.to_values()).is_err());
    // A witness whose set lacks the signatures makes no trace.
    let mut bare = w.clone();
    bare.signed = Default::default();
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&bare)).is_err());
    let width = NUM_COLS;
    let row_of = |ty: usize, which: usize| {
        (0..trace.height()).filter(|&r| trace.values[r * width + ty] == Fp::ONE).nth(which).expect("such a row")
    };
    let breaks = |what: &str, change: &dyn Fn(&mut crate::stark::Trace)| {
        let mut bad = trace.clone();
        change(&mut bad);
        assert!(check_constraints(&BlockAir, &bad, &values).is_err(), "{what}");
    };
    // The path: a sibling, a direction, a row left out of it.
    breaks("sibling", &|t| t.values[row_of(T_SP, 5) * width + COL_DATA + 1] += Fp::ONE);
    breaks("direction", &|t| {
        let at = row_of(T_SP, 0) * width + COL_DIR;
        t.values[at] = Fp::ONE - t.values[at];
    });
    breaks("levels left", &|t| t.values[row_of(T_SP, 2) * width + R_SPN] -= Fp::ONE);
    breaks("the path's end", &|t| {
        let at = row_of(T_SP, 3) * width;
        t.values[at + C_SP_LAST] = Fp::ONE;
        t.values[at + C_SP_END] = Fp::ONE;
    });
    // The entry: the message, the leaf that signed, the key's hash.
    breaks("message", &|t| t.values[row_of(T_ENT0, 0) * width + COL_DATA] += Fp::ONE);
    breaks("message register", &|t| t.values[row_of(T_ENT0, 0) * width + R_SMSG] += Fp::ONE);
    breaks("leaf", &|t| t.values[row_of(T_ENT1, 0) * width + COL_DATA] += Fp::ONE);
    breaks("leaf register", &|t| t.values[row_of(T_ENT1, 0) * width + R_SIDX] += Fp::ONE);
    breaks("key hash kept", &|t| t.values[row_of(T_CM0, 0) * width + R_KH] += Fp::ONE);
    breaks("key's seed", &|t| t.values[row_of(T_PKH1, 0) * width + R_SEED] += Fp::ONE);
    breaks("key's height", &|t| t.values[row_of(T_PKH1, 0) * width + R_KHEIGHT] += Fp::ONE);
    breaks("key's root", &|t| t.values[row_of(T_PKH0, 0) * width + R_PKROOT] += Fp::ONE);
    // A row of the path cannot be another kind of row.
    breaks("a row of another kind", &|t| {
        let at = row_of(T_SP, 1) * width;
        t.values[at + T_SP] = Fp::ZERO;
        t.values[at + T_DONE] = Fp::ONE;
    });
}

#[test]
fn forged_segments_fail() {
    let (segments, _, _, _) = scenario("forge", 10);
    let w = &segments[0];
    // Claiming a larger input amount changes the commitment, so the old
    // path misses the root.
    let mut greedy = w.clone();
    greedy.txs[0].inputs[0].amount += 1;
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&greedy)).is_err());
    // An output whose commitment hides more than the amount counted.
    let mut inflated = w.clone();
    let o = &mut inflated.txs[0].outputs[0].output;
    o.commitment = crate::output::key_commitment(&o.key_hash, o.amount + 1_000_000);
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&inflated)).is_err());
    // A wrong message is one nobody signed: no such entry is in the
    // block's signed set.
    let mut wrong_msg = w.clone();
    wrong_msg.txs[2].message[0] += Fp::ONE;
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&wrong_msg)).is_err());
    // Hand-patched traces: an output amount inflated after the fact.
    let (trace, public) = BlockAir::generate_trace(w);
    let values = public.to_values();
    let width = NUM_COLS;
    let mut bad = trace.clone();
    let r = (0..trace.height()).find(|&r| trace.values[r * width + T_BODY_OUT1] == Fp::ONE).unwrap();
    bad.values[r * width + COL_DATA] += Fp::ONE;
    assert!(check_constraints(&BlockAir, &bad, &values).is_err());
    // The amount hashed into an output's commitment differs from its bits.
    let mut bad = trace.clone();
    let r = (0..trace.height()).find(|&r| trace.values[r * width + T_OCM1] == Fp::ONE).unwrap();
    bad.values[r * width + COL_DATA] += Fp::ONE;
    assert!(check_constraints(&BlockAir, &bad, &values).is_err());
    // Memos: the one listed and the one signed must both be the
    // register's, and the register cannot change within an output.
    for ty in [T_OLIST2, T_BODY_OUT2] {
        let mut bad = trace.clone();
        let r = (0..trace.height()).find(|&r| trace.values[r * width + ty] == Fp::ONE).unwrap();
        bad.values[r * width + COL_DATA + 3] += Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err(), "row type {ty}");
    }
    let mut bad = trace.clone();
    let r = (0..trace.height()).find(|&r| trace.values[r * width + T_BODY_OUT1] == Fp::ONE).unwrap();
    bad.values[r * width + R_MEMO] += Fp::ONE;
    assert!(check_constraints(&BlockAir, &bad, &values).is_err());
    // Leaves: the memo compressed into each leaf must be the register's,
    // and the leaf inserted must be the one computed.
    for ty in [T_ILEAF, T_OLEAF] {
        let mut bad = trace.clone();
        let r = (0..trace.height()).find(|&r| trace.values[r * width + ty] == Fp::ONE).unwrap();
        bad.values[r * width + COL_INPUT + RATE + 2] += Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err(), "leaf row type {ty}");
    }
    let mut bad = trace.clone();
    let r = (0..trace.height()).find(|&r| trace.values[r * width + T_BODY_OUT2] == Fp::ONE).unwrap();
    bad.values[r * width + R_LEAF] += Fp::ONE;
    assert!(check_constraints(&BlockAir, &bad, &values).is_err());
    // Spending with the wrong memo misses the leaf, so the path misses
    // the root.
    let mut wrong_memo = w.clone();
    wrong_memo.txs[0].inputs[0].memo[1] += Fp::ONE;
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&wrong_memo)).is_err());
    // A memo changed after signing breaks the body digest.
    let mut swapped = w.clone();
    swapped.txs[0].outputs[0].output.memo[0] += Fp::ONE;
    assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&swapped)).is_err());
    // And the listed outputs differ with the memo.
    let o = w.txs[0].outputs[0].output;
    let mut other = o.block_output();
    other.memo[0] += Fp::ONE;
    assert_ne!(outputs_state([o.block_output()]), outputs_state([other]));
    // A done row inserted before the last transaction ends.
    let mut bad = trace.clone();
    let r = (0..trace.height()).rev().find(|&r| trace.values[r * width + T_TX_END] == Fp::ONE).unwrap();
    bad.values[r * width + T_TX_END] = Fp::ZERO;
    bad.values[r * width + T_DONE] = Fp::ONE;
    assert!(check_constraints(&BlockAir, &bad, &values).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
fn prove_and_verify_block() {
    let config = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0, zk: false, commit_bits: 0 };
    let (segments, _, _, _) = scenario("prove", 10);
    let (trace, public) = BlockAir::generate_trace(&segments[0]);
    let public = public.to_values();
    let tr = || {
        let mut c = Challenger::new();
        c.observe(Fp::new(0xe5));
        c
    };
    let t = std::time::Instant::now();
    let proof = prove(&config, &BlockAir, &trace, &public, &mut tr());
    println!("block proof ({} rows x {} cols): {:?}", trace.height(), NUM_COLS, t.elapsed());
    let t = std::time::Instant::now();
    assert_eq!(verify(&config, &BlockAir, &public, &proof, &mut tr()), Ok(()));
    println!("verify: {:?}", t.elapsed());
    // The verifier, fuzzed: mutants of the proof's bytes are refused.
    let (iters, seed) = crate::test_util::fuzz_params(200, 0xf022_b1);
    let verifies = |p: &crate::stark::Proof| verify(&config, &BlockAir, &public, p, &mut tr()).is_ok();
    let fuzz = crate::stark::audit::fuzz_proof(&proof, iters, seed, verifies);
    eprintln!("{fuzz:?}");
    assert!(fuzz.accepted.is_empty() && fuzz.panicked.is_empty(), "seed {seed}: {fuzz:?}");
    let mut bad = public.clone();
    bad[PUB_SUM_OUT] += Fp::ONE;
    assert!(verify(&config, &BlockAir, &bad, &proof, &mut tr()).is_err());
}
