//! Transactions: lists of inputs and outputs signed with XMSS.
//!
//! # Model
//!
//! An output pays `amount` to the key with hash `H(pubkey)`; only its
//! commitment goes on chain ([`crate::output`]). To spend one, an input
//! reveals the key and amount and carries a signature, made with that
//! key, over the transaction body; an output under a spend policy is
//! spent by a policy input ([`crate::policy`]). Transactions themselves
//! travel only to whoever proves the block; the block proof attests to
//! them and reveals nothing about them.
//!
//! The body is the canonical encoding of all inputs (key and amount), all
//! policy inputs (policy and amount), all outputs (commitment, amount and
//! memo) and the digests of the name operations, with signatures and
//! positions excluded, laid out in whole sponge blocks per item (see
//! [`body_len`]). Every input signs the same body hash, which is also the
//! transaction id.
//!
//! A transaction may carry name operations (see [`crate::name`]): the
//! inputs sign them and pay their fee, the block lists their public part
//! and the proof's name segment applies them.
//!
//! Fees are implicit: a transaction's balance is the sum of input amounts
//! minus the sum of output amounts. It may be negative; that is how a
//! block reward is paid, and there is no special coinbase type.
//! Per-transaction validation does not constrain the balance; the block
//! rule is that the balances of all its transactions sum to minus the
//! block reward.
//!
//! # Encoding
//!
//! All multi-byte integers are little-endian.
//!
//! ```text
//! transaction := u32 n_in, n_in * input,
//!                u32 n_policy, n_policy * policy input,
//!                u32 n_out, n_out * output,
//!                u32 n_ops, n_ops * op
//! ```
//!
//! with each item as its own module encodes it.
//!
//! # Two forms
//!
//! As with policies, what a node does with a transaction it is sent is
//! done on a view: a [`TransactionRef`] borrows the encoded bytes. Reading
//! one checks the whole encoding once; its body hash, its signatures and
//! its policy inputs are then computed and checked from the bytes, one
//! input at a time on the stack, with no memory allocated.
//!
//! [`UnsignedTransaction`] and [`Transaction`] are the owned forms, for
//! building and signing. They hash the body through the same code.

use core::fmt;

use crate::codec::read_u32;
use crate::hash::{DOM_BODY, Digest, DomainHasher};
use crate::name::NameOp;
use crate::output::{Commitment, Input, Key, OUTPUT_SIZE, Output, OutputList, Sig, amount_fps};
use crate::policy::{PolicyError, PolicyInput, PolicyInputRef};
use crate::poseidon2::{DIGEST, Fp};
use crate::xmss::{KeyExhausted, PublicKey};

// ---------------------------------------------------------------------------
// The body
// ---------------------------------------------------------------------------

/// How many of each item a transaction has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Counts {
    pub inputs: usize,
    pub policy_inputs: usize,
    pub outputs: usize,
    pub ops: usize,
}

/// The number of elements in a body, block aligned so each item is whole
/// sponge blocks:
///
/// ```text
/// [n_in, n_out, n_ops, n_policy, 0, 0, 0, 0]
/// per input:        [root(8)] [pub_seed(4), amount lo30, mid30, hi4, 0]
/// per policy input: [policy(8)] [0, 0, 0, 0, amount lo30, mid30, hi4, 1]
/// per output:       [commitment(8)] [amount lo30, mid30, hi4, 0, 0, 0, 0, 0] [memo slot(8)]
/// per op:           [digest(8)]
/// ```
///
/// A policy input contributes what identifies the output it spends, not
/// its witness, so two spends of the same output through different
/// witnesses are the same transaction.
pub fn body_len(n: &Counts) -> usize {
    DIGEST * (1 + 2 * (n.inputs + n.policy_inputs) + 3 * n.outputs + n.ops)
}

/// Gives the body's sponge blocks to `f`, in order ([`body_len`] has the
/// layout): for each input its key and amount, for each policy input its
/// policy hash and amount, for each output its commitment, amount and
/// memo slot, for each operation its digest.
fn body_blocks(
    n: &Counts,
    inputs: impl Iterator<Item = (PublicKey, u64)>,
    policy_inputs: impl Iterator<Item = (Digest, u64)>,
    outputs: impl Iterator<Item = (Commitment, u64, Digest)>,
    ops: impl Iterator<Item = Digest>,
    mut f: impl FnMut(&[Fp; DIGEST]),
) {
    let mut block = [Fp::ZERO; DIGEST];
    block[0] = Fp::from_u64(n.inputs as u64);
    block[1] = Fp::from_u64(n.outputs as u64);
    block[2] = Fp::from_u64(n.ops as u64);
    block[3] = Fp::from_u64(n.policy_inputs as u64);
    f(&block);
    for (pk, amount) in inputs {
        f(&pk.root);
        let mut block = [Fp::ZERO; DIGEST];
        block[..4].copy_from_slice(&pk.pub_seed);
        block[4..7].copy_from_slice(&amount_fps(amount));
        f(&block);
    }
    for (policy, amount) in policy_inputs {
        f(&policy);
        let mut block = [Fp::ZERO; DIGEST];
        block[4..7].copy_from_slice(&amount_fps(amount));
        block[7] = Fp::ONE;
        f(&block);
    }
    for (commitment, amount, slot) in outputs {
        f(&commitment);
        let mut block = [Fp::ZERO; DIGEST];
        block[..3].copy_from_slice(&amount_fps(amount));
        f(&block);
        f(&slot);
    }
    for digest in ops {
        f(&digest);
    }
}

/// The body hash from the items: `H(DOM_BODY, body)`, the blocks absorbed
/// as they are made.
fn body_hash(
    n: &Counts,
    inputs: impl Iterator<Item = (PublicKey, u64)>,
    policy_inputs: impl Iterator<Item = (Digest, u64)>,
    outputs: impl Iterator<Item = (Commitment, u64, Digest)>,
    ops: impl Iterator<Item = Digest>,
) -> Digest {
    let mut h = DomainHasher::new(DOM_BODY, body_len(n));
    body_blocks(n, inputs, policy_inputs, outputs, ops, |b| h.absorb(b));
    h.finish()
}

/// The body's elements from the items, in one buffer.
fn body_elements(
    n: &Counts,
    inputs: impl Iterator<Item = (PublicKey, u64)>,
    policy_inputs: impl Iterator<Item = (Digest, u64)>,
    outputs: impl Iterator<Item = (Commitment, u64, Digest)>,
    ops: impl Iterator<Item = Digest>,
) -> Vec<Fp> {
    let mut out = Vec::with_capacity(body_len(n));
    body_blocks(n, inputs, policy_inputs, outputs, ops, |b| out.extend_from_slice(b));
    out
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// A transaction in its encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransactionRef<'a> {
    /// The whole transaction: all read once, so every item is whole.
    bytes: &'a [u8],
    counts: Counts,
    inputs: &'a [u8],
    policy_inputs: &'a [u8],
    outputs: OutputsRef<'a>,
    ops: &'a [u8],
}

/// The plain inputs of a [`TransactionRef`], decoded one at a time.
#[derive(Clone)]
pub struct Inputs<'a> {
    rest: &'a [u8],
    left: usize,
}

impl Iterator for Inputs<'_> {
    type Item = Input;

    fn next(&mut self) -> Option<Input> {
        if self.left == 0 {
            return None;
        }
        let (input, rest) = Input::read(self.rest).expect("checked when read");
        self.rest = rest;
        self.left -= 1;
        Some(input)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for Inputs<'_> {}

/// The policy inputs of a [`TransactionRef`], each a view.
#[derive(Clone)]
pub struct PolicyInputs<'a> {
    rest: &'a [u8],
    left: usize,
}

impl<'a> Iterator for PolicyInputs<'a> {
    type Item = PolicyInputRef<'a>;

    fn next(&mut self) -> Option<PolicyInputRef<'a>> {
        if self.left == 0 {
            return None;
        }
        let (input, rest) = PolicyInputRef::read(self.rest).expect("checked when read");
        self.rest = rest;
        self.left -= 1;
        Some(input)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for PolicyInputs<'_> {}

/// The name operations of a [`TransactionRef`], decoded one at a time.
#[derive(Clone)]
pub struct Ops<'a> {
    rest: &'a [u8],
    left: usize,
}

impl Iterator for Ops<'_> {
    type Item = NameOp;

    fn next(&mut self) -> Option<NameOp> {
        if self.left == 0 {
            return None;
        }
        let (op, rest) = NameOp::parse(self.rest).expect("checked when read");
        self.rest = rest;
        self.left -= 1;
        Some(op)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for Ops<'_> {}

/// The outputs of a [`TransactionRef`] in their encoding, [`OUTPUT_SIZE`]
/// bytes each. An output's commitment is not in its encoding: it is
/// computed each time the output is read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OutputsRef<'a>(&'a [u8]);

impl<'a> OutputsRef<'a> {
    pub fn len(&self) -> usize {
        self.0.len() / OUTPUT_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Output `i`. Panics past the end.
    pub fn get(&self, i: usize) -> Output {
        Output::from_bytes(&self.0[i * OUTPUT_SIZE..(i + 1) * OUTPUT_SIZE]).expect("checked when read")
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Output> + 'a {
        self.0.chunks_exact(OUTPUT_SIZE).map(|o| Output::from_bytes(o).expect("checked when read"))
    }
}

impl OutputList for OutputsRef<'_> {
    fn len(&self) -> usize {
        OutputsRef::len(self)
    }

    fn pair(&self, i: usize) -> (Commitment, Digest) {
        let o = self.get(i);
        (o.commitment, o.slot())
    }
}

impl<'a> TransactionRef<'a> {
    /// Reads a transaction that is the whole of `bytes`, checking every
    /// item's encoding.
    pub fn from_bytes(bytes: &'a [u8]) -> Option<TransactionRef<'a>> {
        // The bytes of `n` items read one after another by `read`, and the rest.
        fn run<'b>(
            n: u32,
            start: &'b [u8],
            read: impl Fn(&'b [u8]) -> Option<&'b [u8]>,
        ) -> Option<(&'b [u8], &'b [u8])> {
            let mut rest = start;
            for _ in 0..n {
                rest = read(rest)?;
            }
            Some(start.split_at(start.len() - rest.len()))
        }
        let (n_in, rest) = read_u32(bytes)?;
        let (inputs, rest) = run(n_in, rest, |b| Some(Input::read(b)?.1))?;
        let (n_policy, rest) = read_u32(rest)?;
        let (policy_inputs, rest) = run(n_policy, rest, |b| Some(PolicyInputRef::read(b)?.1))?;
        let (n_out, rest) = read_u32(rest)?;
        let (outputs, rest) = rest.split_at_checked((n_out as usize).checked_mul(OUTPUT_SIZE)?)?;
        if !outputs.chunks_exact(OUTPUT_SIZE).all(Output::is_encoding) {
            return None;
        }
        let (n_ops, rest) = read_u32(rest)?;
        let (ops, rest) = run(n_ops, rest, |b| Some(NameOp::parse(b)?.1))?;
        if !rest.is_empty() {
            return None;
        }
        let counts = Counts {
            inputs: n_in as usize,
            policy_inputs: n_policy as usize,
            outputs: n_out as usize,
            ops: n_ops as usize,
        };
        Some(TransactionRef { bytes, counts, inputs, policy_inputs, outputs: OutputsRef(outputs), ops })
    }

    /// The transaction's encoding.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Serialized size in bytes.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    pub fn inputs(&self) -> Inputs<'a> {
        Inputs { rest: self.inputs, left: self.counts.inputs }
    }

    pub fn policy_inputs(&self) -> PolicyInputs<'a> {
        PolicyInputs { rest: self.policy_inputs, left: self.counts.policy_inputs }
    }

    pub fn outputs(&self) -> OutputsRef<'a> {
        self.outputs
    }

    pub fn ops(&self) -> Ops<'a> {
        Ops { rest: self.ops, left: self.counts.ops }
    }

    /// The body's sponge blocks, in order ([`body_len`] has the layout).
    pub fn body_blocks(&self, f: impl FnMut(&[Fp; DIGEST])) {
        body_blocks(
            &self.counts,
            self.inputs().map(|i| (i.pubkey, i.amount)),
            self.policy_inputs().map(|p| (p.policy(), p.amount())),
            self.outputs.iter().map(|o| (o.commitment, o.amount, o.slot())),
            self.ops().map(|op| op.digest()),
            f,
        )
    }

    /// Hash of the body, excluding signatures.
    pub fn body_hash(&self) -> Digest {
        let mut h = DomainHasher::new(DOM_BODY, body_len(&self.counts));
        self.body_blocks(|b| h.absorb(b));
        h.finish()
    }

    /// Transaction id: the body hash.
    pub fn txid(&self) -> Digest {
        self.body_hash()
    }

    /// Checks that every input carries a valid signature over the body by
    /// its revealed key. Does not check that the spent outputs exist or are
    /// unspent, and does not constrain the balance.
    pub fn verify_signatures(&self) -> bool {
        let msg = self.body_hash();
        self.inputs().all(|i| i.pubkey.verify(&msg, &i.signature))
    }

    /// Checks every policy input's leaf against this transaction, for a
    /// block at `height`; `created` gives the creation height of the
    /// output at a position (`None` if unknown: unspendable).
    pub fn check_policy_inputs(&self, height: u32, created: impl Fn(u64) -> Option<u32>) -> Result<(), PolicyError> {
        if self.counts.policy_inputs == 0 {
            return Ok(());
        }
        let body = self.body_hash();
        for p in self.policy_inputs() {
            let c = created(p.position()).ok_or(PolicyError::Locked)?;
            p.check(&body, &self.outputs, height, c)?;
        }
        Ok(())
    }

    /// Signatures the block proof checks for this transaction: its weight
    /// toward block capacity.
    pub fn weight(&self) -> usize {
        self.counts.inputs + self.policy_inputs().map(|p| p.signatures()).sum::<usize>()
    }

    /// Positions of the outputs being spent, in input order (plain inputs,
    /// then policy inputs).
    pub fn spent_positions(&self) -> impl Iterator<Item = u64> + 'a {
        self.inputs().map(|i| i.position).chain(self.policy_inputs().map(|p| p.position()))
    }

    /// Commitments of the outputs being spent, in input order.
    pub fn spent_commitments(&self) -> impl Iterator<Item = Commitment> + 'a {
        self.inputs().map(|i| i.commitment()).chain(self.policy_inputs().map(|p| p.commitment()))
    }

    /// Sum of input amounts.
    pub fn input_total(&self) -> u128 {
        self.inputs().map(|i| i.amount as u128).sum::<u128>()
            + self.policy_inputs().map(|p| p.amount() as u128).sum::<u128>()
    }

    /// Sum of output amounts.
    pub fn output_total(&self) -> u128 {
        self.outputs.iter().map(|o| o.amount as u128).sum()
    }

    /// Inputs minus outputs. Positive is an implicit fee; negative is a
    /// block reward claim, to be checked at the block level.
    pub fn balance(&self) -> i128 {
        self.input_total() as i128 - self.output_total() as i128
    }

    /// The transaction, owned.
    pub fn to_transaction(&self) -> Transaction {
        Transaction {
            inputs: self.inputs().collect(),
            policy_inputs: self.policy_inputs().map(|p| p.to_input()).collect(),
            outputs: self.outputs.iter().collect(),
            ops: self.ops().collect(),
        }
    }
}

impl fmt::Debug for TransactionRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionRef")
            .field("inputs", &self.inputs().collect::<Vec<_>>())
            .field("policy_inputs", &self.policy_inputs().collect::<Vec<_>>())
            .field("outputs", &self.outputs.iter().collect::<Vec<_>>())
            .field("ops", &self.ops().collect::<Vec<_>>())
            .finish()
    }
}

/// Sets, in the encoded transaction `bytes`, where each input's output is
/// in the UTXO set, in input order (plain inputs, then policy inputs).
/// Positions are not signed, so the signatures and the transaction id are
/// unchanged. Returns whether `bytes` are a transaction with one input per
/// position; if not, nothing is written.
pub fn set_positions(bytes: &mut [u8], positions: &[u64]) -> bool {
    let Some(tx) = TransactionRef::from_bytes(bytes) else { return false };
    let n = tx.counts();
    if positions.len() != n.inputs + n.policy_inputs {
        return false;
    }
    let (plain, policy) = positions.split_at(n.inputs);
    // Each item's size is read before its position is written, so the
    // walk never holds the bytes it changes.
    let mut at = 4;
    for p in plain {
        let (_, rest) = Input::read(&bytes[at..]).expect("checked above");
        let size = bytes.len() - at - rest.len();
        bytes[at + Input::POSITION_AT..][..8].copy_from_slice(&p.to_le_bytes());
        at += size;
    }
    at += 4;
    for p in policy {
        let size = PolicyInputRef::read(&bytes[at..]).expect("checked above").0.size();
        bytes[at + PolicyInputRef::POSITION_AT..][..8].copy_from_slice(&p.to_le_bytes());
        at += size;
    }
    true
}

// ---------------------------------------------------------------------------
// Owned forms: for building
// ---------------------------------------------------------------------------

/// A transaction with signed inputs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    /// Spends of policy outputs (see [`crate::policy`]), after the plain
    /// inputs in the body and in position order.
    pub policy_inputs: Vec<PolicyInput>,
    pub outputs: Vec<Output>,
    /// Name operations, signed by the inputs.
    pub ops: Vec<NameOp>,
}

/// A transaction whose inputs have not been signed yet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedTransaction {
    /// Revealed key and amount of each output being spent.
    pub inputs: Vec<(PublicKey, u64)>,
    /// Policy spends, with or without their witnesses yet.
    pub policy_inputs: Vec<PolicyInput>,
    pub outputs: Vec<Output>,
    pub ops: Vec<NameOp>,
}

/// The body's items from owned lists, as [`body_blocks`] takes them.
macro_rules! owned_body {
    ($inputs:expr, $tx:expr, $with:expr) => {{
        let n = Counts {
            inputs: $inputs.len(),
            policy_inputs: $tx.policy_inputs.len(),
            outputs: $tx.outputs.len(),
            ops: $tx.ops.len(),
        };
        ($with)(
            &n,
            $inputs,
            $tx.policy_inputs.iter().map(|p| (p.policy(), p.amount)),
            $tx.outputs.iter().map(|o| (o.commitment, o.amount, o.slot())),
            $tx.ops.iter().map(NameOp::digest),
        )
    }};
}

impl UnsignedTransaction {
    /// A transaction without name operations.
    pub fn new(inputs: Vec<(PublicKey, u64)>, outputs: Vec<Output>) -> UnsignedTransaction {
        UnsignedTransaction { inputs, policy_inputs: vec![], outputs, ops: vec![] }
    }

    /// A transaction carrying name operations.
    pub fn with_ops(inputs: Vec<(PublicKey, u64)>, outputs: Vec<Output>, ops: Vec<NameOp>) -> UnsignedTransaction {
        UnsignedTransaction { inputs, policy_inputs: vec![], outputs, ops }
    }

    /// Adds policy spends. Their body-mode signatures are over the body
    /// hash this gives once every input is in place.
    pub fn with_policy_inputs(mut self, policy_inputs: Vec<PolicyInput>) -> UnsignedTransaction {
        self.policy_inputs = policy_inputs;
        self
    }

    /// The body hash every input must sign; equals the final transaction id.
    pub fn body_hash(&self) -> Digest {
        owned_body!(self.inputs.iter().copied(), self, body_hash)
    }

    /// The body's elements ([`body_len`] has the layout), for the prover.
    pub fn body_elements(&self) -> Vec<Fp> {
        owned_body!(self.inputs.iter().copied(), self, body_elements)
    }

    /// Signs every input. `signer` is called once per input, in order, with
    /// the input index, its public key and the body hash to sign, and must
    /// return a signature made with the matching secret key. Using a closure
    /// lets one key sign several inputs. Positions start at zero; see
    /// [`Transaction::set_positions`].
    pub fn sign<E>(
        self,
        mut signer: impl FnMut(usize, &PublicKey, &Digest) -> Result<Sig, E>,
    ) -> Result<Transaction, E> {
        let msg = self.body_hash();
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for (i, (pubkey, amount)) in self.inputs.into_iter().enumerate() {
            let signature = signer(i, &pubkey, &msg)?;
            inputs.push(Input { pubkey, amount, position: 0, signature });
        }
        Ok(Transaction { inputs, policy_inputs: self.policy_inputs, outputs: self.outputs, ops: self.ops })
    }

    /// Signs every input with the one key `key`, which must own all of them.
    pub fn sign_with(self, key: &mut Key) -> Result<Transaction, SignError> {
        let pk = key.public_key();
        self.sign(|i, input_pk, msg| {
            if *input_pk != pk {
                return Err(SignError::WrongKey(i));
            }
            key.sign(msg).map_err(SignError::Exhausted)
        })
    }
}

/// Errors from [`UnsignedTransaction::sign_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The key ran out of one-time leaves.
    Exhausted(KeyExhausted),
    /// Input at this index belongs to a different key.
    WrongKey(usize),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Exhausted(e) => write!(f, "{e}"),
            SignError::WrongKey(i) => write!(f, "input {i} is not owned by the signing key"),
        }
    }
}

impl std::error::Error for SignError {}

impl Transaction {
    /// Hash of the body, excluding signatures.
    pub fn body_hash(&self) -> Digest {
        owned_body!(self.inputs.iter().map(|i| (i.pubkey, i.amount)), self, body_hash)
    }

    /// Transaction id: the body hash.
    pub fn txid(&self) -> Digest {
        self.body_hash()
    }

    /// The unsigned form, for example to re-derive the body.
    pub fn unsigned(&self) -> UnsignedTransaction {
        UnsignedTransaction {
            inputs: self.inputs.iter().map(|i| (i.pubkey, i.amount)).collect(),
            policy_inputs: self.policy_inputs.clone(),
            outputs: self.outputs.clone(),
            ops: self.ops.clone(),
        }
    }

    /// The digests of the name operations, in order.
    pub fn op_digests(&self) -> Vec<Digest> {
        self.ops.iter().map(NameOp::digest).collect()
    }

    /// Checks that every input carries a valid signature over the body by
    /// its revealed key. Does not check that the spent outputs exist or are
    /// unspent, and does not constrain the balance.
    pub fn verify_signatures(&self) -> bool {
        let msg = self.body_hash();
        self.inputs.iter().all(|i| i.pubkey.verify(&msg, &i.signature))
    }

    /// Checks every policy input's leaf against this transaction, for a
    /// block at `height`; `created` gives the creation height of the
    /// output at a position (`None` if unknown: unspendable).
    pub fn check_policy_inputs(&self, height: u32, created: impl Fn(u64) -> Option<u32>) -> Result<(), PolicyError> {
        if self.policy_inputs.is_empty() {
            return Ok(());
        }
        let body = self.body_hash();
        for p in &self.policy_inputs {
            let c = created(p.position).ok_or(PolicyError::Locked)?;
            p.check(&body, &self.outputs, height, c)?;
        }
        Ok(())
    }

    /// Signatures the block proof checks for this transaction: its weight
    /// toward block capacity.
    pub fn weight(&self) -> usize {
        self.inputs.len() + self.policy_inputs.iter().map(PolicyInput::signatures).sum::<usize>()
    }

    /// Sets where each input's output is in the UTXO set, in input order
    /// (plain inputs, then policy inputs). Leaves the signatures and the
    /// transaction id unchanged.
    pub fn set_positions(&mut self, positions: &[u64]) {
        assert_eq!(positions.len(), self.inputs.len() + self.policy_inputs.len(), "one position per input");
        let (plain, policy) = positions.split_at(self.inputs.len());
        for (i, p) in self.inputs.iter_mut().zip(plain) {
            i.position = *p;
        }
        for (i, p) in self.policy_inputs.iter_mut().zip(policy) {
            i.position = *p;
        }
    }

    /// Positions of the outputs being spent, in input order (plain inputs,
    /// then policy inputs).
    pub fn spent_positions(&self) -> Vec<u64> {
        self.inputs.iter().map(|i| i.position).chain(self.policy_inputs.iter().map(|p| p.position)).collect()
    }

    /// Commitments of the outputs being spent, in input order.
    pub fn spent_commitments(&self) -> Vec<Commitment> {
        self.inputs
            .iter()
            .map(Input::commitment)
            .chain(self.policy_inputs.iter().map(PolicyInput::commitment))
            .collect()
    }

    /// Sum of input amounts.
    pub fn input_total(&self) -> u128 {
        self.inputs.iter().map(|i| i.amount as u128).sum::<u128>()
            + self.policy_inputs.iter().map(|p| p.amount as u128).sum::<u128>()
    }

    /// Sum of output amounts.
    pub fn output_total(&self) -> u128 {
        self.outputs.iter().map(|o| o.amount as u128).sum()
    }

    /// Inputs minus outputs. Positive is an implicit fee; negative is a
    /// block reward claim, to be checked at the block level.
    pub fn balance(&self) -> i128 {
        self.input_total() as i128 - self.output_total() as i128
    }

    /// Serialized size in bytes.
    pub fn size(&self) -> usize {
        16 + self.inputs.iter().map(Input::size).sum::<usize>()
            + self.policy_inputs.iter().map(PolicyInput::size).sum::<usize>()
            + self.outputs.len() * OUTPUT_SIZE
            + self.ops.iter().map(NameOp::size).sum::<usize>()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            out.extend_from_slice(&i.to_bytes());
        }
        out.extend_from_slice(&(self.policy_inputs.len() as u32).to_le_bytes());
        for p in &self.policy_inputs {
            out.extend_from_slice(&p.to_bytes());
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.to_bytes());
        }
        out.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            out.extend_from_slice(&op.to_bytes());
        }
        out
    }

    /// Parses a transaction; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Transaction> {
        Some(TransactionRef::from_bytes(bytes)?.to_transaction())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_domain;
    use crate::name::{BlockNameOp, Record};
    use crate::output::{INPUT_SIZE, commitment, memo5, pubkey_hash};
    use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer, rebind_message};

    fn key(tag: u8) -> Key {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        Key::generate(&seed)
    }

    fn d(n: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(n + i as u32))
    }

    #[test]
    fn spend_two_keys_with_fee() {
        let mut ka = key(1);
        let mut kb = key(2);
        let kc = key(3);
        let utxo_a = Output::new(&ka.public_key(), 50);
        let utxo_b = Output::new(&kb.public_key(), 30);

        let unsigned = UnsignedTransaction::new(
            vec![(ka.public_key(), 50), (kb.public_key(), 30)],
            vec![Output::new(&kc.public_key(), 70), Output::new(&ka.public_key(), 5)],
        );
        let body = unsigned.body_hash();
        let tx = unsigned.sign(|i, _pk, msg| if i == 0 { ka.sign(msg) } else { kb.sign(msg) }).unwrap();

        assert!(tx.verify_signatures());
        assert_eq!(tx.txid(), body);
        assert_eq!(tx.spent_commitments(), vec![utxo_a.commitment, utxo_b.commitment]);
        assert_eq!(tx.input_total(), 80);
        assert_eq!(tx.output_total(), 75);
        assert_eq!(tx.balance(), 5);
        assert_eq!(ka.next_index(), 1);
        assert_eq!(kb.next_index(), 1);
    }

    #[test]
    fn one_key_spends_several_inputs() {
        let mut k = key(4);
        let pk = k.public_key();
        let unsigned = UnsignedTransaction::new(vec![(pk, 10), (pk, 20), (pk, 30)], vec![Output::new(&pk, 60)]);
        let tx = unsigned.sign_with(&mut k).unwrap();
        assert!(tx.verify_signatures());
        assert_eq!(tx.balance(), 0);
        assert_eq!(k.next_index(), 3);
        let leaves: Vec<u64> = tx.inputs.iter().map(|i| i.signature.index).collect();
        assert_eq!(leaves, vec![0, 1, 2]);

        // sign_with refuses inputs owned by another key.
        let other = key(5).public_key();
        let unsigned = UnsignedTransaction::new(vec![(pk, 1), (other, 1)], vec![]);
        assert_eq!(unsigned.sign_with(&mut k).unwrap_err(), SignError::WrongKey(1));
        assert!(SignError::WrongKey(1).to_string().contains("input 1"));
        // A key with no leaf left signs nothing.
        let mut spent = Key::generate_with_height(&[6; 32], 1);
        spent.set_next_index(2);
        let unsigned = UnsignedTransaction::new(vec![(spent.public_key(), 1)], vec![]);
        let err = unsigned.sign_with(&mut spent).unwrap_err();
        assert_eq!(err, SignError::Exhausted(KeyExhausted));
        assert!(err.to_string().contains("exhausted"));
    }

    #[test]
    fn reward_transaction_has_negative_balance() {
        let miner = key(6).public_key();
        let tx = UnsignedTransaction::new(vec![], vec![Output::new(&miner, 100)])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();
        assert!(tx.inputs.is_empty());
        assert!(tx.verify_signatures());
        assert_eq!(tx.balance(), -100);
        assert_ne!(tx.txid(), [Fp::ZERO; DIGEST]);
    }

    #[test]
    fn tampering_breaks_signatures() {
        let mut ka = key(7);
        let kb = key(8).public_key();
        let unsigned = UnsignedTransaction::new(
            vec![(ka.public_key(), 40)],
            vec![Output::new(&kb, 25), Output::new(&ka.public_key(), 10)],
        );
        let tx = unsigned.sign_with(&mut ka).unwrap();
        assert!(tx.verify_signatures());

        let mut t = tx.clone();
        t.outputs[0].amount = 30;
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.outputs[0].commitment = Output::new(&ka.public_key(), 25).commitment;
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.outputs.swap(0, 1);
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.outputs.pop();
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.inputs[0].amount = 41;
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.inputs[0].pubkey = kb;
        assert!(!t.verify_signatures());
        // A valid signature by the right key over a different body.
        let other = UnsignedTransaction::new(vec![(ka.public_key(), 40)], vec![]).sign_with(&mut ka).unwrap();
        let mut t = tx.clone();
        t.inputs[0].signature = other.inputs[0].signature.clone();
        assert!(!t.verify_signatures());
        // Changing the signature does not change the id.
        assert_eq!(t.txid(), tx.txid());
        assert_eq!(tx.unsigned().body_hash(), tx.txid());
        // The view says the same of each that has an encoding.
        let bytes = t.to_bytes();
        let view = TransactionRef::from_bytes(&bytes).unwrap();
        assert!(!view.verify_signatures());
        assert_eq!(view.txid(), tx.txid());
    }

    #[test]
    fn name_operations_are_signed_and_carried() {
        let mut ka = key(11);
        let mut owner = key(12);
        let commit = NameOp::Commit { commit: d(1), memo: memo5(d(2)) };
        let reveal = NameOp::Reveal { record: Record::new(b"alice", d(3), d(4), d(5)).unwrap(), salt: d(6), commit: 1 };
        let update = NameOp::update(Record::new(b"bob", d(7), d(8), d(9)).unwrap(), &mut owner).unwrap();
        let ops = vec![commit.clone(), reveal.clone(), update.clone()];
        let unsigned = UnsignedTransaction::with_ops(
            vec![(ka.public_key(), 40)],
            vec![Output::new(&ka.public_key(), 30)],
            ops.clone(),
        );
        let tx = unsigned.sign_with(&mut ka).unwrap();
        assert!(tx.verify_signatures());
        assert_eq!(tx.ops, ops);
        assert_eq!(tx.balance(), 10);
        assert_eq!(tx.op_digests(), ops.iter().map(|o| o.digest()).collect::<Vec<_>>());

        // The same inputs and outputs without the operations sign differently.
        let plain = UnsignedTransaction::new(vec![(ka.public_key(), 40)], vec![Output::new(&ka.public_key(), 30)]);
        assert_ne!(plain.body_hash(), tx.txid());
        // Changing an operation's public part breaks the signatures; the witness is not signed.
        let mut t = tx.clone();
        t.ops.swap(0, 1);
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.ops.pop();
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.ops[0] = NameOp::Commit { commit: d(2), memo: memo5(d(2)) };
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.ops[1] = NameOp::Reveal { record: Record::new(b"alice", d(3), d(4), d(5)).unwrap(), salt: d(60), commit: 2 };
        assert!(t.verify_signatures());
        assert_eq!(t.txid(), tx.txid());
        assert_eq!(tx.ops[2].block_op(), BlockNameOp::Update(Record::new(b"bob", d(7), d(8), d(9)).unwrap()));

        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), tx.size());
        assert_eq!(bytes.len(), 16 + INPUT_SIZE + OUTPUT_SIZE + ops.iter().map(NameOp::size).sum::<usize>());
        assert_eq!(Transaction::from_bytes(&bytes), Some(tx.clone()));
        assert!(Transaction::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert_eq!(tx.unsigned().body_hash(), tx.txid());
        // The view reads the operations where they lie.
        let view = TransactionRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.ops().collect::<Vec<_>>(), ops);
        assert_eq!(view.ops().len(), 3);
        assert!(view.verify_signatures());
        assert_eq!(view.txid(), tx.txid());
    }

    #[test]
    fn serialization_roundtrip() {
        let mut ka = key(9);
        let kb = key(10).public_key();
        let mut tx = UnsignedTransaction::new(
            vec![(ka.public_key(), 7), (ka.public_key(), 8)],
            vec![Output::new(&kb, 9), Output::new(&kb, u64::MAX)],
        )
        .sign_with(&mut ka)
        .unwrap();
        // Positions are carried but not signed.
        let id = tx.txid();
        tx.set_positions(&[1 << 39, 12345]);
        assert_eq!((tx.txid(), tx.spent_positions()), (id, vec![1 << 39, 12345]));
        assert!(tx.verify_signatures());

        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), tx.size());
        assert_eq!(bytes.len(), 16 + 2 * INPUT_SIZE + 2 * OUTPUT_SIZE);
        let back = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(back, tx);
        assert!(back.verify_signatures());
        assert_eq!(back.txid(), tx.txid());

        assert!(Transaction::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Transaction::from_bytes(&extra).is_none());
        let mut huge = bytes.clone();
        huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Transaction::from_bytes(&huge).is_none());
        assert!(Transaction::from_bytes(&[]).is_none());

        let empty = Transaction { inputs: vec![], policy_inputs: vec![], outputs: vec![], ops: vec![] };
        assert_eq!(Transaction::from_bytes(&empty.to_bytes()), Some(empty));
    }

    // -----------------------------------------------------------------------
    // The view
    // -----------------------------------------------------------------------

    /// A transaction of every kind of item: two plain inputs (keys of two
    /// heights), a policy input spending a 2-of-2 through its rebindable
    /// leaf or its body-mode one, three outputs (the last two the covered
    /// run) and the three kinds of name operation.
    fn full(rebindable: bool) -> Transaction {
        let mut ka = key(21);
        let mut tall = Key::generate_with_height(&[22; 32], 6);
        let (kb, kc) = (key(23), key(24));
        let hashes = vec![pubkey_hash(&kb.public_key()), pubkey_hash(&kc.public_key())];
        let channel = d(500);
        let policy = Policy::new(vec![
            Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: hashes.clone() }, Cond::After(50)]),
            Leaf::new(vec![Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: hashes }, Cond::State(2)]),
        ]);
        let outputs = vec![
            Output::with_memo(&d(1), 10, memo5(d(2))),
            Output::with_memo(&d(11), 500, memo5(d(12))),
            Output::with_memo(&d(13), 490, memo5(d(14))),
        ];
        let mut spend = policy.spend(rebindable as usize, 1000, 0);
        spend.state = 3;
        spend.covered = (1, 2);
        let mut owner = key(25);
        let ops = vec![
            NameOp::Commit { commit: d(30), memo: memo5(d(31)) },
            NameOp::Reveal { record: Record::new(b"alice", d(32), d(33), d(34)).unwrap(), salt: d(35), commit: 77 },
            NameOp::update(Record::new(b"bob", d(36), d(37), d(38)).unwrap(), &mut owner).unwrap(),
        ];
        let unsigned =
            UnsignedTransaction::with_ops(vec![(ka.public_key(), 40), (tall.public_key(), 5)], outputs.clone(), ops)
                .with_policy_inputs(vec![spend.clone()]);
        let body = unsigned.body_hash();
        // The policy input's signatures: over the body, or over the
        // rebindable message with the state as each key's leaf.
        let (msg, leaf) = if rebindable {
            (rebind_message(&channel, 3, &spend.covered_outputs(&outputs).unwrap()), 3)
        } else {
            (body, 0)
        };
        let signer = |key: u8, mut k: Key| {
            k.set_next_index(leaf);
            Signer { key, pubkey: k.public_key(), signature: k.sign(&msg).unwrap() }
        };
        let mut tx = unsigned.sign(|i, _, m| if i == 0 { ka.sign(m) } else { tall.sign(m) }).unwrap();
        tx.policy_inputs[0].witness[0] = CondWitness::Signatures(vec![signer(0, kb), signer(1, kc)]);
        tx.set_positions(&[5, 6, 7]);
        tx
    }

    /// The view of a transaction's bytes gives what the owned form gives:
    /// items, counts, body, id, signatures, policy check, weight,
    /// positions, commitments, totals, size.
    #[test]
    fn the_view_agrees_with_the_owned_form() {
        for rebindable in [false, true] {
            let tx = full(rebindable);
            let bytes = tx.to_bytes();
            let view = TransactionRef::from_bytes(&bytes).unwrap();
            assert_eq!(view.as_bytes(), &bytes[..]);
            assert_eq!((view.size(), tx.size()), (bytes.len(), bytes.len()));
            assert_eq!(view.to_transaction(), tx);
            assert_eq!(view.counts(), Counts { inputs: 2, policy_inputs: 1, outputs: 3, ops: 3 });
            assert_eq!(view.inputs().collect::<Vec<_>>(), tx.inputs);
            assert_eq!((view.inputs().len(), view.policy_inputs().len()), (2, 1));
            assert_eq!(view.policy_inputs().map(|p| p.to_input()).collect::<Vec<_>>(), tx.policy_inputs);
            assert_eq!(view.outputs().iter().collect::<Vec<_>>(), tx.outputs);
            assert_eq!((view.outputs().len(), view.outputs().is_empty()), (3, false));
            for (i, o) in tx.outputs.iter().enumerate() {
                assert_eq!(view.outputs().get(i), *o);
                assert_eq!(OutputList::pair(&view.outputs(), i), (o.commitment, o.slot()));
            }
            assert_eq!(OutputList::len(&view.outputs()), 3);
            assert_eq!(view.ops().collect::<Vec<_>>(), tx.ops);
            assert_eq!(view.body_hash(), tx.body_hash());
            assert_eq!((view.txid(), tx.txid()), (tx.unsigned().body_hash(), tx.body_hash()));
            assert!(view.verify_signatures() && tx.verify_signatures());
            assert_eq!(view.weight(), 2 + 2);
            assert_eq!(view.weight(), tx.weight());
            assert_eq!(view.spent_positions().collect::<Vec<_>>(), tx.spent_positions());
            assert_eq!(tx.spent_positions(), vec![5, 6, 7]);
            assert_eq!(view.spent_commitments().collect::<Vec<_>>(), tx.spent_commitments());
            assert_eq!(tx.spent_commitments()[0], commitment(&tx.inputs[0].pubkey, 40));
            assert_eq!((view.input_total(), view.output_total(), view.balance()), (1045, 1000, 45));
            assert_eq!((tx.input_total(), tx.output_total(), tx.balance()), (1045, 1000, 45));
            assert!(format!("{view:?}").contains("policy_inputs"));
            // The policy input: the body-mode leaf waits for height 50, the
            // rebindable one for nothing; an output of unknown creation
            // height is unspendable.
            for height in [0, 49, 50, 1000] {
                let got = view.check_policy_inputs(height, |p| (p == 7).then_some(0));
                assert_eq!(got, tx.check_policy_inputs(height, |p| (p == 7).then_some(0)), "height {height}");
                let want = if rebindable || height >= 50 { Ok(()) } else { Err(PolicyError::Locked) };
                assert_eq!(got, want, "height {height}");
            }
            assert_eq!(view.check_policy_inputs(1000, |_| None), Err(PolicyError::Locked));
            assert_eq!(tx.check_policy_inputs(1000, |_| None), Err(PolicyError::Locked));
        }
        // No policy inputs: nothing to check, whatever is known of positions.
        let plain = UnsignedTransaction::new(vec![], vec![Output::new(&key(1).public_key(), 5)]);
        let plain = plain.sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        let bytes = plain.to_bytes();
        let view = TransactionRef::from_bytes(&bytes).unwrap();
        assert_eq!(view.check_policy_inputs(0, |_| None), Ok(()));
        assert_eq!(plain.check_policy_inputs(0, |_| None), Ok(()));
        assert_eq!((view.weight(), view.balance()), (0, -5));
    }

    /// The body is laid out as `body_len` says, and its hash is
    /// `hash_domain` of it: by the owned form's elements and by the view's
    /// blocks alike.
    #[test]
    fn the_body_is_laid_out_in_whole_blocks() {
        let tx = full(true);
        let bytes = tx.to_bytes();
        let view = TransactionRef::from_bytes(&bytes).unwrap();
        let body = tx.unsigned().body_elements();
        assert_eq!(body.len(), body_len(&view.counts()));
        assert_eq!(body.len(), DIGEST * (1 + 2 * 3 + 3 * 3 + 3));
        assert_eq!(hash_domain(DOM_BODY, &body), tx.body_hash());
        let mut blocks = Vec::new();
        view.body_blocks(|b| blocks.extend_from_slice(b));
        assert_eq!(blocks, body);
        let v = |x: Fp| x.to_canonical();
        // The header: inputs, outputs, operations, policy inputs.
        assert_eq!(body[..8].iter().map(|x| v(*x)).collect::<Vec<_>>(), [2, 3, 3, 1, 0, 0, 0, 0]);
        // The first input: its key's root, then seed, amount 40 and a zero.
        let pk = tx.inputs[0].pubkey;
        assert_eq!(&body[8..16], &pk.root);
        assert_eq!(&body[16..20], &pk.pub_seed);
        assert_eq!(body[20..24].iter().map(|x| v(*x)).collect::<Vec<_>>(), [40, 0, 0, 0]);
        // The policy input, after the two plain ones: its policy, then
        // four zeros, amount 1000 and a one.
        let p = &tx.policy_inputs[0];
        assert_eq!(&body[40..48], &p.policy());
        assert_eq!(body[48..56].iter().map(|x| v(*x)).collect::<Vec<_>>(), [0, 0, 0, 0, 1000, 0, 0, 1]);
        // The first output: commitment, amount, memo slot.
        let o = &tx.outputs[0];
        assert_eq!(&body[56..64], &o.commitment);
        assert_eq!(body[64..72].iter().map(|x| v(*x)).collect::<Vec<_>>(), [10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&body[72..80], &o.slot());
        // The last block: the last operation's digest.
        assert_eq!(&body[body.len() - 8..], &tx.ops[2].digest());
        // An amount of more than 30 bits spills into the next limb.
        let big = UnsignedTransaction::new(vec![(pk, (1 << 30) + 7)], vec![]);
        assert_eq!(big.body_elements()[20..24].iter().map(|x| v(*x)).collect::<Vec<_>>(), [7, 1, 0, 0]);
        // Nothing at all still has a body.
        let none = UnsignedTransaction::new(vec![], vec![]);
        assert_eq!(none.body_elements(), vec![Fp::ZERO; 8]);
        assert_eq!(none.body_hash(), hash_domain(DOM_BODY, &[Fp::ZERO; 8]));
    }

    /// Positions are rewritten in the bytes, in input order, without the
    /// id or any signature changing; bytes that are no transaction, or
    /// another number of positions, are left alone.
    #[test]
    fn positions_are_set_in_place() {
        for rebindable in [false, true] {
            let tx = full(rebindable);
            let mut bytes = tx.to_bytes();
            let before = bytes.clone();
            assert!(set_positions(&mut bytes, &[1 << 40, 2, (1 << 41) - 1]));
            let view = TransactionRef::from_bytes(&bytes).unwrap();
            assert_eq!(view.spent_positions().collect::<Vec<_>>(), vec![1 << 40, 2, (1 << 41) - 1]);
            assert_eq!(view.txid(), tx.txid());
            assert!(view.verify_signatures());
            assert_eq!(view.check_policy_inputs(1000, |p| (p == (1 << 41) - 1).then_some(0)), Ok(()));
            let mut moved = tx.clone();
            moved.set_positions(&[1 << 40, 2, (1 << 41) - 1]);
            assert_eq!(moved.to_bytes(), bytes);
            // Only the positions changed: setting them back gives the bytes back.
            assert_ne!(bytes, before);
            assert!(set_positions(&mut bytes, &[5, 6, 7]));
            assert_eq!(bytes, before);
            for wrong in [&[][..], &[1, 2], &[1, 2, 3, 4]] {
                let mut b = before.clone();
                assert!(!set_positions(&mut b, wrong));
                assert_eq!(b, before);
            }
            let mut cut = before[..before.len() - 1].to_vec();
            assert!(!set_positions(&mut cut, &[1, 2, 3]));
            assert_eq!(cut, &before[..before.len() - 1]);
        }
    }

    /// Bytes that are not a transaction are refused: an item of any kind
    /// cut short or malformed, a count of more items than there are, bytes
    /// after the last.
    #[test]
    fn malformed_transactions_are_refused() {
        let tx = full(true);
        let bytes = tx.to_bytes();
        assert!(TransactionRef::from_bytes(&bytes).is_some());
        for cut in [0, 3, 4, 100, bytes.len() / 2, bytes.len() - 1] {
            assert!(TransactionRef::from_bytes(&bytes[..cut]).is_none(), "cut at {cut}");
        }
        assert!(TransactionRef::from_bytes(&[&bytes[..], &[0]].concat()).is_none());
        // Where each section's count is.
        let inputs: usize = tx.inputs.iter().map(Input::size).sum();
        let policy: usize = tx.policy_inputs.iter().map(PolicyInput::size).sum();
        let (n_in, n_policy) = (0, 4 + inputs);
        let n_out = n_policy + 4 + policy;
        let n_ops = n_out + 4 + 3 * OUTPUT_SIZE;
        for (name, at, n) in [("inputs", n_in, 2u32), ("policy inputs", n_policy, 1), ("outputs", n_out, 3), ("operations", n_ops, 3)] {
            assert_eq!(bytes[at..at + 4], n.to_le_bytes(), "{name}");
            for other in [n - 1, n + 1, u32::MAX] {
                let mut b = bytes.clone();
                b[at..at + 4].copy_from_slice(&other.to_le_bytes());
                assert!(TransactionRef::from_bytes(&b).is_none(), "{other} {name}");
            }
        }
        // An element that is none, in each kind of item: the first input's
        // key, the policy input's first sibling, an output's key hash and
        // its memo, an operation's commit.
        let p = crate::poseidon2::P.to_le_bytes();
        for (name, at) in [
            ("input", 4),
            ("policy input", n_policy + 4 + 17),
            ("output key hash", n_out + 4),
            ("output memo", n_out + 4 + OUTPUT_SIZE - 4),
            ("operation", n_ops + 4 + 1),
        ] {
            let mut b = bytes.clone();
            b[at..at + 4].copy_from_slice(&p);
            assert!(TransactionRef::from_bytes(&b).is_none(), "{name}");
            assert!(Transaction::from_bytes(&b).is_none(), "{name}");
        }
        // An unknown kind of operation.
        let mut b = bytes.clone();
        b[n_ops + 4] = 9;
        assert!(TransactionRef::from_bytes(&b).is_none());
        // A transaction of nothing is one.
        let empty = [0u8; 16];
        let view = TransactionRef::from_bytes(&empty).unwrap();
        assert_eq!(view.counts(), Counts { inputs: 0, policy_inputs: 0, outputs: 0, ops: 0 });
        assert!(view.verify_signatures() && view.outputs().is_empty());
        assert_eq!((view.balance(), view.weight()), (0, 0));
    }

    /// The transaction decoders, fuzzed: no input makes reading, hashing
    /// or checking panic, a view's bytes are the bytes read, and the owned
    /// form it gives encodes to them again.
    #[test]
    fn fuzz_transaction_decoders() {
        let mut ka = key(9);
        let kb = key(10).public_key();
        let mut tx = UnsignedTransaction::new(
            vec![(ka.public_key(), 7), (ka.public_key(), 8)],
            vec![Output::new(&kb, 9), Output::new(&kb, u64::MAX)],
        )
        .sign_with(&mut ka)
        .unwrap();
        tx.set_positions(&[1 << 39, 12345]);
        let samples = [tx.to_bytes(), full(false).to_bytes(), full(true).to_bytes()];
        crate::test_util::fuzz_decoder("TransactionRef::from_bytes", &samples, 3_000, |b| {
            TransactionRef::from_bytes(b).map(|view| {
                assert_eq!(view.to_transaction().to_bytes(), view.as_bytes());
                assert_eq!(view.body_hash(), view.to_transaction().body_hash());
                let _ = (view.verify_signatures(), view.weight(), view.balance());
                let _ = view.check_policy_inputs(100, |p| Some(p as u32 & 0xff));
                let _ = (view.spent_positions().count(), view.spent_commitments().count());
                let mut copy = view.as_bytes().to_vec();
                let n = view.counts();
                assert!(set_positions(&mut copy, &vec![3; n.inputs + n.policy_inputs]));
                Some(view.as_bytes().to_vec())
            })
        });
        crate::test_util::fuzz_decoder("Transaction::from_bytes", &samples, 3_000, |b| {
            Transaction::from_bytes(b).map(|t| Some(t.to_bytes()))
        });
    }
}
