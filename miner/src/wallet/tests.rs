//! Tests of the wallet, against a chain that is a list of outputs.

use super::*;
use crate::store::testing::{Lost, MemBackend};

const NOW: u64 = 1_800_000_000;
const COIN: u64 = crate::chain::params::COIN;

/// The chain's outputs: each one's commitment, memo and amount, and
/// whether it is unspent, at the position of its place in the list.
#[derive(Default)]
struct Outputs(Vec<(Commitment, Memo, u64, bool)>);

impl Unspent for Outputs {
    fn holds(&self, position: u64, commitment: &Commitment) -> io::Result<bool> {
        Ok(self.0.get(position as usize).is_some_and(|(c, _, _, live)| *live && c == commitment))
    }

    fn each(&self, f: &mut dyn FnMut(u64, &Commitment, &Memo, u64)) -> io::Result<()> {
        for (position, (c, memo, amount, live)) in self.0.iter().enumerate() {
            if *live {
                f(position as u64, c, memo, *amount);
            }
        }
        Ok(())
    }
}

impl Outputs {
    /// A block makes `outputs`: they are there from now on, and the
    /// wallets are told where.
    fn make(&mut self, outputs: &[Output], wallets: &mut [&mut Wallet<MemBackend>]) {
        let first = self.0.len() as u64;
        self.0.extend(outputs.iter().map(|o| (o.commitment, o.memo, o.amount, true)));
        let made: Vec<Commitment> = outputs.iter().map(|o| o.commitment).collect();
        for wallet in wallets {
            wallet.locate(first, &made, 1, &[0; 32]).unwrap();
        }
    }

    /// A block takes `tx`: what it spends is spent, and what it makes is
    /// made.
    fn take(&mut self, tx: &Transaction, wallets: &mut [&mut Wallet<MemBackend>]) {
        for input in &tx.inputs {
            assert!(self.holds(input.position, &input.commitment()).unwrap(), "spends what is not there");
            self.0[input.position as usize].3 = false;
        }
        self.make(&tx.outputs, wallets);
    }
}

fn new() -> Wallet<MemBackend> {
    Wallet::open(MemBackend::new()).unwrap().0
}

/// A wallet with one confirmed output of `amount`.
fn funded(chain: &mut Outputs, amount: u64) -> Wallet<MemBackend> {
    let mut wallet = new();
    let out = wallet.receive(amount, NOW).unwrap();
    chain.make(&[out], &mut [&mut wallet]);
    wallet
}

/// The wallet as it is found when its file is opened again.
fn reopened(wallet: &Wallet<MemBackend>, password: &str) -> Result<Wallet<MemBackend>> {
    let image = wallet.records.backend().image(Lost::None);
    Wallet::open_with(MemBackend::from_image(image), &mut |_| Ok(password.to_string())).map(|(w, _)| w)
}

/// A wallet is made with a phrase, which is all it is made of: the same
/// phrase is the same keys. Its secret is locked under a password if
/// one is given, and opened only with it.
#[test]
fn a_wallet_is_its_phrase() {
    let (wallet, phrase) = Wallet::open_with(MemBackend::new(), &mut |ask| {
        assert_eq!(ask, Ask::New);
        Ok("correct horse".into())
    })
    .unwrap();
    let phrase = phrase.expect("a new wallet says its phrase");
    assert_eq!(phrase.split(' ').count(), 12);
    assert!(wallet.locked());
    assert_eq!(wallet.phrase("correct horse").unwrap(), phrase);
    assert!(matches!(wallet.phrase("wrong"), Err(WalletError::WrongPassword)));
    // Opened again: asked to unlock, and with nothing new to say.
    assert!(matches!(reopened(&wallet, "wrong"), Err(WalletError::WrongPassword)));
    let image = wallet.records.backend().image(Lost::None);
    let (again, said) = Wallet::open_with(MemBackend::from_image(image), &mut |ask| {
        assert_eq!(ask, Ask::Unlock);
        Ok("correct horse".into())
    })
    .unwrap();
    assert!(said.is_none() && again.master == wallet.master);
    // Restored from the phrase elsewhere: the same keys and memos.
    let nonce = [Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];
    let restored = Wallet::restore(MemBackend::new(), &phrase, "", "").unwrap();
    assert!(restored.scan_pending() && !restored.locked());
    assert_eq!(restored.key(&nonce).public_key(), wallet.key(&nonce).public_key());
    assert_eq!(restored.memo(&nonce), wallet.memo(&nonce));
    // Another passphrase is another wallet; and a wallet is not restored
    // over one.
    let other = Wallet::restore(MemBackend::new(), &phrase, "another", "").unwrap();
    assert_ne!(other.key(&nonce).public_key(), wallet.key(&nonce).public_key());
    let image = wallet.records.backend().image(Lost::None);
    assert!(matches!(Wallet::restore(MemBackend::from_image(image), &phrase, "", ""), Err(WalletError::Exists)));
    assert!(matches!(
        Wallet::restore(MemBackend::new(), "abandon ability", "", ""),
        Err(WalletError::Phrase(bip39::PhraseError::WordCount(2)))
    ));
    // The password is changed, and taken away.
    let mut wallet = wallet;
    assert!(matches!(wallet.set_password("wrong", "new"), Err(WalletError::WrongPassword)));
    wallet.set_password("correct horse", "").unwrap();
    assert!(!wallet.locked() && reopened(&wallet, "").unwrap().phrase("").unwrap() == phrase);
}

/// The outputs of the reference's wallet are this wallet's: two that a
/// wallet of the reference, restored from this phrase, made for itself
/// (their nonces drawn then), each with its memo, amount and commitment.
/// This wallet, of the same phrase, opens their memos and makes the
/// same outputs of them.
#[test]
fn the_references_outputs_are_this_wallets() {
    let entropy: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let phrase = bip39::phrase(&entropy);
    assert_eq!(phrase, "arctic live gadget display excess mandate sniff autumn people disorder affair horn");
    let wallet = Wallet::restore(MemBackend::new(), &phrase, "", "").unwrap();
    let theirs: [(u64, [u32; 5], &str); 2] = [
        (
            50_000_000_000,
            [287503621, 123657142, 1962352237, 1317785694, 1894467307],
            "63211b21fc324b5197629714d6347b026fa79c159f9b3d0d4f82ad200cb47f0c",
        ),
        (
            7,
            [590386712, 1408282531, 381531641, 1099818495, 1658729605],
            "b0072b0ba209906a9989eb3ec53f9075064ffc3284ad36176083705f8b902d64",
        ),
    ];
    for (amount, memo, commitment) in theirs {
        let memo: Memo = memo.map(Fp::new);
        let nonce = wallet.open_memo(&memo).expect("the memo is this wallet's");
        assert_eq!(nonce[..], memo[..NONCE]);
        let out = wallet.output_of(&nonce, amount);
        assert_eq!((out.memo, hex(&digest_to_bytes(&out.commitment)).as_str()), (memo, commitment));
        // The commitment is of the key of that nonce.
        assert_eq!(out.commitment, key_commitment(&pubkey_hash(&wallet.key(&nonce).public_key()), amount));
        // And it is nobody else's: not with the tag one off, not another
        // wallet's.
        let mut other = memo;
        other[NONCE] += Fp::ONE;
        assert_eq!(wallet.open_memo(&other), None);
        assert_eq!(new().open_memo(&memo), None);
    }
}

/// A payment: the sender's slate, the recipient's output added to it,
/// and the sender's signature; what each wallet then has.
#[test]
fn a_payment_is_agreed_by_slate() {
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let mut bob = new();
    assert_eq!(alice.balance(&chain).unwrap(), Balance { confirmed: 100 * COIN as u128, ..Default::default() });

    let slate = alice.send(30 * COIN, None, &chain, NOW).unwrap();
    let fee = Wallet::<MemBackend>::min_fee(1);
    assert_eq!((slate.stage, slate.amount, slate.fee, slate.inputs.len(), slate.change), (1, 30 * COIN, fee, 1, 1));
    // Its input is reserved, and its change expected.
    let b = alice.balance(&chain).unwrap();
    assert_eq!((b.confirmed, b.reserved, b.pending), (0, 100 * COIN as u128, (70 * COIN - fee) as u128));
    assert_eq!(alice.pending_slates(), [(slate.id, 30 * COIN)]);
    assert!(matches!(alice.send(COIN, None, &chain, NOW), Err(WalletError::Insufficient { .. })));

    // As text, to the recipient, and back.
    let text = slate.to_text();
    assert!(text.starts_with("-----BEGIN TAB SLATE-----\n") && Slate::text_ends(&text));
    let mut answered = Slate::from_text(&format!("a line before\n{text}and one after")).unwrap();
    assert_eq!(answered, slate);
    assert!(matches!(alice.finalize(&answered, NOW), Err(WalletError::BadSlate("not a stage-2 slate"))));
    bob.receive_slate(&mut answered, NOW).unwrap();
    assert!(matches!(bob.receive_slate(&mut answered, NOW), Err(WalletError::BadSlate(_))));
    assert_eq!((answered.stage, answered.outputs.len()), (2, 2));
    assert_eq!(bob.balance(&chain).unwrap().unverified, 30 * COIN as u128);

    // What the recipient may not have changed.
    let refused = |alice: &mut Wallet<MemBackend>, change: &dyn Fn(&mut Slate)| {
        let mut slate = answered.clone();
        change(&mut slate);
        assert!(matches!(alice.finalize(&slate, NOW), Err(WalletError::BadSlate(_))));
    };
    refused(&mut alice, &|s| s.fee -= 1);
    refused(&mut alice, &|s| s.amount += 1);
    refused(&mut alice, &|s| s.outputs[1].amount += 1);
    refused(&mut alice, &|s| s.outputs[0].memo[0] += Fp::ONE);
    refused(&mut alice, &|s| s.outputs.swap(0, 1));
    refused(&mut alice, &|s| s.inputs[0].1 += 1);
    refused(&mut alice, &|s| s.outputs.push(s.outputs[1]));
    assert!(matches!(bob.finalize(&answered, NOW), Err(WalletError::Unknown)));

    // Signed: a transaction the chain would take.
    let signed = alice.finalize(&answered, NOW).unwrap();
    assert!(signed.tx.verify_signatures() && signed.last_signatures.is_empty());
    assert_eq!((signed.tx.balance(), signed.tx.spent_positions()), (fee as i128, vec![0]));
    assert!(alice.pending_slates().is_empty());
    assert!(matches!(alice.finalize(&answered, NOW), Err(WalletError::Unknown)));
    let sent = alice.sent();
    assert_eq!((sent.len(), sent[0].txid, sent[0].fee), (1, signed.tx.txid(), fee));
    assert_eq!(alice.balance(&chain).unwrap().locked, 100 * COIN as u128);

    // In a block: each has what it was to have, and the sender's record
    // of the payment is done with.
    chain.take(&signed.tx, &mut [&mut alice, &mut bob]);
    let (a, b) = (alice.balance(&chain).unwrap(), bob.balance(&chain).unwrap());
    assert_eq!(a, Balance { confirmed: (70 * COIN - fee) as u128, ..Default::default() });
    assert_eq!(b, Balance { confirmed: 30 * COIN as u128, ..Default::default() });
    assert_eq!((alice.settle_sent(&chain).unwrap(), alice.sent().len()), (1, 0));
    // And all of it is there when the files are opened again.
    assert_eq!(reopened(&alice, "").unwrap().balance(&chain).unwrap(), a);
    assert_eq!(reopened(&bob, "").unwrap().balance(&chain).unwrap(), b);
}

/// A slate given up frees what it had reserved; and what cannot be paid
/// is refused before anything is.
#[test]
fn a_slate_is_given_up_and_what_cannot_be_paid_is_refused() {
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let before = alice.balance(&chain).unwrap();
    let slate = alice.send(30 * COIN, None, &chain, NOW).unwrap();
    assert!(matches!(alice.cancel_slate(&[9; 32]), Err(WalletError::Unknown)));
    alice.cancel_slate(&slate.id).unwrap();
    assert_eq!((alice.balance(&chain).unwrap(), alice.outputs().len()), (before, 1));
    assert!(alice.pending_slates().is_empty());

    assert!(matches!(alice.send(0, None, &chain, NOW), Err(WalletError::BadSlate(_))));
    assert!(matches!(alice.send(1, None, &chain, NOW), Err(WalletError::BadSlate(_))));
    assert!(matches!(alice.send(100 * COIN, None, &chain, NOW), Err(WalletError::Insufficient { .. })));
    assert!(matches!(alice.send(COIN, Some(1), &chain, NOW), Err(WalletError::FeeTooLow { .. })));
    assert!(matches!(alice.send(COIN, Fee::PerByte(1), &chain, NOW), Err(WalletError::FeeTooLow { .. })));
    assert_eq!(alice.balance(&chain).unwrap(), before);
    // Change too small to be an output goes to the fee.
    let fee = Wallet::<MemBackend>::min_fee(1);
    let slate = alice.send(100 * COIN - fee - 5, None, &chain, NOW).unwrap();
    assert_eq!((slate.change, slate.fee, slate.outputs.len()), (0, fee + 5, 0));
    // Several outputs, where one is not enough.
    let mut chain = Outputs::default();
    let mut carol = new();
    let outs: Vec<Output> = (0..3).map(|_| carol.receive(10 * COIN, NOW).unwrap()).collect();
    chain.make(&outs, &mut [&mut carol]);
    let slate = carol.send(25 * COIN, None, &chain, NOW).unwrap();
    assert_eq!((slate.inputs.len(), slate.fee), (3, Wallet::<MemBackend>::min_fee(3)));
}

/// A wallet restored from its phrase finds its outputs by their memos,
/// and signs for them from the other half of each key's leaves; and an
/// output signs only as many times as its half has leaves.
#[test]
fn outputs_are_found_again_and_leaves_are_not_used_twice() {
    let mut chain = Outputs::default();
    let (mut first, phrase) = Wallet::open(MemBackend::new()).unwrap();
    let mine: Vec<Output> = (1..=3).map(|k| first.receive(k * COIN, NOW).unwrap()).collect();
    let mut stranger = new();
    let theirs = stranger.receive(50 * COIN, NOW).unwrap();
    chain.make(&[mine[0], theirs, mine[1], mine[2]], &mut [&mut first, &mut stranger]);
    chain.0[2].3 = false;

    let mut restored = Wallet::restore(MemBackend::new(), &phrase.unwrap(), "", "").unwrap();
    assert_eq!(restored.balance(&chain).unwrap(), Balance::default());
    // The two that are unspent, and nothing of anyone else's.
    assert_eq!(restored.scan(&chain, NOW).unwrap(), (2, 4 * COIN as u128));
    assert_eq!(restored.scan(&chain, NOW).unwrap(), (0, 0));
    restored.clear_scan_pending().unwrap();
    assert!(!reopened(&restored, "").unwrap().scan_pending());
    let mut found = restored.outputs();
    found.sort_by_key(|o| o.position);
    assert_eq!(
        found.iter().map(|o| (o.position, o.amount)).collect::<Vec<_>>(),
        [(Some(0), COIN), (Some(3), 3 * COIN)]
    );
    assert!(found.iter().all(|o| o.recovered && o.start < 8 && o.used == 0));
    // A wallet that lost where its outputs are finds that again.
    let mut lost = reopened(&first, "").unwrap();
    lost.t.outputs.values_mut().for_each(|o| o.position = None);
    lost.relocate(&chain, NOW).unwrap();
    assert_eq!(lost.balance(&chain).unwrap().confirmed, 4 * COIN as u128);

    // Leaves: the wallet that made the output signs from the first
    // eight in order; the restored one from the other eight.
    let c = mine[0].commitment;
    let mut t = first.t.clone();
    for k in 0..8u64 {
        let (key, last) = first.signing_key(&mut t, &c).unwrap();
        assert_eq!((key.next_index(), last), (k, k == 7));
    }
    assert!(matches!(first.signing_key(&mut t, &c), Err(WalletError::Exhausted)));
    let mut t = restored.t.clone();
    let start = u64::from(restored.owned(&c).unwrap().start);
    for k in 0..8u64 {
        let (key, _) = restored.signing_key(&mut t, &c).unwrap();
        assert_eq!(key.next_index(), 8 + (start + k) % 8);
    }
    assert!(matches!(restored.signing_key(&mut t, &c), Err(WalletError::Exhausted)));
    // A leaf is used on disk when the payment it signs is finalized.
    let mut bob = new();
    let mut slate = restored.send(COIN / 2, None, &chain, NOW).unwrap();
    bob.receive_slate(&mut slate, NOW).unwrap();
    let signed = restored.finalize(&slate, NOW).unwrap();
    assert!(signed.tx.verify_signatures());
    let spent = reopened(&restored, "").unwrap().outputs().into_iter().find(|o| o.state == State::Spent).unwrap();
    assert_eq!((spent.used, spent.amount), (1, 3 * COIN));
}

/// A reward is an output like another, and a record that it is one:
/// forgotten whole if its block comes to nothing.
#[test]
fn a_reward_is_recorded_and_forgotten() {
    let mut chain = Outputs::default();
    let mut miner = new();
    let kept = miner.reward(1500 * COIN, 7, NOW).unwrap();
    let dropped = miner.reward(1500 * COIN, 7, NOW).unwrap();
    assert_eq!(miner.rewards().len(), 2);
    miner.reward_found(&kept.commitment, &[5; 32]).unwrap();
    assert!(miner.forget(&dropped.commitment).unwrap() && !miner.forget(&dropped.commitment).unwrap());
    assert_eq!(miner.rewards(), [(kept.commitment, 7, [5; 32])]);
    chain.make(&[kept], &mut [&mut miner]);
    assert_eq!(miner.balance(&chain).unwrap().confirmed, 1500 * COIN as u128);
    miner.reward_settled(&kept.commitment).unwrap();
    let again = reopened(&miner, "").unwrap();
    assert!(again.rewards().is_empty() && again.outputs().len() == 1 && again.synced() == Some((1, [0; 32])));
}

#[test]
fn base64_is_base64() {
    for (bytes, text) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
        assert_eq!(base64_encode(bytes.as_bytes()), text);
        assert_eq!(base64_decode(text).unwrap(), bytes.as_bytes());
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(base64_decode(&base64_encode(&all)).unwrap(), all);
    for bad in ["Zg=", "Z===", "Zg==Zm9v", "Zh==", "Zm9!", "=m9v"] {
        assert_eq!(base64_decode(bad), None, "{bad}");
    }
}
