//! The node's commands: what is typed at its prompt, and what it says.
//!
//! A command is a line of words. [`Console::run`] takes one and gives
//! back what is to be said of it: it prints nothing, so that whoever
//! asks (the prompt on a terminal, or a program the node is part of)
//! does with the answer what it will.
//!
//! The commands of the node itself need no wallet. Those of the wallet
//! say that there is none where the node was started without one.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::aggregate::AggregateVerifier;
use crate::chain::params::{COIN, DECIMALS};
use crate::logger::fmt::commas;
use crate::name::NameOp;
use crate::net::node::Handle;
use crate::poseidon2::digest_to_bytes;
use crate::store::Backend;
use crate::wallet::names::{NameStage, Registry};
use crate::wallet::{Fee, Slate, State, Wallet, follow};

/// What an offer of a name as text is marked with.
pub const OFFER_MARKER: &str = "TAB NAME OFFER";

/// What the prompt says its commands are.
pub const HELP: &str = "commands:
  status                    the chain's last block, peers, the pool, the wallet's total
  peers                     how many peers are known, and how many are live
  fees                      what a payment is to pay a byte, to be in a block soon, by
                            the hour, or within the day
  leaves                    the sixteen leaves the blocks made here commit to
  set-leaf INDEX FILE       set leaf INDEX (0 to 15) to the SHA-256 of FILE; leaf 0 is
                            the vote for a consensus file, which FILE must be
  set-leaf-value INDEX HEX  set leaf INDEX to 32 bytes given in hex (all zero: none)
  consensus                 the consensus file in force, and how it is voted on
  mempool                   the transactions waiting to be mined
  address                   this wallet's address: what it is known by, as tab1…
  balance                   what there is to spend; what is confirmed but too new to
                            spend; and pending, unverified, reserved, locked and lost
                            funds
  outputs                   the wallet's outputs
  send-file AMOUNT [FEE] FILE
                            start a payment by file: write the slate to FILE for the
                            recipient to `receive`, then `finalize` its answer
                            (FEE: coins in all, or N/byte; the least the pool takes
                            if not given)
  receive FILE [OUT]        answer a slate: add your output (writes OUT, FILE.received
                            if not given)
  finalize FILE             sign an answered slate and pool the transaction
                            (a slate is text, `-----BEGIN TAB SLATE-----` and base64,
                            to keep in a file or copy; FILE `-` is the terminal, for
                            what a command writes)
  slates                    the payments begun and not yet finalized
  sent                      the payments signed and not yet in a block
  cancel ID [FEE]           give up a payment begun (ID: the first digits of its id),
                            freeing what it was to spend; or take back a payment
                            sent and not yet in a block, by another that pays what
                            it spent back to this wallet (FEE as for send-file, at
                            least the smallest that replaces it)
  bump ID [FEE]             pay a payment sent the same with a higher fee, from its
                            change
  resend ID                 pool a payment sent again, as it was signed (after a
                            restart dropped it, or a reorganization moved what it
                            spends)
  prune                     forget outputs expected that the chain does not hold and
                            the pool will not make: of payments taken back, say
  seed                      this wallet's twelve words (its password is asked for,
                            if it has one)
  password                  give the wallet a password, another, or none: asked for
  names                     this wallet's names, and its commits not yet revealed
  name NAME                 look a name up on the chain
  name-commit NAME [VALUE [FEE]]
                            start registering NAME: pool a transaction committing to
                            it, which says nothing of the name (VALUE: 64 hex digits,
                            what the name is to say; `-` or nothing for nothing yet)
  name-reveal NAME [WAIT [FEE]]
                            reveal a committed name once its commit is WAIT blocks
                            old: at least 1; as many as the wallet waits before it
                            spends an output (--min-confirmations) if not given
  name-update NAME VALUE [FEE]
                            change what a name says, putting it under a fresh key
  name-offer NAME FILE [VALUE]
                            write a record for NAME under a key of yours, for its
                            owner to sign over with name-transfer: an offer, as text
                            (`-----BEGIN TAB NAME OFFER-----`); FILE `-` says it here
  name-transfer FILE [FEE]  sign a name over to the offer in FILE
  scan                      find this wallet's outputs and names on the chain (after a
                            restore)
  help                      this
  quit                      stop the node";

/// What is said after a payment sent has been taken back, and after one
/// has been sped up.
const CANCELLED: &str = "The transaction has been cancelled, but it could still end up in a block. \
Call prune to remove the stale transaction from your wallet.";
const BUMPED: &str = "The transaction has been replaced, but the one before it could still end up in a block. \
Call prune to remove the stale transaction from your wallet.";

/// What came of a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// To be said.
    Said(String),
    /// Something was wrong: to be said as an error.
    Wrong(String),
    /// The node is to stop.
    Quit,
    /// An empty line: nothing.
    Nothing,
    /// The wallet's password is to be asked for, and given to
    /// [`Console::seed`]: of a wallet that has one, asked for its words.
    Password,
    /// The wallet's password is to be changed: the one it has is to be
    /// asked for, if it has one ([`Console::locked`]), and the new one
    /// twice, and both given to [`Console::set_password`].
    NewPassword,
}

/// What is said of a wallet's twelve words when they are shown.
pub fn made(phrase: &str) -> String {
    format!(
        "A wallet has been made. Its twelve words, which are all of it: write them down, and keep them\n\
         where nobody else can read them. Whoever has them has what the wallet holds.\n\n    {phrase}"
    )
}

/// What the commands are run on.
pub struct Console<B: Backend + 'static, W: Backend> {
    pub hold: Handle<B, AggregateVerifier>,
    /// None for a node started without a wallet.
    pub wallet: Option<Arc<Mutex<Wallet<W>>>>,
    /// The time by the calendar, in seconds.
    pub unix: fn() -> u64,
    /// Told of what this node's own wallet does with a payment (begun,
    /// answered, signed, given up): a line for the main log. Nothing of
    /// anybody else's transactions is said there.
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// An amount of coins as it is written: its whole part with commas, and
/// as many decimals as it has.
pub fn coins(units: u128) -> String {
    let (whole, part) = (units / COIN as u128, (units % COIN as u128) as u64);
    let whole = commas(whole.min(u64::MAX as u128) as u64);
    match part {
        0 => whole,
        part => format!("{whole}.{}", format!("{part:0width$}", width = DECIMALS).trim_end_matches('0')),
    }
}

/// The base units of an amount of coins as written: digits, with a
/// point and up to ten decimals if there are any. None for anything
/// else, or for more than there can be.
pub fn parse_coins(text: &str) -> Option<u64> {
    let (whole, part) = match text.split_once('.') {
        Some((_, "")) => return None,
        Some(parts) => parts,
        None => (text, ""),
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(part) || part.len() > DECIMALS {
        return None;
    }
    let part = format!("{part:0<width$}", width = DECIMALS).parse::<u64>().ok()?;
    whole.parse::<u64>().ok()?.checked_mul(COIN)?.checked_add(part)
}

fn short(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

type Said = Result<String, String>;

/// Has `wallet` note which of its outputs' leaves the pool's
/// transactions were signed from: so that a wallet whose file has gone
/// back to an earlier state never signs from one of them again. How
/// many outputs it was behind on.
pub fn observe<B: Backend + 'static, W: Backend>(
    hold: &Handle<B, AggregateVerifier>,
    wallet: &Mutex<Wallet<W>>,
) -> Result<usize, String> {
    let mut seen = Vec::new();
    hold.pool(&mut |pool| {
        for e in pool.entries() {
            seen.extend(e.tx().inputs().map(|i| (i.commitment(), i.signature.index)));
        }
    });
    wallet.lock().unwrap_or_else(|e| e.into_inner()).observe_signatures(&seen).map_err(|e| e.to_string())
}

impl<B: Backend + 'static, W: Backend> Console<B, W> {
    /// Does what `line` asks, and gives what is to be said of it.
    pub fn run(&self, line: &str) -> Reply {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some((command, args)) = words.split_first() else { return Reply::Nothing };
        let said = match (*command, args) {
            ("quit" | "exit", []) => return Reply::Quit,
            ("help", []) => Ok(HELP.to_string()),
            ("status", []) => self.status(),
            ("peers", []) => self.peers(),
            ("mempool", []) => self.mempool(),
            ("fees", []) => self.fees(),
            ("leaves", []) => self.leaves(),
            ("set-leaf", [index, file]) => self.set_leaf(index, Some(file), None),
            ("set-leaf-value", [index, value]) => self.set_leaf(index, None, Some(value)),
            ("consensus", []) => self.consensus(),
            ("balance", []) => self.balance(),
            ("address", []) => self.wallet().map(|wallet| wallet.address()),
            ("outputs", []) => self.outputs(),
            ("send-file", [amount, file]) => self.send_file(amount, None, file),
            ("send-file", [amount, fee, file]) => self.send_file(amount, Some(fee), file),
            ("receive", [file]) => self.receive(file, &format!("{file}.received")),
            ("receive", [file, out]) => self.receive(file, out),
            ("finalize", [file]) => self.finalize(file),
            ("slates", []) => self.slates(),
            ("sent", []) => self.sent(),
            ("cancel", [id]) => self.cancel(id, None),
            ("cancel", [id, fee]) => self.cancel(id, Some(fee)),
            ("bump", [id]) => self.bump(id, None),
            ("bump", [id, fee]) => self.bump(id, Some(fee)),
            ("resend", [id]) => self.resend(id),
            ("prune", []) => self.prune(),
            ("password", []) => match self.wallet() {
                Ok(_) => return Reply::NewPassword,
                Err(e) => Err(e),
            },
            // (Its password asked for first, of a wallet that has one.)
            ("seed", []) => match self.wallet().map(|w| w.locked()) {
                Ok(true) => return Reply::Password,
                Ok(false) => self.seed(""),
                Err(e) => Err(e),
            },
            ("names", []) => self.names(),
            ("name", [name]) => self.name(name),
            ("name-commit", [name]) => self.name_commit(name, "-", None),
            ("name-commit", [name, value]) => self.name_commit(name, value, None),
            ("name-commit", [name, value, fee]) => self.name_commit(name, value, Some(fee)),
            ("name-reveal", [name]) => self.name_reveal(name, "", None),
            ("name-reveal", [name, wait]) => self.name_reveal(name, wait, None),
            ("name-reveal", [name, wait, fee]) => self.name_reveal(name, wait, Some(fee)),
            ("name-update", [name, value]) => self.name_update(name, value, None),
            ("name-update", [name, value, fee]) => self.name_update(name, value, Some(fee)),
            ("name-offer", [name, file]) => self.name_offer(name, file, "-"),
            ("name-offer", [name, file, value]) => self.name_offer(name, file, value),
            ("name-transfer", [file]) => self.name_transfer(file, None),
            ("name-transfer", [file, fee]) => self.name_transfer(file, Some(fee)),
            ("scan", []) => self.scan(),
            (
                "status" | "peers" | "mempool" | "fees" | "leaves" | "set-leaf" | "set-leaf-value" | "consensus"
                | "balance" | "address" | "outputs" | "send-file" | "receive" | "finalize" | "slates" | "sent"
                | "cancel" | "bump" | "resend" | "prune" | "seed" | "password" | "scan" | "help" | "quit" | "exit"
                | "names" | "name" | "name-commit" | "name-reveal" | "name-update" | "name-offer" | "name-transfer",
                _,
            ) => Err(format!("{command}: not what it takes (see help)")),
            _ => Err(format!("{command}: no such command (see help)")),
        };
        match said {
            Ok(text) => Reply::Said(text),
            Err(text) => Reply::Wrong(text),
        }
    }

    /// Whether the wallet has a password.
    pub fn locked(&self) -> bool {
        self.wallet().is_ok_and(|w| w.locked())
    }

    /// Gives the wallet the password `new` in place of `old`: either
    /// may be none.
    pub fn set_password(&self, old: &str, new: &str) -> Result<String, String> {
        self.wallet()?.set_password(old, new).map_err(|e| e.to_string())?;
        (self.log)(if new.is_empty() {
            "The wallet's password was taken off"
        } else {
            "The wallet's password was set"
        });
        Ok(match new.is_empty() {
            true => "The wallet has no password now: its file is all it takes to spend from it.".to_string(),
            false => "The wallet's password is set: it is asked for when the node starts.".to_string(),
        })
    }

    /// The wallet's twelve words, if `password` is its password (any,
    /// of a wallet that has none).
    pub fn seed(&self, password: &str) -> Result<String, String> {
        let phrase = self.wallet()?.phrase(password).map_err(|e| e.to_string())?;
        Ok(format!(
            "The wallet's twelve words, which are all of it. Whoever has them has what the wallet holds:\n\
             keep them where nobody else can read them.\n\n    {phrase}"
        ))
    }

    fn wallet(&self) -> Result<MutexGuard<'_, Wallet<W>>, String> {
        let wallet = self.wallet.as_ref().ok_or("this node has no wallet (it was started with --no-wallet)")?;
        Ok(wallet.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn status(&self) -> Said {
        let standing = self.hold.read();
        let tip = self.hold.chain().tip().map_err(|e| e.to_string())?;
        let (pooled, bytes) = self.hold.pool_size();
        let mut out = format!(
            "block {} ({})\npeers: {} live of {} known\npool: {} transactions, {} bytes",
            commas(tip.height as u64),
            short(&digest_to_bytes(&tip.hash())),
            commas(standing.live as u64),
            commas(standing.peers as u64),
            commas(pooled as u64),
            commas(bytes as u64)
        );
        // The message layer: where this node's wallet is reached, and
        // the wallets this node is where others are reached.
        let (sessions, reached, said) = self.hold.sessions();
        if said > 0 {
            out.push_str(&format!("\nreached at: {reached} of {said} nodes"));
        }
        if sessions > 0 {
            out.push_str(&format!("\nsessions: {} wallets are reached here", commas(sessions as u64)));
        }
        let (held, most) = (crate::heap::now() / 1_000_000, crate::heap::peak() / 1_000_000);
        out.push_str(&format!("\nmemory: {} MB held, {} MB at the most", commas(held as u64), commas(most as u64)));
        // (Of the store's file, what is in use and how long it is: the
        // rest is space inside it, taken again before the file grows.)
        if let Ok(state) = self.hold.chain().whole() {
            let (used, end) = state.file().space();
            let mb = |units: u64| commas(units * crate::store::pagefile::UNIT as u64 / 1_000_000);
            out.push_str(&format!("\nstore: {} MB in use, of a file of {} MB", mb(used), mb(end)));
        }
        if let Ok(wallet) = self.wallet() {
            let balance = follow::balance(self.hold.chain(), &wallet).map_err(|e| e.to_string())?;
            out.push_str(&format!("\nwallet: {} confirmed", coins(balance.confirmed)));
        }
        Ok(out)
    }

    fn peers(&self) -> Said {
        let standing = self.hold.read();
        Ok(format!("{} peers known, {} of them live", commas(standing.peers as u64), commas(standing.live as u64)))
    }

    /// The sixteen leaves the blocks made here commit to, and their
    /// root: what a header's auxiliary bytes are.
    fn leaves(&self) -> Said {
        let chain = self.hold.chain();
        let leaves = chain.aux_leaves().map_err(|e| e.to_string())?;
        let hex = |bytes: &[u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut lines: Vec<String> = Vec::new();
        for (i, leaf) in leaves.iter().enumerate().filter(|(_, leaf)| **leaf != [0u8; 32]) {
            let what = if i == 0 { "  (the vote for a consensus file)" } else { "" };
            lines.push(format!("  {i:>2}  {}{what}", hex(leaf)));
        }
        if lines.is_empty() {
            return Ok("no leaf is set: the blocks made here commit to nothing".to_string());
        }
        lines.push(format!("root  {}", hex(&chain.aux_root().map_err(|e| e.to_string())?)));
        Ok(lines.join("\n"))
    }

    /// Sets one of the leaves: to the SHA-256 of a file, or to 32 bytes
    /// given in hex. Leaf 0 is the vote for a consensus file: the file
    /// must be one, and is kept, to be served to whoever asks for what
    /// was voted for.
    fn set_leaf(&self, index: &str, file: Option<&str>, value: Option<&str>) -> Said {
        use crate::chain::leaves::AUX_LEAVES;
        let chain = self.hold.chain();
        let index: usize = index.parse().ok().filter(|i| *i < AUX_LEAVES).ok_or("the leaves are 0 to 15")?;
        let (leaf, said) = match (file, value) {
            (Some(file), _) => {
                let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
                match index {
                    0 => {
                        let parsed = crate::consensus::File::parse(&bytes).map_err(|e| format!("{file}: {e}"))?;
                        let hash = chain.put_consensus_file(&bytes).map_err(|e| e.to_string())?;
                        (hash, format!("the blocks made here vote for {file}: mode {}", parsed.mode))
                    }
                    _ => (crate::sha256::sha256(&bytes), format!("leaf {index} is the SHA-256 of {file}")),
                }
            }
            (None, Some(value)) => {
                let digits = value.as_bytes();
                if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
                    return Err("the value is 64 hex digits".to_string());
                }
                let leaf: [u8; 32] =
                    core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap());
                // (A vote is for a file this node can hand over: not
                // for whatever a number happens to name. But none at
                // all is a vote withdrawn.)
                if index == 0 && leaf != [0u8; 32] && chain.consensus_file(&leaf).map_err(|e| e.to_string())?.is_none()
                {
                    return Err("leaf 0 is a vote for a consensus file: set it with set-leaf 0 FILE".to_string());
                }
                (leaf, format!("leaf {index} is set"))
            }
            (None, None) => return Err("nothing to set it to".to_string()),
        };
        let root = chain.set_aux_leaf(index, leaf).map_err(|e| e.to_string())?;
        (self.log)(&format!("Leaf {index} of the blocks made here was set"));
        let hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!("{said}\nroot  {hex}"))
    }

    /// The consensus file in force, how it was voted for, and what it
    /// says.
    fn consensus(&self) -> Said {
        use crate::consensus::{WINDOW, boundary};
        let chain = self.hold.chain();
        let (current, votes) = chain.consensus().map_err(|e| e.to_string())?;
        let hex = |bytes: &[u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let height = self.hold.read().height;
        let mut lines = vec![format!("mode {}", current.mode)];
        match boundary(height) {
            0 => lines.push(format!("nothing is decided before block {WINDOW}: until then the mode is init")),
            at => lines.push(format!(
                "decided at block {}, of the votes of blocks {} to {}: {} of {} voted",
                commas(at as u64),
                commas(votes.range.0 as u64),
                commas(votes.range.1 as u64),
                commas(votes.cast() as u64),
                commas(votes.blocks as u64)
            )),
        }
        lines.push(format!("the next is decided at block {}", commas((boundary(height) + WINDOW) as u64)));
        if let Some((hash, n)) = &current.winner {
            lines.push(format!("in force: {} ({} votes)", hex(hash), commas(*n as u64)));
        }
        for (hash, n, why) in &current.skipped {
            lines.push(format!("not counted: {} ({} votes): {why}", hex(hash), commas(*n as u64)));
        }
        if let Some(file) = &current.file {
            for relay in &file.relays {
                lines.push(format!("  relay {} {}", crate::address::encode(&relay.id), relay.addr));
            }
        }
        // What is being voted for now, towards the next boundary.
        let running = chain.consensus_votes(height + 1 - boundary(height)).map_err(|e| e.to_string())?;
        for (hash, n, _) in &running.counts {
            lines.push(format!("since then: {} has {} votes", hex(hash), commas(*n as u64)));
        }
        Ok(lines.join("\n"))
    }

    /// What a payment is to pay to be in a block soon, by the hour, or
    /// within the day: as the pool reckons it from what it holds and
    /// what it has seen blocks take.
    fn fees(&self) -> Said {
        use crate::mempool::{TARGET_BLOCK, TARGET_DAY, TARGET_HOUR};
        let unix = (self.unix)();
        let size = Wallet::<W>::payment_size(1);
        let mut lines = Vec::new();
        self.hold.pool(&mut |pool| {
            lines.push(format!(
                "the least a byte is {}; the pool takes from {}",
                commas(pool.policy().min_fee_per_byte),
                commas(pool.admission_fee(unix))
            ));
            for (what, target) in [("next block", TARGET_BLOCK), ("an hour", TARGET_HOUR), ("a day", TARGET_DAY)] {
                let seen = if pool.estimate(target, unix).is_some() { "" } else { " (too little seen yet: the least)" };
                lines.push(format!("  within {what:<11} {} a byte{seen}", commas(pool.suggest(target, size, unix))));
            }
            lines.push(format!(
                "  the least         {} a byte: about {} blocks at the most, by its age",
                commas(pool.admission_fee(unix)),
                commas(pool.reserve_wait(size))
            ));
        });
        lines.push(format!("a simple payment is about {} bytes; fees are in base units", commas(size as u64)));
        Ok(lines.join("\n"))
    }

    fn mempool(&self) -> Said {
        let mut lines = Vec::new();
        let unix = (self.unix)();
        self.hold.pool(&mut |pool| {
            lines.push(format!(
                "{} transactions, {} bytes; the pool asks {} a byte",
                commas(pool.len() as u64),
                commas(pool.bytes() as u64),
                commas(pool.admission_fee(unix))
            ));
            let mut entries: Vec<_> = pool.entries().collect();
            entries.sort_by_key(|e| (e.arrived, e.order));
            for e in entries.iter().take(50) {
                lines.push(format!(
                    "  {}  {} bytes  fee {}  ({} a byte)",
                    short(&digest_to_bytes(&e.txid)),
                    commas(e.size() as u64),
                    coins(e.fee as u128),
                    commas(e.fee / e.size().max(1) as u64)
                ));
            }
            if entries.len() > 50 {
                lines.push(format!("  and {} more", commas(entries.len() as u64 - 50)));
            }
        });
        Ok(lines.join("\n"))
    }

    fn balance(&self) -> Said {
        let wallet = self.wallet()?;
        let b = follow::balance(self.hold.chain(), &wallet).map_err(|e| e.to_string())?;
        // What is there to spend, first; then what is confirmed and
        // has not been in the chain long enough to be.
        let mut out = format!("spendable   {}", coins(b.spendable));
        if b.confirmed > b.spendable {
            out.push_str(&format!(
                "\nconfirmed   {}  (in the chain for fewer than {} blocks: not spent yet)",
                coins(b.confirmed - b.spendable),
                wallet.min_confirmations()
            ));
        }
        let rest = [
            ("pending", b.pending),
            ("unverified", b.unverified),
            ("reserved", b.reserved),
            ("locked", b.locked),
            ("lost", b.lost),
        ];
        for (what, amount) in rest {
            if amount > 0 {
                out.push_str(&format!("\n{what:<11} {}", coins(amount)));
            }
        }
        Ok(out)
    }

    fn outputs(&self) -> Said {
        let wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let mut lines = Vec::new();
        for o in wallet.outputs() {
            let held = wallet.held(&o, &snap).map_err(|e| e.to_string())?;
            let what = match (o.state, held) {
                (State::Unspent, true) => "confirmed",
                (State::Unspent, false) if wallet.is_lost(&o.commitment) => "lost",
                (State::Unspent, false) => "pending",
                (State::Reserved, _) => "reserved",
                (State::Spent, true) => "locked",
                (State::Spent, false) => "spent",
            };
            let at = o.position.map_or("-".to_string(), |p| commas(p));
            lines.push(format!(
                "  {}  {:>24}  {what:<9}  at {at}",
                short(&digest_to_bytes(&o.commitment)),
                coins(o.amount as u128)
            ));
        }
        match lines.is_empty() {
            true => Ok("no outputs".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    /// Writes `text` to the file `file`, or gives it to be said if the
    /// file is `-`; else says `done`.
    fn write(file: &str, text: String, done: String) -> Said {
        if file == "-" {
            return Ok(format!("{text}{done}"));
        }
        std::fs::write(Path::new(file), text).map_err(|e| format!("cannot write {file}: {e}"))?;
        Ok(done)
    }

    fn read_slate(file: &str) -> Result<Slate, String> {
        let text = std::fs::read_to_string(Path::new(file)).map_err(|e| format!("cannot read {file}: {e}"))?;
        Slate::from_text(&text).ok_or_else(|| format!("{file} holds no slate"))
    }

    /// What is said of a payment the wallet could not make: where it
    /// has the funds and they have not been in the chain long enough to
    /// spend, that, and not that it has none.
    fn short_of(wallet: &Wallet<W>, chain: &impl crate::wallet::Unspent, e: crate::wallet::WalletError) -> String {
        let crate::wallet::WalletError::Insufficient { have, need } = e else { return e.to_string() };
        let waiting = wallet.balance(chain).map_or(0, |b| b.confirmed.saturating_sub(b.spendable));
        let blocks = wallet.min_confirmations();
        match waiting {
            0 => format!("insufficient funds: {} to spend, {} needed", coins(have), coins(need)),
            waiting => format!(
                "nothing to spend it from yet: {} to spend, {} needed. {} more is confirmed, but the wallet spends \
                 only what has been in the chain for {blocks} blocks (--min-confirmations)",
                coins(have),
                coins(need),
                coins(waiting)
            ),
        }
    }

    /// A fee as it is written: coins in all, or `N/byte`; the least
    /// that will do if none is.
    fn fee(text: Option<&&str>) -> Result<Fee, String> {
        match text {
            None => Ok(Fee::from(None)),
            Some(text) => match text.strip_suffix("/byte") {
                Some(rate) => Ok(Fee::PerByte(rate.parse().map_err(|_| format!("'{text}' is not a fee"))?)),
                None => Ok(Fee::Total(parse_coins(text).ok_or_else(|| format!("'{text}' is not a fee"))?)),
            },
        }
    }

    fn observe(&self) -> Result<usize, String> {
        match &self.wallet {
            Some(wallet) => observe(&self.hold, wallet),
            None => Ok(0),
        }
    }

    fn send_file(&self, amount: &str, fee: Option<&&str>, file: &str) -> Said {
        let amount = parse_coins(amount).ok_or_else(|| format!("'{amount}' is not an amount of coins"))?;
        let fee = Self::fee(fee)?;
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let slate = wallet.send(amount, fee, &snap, (self.unix)()).map_err(|e| Self::short_of(&wallet, &snap, e))?;
        let done = format!(
            "payment {} begun: {} and a fee of {}, from {} outputs",
            &slate.id_hex()[..8],
            coins(slate.amount as u128),
            coins(slate.fee as u128),
            slate.inputs.len()
        );
        (self.log)(&format!("P{}", &done[1..]));
        Self::write(file, slate.to_text(), format!("{done}; to be answered and then finalized"))
    }

    fn receive(&self, file: &str, out: &str) -> Said {
        let mut slate = Self::read_slate(file)?;
        let mut wallet = self.wallet()?;
        wallet.receive_slate(&mut slate, (self.unix)()).map_err(|e| e.to_string())?;
        let done = format!("payment {} answered: {} to this wallet", &slate.id_hex()[..8], coins(slate.amount as u128));
        (self.log)(&format!("P{}", &done[1..]));
        Self::write(out, slate.to_text(), format!("{done}, once its sender finalizes it"))
    }

    fn finalize(&self, file: &str) -> Said {
        let slate = Self::read_slate(file)?;
        let unix = (self.unix)();
        self.observe()?;
        // (The wallet is let go of before the pool is asked for.)
        let signed = self.wallet()?.finalize(&slate, unix).map_err(|e| e.to_string())?;
        let id = short(&digest_to_bytes(&signed.tx.txid()));
        match self.hold.submit(&signed.tx.to_bytes(), unix) {
            Ok(_) => {
                let done = format!(
                    "payment {} signed and pooled: transaction {id}, {} with a fee of {}",
                    &slate.id_hex()[..8],
                    coins(slate.amount as u128),
                    coins(slate.fee as u128)
                );
                (self.log)(&format!("P{}", &done[1..]));
                Ok(done)
            }
            Err(why) => {
                let failed =
                    format!("payment {} is signed, but the pool does not take it: {why}", &slate.id_hex()[..8]);
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    fn slates(&self) -> Said {
        let pending = self.wallet()?.pending_slates();
        if pending.is_empty() {
            return Ok("no payments begun".to_string());
        }
        let line = |(id, amount): &([u8; 32], u64)| format!("  {}  {}", short(id), coins(*amount as u128));
        Ok(pending.iter().map(line).collect::<Vec<_>>().join("\n"))
    }

    fn sent(&self) -> Said {
        let wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let mut lines = Vec::new();
        for sent in wallet.sent() {
            // (One whose inputs the chain no longer holds is in a block.)
            let mut open = false;
            for c in &sent.inputs {
                if let Some(o) = wallet.owned(c) {
                    open |= wallet.held(&o, &snap).map_err(|e| e.to_string())?;
                }
            }
            if open {
                lines.push(format!(
                    "  {}  fee {}  {}",
                    short(&digest_to_bytes(&sent.txid)),
                    coins(sent.fee as u128),
                    if self.hold.pooled(&sent.txid) { "pooled" } else { "not in the pool (resend)" }
                ));
            }
        }
        match lines.is_empty() {
            true => Ok("no payments sent that are not in a block".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    /// The payment sent whose transaction's id starts `id`.
    fn sent_of(wallet: &Wallet<W>, id: &str) -> Result<crate::hash::Digest, String> {
        let hex = |d: &crate::hash::Digest| digest_to_bytes(d).iter().map(|b| format!("{b:02x}")).collect::<String>();
        let found: Vec<_> = wallet.sent().into_iter().map(|s| s.txid).filter(|t| hex(t).starts_with(id)).collect();
        match found[..] {
            [one] => Ok(one),
            [] => Err(format!("no payment sent with an id that starts {id}")),
            _ => Err(format!("more than one payment sent with an id that starts {id}")),
        }
    }

    /// Pools what the wallet signed in place of a payment sent, and says
    /// what was done: `done`, with the transaction and its fee.
    fn replaced(&self, done: &str, after: &str, was: &crate::hash::Digest, signed: &crate::wallet::Signed) -> Said {
        let (was, id) = (short(&digest_to_bytes(was)), short(&digest_to_bytes(&signed.tx.txid())));
        let fee = coins(signed.tx.balance().max(0) as u128);
        match self.hold.submit(&signed.tx.to_bytes(), (self.unix)()) {
            Ok(_) => {
                let said = format!("payment sent {was} {done}: transaction {id}, with a fee of {fee}");
                (self.log)(&format!("P{}", &said[1..]));
                Ok(format!("{said}\n{after}"))
            }
            Err(why) => {
                let failed = format!("payment sent {was} {done}, but the pool does not take transaction {id}: {why}");
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    fn cancel(&self, id: &str, fee: Option<&&str>) -> Said {
        let fee = Self::fee(fee)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        let hex = |id: &[u8; 32]| id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let found: Vec<[u8; 32]> =
            wallet.pending_slates().into_iter().map(|(i, _)| i).filter(|i| hex(i).starts_with(id)).collect();
        match found[..] {
            [one] => {
                wallet.cancel_slate(&one).map_err(|e| e.to_string())?;
                let done = format!("payment {} given up", short(&one));
                (self.log)(&format!("P{}", &done[1..]));
                Ok(done)
            }
            // Not a payment begun: one sent, then, to be taken back.
            [] => {
                let was = Self::sent_of(&wallet, id)
                    .map_err(|_| format!("no payment begun or sent with an id that starts {id}"))?;
                let signed = {
                    let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
                    let snap = state.snapshot().map_err(|e| e.to_string())?;
                    wallet.cancel_sent(&was, fee, &snap, (self.unix)()).map_err(|e| match e {
                        crate::wallet::WalletError::Landed => {
                            "a block has it already: it cannot be taken back (what it spent is spent on chain)"
                                .to_string()
                        }
                        e => e.to_string(),
                    })?
                };
                drop(wallet);
                self.replaced("taken back", CANCELLED, &was, &signed)
            }
            _ => Err(format!("more than one payment begun with an id that starts {id}")),
        }
    }

    fn bump(&self, id: &str, fee: Option<&&str>) -> Said {
        let fee = Self::fee(fee)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        let was = Self::sent_of(&wallet, id)?;
        let signed = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            wallet.bump_sent(&was, fee, &snap, (self.unix)()).map_err(|e| match e {
                crate::wallet::WalletError::Landed => {
                    "a block has it already: there is nothing to speed up".to_string()
                }
                e => e.to_string(),
            })?
        };
        drop(wallet);
        self.replaced("sped up", BUMPED, &was, &signed)
    }

    fn resend(&self, id: &str) -> Said {
        let wallet = self.wallet()?;
        let was = Self::sent_of(&wallet, id)?;
        let tx = wallet.resend(&was).map_err(|e| e.to_string())?;
        drop(wallet);
        match self.hold.submit(&tx.to_bytes(), (self.unix)()) {
            Ok(_) => Ok(format!("payment sent {} pooled again", short(&digest_to_bytes(&was)))),
            Err(why) => Err(format!("the pool does not take it: {why}")),
        }
    }

    fn prune(&self) -> Said {
        // (What the pool's transactions make may yet be made.)
        let (mut keep, mut commits) = (Vec::new(), Vec::new());
        self.hold.pool(&mut |pool| {
            for e in pool.entries() {
                keep.extend(e.tx().outputs().iter().map(|o| o.commitment));
                commits.extend(e.tx().ops().filter_map(|op| match op {
                    NameOp::Commit { commit, .. } => Some(commit),
                    _ => None,
                }));
            }
        });
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let gone = wallet.prune_pending(&snap, &keep).map_err(|e| e.to_string())?;
        let mut out = format!("{} outputs expected that will not be made were forgotten", commas(gone as u64));
        for name in wallet.prune_commits(&snap, &commits).map_err(|e| e.to_string())? {
            out.push_str(&format!("\nthe commit to {name} forgotten: it never reached the chain"));
        }
        Ok(out)
    }

    fn scan(&self) -> Said {
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let (found, total) = wallet.scan(&snap, (self.unix)()).map_err(|e| e.to_string())?;
        let (names, commits) = wallet.scan_names(&snap, (self.unix)()).map_err(|e| e.to_string())?;
        Ok(format!(
            "{} outputs found that were not known, {} in all; {} names; {} commits not yet revealed",
            commas(found as u64),
            coins(total),
            commas(names as u64),
            commas(commits as u64)
        ))
    }

    /// What a name says, as it is written: 64 hex digits; nothing, for
    /// `-`.
    fn value(text: &str) -> Result<crate::hash::Digest, String> {
        if text == "-" {
            return Ok([crate::poseidon2::Fp::ZERO; 8]);
        }
        let bytes: Vec<u8> = match text.len() == 64 && text.is_ascii() {
            true => (0..32).filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect(),
            false => Vec::new(),
        };
        crate::poseidon2::digest_from_bytes(&bytes)
            .filter(|_| bytes.len() == 32)
            .ok_or_else(|| format!("'{text}' is not what a name says: 64 hex digits, or - for nothing"))
    }

    fn hex(d: &crate::hash::Digest) -> String {
        digest_to_bytes(d).iter().map(|b| format!("{b:02x}")).collect()
    }

    fn names(&self) -> Said {
        let wallet = self.wallet()?;
        let mut lines = Vec::new();
        for n in wallet.owned_names() {
            let stage = match (n.stage, n.transferring, n.pending.is_some()) {
                (_, true, _) => "being given away",
                (NameStage::Owned, _, true) => "owned, a change signed",
                (NameStage::Owned, _, _) => "owned",
                (NameStage::Revealed, _, _) => "revealed, not yet in the chain",
                (NameStage::Offered, _, _) => "offered to this wallet",
            };
            lines.push(format!("  {:<32}  {stage}  says {}", String::from_utf8_lossy(&n.name), Self::hex(&n.value)));
        }
        for c in wallet.pending_commits() {
            let name =
                c.name.as_deref().map_or("(a name not known: reveal it by name)".into(), String::from_utf8_lossy);
            lines.push(format!("  {name:<32}  committed, not yet revealed"));
        }
        match lines.is_empty() {
            true => Ok("no names".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    fn name(&self, name: &str) -> Said {
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        match Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())? {
            Some(record) => {
                Ok(format!("{name} says {}\n  its owner's key: {}", Self::hex(&record.value), Self::hex(&record.owner)))
            }
            None => Ok(format!("{name} is not registered")),
        }
    }

    /// Has a transaction of the wallet's carry `op`, and pools it:
    /// `done` is what is then said, with the transaction. If none can
    /// carry it, it is as if the operation had not been made.
    fn carry(&self, wallet: &mut Wallet<W>, op: NameOp, fee: Fee, done: &str) -> Said {
        let unix = (self.unix)();
        let signed = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            wallet.carry(vec![op.clone()], fee, &snap, unix).map_err(|e| Self::short_of(wallet, &snap, e))
        };
        let signed = match signed {
            Ok(signed) => signed,
            Err(e) => {
                wallet.undo_name_op(&op).map_err(|e| e.to_string())?;
                return Err(e);
            }
        };
        let id = short(&digest_to_bytes(&signed.tx.txid()));
        match self.hold.submit(&signed.tx.to_bytes(), unix) {
            Ok(_) => {
                let said =
                    format!("{done}: transaction {id}, with a fee of {}", coins(signed.tx.balance().max(0) as u128));
                (self.log)(&said);
                Ok(said)
            }
            Err(why) => {
                let failed = format!("{done}, but the pool does not take transaction {id}: {why}");
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    fn name_commit(&self, name: &str, value: &str, fee: Option<&&str>) -> Said {
        let (value, fee) = (Self::value(value)?, Self::fee(fee)?);
        self.observe()?;
        let mut wallet = self.wallet()?;
        let op = wallet.name_commit(name.as_bytes(), value, (self.unix)()).map_err(|e| e.to_string())?;
        self.carry(&mut wallet, op, fee, &format!("Name {name}: committed to"))
    }

    fn name_reveal(&self, name: &str, wait: &str, fee: Option<&&str>) -> Said {
        let fee = Self::fee(fee)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        // Not said: as long as the wallet waits before it spends an
        // output, for the same reason.
        let wait: u32 = match wait {
            "" => wallet.min_confirmations(),
            wait => wait.parse().map_err(|_| format!("'{wait}' is not a number of blocks"))?,
        };
        let op = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            let (height, least) = (snap.tip().0 + 1, self.hold.chain().params().min_reveal);
            wallet.name_reveal(name.as_bytes(), wait, least, &snap, height, (self.unix)()).map_err(|e| e.to_string())?
        };
        self.carry(&mut wallet, op, fee, &format!("Name {name}: revealed"))
    }

    fn name_update(&self, name: &str, value: &str, fee: Option<&&str>) -> Said {
        let (value, fee) = (Self::value(value)?, Self::fee(fee)?);
        self.observe()?;
        let mut wallet = self.wallet()?;
        let (op, _) = wallet.name_update(name.as_bytes(), value).map_err(|e| e.to_string())?;
        self.carry(&mut wallet, op, fee, &format!("Name {name}: changed"))
    }

    fn name_offer(&self, name: &str, file: &str, value: &str) -> Said {
        let value = Self::value(value)?;
        let record = self.wallet()?.name_offer(name.as_bytes(), value, (self.unix)()).map_err(|e| e.to_string())?;
        let b64 = crate::wallet::base64_encode(&record.to_bytes());
        let mut text = format!("-----BEGIN {OFFER_MARKER}-----\n");
        for line in b64.as_bytes().chunks(64) {
            text.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
            text.push('\n');
        }
        text.push_str(&format!("-----END {OFFER_MARKER}-----\n"));
        let done = format!("Name {name}: an offer written, for its owner to sign over with name-transfer");
        (self.log)(&done);
        Self::write(file, text, done)
    }

    fn name_transfer(&self, file: &str, fee: Option<&&str>) -> Said {
        let fee = Self::fee(fee)?;
        let text = std::fs::read_to_string(Path::new(file)).map_err(|e| format!("cannot read {file}: {e}"))?;
        let (begin, end) = (format!("-----BEGIN {OFFER_MARKER}-----"), format!("-----END {OFFER_MARKER}-----"));
        let record = text
            .find(&begin)
            .and_then(|at| {
                let body = &text[at + begin.len()..];
                let b64: String = body[..body.find(&end)?].chars().filter(|c| !c.is_whitespace()).collect();
                crate::name::Record::from_bytes(&crate::wallet::base64_decode(&b64)?).ok()
            })
            .ok_or_else(|| format!("{file} holds no offer of a name"))?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        let name = record.name.as_str().to_string();
        let (op, _) = wallet.name_transfer(record).map_err(|e| e.to_string())?;
        self.carry(&mut wallet, op, fee, &format!("Name {name}: signed over"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coins_are_written_and_read() {
        for (units, text) in [
            (0u64, "0"),
            (1, "0.0000000001"),
            (COIN, "1"),
            (15 * COIN / 10, "1.5"),
            (1_234_567 * COIN + 890, "1,234,567.000000089"),
        ] {
            assert_eq!(coins(units as u128), text);
            assert_eq!(parse_coins(&text.replace(',', "")), Some(units), "{text}");
        }
        assert_eq!(parse_coins("1.50"), Some(15 * COIN / 10));
        for bad in ["", ".5", "1.", "1.00000000001", "-1", "1e3", "1,000", "99999999999999999999", "1844674408"] {
            assert_eq!(parse_coins(bad), None, "{bad}");
        }
    }
}
