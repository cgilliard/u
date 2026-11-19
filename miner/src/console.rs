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
  send AMOUNT [FEE] TO      pay AMOUNT to the wallet at TO: its address (tab1…), its
                            name (@name), or a name under a name (label@name). Its
                            wallet answers and this one signs, with nothing more
                            asked: both must be reached
  subname set LABEL@NAME ADDRESS
                            give a name under NAME, which this wallet holds, to the
                            wallet at ADDRESS: it is sent a certificate, signed again
                            daily while this node runs
  subname delegate NAME ADDRESS [DAYS] FILE
                            say that the key of the wallet at ADDRESS signs for NAME,
                            which this wallet holds, for DAYS days (30): so that the
                            wallet that holds a name need not be the one that runs
                            all day. Written to FILE, for that wallet to take
  subname signer FILE       take such a word: this wallet then gives names under
                            that name
  subname del LABEL@NAME    sign for it no longer: its last certificate holds until
                            its time is past (there is no ending it sooner, but by
                            giving the name to another wallet)
  subname drop LABEL@NAME   be a name this wallet was given no longer
  subnames                  the names given out, and the names this wallet is
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
    /// Whether what is only for trying things may be done here: on a
    /// network for that, in a build for that.
    pub debug: bool,
    /// Full names this wallet may be at the most ([`crate::subnames`]).
    pub max_names: usize,
    /// What is remembered between the prompt and what takes the
    /// wallet's messages.
    pub names: Arc<Mutex<Named>>,
}

/// What is remembered of full names while the node runs.
#[derive(Default)]
pub struct Named {
    /// The full name each payment begun was sent to, by its slate's
    /// id: to say it by, whatever becomes of it.
    sent: std::collections::BTreeMap<[u8; 32], String>,
    /// The names given out whose certificate did not reach the wallet
    /// it is for: given again when names are next looked to.
    again: std::collections::BTreeSet<[u8; 32]>,
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
            ("debug-consensus", [file]) if self.debug => self.debug_consensus(file),
            ("subname", ["set", full, to]) => self.subname_set(full, to),
            ("subname", ["delegate", name, signer, file]) => self.subname_delegate(name, signer, "30", file),
            ("subname", ["delegate", name, signer, days, file]) => self.subname_delegate(name, signer, days, file),
            ("subname", ["signer", file]) => self.subname_signer(file),
            ("subname", ["del", full]) => self.subname_del(full),
            ("subname", ["drop", full]) => self.subname_drop(full),
            ("subnames", []) => self.subnames(),
            ("balance", []) => self.balance(),
            ("address", []) => self.wallet().map(|wallet| wallet.address()),
            ("outputs", []) => self.outputs(),
            ("send", [amount, to]) => self.send(amount, None, to),
            ("send", [amount, fee, to]) => self.send(amount, Some(fee), to),
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
                "send" | "status" | "peers" | "mempool" | "fees" | "leaves" | "set-leaf" | "set-leaf-value"
                | "consensus" | "balance" | "address" | "outputs" | "send-file" | "receive" | "finalize" | "slates"
                | "sent" | "cancel" | "bump" | "resend" | "prune" | "seed" | "password" | "scan" | "help" | "quit"
                | "exit" | "names" | "name" | "name-commit" | "name-reveal" | "name-update" | "name-offer"
                | "name-transfer",
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
    /// Puts a consensus file in force at this node alone, whatever the
    /// chain has decided: to try what relays do without a day of
    /// blocks voting for them.
    fn debug_consensus(&self, path: &str) -> Said {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let file = crate::consensus::File::parse(&bytes).map_err(|e| format!("{path}: {e}"))?;
        self.hold.force_consensus(&file);
        Ok(format!(
            "here the message layer is in {} mode, of {} relays, whatever the chain decides",
            file.mode,
            file.relays.len()
        ))
    }

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

    /// Whom a payment is to: a wallet's address, or the name of one
    /// (`@name`), which says its address.
    fn whom(&self, to: &str) -> Result<crate::hash::Digest, String> {
        let Some(name) = to.strip_prefix('@') else {
            return crate::address::decode(to).ok_or_else(|| format!("'{to}' is no address (tab1…) and no @name"));
        };
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let record = Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())?;
        let record = record.ok_or_else(|| format!("{name} is not registered"))?;
        // (What a name says is a digest: an address, where it is one.)
        match record.value == [crate::poseidon2::Fp::ZERO; 8] {
            false => Ok(record.value),
            true => Err(format!("{name} says no address")),
        }
    }

    /// Begins a payment to a wallet, by its address or its name: the
    /// slate is sent to it, sealed, through a node it is reached at;
    /// its wallet answers, and this one signs the answer and pools the
    /// transaction, with nothing more asked of either.
    fn send(&self, amount: &str, fee: Option<&&str>, to: &str) -> Said {
        // A name under a name: whose it is, is asked of the nodes the
        // full name is reached at when the payment is sent. Until one
        // of them shows it, the payment is to the name.
        let under = match to.split_once('@') {
            Some((label, _)) if !label.is_empty() => {
                let (label, name) = crate::subnames::split(to).ok_or_else(|| format!("'{to}' is no label@name"))?;
                self.value_of(name)?;
                Some(crate::subnames::point(label.as_bytes(), name.as_bytes()))
            }
            _ => None,
        };
        let whom = match under {
            Some(n) => n,
            None => self.whom(to)?,
        };
        let amount = parse_coins(amount).ok_or_else(|| format!("'{amount}' is not an amount of coins"))?;
        let fee = Self::fee(fee)?;
        if !self.hold.reached() {
            return Err("this wallet is reached nowhere yet: it could not be answered (see status)".to_string());
        }
        // (To this wallet itself, if that is what is asked: a payment
        // that shows the wallet is reached.)
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let slate = wallet.send(amount, fee, &snap, (self.unix)()).map_err(|e| Self::short_of(&wallet, &snap, e))?;
        let done = format!(
            "payment {} begun: {} and a fee of {}, to {}",
            &slate.id_hex()[..8],
            coins(slate.amount as u128),
            coins(slate.fee as u128),
            if under.is_some() { to.to_string() } else { crate::address::encode(&whom) }
        );
        (self.log)(&format!("P{}", &done[1..]));
        // Whom it is sent to is kept with it: its answer is taken from
        // that wallet, and from no other. (Of a name under a name,
        // from nobody until it is known whose the name is.)
        wallet.send_to(&slate.id, &whom).map_err(|e| e.to_string())?;
        let body = slate.to_text().into_bytes();
        match under {
            Some(n) => {
                self.names.lock().unwrap_or_else(|e| e.into_inner()).sent.insert(slate.id, to.to_string());
                self.hold.post_to_name(n, crate::msg::KIND_SLATE, slate.id, body);
            }
            None => self.hold.post(whom, crate::msg::KIND_SLATE, slate.id, body, None),
        }
        Ok(format!("{done}; sent to its wallet, to be answered"))
    }

    /// Takes a message that has come for this wallet, and does what it
    /// asks: a slate of a payment to this wallet is answered, and the
    /// answer sent back; the answer to a slate this wallet began is
    /// signed, and the transaction pooled. What was done, to be said.
    pub fn take(&self, message: &crate::msg::Opened) -> Said {
        if message.kind == crate::msg::KIND_NAME {
            return self.given(&message.body);
        }
        if message.kind != crate::msg::KIND_SLATE {
            return Err(format!("a message of a kind not known ({})", message.kind));
        }
        let from = crate::address::encode(&message.from);
        let text = std::str::from_utf8(&message.body).map_err(|_| format!("what {from} sent is no slate"))?;
        let mut slate = Slate::from_text(text).ok_or_else(|| format!("what {from} sent is no slate"))?;
        let unix = (self.unix)();
        // One this wallet began: its answer. (Signed only if it is the
        // slate that was begun, answered: the wallet sees to that.)
        // (Unless it is its own slate come round, not yet answered: a
        // payment of this wallet's to itself, which it answers as any.)
        let wallet = self.wallet()?;
        let to_itself = slate.stage == 1 && message.from == wallet.id();
        let ours = !to_itself && wallet.pending_slates().iter().any(|(id, _)| *id == slate.id);
        drop(wallet);
        if ours {
            // From the wallet it was sent to, or it is nobody's answer:
            // whoever answers says where the payment goes. (One begun
            // in a file was sent to nobody, and is finalized by hand.)
            match self.wallet()?.sent_to(&slate.id) {
                Some(whom) if whom == message.from => {}
                Some(whom) => {
                    let whom = crate::address::encode(&whom);
                    return Err(format!(
                        "payment {} was sent to {whom}, and {from} answers it: not signed",
                        &slate.id_hex()[..8]
                    ));
                }
                None => {
                    return Err(format!(
                        "payment {} was begun in a file, and {from} answers it over the network: not signed (finalize \
                         its answer from a file)",
                        &slate.id_hex()[..8]
                    ));
                }
            }
            self.observe()?;
            let signed = self.wallet()?.finalize(&slate, unix).map_err(|e| e.to_string())?;
            let id = short(&digest_to_bytes(&signed.tx.txid()));
            return match self.hold.submit(&signed.tx.to_bytes(), unix) {
                Ok(_) => {
                    let done = format!(
                        "payment {} answered by {from}, signed and pooled: transaction {id}, {} with a fee of {}",
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
            };
        }
        // One somebody else began, to pay this wallet: answered.
        self.wallet()?.receive_slate(&mut slate, unix).map_err(|e| e.to_string())?;
        let done = format!(
            "payment {} from {from} answered: {} to this wallet",
            &slate.id_hex()[..8],
            coins(slate.amount as u128)
        );
        (self.log)(&format!("P{}", &done[1..]));
        let (answer, known) = (slate.to_text().into_bytes(), Some(message.reply.clone()));
        self.hold.post(message.from, crate::msg::KIND_SLATE, slate.id, answer, known);
        Ok(done)
    }

    /// A message this wallet sent was not passed on: `why`. If it was a
    /// payment this wallet began, the payment is given up, and what it
    /// would have spent is the wallet's to spend again. What is to be
    /// said of it.
    pub fn undelivered(&self, to: &crate::hash::Digest, slate: &[u8; 32], why: &str) -> String {
        let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        // (A certificate that did not reach the wallet it is for: its
        // tag is the id of the name. Given again later.)
        let given = self.wallet().ok().and_then(|wallet| {
            wallet
                .names_given()
                .into_iter()
                .find(|g| digest_to_bytes(&crate::subnames::point(&g.label, &g.name)) == *slate)
        });
        if let Some(given) = given {
            names.again.insert(*slate);
            let holder = crate::address::encode(&given.holder);
            return format!(
                "Error: the certificate of {} was not given to {holder} ({why}): it is tried again while this node runs",
                given.full()
            );
        }
        let to = names.sent.remove(slate).unwrap_or_else(|| crate::address::encode(to));
        drop(names);
        let given_up =
            self.wallet().is_ok_and(|mut wallet| wallet.sent_to(slate).is_some() && wallet.cancel_slate(slate).is_ok());
        match given_up {
            true => format!(
                "Error: payment {} to {to} was not delivered ({why}): given up, nothing was spent",
                short(slate)
            ),
            false => format!("Error: a message to {to} was not delivered ({why})"),
        }
    }

    /// What `name` says on the chain: the id of whoever holds it.
    fn value_of(&self, name: &str) -> Result<crate::hash::Digest, String> {
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let record = Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())?;
        Ok(record.ok_or_else(|| format!("{name} is not registered"))?.value)
    }

    /// Whose the full name a payment was sent to turned out to be: its
    /// answer is taken from that wallet, and from no other.
    pub fn resolved(&self, slate: &[u8; 32], whom: &crate::hash::Digest) -> Said {
        let mut wallet = self.wallet()?;
        if wallet.sent_to(slate).is_none() {
            return Ok(String::new());
        }
        let names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        let name = names.sent.get(slate).cloned().unwrap_or_default();
        wallet.send_to(slate, whom).map_err(|e| e.to_string())?;
        Ok(format!("payment {}: {name} is {}", short(slate), crate::address::encode(whom)))
    }

    /// Gives `label@name`, a name under a name this wallet holds, to
    /// the wallet at `to`: a certificate, sent to that wallet.
    fn subname_set(&self, full: &str, to: &str) -> Said {
        let (label, name) = crate::subnames::split(full).ok_or_else(|| format!("'{full}' is no label@name"))?;
        let holder = crate::address::decode(to).ok_or_else(|| format!("'{to}' is no address (tab1…)"))?;
        let mut wallet = self.wallet()?;
        let word = self.signs(&wallet, name)?;
        let unix = (self.unix)();
        let bundle = wallet
            .give_name(label.as_bytes(), name.as_bytes(), &holder, unix, word.as_deref())
            .map_err(|e| e.to_string())?;
        let own = holder == wallet.id();
        drop(wallet);
        let days = crate::subnames::HOLDS / 86_400;
        let done = format!("{full} is {to}, by a certificate that holds {days} days and is signed again daily");
        (self.log)(&format!("Name given: {done}"));
        match own {
            true => drop(self.given(&bundle)?),
            false => self.send_certificate(label.as_bytes(), name.as_bytes(), holder, bundle),
        }
        Ok(format!("{done}; sent to that wallet, which is the name once it has it"))
    }

    /// Whether this wallet signs for `name`: as the wallet the name
    /// says, with nothing more; or by the word of the wallet it says,
    /// which then goes with what is signed. An error if neither.
    fn signs(&self, wallet: &Wallet<W>, name: &str) -> Result<Option<Vec<u8>>, String> {
        let says = self.value_of(name)?;
        if says == wallet.id() {
            return Ok(None);
        }
        let unix = (self.unix)();
        let word = wallet.signs_for(name.as_bytes()).and_then(|word| {
            let read = crate::subnames::delegated(word, unix)?;
            (read.by == says && read.signer == wallet.id()).then(|| word.to_vec())
        });
        word.map(Some).ok_or_else(|| {
            format!(
                "{name} is not this wallet's to give names under: it says {}, this wallet is {}, and has no word of                  that wallet's that holds (subname signer FILE)",
                crate::address::encode(&says),
                wallet.address()
            )
        })
    }

    /// Says that the key of the wallet at `signer` signs for `name`,
    /// for `days` days: the word of this wallet, which holds the name,
    /// written to `file` for that wallet to take (`subname signer`).
    /// (Nothing is asked of the chain: a wallet kept where nothing can
    /// get at it has none. The word is the name's holder's if this
    /// wallet's address is what the name says.)
    fn subname_delegate(&self, name: &str, signer: &str, days: &str, file: &str) -> Said {
        if !crate::name::valid_name(name.as_bytes()) {
            return Err(format!("{name} is not a valid name"));
        }
        let to = crate::address::decode(signer).ok_or_else(|| format!("'{signer}' is no address (tab1…)"))?;
        let most = crate::subnames::MOST_HOLDS / 86_400;
        let days: u64 = days
            .parse()
            .ok()
            .filter(|d| (1..=most).contains(d))
            .ok_or_else(|| format!("'{days}' is not a number of days from 1 to {most}"))?;
        let wallet = self.wallet()?;
        let until = (self.unix)() + days * 86_400 - 1;
        let word = crate::subnames::delegate(&wallet.identity_key(), name.as_bytes(), &to, until);
        let done = format!(
            "for {days} days the key of {signer} signs for {name}, by the word of this wallet ({}): there is no              taking it back sooner, but by having the name say another address",
            wallet.address()
        );
        (self.log)(&format!("Name {name}: {done}"));
        std::fs::write(file, word).map_err(|e| format!("{file}: {e}"))?;
        Ok(format!("{done}. Written to {file}, for that wallet to take with: subname signer {file}"))
    }

    /// Takes the word of a name's holder that this wallet's key signs
    /// for the name.
    fn subname_signer(&self, file: &str) -> Said {
        let word = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        let unix = (self.unix)();
        let read = crate::subnames::delegated(&word, unix)
            .ok_or_else(|| format!("{file} is not the word of a name's holder, or is past its time"))?;
        let name = String::from_utf8_lossy(&read.name).to_string();
        let mut wallet = self.wallet()?;
        if read.signer != wallet.id() {
            return Err(format!(
                "{file} says the key of {} signs for {name}: this wallet is {}",
                crate::address::encode(&read.signer),
                wallet.address()
            ));
        }
        let says = self.value_of(&name)?;
        if says != read.by {
            return Err(format!(
                "{file} is the word of {}, and {name} says {}: not taken",
                crate::address::encode(&read.by),
                crate::address::encode(&says)
            ));
        }
        wallet.sign_for(read.name.as_slice(), &word).map_err(|e| e.to_string())?;
        let days = read.expires.saturating_sub(unix) as f64 / 86_400.0;
        let done = format!(
            "this wallet signs for {name} for {days:.1} days more, by the word of {}",
            crate::address::encode(&read.by)
        );
        (self.log)(&format!("Name {name}: {done}"));
        Ok(done)
    }

    fn send_certificate(&self, label: &[u8], name: &[u8], holder: crate::hash::Digest, bundle: Vec<u8>) {
        let tag = digest_to_bytes(&crate::subnames::point(label, name));
        self.hold.post(holder, crate::msg::KIND_NAME, tag, bundle, None);
    }

    /// Gives a name out no longer.
    fn subname_del(&self, full: &str) -> Said {
        let (label, name) = crate::subnames::split(full).ok_or_else(|| format!("'{full}' is no label@name"))?;
        match self.wallet()?.take_name_back(label.as_bytes(), name.as_bytes()).map_err(|e| e.to_string())? {
            true => Ok(format!(
                "{full} is given out no longer: its certificate is not signed again, and the last holds until its                  time is past (give the name to another wallet to end it at once)"
            )),
            false => Err(format!("{full} is not a name this wallet gave out")),
        }
    }

    /// Is a full name no longer.
    fn subname_drop(&self, full: &str) -> Said {
        let (label, name) = crate::subnames::split(full).ok_or_else(|| format!("'{full}' is no label@name"))?;
        let was = self.wallet()?.drop_name(label.as_bytes(), name.as_bytes()).map_err(|e| e.to_string())?;
        self.reached_by_names()?;
        match was {
            true => Ok(format!("this wallet is {full} no longer")),
            false => Err(format!("this wallet is not {full}")),
        }
    }

    /// The names given out, and the full names this wallet is.
    fn subnames(&self) -> Said {
        let wallet = self.wallet()?;
        let unix = (self.unix)();
        let days = |until: u64| format!("{:.1} days", until.saturating_sub(unix) as f64 / 86_400.0);
        let mut lines = Vec::new();
        for (n, _, bundle) in wallet.names_held() {
            match crate::subnames::read(&bundle, unix) {
                Some(c) => lines.push(format!(
                    "this wallet is {}, for {} more: reached by it at {} nodes",
                    c.full(),
                    days(c.expires),
                    self.hold.name_reached(&n)
                )),
                None => lines.push("a certificate past its time (it is this wallet's name no longer)".to_string()),
            }
        }
        for word in wallet.signs_for_all() {
            if let Some(read) = crate::subnames::delegated(&word, unix) {
                lines.push(format!(
                    "signs for {}, by the word of {}, for {} more",
                    String::from_utf8_lossy(&read.name),
                    crate::address::encode(&read.by),
                    days(read.expires)
                ));
            }
        }
        for given in wallet.names_given() {
            let to = crate::address::encode(&given.holder);
            lines.push(format!("given: {} is {to}, for {} more", given.full(), days(given.expires)));
        }
        match lines.is_empty() {
            true => Ok("no names under names: none given, and this wallet is none".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    /// A certificate has come that this wallet is a name under a name:
    /// kept, if it is the name's by the chain and names this wallet,
    /// and the wallet is not too many names already.
    fn given(&self, bundle: &[u8]) -> Said {
        let unix = (self.unix)();
        let checked = crate::subnames::read(bundle, unix).ok_or("what came is no certificate of a name")?;
        let full = checked.full();
        let says = self.value_of(&String::from_utf8_lossy(&checked.name))?;
        if says != checked.by {
            return Err(format!("a certificate of {full} that is not signed for whoever holds its name: not kept"));
        }
        let mut wallet = self.wallet()?;
        if checked.holder != wallet.id() {
            return Err(format!("a certificate of {full} that names another wallet: not kept"));
        }
        if !wallet.hold_name(&checked, bundle, self.max_names).map_err(|e| e.to_string())? {
            let held = wallet.names_held();
            let known = held.iter().any(|(n, seq, _)| *n == checked.point() && *seq >= checked.seq);
            return match known {
                true => Ok(String::new()),
                false => Err(format!(
                    "a certificate of {full} is not kept: this wallet is {} names already (subname drop one, or                      --max-names)",
                    held.len()
                )),
            };
        }
        drop(wallet);
        self.reached_by_names()?;
        let days = (checked.expires.saturating_sub(unix)) as f64 / 86_400.0;
        let done = format!("This wallet is {full}, by a certificate that holds {days:.1} days more");
        (self.log)(&done);
        Ok(done)
    }

    /// Tells the node which full names its wallet is to be reached by:
    /// those whose certificates hold now.
    pub fn reached_by_names(&self) -> Result<(), String> {
        let unix = (self.unix)();
        let held = self.wallet()?.names_held();
        let hold = held.into_iter().filter(|(_, _, bundle)| crate::subnames::read(bundle, unix).is_some());
        self.hold.set_names(hold.collect());
        Ok(())
    }

    /// Looks to the names given out: signs another certificate for
    /// each whose last was signed a day ago, and for each whose last
    /// did not reach its wallet, and sends it.
    pub fn renew_names(&self) -> Result<(), String> {
        let unix = (self.unix)();
        let again = std::mem::take(&mut self.names.lock().unwrap_or_else(|e| e.into_inner()).again);
        let mut wallet = self.wallet()?;
        let at = |g: &crate::wallet::Given| digest_to_bytes(&crate::subnames::point(&g.label, &g.name));
        let mut due = wallet.names_to_renew(unix);
        due.extend(wallet.names_given().into_iter().filter(|g| again.contains(&at(g))));
        for given in due {
            // (Only of a name this wallet still signs for.)
            let name = String::from_utf8_lossy(&given.name).to_string();
            let Ok(word) = self.signs(&wallet, &name) else { continue };
            let bundle = wallet
                .give_name(&given.label, &given.name, &given.holder, unix, word.as_deref())
                .map_err(|e| e.to_string())?;
            match given.holder == wallet.id() {
                true => drop(wallet.hold_name(
                    &crate::subnames::read(&bundle, unix).ok_or("no certificate")?,
                    &bundle,
                    usize::MAX,
                )),
                false => self.send_certificate(&given.label, &given.name, given.holder, bundle),
            }
        }
        drop(wallet);
        self.reached_by_names()
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

    /// What a name says, as it is written: an address (`tab1…`), or
    /// 64 hex digits; nothing, for `-`.
    fn value(text: &str) -> Result<crate::hash::Digest, String> {
        if text == "-" {
            return Ok([crate::poseidon2::Fp::ZERO; 8]);
        }
        if let Some(id) = crate::address::decode(text) {
            return Ok(id);
        }
        let bytes: Vec<u8> = match text.len() == 64 && text.is_ascii() {
            true => (0..32).filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect(),
            false => Vec::new(),
        };
        crate::poseidon2::digest_from_bytes(&bytes).filter(|_| bytes.len() == 32).ok_or_else(|| {
            format!("'{text}' is not what a name says: an address (tab1…), 64 hex digits, or - for nothing")
        })
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
