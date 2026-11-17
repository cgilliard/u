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
use crate::net::node::Handle;
use crate::poseidon2::digest_to_bytes;
use crate::store::Backend;
use crate::wallet::{Fee, Slate, State, Wallet, follow};

/// What the prompt says its commands are.
pub const HELP: &str = "commands:
  status                    the chain's last block, peers, the pool, the wallet's total
  peers                     how many peers are known, and how many are live
  mempool                   the transactions waiting to be mined
  balance                   confirmed, pending, unverified, reserved and locked funds
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
  cancel ID                 give up a payment begun (ID: the first digits of its id),
                            freeing what it was to spend
  scan                      find this wallet's outputs on the chain (after a restore)
  help                      this
  quit                      stop the node";

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
            ("balance", []) => self.balance(),
            ("outputs", []) => self.outputs(),
            ("send-file", [amount, file]) => self.send_file(amount, None, file),
            ("send-file", [amount, fee, file]) => self.send_file(amount, Some(fee), file),
            ("receive", [file]) => self.receive(file, &format!("{file}.received")),
            ("receive", [file, out]) => self.receive(file, out),
            ("finalize", [file]) => self.finalize(file),
            ("slates", []) => self.slates(),
            ("cancel", [id]) => self.cancel(id),
            ("scan", []) => self.scan(),
            (
                "status" | "peers" | "mempool" | "balance" | "outputs" | "send-file" | "receive" | "finalize"
                | "slates" | "cancel" | "scan" | "help" | "quit" | "exit",
                _,
            ) => Err(format!("{command}: not what it takes (see help)")),
            _ => Err(format!("{command}: no such command (see help)")),
        };
        match said {
            Ok(text) => Reply::Said(text),
            Err(text) => Reply::Wrong(text),
        }
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
        let mut out = format!("confirmed   {}", coins(b.confirmed));
        for (what, amount) in
            [("pending", b.pending), ("unverified", b.unverified), ("reserved", b.reserved), ("locked", b.locked)]
        {
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

    fn send_file(&self, amount: &str, fee: Option<&&str>, file: &str) -> Said {
        let amount = parse_coins(amount).ok_or_else(|| format!("'{amount}' is not an amount of coins"))?;
        let fee = match fee {
            None => Fee::from(None),
            Some(text) => match text.strip_suffix("/byte") {
                Some(rate) => Fee::PerByte(rate.parse().map_err(|_| format!("'{text}' is not a fee"))?),
                None => Fee::Total(parse_coins(text).ok_or_else(|| format!("'{text}' is not a fee"))?),
            },
        };
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let slate = wallet.send(amount, fee, &snap, (self.unix)()).map_err(|e| e.to_string())?;
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

    fn cancel(&self, id: &str) -> Said {
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
            [] => Err(format!("no payment begun with an id that starts {id}")),
            _ => Err(format!("more than one payment begun with an id that starts {id}")),
        }
    }

    fn scan(&self) -> Said {
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let (found, total) = wallet.scan(&snap, (self.unix)()).map_err(|e| e.to_string())?;
        Ok(format!("{} outputs found that were not known, {} in all", commas(found as u64), coins(total)))
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
