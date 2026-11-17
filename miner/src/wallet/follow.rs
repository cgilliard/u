//! The wallet following the chain: where its outputs are, as blocks
//! make them.
//!
//! After every change of the chain's last block the wallet is told of
//! the outputs of the blocks it has not looked at ([`follow`]): which of
//! them are its own, and where each is. Where the blocks cannot be gone
//! through one by one (the chain went over to another branch, or the
//! wallet has been away for longer than blocks' bodies are kept) it
//! looks through the unspent outputs for its own instead, by their
//! memos.

use super::{Wallet, WalletError};
use crate::block::BodyRef;
use crate::chain::Chain;
use crate::hash::Digest;
use crate::poseidon2::digest_to_bytes;
use crate::store::Backend;

/// What [`follow`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Followed {
    /// Blocks gone through, one by one.
    pub blocks: u32,
    /// Whether the unspent outputs were looked through instead.
    pub looked_through: bool,
    /// Outputs a restore's first scan found, and their total.
    pub found: (usize, u128),
}

/// Brings `wallet` up to `chain`'s last block, at `now`: nothing is done
/// where it is there already, or while the chain has no state to read.
pub fn follow<B: Backend + 'static, V, W: Backend>(
    chain: &Chain<B, V>,
    wallet: &mut Wallet<W>,
    now: u64,
) -> Result<Followed, WalletError> {
    let mut done = Followed::default();
    let Ok(state) = chain.whole() else { return Ok(done) };
    let snap = state.snapshot()?;
    let (height, tip) = snap.tip();
    let tip_bytes = digest_to_bytes(&tip);
    if wallet.synced() != Some((height, tip_bytes)) {
        // The blocks since the last looked at, if that one is still of
        // the chain: each with where its outputs begin. The newest
        // block's are the last before the next position, and each
        // block's before those of the one after it (its commits of
        // names taking the positions after its outputs).
        let on_chain = |h: u32, id: &[u8; 32]| {
            chain.header_at(h).ok().flatten().is_some_and(|header| digest_to_bytes(&header.hash()) == *id)
        };
        let from = match wallet.synced() {
            Some((h, id)) if h <= height && on_chain(h, &id) => Some(h + 1),
            // A wallet with nothing in it has nothing to find.
            None if wallet.outputs().is_empty() => Some(height + 1),
            _ => None,
        };
        let mut blocks: Vec<(u64, Vec<Digest>, u32, [u8; 32])> = Vec::new();
        let mut whole = from.is_some() && on_chain(height, &tip_bytes);
        let mut end = snap.outputs().next;
        for h in (from.unwrap_or(height + 1)..=height).rev() {
            let body = chain.header_at(h).ok().flatten().and_then(|header| {
                let id = header.hash();
                Some((id, chain.body(&id).ok().flatten()?))
            });
            let Some((id, body)) = body else {
                whole = false;
                break;
            };
            let Ok(body) = BodyRef::from_bytes(&body) else {
                whole = false;
                break;
            };
            let made: Vec<Digest> = body.outputs().map(|o| o.commitment).collect();
            let Some(first) = end.checked_sub((made.len() + body.commits()) as u64) else {
                whole = false;
                break;
            };
            blocks.push((first, made, h, digest_to_bytes(&id)));
            end = first;
        }
        if whole {
            for (first, made, h, id) in blocks.iter().rev() {
                wallet.locate(*first, made, *h, id)?;
                done.blocks += 1;
            }
            // (Nothing to go through: it is here all the same.)
            if blocks.is_empty() {
                wallet.locate(0, &[], height, &tip_bytes)?;
            }
        } else {
            wallet.relocate(&snap, now)?;
            wallet.locate(0, &[], height, &tip_bytes)?;
            done.looked_through = true;
        }
    }
    // A wallet restored from its phrase finds what is its own, once.
    if wallet.scan_pending() {
        done.found = wallet.scan(&snap, now)?;
        wallet.clear_scan_pending()?;
    }
    wallet.settle_sent(&snap)?;
    // Rewards of blocks found, once no reorganization reaches them:
    // done with if the block is the chain's, forgotten if it is not.
    let settled = chain.keep() as u32;
    for (c, h, block) in wallet.rewards() {
        if block != [0; 32] && height >= h.saturating_add(settled) {
            let on_chain = chain.header_at(h).ok().flatten().is_some_and(|x| digest_to_bytes(&x.hash()) == block);
            match on_chain {
                true => wallet.reward_settled(&c)?,
                false => drop(wallet.forget(&c)?),
            }
        }
    }
    Ok(done)
}

/// What the wallet has, against the chain's state as it is: nothing
/// while there is no state to read.
pub fn balance<B: Backend + 'static, V, W: Backend>(
    chain: &Chain<B, V>,
    wallet: &Wallet<W>,
) -> Result<super::Balance, WalletError> {
    let Ok(state) = chain.whole() else { return Ok(super::Balance::default()) };
    let snap = state.snapshot()?;
    wallet.balance(&snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::apply::tests::{extend_with, grow};
    use crate::chain::headers::tests::{easy, seed, table};
    use crate::chain::params::COIN;
    use crate::chain::verify::AcceptAllProofs;
    use crate::store::testing::MemBackend;

    const NOW: u64 = 1_800_000_000;

    fn chain() -> Chain<MemBackend, AcceptAllProofs> {
        let chain = Chain::open(MemBackend::new(), 64, easy(), seed(), AcceptAllProofs).unwrap();
        chain.set_dataset(table());
        chain
    }

    /// A wallet's outputs are confirmed when blocks make them, and it is
    /// told where they are whichever way it comes to know: block by
    /// block, or by looking through what is unspent.
    #[test]
    fn a_wallet_follows_the_chain() {
        let chain = chain();
        let mut wallet = Wallet::open(MemBackend::new()).unwrap().0;
        // A new wallet has nothing to find: it is where the chain is.
        grow(&chain, 3, 1);
        assert_eq!(follow(&chain, &mut wallet, NOW).unwrap(), Followed::default());
        assert_eq!(wallet.synced().map(|s| s.0), Some(3));
        // Blocks that pay it, and others between: gone through one by
        // one.
        let first = wallet.receive(1500 * COIN, NOW).unwrap();
        extend_with(&chain, &[first.block_output()]);
        grow(&chain, 2, 2);
        let second = wallet.receive(1500 * COIN, NOW).unwrap();
        extend_with(&chain, &[second.block_output()]);
        assert_eq!(balance(&chain, &wallet).unwrap().pending, 3000 * COIN as u128);
        assert_eq!(follow(&chain, &mut wallet, NOW).unwrap().blocks, 4);
        assert_eq!(balance(&chain, &wallet).unwrap().confirmed, 3000 * COIN as u128);
        assert_eq!(follow(&chain, &mut wallet, NOW).unwrap(), Followed::default());
        // A wallet that does not know how far it had looked looks
        // through what is unspent, and finds the same.
        let mut lost = Wallet::restore(MemBackend::new(), &wallet.phrase("").unwrap(), "", "").unwrap();
        let did = follow(&chain, &mut lost, NOW).unwrap();
        assert_eq!(did.found, (2, 3000 * COIN as u128));
        assert_eq!(balance(&chain, &lost).unwrap().confirmed, 3000 * COIN as u128);
        wallet.set_synced(None).unwrap();
        assert!(follow(&chain, &mut wallet, NOW).unwrap().looked_through);
        assert_eq!(balance(&chain, &wallet).unwrap().confirmed, 3000 * COIN as u128);
    }
}
