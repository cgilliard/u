//! The chain: which blocks are valid, and which of them make it.
//!
//! The store ([`crate::store`]) keeps the state and the blocks and knows
//! nothing of what they mean. This is what they mean: the rules a header
//! and a block are held to, the work that chooses between branches, and
//! what a block's proof is asked to show.
//!
//! - [`params`]: a network's fixed numbers, what a block pays, and
//!   genesis.
//! - [`verify`]: the statement a block's proof attests to, and who
//!   checks it.
//! - [`headers`]: the rules of a header, and the headers a node keeps
//!   ahead of the blocks it has.
//!
//! A [`Chain`] is a store with a network's rules over it.

pub mod headers;
pub mod params;
pub mod verify;

use std::sync::{Arc, Mutex, RwLock};

use crate::block::Header;
use crate::error::Error;
use crate::hash::Digest;
use crate::pow::{Dataset, SeedText};
use crate::store::backend::Backend;
use crate::store::state::State;
use crate::u256::U256;
use headers::{Known, Status};
use params::ChainParams;

/// A network's chain, in a store.
pub struct Chain<B: Backend + 'static, V> {
    state: State<B>,
    params: ChainParams,
    seed: SeedText<'static>,
    verifier: V,
    /// A table of the proof of work, if one is loaded: a header's work is
    /// checked against it in microseconds, where from the seed text
    /// alone it takes tens of milliseconds.
    dataset: RwLock<Option<Arc<Dataset<'static>>>>,
    /// A header and block 1 of its branch, as last found: where a
    /// schedule that starts at the first block is anchored.
    anchor: Mutex<Option<(Digest, Header)>>,
    /// Heights whose full proof of work was checked, for the tests.
    #[cfg(test)]
    pub(crate) full_pow_heights: Mutex<Vec<u32>>,
}

impl<B: Backend + 'static, V> Chain<B, V> {
    /// Opens the chain kept in `backend`, or begins it: an empty store
    /// is given the network's genesis. A store that holds another
    /// genesis is refused ([`Error::WrongGenesis`]). `keep` is how many
    /// blocks can be undone ([`crate::store::state`]); `seed` must be the
    /// text of `params.pow`.
    pub fn open(
        backend: B,
        keep: usize,
        params: ChainParams,
        seed: SeedText<'static>,
        verifier: V,
    ) -> Result<Self, Error> {
        assert_eq!(*seed.params(), params.pow, "the seed text is the network's");
        let state = State::open(backend, keep)?;
        let genesis = params.genesis().header;
        let id = genesis.hash();
        let there = {
            let snap = state.snapshot()?;
            snap.blocks().at(snap.pages(), 0)?
        };
        match there {
            Some(found) if found == id => {}
            Some(_) => return Err(Error::WrongGenesis),
            None => state.write_blocks(|txn, blocks| {
                let known = Known { header: genesis, work: U256::ZERO, status: Status::Valid };
                blocks.put_entry(txn, &known.entry())?;
                blocks.set_at(txn, 0, Some(id))
            })?,
        }
        Ok(Chain {
            state,
            params,
            seed,
            verifier,
            dataset: RwLock::new(None),
            anchor: Mutex::new(None),
            #[cfg(test)]
            full_pow_heights: Mutex::new(Vec::new()),
        })
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    /// The store beneath.
    pub fn state(&self) -> &State<B> {
        &self.state
    }

    /// Gives the chain a table of the proof of work to check headers
    /// against. It is used for the heights it is the table of.
    pub fn set_dataset(&self, dataset: Arc<Dataset<'static>>) {
        *self.dataset.write().unwrap() = Some(dataset);
    }
}
