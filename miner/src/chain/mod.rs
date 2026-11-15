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

pub mod params;
pub mod verify;
