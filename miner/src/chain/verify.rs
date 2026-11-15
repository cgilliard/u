//! What a block's proof is asked to show, and who checks it.
//!
//! A node checks of a block what it can see: the header's rules, the
//! body's form, that what the block spends is there, the state root, the
//! supply. What it cannot see (that the spenders hold the keys, that no
//! transaction makes coins, that a name's owner signed its update) the
//! block's proof attests to. The [`BlockStatement`] is the public side
//! of that: everything the proof is about, taken from the chain and the
//! block, none of it from the prover.
//!
//! The chain is written against [`ProofVerifier`], so it stands without
//! the circuits: with [`AcceptAllProofs`] every rule but the proof's is
//! checked, which is how the chain's own tests run.

use crate::block::BodyRef;
use crate::hash::Digest;
use crate::pow_air::Work;

/// Statement a block's proof must attest to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockStatement<'a> {
    pub height: u32,
    pub prev_state_root: Digest,
    pub new_state_root: Digest,
    /// Position of the first output appended by this block. With the
    /// outputs and commits of the body it gives the position after the
    /// last, so the proofs of a chain's blocks say how many outputs
    /// there have been: what a node that takes its state from others
    /// has no other way to know.
    pub first_output_position: u64,
    /// Subsidy the block may create.
    pub subsidy: u64,
    /// The body, as the block carries it: read where it lies.
    pub body: BodyRef<'a>,
    /// The parent header's work, which the block's proof proves.
    pub parent_work: Work,
    /// The parent header's hash (the block's `prev_hash`).
    pub parent_hash: Digest,
}

/// Verifies a block's validity proof. The real implementation is the STARK
/// verifier for the block circuit.
pub trait ProofVerifier {
    fn verify(&self, statement: &BlockStatement<'_>, proof: &[u8]) -> bool;

    /// Debugging only: whether proofs go unchecked.
    fn is_unchecked(&self) -> bool {
        false
    }
}

/// Accepts every proof. For development and tests only; a node using this
/// trusts block producers completely.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllProofs;

impl ProofVerifier for AcceptAllProofs {
    fn verify(&self, _: &BlockStatement<'_>, _: &[u8]) -> bool {
        true
    }

    fn is_unchecked(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Body;
    use crate::poseidon2::Fp;

    /// A verifier that reads the statement: the trait is usable as one
    /// object, by reference, with a body read in place.
    struct OnlyEmptyBlocks;

    impl ProofVerifier for OnlyEmptyBlocks {
        fn verify(&self, statement: &BlockStatement<'_>, proof: &[u8]) -> bool {
            statement.body.inputs().len() == 0 && proof.is_empty()
        }
    }

    #[test]
    fn a_statement_is_checked_by_whoever_is_asked() {
        let bytes = Body::default().to_bytes();
        let body = BodyRef::from_bytes(&bytes).unwrap();
        let d = |x: u32| -> Digest { [Fp::new(x); 8] };
        let statement = BlockStatement {
            height: 7,
            prev_state_root: d(1),
            new_state_root: d(2),
            first_output_position: 40,
            subsidy: 50,
            body,
            parent_work: Work { pow_hash: d(3), nonce: [4; 32], mix: d(5), log_items: 10 },
            parent_hash: d(6),
        };
        assert_eq!(statement, statement.clone());
        let verifiers: [&dyn ProofVerifier; 2] = [&AcceptAllProofs, &OnlyEmptyBlocks];
        assert!(verifiers.iter().all(|v| v.verify(&statement, &[])));
        assert!(AcceptAllProofs.verify(&statement, &[1, 2, 3]));
        assert!(!OnlyEmptyBlocks.verify(&statement, &[1]));
        assert!(AcceptAllProofs.is_unchecked() && !OnlyEmptyBlocks.is_unchecked());
    }
}
