//! The durable, reorg-aware chain cursor (Annex M M.9.2).

use crate::events::BitcoinNetworkV1;

/// The observation cursor (M.9.2). It only advances inside the same
/// durable transaction that persists the derived events and outbox, so a
/// redelivery never duplicates an effect (property P11).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinChainCursorV1 {
    /// The network this cursor tracks.
    pub network: BitcoinNetworkV1,
    /// The tip block hash the cursor has reached.
    pub block_hash: [u8; 32],
    /// The tip height.
    pub height: u64,
    /// A rolling digest of the accepted header chain.
    pub header_chain_digest: [u8; 32],
    /// Monotonic revision; a regression is corruption.
    pub revision: u64,
}

impl BitcoinChainCursorV1 {
    /// The genesis cursor of a network (height 0, zero digest).
    #[must_use]
    pub fn genesis(network: BitcoinNetworkV1, genesis_hash: [u8; 32]) -> Self {
        Self {
            network,
            block_hash: genesis_hash,
            height: 0,
            header_chain_digest: [0u8; 32],
            revision: 0,
        }
    }
}
