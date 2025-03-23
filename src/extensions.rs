#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extensions {
    TickHasher, // Used for hashing the ticks
    Breaker, // Used for breaking the ticks
    MerkleTree, // Used for creating the merkle tree
}