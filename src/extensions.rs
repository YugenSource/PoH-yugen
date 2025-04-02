#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extensions {
    TickHasher, // Used for hashing the ticks
    Breaker, // Used for breaking the ticks
    MerkleTree, // Used for creating the merkle tree
    
    // Timestamps
    Timestamp, // Used for adding timestamps to the ticks
    TimestampRFC3339, // Used for adding RFC3339 timestamps to the ticks

    // Milestones
    Milestone, // Used for creating milestones in the PoH process
}