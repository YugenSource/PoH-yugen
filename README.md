# PoH-yugen (Proof-of-History Implementation)

**Author:** @silene0259

**Date:** 2024-03-23

## Description

**Proof-of-History** offers a realistic way of measuring time using **hash functions** and **ticks** (time intervals). `PoH-yugen` features advanced features like custom configuration including:

* Interval Choosing (Ticks)
* Max Entries (Number of Ticks Per Slot)
* Generic Hash Functions (any that use the `digest` trait)
* Appending Data Per Tick
* Seeding
* Other Advanced Features

## Usage

```rust
use poh_yugen::{PoHConfig,PoHUsage,InitialSeed,TickEntryType};
use sha2::Sha256;

fn main() {
    let config = PoHConfig::new(Sha256::new(), 32, 10, Some(1000), true, true, TickEntryType::Data);
    let seed = InitialSeed([0; 64]);
    let mut poh = PoHUsage::new(config, seed, Some(vec![1, 2, 3]), vec![]);
    println!("{:?}", poh.state);
    println!("Initializing PoH...");
    // Initialize the PoH process
    poh.init();
}


```
