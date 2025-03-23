
// SPDX-License-Identifier: Apache-2.0

//! This module provides the data structures and functions for the Proof of History (PoH) algorithm.
//! The PoH algorithm is a cryptographic primitive that allows for the generation
//! of a verifiable and tamper-proof history of events. It is used in various
//! blockchain systems to provide a secure and efficient way to order transactions
//! and events in a distributed network.
//! 

// Digestis used for hashing and cryptographic operations.
// The `digest` crate provides a variety of hashing algorithms and utilities
use digest::{Digest,Output,OutputSizeUser};
use sha2::Sha256;


pub mod extensions;

pub trait Seedable {
    /// Generates a new seed for the Proof of History (PoH) algorithm.
    /// This function should be implemented to provide a cryptographically
    /// secure random seed that can be used to initialize the PoH process.
    fn generate_seed() -> [u8; 64];
    fn get_seed(&self) -> [u8; 64];
    fn set_seed(&mut self, seed: [u8; 64]);
}

pub trait EventData {
    /// Generates a hash for the given event data.
    /// This function should be implemented to provide a secure hash
    /// of the event data, which can be used to verify the integrity
    /// of the PoH entries.
    fn hash_event_data(data: &[u8]) -> [u8; 32];
}


/// Initial seed for the Proof of History (PoH) algorithm.
/// This seed is used to initialize the PoH process and is typically derived
/// from a known source of entropy, such as the system's random number generator.
/// The seed is a 64-byte array, which provides sufficient entropy for the PoH algorithm.
/// The seed is used to generate the initial state of the PoH, which is then
/// updated with each tick of the PoH clock.
/// The seed is crucial for ensuring the security and unpredictability of the PoH process.
/// It is important to keep the seed secret and secure, as it directly affects
/// the integrity of the PoH output.
/// The seed should be generated using a cryptographically secure random number generator
/// to ensure that it is unpredictable and resistant to attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InitialSeed(pub [u8; 64]);

/// Appended Data for the Proof of History (PoH) algorithm.
/// This structure is used to store additional data that is appended to the PoH entries.
/// The appended data can be used to include metadata or other information
/// that is relevant to the PoH process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppendedData {
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventHash {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoHConfig<D: Digest + Clone> {
    /// The hasher used for the Proof of History (PoH) algorithm.
    /// This hasher is responsible for generating the cryptographic hashes
    /// for the PoH entries and for verifying the integrity of the PoH process.
    /// The hasher should be a cryptographic hash function that is suitable
    /// for use in the PoH algorithm, such as SHA-256 or SHA-512.
    /// The hasher should be chosen based on the desired security level
    /// and performance requirements of the PoH process.
    /// The hasher should be implemented using the `digest` crate,
    /// which provides a variety of hashing algorithms and utilities.
    /// The hasher should be initialized with a secure random seed
    /// to ensure that the PoH process is unpredictable and resistant to attacks.
    /// The hasher should be able to produce a fixed-size output, typically 32 or 64 bytes,
    /// depending on the chosen hashing algorithm.
    /// The hasher should be able to process input data of arbitrary length
    /// and produce a hash output that is unique to the input data.
    /// The hasher should be able to handle collisions and produce a unique
    /// hash output for different input data.
    /// The hasher should be able to produce a hash output that is resistant
    /// to pre-image and second pre-image attacks, ensuring the integrity
    /// and security of the PoH process.
    /// The hasher should be able to produce a hash output that is collision-resistant,
    /// ensuring that it is computationally infeasible to find two different
    /// input data that produce the same hash output.
    /// The hasher should be able to produce a hash output that is secure
    /// against length extension attacks, ensuring that it is computationally
    /// infeasible to find a valid hash output for a modified input data
    /// without knowing the original input data.
    /// The hasher should be able to produce a hash output that is secure
    /// against chosen-prefix attacks, ensuring that it is computationally
    /// infeasible to find two different input data that produce the same
    /// hash output when the prefix of the input data is known.
    /// The hasher should be able to produce a hash output that is secure
    /// against birthday attacks, ensuring that it is computationally infeasible
    /// to find two different input data that produce the same hash output
    /// when the length of the input data is known.
    /// The hasher should be able to produce a hash output that is secure
    /// against length extension attacks, ensuring that it is computationally
    /// infeasible to find a valid hash output for a modified input data
    /// without knowing the original input data.
    pub hasher: D,
    /// The size of the output produced by the PoH algorithm.
    /// This value determines the length of the hash output generated by
    /// the PoH process. The output size is typically measured in bytes
    /// and should be chosen based on the desired security level and
    /// performance requirements of the PoH process.
    /// A common value for the output size is 32 bytes (256 bits) for SHA-256
    /// or 64 bytes (512 bits) for SHA-512. The output size should be
    /// set to a positive value to ensure that the PoH process can generate
    /// a valid hash output. A value of 0 indicates that the PoH process
    /// should not produce any output and the PoH state should remain empty
    /// until the next entry is added. The output size should be chosen
    /// based on the specific requirements of the application and the
    /// capabilities of the underlying hardware.
    pub output_size: usize,
    /// The interval in ticks for the PoH algorithm.
    /// This value determines how often the PoH clock ticks and updates the state.
    /// A smaller value results in more frequent updates, while a larger value
    /// results in less frequent updates. The ticks interval should be chosen
    /// based on the desired granularity of the PoH process and the performance
    /// requirements of the system.
    /// The ticks interval is typically measured in milliseconds or microseconds,
    /// depending on the desired resolution of the PoH clock.
    /// A common value for the ticks interval is 1000 microseconds (1 millisecond),
    /// which provides a good balance between performance and granularity.
    /// The ticks interval should be chosen based on the specific requirements
    /// of the application and the capabilities of the underlying hardware.
    /// A value of 0 indicates that the PoH clock should not tick, and the PoH
    /// process should be paused until the next tick is triggered.
    /// The ticks interval should be set to a positive value to ensure that
    /// the PoH process continues to run and update the state.
    /// A value of 1 indicates that the PoH clock should tick once per microsecond,
    pub tick_interval: u64,
    /// The maximum number of entries allowed in the PoH.
    /// This value determines the maximum size of the PoH state and the
    /// maximum number of entries that can be generated by the PoH algorithm.
    /// A smaller value results in a smaller PoH state and fewer entries,
    /// while a larger value results in a larger PoH state and more entries.
    /// The maximum entries value should be chosen based on the desired
    /// capacity of the PoH process and the performance requirements of the system.
    /// The maximum entries value is typically measured in bytes or kilobytes,
    /// depending on the desired size of the PoH state and the number of entries.
    /// A common value for the maximum entries is 1000, which provides a good
    /// balance between capacity and performance.
    /// The maximum entries value should be set to a positive value to ensure
    /// that the PoH process can generate entries and update the state.
    /// A value of None indicates that there is no limit on the number of entries
    /// and the PoH process can continue to generate entries until it is stopped.
    /// A value of 0 indicates that the PoH process should not generate any entries
    /// and the PoH state should remain empty until the next entry is added.
    pub max_entries: Option<usize>,
    /// Flags to control the behavior of the PoH algorithm.
    /// These flags determine whether data entries and empty entries are allowed
    /// in the PoH process. The allow_data_entries flag indicates whether
    /// data entries can be added to the PoH, while the allow_empty_entries
    /// flag indicates whether empty entries can be added to the PoH.
    /// The allow_data_entries flag should be set to true if the PoH process
    /// should allow data entries to be added, and false if only empty entries
    /// should be allowed.
    pub allow_data_entries: bool,
    pub allow_empty_entries: bool,

    /// The type of entry to be used in the PoH process.
    /// This value determines the type of data that can be appended to the PoH entries.
    /// The tic_entry_type value should be set to one of the following types:
    /// - Data: Indicates that the PoH process should allow data entries to be added.
    /// - Empty: Indicates that the PoH process should allow empty entries to be added.
    /// - UTF8String: Indicates that the PoH process should allow UTF-8 string entries to be added.
    /// - Hash(usize): Indicates that the PoH process should allow hash entries of a specified size to be added.
    /// The tic_entry_type value should be set to a valid TicEntryType value
    /// to ensure that the PoH process can generate entries and update the state.
    pub tick_entry_type: TickEntryType,

}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TickEntryType {
    Data,
    Empty,
    ByteString,
    UTF8String,
    Hash(usize),
    /// Event hash types for different sizes
    EventHash28,
    EventHash32,
    EventHash48,
    EventHash64,
}

impl<D: Digest + Clone> PoHConfig<D> {
    pub fn new(digest: D, output_size: usize, tick_interval: u64, max_entries: Option<usize>, allow_data_entries: bool, allow_empty_entries: bool, tick_entry_type: TickEntryType) -> Self {
        Self {
            // Hasher used for the PoH algorithm with variable output size
            hasher: digest,
            output_size: output_size,

            tick_interval,
            max_entries,
            
            allow_data_entries,
            allow_empty_entries,
            tick_entry_type,
        }
    }
}

/* 
impl<D: Digest + Clone> Clone for PoHConfig<D> {
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
            output_size: self.output_size,
            tick_interval: self.tick_interval,
            max_entries: self.max_entries,
            allow_data_entries: self.allow_data_entries,
            allow_empty_entries: self.allow_empty_entries,
            tick_entry_type: self.tick_entry_type,
        }
    }
}
*/

/// Proof of History (PoH) usage structure.
/// This structure encapsulates the configuration and functionality
/// of the Proof of History (PoH) algorithm.
/// It provides methods for generating and verifying PoH entries,
/// as well as for managing the PoH state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoHUsage<D: Digest + Clone> {
    id: u64,
    config: PoHConfig<D>,
    state: Vec<PoHEntry>, // Holds the PoH entries
    extensions: Vec<extensions::Extensions>, // Holds any extensions for the PoH process
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoHEntry {
    pub hash: Vec<u8>, // The hash of the PoH entry
    pub appended_data: Option<AppendedData>,
}

impl<D: Digest + Clone> PoHUsage<D> {
    pub fn new(config: PoHConfig<D>, seed: InitialSeed, init_data: Option<Vec<u8>>, extensions: Vec<extensions::Extensions>) -> Self {
        // Appended Data is initialized to None, as it will be created if init_data is provided
        let mut appended_data = None;

        // Initialize the PoH with the provided seed
        let mut hasher = config.hasher.clone();
        hasher.update(seed.0);
        
        // If there is initial data, hash it and create an AppendedData instance
        if init_data.is_some() {
            hasher.update(init_data.clone().unwrap());
            appended_data = Some(AppendedData::new(init_data.unwrap().to_vec()));
        }
        let output = hasher.finalize();

        Self { 
            id: 0, 
            config: config, 
            state: vec![PoHEntry { hash: output.to_vec(), appended_data: appended_data }], 
            extensions,
        }
    }
    pub fn get_id(&self) -> u64 {
        self.id
    }
    pub fn get_config(&self) -> &PoHConfig<D> {
        &self.config
    }
    pub fn init(&mut self) {
        let initial_state = self.state[0].hash.clone();
        let interval = self.config.tick_interval;
        let max_entries = self.config.max_entries.unwrap_or(1000); // Default to 1000 if None

        
        let mut output_of_previous_tick: Vec<u8> = initial_state;
        for _ in 0..max_entries {
            for _ in 0..interval {
                let mut hasher = self.config.hasher.clone();
                hasher.update(output_of_previous_tick);
                let output = hasher.finalize();
                output_of_previous_tick = output.to_vec();
            }
            // Create a new PoH entry with the output of the previous tick
            let new_entry = PoHEntry {
                hash: output_of_previous_tick.clone(),
                appended_data: None, // No appended data for now
            };
            self.state.push(new_entry);
            // Print the output of the previous tick
            println!("Output after {} ticks: {:?}", interval, hex::encode(output_of_previous_tick.clone()));
        }
    }
    pub fn get_state(&self) -> &Vec<PoHEntry> {
        &self.state
    }

}


impl PoHEntry {
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.hash)
    }
}

// Appended Data implementation

impl AppendedData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

#[test]
fn run() {
    let config = PoHConfig::new(Sha256::new(), 32, 1000, Some(1000), true, true, TickEntryType::Data);
    let seed = InitialSeed([0; 64]);
    let mut poh = PoHUsage::new(config, seed, Some(vec![1, 2, 3]), vec![]);
    println!("{:?}", poh.state);
    println!("Initializing PoH...");
    // Initialize the PoH process
    poh.init();

}