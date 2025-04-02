use chrono::Utc;

/// Represents a timestamp in the PoH (Proof of History) process.


pub fn get_current_timestamp_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub fn get_current_timestamp() -> u64 {
    return Utc::now().timestamp() as u64;
}