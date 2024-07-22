use crate::hash::{SaltPoseidon, SaltSHA256};
use crate::utils::{int_to_field, uint_to_field};
use chrono::{DateTime, Utc};
use poseidon_rs::Fr;

/// A message with as payload a single u64 value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message ID.
    pub id: u64,
    /// Device ID.
    pub device_id: Vec<u8>,
    /// Timestamp (UNIX timestamp).
    pub timestamp: DateTime<Utc>,
    /// Value.
    pub value: u64,
}

pub trait SerializableMessage {
    fn to_bytes(&self) -> Vec<u8>;
    fn to_bytes_salted(&self, salt: &SaltSHA256) -> Vec<u8>;
    fn to_fields(&self) -> Vec<Fr>;
    fn to_fields_salted(&self, salt: &SaltPoseidon) -> Vec<Fr>;
}

impl SerializableMessage for Message {
    /// Serialize a message to bytes, e.g. to sign using SHA256, unsalted.
    ///
    /// This converts the message to 16 bytes: timestamp ++ value,
    /// where timestamp = 8 bytes (BE), value = 8 bytes (BE).
    fn to_bytes(&self) -> Vec<u8> {
        let timestamp: [u8; 8] = self.timestamp.timestamp().to_be_bytes();
        let value: [u8; 8] = self.value.to_be_bytes();
        let mut data = [0u8; 16];
        data[0..8].copy_from_slice(&timestamp);
        data[8..16].copy_from_slice(&value);
        // eprintln!("data: {:?}", data);
        data.to_vec()
    }

    /// Serialize a message to bytes, e.g. to sign using SHA256, with salt.
    ///
    /// This converts the message to 80 bytes: timestamp ++ value ++ salt,
    /// where timestamp = 8 bytes (BE), value = 8 bytes (BE), salt = 64 bytes.
    fn to_bytes_salted(&self, salt: &SaltSHA256) -> Vec<u8> {
        let timestamp: [u8; 8] = self.timestamp.timestamp().to_be_bytes();
        let value: [u8; 8] = self.value.to_be_bytes();
        let mut data = [0u8; 80];
        data[0..8].copy_from_slice(&timestamp);
        data[8..16].copy_from_slice(&value);
        data[16..80].copy_from_slice(salt);
        // eprintln!("data: {:?}", data);
        data.to_vec()
    }

    /// Serialize a message to fields, e.g. to sign using Poseidon, unsalted.
    ///
    /// Result = [timestamp, value]
    /// where timestamp = field, value = field.
    fn to_fields(&self) -> Vec<Fr> {
        let timestamp: Fr = int_to_field(self.timestamp.timestamp());
        let value: Fr = uint_to_field(self.value);
        [timestamp, value].to_vec()
    }

    /// Serialize a message to fields, e.g. to sign using Poseidon, with salt.
    ///
    /// Result = [timestamp, value, salt[0], salt[1], salt[2], salt[3]]
    /// where timestamp = field, value = field, salt = 4 fields.
    fn to_fields_salted(&self, salt: &SaltPoseidon) -> Vec<Fr> {
        let timestamp: Fr = int_to_field(self.timestamp.timestamp());
        let value: Fr = uint_to_field(self.value);
        [timestamp, value, salt[0], salt[1], salt[2], salt[3]].to_vec()
    }
}
