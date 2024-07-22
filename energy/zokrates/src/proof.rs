//! This module contains code to parse ZoKrates outputs.

use datajson::{utils::bytes_to_field, Fr, PublicKeyEdDSA};

pub type PublicKey = PublicKeyEdDSA;

pub type HashSHA256 = Vec<u8>;
pub type HashPoseidon = Fr;

#[derive(Clone, Debug)]
pub enum Hash {
    Sha256(HashSHA256),
    Poseidon(HashPoseidon),
}

#[derive(Clone, Copy, Debug)]
pub struct MessageMetadata {
    /// Device's ID
    pub device_id: u64,
    /// Message ID
    pub message_id: u64,
    /// UNIX timestamp
    pub timestamp: u64,
}

pub const PUBLIC_KEY_SIZE: usize = 2; // 2 points in the field
pub const MESSAGE_METADATA_SIZE: usize = 3;
pub const HASH_POSEIDON_SIZE: usize = 1;
pub const HASH_SHA256_SIZE: usize = 8;

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct HistoricalPoseidonPublicData {
    pub publicKey: PublicKey,
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub avg: u64,                   // private output
    pub avg_hashed: HashPoseidon,   // output
}

pub fn historical_poseidon_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + 1 + MESSAGE_METADATA_SIZE * n_messages + 1 + HASH_POSEIDON_SIZE
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct HistoricalPoseidonNoSigPublicData {
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub avg: u64,                   // private output
    pub avg_hashed: HashPoseidon,   // output
    pub hashes: Vec<HashPoseidon>,  // output, size MAX_N_MESSAGES
}

pub fn historical_poseidon_no_sig_size(n_messages: usize) -> usize {
    1 + MESSAGE_METADATA_SIZE * n_messages
        + 1
        + HASH_POSEIDON_SIZE
        + HASH_POSEIDON_SIZE * n_messages
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct HistoricalSha256PublicData {
    pub publicKey: PublicKey,
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub avg: u64,                   // private output
    pub avg_hashed: HashSHA256,     // output
}

pub fn historical_sha256_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + 1 + MESSAGE_METADATA_SIZE * n_messages + 1 + HASH_SHA256_SIZE
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct HistoricalSha256NoSigPublicData {
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub avg: u64,                   // private output
    pub avg_hashed: HashSHA256,     // output
    pub hashes: Vec<HashSHA256>,    // output, size MAX_N_MESSAGES
}

pub fn historical_sha256_no_sig_size(n_messages: usize) -> usize {
    1 + MESSAGE_METADATA_SIZE * n_messages + 1 + HASH_SHA256_SIZE + HASH_SHA256_SIZE * n_messages
}

pub enum HistoricalPublicData {
    Poseidon(HistoricalPoseidonPublicData),
    PoseidonNoSig(HistoricalPoseidonNoSigPublicData),
    Sha256(HistoricalSha256PublicData),
    Sha256NoSig(HistoricalSha256NoSigPublicData),
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Challenge1PoseidonPublicData {
    pub publicKey: PublicKey,
    pub nHistorical: u32,
    pub historicalHashes: Vec<HashPoseidon>, // size MAX_N_HISTORICAL
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub result: u64,                // output
}

pub fn challenge1_poseidon_size(n_historical: usize, n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE
        + 1
        + HASH_POSEIDON_SIZE * n_historical
        + 1
        + MESSAGE_METADATA_SIZE * n_messages
        + 1
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Challenge1PoseidonNoSigPublicData {
    pub nHistorical: u32,
    pub historicalHashes: Vec<HashPoseidon>, // size MAX_N_HISTORICAL
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub result: u64,                // output
    pub hashes: Vec<HashPoseidon>,  // output, size MAX_N_MESSAGES
}

pub fn challenge1_poseidon_no_sig_size(n_historical: usize, n_messages: usize) -> usize {
    1 + HASH_POSEIDON_SIZE * n_historical
        + 1
        + MESSAGE_METADATA_SIZE * n_messages
        + 1
        + HASH_POSEIDON_SIZE * n_messages
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Challenge1Sha256PublicData {
    pub publicKey: PublicKey,
    pub nHistorical: u32,
    pub historicalHashes: Vec<HashSHA256>, // size MAX_N_HISTORICAL
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub result: u64,                // output
}

pub fn challenge1_sha256_size(n_messages: usize, n_historical: usize) -> usize {
    PUBLIC_KEY_SIZE
        + 1
        + HASH_SHA256_SIZE * n_historical
        + 1
        + MESSAGE_METADATA_SIZE * n_messages
        + 1
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Challenge1Sha256NoSigPublicData {
    pub nHistorical: u32,
    pub historicalHashes: Vec<HashSHA256>, // size MAX_N_HISTORICAL
    pub nMessages: u32,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub result: u64,                // output
    pub hashes: Vec<HashSHA256>,    // output, size MAX_N_MESSAGES
}

pub fn challenge1_sha256_no_sig_size(n_messages: usize, n_historical: usize) -> usize {
    1 + HASH_SHA256_SIZE * n_historical
        + 1
        + MESSAGE_METADATA_SIZE * n_messages
        + 1
        + HASH_SHA256_SIZE * n_messages
}

pub enum Challenge1PublicData {
    Poseidon(Challenge1PoseidonPublicData),
    PoseidonNoSig(Challenge1PoseidonNoSigPublicData),
    Sha256(Challenge1Sha256PublicData),
    Sha256NoSig(Challenge1Sha256NoSigPublicData),
}

/// Decode a hex string into vector of bytes.
pub fn decode_hex(hex: &str) -> Vec<u8> {
    if hex.starts_with("0x") {
        hex::decode(&hex[2..]).unwrap()
    } else {
        hex::decode(hex).unwrap()
    }
}

/// Parse bytes to a u32.
pub fn parse_u32(bytes: &[u8]) -> u32 {
    let i = bytes.len() - 4;
    for b in &bytes[0..i] {
        assert_eq!(*b, 0);
    }
    u32::from_be_bytes(bytes[i..].try_into().unwrap())
}

/// Parse bytes to a u64.
pub fn parse_u64(bytes: &[u8]) -> u64 {
    let i = bytes.len() - 8;
    for b in &bytes[0..i] {
        assert_eq!(*b, 0);
    }
    u64::from_be_bytes(bytes[i..].try_into().unwrap())
}

/// Parse bytes that encode a public key (= 2 fields).
pub fn parse_public_key(fields: &[Vec<u8>]) -> PublicKey {
    assert_eq!(fields.len(), PUBLIC_KEY_SIZE);
    let x = bytes_to_field(&fields[0]);
    let y = bytes_to_field(&fields[1]);
    PublicKeyEdDSA(babyjubjub_rs::Point { x, y })
}

/// Parse bytes that encode a Poseidon hash (= 1 field).
pub fn parse_hash_poseidon(bytes: &[u8]) -> HashPoseidon {
    datajson::utils::bytes_to_field(bytes)
}

/// Parse bytes that encode a SHA256 hash (= 8 * u32).
pub fn parse_hash_sha256(parts: &[Vec<u8>]) -> HashSHA256 {
    assert_eq!(parts.len(), HASH_SHA256_SIZE);
    let mut hash = Vec::new();
    for part in parts {
        hash.extend_from_slice(part);
    }
    hash
}
