// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains code to parse ZoKrates outputs.

use debs_datajson::{Fr, PublicKeyEdDSA};
use hash_sign::utils::bytes_to_field;

pub type PublicKey = PublicKeyEdDSA;

pub type HashPoseidon = Fr;

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

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct FlexibilityPoseidonPublicData {
    pub publicKey: PublicKey,
    pub msgsBefore: Vec<MessageMetadata>, // size N_BEFORE
    pub msgsAfter: Vec<MessageMetadata>,  // size N_AFTER
    pub difference: u64,                  // output
    pub sign: bool,                       // output
}

pub fn flexibility_poseidon_size(n_before: usize, n_after: usize) -> usize {
    PUBLIC_KEY_SIZE + MESSAGE_METADATA_SIZE * n_before + MESSAGE_METADATA_SIZE * n_after + 1 + 1
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct FlexibilityPoseidonNoSigPublicData {
    pub msgsBefore: Vec<MessageMetadata>, // size N_BEFORE
    pub msgsAfter: Vec<MessageMetadata>,  // size N_AFTER
    pub difference: u64,                  // output
    pub sign: bool,                       // output
    pub hashesBefore: Vec<HashPoseidon>,  // output, size N_BEFORE
    pub hashesAfter: Vec<HashPoseidon>,   // output, size N_AFTER
}

pub fn flexibility_poseidon_no_sig_size(n_before: usize, n_after: usize) -> usize {
    MESSAGE_METADATA_SIZE * n_before
        + MESSAGE_METADATA_SIZE * n_after
        + 1
        + 1
        + HASH_POSEIDON_SIZE * n_before
        + HASH_POSEIDON_SIZE * n_after
}

pub enum FlexibilityPublicData {
    Poseidon(FlexibilityPoseidonPublicData),
    PoseidonNoSig(FlexibilityPoseidonNoSigPublicData),
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
#[allow(dead_code)]
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

/// Parse bytes to a bool.
pub fn parse_bool(bytes: &[u8]) -> bool {
    // Last byte is the boolean value; the others must be 0.
    for b in &bytes[0..bytes.len() - 1] {
        assert_eq!(*b, 0);
    }
    let last_byte = bytes[bytes.len() - 1];
    if last_byte == 1 {
        true
    } else if last_byte == 0 {
        false
    } else {
        panic!("Invalid boolean value");
    }
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
    hash_sign::utils::bytes_to_field(bytes)
}
