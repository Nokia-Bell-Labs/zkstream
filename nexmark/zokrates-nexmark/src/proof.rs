// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains code to parse ZoKrates outputs.

#![allow(non_snake_case)]

use hash_sign::utils::bytes_to_field;
use nexmark_datajson::{Fr, PublicKeyEdDSA};

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

#[derive(Clone, Debug)]
pub struct Q1PoseidonPublicData {
    pub publicKey: PublicKey,
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub outputs: Vec<u64>,          // output, size N_MESSAGES
}

pub fn q1_poseidon_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + MESSAGE_METADATA_SIZE * n_messages + n_messages
}

pub fn read_q1_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q1PoseidonPublicData {
    assert_eq!(inputs.len(), q1_poseidon_size(n_messages));
    let publicKey = drain_public_key(inputs);
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let outputs = drain_u64s_from_inputs(inputs, n_messages);
    assert!(inputs.is_empty());
    Q1PoseidonPublicData {
        publicKey,
        msgs,
        outputs,
    }
}

#[derive(Clone, Debug)]
pub struct Q1PoseidonNoSigPublicData {
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub outputs: Vec<u64>,          // output, size N_MESSAGES
    pub hashes: Vec<HashPoseidon>,  // output, size N_MESSAGES
}

pub fn q1_poseidon_no_sig_size(n_messages: usize) -> usize {
    MESSAGE_METADATA_SIZE * n_messages + n_messages + HASH_POSEIDON_SIZE * n_messages
}

pub fn read_q1_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q1PoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q1_poseidon_no_sig_size(n_messages));
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let outputs = drain_u64s_from_inputs(inputs, n_messages);
    let hashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    assert!(inputs.is_empty());
    Q1PoseidonNoSigPublicData {
        msgs,
        outputs,
        hashes,
    }
}

#[derive(Clone, Debug)]
pub struct Q4aPoseidonPublicData {
    pub publicKey: PublicKey,
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub price_private: u64,         // output
    pub auction: u64,               // output
    pub price_hashed: HashPoseidon, // output
}

pub fn q4a_poseidon_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + MESSAGE_METADATA_SIZE * n_messages + 1 + 1 + HASH_POSEIDON_SIZE
}

pub fn read_q4a_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q4aPoseidonPublicData {
    assert_eq!(inputs.len(), q4a_poseidon_size(n_messages));
    let publicKey = drain_public_key(inputs);
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let price_private = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let price_hashed = parse_hash_poseidon(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q4aPoseidonPublicData {
        publicKey,
        msgs,
        price_private,
        auction,
        price_hashed,
    }
}

#[derive(Clone, Debug)]
pub struct Q4aPoseidonNoSigPublicData {
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub price_private: u64,         // output
    pub auction: u64,               // output
    pub price_hashed: HashPoseidon, // output
    pub hashes: Vec<HashPoseidon>,  // output, size N_MESSAGES
}

pub fn q4a_poseidon_no_sig_size(n_messages: usize) -> usize {
    MESSAGE_METADATA_SIZE * n_messages
        + 1
        + 1
        + HASH_POSEIDON_SIZE
        + HASH_POSEIDON_SIZE * n_messages
}

pub fn read_q4a_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q4aPoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q4a_poseidon_no_sig_size(n_messages));
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let price_private = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let price_hashed = parse_hash_poseidon(&inputs.remove(0));
    let hashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    assert!(inputs.is_empty());
    Q4aPoseidonNoSigPublicData {
        msgs,
        price_private,
        auction,
        price_hashed,
        hashes,
    }
}

#[derive(Clone, Debug)]
pub struct Q4bPoseidonPublicData {
    pub valsHashes: Vec<HashPoseidon>, // size N_MESSAGES
    pub avg: u64,                      // output
}

pub fn q4b_poseidon_size(n_messages: usize) -> usize {
    HASH_POSEIDON_SIZE * n_messages + 1
}

pub fn read_q4b_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q4bPoseidonPublicData {
    assert_eq!(inputs.len(), q4b_poseidon_size(n_messages));
    let valsHashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    let avg = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q4bPoseidonPublicData { valsHashes, avg }
}

#[derive(Clone, Debug)]
pub struct Q4bPoseidonNoSigPublicData {
    pub valsHashes: Vec<HashPoseidon>, // size N_MESSAGES
    pub avg: u64,                      // output
}

pub fn q4b_poseidon_no_sig_size(n_messages: usize) -> usize {
    HASH_POSEIDON_SIZE * n_messages + 1
}

pub fn read_q4b_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q4bPoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q4b_poseidon_no_sig_size(n_messages));
    let valsHashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    let avg = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q4bPoseidonNoSigPublicData { valsHashes, avg }
}

#[derive(Clone, Debug)]
pub struct Q5aPoseidonPublicData {
    pub publicKey: PublicKey,
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub count_private: u64,         // output
    pub auction: u64,               // output
    pub count_hashed: HashPoseidon, // output
}

pub fn q5a_poseidon_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + MESSAGE_METADATA_SIZE * n_messages + 1 + 1 + HASH_POSEIDON_SIZE
}

pub fn read_q5a_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q5aPoseidonPublicData {
    assert_eq!(inputs.len(), q5a_poseidon_size(n_messages));
    let publicKey = drain_public_key(inputs);
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let count_private = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let count_hashed = parse_hash_poseidon(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q5aPoseidonPublicData {
        publicKey,
        msgs,
        count_private,
        auction,
        count_hashed,
    }
}

#[derive(Clone, Debug)]
pub struct Q5aPoseidonNoSigPublicData {
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub count_private: u64,         // output
    pub auction: u64,               // output
    pub count_hashed: HashPoseidon, // output
    pub hashes: Vec<HashPoseidon>,  // output, size N_MESSAGES
}

pub fn q5a_poseidon_no_sig_size(n_messages: usize) -> usize {
    MESSAGE_METADATA_SIZE * n_messages
        + 1
        + 1
        + HASH_POSEIDON_SIZE
        + HASH_POSEIDON_SIZE * n_messages
}

pub fn read_q5a_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q5aPoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q5a_poseidon_no_sig_size(n_messages));
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let count_private = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let count_hashed = parse_hash_poseidon(&inputs.remove(0));
    let hashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    assert!(inputs.is_empty());
    Q5aPoseidonNoSigPublicData {
        msgs,
        count_private,
        auction,
        count_hashed,
        hashes,
    }
}

#[derive(Clone, Debug)]
pub struct Q5bPoseidonPublicData {
    pub valsHashes: Vec<HashPoseidon>, // size N_MESSAGES
    pub avg: u64,                      // output
}

pub fn q5b_poseidon_size(n_messages: usize) -> usize {
    HASH_POSEIDON_SIZE * n_messages + 1
}

pub fn read_q5b_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q5bPoseidonPublicData {
    assert_eq!(inputs.len(), q5b_poseidon_size(n_messages));
    let valsHashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    let avg = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q5bPoseidonPublicData { valsHashes, avg }
}

#[derive(Clone, Debug)]
pub struct Q5bPoseidonNoSigPublicData {
    pub valsHashes: Vec<HashPoseidon>, // size N_MESSAGES
    pub avg: u64,                      // output
}

pub fn q5b_poseidon_no_sig_size(n_messages: usize) -> usize {
    HASH_POSEIDON_SIZE * n_messages + 1
}

pub fn read_q5b_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q5bPoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q5b_poseidon_no_sig_size(n_messages));
    let valsHashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    let avg = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q5bPoseidonNoSigPublicData { valsHashes, avg }
}

#[derive(Clone, Debug)]
pub struct Q6aPoseidonPublicData {
    pub publicKey: PublicKey,
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub price_private: u64,         // output
    pub auction: u64,               // output
    pub price_hashed: HashPoseidon, // output
}

pub fn q6a_poseidon_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + MESSAGE_METADATA_SIZE * n_messages + 1 + 1 + HASH_POSEIDON_SIZE
}

pub fn read_q6a_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q6aPoseidonPublicData {
    assert_eq!(inputs.len(), q6a_poseidon_size(n_messages));
    let publicKey = drain_public_key(inputs);
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let price_private = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let price_hashed = parse_hash_poseidon(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q6aPoseidonPublicData {
        publicKey,
        msgs,
        price_private,
        auction,
        price_hashed,
    }
}

#[derive(Clone, Debug)]
pub struct Q6aPoseidonNoSigPublicData {
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub price_private: u64,         // output
    pub auction: u64,               // output
    pub price_hashed: HashPoseidon, // output
    pub hashes: Vec<HashPoseidon>,  // output, size N_MESSAGES
}

pub fn q6a_poseidon_no_sig_size(n_messages: usize) -> usize {
    MESSAGE_METADATA_SIZE * n_messages
        + 1
        + 1
        + HASH_POSEIDON_SIZE
        + HASH_POSEIDON_SIZE * n_messages
}

pub fn read_q6a_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q6aPoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q6a_poseidon_no_sig_size(n_messages));
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let price_private = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let price_hashed = parse_hash_poseidon(&inputs.remove(0));
    let hashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    assert!(inputs.is_empty());
    Q6aPoseidonNoSigPublicData {
        msgs,
        price_private,
        auction,
        price_hashed,
        hashes,
    }
}

#[derive(Clone, Debug)]
pub struct Q6bPoseidonPublicData {
    pub valsHashes: Vec<HashPoseidon>, // size N_MESSAGES
    pub avg: u64,                      // output
}

pub fn q6b_poseidon_size(n_messages: usize) -> usize {
    HASH_POSEIDON_SIZE * n_messages + 1
}

pub fn read_q6b_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q6bPoseidonPublicData {
    assert_eq!(inputs.len(), q6b_poseidon_size(n_messages));
    let valsHashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    let avg = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q6bPoseidonPublicData { valsHashes, avg }
}

#[derive(Clone, Debug)]
pub struct Q6bPoseidonNoSigPublicData {
    pub valsHashes: Vec<HashPoseidon>, // size N_MESSAGES
    pub avg: u64,                      // output
}

pub fn q6b_poseidon_no_sig_size(n_messages: usize) -> usize {
    HASH_POSEIDON_SIZE * n_messages + 1
}

pub fn read_q6b_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q6bPoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q6b_poseidon_no_sig_size(n_messages));
    let valsHashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    let avg = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q6bPoseidonNoSigPublicData { valsHashes, avg }
}

#[derive(Clone, Debug)]
pub struct Q7PoseidonPublicData {
    pub publicKey: PublicKey,
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub price: u64,                 // output
    pub auction: u64,               // output
}

pub fn q7_poseidon_size(n_messages: usize) -> usize {
    PUBLIC_KEY_SIZE + MESSAGE_METADATA_SIZE * n_messages + 1 + 1
}

pub fn read_q7_poseidon_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q7PoseidonPublicData {
    assert_eq!(inputs.len(), q7_poseidon_size(n_messages));
    let publicKey = drain_public_key(inputs);
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let price = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    assert!(inputs.is_empty());
    Q7PoseidonPublicData {
        publicKey,
        msgs,
        price,
        auction,
    }
}

#[derive(Clone, Debug)]
pub struct Q7PoseidonNoSigPublicData {
    pub msgs: Vec<MessageMetadata>, // size N_MESSAGES
    pub price: u64,                 // output
    pub auction: u64,               // output
    pub hashes: Vec<HashPoseidon>,  // output, size N_MESSAGES
}

pub fn q7_poseidon_no_sig_size(n_messages: usize) -> usize {
    MESSAGE_METADATA_SIZE * n_messages + 1 + 1 + HASH_POSEIDON_SIZE * n_messages
}

pub fn read_q7_poseidon_nosig_proof(
    inputs: &mut Vec<Vec<u8>>,
    n_messages: usize,
) -> Q7PoseidonNoSigPublicData {
    assert_eq!(inputs.len(), q7_poseidon_no_sig_size(n_messages));
    let msgs = drain_messages_from_inputs(inputs, n_messages);
    let price = parse_u64(&inputs.remove(0));
    let auction = parse_u64(&inputs.remove(0));
    let hashes = drain_poseidon_hashes_from_inputs(inputs, n_messages);
    assert!(inputs.is_empty());
    Q7PoseidonNoSigPublicData {
        msgs,
        price,
        auction,
        hashes,
    }
}

/// Read proof file and return the public inputs.
pub(crate) fn read_proof_inputs(proof: serde_json::Value) -> Vec<Vec<u8>> {
    let inputs_json = proof
        .as_object()
        .expect("proof should contain a map")
        .get("inputs")
        .expect("proof should contain inputs")
        .as_array()
        .expect("inputs should be an array");
    inputs_json
        .iter()
        .map(|i| {
            let input = i.as_str().expect("input should be a string");
            decode_hex(input)
        })
        .collect::<Vec<_>>()
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
#[allow(dead_code)]
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

/// Drain `n` elements from inputs.
fn drain(inputs: &mut Vec<Vec<u8>>, n: usize) -> Vec<Vec<u8>> {
    inputs.drain(..n).collect::<Vec<_>>()
}

/// Parse public keys.
fn drain_public_key(inputs: &mut Vec<Vec<u8>>) -> PublicKey {
    parse_public_key(&drain(inputs, PUBLIC_KEY_SIZE))
}

/// Parse messages from public inputs.
fn drain_messages_from_inputs(inputs: &mut Vec<Vec<u8>>, n: usize) -> Vec<MessageMetadata> {
    inputs
        .drain(..n * MESSAGE_METADATA_SIZE)
        .collect::<Vec<_>>()
        .chunks_exact(MESSAGE_METADATA_SIZE)
        .map(|c| MessageMetadata {
            device_id: parse_u64(&c[0]),
            message_id: parse_u64(&c[1]),
            timestamp: parse_u64(&c[2]),
        })
        .collect::<Vec<_>>()
}

/// Parse Poseidon hashes from public inputs.
fn drain_poseidon_hashes_from_inputs(inputs: &mut Vec<Vec<u8>>, n: usize) -> Vec<HashPoseidon> {
    inputs
        .drain(..n * HASH_POSEIDON_SIZE)
        .collect::<Vec<_>>()
        .chunks_exact(HASH_POSEIDON_SIZE)
        .map(|c| parse_hash_poseidon(&c[0]))
        .collect::<Vec<_>>()
}

/// Parse u64s from public inputs.
fn drain_u64s_from_inputs(inputs: &mut Vec<Vec<u8>>, n: usize) -> Vec<u64> {
    inputs.drain(..n).map(|i| parse_u64(&i)).collect::<Vec<_>>()
}
