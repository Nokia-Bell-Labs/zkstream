//! This module contains the ABIs of the ZoKrates programs.
//! They were derived from the *.abi.json files generated by ZoKrates.

#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

/// Field is encoded as a string containing the number, e.g. "123".
pub type Field = String;

/// Other numbers are encoded as a hexadecimal number in a string, e.g. "0x123".
pub type Number = String;

pub type HashPoseidon = Field;
pub type HashSHA256 = Vec<Number>; // size 8

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Hash {
    Poseidon(HashPoseidon),
    Sha256(HashSHA256),
}

pub type SaltPoseidon = [Field; 4];
pub type SaltSHA256 = Vec<Number>; // size 64

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub deviceId: Number,
    pub messageId: Number,
    pub timestamp: Number,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalResultPoseidon {
    pub average: Number,
    pub salt: SaltPoseidon,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalResultSHA256 {
    pub average: Number,
    pub salt: SaltSHA256,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum HistoricalResult {
    Poseidon(HistoricalResultPoseidon),
    Sha256(HistoricalResultSHA256),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub Rx: Field,
    pub Ry: Field,
    pub S: Field,
}

/// Based on historical.poseidon.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct HistoricalPoseidonAbi {
    pub publicKey: PublicKey,
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub signatures: Vec<Signature>, // size MAX_N_MESSAGES
    pub outputSalt: SaltPoseidon,
}

/// Based on historical.poseidon.nosig.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct HistoricalPoseidonNoSigAbi {
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub salts: Vec<SaltPoseidon>,   // size MAX_N_MESSAGES
    pub outputSalt: SaltPoseidon,
}

/// Based on historical.sha256.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct HistoricalSha256Abi {
    pub publicKey: PublicKey,
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub signatures: Vec<Signature>, // size MAX_N_MESSAGES
    pub outputSalt: SaltSHA256,
}

/// Based on historical.sha256.nosig.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct HistoricalSha256NoSigAbi {
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub salts: Vec<SaltSHA256>,     // size MAX_N_MESSAGES
    pub outputSalt: SaltSHA256,
}

/// Based on challenge1.poseidon.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct Challenge1PoseidonAbi {
    pub publicKey: PublicKey,
    pub nHistorical: Number,
    pub historicalHashes: Vec<HashPoseidon>, // size MAX_N_HISTORICAL
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub historicalResults: Vec<HistoricalResultPoseidon>, // size MAX_N_HISTORICAL
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub signatures: Vec<Signature>, // size MAX_N_MESSAGES
}

/// Based on challenge1.poseidon.nosig.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct Challenge1PoseidonNoSigAbi {
    pub nHistorical: Number,
    pub historicalHashes: Vec<HashPoseidon>, // size MAX_N_HISTORICAL
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub historicalResults: Vec<HistoricalResultPoseidon>, // size MAX_N_HISTORICAL
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub salts: Vec<SaltPoseidon>,   // size MAX_N_MESSAGES
}

/// Based on challenge1.sha256.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct Challenge1Sha256Abi {
    pub publicKey: PublicKey,
    pub nHistorical: Number,
    pub historicalHashes: Vec<HashSHA256>, // size MAX_N_HISTORICAL
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub historicalResults: Vec<HistoricalResultSHA256>, // size MAX_N_HISTORICAL
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub signatures: Vec<Signature>, // size MAX_N_MESSAGES
}

/// Based on challenge1.sha256.nosig.abi.json.
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct Challenge1Sha256NoSigAbi {
    pub nHistorical: Number,
    pub historicalHashes: Vec<HashSHA256>, // size MAX_N_HISTORICAL
    pub nMessages: Number,
    pub msgs: Vec<MessageMetadata>, // size MAX_N_MESSAGES
    pub historicalResults: Vec<HistoricalResultSHA256>, // size MAX_N_HISTORICAL
    pub vals: Vec<Number>,          // size MAX_N_MESSAGES
    pub salts: Vec<SaltSHA256>,     // size MAX_N_MESSAGES
}
