// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains code to generate the inputs for the ZoKrates programs.

use debs_datajson::{BLSSignature, Data, SignedMessage};
use hash_sign::utils::{bigint_to_decimal_str, field_to_decimal_str};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::sync::Mutex;

use crate::abi::*;
use crate::params::Params;
use crate::{HashScheme, SigVariant};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoricalInputs {
    PoseidonNoSig(HistoricalPoseidonNoSigAbi),
    Poseidon(HistoricalPoseidonAbi),
    Sha256NoSig(HistoricalSha256NoSigAbi),
    Sha256(HistoricalSha256Abi),
}

pub type HistoricalOutputs = (HistoricalResult, Hash);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Challenge1Inputs {
    PoseidonNoSig(Challenge1PoseidonNoSigAbi),
    Poseidon(Challenge1PoseidonAbi),
    Sha256NoSig(Challenge1Sha256NoSigAbi),
    Sha256(Challenge1Sha256Abi),
}

/// Convert number to hexadecimal string, prefixed with "0x".
fn to_hex<T: std::fmt::LowerHex>(n: T) -> String {
    format!("{n:#x}")
}

lazy_static! {
    static ref ZERO_METADATA: MessageMetadata = MessageMetadata {
        deviceId: String::from("0x0000000000000000"),
        messageId: String::from("0x0"),
        timestamp: String::from("0x0"),
    };
    static ref ZERO_VALUE: Number = String::from("0x0");
    static ref ZERO_SIGNATURE: Signature = Signature {
        Rx: String::from("0"),
        Ry: String::from("0"),
        S: String::from("0"),
    };
    static ref ZERO_SALT_POSEIDON: SaltPoseidon = [
        String::from("0"),
        String::from("0"),
        String::from("0"),
        String::from("0"),
    ];
    static ref ZERO_SALT_SHA256: SaltSHA256 = vec![String::from("0x0"); 64];
    static ref ZERO_HASH_POSEIDON: HashPoseidon = String::from("0");
    static ref ZERO_HASH_SHA256: HashSHA256 = vec![String::from("0x0"); 8];
    static ref ZERO_HISTORICAL_RESULT_POSEIDON: HistoricalResultPoseidon =
        HistoricalResultPoseidon {
            average: String::from("0"),
            salt: ZERO_SALT_POSEIDON.clone(),
        };
    static ref ZERO_HISTORICAL_RESULT_SHA256: HistoricalResultSHA256 = HistoricalResultSHA256 {
        average: String::from("0"),
        salt: ZERO_SALT_SHA256.clone(),
    };
}

/// Fill up a list of elements with "zero" elements, up to a maximum length.
fn fill_up_to_max<T: Clone>(list: &mut Vec<T>, zero: T, max: usize) {
    // If there are too many messages, warn about this and delete the extra ones.
    if list.len() > max {
        println!(
            "WARNING: There are more messages than the maximum allowed! Hence, we will drop some."
        );
        list.truncate(max);
        return;
    }

    // Pad with "zeros".
    let n = list.len();
    for _ in n..max {
        list.push(zero.clone());
    }
}

lazy_static! {
    /// Seed RNG with a fixed value for reproducibility.
    static ref RNG: Mutex<StdRng> = Mutex::new(StdRng::seed_from_u64(1));
}

/// Generate random salt for Poseidon.
fn generate_salt_poseidon() -> SaltPoseidon {
    // Generate 64 random bytes.
    let mut salt = [0u8; 64];
    RNG.lock().unwrap().fill(&mut salt);
    // Split into 4 chunks of 16 bytes each.
    let salt_chunks: [[u8; 16]; 4] = [
        salt[0..16].try_into().unwrap(),
        salt[16..32].try_into().unwrap(),
        salt[32..48].try_into().unwrap(),
        salt[48..64].try_into().unwrap(),
    ];
    // Convert to fields (= string with decimal values) in vec.
    let salt_vec = salt_chunks
        .iter()
        .map(|b| u128::from_be_bytes(*b).to_string())
        .collect::<Vec<_>>();
    // Convert to array.
    salt_vec.try_into().unwrap()
}

/// Generate random salt for SHA256.
fn generate_salt_sha256() -> SaltSHA256 {
    let mut salt = [0u8; 64];
    RNG.lock().unwrap().fill(&mut salt);
    salt.iter().map(|b| to_hex(b)).collect::<Vec<_>>()
}

/// Get messages metadata and values from list of messages.
fn get_messages(
    messages: &Vec<SignedMessage>,
    n_messages: usize,
) -> (Vec<MessageMetadata>, Vec<Number>) {
    let mut metadatas = messages
        .iter()
        .map(|m| MessageMetadata {
            deviceId: hex::encode(&m.device_id),
            messageId: to_hex(m.id),
            timestamp: to_hex(m.timestamp.timestamp()),
        })
        .collect::<Vec<_>>();
    let mut values = messages.iter().map(|m| to_hex(m.value)).collect::<Vec<_>>();
    fill_up_to_max(&mut metadatas, ZERO_METADATA.clone(), n_messages);
    fill_up_to_max(&mut values, ZERO_VALUE.clone(), n_messages);
    (metadatas, values)
}

/// Get message signatures from list of messages, using EdDSA and Poseidon (unsalted).
fn get_eddsa_poseidon_signatures(
    messages: &Vec<SignedMessage>,
    n_messages: usize,
) -> Vec<Signature> {
    let mut signatures = messages
        .iter()
        .map(|m| Signature {
            Rx: field_to_decimal_str(&m.signature_eddsa_poseidon_unsalted.rx),
            Ry: field_to_decimal_str(&m.signature_eddsa_poseidon_unsalted.ry),
            S: bigint_to_decimal_str(&m.signature_eddsa_poseidon_unsalted.s),
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut signatures, ZERO_SIGNATURE.clone(), n_messages);
    signatures
}

/// Get message signatures from list of messages, using BLS and Poseidon (salted).
pub(crate) fn get_bls_poseidon_signatures(messages: &Vec<SignedMessage>) -> Vec<BLSSignature> {
    messages
        .iter()
        .map(|m| m.signature_bls_poseidon_salted)
        .collect::<Vec<_>>()
}

/// Get message signatures from list of messages, using BLS and SHA256 (salted).
pub(crate) fn get_bls_sha256_signatures(messages: &Vec<SignedMessage>) -> Vec<BLSSignature> {
    messages
        .iter()
        .map(|m| m.signature_bls_sha256_salted)
        .collect::<Vec<_>>()
}

/// Get message salts for Poseidon from list of messages.
fn get_salts_poseidon(messages: &Vec<SignedMessage>, n_messages: usize) -> Vec<SaltPoseidon> {
    let mut salts = messages
        .iter()
        .map(|m| {
            m.salt_fields
                .iter()
                .map(|f| field_to_decimal_str(f))
                .collect::<Vec<String>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut salts, ZERO_SALT_POSEIDON.clone(), n_messages);
    salts
}

/// Get message salts for SHA256 from list of messages.
fn get_salts_sha256(messages: &Vec<SignedMessage>, n_messages: usize) -> Vec<SaltSHA256> {
    let mut salts = messages
        .iter()
        .map(|m| {
            m.salt
                .iter()
                .map(|f| to_hex(f))
                .collect::<Vec<String>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut salts, ZERO_SALT_SHA256.clone(), n_messages);
    salts
}

/// Generate inputs for historical program.
#[allow(non_snake_case)]
pub(crate) fn generate_inputs_for_historical(
    params: Params,
    data: &Data,
    i: usize,
) -> HistoricalInputs {
    let window_start = data.historical[i].start;
    let window_end = data.historical[i].start + params.window_duration;
    let messages = &data.historical[i]
        .messages
        .iter()
        .filter(|m| m.timestamp >= window_start && m.timestamp < window_end)
        .cloned()
        .collect::<Vec<_>>();
    let n_messages = params.n_messages;

    let public_key = &data.public_key_eddsa;
    let publicKey = PublicKey {
        x: field_to_decimal_str(&public_key.0.x),
        y: field_to_decimal_str(&public_key.0.y),
    };

    let (msgs, vals) = get_messages(messages, n_messages);
    let nMessages = to_hex(min(messages.len(), n_messages));

    match (params.hash_scheme, params.sig_variant) {
        (HashScheme::Poseidon, SigVariant::NoSig) => {
            let salts = get_salts_poseidon(messages, n_messages);
            let outputSalt = generate_salt_poseidon();
            HistoricalInputs::PoseidonNoSig(HistoricalPoseidonNoSigAbi {
                nMessages,
                msgs,
                vals,
                salts,
                outputSalt,
            })
        }
        (HashScheme::Poseidon, SigVariant::Sig) => {
            let signatures = get_eddsa_poseidon_signatures(messages, n_messages);
            let outputSalt = generate_salt_poseidon();
            HistoricalInputs::Poseidon(HistoricalPoseidonAbi {
                publicKey,
                nMessages,
                msgs,
                vals,
                signatures,
                outputSalt,
            })
        }
        (HashScheme::Sha256, SigVariant::NoSig) => {
            let salts = get_salts_sha256(messages, n_messages);
            let outputSalt = generate_salt_sha256();
            HistoricalInputs::Sha256NoSig(HistoricalSha256NoSigAbi {
                nMessages,
                msgs,
                vals,
                salts,
                outputSalt,
            })
        }
        (HashScheme::Sha256, SigVariant::Sig) => {
            let signatures = get_eddsa_poseidon_signatures(messages, n_messages);
            let outputSalt = generate_salt_sha256();
            HistoricalInputs::Sha256(HistoricalSha256Abi {
                publicKey,
                nMessages,
                msgs,
                vals,
                signatures,
                outputSalt,
            })
        }
    }
}

/// Get the results from the outputs of the historical program.
fn get_historical_results_poseidon(
    historical_outputs: &Vec<HistoricalOutputs>,
    n_historical: usize,
) -> (Vec<HistoricalResultPoseidon>, Vec<HashPoseidon>) {
    let mut results = historical_outputs
        .iter()
        .map(|(r, _h)| match r {
            HistoricalResult::Poseidon(p) => p.clone(),
            _ => panic!("unexpected historical output"),
        })
        .collect();
    let mut hashes = historical_outputs
        .iter()
        .map(|(_r, h)| match h {
            Hash::Poseidon(p) => p.clone(),
            _ => panic!("unexpected historical output"),
        })
        .collect();
    fill_up_to_max(
        &mut results,
        ZERO_HISTORICAL_RESULT_POSEIDON.clone(),
        n_historical,
    );
    fill_up_to_max(&mut hashes, ZERO_HASH_POSEIDON.clone(), n_historical);
    (results, hashes)
}

/// Get the results from the outputs of the historical program.
fn get_historical_results_sha256(
    historical_outputs: &Vec<HistoricalOutputs>,
    n_historical: usize,
) -> (Vec<HistoricalResultSHA256>, Vec<HashSHA256>) {
    let mut results = historical_outputs
        .iter()
        .map(|(r, _h)| match r {
            HistoricalResult::Sha256(s) => s.clone(),
            _ => panic!("unexpected historical output"),
        })
        .collect();
    let mut hashes = historical_outputs
        .iter()
        .map(|(_r, h)| match h {
            Hash::Sha256(s) => s.clone(),
            _ => panic!("unexpected historical output"),
        })
        .collect();
    fill_up_to_max(
        &mut results,
        ZERO_HISTORICAL_RESULT_SHA256.clone(),
        n_historical,
    );
    fill_up_to_max(&mut hashes, ZERO_HASH_SHA256.clone(), n_historical);
    (results, hashes)
}

/// Generate inputs for challenge1 program.
#[allow(non_snake_case)]
pub(crate) fn generate_inputs_for_challenge1(
    params: Params,
    data: &Data,
    historical_outputs: &Vec<HistoricalOutputs>,
) -> Challenge1Inputs {
    let window_start = data.current.start;
    let window_end = data.current.start + params.window_duration;
    let messages = &data
        .current
        .messages
        .iter()
        .filter(|m| m.timestamp >= window_start && m.timestamp < window_end)
        .cloned()
        .collect::<Vec<_>>();
    let n_messages = params.n_messages;

    let public_key = &data.public_key_eddsa;
    let publicKey = PublicKey {
        x: field_to_decimal_str(&public_key.0.x),
        y: field_to_decimal_str(&public_key.0.y),
    };

    let (msgs, vals) = get_messages(messages, n_messages);
    let nMessages = to_hex(min(messages.len(), n_messages));
    let n_historical = historical_outputs.len();
    let nHistorical = to_hex(n_historical);

    // Pre-sort historical results.
    let mut sorted_historical_outputs = historical_outputs.clone();
    sorted_historical_outputs.sort_by_key(|(r, _h)| {
        match r {
            HistoricalResult::Poseidon(r) => &r.average,
            HistoricalResult::Sha256(r) => &r.average,
        }
        .parse::<u64>()
        .expect("could not parse average to u64")
    });

    match (params.hash_scheme, params.sig_variant) {
        (HashScheme::Poseidon, SigVariant::NoSig) => {
            let (historicalResults, historicalHashes) =
                get_historical_results_poseidon(&sorted_historical_outputs, n_historical);
            let salts = get_salts_poseidon(messages, n_messages);
            Challenge1Inputs::PoseidonNoSig(Challenge1PoseidonNoSigAbi {
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                historicalResults,
                vals,
                salts,
            })
        }
        (HashScheme::Poseidon, SigVariant::Sig) => {
            let (historicalResults, historicalHashes) =
                get_historical_results_poseidon(&sorted_historical_outputs, n_historical);
            let signatures = get_eddsa_poseidon_signatures(messages, n_messages);
            Challenge1Inputs::Poseidon(Challenge1PoseidonAbi {
                publicKey,
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                historicalResults,
                vals,
                signatures,
            })
        }
        (HashScheme::Sha256, SigVariant::NoSig) => {
            let (historicalResults, historicalHashes) =
                get_historical_results_sha256(&sorted_historical_outputs, n_historical);
            let salts = get_salts_sha256(messages, n_messages);
            Challenge1Inputs::Sha256NoSig(Challenge1Sha256NoSigAbi {
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                historicalResults,
                vals,
                salts,
            })
        }
        (HashScheme::Sha256, SigVariant::Sig) => {
            let (historicalResults, historicalHashes) =
                get_historical_results_sha256(&sorted_historical_outputs, n_historical);
            let signatures = get_eddsa_poseidon_signatures(messages, n_messages);
            Challenge1Inputs::Sha256(Challenge1Sha256Abi {
                publicKey,
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                historicalResults,
                vals,
                signatures,
            })
        }
    }
}
