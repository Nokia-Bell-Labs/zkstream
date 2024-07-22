//! This module contains code to generate the inputs for the ZoKrates programs.

use crate::abi::*;
use datajson::utils::{bigint_to_decimal_str, field_to_decimal_str};
use datajson::{
    bls_signature_from_json, eddsa_signature_from_json, public_key_eddsa_from_json, BLSSignature,
    DataJson, SignedMessageJson,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::Mutex;

/// Convert number to hexadecimal string, prefixed with "0x".
pub(crate) fn to_hex<T: std::fmt::LowerHex>(n: T) -> String {
    format!("{n:#x}")
}

lazy_static! {
    pub static ref ZERO_METADATA: MessageMetadata = MessageMetadata {
        deviceId: String::from("0x0000000000000000"),
        messageId: String::from("0x0"),
        timestamp: String::from("0x0"),
    };
    pub static ref ZERO_BID: Bid = Bid {
        auction: String::from("0x0"),
        price: String::from("0x0"),
    };
    pub static ref ZERO_U64: Number = String::from("0x0");
    pub static ref ZERO_SIGNATURE: Signature = Signature {
        Rx: String::from("0"),
        Ry: String::from("0"),
        S: String::from("0"),
    };
    pub static ref ZERO_SALT_POSEIDON: SaltPoseidon = [
        String::from("0"),
        String::from("0"),
        String::from("0"),
        String::from("0"),
    ];
    pub static ref ZERO_HASH_POSEIDON: HashPoseidon = String::from("0");
}

/// Fill up a list of elements with "zero" elements, up to a maximum length.
pub fn fill_up_to_max<T: Clone>(list: &mut Vec<T>, zero: T, max: usize) {
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
#[allow(dead_code)]
pub fn generate_salt_poseidon() -> SaltPoseidon {
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

/// Get messages metadata, bids, and salts from list of messages.
pub fn get_bids(
    messages: &Vec<SignedMessageJson>,
    n_messages: usize,
) -> (Vec<MessageMetadata>, Bids, Vec<SaltPoseidon>) {
    let mut metadatas = messages
        .iter()
        .map(|m| MessageMetadata {
            deviceId: to_hex(m.message.device_id),
            messageId: to_hex(m.message.id),
            timestamp: to_hex(m.message.timestamp),
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut metadatas, ZERO_METADATA.clone(), n_messages);
    let mut values = messages
        .iter()
        .map(|m| Bid {
            auction: to_hex(m.message.value.auction),
            price: to_hex(m.message.value.price),
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut values, ZERO_BID.clone(), n_messages);
    let bids = Bids {
        values,
        n: to_hex(messages.len()),
    };
    let mut salts = messages
        .iter()
        .map(|m| {
            m.salt_fields
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<String>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut salts, ZERO_SALT_POSEIDON.clone(), n_messages);
    (metadatas, bids, salts)
}

/// Get U64s from vector of u64s.
pub fn get_u64s(u64s: &Vec<u64>, n_messages: usize) -> U64s {
    let mut values = u64s.iter().map(|v| to_hex(v)).collect::<Vec<_>>();
    fill_up_to_max(&mut values, ZERO_U64.clone(), n_messages);
    U64s {
        values,
        n: to_hex(u64s.len()),
    }
}

/// Get hashed values and their salts from a list of hashes and salts.
pub fn get_hashes_salts(
    hashes: &Vec<HashPoseidon>,
    salts: &Vec<SaltPoseidon>,
    n_messages: usize,
) -> (Vec<HashPoseidon>, Vec<SaltPoseidon>) {
    let mut hashes = hashes.clone();
    fill_up_to_max(&mut hashes, ZERO_HASH_POSEIDON.clone(), n_messages);
    let mut salts = salts.clone();
    fill_up_to_max(&mut salts, ZERO_SALT_POSEIDON.clone(), n_messages);
    (hashes, salts)
}

/// Get public key from data.
pub fn get_public_key_eddsa(data: &DataJson) -> PublicKey {
    let public_key = public_key_eddsa_from_json(&data.public_key_eddsa);
    PublicKey {
        x: field_to_decimal_str(&public_key.0.x),
        y: field_to_decimal_str(&public_key.0.y),
    }
}

/// Get message signatures from list of messages, using EdDSA and Poseidon (unsalted).
pub fn get_eddsa_poseidon_signatures(
    messages: &Vec<SignedMessageJson>,
    n_messages: usize,
) -> Vec<Signature> {
    let mut signatures = messages
        .iter()
        .map(|m| {
            let s = eddsa_signature_from_json(&m.signature_eddsa_poseidon_unsalted);
            Signature {
                Rx: field_to_decimal_str(&s.rx),
                Ry: field_to_decimal_str(&s.ry),
                S: bigint_to_decimal_str(&s.s),
            }
        })
        .collect::<Vec<_>>();
    fill_up_to_max(&mut signatures, ZERO_SIGNATURE.clone(), n_messages);
    signatures
}

/// Get message signatures from list of messages, using BLS and Poseidon (salted).
pub fn get_bls_poseidon_signatures(messages: &Vec<SignedMessageJson>) -> Vec<BLSSignature> {
    messages
        .iter()
        .map(|m| bls_signature_from_json(&m.signature_bls_poseidon_salted))
        .collect::<Vec<_>>()
}
