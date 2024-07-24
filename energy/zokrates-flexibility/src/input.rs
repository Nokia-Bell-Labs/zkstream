//! This module contains code to generate the inputs for the ZoKrates programs.

use debs_datajson::{BLSSignature, Data, SignedMessage};
use hash_sign::utils::{bigint_to_decimal_str, field_to_decimal_str};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::abi::*;
use crate::params::{HashScheme, Params, SigVariant};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlexibilityInputs {
    PoseidonNoSig(FlexibilityPoseidonNoSigAbi),
    Poseidon(FlexibilityPoseidonAbi),
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
    static ref ZERO_HASH_POSEIDON: HashPoseidon = String::from("0");
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
#[allow(dead_code)]
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

/// Generate inputs for flexibility program.
#[allow(non_snake_case)]
pub(crate) fn generate_inputs_for_flexibility(params: Params, data: &Data) -> FlexibilityInputs {
    let n_before = params.n_before;
    let n_after = params.n_after;

    let messages_before = &data.current.messages[..n_before].to_vec();
    let messages_after = &data.current.messages[n_before..(n_before + n_after)].to_vec();
    // eprintln!(
    //     "Data values: {:?}, {:?}",
    //     messages_before.iter().map(|m| m.value).collect::<Vec<_>>(),
    //     messages_after.iter().map(|m| m.value).collect::<Vec<_>>()
    // );
    if messages_before.len() + messages_after.len() != n_before + n_after {
        panic!(
            "There are not enough messages in the given data.json file: \
            expected {} before and {} after messages, but got {} before and {} after messages",
            n_before,
            n_after,
            messages_before.len(),
            messages_after.len()
        );
    }

    let public_key = &data.public_key_eddsa;
    let publicKey = PublicKey {
        x: field_to_decimal_str(&public_key.0.x),
        y: field_to_decimal_str(&public_key.0.y),
    };

    let n_before = messages_before.len();
    let n_after = messages_after.len();
    let (msgsBefore, valsBefore) = get_messages(messages_before, n_before);
    let (msgsAfter, valsAfter) = get_messages(messages_after, n_after);

    match (params.hash_scheme, params.sig_variant) {
        (HashScheme::Poseidon, SigVariant::NoSig) => {
            let saltsBefore = get_salts_poseidon(messages_before, n_before);
            let saltsAfter = get_salts_poseidon(messages_after, n_after);
            FlexibilityInputs::PoseidonNoSig(FlexibilityPoseidonNoSigAbi {
                msgsBefore,
                msgsAfter,
                valsBefore,
                valsAfter,
                saltsBefore,
                saltsAfter,
            })
        }
        (HashScheme::Poseidon, SigVariant::Sig) => {
            let signaturesBefore = get_eddsa_poseidon_signatures(messages_before, n_before);
            let signaturesAfter = get_eddsa_poseidon_signatures(messages_after, n_after);
            FlexibilityInputs::Poseidon(FlexibilityPoseidonAbi {
                publicKey,
                msgsBefore,
                msgsAfter,
                valsBefore,
                valsAfter,
                signaturesBefore,
                signaturesAfter,
            })
        }
    }
}
