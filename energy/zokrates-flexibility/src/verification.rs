//! This module contains the verification.

use crate::execute_command;
use crate::params::{variant_to_string, Bls, HashScheme, Params, SigVariant};
use crate::proof::{
    self, decode_hex, parse_bool, parse_hash_poseidon, parse_public_key, parse_u64,
    FlexibilityPublicData, HashPoseidon, MessageMetadata, HASH_POSEIDON_SIZE,
    MESSAGE_METADATA_SIZE, PUBLIC_KEY_SIZE,
};
use chrono::Timelike;
use datajson::{Data, PublicKeyBLS, PublicKeyEdDSA, Slice};
use hash_sign::sign::{verify_bls_signature, BLSAggregateSignature};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

/// Maximum number of 'missing' messages per slice.
const MAX_MISSING_MEASUREMENTS_PER_SLICE: usize = 15;

/// Verify everything.
pub fn verify(params: Params, data: &Data, aggsig: Option<BLSAggregateSignature>) {
    println!("> Verifying");
    let t_all = Instant::now();

    let variant = variant_to_string(params.hash_scheme, params.sig_variant);
    let flexibility_name = format!("flexibility.{variant}");

    // Load proof.
    println!("> Loading proof files");
    let mut t = Instant::now();
    let flexibility_proof = read_flexibility_proof(&flexibility_name, params);
    println!("| Time to load proof files: {:?}", t.elapsed());

    // We cannot trust any meta-information (device_id, current_slice_id, current_slice_time, ...)
    // as they are received from an untrusted party and are not part of the proof.
    // So we'll use them as reference pointers without relying on their content.
    let current_slice_time = data.current.start;

    // Fetch pubkey from known DB.
    let pub_key = &data.public_key_eddsa;
    let device_id = 0;

    // Verify the time
    // Assert time rounded to quarter
    assert_eq!(current_slice_time.time().minute() % 15, 0);
    // Assert end time
    assert!(current_slice_time < data.current.end);

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify flexibility proof
    println!("> Verify flexibility proof");
    t = Instant::now();

    // Verify messages
    let slice = &data.current;
    match flexibility_proof {
        FlexibilityPublicData::Poseidon(ref p) => {
            // Check if proper keys are used
            assert!(pub_key.0.equals(p.publicKey.0.clone()));
            let msgs = p
                .msgsBefore
                .iter()
                .chain(p.msgsAfter.iter())
                .collect::<Vec<_>>();
            verify_messages(slice, &msgs, device_id, params);
        }
        FlexibilityPublicData::PoseidonNoSig(ref p) => {
            let msgs = p
                .msgsBefore
                .iter()
                .chain(p.msgsAfter.iter())
                .collect::<Vec<_>>();
            let hashes = p
                .hashesBefore
                .iter()
                .chain(p.hashesAfter.iter())
                .collect::<Vec<_>>();
            verify_messages(slice, &msgs, device_id, params);
            match params.bls {
                Bls::No => verify_eddsa_signatures_poseidon(&slice, &hashes, pub_key),
                Bls::Yes => all_hashes = hashes,
            }
        }
    };

    // Verify proof itself
    verify_proof(&flexibility_name, &flexibility_name);

    println!("| Time to verify flexibility proof: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &data.public_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
    let result = match flexibility_proof {
        FlexibilityPublicData::Poseidon(ref p) => (p.sign, p.difference),
        FlexibilityPublicData::PoseidonNoSig(ref p) => (p.sign, p.difference),
    };
    println!(
        "The verified result is {}{:?}",
        if result.0 { "+" } else { "-" },
        result.1
    );
}

/// Read flexibility proof from file, returning the public inputs and outputs.
#[allow(non_snake_case)]
fn read_flexibility_proof(execution_name: &str, params: Params) -> FlexibilityPublicData {
    println!("> Reading proof for {execution_name}");

    let mut inputs = read_proof_inputs(execution_name);

    let n_before = params.n_before;
    let n_after = params.n_after;

    match (params.hash_scheme, params.sig_variant) {
        (HashScheme::Poseidon, SigVariant::Sig) => {
            assert_eq!(
                inputs.len(),
                proof::flexibility_poseidon_size(n_before, n_after)
            );
            let publicKey = parse_public_key(&inputs.drain(..PUBLIC_KEY_SIZE).collect::<Vec<_>>());
            let msgsBefore = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_before * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let msgsAfter = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_after * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let difference = parse_u64(&inputs.remove(0));
            let sign = parse_bool(&inputs.remove(0));
            assert!(inputs.is_empty());
            FlexibilityPublicData::Poseidon(proof::FlexibilityPoseidonPublicData {
                publicKey,
                msgsBefore,
                msgsAfter,
                difference,
                sign,
            })
        }
        (HashScheme::Poseidon, SigVariant::NoSig) => {
            assert_eq!(
                inputs.len(),
                proof::flexibility_poseidon_no_sig_size(n_before, n_after)
            );
            let msgsBefore = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_before * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let msgsAfter = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_after * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let difference = parse_u64(&inputs.remove(0));
            let sign = parse_bool(&inputs.remove(0));
            let hashesBefore =
                parse_poseidon_hashes_from_inputs(&inputs.drain(..n_before).collect::<Vec<_>>());
            let hashesAfter =
                parse_poseidon_hashes_from_inputs(&inputs.drain(..n_after).collect::<Vec<_>>());
            assert!(inputs.is_empty());
            FlexibilityPublicData::PoseidonNoSig(proof::FlexibilityPoseidonNoSigPublicData {
                msgsBefore,
                msgsAfter,
                difference,
                sign,
                hashesBefore,
                hashesAfter,
            })
        }
    }
}

/// Read proof file and return the public inputs.
fn read_proof_inputs(execution_name: &str) -> Vec<Vec<u8>> {
    let proof_path = PathBuf::from(&format!("{}.proof.json", execution_name));
    let proof_file = fs::read_to_string(proof_path).expect("could not read proof file");
    let proof: serde_json::Value =
        serde_json::from_str(&proof_file).expect("could not parse proof file as JSON");
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

/// Parse messages from public inputs.
fn parse_messages_from_inputs(inputs: &[Vec<u8>]) -> Vec<proof::MessageMetadata> {
    inputs
        .chunks_exact(MESSAGE_METADATA_SIZE)
        .map(|c| proof::MessageMetadata {
            device_id: parse_u64(&c[0]),
            message_id: parse_u64(&c[1]),
            timestamp: parse_u64(&c[2]),
        })
        .collect::<Vec<_>>()
}

/// Parse Poseidon hashes from public inputs.
fn parse_poseidon_hashes_from_inputs(inputs: &[Vec<u8>]) -> Vec<proof::HashPoseidon> {
    inputs
        .chunks_exact(HASH_POSEIDON_SIZE)
        .map(|c| parse_hash_poseidon(&c[0]))
        .collect::<Vec<_>>()
}

/// Verify actual proof.
fn verify_proof(program_name: &str, execution_name: &str) {
    println!("> Verifying proof for {execution_name}");

    let mut c = Command::new("zokrates");
    c.arg("verify");
    c.args(["-v", &format!("{program_name}.verification.key")]);
    c.args(["-j", &format!("{execution_name}.proof.json")]);

    execute_command(&mut c, "verify");
}

/// Verify properties of messages in a slice.
fn verify_messages(
    slice: &Slice,
    messages_metadata: &Vec<&MessageMetadata>,
    device_id: u64,
    params: Params,
) {
    // Check if data lengths match
    let n_messages = params.n_before + params.n_after;
    assert!(slice.messages.len() >= n_messages);
    assert_eq!(messages_metadata.len(), n_messages);
    // Check if time slice makes sense
    let slice_start = slice.start.timestamp() as u64;
    let slice_end = slice.end.timestamp() as u64;
    for message in messages_metadata {
        assert!(message.timestamp >= slice_start);
        assert!(message.timestamp <= slice_end);
    }
    // Check if too many messages are missing
    let mut timestamps_sorted = messages_metadata
        .iter()
        .map(|m| m.timestamp)
        .collect::<Vec<_>>();
    timestamps_sorted.sort();
    let mut missing = 0;
    for i in 1..timestamps_sorted.len() {
        let a = timestamps_sorted[i - 1];
        let b = timestamps_sorted[i];
        if b >= a + 3 && b <= a + 7 {
            continue;
        } else {
            missing += 1;
        }
    }
    eprintln!(
        "Missing messages for slice starting at {:?}: {}",
        slice.start, missing
    );
    if missing > MAX_MISSING_MEASUREMENTS_PER_SLICE {
        // Don't assert but just produce a warning, as in our example data some slices
        // have many missing messages. In a real-world scenario, it is up to the
        // consumer to decide how to deal with this.
        eprintln!("WARNING: Too many missing measurements");
    }

    // Check if msg_ids are unique
    let mut unique_ids = HashSet::<u64>::new();
    for message in messages_metadata {
        assert!(unique_ids.insert(message.message_id));
    }

    // Check message device_ids
    // Note: not in Circom version, as it has one device_id for all messages.
    for message in messages_metadata {
        assert_eq!(message.device_id, device_id);
    }
}

/// Verify EdDSA signatures of messages in a slice, using the Poseidon hash.
fn verify_eddsa_signatures_poseidon(
    slice: &Slice,
    hashes: &Vec<&HashPoseidon>,
    public_key: &PublicKeyEdDSA,
) {
    let pk = &public_key.0;
    for (hash, message) in hashes.iter().zip(slice.messages.iter()) {
        // Hash is coming from proof, signature is coming from sensor (data.json).
        // Look up signature in data and re-create it.
        let signature =
            hash_sign::sign::convert_eddsa_signature(&message.signature_eddsa_poseidon_salted);
        let hash_bi = datajson::utils::field_to_bigint(hash);
        // Verify signature.
        let t = Instant::now();
        assert!(babyjubjub_rs::verify(pk.clone(), signature, hash_bi));
        eprintln!(
            "| Time to verify signature of message {}: {:?}",
            message.id,
            t.elapsed()
        );
    }
}

/// Verify BLS aggregated signature `aggsig` of messages of which the `hashes` are
/// given.
fn verify_bls_signatures(
    aggsig: BLSAggregateSignature,
    hashes: &Vec<&HashPoseidon>,
    public_key: &PublicKeyBLS,
) {
    println!("> Verify BLS aggregated signature");
    // Convert hashes to bytes (SHA256 = bytes; Poseidon = field to bytes)
    let hashes_as_bytes: Vec<Vec<u8>> = hashes
        .iter()
        .map(|h| datajson::utils::field_to_bytes(h))
        .collect::<Vec<_>>();

    let t = Instant::now();
    assert!(verify_bls_signature(
        aggsig,
        &hashes_as_bytes,
        &public_key.0
    ));
    println!(
        "| Time to verify BLS aggregated signature: {:?}",
        t.elapsed()
    );
}
