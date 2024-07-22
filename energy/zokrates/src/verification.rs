//! This module contains the verification.

use crate::execute_command;
use crate::params::{Bls, HashScheme, Params, SigVariant};
use crate::proof::{
    self, decode_hex, parse_hash_poseidon, parse_hash_sha256, parse_public_key, parse_u32,
    parse_u64, Challenge1PublicData, Hash, HashPoseidon, HashSHA256, HistoricalPublicData,
    MessageMetadata, HASH_POSEIDON_SIZE, HASH_SHA256_SIZE, MESSAGE_METADATA_SIZE, PUBLIC_KEY_SIZE,
};
use chrono::{Duration, Timelike};
use datajson::{Data, PublicKeyBLS, PublicKeyEdDSA, Slice};
use hash_sign::sign::{verify_bls_signature, BLSAggregateSignature};
use std::collections::HashSet;
use std::fs;
use std::ops::{Add, Sub};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

/// Maximum number of 'missing' messages per slice.
const MAX_MISSING_MEASUREMENTS_PER_SLICE: usize = 15;

/// Verify everything.
pub fn verify(params: Params, data: &Data, aggsig: Option<BLSAggregateSignature>) {
    println!("> Verifying");
    let t_all = Instant::now();

    let variant = crate::params::variant_to_string(params.hash_scheme, params.sig_variant);
    let window_duration = params.window_duration;
    let max_n_messages = params.n_messages;
    let n_historical = params.n_historical;
    let challenge1_name = format!("challenge1.{variant}");
    let historical_name = format!("historical.{variant}");
    let historical_i_name = |i: usize| format!("historical.{variant}-{i}");

    // Load proofs.
    println!("> Loading proof files");
    let mut t = Instant::now();
    let historical_proofs = (0..n_historical)
        .map(|i| read_historical_proof(&historical_i_name(i), params))
        .collect::<Vec<_>>();
    let challenge1_proof = read_challenge1_proof(&challenge1_name, params);
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

    // Let's check which historical slices we used in this proof
    // Assert given length aligns with public proof signal
    assert_eq!(data.historical.len(), historical_proofs.len());
    assert!(data.historical.len() <= n_historical);

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify historical proofs
    let mut unique_times = HashSet::<i64>::new();
    for (i, (slice, proof)) in data
        .historical
        .iter()
        .zip(historical_proofs.iter())
        .enumerate()
    {
        println!("> Verify historical proof {}", i);
        t = Instant::now();

        // Assert unique time
        assert!(unique_times.insert(slice.start.timestamp()));
        // Assert time in not-too-distant past (1month)
        // See https://debs.org/grand-challenges/2014/
        // println!("{:?} - {:?}", historical_slice.start, historical_slice.end);
        assert!(slice.start < current_slice_time);
        assert!(slice.start > current_slice_time.sub(Duration::days(30)));
        // Assert time rounded to quarter
        assert_eq!(slice.start.time().minute() % 15, 0);
        // Assert end time
        assert!(slice.start.add(window_duration) <= slice.end);
        // Assert that historical time is 2 quarters later at any previous day
        assert_eq!(
            slice.start.time(),
            current_slice_time.add(Duration::minutes(30)).time(),
        );

        // Verify messages
        match proof {
            HistoricalPublicData::Poseidon(p) => {
                // Check if proper keys are used
                assert!(pub_key.0.equals(p.publicKey.0.clone()));
                verify_messages(
                    &slice,
                    p.nMessages as usize,
                    &p.msgs,
                    device_id,
                    max_n_messages,
                )
            }
            HistoricalPublicData::PoseidonNoSig(p) => {
                let n_msgs = p.nMessages as usize;
                let hashes = &p
                    .hashes
                    .iter()
                    .map(|h| Hash::Poseidon(*h))
                    .collect::<Vec<_>>();
                verify_messages(&slice, n_msgs, &p.msgs, device_id, max_n_messages);
                match params.bls {
                    Bls::No => verify_eddsa_signatures_poseidon(&slice, n_msgs, &p.hashes, pub_key),
                    Bls::Yes => {
                        // Here we just gather the hashes, we will verify the aggregated
                        // signature later. Do not copy padded elements.
                        all_hashes.append(&mut hashes[0..n_msgs].to_vec());
                    }
                }
            }
            HistoricalPublicData::Sha256(p) => {
                // Check if proper keys are used
                assert!(pub_key.0.equals(p.publicKey.0.clone()));
                verify_messages(
                    &slice,
                    p.nMessages as usize,
                    &p.msgs,
                    device_id,
                    max_n_messages,
                );
            }
            HistoricalPublicData::Sha256NoSig(p) => {
                let n_msgs = p.nMessages as usize;
                let hashes = &p
                    .hashes
                    .iter()
                    .map(|h| Hash::Sha256(h.clone()))
                    .collect::<Vec<_>>();
                verify_messages(&slice, n_msgs, &p.msgs, device_id, max_n_messages);
                match params.bls {
                    Bls::No => verify_eddsa_signatures_sha256(&slice, n_msgs, &p.hashes, pub_key),
                    Bls::Yes => all_hashes.append(&mut hashes[0..n_msgs].to_vec()),
                }
            }
        };

        // Verify proof itself
        verify_proof(&historical_name, &historical_i_name(i));

        println!("| Time to verify historical proof {}: {:?}", i, t.elapsed());
    }

    // Verify challenge1 proof
    println!("> Verify challenge1 proof");
    t = Instant::now();

    // Assert link between verified historical proofs and challenge1 proof
    // Assert all historical hashes are included as public signals without re-use
    // Note: hashes can be in a different order, because they are sorted outside proof,
    // but every hash should be included exactly once.
    match params.hash_scheme {
        HashScheme::Poseidon => {
            let mut historical_hashes: Vec<HashPoseidon> = historical_proofs
                .iter()
                .map(|proof| match proof {
                    HistoricalPublicData::Poseidon(proof) => proof.avg_hashed,
                    HistoricalPublicData::PoseidonNoSig(proof) => proof.avg_hashed,
                    _ => panic!("historical proof uses wrong variant"),
                })
                .collect();
            historical_hashes.sort();
            let mut challenge1_hashes: Vec<HashPoseidon> = match challenge1_proof {
                Challenge1PublicData::Poseidon(ref proof) => proof.historicalHashes.clone(),
                Challenge1PublicData::PoseidonNoSig(ref proof) => proof.historicalHashes.clone(),
                _ => panic!("challenge1 proof uses wrong variant"),
            }
            .iter()
            .take(n_historical)
            .cloned()
            .collect();
            challenge1_hashes.sort();
            assert_eq!(historical_hashes.len(), challenge1_hashes.len());
            assert_eq!(historical_hashes, challenge1_hashes);
        }
        HashScheme::Sha256 => {
            let mut historical_hashes: Vec<HashSHA256> = historical_proofs
                .iter()
                .map(|proof| match proof {
                    HistoricalPublicData::Sha256(proof) => proof.avg_hashed.clone(),
                    HistoricalPublicData::Sha256NoSig(proof) => proof.avg_hashed.clone(),
                    _ => panic!("historical proof uses wrong variant"),
                })
                .collect();
            historical_hashes.sort();
            let mut challenge1_hashes: Vec<HashSHA256> = match challenge1_proof {
                Challenge1PublicData::Sha256(ref proof) => proof.historicalHashes.clone(),
                Challenge1PublicData::Sha256NoSig(ref proof) => proof.historicalHashes.clone(),
                _ => panic!("challenge1 proof uses wrong variant"),
            }
            .iter()
            .take(n_historical)
            .cloned()
            .collect();
            challenge1_hashes.sort();
            assert_eq!(historical_hashes.len(), challenge1_hashes.len());
            assert_eq!(historical_hashes, challenge1_hashes);
        }
    }

    // Verify messages
    let slice = &data.current;
    match challenge1_proof {
        Challenge1PublicData::Poseidon(ref p) => {
            // Check if proper keys are used
            assert!(pub_key.0.equals(p.publicKey.0.clone()));
            verify_messages(
                slice,
                p.nMessages as usize,
                &p.msgs,
                device_id,
                max_n_messages,
            )
        }
        Challenge1PublicData::PoseidonNoSig(ref p) => {
            let n_msgs = p.nMessages as usize;
            let hashes = &p
                .hashes
                .iter()
                .map(|h| Hash::Poseidon(*h))
                .collect::<Vec<_>>();
            verify_messages(slice, n_msgs, &p.msgs, device_id, max_n_messages);
            match params.bls {
                Bls::No => verify_eddsa_signatures_poseidon(&slice, n_msgs, &p.hashes, pub_key),
                Bls::Yes => all_hashes.append(&mut hashes[0..n_msgs].to_vec()),
            }
        }
        Challenge1PublicData::Sha256(ref p) => {
            // Check if proper keys are used
            assert!(pub_key.0.equals(p.publicKey.0.clone()));
            verify_messages(
                &slice,
                p.nMessages as usize,
                &p.msgs,
                device_id,
                max_n_messages,
            );
        }
        Challenge1PublicData::Sha256NoSig(ref p) => {
            let n_msgs = p.nMessages as usize;
            let hashes = &p
                .hashes
                .iter()
                .map(|h| Hash::Sha256(h.clone()))
                .collect::<Vec<_>>();
            verify_messages(&slice, n_msgs, &p.msgs, device_id, max_n_messages);
            match params.bls {
                Bls::No => verify_eddsa_signatures_sha256(&slice, n_msgs, &p.hashes, pub_key),
                Bls::Yes => all_hashes.append(&mut hashes[0..n_msgs].to_vec()),
            }
        }
    };

    // Verify proof itself
    verify_proof(&challenge1_name, &challenge1_name);

    println!("| Time to verify challenge1 proof: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &data.public_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
    let result = match challenge1_proof {
        Challenge1PublicData::Poseidon(ref p) => p.result,
        Challenge1PublicData::PoseidonNoSig(ref p) => p.result,
        Challenge1PublicData::Sha256(ref p) => p.result,
        Challenge1PublicData::Sha256NoSig(ref p) => p.result,
    };
    println!("The verified result is {:?}", result);
}

/// Read historical proof from file, returning the public inputs and outputs.
#[allow(non_snake_case)]
fn read_historical_proof(execution_name: &str, params: Params) -> HistoricalPublicData {
    println!("> Reading proof for {execution_name}");

    let mut inputs = read_proof_inputs(execution_name);

    let n_messages = params.n_messages;

    match (params.hash_scheme, params.sig_variant) {
        (HashScheme::Poseidon, SigVariant::Sig) => {
            assert_eq!(inputs.len(), proof::historical_poseidon_size(n_messages));
            let publicKey = parse_public_key(&inputs.drain(..PUBLIC_KEY_SIZE).collect::<Vec<_>>());
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..n_messages * MESSAGE_METADATA_SIZE)
                    .collect::<Vec<_>>(),
            );
            let avg = parse_u64(&inputs.remove(0));
            let avg_hashed = parse_hash_poseidon(&inputs.remove(0));
            assert!(inputs.is_empty());
            HistoricalPublicData::Poseidon(proof::HistoricalPoseidonPublicData {
                publicKey,
                nMessages,
                msgs,
                avg,
                avg_hashed,
            })
        }
        (HashScheme::Poseidon, SigVariant::NoSig) => {
            assert_eq!(
                inputs.len(),
                proof::historical_poseidon_no_sig_size(n_messages)
            );
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..n_messages * MESSAGE_METADATA_SIZE)
                    .collect::<Vec<_>>(),
            );
            let avg = parse_u64(&inputs.remove(0));
            let avg_hashed = parse_hash_poseidon(&inputs.remove(0));
            let hashes =
                parse_poseidon_hashes_from_inputs(&inputs.drain(..n_messages).collect::<Vec<_>>());
            assert!(inputs.is_empty());
            HistoricalPublicData::PoseidonNoSig(proof::HistoricalPoseidonNoSigPublicData {
                nMessages,
                msgs,
                avg,
                avg_hashed,
                hashes,
            })
        }
        (HashScheme::Sha256, SigVariant::Sig) => {
            assert_eq!(inputs.len(), proof::historical_sha256_size(n_messages));
            let publicKey = parse_public_key(&inputs.drain(..PUBLIC_KEY_SIZE).collect::<Vec<_>>());
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..n_messages * MESSAGE_METADATA_SIZE)
                    .collect::<Vec<_>>(),
            );
            let avg = parse_u64(&inputs.remove(0));
            let avg_hashed =
                parse_hash_sha256(&inputs.drain(..HASH_SHA256_SIZE).collect::<Vec<_>>());
            assert!(inputs.is_empty());
            HistoricalPublicData::Sha256(proof::HistoricalSha256PublicData {
                publicKey,
                nMessages,
                msgs,
                avg,
                avg_hashed,
            })
        }
        (HashScheme::Sha256, SigVariant::NoSig) => {
            assert_eq!(
                inputs.len(),
                proof::historical_sha256_no_sig_size(n_messages)
            );
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..n_messages * MESSAGE_METADATA_SIZE)
                    .collect::<Vec<_>>(),
            );
            let avg = parse_u64(&inputs.remove(0));
            let avg_hashed =
                parse_hash_sha256(&inputs.drain(..HASH_SHA256_SIZE).collect::<Vec<_>>());
            let hashes = parse_sha256_hashes_from_inputs(
                &inputs
                    .drain(..n_messages * HASH_SHA256_SIZE)
                    .collect::<Vec<_>>(),
            );
            assert!(inputs.is_empty());
            HistoricalPublicData::Sha256NoSig(proof::HistoricalSha256NoSigPublicData {
                nMessages,
                msgs,
                avg,
                avg_hashed,
                hashes,
            })
        }
    }
}

/// Read challenge1 proof from file, returning the public inputs and outputs.
#[allow(non_snake_case)]
fn read_challenge1_proof(execution_name: &str, params: Params) -> Challenge1PublicData {
    println!("> Reading proof for {execution_name}");

    let mut inputs = read_proof_inputs(execution_name);

    let n_messages = params.n_messages;
    let n_historical = params.n_historical;

    match (params.hash_scheme, params.sig_variant) {
        (HashScheme::Poseidon, SigVariant::Sig) => {
            assert_eq!(
                inputs.len(),
                proof::challenge1_poseidon_size(n_historical, n_messages)
            );
            let publicKey = parse_public_key(&inputs.drain(..PUBLIC_KEY_SIZE).collect::<Vec<_>>());
            let nHistorical = parse_u32(&inputs.remove(0));
            let historicalHashes = parse_poseidon_hashes_from_inputs(
                &inputs.drain(..n_historical).collect::<Vec<_>>(),
            );
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_messages * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let result = parse_u64(&inputs.remove(0));
            assert!(inputs.is_empty());
            Challenge1PublicData::Poseidon(proof::Challenge1PoseidonPublicData {
                publicKey,
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                result,
            })
        }
        (HashScheme::Poseidon, SigVariant::NoSig) => {
            assert_eq!(
                inputs.len(),
                proof::challenge1_poseidon_no_sig_size(n_historical, n_messages)
            );
            let nHistorical = parse_u32(&inputs.remove(0));
            let historicalHashes = parse_poseidon_hashes_from_inputs(
                &inputs.drain(..n_historical).collect::<Vec<_>>(),
            );
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_messages * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let result = parse_u64(&inputs.remove(0));
            let hashes =
                parse_poseidon_hashes_from_inputs(&inputs.drain(..n_messages).collect::<Vec<_>>());
            assert!(inputs.is_empty());
            Challenge1PublicData::PoseidonNoSig(proof::Challenge1PoseidonNoSigPublicData {
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                result,
                hashes,
            })
        }
        (HashScheme::Sha256, SigVariant::Sig) => {
            assert_eq!(
                inputs.len(),
                proof::challenge1_sha256_size(n_messages, n_historical)
            );
            let publicKey = parse_public_key(&inputs.drain(..PUBLIC_KEY_SIZE).collect::<Vec<_>>());
            let nHistorical = parse_u32(&inputs.remove(0));
            let historicalHashes = parse_sha256_hashes_from_inputs(
                &inputs
                    .drain(..n_historical * HASH_SHA256_SIZE)
                    .collect::<Vec<_>>(),
            );
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_messages * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let result = parse_u64(&inputs.remove(0));
            assert!(inputs.is_empty());
            Challenge1PublicData::Sha256(proof::Challenge1Sha256PublicData {
                publicKey,
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                result,
            })
        }
        (HashScheme::Sha256, SigVariant::NoSig) => {
            assert_eq!(
                inputs.len(),
                proof::challenge1_sha256_no_sig_size(n_messages, n_historical)
            );
            let nHistorical = parse_u32(&inputs.remove(0));
            let historicalHashes = parse_sha256_hashes_from_inputs(
                &inputs
                    .drain(..n_historical * HASH_SHA256_SIZE)
                    .collect::<Vec<_>>(),
            );
            let nMessages = parse_u32(&inputs.remove(0));
            let msgs = parse_messages_from_inputs(
                &inputs
                    .drain(..(n_messages * MESSAGE_METADATA_SIZE))
                    .collect::<Vec<_>>(),
            );
            let result = parse_u64(&inputs.remove(0));
            let hashes = parse_sha256_hashes_from_inputs(
                &inputs
                    .drain(..n_messages * HASH_SHA256_SIZE)
                    .collect::<Vec<_>>(),
            );
            assert!(inputs.is_empty());
            Challenge1PublicData::Sha256NoSig(proof::Challenge1Sha256NoSigPublicData {
                nHistorical,
                historicalHashes,
                nMessages,
                msgs,
                result,
                hashes,
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

/// Parse SHA256 hashes from public inputs.
fn parse_sha256_hashes_from_inputs(inputs: &[Vec<u8>]) -> Vec<proof::HashSHA256> {
    inputs
        .chunks_exact(HASH_SHA256_SIZE)
        .map(|c| parse_hash_sha256(&c))
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
    n_messages: usize,
    messages_metadata: &Vec<MessageMetadata>,
    device_id: u64,
    max_n_messages: usize,
) {
    // Check if padded (empty) messages are at the end
    for message in messages_metadata.iter().skip(n_messages) {
        assert_eq!(message.device_id, 0);
        assert_eq!(message.message_id, 0);
        assert_eq!(message.timestamp, 0);
    }

    // Remove padded messages for the rest of the checks
    let messages_metadata = &messages_metadata
        .iter()
        .take(n_messages)
        .collect::<Vec<_>>();

    // Check if data lengths match
    assert!(n_messages <= max_n_messages);
    assert!(n_messages <= slice.messages.len());
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
    n_messages: usize,
    hashes: &Vec<HashPoseidon>,
    public_key: &PublicKeyEdDSA,
) {
    let pk = &public_key.0;
    for (hash, message) in hashes.iter().zip(slice.messages.iter()).take(n_messages) {
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

/// Verify EdDSA signatures of messages in a slice, using the SHA256 hash.
fn verify_eddsa_signatures_sha256(
    _slice: &Slice,
    _n_messages: usize,
    _hashes: &Vec<HashSHA256>,
    _public_key: &PublicKeyEdDSA,
) {
    // unimplemented!("we don't support the combination of SHA256 & EdDSA signatures");
    /*
    let pk = &public_key.0;
    for (hash, message) in hashes.iter().zip(slice.messages.iter()).take(n_messages) {
        // Hash is coming from proof, signature is coming from sensor (data.json).
        // Look up signature in data and re-create it.
        // Verify signature.
        let t = Instant::now();
        // assert!(babyjubjub_rs::verify(pk.clone(), signature, hash_bi));
        eprintln!(
            "| Time to verify signature of message {}: {:?}",
            message.id,
            t.elapsed()
        );
    }
    */
}

/// Verify BLS aggregated signature `aggsig` of messages of which the `hashes` are
/// given.
fn verify_bls_signatures(
    aggsig: BLSAggregateSignature,
    hashes: &Vec<Hash>,
    public_key: &PublicKeyBLS,
) {
    println!("> Verify BLS aggregated signature");
    // Convert hashes to bytes (SHA256 = bytes; Poseidon = field to bytes)
    let hashes_as_bytes: Vec<Vec<u8>> = hashes
        .iter()
        .map(|h| match h {
            Hash::Sha256(h) => h.clone(),
            Hash::Poseidon(h) => datajson::utils::field_to_bytes(h),
        })
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
