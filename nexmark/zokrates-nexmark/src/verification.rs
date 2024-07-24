// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the verification.

use crate::params::{program_name, Bls, Params, SigVariant};
use crate::proof::{self, HashPoseidon, MessageMetadata};
use crate::zokrates;
use crate::Options;
use hash_sign::sign::{verify_bls_signature, BLSAggregateSignature};
use nexmark_datajson::{
    eddsa_signature_from_json, public_key_bls_from_json, public_key_eddsa_from_json, DataJson, Fr,
    PublicKeyBLS, PublicKeyEdDSA, SignedMessageJson,
};
use std::collections::HashSet;
use std::time::Instant;

pub fn q1(
    data: &DataJson,
    aggsig: Option<BLSAggregateSignature>,
    params: Params,
    _options: Options,
) {
    println!("> Verifying");
    let t_all = Instant::now();

    let program_name = program_name("q1", &params);
    let n_messages = data.bids.len();

    // Verify proofs themselves.
    zokrates::verify_proof(&program_name, &program_name);

    // Fetch pubkey from known DB.
    let pub_key_eddsa = public_key_eddsa_from_json(&data.public_key_eddsa);
    let pub_key_bls = public_key_bls_from_json(&data.public_key_bls);
    let device_id = 0;

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify inputs.
    println!("> Verifying proof inputs");
    let t = Instant::now();
    let proof_json = zokrates::open_proof_file(&program_name);
    let mut inputs = proof::read_proof_inputs(proof_json);
    match params.sig_variant {
        SigVariant::Sig => {
            let p = proof::read_q1_poseidon_proof(&mut inputs, n_messages);
            assert!(pub_key_eddsa.0.equals(p.publicKey.0.clone()));
            verify_messages(&data.bids, &p.msgs, device_id);
        }
        SigVariant::NoSig => {
            let p = proof::read_q1_poseidon_nosig_proof(&mut inputs, n_messages);
            verify_messages(&data.bids, &p.msgs, device_id);
            match params.bls {
                Bls::No => {
                    verify_eddsa_signatures_poseidon(&data.bids, &p.msgs, &p.hashes, &pub_key_eddsa)
                }
                Bls::Yes => all_hashes = p.hashes,
            }
        }
    }
    println!("| Time to verify proof inputs: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &pub_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
}

pub fn q4(
    data: &DataJson,
    n_a: usize,
    n_b: usize,
    aggsig: Option<BLSAggregateSignature>,
    params: Params,
    _options: Options,
) {
    println!("> Verifying");
    let t_all = Instant::now();

    let program_name_a = program_name("q4a", &params);
    let program_name_b = program_name("q4b", &params);
    let execution_name_a = |i: usize| format!("{program_name_a}-{i}");
    let execution_name_b = |i: usize| format!("{program_name_b}-{i}");
    // Hard-coded in nexmark.rs
    let n_messages_a = 50;
    let n_messages_b = 10;

    // Verify proofs themselves.
    for i in 0..n_a {
        zokrates::verify_proof(&program_name_a, &execution_name_a(i));
    }
    for i in 0..n_b {
        zokrates::verify_proof(&program_name_b, &execution_name_b(i));
    }

    // Fetch pubkey from known DB.
    let pub_key_eddsa = public_key_eddsa_from_json(&data.public_key_eddsa);
    let pub_key_bls = public_key_bls_from_json(&data.public_key_bls);
    let device_id = 0;

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify inputs.
    println!("> Verifying proof inputs");
    let t = Instant::now();
    // q4a
    let mut output_hashes = Vec::new();
    for i in 0..n_a {
        let proof_json = zokrates::open_proof_file(&execution_name_a(i));
        let mut inputs = proof::read_proof_inputs(proof_json);
        match params.sig_variant {
            SigVariant::Sig => {
                let p = proof::read_q4a_poseidon_proof(&mut inputs, n_messages_a);
                assert!(pub_key_eddsa.0.equals(p.publicKey.0.clone()));
                verify_messages(&data.bids, &p.msgs, device_id);
                output_hashes.push(p.price_hashed);
            }
            SigVariant::NoSig => {
                let p = proof::read_q4a_poseidon_nosig_proof(&mut inputs, n_messages_a);
                let n_messages = n_non_zero_messages(&p.msgs);
                verify_messages(&data.bids, &p.msgs, device_id);
                match params.bls {
                    Bls::No => verify_eddsa_signatures_poseidon(
                        &data.bids,
                        &p.msgs,
                        &p.hashes,
                        &pub_key_eddsa,
                    ),
                    Bls::Yes => {
                        let mut hashes = p.hashes[..n_messages].to_vec();
                        all_hashes.append(&mut hashes);
                    }
                }
                output_hashes.push(p.price_hashed);
            }
        }
    }
    // q4b
    let mut input_hashes = Vec::new();
    for i in 0..n_b {
        let proof_json = zokrates::open_proof_file(&execution_name_b(i));
        let mut inputs = proof::read_proof_inputs(proof_json);
        match params.sig_variant {
            SigVariant::Sig => {
                let p = proof::read_q4b_poseidon_proof(&mut inputs, n_messages_b);
                input_hashes.extend(p.valsHashes);
            }
            SigVariant::NoSig => {
                let p = proof::read_q4b_poseidon_nosig_proof(&mut inputs, n_messages_b);
                input_hashes.extend(p.valsHashes);
            }
        }
    }
    // Check if all outputs of q4a are a permutation of all inputs of q4b.
    // TODO this is actually not sufficient: we should also check if they were grouped
    // correctly.
    let input_hashes = filter_zero_hashes(&input_hashes);
    assert!(
        is_permutation(&input_hashes, &output_hashes),
        "Hashes input to q4b are not a permutation of hashes output by q4a; \
        output of q4a = {:?}, input of q4b = {:?}",
        output_hashes,
        input_hashes
    );
    println!("| Time to verify proof inputs: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &pub_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
}

pub fn q5(
    data: &DataJson,
    n_a: usize,
    aggsig: Option<BLSAggregateSignature>,
    params: Params,
    _options: Options,
) {
    println!("> Verifying");
    let t_all = Instant::now();

    let program_name_a = program_name("q5a", &params);
    let program_name_b = program_name("q5b", &params);
    let execution_name_a = |i: usize| format!("{program_name_a}-{i}");
    // Hard-coded in nexmark.rs
    let n_messages_a = 50;
    let n_messages_b = data.auctions.len();

    // Verify proofs themselves.
    for i in 0..n_a {
        zokrates::verify_proof(&program_name_a, &execution_name_a(i));
    }
    zokrates::verify_proof(&program_name_b, &program_name_b);

    // Fetch pubkey from known DB.
    let pub_key_eddsa = public_key_eddsa_from_json(&data.public_key_eddsa);
    let pub_key_bls = public_key_bls_from_json(&data.public_key_bls);
    let device_id = 0;

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify inputs.
    println!("> Verifying proof inputs");
    let t = Instant::now();
    // q5a
    let mut output_hashes = Vec::new();
    for i in 0..n_a {
        let proof_json = zokrates::open_proof_file(&execution_name_a(i));
        let mut inputs = proof::read_proof_inputs(proof_json);
        match params.sig_variant {
            SigVariant::Sig => {
                let p = proof::read_q5a_poseidon_proof(&mut inputs, n_messages_a);
                assert!(pub_key_eddsa.0.equals(p.publicKey.0.clone()));
                verify_messages(&data.bids, &p.msgs, device_id);
                output_hashes.push(p.count_hashed);
            }
            SigVariant::NoSig => {
                let p = proof::read_q5a_poseidon_nosig_proof(&mut inputs, n_messages_a);
                let n_messages = n_non_zero_messages(&p.msgs);
                verify_messages(&data.bids, &p.msgs, device_id);
                match params.bls {
                    Bls::No => verify_eddsa_signatures_poseidon(
                        &data.bids,
                        &p.msgs,
                        &p.hashes,
                        &pub_key_eddsa,
                    ),
                    Bls::Yes => {
                        let mut hashes = p.hashes[..n_messages].to_vec();
                        all_hashes.append(&mut hashes);
                    }
                }
                output_hashes.push(p.count_hashed);
            }
        }
    }
    // q5b
    let input_hashes;
    {
        let proof_json = zokrates::open_proof_file(&program_name_b);
        let mut inputs = proof::read_proof_inputs(proof_json);
        match params.sig_variant {
            SigVariant::Sig => {
                let p = proof::read_q5b_poseidon_proof(&mut inputs, n_messages_b);
                input_hashes = p.valsHashes;
            }
            SigVariant::NoSig => {
                let p = proof::read_q5b_poseidon_nosig_proof(&mut inputs, n_messages_b);
                input_hashes = p.valsHashes;
            }
        }
    }
    // Check if all outputs of q5a are a permutation of the inputs of q5b.
    let input_hashes = filter_zero_hashes(&input_hashes);
    assert!(
        is_permutation(&input_hashes, &output_hashes),
        "Hashes input to q5b are not a permutation of hashes output by q5a; \
        output of q5a = {:?}, input of q5b = {:?}",
        output_hashes,
        input_hashes
    );
    println!("| Time to verify proof inputs: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &pub_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
}

pub fn q6(
    data: &DataJson,
    n_a: usize,
    n_b: usize,
    aggsig: Option<BLSAggregateSignature>,
    params: Params,
    _options: Options,
) {
    println!("> Verifying");
    let t_all = Instant::now();

    let program_name_a = program_name("q6a", &params);
    let program_name_b = program_name("q6b", &params);
    let execution_name_a = |i: usize| format!("{program_name_a}-{i}");
    let execution_name_b = |i: usize| format!("{program_name_b}-{i}");
    // Hard-coded in nexmark.rs
    let n_messages_a = 50;
    let n_messages_b = 10;

    // Verify proofs themselves.
    for i in 0..n_a {
        zokrates::verify_proof(&program_name_a, &execution_name_a(i));
    }
    for i in 0..n_b {
        zokrates::verify_proof(&program_name_b, &execution_name_b(i));
    }

    // Fetch pubkey from known DB.
    let pub_key_eddsa = public_key_eddsa_from_json(&data.public_key_eddsa);
    let pub_key_bls = public_key_bls_from_json(&data.public_key_bls);
    let device_id = 0;

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify inputs.
    println!("> Verifying proof inputs");
    let t = Instant::now();
    // q6a
    let mut output_hashes = Vec::new();
    for i in 0..n_a {
        let proof_json = zokrates::open_proof_file(&execution_name_a(i));
        let mut inputs = proof::read_proof_inputs(proof_json);
        match params.sig_variant {
            SigVariant::Sig => {
                let p = proof::read_q6a_poseidon_proof(&mut inputs, n_messages_a);
                assert!(pub_key_eddsa.0.equals(p.publicKey.0.clone()));
                verify_messages(&data.bids, &p.msgs, device_id);
                output_hashes.push(p.price_hashed);
            }
            SigVariant::NoSig => {
                let p = proof::read_q6a_poseidon_nosig_proof(&mut inputs, n_messages_a);
                let n_messages = n_non_zero_messages(&p.msgs);
                verify_messages(&data.bids, &p.msgs, device_id);
                match params.bls {
                    Bls::No => verify_eddsa_signatures_poseidon(
                        &data.bids,
                        &p.msgs,
                        &p.hashes,
                        &pub_key_eddsa,
                    ),
                    Bls::Yes => {
                        let mut hashes = p.hashes[..n_messages].to_vec();
                        all_hashes.append(&mut hashes);
                    }
                }
                output_hashes.push(p.price_hashed);
            }
        }
    }
    // q6b
    let mut input_hashes = Vec::new();
    for i in 0..n_b {
        let proof_json = zokrates::open_proof_file(&execution_name_b(i));
        let mut inputs = proof::read_proof_inputs(proof_json);
        match params.sig_variant {
            SigVariant::Sig => {
                let p = proof::read_q6b_poseidon_proof(&mut inputs, n_messages_b);
                input_hashes.extend(p.valsHashes);
            }
            SigVariant::NoSig => {
                let p = proof::read_q6b_poseidon_nosig_proof(&mut inputs, n_messages_b);
                input_hashes.extend(p.valsHashes);
            }
        }
    }
    // Check if all outputs of q6a are a permutation of all inputs of q6b.
    // TODO this is actually not sufficient: we should also check if they were grouped
    // correctly.
    let input_hashes = filter_zero_hashes(&input_hashes);
    assert!(
        is_permutation(&input_hashes, &output_hashes),
        "Hashes input to q6b are not a permutation of hashes output by q6a; \
        output of q6a = {:?}, input of q6b = {:?}",
        output_hashes,
        input_hashes
    );
    println!("| Time to verify proof inputs: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &pub_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
}

pub fn q7(
    data: &DataJson,
    aggsig: Option<BLSAggregateSignature>,
    params: Params,
    _options: Options,
) {
    println!("> Verifying");
    let t_all = Instant::now();

    let program_name = program_name("q7", &params);
    let n_messages = data.bids.len();

    // Verify proofs themselves.
    zokrates::verify_proof(&program_name, &program_name);

    // Fetch pubkey from known DB.
    let pub_key_eddsa = public_key_eddsa_from_json(&data.public_key_eddsa);
    let pub_key_bls = public_key_bls_from_json(&data.public_key_bls);
    let device_id = 0;

    // Gather all hashes, used for BLS signature verification
    let mut all_hashes = Vec::new();

    // Verify inputs.
    println!("> Verifying proof inputs");
    let t = Instant::now();
    let proof_json = zokrates::open_proof_file(&program_name);
    let mut inputs = proof::read_proof_inputs(proof_json);
    match params.sig_variant {
        SigVariant::Sig => {
            let p = proof::read_q7_poseidon_proof(&mut inputs, n_messages);
            assert!(pub_key_eddsa.0.equals(p.publicKey.0.clone()));
            verify_messages(&data.bids, &p.msgs, device_id);
        }
        SigVariant::NoSig => {
            let p = proof::read_q7_poseidon_nosig_proof(&mut inputs, n_messages);
            verify_messages(&data.bids, &p.msgs, device_id);
            match params.bls {
                Bls::No => {
                    verify_eddsa_signatures_poseidon(&data.bids, &p.msgs, &p.hashes, &pub_key_eddsa)
                }
                Bls::Yes => all_hashes = p.hashes,
            }
        }
    }
    println!("| Time to verify proof inputs: {:?}", t.elapsed());

    // Verify BLS aggregated signature
    if params.bls == Bls::Yes && !all_hashes.is_empty() {
        let aggsig = aggsig.expect("BLS aggregated signature is missing");
        eprintln!("Number of hashes = {}", all_hashes.len());
        verify_bls_signatures(aggsig, &all_hashes, &pub_key_bls);
    }

    println!("| Time to verify everything: {:?}", t_all.elapsed());

    println!("Verification successful");
}

/// Verify properties of messages.
fn verify_messages(
    _messages: &Vec<SignedMessageJson>,
    messages_metadata: &Vec<MessageMetadata>,
    _device_id: u64,
) {
    // Filter out zero messages.
    let messages_metadata = filter_zero_messages(messages_metadata);

    // Check if msg_ids are unique
    let mut unique_ids = HashSet::<u64>::new();
    for message in messages_metadata {
        assert!(unique_ids.insert(message.message_id));
    }

    // Check message device_ids
    // TODO can this be safely skipped?
    // for message in messages_metadata {
    //     assert_eq!(message.device_id, device_id);
    // }
}

/// Verify EdDSA signatures of messages, using the Poseidon hash.
/// The hash is coming from the proof; the signature is coming from the sensor (data.json).
///
/// Note that the messages need not be ordered, while messages_metadata is ordered in
/// the same way as the hashes.
fn verify_eddsa_signatures_poseidon(
    messages: &Vec<SignedMessageJson>,
    messages_metadata: &Vec<MessageMetadata>,
    hashes: &Vec<HashPoseidon>,
    public_key: &PublicKeyEdDSA,
) {
    let pk = &public_key.0;
    for (hash, metadata) in hashes.iter().zip(messages_metadata.iter()) {
        // Skip zero messages.
        if is_zero_message(metadata) {
            continue;
        }
        // Look up message.
        let message = find_message_by_id(messages, metadata.message_id).expect("Message not found");
        // Hash is coming from proof, signature is coming from sensor (data.json).
        // Look up signature in data and re-create it.
        let signature = hash_sign::sign::convert_eddsa_signature(&eddsa_signature_from_json(
            &message.signature_eddsa_poseidon_salted,
        ));
        let hash_bi = hash_sign::utils::field_to_bigint(hash);
        // Verify signature.
        let t = Instant::now();
        assert!(babyjubjub_rs::verify(pk.clone(), signature, hash_bi));
        eprintln!(
            "| Time to verify signature of message {}: {:?}",
            message.message.id,
            t.elapsed()
        );
    }
}

/// Verify BLS aggregated signature `aggsig` of messages of which the `hashes` are
/// given.
fn verify_bls_signatures(
    aggsig: BLSAggregateSignature,
    hashes: &Vec<HashPoseidon>,
    public_key: &PublicKeyBLS,
) {
    println!("> Verify BLS aggregated signature");
    // Convert hashes to bytes (SHA256 = bytes; Poseidon = field to bytes)
    let hashes_as_bytes: Vec<Vec<u8>> = hashes
        .iter()
        .map(|h| hash_sign::utils::field_to_bytes(h))
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

/// Find message by ID.
fn find_message_by_id(
    messages: &Vec<SignedMessageJson>,
    message_id: u64,
) -> Option<&SignedMessageJson> {
    messages.iter().find(|m| m.message.id == message_id)
}

/// Check if a message is a zero message.
fn is_zero_message(message: &MessageMetadata) -> bool {
    message.message_id == 0 && message.timestamp == 0
}

/// Filter zero messages from a vector of messages.
fn filter_zero_messages(messages: &Vec<MessageMetadata>) -> Vec<MessageMetadata> {
    messages
        .iter()
        .filter(|m| !is_zero_message(m))
        .cloned()
        .collect()
}

/// Get number of non-zero messages in a vector of messages.
/// Normally, these should be at the beginning of the vector.
fn n_non_zero_messages(messages: &Vec<MessageMetadata>) -> usize {
    messages.iter().take_while(|m| !is_zero_message(m)).count()
}

use ff::PrimeField;
lazy_static! {
    pub static ref ZERO_HASH: Fr = Fr::from_str("0").unwrap();
}

/// Check if a hash is a zero hash.
fn is_zero_hash(hash: &HashPoseidon) -> bool {
    *hash == *ZERO_HASH
}

/// Filter zero hashes from a vector of hashes.
fn filter_zero_hashes(hashes: &Vec<HashPoseidon>) -> Vec<HashPoseidon> {
    hashes
        .iter()
        .filter(|h| !is_zero_hash(h))
        .cloned()
        .collect()
}

/// Check if two vectors are a permutation of each other.
fn is_permutation<T: std::cmp::Ord + Clone>(a: &Vec<T>, b: &Vec<T>) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.sort();
    b.sort();
    a == b
}
