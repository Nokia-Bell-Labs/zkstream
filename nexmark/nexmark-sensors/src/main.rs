// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use babyjubjub_rs::PrivateKey;
use blst::min_pk as bls;
use clap::Parser;
use hash_sign::hash::{generate_salt, salt_to_fields};
use hash_sign::{hash, sign};
use k256::ecdsa;
use nexmark_datajson::{
    signed_message_to_json, Data, DataJson, Message, MessageValue, PublicKeyBLS, PublicKeyECDSA,
    PublicKeyEdDSA, SignedMessage, SignedMessageJson,
};
use std::fs::File;
use std::path::PathBuf;

/// Run a program on incoming messages and generate a proof.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to incoming data JSON. Default: data/data.json.
    #[arg(short = 'i', long)]
    input: Option<PathBuf>,

    /// Path where output JSON is written. Default: data.json.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

fn main() {
    #![allow(non_snake_case)]

    // Parse command line arguments.
    let cli: Cli = Cli::parse();
    let input_path = cli.input.unwrap_or(PathBuf::from("data/data.json"));
    let output_path = cli.output.unwrap_or(PathBuf::from("data.json"));

    // Generate private and public key for use with EdDSA & BabyJubJub.
    const PRIVATE_KEY_EDDSA_HEX: &'static str =
        "046A44B42846312EEE2F16708C1C508DE917AC42703CBD0531281CAFB5857A51";
    let private_key_eddsa =
        PrivateKey::import(hex::decode(PRIVATE_KEY_EDDSA_HEX).unwrap()).unwrap();
    let public_key_eddsa = private_key_eddsa.public();
    let public_key_eddsa_json =
        nexmark_datajson::public_key_eddsa_to_json(&PublicKeyEdDSA(public_key_eddsa));

    // Generate private and public key for use with ECDSA.
    const PRIVATE_KEY_ECDSA_HEX: &'static str =
        "046A44B42846312EEE2F16708C1C508DE917AC42703CBD0531281CAFB5857A51";
    let private_key_ecdsa =
        ecdsa::SigningKey::from_slice(&hex::decode(PRIVATE_KEY_ECDSA_HEX).unwrap()).unwrap();
    let public_key_ecdsa = private_key_ecdsa.verifying_key();
    let public_key_ecdsa_json =
        nexmark_datajson::public_key_ecdsa_to_json(&PublicKeyECDSA(*public_key_ecdsa));

    // Generate private and public key for use with BLS.
    const PRIVATE_KEY_BLS: &'static [u8] = &[
        112, 114, 208, 211, 128, 163, 61, 0, 145, 43, 197, 117, 210, 101, 173, 30, 4, 129, 55, 198,
        191, 98, 120, 9, 104, 82, 38, 109, 205, 12, 112, 121,
    ];
    let private_key_bls: bls::SecretKey =
        bls::SecretKey::from_bytes(PRIVATE_KEY_BLS).expect("could not create BLS secret key");
    let public_key_bls = private_key_bls.sk_to_pk();
    let key_pair_bls = sign::BLSKeyPair {
        sk: private_key_bls,
        pk: public_key_bls,
    };
    let public_key_bls_json =
        nexmark_datajson::public_key_bls_to_json(&PublicKeyBLS(public_key_bls));

    // Read input file.
    let file = File::open(input_path).expect("could not open JSON file");
    let data: Data = serde_json::from_reader(file).expect("could not read JSON file");
    let mut messages: Vec<SignedMessageJson> = Vec::new();

    for (i, bid) in data.bids.iter().enumerate() {
        // Unique number, not consecutive.
        let msg_id = i as u64;
        // Value.
        let value = MessageValue {
            auction: bid.auction,
            price: bid.price,
        };
        eprintln!("Value: {:?}", value);
        // Message.
        let message = Message {
            id: msg_id,
            device_id: bid.bidder,
            timestamp: bid.dateTime,
            value,
        };

        let salt_bytes = generate_salt();
        let salt_fields = salt_to_fields(&salt_bytes);
        // eprintln!("Salt (bytes): {:?}", &salt_bytes);
        eprintln!("Salt (hex): {:?}", hex::encode(salt_bytes));
        // eprintln!("Salt (fields): {:?}", salt_fields);

        // Hash using both hash functions (SHA256 & Poseidon) and with/without salt.
        let hash_sha256_unsalted = hash::sha256_unsalted(&message);
        eprintln!(
            "Hash unsalted SHA256: {:?}",
            hex::encode(hash_sha256_unsalted.clone())
        );
        let hash_sha256_salted = hash::sha256_salted(&message, &salt_bytes);
        eprintln!(
            "Hash salted SHA256: {:?}",
            hex::encode(hash_sha256_salted.clone())
        );
        let hash_poseidon_unsalted = hash::poseidon_unsalted(&message);
        eprintln!("Hash unsalted Poseidon: {:?}", hash_poseidon_unsalted);
        let hash_poseidon_salted = hash::poseidon_salted(&message, &salt_fields);
        eprintln!("Hash salted Poseidon: {:?}", hash_poseidon_salted);

        // Sign using all possible combinations of hash functions, signatures schemes, and
        // with/without salt.
        let signature_eddsa_sha256_unsalted =
            sign::eddsa_sha256_unsalted(&message, &private_key_eddsa);
        eprintln!(
            "Signature unsalted SHA256 EdDSA-BabyJubJub: {:?}",
            signature_eddsa_sha256_unsalted
        );
        let signature_eddsa_sha256_salted =
            sign::eddsa_sha256_salted(&message, &salt_bytes, &private_key_eddsa);
        eprintln!(
            "Signature salted SHA256 EdDSA-BabyJubJub: {:?}",
            signature_eddsa_sha256_salted
        );
        let signature_eddsa_poseidon_unsalted =
            sign::eddsa_poseidon_unsalted(&message, &private_key_eddsa);
        eprintln!(
            "Signature unsalted Poseidon EdDSA-BabyJubJub: {:?}",
            signature_eddsa_poseidon_unsalted
        );
        let signature_eddsa_poseidon_salted =
            sign::eddsa_poseidon_salted(&message, &salt_fields, &private_key_eddsa);
        eprintln!(
            "Signature salted Poseidon EdDSA-BabyJubJub: {:?}",
            signature_eddsa_poseidon_salted
        );
        let signature_ecdsa_sha256_unsalted =
            sign::ecdsa_sha256_unsalted(&message, &private_key_ecdsa);
        eprintln!(
            "Signature unsalted SHA256 ECDSA: {:?}",
            signature_ecdsa_sha256_unsalted
        );
        let signature_ecdsa_sha256_salted =
            sign::ecdsa_sha256_salted(&message, &salt_bytes, &private_key_ecdsa);
        eprintln!(
            "Signature salted SHA256 ECDSA: {:?}",
            signature_ecdsa_sha256_salted
        );
        let signature_bls_sha256_salted =
            sign::bls_sha256_salted(&message, &salt_bytes, &key_pair_bls);
        eprintln!(
            "Signature salted SHA256 BLS: {:?}",
            signature_bls_sha256_salted
        );
        let signature_bls_poseidon_salted =
            sign::bls_poseidon_salted(&message, &salt_fields, &key_pair_bls);
        eprintln!(
            "Signature salted Poseidon BLS: {:?}",
            signature_bls_poseidon_salted
        );

        let signed = SignedMessage {
            message,
            salt: salt_bytes.to_vec(),
            salt_fields,
            hash_sha256_unsalted,
            hash_sha256_salted,
            hash_poseidon_unsalted,
            hash_poseidon_salted,
            signature_eddsa_sha256_unsalted,
            signature_eddsa_sha256_salted,
            signature_eddsa_poseidon_unsalted,
            signature_eddsa_poseidon_salted,
            signature_ecdsa_sha256_unsalted,
            signature_ecdsa_sha256_salted,
            signature_bls_sha256_salted,
            signature_bls_poseidon_salted,
        };

        messages.push(signed_message_to_json(&signed));
    }

    // Print some info.
    eprintln!("Number of messages: {}", messages.len());
    eprintln!("Number of persons: {}", data.persons.len());
    eprintln!("Number of auctions: {}", data.auctions.len());
    eprintln!("Number of bids: {}", data.bids.len());

    // Output as JSON.
    let data_out = DataJson {
        public_key_eddsa: public_key_eddsa_json,
        public_key_ecdsa: public_key_ecdsa_json,
        public_key_bls: public_key_bls_json,
        persons: data.persons,
        auctions: data.auctions,
        bids: messages,
    };
    let output_file = File::create(output_path).expect("could not create JSON file");
    serde_json::to_writer_pretty(output_file, &data_out).expect("could not write JSON file");
}
