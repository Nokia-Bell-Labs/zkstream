// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use babyjubjub_rs::PrivateKey;
use blst::min_pk as bls;
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use clap::Parser;
use debs_datajson::{
    data_to_json, Data, Message, PublicKeyBLS, PublicKeyECDSA, PublicKeyEdDSA, SignedMessage, Slice,
};
use hash_sign::hash::{generate_salt, salt_to_fields};
use hash_sign::{hash, sign};
use k256::ecdsa;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

/// Run a program on incoming messages and generate a proof.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to data CSV. Default: data.csv.
    #[arg(short = 'd', long)]
    csv: Option<PathBuf>,

    /// Path where output JSON is written. Default: data.json.
    #[arg(short = 'j', long)]
    json: Option<PathBuf>,
}

/// A line in the data.csv file.
///
/// The CSV file is expected to have the following columns:
/// 0. id – a unique identifier of the measurement [32 bit unsigned integer value]
/// 1. timestamp – timestamp of measurement (number of seconds since January 1, 1970,
///    00:00:00 GMT) [32 bit unsigned integer value]
/// 2. value – the measurement [32 bit floating point]
/// 3. property – type of the measurement: 0 for work or 1 for load [boolean]
/// 4. plug_id – a unique identifier (within a household) of the smart plug [32 bit
///    unsigned integer value]
/// 5. household_id – a unique identifier of a household (within a house) where the
///    plug is located [32 bit unsigned integer value]
/// 6. house_id – a unique identifier of a house where the household with the plug is
///    located [32 bit unsigned integer value]
#[derive(Debug, Deserialize)]
struct CSVRecord {
    /// A unique identifier of the measurement.
    id: u32,
    /// Timestamp of measurement (number of seconds since January 1, 1970, 00:00:00 GMT).
    timestamp: u32,
    /// The measurement.
    value: f32,
    /// Type of the measurement: 0 for work or 1 for load.
    property: u8,
    /// A unique identifier (within a household) of the smart plug.
    plug_id: u32,
    /// A unique identifier of a household (within a house) where the plug is located.
    household_id: u32,
    /// A unique identifier of a house where the household with the plug is located.
    house_id: u32,
}

fn main() {
    #![allow(non_snake_case)]

    // Assume it is now September 30th, 2013, 00:13:50 UTC+02:00.
    // We will predict the load for 2013-09-30 00:30 to 00:45.
    // Hence, the input data is:
    // 1. the data in the current (partial) slice, i.e. 2013-09-30 00:00 to now.
    // 2. the data in each historical slice, i.e. 00:30 to 00:45 for all previous days.
    //
    // The above assumes a window size of 15 minutes. As we want to vary the window size,
    // up to 1 hour, we actually use a window size of 1 hour and then truncate the data
    // up to the chosen window size where needed.
    //
    // Note: the DEBS challenge data is in timezone UTC+02:00. Below, we convert to UTC.
    let NOW: DateTime<Utc> = Utc.with_ymd_and_hms(2013, 9, 29, 22, 13, 50).unwrap();
    let CURRENT_SLICE_START: DateTime<Utc> = Utc.with_ymd_and_hms(2013, 9, 29, 22, 0, 0).unwrap();
    let CURRENT_SLICE_END: DateTime<Utc> = NOW;
    let HISTORICAL_SLICE_START: NaiveTime = NaiveTime::from_hms_opt(22, 30, 0).unwrap();
    let HISTORICAL_SLICE_END: NaiveTime = NaiveTime::from_hms_opt(23, 30, 0).unwrap();

    // Check if a timestamp is in the current slice.
    let in_current_slice = |timestamp: DateTime<Utc>| {
        timestamp >= CURRENT_SLICE_START && timestamp <= CURRENT_SLICE_END
    };
    // Check if a timestamp is in a historical slice.
    let in_historical_slice = |timestamp: DateTime<Utc>| {
        let in_slice =
            timestamp.time() >= HISTORICAL_SLICE_START && timestamp.time() <= HISTORICAL_SLICE_END;
        let before_now = timestamp < NOW;
        in_slice && before_now
    };

    // Parse command line arguments.
    let cli: Cli = Cli::parse();
    let csv_path = cli.csv.unwrap_or(PathBuf::from("data.csv"));
    let json_path = cli.json.unwrap_or(PathBuf::from("data.json"));

    // Generate private and public key for use with EdDSA & BabyJubJub.
    const PRIVATE_KEY_EDDSA_HEX: &'static str =
        "046A44B42846312EEE2F16708C1C508DE917AC42703CBD0531281CAFB5857A51";
    let private_key_eddsa =
        PrivateKey::import(hex::decode(PRIVATE_KEY_EDDSA_HEX).unwrap()).unwrap();
    let public_key_eddsa = private_key_eddsa.public();

    // Generate private and public key for use with ECDSA.
    const PRIVATE_KEY_ECDSA_HEX: &'static str =
        "046A44B42846312EEE2F16708C1C508DE917AC42703CBD0531281CAFB5857A51";
    let private_key_ecdsa =
        ecdsa::SigningKey::from_slice(&hex::decode(PRIVATE_KEY_ECDSA_HEX).unwrap()).unwrap();
    let public_key_ecdsa = private_key_ecdsa.verifying_key();

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

    // Read CSV file.
    let file = File::open(csv_path).expect("could not open CSV file");
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);

    let mut current_slice = Slice {
        start: CURRENT_SLICE_START,
        end: CURRENT_SLICE_END,
        messages: Vec::new(),
    };
    let mut historical_slices: Vec<Slice> = Vec::new();
    let mut last_historical_slice_date: Option<NaiveDate> = None;

    for result in rdr.deserialize() {
        let record: CSVRecord = result.expect("could not deserialize CSV record");

        // Filter out relevant data: we're only interested in plug 0 in household 0 of
        // house 0, and only its load data (column 3).
        // Note: this filter is actually already done in the example data, so this
        // should return everything.
        if !(record.plug_id == 0
            && record.household_id == 0
            && record.house_id == 0
            && record.property == 1)
        {
            continue;
        }

        // Filter relevant data based on timestamp.
        let timestamp = Utc.timestamp_opt(record.timestamp as i64, 0).unwrap();
        let in_current = in_current_slice(timestamp);
        let in_historical = in_historical_slice(timestamp);
        let included = in_current || in_historical;
        if !included {
            continue;
        }

        // Unique number, not consecutive.
        let msg_id = record.id as u64;
        // Device id. 8 bytes in total.
        let device_id: Vec<u8> = [
            (record.house_id as u16).to_le_bytes(),     // [u8; 2]
            (record.household_id as u16).to_le_bytes(), // [u8; 2]
            (record.plug_id as u16).to_le_bytes(),      // [u8; 2]
            [0, 0],                                     // [u8; 2]
        ]
        .concat();
        // Value. Convert from 123.456 W to 123456 mW, as integer.
        let value = (record.value * 1000.0) as u64;
        eprintln!("Value: {}", value);
        // Message.
        let message = Message {
            id: msg_id,
            device_id: device_id.clone(),
            timestamp,
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
            id: msg_id,
            device_id,
            timestamp,
            value,
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

        // Add to current slice or historical slice.
        if in_current {
            current_slice.messages.push(signed);
        } else if in_historical {
            // Check if we need to create a new historical slice.
            let message_date = timestamp.date_naive();
            if last_historical_slice_date != Some(message_date) {
                // Create new slice.
                let start = NaiveDateTime::new(message_date, HISTORICAL_SLICE_START)
                    .and_local_timezone(Utc)
                    .unwrap();
                let end = NaiveDateTime::new(message_date, HISTORICAL_SLICE_END)
                    .and_local_timezone(Utc)
                    .unwrap();
                let slice = Slice {
                    start,
                    end,
                    messages: Vec::new(),
                };
                historical_slices.push(slice);
                last_historical_slice_date = Some(message_date);
            }
            // Add to last historical slice.
            let last_slice = historical_slices.last_mut().unwrap();
            last_slice.messages.push(signed);
        }
    }

    // Print some info.
    eprintln!(
        "Number of messages in current slice: {}",
        current_slice.messages.len()
    );
    eprintln!("Number of historical slices: {}", historical_slices.len());
    eprintln!(
        "Dates of historical slices: {:?}",
        historical_slices
            .iter()
            .map(|slice| slice.start.date_naive())
            .collect::<Vec<_>>()
    );
    let n_historical: Vec<usize> = historical_slices
        .iter()
        .map(|slice| slice.messages.len())
        .collect();
    eprintln!(
        "Number of messages per historical slice: {:?}",
        n_historical
    );
    eprintln!(
        "Total number of messages in historical slices: {}",
        n_historical.iter().sum::<usize>()
    );

    // Output as JSON.
    let data = Data {
        public_key_eddsa: PublicKeyEdDSA(public_key_eddsa),
        public_key_ecdsa: PublicKeyECDSA(*public_key_ecdsa),
        public_key_bls: PublicKeyBLS(public_key_bls),
        current: current_slice,
        historical: historical_slices,
    };
    let data_json = data_to_json(&data);
    let json_file = File::create(json_path).expect("could not create JSON file");
    serde_json::to_writer_pretty(json_file, &data_json).expect("could not write JSON file");
}
