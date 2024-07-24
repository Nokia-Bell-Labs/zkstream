// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use babyjubjub_rs;
use blst::min_pk as bls;
use ff::to_hex;
use hash_sign::{
    hash::{SaltPoseidon, SaltSHA256},
    utils::{
        bigint_to_json_number, field_to_json_number, int_to_field, json_number_to_bigint,
        json_number_to_field, uint_to_field,
    },
    SerializableMessage,
};
use hex;
use k256::ecdsa;
use poseidon_rs;
use serde::{Deserialize, Serialize};
use serde_json::Number;

// Re-expose
pub type Fr = poseidon_rs::Fr;

/// Format of input JSON file (no signatures).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Data {
    /// Persons
    pub persons: Vec<Person>,
    /// Auctions
    pub auctions: Vec<Auction>,
    /// Bids
    pub bids: Vec<Bid>,
}

/// Format of output JSON file (with signatures added).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataJson {
    /// Public key when using EdDSA & BabyJubJub.
    pub public_key_eddsa: PublicKeyEdDSAJson,
    /// Public key when using ECDSA.
    pub public_key_ecdsa: PublicKeyECDSAJson,
    /// Public key when using BLS.
    pub public_key_bls: PublicKeyBLSJson,
    /// Persons
    pub persons: Vec<Person>,
    /// Auctions
    pub auctions: Vec<Auction>,
    /// Bids
    pub bids: Vec<SignedMessageJson>,
}

#[derive(Debug, Clone)]
pub struct PublicKeyEdDSA(pub babyjubjub_rs::Point);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyEdDSAJson {
    x_hex: String,
    x_field: Number,
    y_hex: String,
    y_field: Number,
}

pub fn public_key_eddsa_to_json(pk: &PublicKeyEdDSA) -> PublicKeyEdDSAJson {
    PublicKeyEdDSAJson {
        x_hex: to_hex(&pk.0.x),
        x_field: field_to_json_number(&pk.0.x),
        y_hex: to_hex(&pk.0.y),
        y_field: field_to_json_number(&pk.0.y),
    }
}

pub fn public_key_eddsa_from_json(pk: &PublicKeyEdDSAJson) -> PublicKeyEdDSA {
    PublicKeyEdDSA(babyjubjub_rs::Point {
        x: json_number_to_field(&pk.x_field),
        y: json_number_to_field(&pk.y_field),
    })
}

#[derive(Debug, Clone)]
pub struct PublicKeyECDSA(pub ecdsa::VerifyingKey);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyECDSAJson {
    x_bytes: Vec<u8>,
    x_hex: String,
    y_bytes: Vec<u8>,
    y_hex: String,
}

pub fn public_key_ecdsa_to_json(pk: &PublicKeyECDSA) -> PublicKeyECDSAJson {
    let pt = pk.0.to_encoded_point(false);
    let x = pt.x().unwrap();
    let y = pt.y().unwrap();
    PublicKeyECDSAJson {
        x_bytes: x.to_vec(),
        x_hex: hex::encode(x),
        y_bytes: y.to_vec(),
        y_hex: hex::encode(y),
    }
}

pub fn public_key_ecdsa_from_json(pk: &PublicKeyECDSAJson) -> PublicKeyECDSA {
    let pt = k256::EncodedPoint::from_affine_coordinates(
        pk.x_bytes.as_slice().into(),
        pk.y_bytes.as_slice().into(),
        false,
    );
    let key = ecdsa::VerifyingKey::from_encoded_point(&pt).expect("could not decode point");
    PublicKeyECDSA(key)
}

#[derive(Debug, Clone)]
pub struct PublicKeyBLS(pub bls::PublicKey);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyBLSJson(Vec<u8>);

pub fn public_key_bls_to_json(pk: &PublicKeyBLS) -> PublicKeyBLSJson {
    PublicKeyBLSJson(pk.0.to_bytes().to_vec())
}

pub fn public_key_bls_from_json(pk: &PublicKeyBLSJson) -> PublicKeyBLS {
    PublicKeyBLS(bls::PublicKey::from_bytes(&pk.0).expect("could not deserialize BLS public key"))
}

/// A person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Person {
    /// Person ID.
    pub id: u64,
    /// Name.
    pub name: String,
    /// E-mail address.
    pub emailAddress: String,
    /// Credit card number.
    pub creditCard: String,
    /// City.
    pub city: String,
    /// State.
    pub state: String,
    // /// Time at which the person was created.
    // pub dateTime: i64,
    /// Extra information.
    pub extra: String,
}

/// An auction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Auction {
    /// Auction ID.
    pub id: u64,
    /// Item name.
    pub itemName: String,
    /// Description.
    pub description: String,
    /// Initial bid.
    pub initialBid: u64,
    /// Reserve price.
    pub reserve: u64,
    /// Start time.
    pub dateTime: i64,
    /// Expire time.
    pub expires: i64,
    /// Seller ID.
    pub seller: u64,
    /// Category.
    pub category: u64,
    /// Extra information.
    pub extra: String,
}

/// A bid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bid {
    /// Auction ID.
    pub auction: u64,
    /// Bidder ID.
    pub bidder: u64,
    /// Price.
    pub price: u64,
    /// Time.
    pub dateTime: i64,
    /// Extra information.
    pub extra: String,
}

/// A signed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    /// Message.
    pub message: Message,
    /// Salt. (512 bit, 64 byte)
    pub salt: Vec<u8>,
    /// Salt as fields. XXX
    pub salt_fields: [Fr; 4],
    /// Unsalted SHA256 hash.
    pub hash_sha256_unsalted: Vec<u8>,
    /// Salted SHA256 hash.
    pub hash_sha256_salted: Vec<u8>,
    /// Unsalted Poseidon hash.
    pub hash_poseidon_unsalted: Fr,
    /// Salted Poseidon hash.
    pub hash_poseidon_salted: Fr,
    /// EdDSA (using BabyJubJub) signature of unsalted SHA256 hash.
    /// (Compatible with Zokrates' stdlib verifyEddsa.)
    pub signature_eddsa_sha256_unsalted: EdDSASignature,
    /// EdDSA (using BabyJubJub) signature of salted SHA256 hash.
    /// (Compatible with Zokrates' stdlib verifyEddsa.)
    pub signature_eddsa_sha256_salted: EdDSASignature,
    /// EdDSA (using BabyJubJub) signature of unsalted Poseidon hash.
    /// (Compatible with Circom, our custom Zokrates verifyEddsa, and Rust's babyjubjub_rs.)
    pub signature_eddsa_poseidon_unsalted: EdDSASignature,
    /// EdDSA (using BabyJubJub) signature of salted Poseidon hash.
    /// (Compatible with Circom, our custom Zokrates verifyEddsa, and Rust's babyjubjub_rs.)
    pub signature_eddsa_poseidon_salted: EdDSASignature,
    /// ECDSA signature of unsalted SHA256 hash.
    /// (Compatible with RISC-0's accelerator and Rust's k256::ecdsa library.)
    pub signature_ecdsa_sha256_unsalted: ECDSASignature,
    /// ECDSA signature of salted SHA256 hash.
    /// (Compatible with RISC-0's accelerator and Rust's k256::ecdsa library.)
    pub signature_ecdsa_sha256_salted: ECDSASignature,
    /// BLS signature of salted SHA256 hash.
    /// (Compatible with BLS library.)
    pub signature_bls_sha256_salted: BLSSignature,
    /// BLS signature of salted Poseidon hash.
    /// (Compatible with BLS library.)
    pub signature_bls_poseidon_salted: BLSSignature,
}

/// A signed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessageJson {
    /// Message
    pub message: Message,
    /// Salt. (512 bit, 64 byte)
    pub salt_bytes: Vec<u8>,
    pub salt_hex: String,
    pub salt_fields: [Number; 4],
    /// Unsalted SHA256 hash.
    pub hash_sha256_unsalted_bytes: Vec<u8>,
    pub hash_sha256_unsalted_hex: String,
    /// Salted SHA256 hash.
    pub hash_sha256_salted_bytes: Vec<u8>,
    pub hash_sha256_salted_hex: String,
    /// Unsalted Poseidon hash.
    pub hash_poseidon_unsalted_field: Number,
    /// Salted Poseidon hash.
    pub hash_poseidon_salted_field: Number,
    /// EdDSA (using BabyJubJub) signature of unsalted SHA256 hash.
    /// (Compatible with Zokrates' stdlib verifyEddsa.)
    pub signature_eddsa_sha256_unsalted: EdDSASignatureJson,
    /// EdDSA (using BabyJubJub) signature of salted SHA256 hash.
    /// (Compatible with Zokrates' stdlib verifyEddsa.)
    pub signature_eddsa_sha256_salted: EdDSASignatureJson,
    /// EdDSA (using BabyJubJub) signature of unsalted Poseidon hash.
    /// (Compatible with Circom, our custom Zokrates verifyEddsa, and Rust's babyjubjub_rs.)
    pub signature_eddsa_poseidon_unsalted: EdDSASignatureJson,
    /// EdDSA (using BabyJubJub) signature of salted Poseidon hash.
    /// (Compatible with Circom, our custom Zokrates verifyEddsa, and Rust's babyjubjub_rs.)
    pub signature_eddsa_poseidon_salted: EdDSASignatureJson,
    /// ECDSA signature of unsalted SHA256 hash.
    /// (Compatible with RISC-0's accelerator and Rust's k256::ecdsa library.)
    pub signature_ecdsa_sha256_unsalted: ECDSASignatureJson,
    /// ECDSA signature of salted SHA256 hash.
    /// (Compatible with RISC-0's accelerator and Rust's k256::ecdsa library.)
    pub signature_ecdsa_sha256_salted: ECDSASignatureJson,
    /// BLS signature of salted SHA256 hash.
    /// (Compatible with BLS library.)
    pub signature_bls_sha256_salted: BLSSignatureJson,
    /// BLS signature of salted Poseidon hash.
    /// (Compatible with BLS library.)
    pub signature_bls_poseidon_salted: BLSSignatureJson,
}

pub fn signed_message_to_json(m: &SignedMessage) -> SignedMessageJson {
    SignedMessageJson {
        message: m.message.clone(),
        salt_bytes: m.salt.clone(),
        salt_hex: hex::encode(&m.salt),
        salt_fields: m
            .salt_fields
            .iter()
            .map(|s| field_to_json_number(s))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        hash_sha256_unsalted_bytes: m.hash_sha256_unsalted.clone(),
        hash_sha256_unsalted_hex: hex::encode(&m.hash_sha256_unsalted),
        hash_sha256_salted_bytes: m.hash_sha256_salted.clone(),
        hash_sha256_salted_hex: hex::encode(&m.hash_sha256_salted),
        hash_poseidon_unsalted_field: field_to_json_number(&m.hash_poseidon_unsalted),
        hash_poseidon_salted_field: field_to_json_number(&m.hash_poseidon_salted),
        signature_eddsa_sha256_unsalted: eddsa_signature_to_json(
            &m.signature_eddsa_sha256_unsalted,
        ),
        signature_eddsa_sha256_salted: eddsa_signature_to_json(&m.signature_eddsa_sha256_salted),
        signature_eddsa_poseidon_unsalted: eddsa_signature_to_json(
            &m.signature_eddsa_poseidon_unsalted,
        ),
        signature_eddsa_poseidon_salted: eddsa_signature_to_json(
            &m.signature_eddsa_poseidon_salted,
        ),
        signature_ecdsa_sha256_unsalted: ecdsa_signature_to_json(
            &m.signature_ecdsa_sha256_unsalted,
        ),
        signature_ecdsa_sha256_salted: ecdsa_signature_to_json(&m.signature_ecdsa_sha256_salted),
        signature_bls_sha256_salted: bls_signature_to_json(&m.signature_bls_sha256_salted),
        signature_bls_poseidon_salted: bls_signature_to_json(&m.signature_bls_poseidon_salted),
    }
}

pub fn signed_message_from_json(m: &SignedMessageJson) -> SignedMessage {
    SignedMessage {
        message: m.message.clone(),
        salt: m.salt_bytes.clone(),
        salt_fields: m
            .salt_fields
            .iter()
            .map(|s| json_number_to_field(s))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        hash_sha256_unsalted: m.hash_sha256_unsalted_bytes.clone(),
        hash_sha256_salted: m.hash_sha256_salted_bytes.clone(),
        hash_poseidon_unsalted: json_number_to_field(&m.hash_poseidon_unsalted_field),
        hash_poseidon_salted: json_number_to_field(&m.hash_poseidon_salted_field),
        signature_eddsa_sha256_unsalted: eddsa_signature_from_json(
            &m.signature_eddsa_sha256_unsalted,
        ),
        signature_eddsa_sha256_salted: eddsa_signature_from_json(&m.signature_eddsa_sha256_salted),
        signature_eddsa_poseidon_unsalted: eddsa_signature_from_json(
            &m.signature_eddsa_poseidon_unsalted,
        ),
        signature_eddsa_poseidon_salted: eddsa_signature_from_json(
            &m.signature_eddsa_poseidon_salted,
        ),
        signature_ecdsa_sha256_unsalted: ecdsa_signature_from_json(
            &m.signature_ecdsa_sha256_unsalted,
        ),
        signature_ecdsa_sha256_salted: ecdsa_signature_from_json(&m.signature_ecdsa_sha256_salted),
        signature_bls_sha256_salted: bls_signature_from_json(&m.signature_bls_sha256_salted),
        signature_bls_poseidon_salted: bls_signature_from_json(&m.signature_bls_poseidon_salted),
    }
}

/// An EdDSA-style signature.
pub type EdDSASignature = hash_sign::sign::EdDSASignature;

/// An EdDSA-style signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdDSASignatureJson {
    pub rx_hex: String,
    pub rx_field: Number,
    pub ry_hex: String,
    pub ry_field: Number,
    pub s_hex: String,
    pub s_field: Number,
}

pub fn eddsa_signature_to_json(s: &EdDSASignature) -> EdDSASignatureJson {
    EdDSASignatureJson {
        rx_hex: to_hex(&s.rx),
        rx_field: field_to_json_number(&s.rx),
        ry_hex: to_hex(&s.ry),
        ry_field: field_to_json_number(&s.ry),
        s_hex: s.s.to_str_radix(16),
        s_field: bigint_to_json_number(&s.s),
    }
}

pub fn eddsa_signature_from_json(s: &EdDSASignatureJson) -> EdDSASignature {
    EdDSASignature {
        rx: json_number_to_field(&s.rx_field),
        ry: json_number_to_field(&s.ry_field),
        s: json_number_to_bigint(&s.s_field),
    }
}

/// An ECDSA-style signature.
pub type ECDSASignature = hash_sign::sign::ECDSASignature;

/// A ECDSA-style signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ECDSASignatureJson {
    // 32 bytes
    pub r: Vec<u8>,
    pub r_hex: String,
    // 32 bytes
    pub s: Vec<u8>,
    pub s_hex: String,
}

pub fn ecdsa_signature_to_json(s: &ECDSASignature) -> ECDSASignatureJson {
    ECDSASignatureJson {
        r: s.r.clone(),
        r_hex: hex::encode(&s.r),
        s: s.s.clone(),
        s_hex: hex::encode(&s.s),
    }
}

pub fn ecdsa_signature_from_json(s: &ECDSASignatureJson) -> ECDSASignature {
    ECDSASignature {
        r: s.r.clone(),
        s: s.s.clone(),
    }
}

/// A BLS signature.
pub type BLSSignature = bls::Signature;

/// A BLS signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BLSSignatureJson(pub Vec<u8>);

pub fn bls_signature_to_json(s: &BLSSignature) -> BLSSignatureJson {
    BLSSignatureJson(s.to_bytes().to_vec())
}

pub fn bls_signature_from_json(s: &BLSSignatureJson) -> BLSSignature {
    bls::Signature::from_bytes(&s.0).expect("could not deserialize BLS signature")
}

/// A message contains a bid for an auction with a price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageValue {
    /// Auction ID.
    pub auction: u64,
    /// Price.
    pub price: u64,
}

/// A message contains a timestamped bid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Message ID.
    pub id: u64,
    /// Device ID. = Bidder ID.
    pub device_id: u64,
    /// Timestamp (UNIX timestamp).
    pub timestamp: i64,
    /// Value.
    pub value: MessageValue,
}

impl SerializableMessage for Message {
    /// Serialize a message to bytes, e.g. to sign using SHA256, unsalted.
    ///
    /// This converts the message to 24 bytes: timestamp ++ value,
    /// where timestamp = 8 bytes (BE), value = 8 bytes (BE) + 8 bytes (BE).
    fn to_bytes(&self) -> Vec<u8> {
        let timestamp: [u8; 8] = self.timestamp.to_be_bytes();
        let value1: [u8; 8] = self.value.auction.to_be_bytes();
        let value2: [u8; 8] = self.value.price.to_be_bytes();
        let mut data = [0u8; 24];
        data[0..8].copy_from_slice(&timestamp);
        data[8..16].copy_from_slice(&value1);
        data[16..24].copy_from_slice(&value2);
        // eprintln!("data: {:?}", data);
        data.to_vec()
    }

    /// Serialize a message to bytes, e.g. to sign using SHA256, with salt.
    ///
    /// This converts the message to 88 bytes: timestamp ++ value ++ salt,
    /// where timestamp = 8 bytes (BE), value = 8 bytes (BE) + 8 bytes (BE), salt = 64 bytes.
    fn to_bytes_salted(&self, salt: &SaltSHA256) -> Vec<u8> {
        let timestamp: [u8; 8] = self.timestamp.to_be_bytes();
        let value1: [u8; 8] = self.value.auction.to_be_bytes();
        let value2: [u8; 8] = self.value.price.to_be_bytes();
        let mut data = [0u8; 88];
        data[0..8].copy_from_slice(&timestamp);
        data[8..16].copy_from_slice(&value1);
        data[16..24].copy_from_slice(&value2);
        data[24..88].copy_from_slice(salt);
        // eprintln!("data: {:?}", data);
        data.to_vec()
    }

    /// Serialize a message to fields, e.g. to sign using Poseidon, unsalted.
    ///
    /// Result = [timestamp, value]
    /// where timestamp = field, value = field.
    fn to_fields(&self) -> Vec<Fr> {
        let timestamp: Fr = int_to_field(self.timestamp);
        assert!(
            self.value.auction < (1 << 32),
            "auction id must be less than 2^32"
        );
        assert!(self.value.price < (1 << 32), "price must be less than 2^32");
        let value: Fr = uint_to_field((self.value.auction << 32) + self.value.price);
        [timestamp, value].to_vec()
    }

    /// Serialize a message to fields, e.g. to sign using Poseidon, with salt.
    ///
    /// Result = poseidon(timestamp, value, salt[0], salt[1], salt[2], salt[3])
    /// where timestamp = field, value = field, salt = 4 fields.
    fn to_fields_salted(&self, salt: &SaltPoseidon) -> Vec<Fr> {
        let timestamp: Fr = int_to_field(self.timestamp);
        assert!(
            self.value.auction < (1 << 32),
            "auction id must be less than 2^32"
        );
        assert!(self.value.price < (1 << 32), "price must be less than 2^32");
        let value: Fr = uint_to_field((self.value.auction << 32) + self.value.price);
        [timestamp, value, salt[0], salt[1], salt[2], salt[3]].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use serde_json::Number;
    use std::{fs::File, str::FromStr};

    #[test]
    fn test_deserialize_serialize() {
        // Read in test file.
        let test_file = File::open("test/data.short.json")
            .expect("test/data.short.json should contain test data");
        let data: DataJson = serde_json::from_reader(test_file).unwrap();

        // Check some things in the JSON.
        assert_eq!(
            data.public_key_eddsa.x_hex,
            "1eb37a21d81104513e8d2efd635ea79ee98b9aeaceeed2fa4e85ba3cec8074e9"
        );
        assert_eq!(
            data.public_key_eddsa.x_field,
            Number::from_str(
                "13886494007580326243456458651740327726561189795419074881554172413570220848361"
            )
            .unwrap()
        );
        assert_eq!(
            data.public_key_ecdsa.x_hex,
            "631c8302ac76be960385eac8568bd2c26f96c9641fb8a48ed41b7ee3e5e72319"
        );
        assert_eq!(
            &data.public_key_ecdsa.x_bytes,
            &[
                99, 28, 131, 2, 172, 118, 190, 150, 3, 133, 234, 200, 86, 139, 210, 194, 111, 150,
                201, 100, 31, 184, 164, 142, 212, 27, 126, 227, 229, 231, 35, 25
            ],
        );
        assert_eq!(
            data.public_key_bls.0,
            &[
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
        );

        // Check some things.
        let pk_eddsa = public_key_eddsa_from_json(&data.public_key_eddsa);
        assert_eq!(
            pk_eddsa.0.x,
            Fr::from_str(
                "13886494007580326243456458651740327726561189795419074881554172413570220848361"
            )
            .unwrap()
        );
        let pk_ecdsa = public_key_ecdsa_from_json(&data.public_key_ecdsa);
        assert_eq!(
            pk_ecdsa.0.to_encoded_point(false).x().unwrap().as_slice(),
            &[
                99, 28, 131, 2, 172, 118, 190, 150, 3, 133, 234, 200, 86, 139, 210, 194, 111, 150,
                201, 100, 31, 184, 164, 142, 212, 27, 126, 227, 229, 231, 35, 25
            ],
        );
        assert_eq!(data.persons.len(), 2);
        assert_eq!(data.persons[0].id, 1);
        assert_eq!(data.persons[0].name, "Person 1");
        assert_eq!(data.persons[1].id, 2);
        assert_eq!(data.persons[1].name, "Person 2");
        assert_eq!(data.auctions.len(), 2);
        assert_eq!(data.auctions[0].id, 1);
        assert_eq!(data.auctions[0].initialBid, 41322);
        assert_eq!(data.auctions[1].id, 2);
        assert_eq!(data.auctions[1].initialBid, 34345);
        assert_eq!(data.bids.len(), 3);
        assert_eq!(data.bids[0].message.value.auction, 25);
        assert_eq!(data.bids[0].message.device_id, 3);
        assert_eq!(data.bids[0].message.value.price, 29425);
        assert_eq!(data.bids[0].message.timestamp, 1565337994551);
        assert_eq!(data.bids[1].message.value.auction, 23);
        assert_eq!(data.bids[1].message.device_id, 3);
        assert_eq!(data.bids[1].message.value.price, 2841);
        assert_eq!(data.bids[1].message.timestamp, 1565337994552);
    }
}
