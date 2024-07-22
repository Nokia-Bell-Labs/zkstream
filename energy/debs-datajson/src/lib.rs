use babyjubjub_rs;
use blst::min_pk as bls;
use chrono::{DateTime, Utc};
use ff::to_hex;
use hash_sign::utils::{
    bigint_to_json_number, field_to_json_number, json_number_to_bigint, json_number_to_field,
};
use hex;
use k256::ecdsa;
use poseidon_rs;
use serde::{Deserialize, Serialize};
use serde_json::Number;

// Re-expose
pub type Fr = poseidon_rs::Fr;

/// Data in data.json file.
#[derive(Debug)]
pub struct Data {
    /// Public key when using EdDSA & BabyJubJub.
    pub public_key_eddsa: PublicKeyEdDSA,
    /// Public key when using ECDSA.
    pub public_key_ecdsa: PublicKeyECDSA,
    /// Public key when using BLS.
    pub public_key_bls: PublicKeyBLS,
    /// The current slice.
    pub current: Slice,
    /// Historical slices.
    pub historical: Vec<Slice>,
}

/// Format of data.json file.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataJson {
    /// Public key when using EdDSA & BabyJubJub.
    pub public_key_eddsa: PublicKeyEdDSAJson,
    /// Public key when using ECDSA.
    pub public_key_ecdsa: PublicKeyECDSAJson,
    /// Public key when using BLS.
    pub public_key_bls: PublicKeyBLSJson,
    /// The current slice.
    pub current: SliceJson,
    /// Historical slices.
    pub historical: Vec<SliceJson>,
}

pub fn data_to_json(d: &Data) -> DataJson {
    DataJson {
        public_key_eddsa: public_key_eddsa_to_json(&d.public_key_eddsa),
        public_key_ecdsa: public_key_ecdsa_to_json(&d.public_key_ecdsa),
        public_key_bls: public_key_bls_to_json(&d.public_key_bls),
        current: slice_to_json(&d.current),
        historical: d.historical.iter().map(|s| slice_to_json(s)).collect(),
    }
}

pub fn data_from_json(d: &DataJson) -> Data {
    Data {
        public_key_eddsa: public_key_eddsa_from_json(&d.public_key_eddsa),
        public_key_ecdsa: public_key_ecdsa_from_json(&d.public_key_ecdsa),
        public_key_bls: public_key_bls_from_json(&d.public_key_bls),
        current: slice_from_json(&d.current),
        historical: d.historical.iter().map(|s| slice_from_json(s)).collect(),
    }
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

/// A slice of messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    /// Start timestamp.
    pub start: DateTime<Utc>,
    /// End timestamp.
    pub end: DateTime<Utc>,
    /// Messages.
    pub messages: Vec<SignedMessage>,
}

/// A slice of messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceJson {
    /// Start timestamp.
    pub start: i64,
    pub start_iso: String,
    /// End timestamp.
    pub end: i64,
    pub end_iso: String,
    /// Messages.
    pub messages: Vec<SignedMessageJson>,
}

pub fn slice_to_json(s: &Slice) -> SliceJson {
    SliceJson {
        start: s.start.timestamp(),
        start_iso: s.start.to_rfc3339(),
        end: s.end.timestamp(),
        end_iso: s.end.to_rfc3339(),
        messages: s
            .messages
            .iter()
            .map(|m| signed_message_to_json(m))
            .collect(),
    }
}

pub fn slice_from_json(s: &SliceJson) -> Slice {
    Slice {
        start: s.start_iso.parse::<DateTime<Utc>>().unwrap(),
        end: s.end_iso.parse::<DateTime<Utc>>().unwrap(),
        messages: s
            .messages
            .iter()
            .map(|m| signed_message_from_json(m))
            .collect(),
    }
}

/// A signed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    /// Message ID.
    pub id: u64,
    /// Device ID.
    pub device_id: Vec<u8>,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Value.
    pub value: u64,
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
    /// Message ID.
    pub id: u64,
    /// Device ID.
    pub device_id: Vec<u8>,
    pub device_id_hex: String,
    /// Timestamp.
    pub timestamp: i64,
    pub timestamp_iso: String,
    /// Value.
    pub value: u64,
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
        id: m.id,
        device_id: m.device_id.clone(),
        device_id_hex: hex::encode(&m.device_id),
        timestamp: m.timestamp.timestamp(),
        timestamp_iso: m.timestamp.to_rfc3339(),
        value: m.value,
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
        id: m.id,
        device_id: m.device_id.clone(),
        timestamp: m.timestamp_iso.parse::<DateTime<Utc>>().unwrap(),
        value: m.value,
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

/// An ECDSA-style signature.
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

/// A message.
pub type Message = hash_sign::message::Message;

/// A message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageJson {
    /// Message ID.
    pub id: u64,
    /// Device ID.
    pub device_id: String,
    /// Timestamp (UNIX timestamp).
    pub timestamp: i64,
    pub timestamp_iso: String,
    /// Value.
    pub value: u64,
}

pub fn message_to_json(m: &Message) -> MessageJson {
    MessageJson {
        id: m.id,
        device_id: hex::encode(&m.device_id),
        timestamp: m.timestamp.timestamp(),
        timestamp_iso: m.timestamp.to_rfc3339(),
        value: m.value,
    }
}

pub fn message_from_json(m: &MessageJson) -> Message {
    Message {
        id: m.id,
        device_id: hex::decode(&m.device_id).unwrap(),
        timestamp: m.timestamp_iso.parse::<DateTime<Utc>>().unwrap(),
        value: m.value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ff::PrimeField;
    use serde_json::Number;
    use std::{fs::File, str::FromStr};

    #[test]
    fn test_deserialize_serialize() {
        // Read in test file.
        let test_file = File::open("test/data.short.json")
            .expect("test/data.short.json should contain test data");
        let data_json: DataJson = serde_json::from_reader(test_file).unwrap();

        // Check some things in the JSON.
        assert_eq!(
            data_json.public_key_eddsa.x_hex,
            "1eb37a21d81104513e8d2efd635ea79ee98b9aeaceeed2fa4e85ba3cec8074e9"
        );
        assert_eq!(
            data_json.public_key_eddsa.x_field,
            Number::from_str(
                "13886494007580326243456458651740327726561189795419074881554172413570220848361"
            )
            .unwrap()
        );
        assert_eq!(
            data_json.public_key_ecdsa.x_hex,
            "631c8302ac76be960385eac8568bd2c26f96c9641fb8a48ed41b7ee3e5e72319"
        );
        assert_eq!(
            &data_json.public_key_ecdsa.x_bytes,
            &[
                99, 28, 131, 2, 172, 118, 190, 150, 3, 133, 234, 200, 86, 139, 210, 194, 111, 150,
                201, 100, 31, 184, 164, 142, 212, 27, 126, 227, 229, 231, 35, 25
            ],
        );
        assert_eq!(
            data_json.public_key_bls.0,
            &[
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
        );
        assert_eq!(data_json.current.start, 1380492000);
        assert_eq!(data_json.current.start_iso, "2013-09-29T22:00:00+00:00");
        assert_eq!(data_json.current.messages.len(), 2);
        assert_eq!(data_json.current.messages[0].id, 3966876510);
        assert_eq!(data_json.current.messages[0].timestamp, 1380492001);
        assert_eq!(data_json.current.messages[0].value, 1435);
        assert_eq!(data_json.historical.len(), 2);

        // Deserialize from JSON.
        let data = data_from_json(&data_json);

        // Check some things.
        assert_eq!(
            data.public_key_eddsa.0.x,
            Fr::from_str(
                "13886494007580326243456458651740327726561189795419074881554172413570220848361"
            )
            .unwrap()
        );
        assert_eq!(
            data.public_key_ecdsa
                .0
                .to_encoded_point(false)
                .x()
                .unwrap()
                .as_slice(),
            &[
                99, 28, 131, 2, 172, 118, 190, 150, 3, 133, 234, 200, 86, 139, 210, 194, 111, 150,
                201, 100, 31, 184, 164, 142, 212, 27, 126, 227, 229, 231, 35, 25
            ],
        );
        assert_eq!(
            data.current.start,
            Utc.with_ymd_and_hms(2013, 9, 29, 22, 0, 0).unwrap()
        );
        assert_eq!(data.current.messages.len(), 2);
        assert_eq!(data.current.messages[0].id, 3966876510);
        assert_eq!(
            data.current.messages[0].timestamp,
            Utc.with_ymd_and_hms(2013, 9, 29, 22, 0, 1).unwrap()
        );
        assert_eq!(data.current.messages[0].value, 1435);
        assert_eq!(data.historical.len(), 2);

        // Re-serialize to JSON, and check if it's the same as the original.
        let data_json2 = data_to_json(&data);
        assert_eq!(data_json, data_json2);
    }
}
