use datajson::utils::{int_to_field, uint_to_field};
use datajson::Message;
use ff::PrimeField;
use poseidon_rs::{Fr, Poseidon};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

lazy_static! {
    // Seed RNG with a fixed value for reproducibility.
    static ref RNG: Mutex<StdRng> = Mutex::new(StdRng::seed_from_u64(1));
}

pub type SaltSHA256 = [u8; 64];
pub type SaltPoseidon = [Fr; 4];

/// Generate random salt of 512 bit = 64 bytes.
pub fn generate_salt() -> SaltSHA256 {
    let mut salt = [0u8; 64];
    RNG.lock().unwrap().fill(&mut salt);
    salt
}

/// Convert salt of 64 bytes to 4 fields.
pub fn salt_to_fields(salt_bytes: &SaltSHA256) -> SaltPoseidon {
    // Convert salt of 64 x u8 to 4 x u128.
    let salt_u128: [u128; 4] = [
        u128::from_le_bytes((&salt_bytes[0..16]).try_into().unwrap()),
        u128::from_le_bytes((&salt_bytes[16..32]).try_into().unwrap()),
        u128::from_le_bytes((&salt_bytes[32..48]).try_into().unwrap()),
        u128::from_le_bytes((&salt_bytes[48..64]).try_into().unwrap()),
    ];
    // Convert from 4 x u128 to 4 x Fr.
    let salt_fr: [Fr; 4] = [
        Fr::from_str(&salt_u128[0].to_string()).unwrap(),
        Fr::from_str(&salt_u128[1].to_string()).unwrap(),
        Fr::from_str(&salt_u128[2].to_string()).unwrap(),
        Fr::from_str(&salt_u128[3].to_string()).unwrap(),
    ];
    // eprintln!("salt: {:?}", salt_fr);
    salt_fr
}

/// Serialize data to sign using SHA256, unsalted.
///
/// This converts the message to 24 bytes: timestamp ++ value,
/// where timestamp = 8 bytes (BE), value = 8 bytes (BE) + 8 bytes (BE).
pub fn serialize_sha256_unsalted(message: &Message) -> [u8; 24] {
    let timestamp: [u8; 8] = message.timestamp.to_be_bytes();
    let value1: [u8; 8] = message.value.auction.to_be_bytes();
    let value2: [u8; 8] = message.value.price.to_be_bytes();
    let mut data = [0u8; 24];
    data[0..8].copy_from_slice(&timestamp);
    data[8..16].copy_from_slice(&value1);
    data[16..24].copy_from_slice(&value2);
    // eprintln!("data: {:?}", data);
    data
}

/// Serialize data to sign using SHA256, with salt.
///
/// This converts the message to 88 bytes: timestamp ++ value ++ salt,
/// where timestamp = 8 bytes (BE), value = 8 bytes (BE) + 8 bytes (BE), salt = 64 bytes.
pub fn serialize_sha256_salted(message: &Message, salt: &SaltSHA256) -> [u8; 88] {
    let timestamp: [u8; 8] = message.timestamp.to_be_bytes();
    let value1: [u8; 8] = message.value.auction.to_be_bytes();
    let value2: [u8; 8] = message.value.price.to_be_bytes();
    let mut data = [0u8; 88];
    data[0..8].copy_from_slice(&timestamp);
    data[8..16].copy_from_slice(&value1);
    data[16..24].copy_from_slice(&value2);
    data[24..88].copy_from_slice(salt);
    // eprintln!("data: {:?}", data);
    data
}

/// Hash a message using SHA256, with salt.
///
/// Result = sha256(timestamp ++ value ++ salt)
/// where timestamp = 8 bytes (BE), value = 8 bytes (BE), salt = 64 bytes.
pub fn sha256_salted(message: &Message, salt: &SaltSHA256) -> Vec<u8> {
    let hash = Sha256::digest(&serialize_sha256_salted(message, salt));
    // eprintln!("hash: {:?}", hash);
    hash.to_vec()
}

/// Hash a message using SHA256, unsalted.
///
/// Result = sha256(timestamp ++ value)
/// where timestamp = 8 bytes (BE), value = 8 bytes (BE).
pub fn sha256_unsalted(message: &Message) -> Vec<u8> {
    let hash = Sha256::digest(&serialize_sha256_unsalted(message));
    // eprintln!("hash: {:?}", hash);
    hash.to_vec()
}

/// Hash a message using Poseidon, with salt.
///
/// Result = poseidon(timestamp, value, salt[0], salt[1], salt[2], salt[3])
/// where timestamp = field, value = field, salt = 4 fields.
pub fn poseidon_salted(message: &Message, salt: &SaltPoseidon) -> Fr {
    let timestamp: Fr = int_to_field(message.timestamp);
    assert!(
        message.value.auction < (1 << 32),
        "auction id must be less than 2^32"
    );
    assert!(
        message.value.price < (1 << 32),
        "price must be less than 2^32"
    );
    let value: Fr = uint_to_field((message.value.auction << 32) + message.value.price);
    let hash = Poseidon::new()
        .hash(vec![timestamp, value, salt[0], salt[1], salt[2], salt[3]])
        .unwrap();
    // eprintln!("hash: {}", hash_fr);
    hash
}

/// Hash a message using Poseidon, unsalted.
///
/// Result = poseidon(timestamp, value)
/// where timestamp = field, value = field.
pub fn poseidon_unsalted(message: &Message) -> Fr {
    let timestamp: Fr = int_to_field(message.timestamp);
    assert!(
        message.value.auction < (1 << 32),
        "auction id must be less than 2^32"
    );
    assert!(
        message.value.price < (1 << 32),
        "price must be less than 2^32"
    );
    let value: Fr = uint_to_field((message.value.auction << 32) + message.value.price);
    let hash = Poseidon::new().hash(vec![timestamp, value]).unwrap();
    // eprintln!("hash: {}", hash_fr);
    hash
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use datajson::MessageValue;

    use super::*;

    lazy_static! {
        // Unix timestamp 1577836800 (= 0x5E0BE100 in BE; 0x00E10B5E in LE).
        static ref TIMESTAMP: DateTime<Utc> = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        static ref MESSAGE: Message = Message {
            id: 7,
            device_id: 456,
            value: MessageValue { auction: 123, price: 321 },
            // = 123 * 2^32 + 321 = 528280977729
            timestamp: TIMESTAMP.timestamp(),
        };
        static ref SALT: [u8; 64] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
        ];
    }

    #[test]
    fn test_sha256_salted() {
        // sha256(0x000000005E0BE100 + 0x000000000000007B + 0x0000000000000141 +
        //   0x0102030405060708090a0b0c0d0e0f
        //   101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
        //   303132333435363738393a3b3c3d3e3f40)
        // = 0x6751490c2378ab89b9c3e2780638702debec0d93c5b25632da20dcfa1a0ff1e0
        // = [103, 81, 73, 12, 35, 120, 171, 137, 185, 195, 226, 120, 6, 56, 112, 45, 235, 236,
        //    13, 147, 197, 178, 86, 50, 218, 32, 220, 250, 26, 15, 241, 224]
        assert_eq!(
            vec![
                103, 81, 73, 12, 35, 120, 171, 137, 185, 195, 226, 120, 6, 56, 112, 45, 235, 236,
                13, 147, 197, 178, 86, 50, 218, 32, 220, 250, 26, 15, 241, 224
            ],
            sha256_salted(&MESSAGE, &SALT)
        );
    }

    #[test]
    fn test_sha256_unsalted() {
        // sha256(0x000000005E0BE100 + 0x000000000000007B + 0x0000000000000141)
        // = 0x46ba2d46c1cb6985ef8e855eeef624a048fe44c805321247923c2ded8466d3a6
        // = [70, 186, 45, 70, 193, 203, 105, 133, 239, 142, 133, 94, 238, 246, 36, 160, 72, 254,
        //    68, 200, 5, 50, 18, 71, 146, 60, 45, 237, 132, 102, 211, 166]
        assert_eq!(
            vec![
                70, 186, 45, 70, 193, 203, 105, 133, 239, 142, 133, 94, 238, 246, 36, 160, 72, 254,
                68, 200, 5, 50, 18, 71, 146, 60, 45, 237, 132, 102, 211, 166
            ],
            sha256_unsalted(&MESSAGE)
        );
    }

    #[test]
    fn test_poseidon_salted() {
        let salt_fields = salt_to_fields(&SALT);
        // poseidon([
        //     1577836800,
        //     528280977729,
        //     0x00000000000000000000000000000000100f0e0d0c0b0a090807060504030201,
        //     0x00000000000000000000000000000000201f1e1d1c1b1a191817161514131211,
        //     0x00000000000000000000000000000000302f2e2d2c2b2a292827262524232221,
        //     0x00000000000000000000000000000000403f3e3d3c3b3a393837363534333231
        // ])
        // = poseidon([
        //     1577836800,
        //     528280977729,
        //     21345817372864405881847059188222722561,
        //     42696867846335054569745073772176806417,
        //     64047918319805703257643088356130890273,
        //     85398968793276351945541102940084974129
        // ])
        // = 12757120842739295214529540480751019909478086822962532388908380917277859393061
        // = 0x1c344646f31347bf34c5c979c22cf909e2ee5ff7e9e71f798eef65f200ce2e25
        assert_eq!(
            Fr::from_str(
                "12757120842739295214529540480751019909478086822962532388908380917277859393061"
            )
            .unwrap(),
            poseidon_salted(&MESSAGE, &salt_fields)
        );
    }

    #[test]
    fn test_poseidon_unsalted() {
        // poseidon([
        //     1577836800,
        //     528280977729
        // ])
        // = 8895768287631283409829976895763390893671667802410697332647501803856265529309
        // = 0x13aad39079c8d463a2fcd12dbad3668ddc2c88171ad70fbc115c9f7d05dcc7dd
        assert_eq!(
            Fr::from_str(
                "8895768287631283409829976895763390893671667802410697332647501803856265529309"
            )
            .unwrap(),
            poseidon_unsalted(&MESSAGE)
        );
    }
}
