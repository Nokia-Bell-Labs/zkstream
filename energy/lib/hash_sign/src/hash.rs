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
/// This converts the message to 16 bytes: timestamp ++ value,
/// where timestamp = 8 bytes (BE), value = 8 bytes (BE).
pub fn serialize_sha256_unsalted(message: &Message) -> [u8; 16] {
    let timestamp: [u8; 8] = message.timestamp.timestamp().to_be_bytes();
    let value: [u8; 8] = message.value.to_be_bytes();
    let mut data = [0u8; 16];
    data[0..8].copy_from_slice(&timestamp);
    data[8..16].copy_from_slice(&value);
    // eprintln!("data: {:?}", data);
    data
}

/// Serialize data to sign using SHA256, with salt.
///
/// This converts the message to 80 bytes: timestamp ++ value ++ salt,
/// where timestamp = 8 bytes (BE), value = 8 bytes (BE), salt = 64 bytes.
pub fn serialize_sha256_salted(message: &Message, salt: &SaltSHA256) -> [u8; 80] {
    let timestamp: [u8; 8] = message.timestamp.timestamp().to_be_bytes();
    let value: [u8; 8] = message.value.to_be_bytes();
    let mut data = [0u8; 80];
    data[0..8].copy_from_slice(&timestamp);
    data[8..16].copy_from_slice(&value);
    data[16..80].copy_from_slice(salt);
    // eprintln!("data: {:?}", data);
    data
}

/// Hash a message using SHA256, with salt.
///
/// Result = sha256(timestamp ++ value ++ salt)
/// where timestamp = 8 bytes (LE), value = 8 bytes (LE), salt = 64 bytes.
pub fn sha256_salted(message: &Message, salt: &SaltSHA256) -> Vec<u8> {
    let hash = Sha256::digest(&serialize_sha256_salted(message, salt));
    // eprintln!("hash: {:?}", hash);
    hash.to_vec()
}

/// Hash a message using SHA256, unsalted.
///
/// Result = sha256(timestamp ++ value)
/// where timestamp = 8 bytes (LE), value = 8 bytes (LE).
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
    let timestamp: Fr = int_to_field(message.timestamp.timestamp());
    let value: Fr = uint_to_field(message.value);
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
    let timestamp: Fr = int_to_field(message.timestamp.timestamp());
    let value: Fr = uint_to_field(message.value);
    let hash = Poseidon::new().hash(vec![timestamp, value]).unwrap();
    // eprintln!("hash: {}", hash_fr);
    hash
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};

    use super::*;

    lazy_static! {
        // Unix timestamp 1577836800 (= 0x5E0BE100 in BE; 0x00E10B5E in LE).
        static ref TIMESTAMP: DateTime<Utc> = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        static ref MESSAGE: Message = Message {
            id: 7,
            device_id: vec![0, 1, 2, 3],
            value: 123, // = 0x000000000000007b in BE; 0x7b00000000000000 in LE
            timestamp: *TIMESTAMP,
        };
        static ref SALT: [u8; 64] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
        ];
    }

    #[test]
    fn test_sha256_salted() {
        // sha256(0x000000005E0BE100 + 0x000000000000007b + 0x0102030405060708090a0b0c0d0e0f
        //   101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
        //   303132333435363738393a3b3c3d3e3f40)
        // = 0x431a99c6fcdafcf1eca1fef43e9781af713a8aac70e3f57918fc32a0f6365e70
        // = [67, 26, 153, 198, 252, 218, 252, 241, 236, 161, 254, 244, 62, 151, 129, 175, 113,
        //    58, 138, 172, 112, 227, 245, 121, 24, 252, 50, 160, 246, 54, 94, 112]
        assert_eq!(
            vec![
                67, 26, 153, 198, 252, 218, 252, 241, 236, 161, 254, 244, 62, 151, 129, 175, 113,
                58, 138, 172, 112, 227, 245, 121, 24, 252, 50, 160, 246, 54, 94, 112
            ],
            sha256_salted(&MESSAGE, &SALT)
        );
    }

    #[test]
    fn test_sha256_unsalted() {
        // sha256(0x000000005E0BE100 + 0x000000000000007b)
        // = 0x2b2ccb3baab83e7b6c9a1e47287e10382c91b0e2a57901f2bafdac6364b48801
        // = [43, 44, 203, 59, 170, 184, 62, 123, 108, 154, 30, 71, 40, 126, 16, 56, 44, 145, 176,
        //    226, 165, 121, 1, 242, 186, 253, 172, 99, 100, 180, 136, 1]
        assert_eq!(
            vec![
                43, 44, 203, 59, 170, 184, 62, 123, 108, 154, 30, 71, 40, 126, 16, 56, 44, 145,
                176, 226, 165, 121, 1, 242, 186, 253, 172, 99, 100, 180, 136, 1
            ],
            sha256_unsalted(&MESSAGE)
        );
    }

    #[test]
    fn test_poseidon_salted() {
        let salt_fields = salt_to_fields(&SALT);
        // poseidon([
        //     1577836800,
        //     123,
        //     0x00000000000000000000000000000000100f0e0d0c0b0a090807060504030201,
        //     0x00000000000000000000000000000000201f1e1d1c1b1a191817161514131211,
        //     0x00000000000000000000000000000000302f2e2d2c2b2a292827262524232221,
        //     0x00000000000000000000000000000000403f3e3d3c3b3a393837363534333231
        // ])
        // = poseidon([
        //     1577836800,
        //     123,
        //     21345817372864405881847059188222722561,
        //     42696867846335054569745073772176806417,
        //     64047918319805703257643088356130890273,
        //     85398968793276351945541102940084974129
        // ])
        // = 17985402459508117977374367808756369644719494016363347420579663660868172185120
        // = 0x27c360864103a539c35d8d705da901e8b76702a79525d2a8f199c1562366fe20
        assert_eq!(
            Fr::from_str(
                "17985402459508117977374367808756369644719494016363347420579663660868172185120"
            )
            .unwrap(),
            poseidon_salted(&MESSAGE, &salt_fields)
        );
    }

    #[test]
    fn test_poseidon_unsalted() {
        // poseidon([
        //     1577836800,
        //     123
        // ])
        // = 9680575115483137054619374951052552265437214847559015354341148812072812999628
        // = 0x156702e79afc92cf8fb3a619dbfc38c6c26f97539ab8cf10702dd4d74ac2f3cc
        assert_eq!(
            Fr::from_str(
                "9680575115483137054619374951052552265437214847559015354341148812072812999628"
            )
            .unwrap(),
            poseidon_unsalted(&MESSAGE)
        );
    }
}
