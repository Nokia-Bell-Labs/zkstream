use aggsigs::schemes::bls;
use babyjubjub_rs;
use datajson::utils::{field_to_bigint, field_to_bytes};
use datajson::{ECDSASignature, EdDSASignature, Message};
use ff::PrimeField;
use k256::{ecdsa, ecdsa::signature::Signer};
use num_bigint::BigInt;
use poseidon_rs::Fr;

use crate::hash::*;

//
// ECDSA
//

/// Extract fields from ecdsa::Signature and wrap in our ECDSASignature.
fn convert_ecdsa_signature(signature: &ecdsa::Signature) -> ECDSASignature {
    ECDSASignature {
        r: hex::decode(signature.r().to_string()).expect("could not decode hex signature.r"),
        s: hex::decode(signature.s().to_string()).expect("could not decode hex signature.s"),
    }
}

/// Sign a message using ECDSA, with an unsalted SHA256 hash.
pub fn ecdsa_sha256_unsalted(message: &Message, private_key: &ecdsa::SigningKey) -> ECDSASignature {
    let data = serialize_sha256_unsalted(message);
    let signature: ecdsa::Signature = private_key.sign(&data);
    eprintln!("signature: {:?}", signature);
    // eprintln!("r: {:?}", signature.r().to_string());
    // eprintln!("s: {:?}", signature.s().to_string());
    convert_ecdsa_signature(&signature)
}

/// Sign a message using ECDSA, with a salted SHA256 hash.
pub fn ecdsa_sha256_salted(
    message: &Message,
    salt: &SaltSHA256,
    private_key: &ecdsa::SigningKey,
) -> ECDSASignature {
    let data = serialize_sha256_salted(message, salt);
    let signature: ecdsa::Signature = private_key.sign(&data);
    eprintln!("signature: {:?}", signature);
    // eprintln!("r: {:?}", signature.r().to_string());
    // eprintln!("s: {:?}", signature.s().to_string());
    convert_ecdsa_signature(&signature)
}

//
// EdDSA
//

/// Extract fields from babyjubjub_rs::Signature and wrap in our EdDSASignature.
pub fn convert_babyjubjub_signature(signature: &babyjubjub_rs::Signature) -> EdDSASignature {
    EdDSASignature {
        rx: signature.r_b8.x,
        ry: signature.r_b8.y,
        s: signature.s.clone(),
    }
}

/// Convert our EdDSASignature to a babyjubjub_rs::Signature.
pub fn convert_eddsa_signature(signature: &EdDSASignature) -> babyjubjub_rs::Signature {
    babyjubjub_rs::Signature {
        r_b8: babyjubjub_rs::Point {
            x: signature.rx,
            y: signature.ry,
        },
        s: signature.s.clone(),
    }
}

/// Sign a message using EdDSA (BabyJubJub), with an unsalted SHA256 hash.
pub fn eddsa_sha256_unsalted(
    _message: &Message,
    _private_key: &babyjubjub_rs::PrivateKey,
) -> EdDSASignature {
    // let signature = private_key.sign(&data); -- FIXME this uses poseidon internally
    EdDSASignature {
        rx: Fr::from_str("0").unwrap(),
        ry: Fr::from_str("0").unwrap(),
        s: BigInt::from(0),
    }
}

/// Sign a message using EdDSA (BabyJubJub), with a salted SHA256 hash.
pub fn eddsa_sha256_salted(
    _message: &Message,
    _salt: &SaltSHA256,
    _private_key: &babyjubjub_rs::PrivateKey,
) -> EdDSASignature {
    // let signature = private_key.sign(&data); -- FIXME this uses poseidon internally
    EdDSASignature {
        rx: Fr::from_str("0").unwrap(),
        ry: Fr::from_str("0").unwrap(),
        s: BigInt::from(0),
    }
}

/// Sign a message using EdDSA (BabyJubJub), with an unsalted Poseidon hash.
pub fn eddsa_poseidon_unsalted(
    message: &Message,
    private_key: &babyjubjub_rs::PrivateKey,
) -> EdDSASignature {
    let hash_fr = poseidon_unsalted(&message);
    let hash_bi = field_to_bigint(&hash_fr);
    let signature = private_key.sign(hash_bi).unwrap();
    eprintln!("signature: {:?}", signature);
    convert_babyjubjub_signature(&signature)
}

/// Sign a message using EdDSA (BabyJubJub), with a salted Poseidon hash.
pub fn eddsa_poseidon_salted(
    message: &Message,
    salt: &SaltPoseidon,
    private_key: &babyjubjub_rs::PrivateKey,
) -> EdDSASignature {
    let hash_fr = poseidon_salted(&message, &salt);
    let hash_bi = field_to_bigint(&hash_fr);
    let signature = private_key.sign(hash_bi).unwrap();
    eprintln!("signature: {:?}", signature);
    convert_babyjubjub_signature(&signature)
}

//
// BLS
//

pub type BLSKeyPair = bls::KeyPair;
pub type BLSPubKey = bls::Pk;
pub type BLSSignature = bls::Sig;
pub type BLSAggregateSignature = bls::AggSig;

/// Sign a message using BLS, with an unsalted SHA256 hash.
pub fn bls_sha256_unsalted(message: &Message, key_pair: &BLSKeyPair) -> BLSSignature {
    let data = serialize_sha256_unsalted(message);
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &data);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Sign a message using BLS, with a salted SHA256 hash.
pub fn bls_sha256_salted(
    message: &Message,
    salt: &SaltSHA256,
    key_pair: &BLSKeyPair,
) -> BLSSignature {
    let data = serialize_sha256_salted(message, salt);
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &data);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Sign a message using BLS, with an unsalted Poseidon hash.
pub fn bls_poseidon_unsalted(message: &Message, key_pair: &BLSKeyPair) -> BLSSignature {
    let hash_fr = poseidon_unsalted(&message);
    let hash_bytes = field_to_bytes(&hash_fr);
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &hash_bytes);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Sign a message using BLS, with a salted Poseidon hash.
pub fn bls_poseidon_salted(
    message: &Message,
    salt: &SaltPoseidon,
    key_pair: &BLSKeyPair,
) -> BLSSignature {
    let hash_fr = poseidon_salted(&message, &salt);
    let hash_bytes = field_to_bytes(&hash_fr);
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &hash_bytes);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Aggregate BLS signatures.
pub fn aggregate_bls_signatures(signatures: &[BLSSignature]) -> BLSAggregateSignature {
    // Convert from &[BLSSignature] to &[&BLSSignature]
    bls::aggregate(&signatures.iter().collect::<Vec<_>>())
}

/// Verify an aggregated BLS signature.
pub fn verify_bls_signature(
    signature: BLSAggregateSignature,
    hashes: &Vec<Vec<u8>>,
    public_key: &BLSPubKey,
) -> bool {
    // Convert from &Vec<Vec<u8>> to &[&[u8]]
    let hashes: Vec<&[u8]> = hashes.iter().map(|h| h.as_slice()).collect();
    // Doesn't work for now?? FIXME
    //let result = bls::verify_agg_multiple_messages_one_pk(signature, &hashes, public_key);
    // Workaround:
    let pks = vec![public_key; hashes.len()];
    let result = bls::verify_agg_multiple_messages(signature, &hashes, &pks);
    if result == blst::BLST_ERROR::BLST_SUCCESS {
        return true;
    } else {
        eprintln!("Error while verifying BLS signature: {:?}", result);
        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use babyjubjub_rs;
    use babyjubjub_rs::{Point, Signature};
    use chrono::{DateTime, TimeZone, Utc};
    use datajson::MessageValue;

    lazy_static! {
        // Unix timestamp 1577836800
        static ref TIMESTAMP: DateTime<Utc> = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        static ref MESSAGE: Message = Message {
            id: 7,
            device_id: 456,
            value: MessageValue { auction: 123, price: 321 },
            timestamp: TIMESTAMP.timestamp(),
        };
        static ref SALT: [u8; 64] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
        ];
        static ref ECDSA_PRIVATE_KEY: ecdsa::SigningKey = ecdsa::SigningKey::from_slice(&[
            76, 8, 131, 166, 145, 2, 147, 125, 98, 49, 71, 27, 93, 187, 98, 4, 254, 81, 41, 97, 112,
            130, 121, 42, 228, 104, 208, 26, 63, 54, 35, 24
        ]).unwrap();
        static ref EDDSA_PRIVATE_KEY: babyjubjub_rs::PrivateKey = babyjubjub_rs::PrivateKey::import(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1
        ]).unwrap();
        static ref BLS_SECRET_KEY: blst::min_pk::SecretKey = blst::min_pk::SecretKey::from_bytes(&[
            112, 114, 208, 211, 128, 163, 61, 0, 145, 43, 197, 117, 210, 101, 173, 30, 4, 129, 55,
            198, 191, 98, 120, 9, 104, 82, 38, 109, 205, 12, 112, 121
        ]).unwrap();

        static ref EDDSA_PRIVATE_KEY_ZERO: babyjubjub_rs::PrivateKey = babyjubjub_rs::PrivateKey::import(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]).unwrap();
    }

    #[test]
    fn test_ecdsa_sha256_unsalted() {
        let private_key: &ecdsa::SigningKey = &ECDSA_PRIVATE_KEY;

        // Check public key.
        let public_key = private_key.verifying_key();
        assert_eq!(
            &[
                78, 59, 129, 175, 156, 34, 52, 202, 208, 157, 103, 156, 230, 3, 94, 209, 57, 35,
                71, 206, 100, 206, 64, 95, 93, 205, 54, 34, 138, 37, 222, 110
            ],
            public_key.to_encoded_point(false).x().unwrap().as_slice()
        );
        assert_eq!(
            &[
                71, 253, 53, 196, 33, 93, 30, 223, 83, 230, 248, 61, 227, 68, 97, 92, 231, 25, 189,
                176, 253, 135, 143, 110, 215, 111, 6, 221, 39, 121, 86, 222
            ],
            public_key.to_encoded_point(false).y().unwrap().as_slice()
        );

        // Generate signature.
        let signature = ecdsa_sha256_unsalted(&MESSAGE, &private_key);

        // Check if signature can be verified by k256.
        use k256::ecdsa::signature::Verifier;
        let data = serialize_sha256_unsalted(&MESSAGE);
        let rs = [signature.r.clone(), signature.s.clone()].concat();
        let k256_signature = ecdsa::Signature::from_slice(&rs)
            .expect("could not create k256 signature from our signature");
        assert!(public_key.verify(&data, &k256_signature).is_ok());

        // Check signature values.
        assert_eq!(
            &[
                133, 217, 246, 42, 178, 239, 101, 251, 34, 188, 94, 123, 238, 70, 200, 22, 186,
                161, 176, 78, 34, 107, 138, 0, 80, 120, 103, 93, 233, 105, 193, 126
            ],
            signature.r.as_slice()
        );
        assert_eq!(
            &[
                45, 173, 189, 239, 107, 142, 31, 161, 93, 232, 157, 62, 54, 41, 144, 24, 31, 233,
                102, 237, 83, 74, 210, 168, 233, 77, 110, 170, 46, 125, 226, 22
            ],
            signature.s.as_slice()
        );
    }

    #[test]
    fn test_ecdsa_sha256_salted() {
        let private_key: &ecdsa::SigningKey = &ECDSA_PRIVATE_KEY;

        // Check public key.
        let public_key = private_key.verifying_key();
        assert_eq!(
            &[
                78, 59, 129, 175, 156, 34, 52, 202, 208, 157, 103, 156, 230, 3, 94, 209, 57, 35,
                71, 206, 100, 206, 64, 95, 93, 205, 54, 34, 138, 37, 222, 110
            ],
            public_key.to_encoded_point(false).x().unwrap().as_slice()
        );
        assert_eq!(
            &[
                71, 253, 53, 196, 33, 93, 30, 223, 83, 230, 248, 61, 227, 68, 97, 92, 231, 25, 189,
                176, 253, 135, 143, 110, 215, 111, 6, 221, 39, 121, 86, 222
            ],
            public_key.to_encoded_point(false).y().unwrap().as_slice()
        );

        // Generate signature.
        let signature = ecdsa_sha256_salted(&MESSAGE, &SALT, &private_key);

        // Check if signature can be verified by k256.
        use k256::ecdsa::signature::Verifier;
        let data = serialize_sha256_salted(&MESSAGE, &SALT);
        let rs = [signature.r.clone(), signature.s.clone()].concat();
        let k256_signature = ecdsa::Signature::from_slice(&rs)
            .expect("could not create k256 signature from our signature");
        assert!(public_key.verify(&data, &k256_signature).is_ok());

        // Check signature values.
        assert_eq!(
            &[
                242, 176, 112, 241, 141, 32, 60, 100, 184, 91, 249, 118, 70, 252, 79, 164, 164,
                203, 57, 101, 24, 23, 89, 164, 183, 23, 125, 231, 131, 251, 239, 224
            ],
            signature.r.as_slice()
        );
        assert_eq!(
            &[
                59, 137, 181, 23, 18, 113, 173, 102, 27, 218, 207, 126, 40, 53, 244, 35, 69, 112,
                62, 199, 164, 42, 227, 209, 80, 196, 188, 230, 4, 168, 130, 95
            ],
            signature.s.as_slice()
        );
    }

    #[test]
    fn test_eddsa_poseidon_unsalted() {
        // Check public key.
        let public_key = EDDSA_PRIVATE_KEY.public();
        assert_eq!(
            // 0x042e5b5841c2989943fe925c5776bdd2e977ecdb87cc4d19d59e93f2bb40dc0d
            Fr::from_str(
                "1891156797631087029347893674931101305929404954783323547727418062433377377293"
            )
            .unwrap(),
            public_key.x
        );
        assert_eq!(
            // 0x20ad8a9be9c56d29b2cc80d0622e1c365217571b0df47e9c2619cfc4c7a6d6d6
            Fr::from_str(
                "14780632341277755899330141855966417738975199657954509255716508264496764475094"
            )
            .unwrap(),
            public_key.y
        );

        // Generate signature.
        let signature = eddsa_poseidon_unsalted(&MESSAGE, &EDDSA_PRIVATE_KEY);

        // Check if signature can be verified by babyjubjub-rs.
        let r_b8 = Point {
            x: signature.rx,
            y: signature.ry,
        };
        let s = Signature {
            r_b8,
            s: signature.s.clone(),
        };
        let hash = poseidon_unsalted(&MESSAGE);
        assert_eq!(
            // 0x13aad39079c8d463a2fcd12dbad3668ddc2c88171ad70fbc115c9f7d05dcc7dd
            Fr::from_str(
                "8895768287631283409829976895763390893671667802410697332647501803856265529309"
            )
            .unwrap(),
            hash
        );
        let hash_bi = field_to_bigint(&hash);
        assert!(babyjubjub_rs::verify(public_key, s, hash_bi));

        // Check signature values.
        assert_eq!(
            // 0x17f27fd138c84c050ed252f8c84ec13195481096b7f24d5bb05b1f2551d1b9df
            Fr::from_str(
                "10831654669486277496775894144906411134819034088943173786106620018189277444575"
            )
            .unwrap(),
            signature.rx
        );
        assert_eq!(
            // 0x1ae23bd28368e28b711d9cd5a60fe353ce248a059a580425a6aeb08df6d52ca9
            Fr::from_str(
                "12159854378267159071450143760686627786493814795481863914884328258271767243945"
            )
            .unwrap(),
            signature.ry
        );
        assert_eq!(
            BigInt::parse_bytes(
                b"1322711500316554715144291426325060121042654028222822525076407488792983938454",
                10
            )
            .unwrap(),
            signature.s
        );

        // See also: zokrates/test/test_eddsa_poseidon.zok
    }

    #[test]
    fn test_eddsa_poseidon_salted() {
        let salt = salt_to_fields(&SALT);

        // Check public key.
        let public_key = EDDSA_PRIVATE_KEY.public();
        assert_eq!(
            // 0x042e5b5841c2989943fe925c5776bdd2e977ecdb87cc4d19d59e93f2bb40dc0d
            Fr::from_str(
                "1891156797631087029347893674931101305929404954783323547727418062433377377293"
            )
            .unwrap(),
            public_key.x
        );
        assert_eq!(
            // 0x20ad8a9be9c56d29b2cc80d0622e1c365217571b0df47e9c2619cfc4c7a6d6d6
            Fr::from_str(
                "14780632341277755899330141855966417738975199657954509255716508264496764475094"
            )
            .unwrap(),
            public_key.y
        );

        // Generate signature.
        let signature = eddsa_poseidon_salted(&MESSAGE, &salt, &EDDSA_PRIVATE_KEY);

        // Check if signature can be verified by babyjubjub-rs.
        let s = convert_eddsa_signature(&signature);
        let hash = poseidon_salted(&MESSAGE, &salt);
        assert_eq!(
            // 0x1c344646f31347bf34c5c979c22cf909e2ee5ff7e9e71f798eef65f200ce2e25
            Fr::from_str(
                "12757120842739295214529540480751019909478086822962532388908380917277859393061"
            )
            .unwrap(),
            hash
        );
        let hash_bi = field_to_bigint(&hash);
        assert!(babyjubjub_rs::verify(public_key, s, hash_bi));

        // Check signature values.
        assert_eq!(
            // 0x16172c5e9032ada2c3071185d8275dfb314020b20ebea5538f43291f95cb434d
            Fr::from_str(
                "9991826377581826709953286203015213594072768892915229809241357677425649730381"
            )
            .unwrap(),
            signature.rx
        );
        assert_eq!(
            // 0x09019897e91b887b2ce7f9a90eda210f868b503b535eb9f87cd7c19a8c807a80
            Fr::from_str(
                "4073635645259925216426170807641199647647845652443877759334119150278731135616"
            )
            .unwrap(),
            signature.ry
        );
        assert_eq!(
            BigInt::parse_bytes(
                b"2552976830710822964698333504605130914769924257119366612357782562213591731670",
                10
            )
            .unwrap(),
            signature.s
        );
    }

    #[test]
    fn test_eddsa_zero() {
        // Check public key.
        let public_key = EDDSA_PRIVATE_KEY_ZERO.public();
        assert_eq!(
            // 0x247fb74a2522435359fd14dddd4777901eaeaa238697b1f621e2296dced26ca9
            Fr::from_str(
                "16508917144752610602145963506823743115557101240265470506805505298395529637033"
            )
            .unwrap(),
            public_key.x
        );
        assert_eq!(
            // 0x29312493e14ec0daa3fc22648bee7f178938dbe556cbb51006b519c05a09f191
            Fr::from_str(
                "18631654747796370155722974221085383534170330422926471002342567715267253236113"
            )
            .unwrap(),
            public_key.y
        );

        // Generate signature.
        // let timestamp_zero: DateTime<Utc> = Utc.timestamp_opt(0, 0).unwrap();
        // let message_zero: Message = Message {
        //     id: 0,
        //     device_id: vec![0, 0, 0, 0],
        //     value: 0,
        //     timestamp: timestamp_zero,
        // };
        let zero = BigInt::from(0);
        let sig = EDDSA_PRIVATE_KEY_ZERO.sign(zero.clone()).unwrap();
        let signature = convert_babyjubjub_signature(&sig);

        // Check if signature can be verified by babyjubjub-rs.
        let r_b8 = Point {
            x: signature.rx,
            y: signature.ry,
        };
        let s = Signature {
            r_b8,
            s: signature.s.clone(),
        };
        assert!(babyjubjub_rs::verify(public_key, s, zero));

        // Check signature values.
        assert_eq!(
            // 0x2aae7e61f2f19acf9835c9b1f34ed477954301b3a6c028711cd8296b1656bebd
            Fr::from_str(
                "19305443290508114514596883319505632209723717456873021433762886134731615157949"
            )
            .unwrap(),
            signature.rx
        );
        assert_eq!(
            // 0x1104dc9e9c79abe6d631f73ea85059b36691f3d39d7db14e5b40dafaf8b7c9c6
            Fr::from_str(
                "7697908474521279722044072655602572024791636126724064066592600415024484698566"
            )
            .unwrap(),
            signature.ry
        );
        assert_eq!(
            BigInt::parse_bytes(
                b"983289417060294735236888011028457617482700900137563028470545220005821415621",
                10
            )
            .unwrap(),
            signature.s
        );

        // See also: zokrates/test/test_eddsa_poseidon.zok
    }

    #[test]
    fn test_bls_sha256_unsalted() {
        let private_key: &blst::min_pk::SecretKey = &BLS_SECRET_KEY;

        // Check public key.
        let public_key = private_key.sk_to_pk();
        assert_eq!(
            [
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
            public_key.to_bytes()
        );

        let key_pair = bls::KeyPair {
            sk: private_key.clone(),
            pk: public_key.clone(),
        };

        // Generate signature.
        let signature = bls_sha256_unsalted(&MESSAGE, &key_pair);

        // Check if signature can be verified by bls library.
        let data = serialize_sha256_unsalted(&MESSAGE);
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                147, 93, 60, 132, 219, 56, 86, 169, 78, 124, 224, 44, 82, 254, 174, 70, 103, 206,
                15, 88, 68, 102, 180, 72, 185, 195, 187, 0, 233, 27, 156, 255, 20, 210, 153, 238,
                25, 37, 108, 242, 114, 161, 18, 152, 205, 22, 128, 230, 18, 27, 48, 223, 90, 149,
                95, 248, 155, 220, 180, 33, 225, 124, 138, 12, 221, 94, 22, 188, 249, 106, 97, 248,
                118, 77, 246, 189, 227, 248, 193, 111, 56, 218, 7, 47, 193, 17, 138, 80, 169, 117,
                199, 19, 111, 101, 101, 31
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_sha256_salted() {
        let private_key: &blst::min_pk::SecretKey = &BLS_SECRET_KEY;

        // Check public key.
        let public_key = private_key.sk_to_pk();
        assert_eq!(
            [
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
            public_key.to_bytes()
        );

        let key_pair = bls::KeyPair {
            sk: private_key.clone(),
            pk: public_key.clone(),
        };

        // Generate signature.
        let signature = bls_sha256_salted(&MESSAGE, &SALT, &key_pair);

        // Check if signature can be verified by bls library.
        let data = serialize_sha256_salted(&MESSAGE, &SALT);
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                128, 188, 195, 59, 221, 194, 3, 231, 18, 255, 22, 130, 87, 247, 46, 87, 55, 161,
                124, 12, 172, 125, 66, 179, 96, 72, 193, 239, 19, 198, 208, 165, 77, 75, 114, 84,
                209, 197, 218, 35, 92, 231, 179, 127, 178, 76, 20, 69, 2, 181, 13, 124, 210, 39,
                146, 52, 71, 143, 52, 115, 192, 68, 139, 138, 1, 189, 221, 239, 23, 204, 132, 66,
                182, 188, 29, 97, 113, 232, 208, 161, 119, 115, 157, 190, 156, 63, 36, 15, 33, 92,
                210, 147, 251, 166, 154, 93
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_poseidon_unsalted() {
        let private_key: &blst::min_pk::SecretKey = &BLS_SECRET_KEY;

        // Check public key.
        let public_key = private_key.sk_to_pk();
        assert_eq!(
            [
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
            public_key.to_bytes()
        );

        let key_pair = bls::KeyPair {
            sk: private_key.clone(),
            pk: public_key.clone(),
        };

        // Generate signature.
        let signature = bls_poseidon_unsalted(&MESSAGE, &key_pair);

        // Check if signature can be verified by bls library.
        let data = field_to_bytes(&poseidon_unsalted(&MESSAGE));
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                146, 114, 231, 75, 143, 37, 250, 4, 128, 2, 215, 226, 138, 208, 200, 130, 94, 238,
                91, 105, 71, 146, 100, 126, 13, 233, 208, 243, 5, 203, 43, 63, 11, 65, 175, 154,
                44, 119, 139, 177, 88, 250, 253, 94, 138, 69, 29, 73, 16, 64, 255, 192, 147, 107,
                47, 112, 123, 246, 169, 235, 162, 45, 224, 13, 145, 181, 49, 148, 245, 91, 191, 24,
                111, 115, 162, 142, 202, 27, 212, 87, 199, 196, 248, 193, 111, 118, 17, 46, 138,
                230, 71, 216, 131, 223, 133, 189
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_poseidon_salted() {
        let private_key: &blst::min_pk::SecretKey = &BLS_SECRET_KEY;
        let salt = salt_to_fields(&SALT);

        // Check public key.
        let public_key = private_key.sk_to_pk();
        assert_eq!(
            [
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
            public_key.to_bytes()
        );

        let key_pair = bls::KeyPair {
            sk: private_key.clone(),
            pk: public_key.clone(),
        };

        // Generate signature.
        let signature = bls_poseidon_salted(&MESSAGE, &salt, &key_pair);

        // Check if signature can be verified by bls library.
        let data = field_to_bytes(&poseidon_salted(&MESSAGE, &salt));
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                139, 172, 40, 183, 87, 121, 153, 167, 70, 170, 169, 82, 222, 142, 158, 208, 88, 33,
                230, 37, 252, 214, 75, 65, 9, 245, 13, 127, 35, 228, 245, 65, 247, 181, 71, 36,
                157, 223, 35, 224, 205, 168, 32, 90, 35, 181, 214, 123, 5, 50, 253, 122, 161, 238,
                77, 225, 66, 88, 236, 102, 61, 81, 239, 184, 97, 202, 7, 247, 131, 247, 55, 243,
                135, 18, 95, 252, 153, 161, 241, 149, 150, 228, 11, 173, 20, 128, 254, 69, 145, 16,
                58, 126, 250, 53, 247, 100
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_aggregate_verify() {
        let private_key: &blst::min_pk::SecretKey = &BLS_SECRET_KEY;
        let messages = [
            Message {
                id: 1,
                device_id: 456,
                value: MessageValue {
                    auction: 1,
                    price: 10,
                },
                timestamp: TIMESTAMP.timestamp(),
            },
            Message {
                id: 2,
                device_id: 456,
                value: MessageValue {
                    auction: 2,
                    price: 20,
                },
                timestamp: TIMESTAMP.timestamp(),
            },
            Message {
                id: 3,
                device_id: 456,
                value: MessageValue {
                    auction: 3,
                    price: 30,
                },
                timestamp: TIMESTAMP.timestamp(),
            },
            Message {
                id: 4,
                device_id: 456,
                value: MessageValue {
                    auction: 4,
                    price: 40,
                },
                timestamp: TIMESTAMP.timestamp(),
            },
        ];
        let salt = salt_to_fields(&SALT);

        // Check public key.
        let public_key = private_key.sk_to_pk();
        assert_eq!(
            [
                168, 179, 127, 95, 141, 103, 59, 248, 193, 7, 1, 15, 193, 209, 177, 54, 61, 155,
                185, 239, 137, 159, 162, 38, 198, 61, 74, 124, 62, 248, 75, 236, 108, 12, 99, 120,
                48, 70, 203, 84, 130, 180, 217, 135, 191, 174, 228, 168
            ],
            public_key.to_bytes()
        );

        let key_pair = bls::KeyPair {
            sk: private_key.clone(),
            pk: public_key.clone(),
        };

        // Generate some signatures.
        let signatures = messages
            .iter()
            .map(|m| bls_poseidon_salted(&m, &salt, &key_pair))
            .collect::<Vec<_>>();

        // Check if individual signatures can be verified by bls library.
        for (message, signature) in messages.iter().zip(signatures.iter()) {
            let data = field_to_bytes(&poseidon_salted(&message, &salt));
            eprintln!("Message that is being verified: {:?}", data);
            assert_eq!(
                bls::verify(&public_key, &data, &signature),
                blst::BLST_ERROR::BLST_SUCCESS
            );
        }

        // Generate aggregated signature.
        let agg_sig = aggregate_bls_signatures(&signatures);
        eprintln!("Aggregated signature: {:?}", agg_sig);

        // Verify aggregated signature.
        let hashes = messages
            .iter()
            .map(|m| field_to_bytes(&poseidon_salted(m, &salt)))
            .collect::<Vec<Vec<u8>>>();
        eprintln!("Messages that are being verified: {:?}", hashes);
        assert!(
            verify_bls_signature(agg_sig, &hashes, &public_key),
            "could not verify signature"
        );
    }
}
