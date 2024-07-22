use crate::serialize::SerializableMessage;
use crate::utils::{field_to_bigint, field_to_bytes};
use aggsigs::schemes::bls;
use babyjubjub_rs;
use ff::PrimeField;
use k256::{ecdsa, ecdsa::signature::Signer};
use num_bigint::BigInt;
use poseidon_rs::Fr;

use crate::hash::*;

//
// ECDSA
//

/// An ECDSA-style signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSASignature {
    /// 32 bytes
    pub r: Vec<u8>,
    /// 32 bytes
    pub s: Vec<u8>,
}

/// Extract fields from ecdsa::Signature and wrap in our ECDSASignature.
fn convert_ecdsa_signature(signature: &ecdsa::Signature) -> ECDSASignature {
    ECDSASignature {
        r: hex::decode(signature.r().to_string()).expect("could not decode hex signature.r"),
        s: hex::decode(signature.s().to_string()).expect("could not decode hex signature.s"),
    }
}

/// Sign a message using ECDSA, with an unsalted SHA256 hash.
pub fn ecdsa_sha256_unsalted<M: SerializableMessage>(
    message: &M,
    private_key: &ecdsa::SigningKey,
) -> ECDSASignature {
    let data = message.to_bytes();
    let signature: ecdsa::Signature = private_key.sign(&data);
    eprintln!("signature: {:?}", signature);
    // eprintln!("r: {:?}", signature.r().to_string());
    // eprintln!("s: {:?}", signature.s().to_string());
    convert_ecdsa_signature(&signature)
}

/// Sign a message using ECDSA, with a salted SHA256 hash.
pub fn ecdsa_sha256_salted<M: SerializableMessage>(
    message: &M,
    salt: &SaltSHA256,
    private_key: &ecdsa::SigningKey,
) -> ECDSASignature {
    let data = message.to_bytes_salted(salt);
    let signature: ecdsa::Signature = private_key.sign(&data);
    eprintln!("signature: {:?}", signature);
    // eprintln!("r: {:?}", signature.r().to_string());
    // eprintln!("s: {:?}", signature.s().to_string());
    convert_ecdsa_signature(&signature)
}

//
// EdDSA
//

/// An EdDSA-style signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSASignature {
    pub rx: Fr,
    pub ry: Fr,
    pub s: BigInt,
}

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
pub fn eddsa_sha256_unsalted<M: SerializableMessage>(
    _message: &M,
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
pub fn eddsa_sha256_salted<M: SerializableMessage>(
    _message: &M,
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
pub fn eddsa_poseidon_unsalted<M: SerializableMessage>(
    message: &M,
    private_key: &babyjubjub_rs::PrivateKey,
) -> EdDSASignature {
    let hash_fr = poseidon_unsalted(message);
    let hash_bi = field_to_bigint(&hash_fr);
    let signature = private_key.sign(hash_bi).unwrap();
    eprintln!("signature: {:?}", signature);
    convert_babyjubjub_signature(&signature)
}

/// Sign a message using EdDSA (BabyJubJub), with a salted Poseidon hash.
pub fn eddsa_poseidon_salted<M: SerializableMessage>(
    message: &M,
    salt: &SaltPoseidon,
    private_key: &babyjubjub_rs::PrivateKey,
) -> EdDSASignature {
    let hash_fr = poseidon_salted(message, &salt);
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
pub fn bls_sha256_unsalted<M: SerializableMessage>(
    message: &M,
    key_pair: &BLSKeyPair,
) -> BLSSignature {
    let data = message.to_bytes();
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &data);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Sign a message using BLS, with a salted SHA256 hash.
pub fn bls_sha256_salted<M: SerializableMessage>(
    message: &M,
    salt: &SaltSHA256,
    key_pair: &BLSKeyPair,
) -> BLSSignature {
    let data = message.to_bytes_salted(salt);
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &data);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Sign a message using BLS, with an unsalted Poseidon hash.
pub fn bls_poseidon_unsalted<M: SerializableMessage>(
    message: &M,
    key_pair: &BLSKeyPair,
) -> BLSSignature {
    let hash_fr = poseidon_unsalted(message);
    let hash_bytes = field_to_bytes(&hash_fr);
    let signature = bls::sign(&key_pair.sk, &key_pair.pk, &hash_bytes);
    eprintln!("signature: {:?}", signature);
    signature
}

/// Sign a message using BLS, with a salted Poseidon hash.
pub fn bls_poseidon_salted<M: SerializableMessage>(
    message: &M,
    salt: &SaltPoseidon,
    key_pair: &BLSKeyPair,
) -> BLSSignature {
    let hash_fr = poseidon_salted(message, &salt);
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
    use crate::serialize::Message;
    use babyjubjub_rs;
    use babyjubjub_rs::{Point, Signature};
    use chrono::{DateTime, TimeZone, Utc};

    lazy_static! {
        // Unix timestamp 1577836800
        static ref TIMESTAMP: DateTime<Utc> = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        static ref MESSAGE: Message = Message {
            id: 7,
            device_id: vec![0, 1, 2, 3],
            value: 123,
            timestamp: *TIMESTAMP,
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
        let message: &Message = &MESSAGE;
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
        let signature = ecdsa_sha256_unsalted(message, &private_key);

        // Check if signature can be verified by k256.
        use k256::ecdsa::signature::Verifier;
        let data = message.to_bytes();
        let rs = [signature.r.clone(), signature.s.clone()].concat();
        let k256_signature = ecdsa::Signature::from_slice(&rs)
            .expect("could not create k256 signature from our signature");
        assert!(public_key.verify(&data, &k256_signature).is_ok());

        // Check signature values.
        assert_eq!(
            // "1C967747073EBA936BB63D7D3948672D64954E7E126ED9EE71B6BCF9A8DFA408"
            &[
                28, 150, 119, 71, 7, 62, 186, 147, 107, 182, 61, 125, 57, 72, 103, 45, 100, 149,
                78, 126, 18, 110, 217, 238, 113, 182, 188, 249, 168, 223, 164, 8
            ],
            signature.r.as_slice()
        );
        assert_eq!(
            // "48AEA21BFAD681BC275BF73299D73C3996E4F0BAF82CC7EEDAA7E444C1E1E6D7"
            &[
                72, 174, 162, 27, 250, 214, 129, 188, 39, 91, 247, 50, 153, 215, 60, 57, 150, 228,
                240, 186, 248, 44, 199, 238, 218, 167, 228, 68, 193, 225, 230, 215
            ],
            signature.s.as_slice()
        );
    }

    #[test]
    fn test_ecdsa_sha256_salted() {
        let message: &Message = &MESSAGE;
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
        let signature = ecdsa_sha256_salted(message, &SALT, &private_key);

        // Check if signature can be verified by k256.
        use k256::ecdsa::signature::Verifier;
        let data = message.to_bytes_salted(&SALT);
        let rs = [signature.r.clone(), signature.s.clone()].concat();
        let k256_signature = ecdsa::Signature::from_slice(&rs)
            .expect("could not create k256 signature from our signature");
        assert!(public_key.verify(&data, &k256_signature).is_ok());

        // Check signature values.
        assert_eq!(
            // "861A6936087CC2627826750624A874B5D38BA89AE0003D749EED1311D2B21E9D"
            &[
                134, 26, 105, 54, 8, 124, 194, 98, 120, 38, 117, 6, 36, 168, 116, 181, 211, 139,
                168, 154, 224, 0, 61, 116, 158, 237, 19, 17, 210, 178, 30, 157
            ],
            signature.r.as_slice()
        );
        assert_eq!(
            // "36C256CBAB9110F79F563445820B7EE77365455CC258811A358C5D6F7D12109F"
            &[
                54, 194, 86, 203, 171, 145, 16, 247, 159, 86, 52, 69, 130, 11, 126, 231, 115, 101,
                69, 92, 194, 88, 129, 26, 53, 140, 93, 111, 125, 18, 16, 159
            ],
            signature.s.as_slice()
        );
    }

    #[test]
    fn test_eddsa_poseidon_unsalted() {
        let message: &Message = &MESSAGE;

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
        let signature = eddsa_poseidon_unsalted(message, &EDDSA_PRIVATE_KEY);

        // Check if signature can be verified by babyjubjub-rs.
        let r_b8 = Point {
            x: signature.rx,
            y: signature.ry,
        };
        let s = Signature {
            r_b8,
            s: signature.s.clone(),
        };
        let hash = poseidon_unsalted(message);
        assert_eq!(
            // 0x156702e79afc92cf8fb3a619dbfc38c6c26f97539ab8cf10702dd4d74ac2f3cc
            Fr::from_str(
                "9680575115483137054619374951052552265437214847559015354341148812072812999628"
            )
            .unwrap(),
            hash
        );
        let hash_bi = field_to_bigint(&hash);
        assert!(babyjubjub_rs::verify(public_key, s, hash_bi));

        // Check signature values.
        assert_eq!(
            // 0x05a4c9e90792e930a757b00482f3b126b004bd635e35ed64944a6aac6d5f5849
            Fr::from_str(
                "2552720695020887001329174990843062548795192210336039033576484908222566586441"
            )
            .unwrap(),
            signature.rx
        );
        assert_eq!(
            // 0x12f6b00ed93fc446be9d3e7b61c265efe095ddc059fa359d9f042d20a8bd4f05
            Fr::from_str(
                "8577490760109565407915233892753756016567698545842783288469396887258244402949"
            )
            .unwrap(),
            signature.ry
        );
        assert_eq!(
            BigInt::parse_bytes(
                b"2542684221057280233605538485080584714408685800914917355687464666426774284819",
                10
            )
            .unwrap(),
            signature.s
        );

        // See also: zokrates/test/test_eddsa_poseidon.zok
    }

    #[test]
    fn test_eddsa_poseidon_salted() {
        let message: &Message = &MESSAGE;
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
        let signature = eddsa_poseidon_salted(message, &salt, &EDDSA_PRIVATE_KEY);

        // Check if signature can be verified by babyjubjub-rs.
        let s = convert_eddsa_signature(&signature);
        let hash = poseidon_salted(message, &salt);
        assert_eq!(
            // 0x27c360864103a539c35d8d705da901e8b76702a79525d2a8f199c1562366fe20
            Fr::from_str(
                "17985402459508117977374367808756369644719494016363347420579663660868172185120"
            )
            .unwrap(),
            hash
        );
        let hash_bi = field_to_bigint(&hash);
        assert!(babyjubjub_rs::verify(public_key, s, hash_bi));

        // Check signature values.
        assert_eq!(
            // 0x13ef9a42fb8534cecab40169230463fd1abc8744cf92db756365d0fee461e9e4
            Fr::from_str(
                "9017285246346164106799368156661840504135261465872392616959887281050580281828"
            )
            .unwrap(),
            signature.rx
        );
        assert_eq!(
            // 0x034db8296fc6b9d9abf0633060ccde05c601eda40ed0ed7c407d267ee5d79cbd
            Fr::from_str(
                "1494256808194773076093450223144583911682113686446606437738251574790973791421"
            )
            .unwrap(),
            signature.ry
        );
        assert_eq!(
            BigInt::parse_bytes(
                b"2510500011589319156575434229707809297296185328097396229516035315955699475543",
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
        let message: &Message = &MESSAGE;
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
        let signature = bls_sha256_unsalted(message, &key_pair);

        // Check if signature can be verified by bls library.
        let data = message.to_bytes();
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                183, 206, 208, 182, 98, 86, 113, 178, 212, 143, 101, 87, 1, 168, 44, 89, 212, 179,
                61, 72, 91, 69, 104, 129, 140, 140, 15, 90, 147, 242, 250, 127, 198, 114, 90, 75,
                234, 47, 135, 234, 182, 60, 231, 198, 220, 103, 219, 118, 15, 192, 123, 114, 227,
                59, 146, 73, 31, 152, 34, 104, 116, 56, 173, 186, 87, 11, 179, 61, 110, 234, 245,
                225, 154, 189, 168, 199, 50, 120, 175, 99, 93, 252, 250, 248, 186, 86, 49, 103,
                213, 87, 19, 14, 75, 38, 69, 190
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_sha256_salted() {
        let message: &Message = &MESSAGE;
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
        let signature = bls_sha256_salted(message, &SALT, &key_pair);

        // Check if signature can be verified by bls library.
        let data = message.to_bytes_salted(&SALT);
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                145, 137, 53, 184, 131, 97, 38, 13, 18, 163, 177, 114, 102, 183, 25, 20, 61, 233,
                14, 214, 214, 59, 174, 130, 221, 209, 153, 255, 195, 144, 175, 173, 152, 68, 125,
                139, 123, 16, 154, 21, 27, 54, 154, 26, 223, 234, 5, 16, 11, 80, 251, 168, 53, 232,
                30, 26, 5, 142, 126, 235, 170, 170, 182, 122, 71, 80, 2, 36, 129, 215, 21, 183, 86,
                98, 80, 165, 118, 128, 27, 247, 52, 207, 78, 126, 135, 147, 8, 109, 144, 169, 144,
                125, 73, 60, 84, 87
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_poseidon_unsalted() {
        let message: &Message = &MESSAGE;
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
        let signature = bls_poseidon_unsalted(message, &key_pair);

        // Check if signature can be verified by bls library.
        let data = field_to_bytes(&poseidon_unsalted(message));
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                163, 208, 41, 172, 163, 0, 41, 31, 238, 189, 24, 166, 181, 80, 74, 178, 87, 76,
                207, 16, 6, 174, 96, 28, 210, 113, 15, 234, 202, 34, 15, 60, 139, 42, 178, 44, 69,
                171, 204, 48, 86, 126, 147, 50, 179, 252, 24, 239, 24, 21, 214, 117, 47, 87, 180,
                226, 174, 72, 23, 89, 57, 43, 154, 204, 32, 37, 205, 90, 5, 0, 81, 144, 168, 20,
                34, 208, 45, 212, 135, 150, 242, 105, 14, 231, 222, 52, 95, 101, 118, 189, 135, 1,
                56, 180, 27, 122
            ],
            signature.to_bytes()
        );
    }

    #[test]
    fn test_bls_poseidon_salted() {
        let message: &Message = &MESSAGE;
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
        let signature = bls_poseidon_salted(message, &salt, &key_pair);

        // Check if signature can be verified by bls library.
        let data = field_to_bytes(&poseidon_salted(message, &salt));
        assert_eq!(
            bls::verify(&public_key, &data, &signature),
            blst::BLST_ERROR::BLST_SUCCESS
        );

        // Check signature values.
        assert_eq!(
            [
                183, 9, 223, 85, 174, 151, 244, 110, 210, 29, 124, 41, 69, 189, 142, 178, 129, 179,
                182, 145, 71, 6, 253, 99, 121, 122, 159, 174, 186, 0, 226, 188, 29, 102, 150, 211,
                93, 159, 130, 249, 75, 222, 246, 209, 81, 70, 116, 70, 10, 210, 229, 26, 146, 206,
                161, 201, 111, 152, 158, 205, 165, 33, 81, 217, 204, 200, 197, 209, 117, 92, 16,
                248, 5, 122, 30, 40, 163, 13, 132, 86, 210, 71, 180, 253, 80, 66, 151, 155, 162,
                228, 254, 55, 223, 138, 163, 52
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
                device_id: vec![0, 1, 2, 3],
                value: 1,
                timestamp: *TIMESTAMP,
            },
            Message {
                id: 2,
                device_id: vec![0, 1, 2, 3],
                value: 2,
                timestamp: *TIMESTAMP,
            },
            Message {
                id: 3,
                device_id: vec![0, 1, 2, 3],
                value: 3,
                timestamp: *TIMESTAMP,
            },
            Message {
                id: 4,
                device_id: vec![0, 1, 2, 3],
                value: 4,
                timestamp: *TIMESTAMP,
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
            .map(|m| bls_poseidon_salted(m, &salt, &key_pair))
            .collect::<Vec<_>>();

        // Check if individual signatures can be verified by bls library.
        for (message, signature) in messages.iter().zip(signatures.iter()) {
            let data = field_to_bytes(&poseidon_salted(message, &salt));
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
