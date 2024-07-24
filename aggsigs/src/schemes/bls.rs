// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::{blst_p1, blst_p1_affine, blst_p2, blst_p2_affine, blst_scalar, BLST_ERROR};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rand_core::SeedableRng;
use std::collections::HashMap;

/// This is a BLST wrapper to offer a protection against rogue
/// public key attacks. This protections is based on this paper:
/// https://eprint.iacr.org/2018/483.pdf

pub type Sig = Signature;
pub type AggSig = AggregateSignature;
pub type Pk = PublicKey;
pub type VerResult = BLST_ERROR;

pub const DST: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl KeyPair {
    pub fn encode(&self) -> HashMap<String, String> {
        let mut dic: HashMap<String, String> = HashMap::new();
        let pk_bytes = self.pk.to_bytes();
        let pk_hex = hex::encode(pk_bytes);
        let sk_bytes = self.sk.to_bytes();
        let sk_hex = hex::encode(sk_bytes);
        dic.insert("pk".to_string(), pk_hex);
        dic.insert("sk".to_string(), sk_hex);
        dic
    }

    pub fn decode(&self, sk: &[u8], pk: &[u8]) -> KeyPair {
        let sk = sk_from_bytes(sk).unwrap();
        let pk = pk_from_bytes(pk).unwrap();
        KeyPair { sk, pk }
    }
}

pub fn get_data(data_bytes: &mut [u8]) {
    let mut rng = ChaCha20Rng::from_entropy();
    rng.fill_bytes(data_bytes);
}

pub fn gen_key_pair() -> KeyPair {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    // key gen
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    KeyPair { sk, pk }
}

fn hash_pk(pk: &PublicKey) -> Option<blst_scalar> {
    let pk_bytes = pk.to_bytes();
    let pk_hash = blake3::hash(pk_bytes.as_slice());
    let pk_hash_bytes = pk_hash.as_bytes();

    unsafe {
        let mut out = blst_scalar::default();
        if blst::blst_scalar_from_le_bytes(&mut out, pk_hash_bytes.as_ptr(), pk_hash_bytes.len()) {
            Some(out)
        } else {
            None
        }
    }
}

fn sig_to_blst_p2(sig: &Signature) -> blst_p2 {
    let sig_affine_bytes = sig.to_bytes();
    unsafe {
        // affine_bytes -> affine_blst_p2
        let mut sig_affine_blst_p2 = blst_p2_affine::default();
        blst::blst_p2_uncompress(&mut sig_affine_blst_p2, sig_affine_bytes.as_ptr());

        let mut sig_blst_p2 = blst_p2::default();
        blst::blst_p2_from_affine(&mut sig_blst_p2, &sig_affine_blst_p2);

        sig_blst_p2
    }
}

fn blst_p2_to_sig(sig_blst_p2: &blst_p2) -> Signature {
    unsafe {
        let mut sig_blst_p2_affine = blst_p2_affine::default();
        blst::blst_p2_to_affine(&mut sig_blst_p2_affine, sig_blst_p2);

        let mut sig_affine_bytes: [u8; 96] = [0u8; 96];
        blst::blst_p2_affine_compress(sig_affine_bytes.as_mut_ptr(), &sig_blst_p2_affine);

        Signature::from_bytes(sig_affine_bytes.as_slice())
            .expect("blst_p2_to_sig() failed to reconstruct the sig from affine bytes")
    }
}

fn pk_to_blst_p1(pk: &PublicKey) -> blst_p1 {
    let pk_affine_bytes = pk.to_bytes();
    unsafe {
        // affine_bytes -> affine_blst_p2
        let mut pk_affine_blst_p1 = blst_p1_affine::default();
        blst::blst_p1_uncompress(&mut pk_affine_blst_p1, pk_affine_bytes.as_ptr());

        let mut pk_blst_p1 = blst_p1::default();
        blst::blst_p1_from_affine(&mut pk_blst_p1, &pk_affine_blst_p1);

        pk_blst_p1
    }
}

fn blst_p1_to_pk(pk_blst_p1: &blst_p1) -> PublicKey {
    unsafe {
        let mut pk_blst_p1_affine = blst_p1_affine::default();
        blst::blst_p1_to_affine(&mut pk_blst_p1_affine, pk_blst_p1);

        let mut pk_affine_bytes: [u8; 48] = [0u8; 48];
        blst::blst_p1_affine_compress(pk_affine_bytes.as_mut_ptr(), &pk_blst_p1_affine);

        PublicKey::from_bytes(pk_affine_bytes.as_slice())
            .expect("blst_p1_to_pk() failed to reconstruct the PK from affine bytes")
    }
}

/// DST is set as "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
/// because we protect against the rogue PK attacj using a techniques
/// introduced in this paper: https://eprint.iacr.org/2018/483.pdf
/// and not the ones indicated in the standardization draft. This
/// approached is referenced in the draft as well.
/// σ <- (H₀(m)^sk)^t = sig^t
pub fn sign(sk: &SecretKey, pk: &PublicKey, data: &[u8]) -> Sig {
    let sig = sk.sign(data, DST, &[]);

    // t <- Hash(pk)
    let t_blst_scalar = hash_pk(&pk).expect("Hashing pk to generate t has failed");

    // sig^t
    let sig_blst_p2 = sig_to_blst_p2(&sig);
    unsafe {
        let mut sig_t_blst_p2 = blst_p2::default();
        blst::blst_p2_mult(
            &mut sig_t_blst_p2,
            &sig_blst_p2,
            t_blst_scalar.b.as_ptr(),
            t_blst_scalar.b.len(),
        );

        blst_p2_to_sig(&sig_t_blst_p2)
    }
}

///e(g1,σ) == e(pk^t,H_0(m))
pub fn verify(pk: &Pk, data: &[u8], sig: &Sig) -> VerResult {
    // t <- Hash(pk)
    let t_blst_scalar = hash_pk(&pk).expect("Hashing pk to generate t has failed");

    // pk^t
    let pk_blst_p1 = pk_to_blst_p1(&pk);
    let mut pk_t_blst_p1 = blst_p1::default();
    unsafe {
        blst::blst_p1_mult(
            &mut pk_t_blst_p1,
            &pk_blst_p1,
            t_blst_scalar.b.as_ptr(),
            t_blst_scalar.b.len(),
        );
    }
    let pk_t = blst_p1_to_pk(&pk_t_blst_p1);

    sig.verify(true, data, DST, &[], &pk_t, false)
}

pub fn aggregate(sigs: &[&Sig]) -> AggregateSignature {
    let agg = match AggregateSignature::aggregate(sigs, false) {
        Ok(agg) => agg,
        Err(err) => panic!("aggregate failure: {:?}", err),
    };
    agg
}

/// pk^t
fn compute_pk_t(pk: &PublicKey) -> blst_p1 {
    // t <- H(pk)
    let t_blst_scalar = hash_pk(pk).expect("Hashing pk to generate t has failed");
    let pk_blst_p1 = pk_to_blst_p1(pk);

    let mut pk_t_blst_p1 = blst_p1::default();
    unsafe {
        blst::blst_p1_mult(
            &mut pk_t_blst_p1,
            &pk_blst_p1,
            t_blst_scalar.b.as_ptr(),
            t_blst_scalar.b.len(),
        );
        pk_t_blst_p1
    }
}

fn aggregate_2_pks(pk1: &blst_p1, pk2: &blst_p1) -> blst_p1 {
    unsafe {
        let mut sig_agg_blst_p1 = blst_p1::default();
        blst::blst_p1_add_or_double(&mut sig_agg_blst_p1, pk1, pk2);
        sig_agg_blst_p1
    }
}

pub fn aggregate_public_keys(public_keys: &[(&Pk, u64)]) -> Pk {
    let mut aggs = vec![];
    for pk_pair in public_keys {
        let pk = (*pk_pair).0;
        let count = (*pk_pair).1;

        let agg_blst_p1 = aggregate_same_pks(pk, count);
        let agg = blst_p1_to_pk(&agg_blst_p1);

        aggs.push(agg);
    }

    let aggs_ref: Vec<&PublicKey> = aggs.iter().map(|a| a).collect();
    let agg_of_aggs_pk_blst_p1 = aggregate_pks(&aggs_ref);
    blst_p1_to_pk(&agg_of_aggs_pk_blst_p1)
}

/// This function can be used if the corresponding SK was
/// used to sign the same message.
/// (t₁,...,tₙ) <- H1(pk₁,...,pkₙ)
/// apk <- pk₁^t₁ ... pkₙ^tₙ
pub fn aggregate_pks(public_keys: &[&Pk]) -> blst_p1 {
    // [pk_i^t_i]
    let mut pks_t_blst_p1: Vec<blst_p1> = vec![];
    for pk in public_keys {
        let pk_t_blst_p1 = compute_pk_t(pk);
        pks_t_blst_p1.push(pk_t_blst_p1);
    }

    // apk <- pk₁^t₁ ... pkₙ^tₙ
    if public_keys.len() > 1 {
        let mut apk_blst_p1 = pks_t_blst_p1[0];
        for pk_t_blst_p1 in &mut pks_t_blst_p1[1..public_keys.len()] {
            apk_blst_p1 = aggregate_2_pks(&apk_blst_p1, &*pk_t_blst_p1)
        }
        apk_blst_p1
    } else if public_keys.len() == 1 {
        pks_t_blst_p1[0]
    } else {
        blst_p1::default()
    }
}

pub fn aggregate_same_pks(public_key: &Pk, times: u64) -> blst_p1 {
    let mut pks = vec![];
    for _i in 0..times {
        pks.push(public_key);
    }
    aggregate_pks(&pks)
}

/// All sigs were on the same message but
/// with various (sk,pk) key pairs.
/// (t₁,...,tₙ) <- H1(pk₁,...,pkₙ)
/// apk <- pk₁^t₁ ... pkₙ^tₙ
///e(g1,σ) == e(apk,H_0(m))
pub fn verify_agg_one_message(agg_sig: AggSig, message: &[u8], public_keys: &[&Pk]) -> VerResult {
    // (t₁,...,tₙ) <- H1(pk₁,...,pkₙ)
    // apk <- pk₁^t₁ ... pkₙ^tₙ
    let apk_blst_p1 = aggregate_pks(public_keys);
    let apk = blst_p1_to_pk(&apk_blst_p1);

    verify_agg_one_message_apk(agg_sig, message, apk)
}

/// All sigs were on the same message but
/// with various (sk,pk) key pairs.
/// agg_pk = aggregate_pks(pks)
pub fn verify_agg_one_message_apk(agg_sig: AggSig, message: &[u8], agg_pk: Pk) -> VerResult {
    let sig = agg_sig.to_signature();

    sig.verify(true, message, DST, &[], &agg_pk, false)
}

/// Each signature on a different message
/// with various (sk,pk) key pairs. Each
/// public key is a pure public key and not
/// an aggregate pk (known as as apk).
///
/// For each pk in pks:
///     (t) <- H1(pk)
///     pk_t <- pk^t
/// e(g1,σ) == e(pk₁^t₁,H_0(m))....e(pkₙ^tₙ,H_0(m))
pub fn verify_agg_multiple_messages(
    agg_sig: AggSig,
    messages: &[&[u8]],
    public_keys: &[&Pk],
) -> VerResult {
    // [pk_i^t_i]
    let mut pks_t = vec![];
    for pk in public_keys {
        let pk_t_blst_p1 = compute_pk_t(pk);
        let pk_t = blst_p1_to_pk(&pk_t_blst_p1);
        pks_t.push(pk_t);
    }

    let pks_t_refs: Vec<&PublicKey> = pks_t.iter().map(|pk| pk).collect();
    verify_agg_multiple_messages_apk(agg_sig, messages, &pks_t_refs)
}

/// Each signature on a different message
/// with various (sk,pk) key pairs. Each
/// public key is an aggregate of pks.
/// Each apk is on a message.
///
/// For each pk in pks:
///     (t) <- H1(pk)
///     pk_t <- pk^t
/// e(g1,σ) == e(pk₁^t₁,H_0(m))....e(pkₙ^tₙ,H_0(m))
pub fn verify_agg_multiple_messages_apk(
    agg_sig: AggSig,
    messages: &[&[u8]],
    agg_pk: &[&Pk],
) -> VerResult {
    let sig = agg_sig.to_signature();
    sig.aggregate_verify(true, messages, DST, agg_pk, false)
}

/// this internally aggregates the pk by
/// duplicating it as many times as the
/// number of the messages.
/// TODO: more security investigation
pub fn verify_agg_multiple_messages_one_pk(
    agg_sig: AggSig,
    messages: &[&[u8]],
    pk: &Pk,
) -> VerResult {
    // aggregate PKs (which are the same in this case)
    let apk_blst_p1 = aggregate_same_pks(pk, messages.len() as u64);
    let apk = blst_p1_to_pk(&apk_blst_p1);
    let pks = vec![&apk];

    // verify
    verify_agg_multiple_messages_apk(agg_sig, messages, &pks)
}

pub fn sig_from_bytes(bytes: &[u8]) -> Result<Sig, BLST_ERROR> {
    Signature::from_bytes(bytes)
}

pub fn sig_from_hex(hex: &str) -> Result<Sig, BLST_ERROR> {
    let bytes = hex::decode(hex).unwrap();
    Sig::from_bytes(bytes.as_slice())
}

pub fn pk_from_bytes(bytes: &[u8]) -> Result<Pk, BLST_ERROR> {
    PublicKey::from_bytes(bytes)
}

pub fn pk_from_hex(hex: &str) -> Result<Pk, BLST_ERROR> {
    let pk_byes = hex::decode(hex).unwrap();
    PublicKey::from_bytes(pk_byes.as_slice())
}

pub fn sk_from_bytes(bytes: &[u8]) -> Result<SecretKey, BLST_ERROR> {
    SecretKey::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn encoding_decoding() {
        let key_pairs = gen_key_pair();

        let pk_bytes = key_pairs.pk.to_bytes();
        let pk_hex = hex::encode(pk_bytes);

        let decoded_from_hex = pk_from_hex(pk_hex.as_str()).unwrap();
        assert_eq!(pk_bytes, decoded_from_hex.to_bytes());

        let data = b"Hello World!";
        let signature = sign(&key_pairs.sk, &key_pairs.pk, data);

        let sig_bytes = signature.to_bytes();
        let sig_hex = hex::encode(sig_bytes);

        let constructed_sig = sig_from_hex(sig_hex.as_str()).unwrap();
        assert_eq!(constructed_sig.to_bytes(), sig_bytes);
    }

    #[test]
    fn serializations() {
        let data = b"Hello World!";
        let key_pairs = gen_key_pair();

        // public keys
        let pk_bytes = key_pairs.pk.to_bytes();
        assert_eq!(pk_from_bytes(&pk_bytes).unwrap(), key_pairs.pk);

        // secret keys
        // let sk_bytes = key_pairs.sk.to_bytes();
        // assert_eq!(sk_from_bytes(&sk_bytes).unwrap(), key_pairs.sk);

        // signature
        let sig = sign(&key_pairs.sk, &key_pairs.pk, data);
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_from_bytes(&sig_bytes).unwrap(), sig);
    }

    #[test]
    fn sign_agg_verify() {
        let data1 = "Hello World!".as_bytes();
        let data2 = "Fuck off World!".as_bytes();
        let key_pairs = gen_key_pair();

        // signatures
        let sig1 = sign(&key_pairs.sk, &key_pairs.pk, data1);
        let sig2 = sign(&key_pairs.sk, &key_pairs.pk, data2);

        // aggregate
        let sig_agg = aggregate(&vec![&sig1, &sig2]);

        // verify
        let pks = vec![&key_pairs.pk, &key_pairs.pk];
        let datas = vec![data1, data2];
        // verify_agg(sig_agg, datas.as_slice(), pks.as_slice());
        let res = verify_agg_multiple_messages(sig_agg, &datas, &pks);
        assert_eq!(BLST_ERROR::BLST_SUCCESS, res);

        let sig_from_agg_sig = sig_agg.to_signature();
        let agg_sig_from_sig = AggregateSignature::from_signature(&sig_from_agg_sig);
        // verify_agg(agg_sig_from_sig, datas.as_slice(), pks.as_slice());
        let res = verify_agg_multiple_messages(agg_sig_from_sig, &datas, &pks);
        assert_eq!(BLST_ERROR::BLST_SUCCESS, res);
    }

    #[test]
    fn test_gen_key() {
        let key_pairs = gen_key_pair();
        let pk = key_pairs.pk;
        let sk = key_pairs.sk;

        println!("pk: {:?}", pk.to_bytes());
        println!("sk: {:?}", sk.to_bytes());
    }

    #[test]
    fn test_hash_pk() {
        let key_pairs = gen_key_pair();
        let pk = key_pairs.pk;

        let t_option = hash_pk(&pk);
        assert_ne!(t_option, None);

        let t = t_option.unwrap();
        assert_eq!(t.b.len(), 32usize);

        println!("t: {:?}", t.b);
    }

    #[test]
    fn test_sig_to_p2_conversions() {
        // gen key
        let key_pairs = gen_key_pair();
        let sk = key_pairs.sk;
        let pk = key_pairs.pk;

        // sign
        let data = "Hello World!".as_bytes();
        let sig = sign(&sk, &pk, data);

        // sig to p2
        let sig_blst_p2 = sig_to_blst_p2(&sig);
        println!("blst_p2: {:?}", sig_blst_p2);

        let blst_p2_sig = blst_p2_to_sig(&sig_blst_p2);

        println!("blst_p2_expected: {:?}", sig.to_bytes());
        println!("blst_p2_bytes: {:?}", blst_p2_sig.to_bytes());
    }

    #[test]
    fn test_pk_conversions() {
        // gen key
        let key_pairs = gen_key_pair();
        let pk = key_pairs.pk;

        let pk_blst_p1 = pk_to_blst_p1(&pk);
        let pk_decoded = blst_p1_to_pk(&pk_blst_p1);

        pk_decoded.validate().expect("PK validation failed");
        assert_eq!(pk, pk_decoded);
    }

    #[test]
    fn test_sign_verify_m() {
        // gen key
        let key_pairs = gen_key_pair();
        let _sk = key_pairs.sk;
        let pk = key_pairs.pk;

        // sign
        let data = "Hello World!".as_bytes();
        let sig = sign(&_sk, &pk, data);

        let verif_result = verify(&pk, data, &sig);
        assert_eq!(BLST_ERROR::BLST_SUCCESS, verif_result);
    }

    #[test]
    fn test_apk_related_functions() {
        let kp1 = gen_key_pair();
        let kp2 = gen_key_pair();
        let kp3 = gen_key_pair();
        let kp4 = gen_key_pair();

        let pks = vec![&kp1.pk, &kp2.pk, &kp3.pk, &kp4.pk];

        let _apk = aggregate_pks(&pks);

        let kp_only_one = gen_key_pair();
        let only_one_pk = vec![&kp_only_one.pk];
        let _apk_only_one = aggregate_pks(&only_one_pk);
    }

    #[test]
    fn test_verify_agg_one_message() {
        // gen key
        let kp1 = gen_key_pair();
        let kp2 = gen_key_pair();
        let kp3 = gen_key_pair();
        let kp4 = gen_key_pair();

        // sign
        let data = "Hello World!".as_bytes();
        let sig1 = sign(&kp1.sk, &kp1.pk, data);
        let sig2 = sign(&kp2.sk, &kp2.pk, data);
        let sig3 = sign(&kp3.sk, &kp3.pk, data);
        let sig4 = sign(&kp4.sk, &kp4.pk, data);

        // aggregate
        let sigs = vec![&sig1, &sig2, &sig3, &sig4];
        let agg_sig = aggregate(&sigs.as_slice());

        // verify
        let pks = vec![&kp1.pk, &kp2.pk, &kp3.pk, &kp4.pk];
        let result = verify_agg_one_message(agg_sig, data, pks.as_slice());
        assert_eq!(BLST_ERROR::BLST_SUCCESS, result);

        // wrong verification
        let pks_one_missing = vec![&kp1.pk, &kp2.pk, &kp3.pk];
        let result_one_missing = verify_agg_one_message(agg_sig, data, pks_one_missing.as_slice());
        assert_ne!(BLST_ERROR::BLST_SUCCESS, result_one_missing);
        println!(
            "verify_agg_one_message(one pk missing): {:?}",
            result_one_missing
        );

        // wrong verification
        let pks_one_extra = vec![&kp1.pk, &kp2.pk, &kp3.pk, &kp4.pk, &kp4.pk];
        let result_one_extra = verify_agg_one_message(agg_sig, data, pks_one_extra.as_slice());
        assert_ne!(BLST_ERROR::BLST_SUCCESS, result_one_extra);
        println!(
            "verify_agg_one_message(one pk extra): {:?}",
            result_one_extra
        );
    }

    #[test]
    fn test_verify_agg_multiple_messages() {
        // gen key
        let kp1 = gen_key_pair();
        let kp2 = gen_key_pair();
        let kp3 = gen_key_pair();
        let kp4 = gen_key_pair();

        // sign
        let data1 = "Hello World!1".as_bytes();
        let data2 = "Hello World!2".as_bytes();
        let data3 = "Hello World!3".as_bytes();
        let data4 = "Hello World!4".as_bytes();
        let sig1 = sign(&kp1.sk, &kp1.pk, data1);
        let sig2 = sign(&kp2.sk, &kp2.pk, data2);
        let sig3 = sign(&kp3.sk, &kp3.pk, data3);
        let sig4 = sign(&kp4.sk, &kp4.pk, data4);

        // aggregate
        let sigs = vec![&sig1, &sig2, &sig3, &sig4];
        let agg_sig = aggregate(&sigs.as_slice());

        // verify
        let pks = vec![&kp1.pk, &kp2.pk, &kp3.pk, &kp4.pk];
        let datas = vec![data1, data2, data3, data4];
        let result = verify_agg_multiple_messages(agg_sig, &datas, pks.as_slice());
        assert_eq!(BLST_ERROR::BLST_SUCCESS, result);

        // wrong verification
        let pks_one_missing = vec![&kp1.pk, &kp2.pk, &kp3.pk];
        let result_one_missing =
            verify_agg_multiple_messages(agg_sig, &datas, pks_one_missing.as_slice());
        assert_ne!(BLST_ERROR::BLST_SUCCESS, result_one_missing);
        println!(
            "verify_agg_multiple_messages(one pk missing): {:?}",
            result_one_missing
        );

        // wrong verification
        let pks_one_extra = vec![&kp1.pk, &kp2.pk, &kp3.pk, &kp4.pk, &kp4.pk];
        let result_one_extra =
            verify_agg_multiple_messages(agg_sig, &datas, pks_one_extra.as_slice());
        assert_ne!(BLST_ERROR::BLST_SUCCESS, result_one_extra);
        println!(
            "verify_agg_multiple_messages(one pk extra): {:?}",
            result_one_extra
        );
    }

    #[test]
    fn test_agg_of_aggs() {
        // 4 sensors
        let kp1 = gen_key_pair();
        let kp2 = gen_key_pair();
        let kp3 = gen_key_pair();

        // sensor 1 produces 50 messages
        let s1_messages = produce_messages(1u8, 50u16);
        let s1_sigs: Vec<Sig> = s1_messages
            .iter()
            .map(|s1_message| sign(&kp1.sk, &kp1.pk, s1_message))
            .collect();
        let s1_sigs_refs: Vec<&Sig> = s1_sigs.iter().map(|sig| sig).collect();
        let s1_sig_agg = aggregate(&s1_sigs_refs);

        // sensor 2 produces 43 messages
        let s2_messages = produce_messages(2u8, 43u16);
        let s2_sigs: Vec<Sig> = s2_messages
            .iter()
            .map(|s2_message| sign(&kp2.sk, &kp2.pk, s2_message))
            .collect();
        let s2_sigs_refs: Vec<&Sig> = s2_sigs.iter().map(|sig| sig).collect();
        let s2_sig_agg = aggregate(&s2_sigs_refs);

        // sensor 3 produces 66 messages
        let s3_messages = produce_messages(3u8, 66u16);
        let s3_sigs: Vec<Sig> = s3_messages
            .iter()
            .map(|s3_message| sign(&kp3.sk, &kp3.pk, s3_message))
            .collect();
        let s3_sigs_refs: Vec<&Sig> = s3_sigs.iter().map(|sig| sig).collect();
        let s3_sig_agg = aggregate(&s3_sigs_refs);

        // Correctness: verify each aggregate signature independently

        // sensor1
        let s1_messages_refs: Vec<&[u8]> = s1_messages.iter().map(|m| m.as_slice()).collect();
        let s1_result = verify_agg_multiple_messages_one_pk(s1_sig_agg, &s1_messages_refs, &kp1.pk);
        assert_ne!(BLST_ERROR::BLST_SUCCESS, s1_result);

        // sensor2
        let s2_messages_refs: Vec<&[u8]> = s2_messages.iter().map(|m| m.as_slice()).collect();
        let s2_result = verify_agg_multiple_messages_one_pk(s2_sig_agg, &s2_messages_refs, &kp2.pk);
        assert_ne!(BLST_ERROR::BLST_SUCCESS, s2_result);

        // sensor3
        let s3_messages_refs: Vec<&[u8]> = s3_messages.iter().map(|m| m.as_slice()).collect();
        let s3_result = verify_agg_multiple_messages_one_pk(s3_sig_agg, &s3_messages_refs, &kp3.pk);
        assert_ne!(BLST_ERROR::BLST_SUCCESS, s3_result);

        // aggregate the aggregates
        let aggs = vec![
            s1_sig_agg.to_signature(),
            s2_sig_agg.to_signature(),
            s3_sig_agg.to_signature(),
        ];
        let aggs_refs: Vec<&Signature> = aggs.iter().map(|s| s).collect();
        let agg_of_aggs = aggregate(&aggs_refs);

        // verify agg_of_aggs
        // all public keys and the number of signatures signed by them
        let all_public_keys = vec![
            (&kp1.pk, s1_messages.len() as u64),
            (&kp2.pk, s2_messages.len() as u64),
            (&kp3.pk, s3_messages.len() as u64),
        ];
        let apk = aggregate_public_keys(&all_public_keys);

        // all messages signed by all signatures
        let mut all_messages: Vec<Vec<u8>> = Vec::new();
        all_messages.extend(s1_messages);
        all_messages.extend(s2_messages);
        all_messages.extend(s3_messages);
        let all_messages_refs: Vec<&[u8]> = all_messages.iter().map(|m| m.as_slice()).collect();

        // verify
        let all_result =
            verify_agg_multiple_messages_apk(agg_of_aggs, &all_messages_refs, &vec![&apk]);
        assert_ne!(BLST_ERROR::BLST_SUCCESS, all_result);
    }

    fn produce_messages(sensor: u8, message_count: u16) -> Vec<Vec<u8>> {
        let mut messages = vec![];
        for i in 0..message_count {
            let m = format!("{:?}-{:?}", sensor, i);
            messages.push(Vec::from(m.as_bytes()));
        }
        messages
    }
}
