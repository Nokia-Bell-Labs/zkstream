// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use poseidon_rs::{Fr, FrRepr};
use serde_json;
use std::str::FromStr;

/// Convert a u64 to a field.
pub fn uint_to_field(i: u64) -> Fr {
    Fr::from_str(&i.to_string()).unwrap()
}

/// Convert a i64 to a field.
pub fn int_to_field(i: i64) -> Fr {
    Fr::from_str(&i.to_string()).unwrap()
}

/// Convert a decimal string to a BigInt.
pub fn decimal_str_to_bigint(s: &str) -> BigInt {
    BigInt::from_str(&s).unwrap()
}

/// Convert a decimal string to a field.
pub fn decimal_str_to_field(s: &str) -> Fr {
    Fr::from_str(&s).unwrap()
}

/// Convert a BigInt to a decimal string.
pub fn bigint_to_decimal_str(bi: &BigInt) -> String {
    bi.to_str_radix(10)
}

/// Convert a field to a decimal string.
pub fn field_to_decimal_str(el: &Fr) -> String {
    let bi = field_to_bigint(el);
    bigint_to_decimal_str(&bi)
}

/// Convert the field element `el` to bytes (in big-endian).
pub fn field_to_bytes(el: &Fr) -> Vec<u8> {
    // eprintln!("fr: {}", el);
    // Convert from Fr to FrRepr.
    let repr = el.into_repr();
    // eprintln!("fr_repr: {}", repr);
    // Convert from FrRepr to &[u64], in little-endian.
    let parts = repr.as_ref();
    // eprintln!("as_ref: {:?}", parts);
    // Convert from &[u64] to [[u8]] to Vec<u8>.
    let bytes = parts // &[u64], little-endian
        .iter()
        .rev() // [u64], big-endian
        .map(|x| x.to_be_bytes()) // [[u8]]
        .flatten() // [u8]
        .collect::<Vec<u8>>();
    // eprintln!("bytes: {:?}", bytes);
    bytes
}

/// Convert bytes (in big-endian) to a field element.
pub fn bytes_to_field(bytes: &[u8]) -> Fr {
    let mut repr = FrRepr::default();
    repr.read_be(bytes).unwrap();
    let el = Fr::from_repr(repr).unwrap();
    // eprintln!("fr: {}", el);
    el
}

/// Convert the field element `el` to a BigInt.
pub fn field_to_bigint(el: &Fr) -> BigInt {
    let bytes = field_to_bytes(el);
    BigInt::from_bytes_be(Sign::Plus, &bytes)
}

/// Convert a BigInt to a JSON number.
pub fn bigint_to_json_number(bigint: &BigInt) -> serde_json::Number {
    let string = bigint.to_str_radix(10);
    serde_json::Number::from_str(&string).unwrap()
}

/// Convert a field to a JSON number.
pub fn field_to_json_number(field: &Fr) -> serde_json::Number {
    let bigint = field_to_bigint(field);
    bigint_to_json_number(&bigint)
}

/// Convert a JSON number to a BigInt.
pub fn json_number_to_bigint(json: &serde_json::Number) -> BigInt {
    decimal_str_to_bigint(&json.to_string())
}

/// Convert a JSON number to a field.
pub fn json_number_to_field(json: &serde_json::Number) -> Fr {
    decimal_str_to_field(&json.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Number;

    lazy_static! {
        static ref DECIMAL_STR_ZERO: &'static str = "0";
        static ref DECIMAL_STR_ONE: &'static str = "1";
        static ref DECIMAL_STR_1001: &'static str = "1001";
        static ref DECIMAL_STR_LARGE: &'static str = "13295348564058270574916120458727243244321681575434307369270852791195253844015";
        static ref BI_ZERO: BigInt = BigInt::from(0);
        static ref BI_ONE: BigInt = BigInt::from(1);
        static ref BI_1001: BigInt = BigInt::from(1001);
        static ref BI_LARGE: BigInt = BigInt::parse_bytes(
            b"13295348564058270574916120458727243244321681575434307369270852791195253844015",
            10
        )
        .unwrap();
        static ref FR_ZERO: Fr = Fr::from_str("0").unwrap();
        static ref FR_ONE: Fr = Fr::from_str("1").unwrap();
        static ref FR_1001: Fr = Fr::from_str("1001").unwrap();
        static ref FR_LARGE: Fr = Fr::from_str(
            "13295348564058270574916120458727243244321681575434307369270852791195253844015"
        )
        .unwrap();
        static ref BYTES_ZERO: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ];
        static ref BYTES_ONE: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1
        ];
        static ref BYTES_1001: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 233
        ];
        // 1D 64 E6 8E B1 81 6D 01 AC CF 2F ED 1D 95 30 98 41 5B 8C 12 4A 64 28 63 A7 9B 4C CC 77 C7 A8 2F
        static ref BYTES_LARGE: [u8; 32] = [
            29, 100, 230, 142, 177, 129, 109, 1, 172, 207, 47, 237, 29, 149, 48, 152, 65, 91,
                140, 18, 74, 100, 40, 99, 167, 155, 76, 204, 119, 199, 168, 47
        ];
        static ref JSON_ZERO: Number = Number::from_str("0").unwrap();
        static ref JSON_ONE: Number = Number::from_str("1").unwrap();
        static ref JSON_1001: Number = Number::from_str("1001").unwrap();
        static ref JSON_LARGE: Number = Number::from_str(
            "13295348564058270574916120458727243244321681575434307369270852791195253844015"
        ).unwrap();
    }

    #[test]
    fn test_uint_to_bigint() {
        assert_eq!(*FR_ZERO, uint_to_field(0));
        assert_eq!(*FR_ONE, uint_to_field(1));
        assert_eq!(*FR_1001, uint_to_field(1001));
        // assert_eq!(*FR_LARGE, uint_to_field(..to big for u64..));
    }

    #[test]
    fn test_int_to_bigint() {
        assert_eq!(*FR_ZERO, int_to_field(0));
        assert_eq!(*FR_ONE, int_to_field(1));
        assert_eq!(*FR_1001, int_to_field(1001));
        // assert_eq!(*FR_LARGE, int_to_field(..to big for u64..));
    }

    #[test]
    fn test_decimal_str_to_bigint() {
        assert_eq!(*BI_ZERO, decimal_str_to_bigint(&DECIMAL_STR_ZERO));
        assert_eq!(*BI_ONE, decimal_str_to_bigint(&DECIMAL_STR_ONE));
        assert_eq!(*BI_1001, decimal_str_to_bigint(&DECIMAL_STR_1001));
        assert_eq!(*BI_LARGE, decimal_str_to_bigint(&DECIMAL_STR_LARGE));
    }

    #[test]
    fn test_decimal_str_to_field() {
        assert_eq!(*FR_ZERO, decimal_str_to_field(&DECIMAL_STR_ZERO));
        assert_eq!(*FR_ONE, decimal_str_to_field(&DECIMAL_STR_ONE));
        assert_eq!(*FR_1001, decimal_str_to_field(&DECIMAL_STR_1001));
        assert_eq!(*FR_LARGE, decimal_str_to_field(&DECIMAL_STR_LARGE));
    }

    #[test]
    fn test_bigint_to_decimal_str() {
        assert_eq!(*DECIMAL_STR_ZERO, bigint_to_decimal_str(&BI_ZERO));
        assert_eq!(*DECIMAL_STR_ONE, bigint_to_decimal_str(&BI_ONE));
        assert_eq!(*DECIMAL_STR_1001, bigint_to_decimal_str(&BI_1001));
        assert_eq!(*DECIMAL_STR_LARGE, bigint_to_decimal_str(&BI_LARGE));
    }

    #[test]
    fn test_field_to_decimal_str() {
        assert_eq!(*DECIMAL_STR_ZERO, field_to_decimal_str(&FR_ZERO));
        assert_eq!(*DECIMAL_STR_ONE, field_to_decimal_str(&FR_ONE));
        assert_eq!(*DECIMAL_STR_1001, field_to_decimal_str(&FR_1001));
        assert_eq!(*DECIMAL_STR_LARGE, field_to_decimal_str(&FR_LARGE));
    }

    #[test]
    fn test_field_to_bytes() {
        assert_eq!(*BYTES_ZERO, field_to_bytes(&FR_ZERO).as_slice());
        assert_eq!(*BYTES_ONE, field_to_bytes(&FR_ONE).as_slice());
        assert_eq!(*BYTES_1001, field_to_bytes(&FR_1001).as_slice());
        assert_eq!(*BYTES_LARGE, field_to_bytes(&FR_LARGE).as_slice());
    }

    #[test]
    fn test_bytes_to_field() {
        assert_eq!(*FR_ZERO, bytes_to_field(&*BYTES_ZERO));
        assert_eq!(*FR_ONE, bytes_to_field(&*BYTES_ONE));
        assert_eq!(*FR_1001, bytes_to_field(&*BYTES_1001));
        assert_eq!(*FR_LARGE, bytes_to_field(&*BYTES_LARGE));
    }

    #[test]
    fn test_field_to_bigint() {
        assert_eq!(*BI_ZERO, field_to_bigint(&FR_ZERO));
        assert_eq!(*BI_ONE, field_to_bigint(&FR_ONE));
        assert_eq!(*BI_1001, field_to_bigint(&FR_1001));
        assert_eq!(*BI_LARGE, field_to_bigint(&FR_LARGE));
    }

    #[test]
    fn test_bigint_to_json_number() {
        assert_eq!(*JSON_ZERO, bigint_to_json_number(&*BI_ZERO));
        assert_eq!(*JSON_ONE, bigint_to_json_number(&*BI_ONE));
        assert_eq!(*JSON_1001, bigint_to_json_number(&*BI_1001));
        assert_eq!(*JSON_LARGE, bigint_to_json_number(&*BI_LARGE));
    }

    #[test]
    fn test_field_to_json_number() {
        assert_eq!(*JSON_ZERO, field_to_json_number(&FR_ZERO));
        assert_eq!(*JSON_ONE, field_to_json_number(&FR_ONE));
        assert_eq!(*JSON_1001, field_to_json_number(&FR_1001));
        assert_eq!(*JSON_LARGE, field_to_json_number(&FR_LARGE));
    }

    #[test]
    fn test_json_number_to_bigint() {
        assert_eq!(*BI_ZERO, json_number_to_bigint(&JSON_ZERO));
        assert_eq!(*BI_ONE, json_number_to_bigint(&JSON_ONE));
        assert_eq!(*BI_1001, json_number_to_bigint(&JSON_1001));
        assert_eq!(*BI_LARGE, json_number_to_bigint(&JSON_LARGE));
    }

    #[test]
    fn test_json_number_to_field() {
        assert_eq!(*FR_ZERO, json_number_to_field(&JSON_ZERO));
        assert_eq!(*FR_ONE, json_number_to_field(&JSON_ONE));
        assert_eq!(*FR_1001, json_number_to_field(&JSON_1001));
        assert_eq!(*FR_LARGE, json_number_to_field(&JSON_LARGE));
    }
}
