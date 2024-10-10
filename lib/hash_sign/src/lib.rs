// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#[macro_use]
extern crate lazy_static;

pub mod hash;
pub mod message;
pub mod sign;
pub mod utils;

pub use hash::{SaltPoseidon, SaltSHA256};
pub use poseidon_rs::Fr;

pub trait SerializableMessage {
    fn to_bytes(&self) -> Vec<u8>;
    fn to_bytes_salted(&self, salt: &SaltSHA256) -> Vec<u8>;
    fn to_fields(&self) -> Vec<Fr>;
    fn to_fields_salted(&self, salt: &SaltPoseidon) -> Vec<Fr>;
}
