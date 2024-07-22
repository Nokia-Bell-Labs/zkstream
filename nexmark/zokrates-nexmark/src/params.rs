//! This module defines parameters to the ZoKrates programs.

/// Hashing schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScheme {
    Poseidon,
}

/// Signature inside or outside of proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVariant {
    Sig,
    NoSig,
}

/// BLS signature or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bls {
    No,
    Yes,
}

/// The program's parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub hash_scheme: HashScheme,
    pub sig_variant: SigVariant,
    pub bls: Bls,
}

/// Parses variant string, like `poseidon`, `poseidon.nosig`, or `poseidon.nosig.bls`.
pub(crate) fn parse_variant(variant: &str) -> (HashScheme, SigVariant, Bls) {
    let mut variant = variant.to_string().to_ascii_lowercase();
    let hash;
    let sig;
    let bls;

    if variant.ends_with(".bls") {
        bls = Bls::Yes;
        // remove ".bls" suffix
        variant = variant[..variant.len() - 4].to_string();
    } else {
        bls = Bls::No;
    }

    if variant.ends_with(".nosig") {
        sig = SigVariant::NoSig;
        // remove ".nosig" suffix
        variant = variant[..variant.len() - 6].to_string();
    } else {
        sig = SigVariant::Sig;
    }

    if bls == Bls::Yes && sig != SigVariant::NoSig {
        panic!("BLS is only supported in the nosig variant");
    }

    if variant == "poseidon" {
        hash = HashScheme::Poseidon;
    } else {
        panic!("invalid variant");
    }

    (hash, sig, bls)
}

/// Convert variant back to string.
pub(crate) fn variant_to_string(hash: HashScheme, sig: SigVariant) -> String {
    let h = match hash {
        HashScheme::Poseidon => "poseidon",
    };
    let s = match sig {
        SigVariant::Sig => "",
        SigVariant::NoSig => ".nosig",
    };
    h.to_string() + s
}

/// Compose a program name, by concatenating the name and the variant.
pub(crate) fn program_name(name: &str, params: &Params) -> String {
    let variant = variant_to_string(params.hash_scheme, params.sig_variant);
    let program_name = format!("{name}.{variant}");
    program_name
}
