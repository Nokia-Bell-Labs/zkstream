mod abi;
mod input;
mod nexmark;
mod params;
mod proof;
mod verification;
mod zokrates;

use crate::params::Params;
use clap::Parser;
use nexmark_datajson::DataJson;
use serde_json;
use std::fs;
use std::path::PathBuf;

#[macro_use]
extern crate lazy_static;

/// Compile and run Zokrates programs and generate proofs.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to data json. Default: ../data.json.
    #[arg(short = 'd', long)]
    data: Option<PathBuf>,

    /// Query to run. Examples: q1, q4. Note that some queries consist of
    /// multiple programs.
    #[arg(short = 'p', long, default_value_t = String::from("q1"))]
    program: String,

    /// Variant to run. One of: poseidon.nosig (default), poseidon, poseidon.nosig.bls.
    #[arg(short = 'v', long, default_value_t = String::from("poseidon.nosig"))]
    variant: String,

    /// Skip compilation?
    #[arg(long, default_value_t = false)]
    skip_compilation: bool,

    /// Enable debug mode?
    #[arg(long, default_value_t = false)]
    debug: bool,
}

/// Global 'options'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub skip_compilation: bool,
    pub debug: bool,
}

fn main() {
    let cli: Cli = Cli::parse();
    let data_path = cli.data.unwrap_or(PathBuf::from("../data.json"));

    let debug = cli.debug;
    if debug {
        println!("WARNING: do not enable DEBUG for benchmarking!");
    }

    // Select program and variant.
    println!("> Program {}", cli.program);
    let query = cli.program;
    println!("> Variant {}", cli.variant);
    let (hash_scheme, sig_variant, bls) = params::parse_variant(&cli.variant);

    let params = Params {
        hash_scheme,
        sig_variant,
        bls,
    };
    let options = Options {
        skip_compilation: cli.skip_compilation,
        debug,
    };

    // Parse data.json.
    println!("> Parsing data.json");
    let data_file = fs::read_to_string(data_path).expect("could not read data.json");
    let data: DataJson = serde_json::from_str(&data_file).expect("could not parse data JSON");
    // eprintln!("Data: {:?}", data);

    match query.as_str() {
        "q1" => nexmark::query1(params, options, data),
        "q4" => nexmark::query4(params, options, data),
        "q5" => nexmark::query5(params, options, data),
        "q6" => nexmark::query6(params, options, data),
        "q7" => nexmark::query7(params, options, data),
        _ => panic!("Unsupported query {:?}.", query),
    };
}
