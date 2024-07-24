// Copyright 2024 Nokia
// Licensed under the BSD 3-Clause Clear License.
// SPDX-License-Identifier: BSD-3-Clause-Clear

mod abi;
mod input;
mod params;
mod proof;
mod verification;

use crate::input::{generate_inputs_for_flexibility, get_bls_poseidon_signatures};
use crate::params::{Bls, Params};
use clap::Parser;
use debs_datajson::{Data, DataJson, SignedMessage};
use hash_sign::sign::{self, BLSAggregateSignature};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

#[macro_use]
extern crate lazy_static;

/// Compile and run Zokrates programs and generate proofs.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to data json. Default: ../data.json.
    #[arg(short = 'd', long)]
    data: Option<PathBuf>,

    /// Variant to run. One of: poseidon.nosig (default), poseidon, poseidon.nosig.bls.
    #[arg(short = 'v', long, default_value_t = String::from("poseidon.nosig"))]
    variant: String,

    /// Number of messages before the activation time. Default is 120 (10 minutes).
    #[arg(short = 'B', long, default_value_t = 60)]
    n_before: usize,

    /// Number of messages after the activation time. Default is 60 (5 minutes).
    #[arg(short = 'A', long, default_value_t = 30)]
    n_after: usize,

    /// Skip compilation?
    #[arg(long, default_value_t = false)]
    skip_compilation: bool,

    /// Skip execution and proof generation? (Useful when doing only verification.)
    #[arg(long, default_value_t = false)]
    skip_execution: bool,

    /// Skip verification?
    #[arg(long, default_value_t = false)]
    skip_verification: bool,

    /// Enable debug mode?
    #[arg(long, default_value_t = false)]
    debug: bool,
}

fn main() {
    let cli: Cli = Cli::parse();
    let data_path = cli.data.unwrap_or(PathBuf::from("../data.json"));

    let n_before = cli.n_before;
    let n_after = cli.n_after;
    println!("> Number of before messages: {}", n_before);
    println!("> Number of after messages: {}", n_after);

    let debug = cli.debug;
    if debug {
        println!("WARNING: do not enable DEBUG for benchmarking!");
    }

    // Select variant.
    println!("> Variant {}", cli.variant);
    let (hash_scheme, sig_variant, bls) = params::parse_variant(&cli.variant);
    let variant = params::variant_to_string(hash_scheme, sig_variant);
    let flexibility_name = format!("flexibility.{variant}");

    let params = Params {
        hash_scheme,
        sig_variant,
        bls,
        n_before,
        n_after,
    };

    // Parse data.json.
    println!("> Parsing data.json");
    let data_file = fs::read_to_string(data_path).expect("could not read data.json");
    let data_json: DataJson = serde_json::from_str(&data_file).expect("could not parse data JSON");
    let data: Data = debs_datajson::data_from_json(&data_json);
    // eprintln!("Data: {:?}", data);

    // Compile code.
    if !cli.skip_compilation {
        compile(&flexibility_name, debug, params);
        setup(&flexibility_name);
    }

    // Execute programs and generate proofs.
    if !cli.skip_execution {
        execute_flexibility(&flexibility_name, &flexibility_name, params, &data);
        generate_proof(&flexibility_name, &flexibility_name);
    }

    // When using BLS, aggregate signatures.
    // Note: we assume everything is signed with the same public key.
    let aggsig = if bls == Bls::Yes {
        let messages = data.current.messages[..(n_before + n_after)].to_vec();
        aggregate_signatures(&messages)
    } else {
        None
    };

    // Verify everything
    if !cli.skip_verification {
        verification::verify(params, &data, aggsig);
    }
}

/// Execute command.
/// Time it and print the execution time.
/// Also checks if the command succeeded, and panics and logs stdout and stderr if it didn't.
fn execute_command(command: &mut Command, description: &str) {
    let t = Instant::now();
    let output = command.output().expect(&format!("{description} failed"));
    println!("| Time to {description}: {:?}", t.elapsed());

    if !output.status.success() {
        eprintln!(
            "stdout: {}",
            String::from_utf8(output.stdout.clone()).expect("could not read stdout")
        );
        eprintln!(
            "stderr: {}",
            String::from_utf8(output.stderr.clone()).expect("could not read stderr")
        );
        panic!("{description} returned non-zero exit code");
    }
}

/// Execute command with input provided on stdin.
/// Time it and print the execution time.
/// Also checks if the command succeeded, and panics and logs stdout and stderr if it didn't.
fn execute_command_with_stdin(command: &mut Command, description: &str, input: &[u8]) {
    command.stdin(Stdio::piped());
    let input_vec = input.to_vec();

    let t = Instant::now();
    let mut child = command
        .spawn()
        .expect(&format!("{description} could not be spawned"));

    let mut stdin = child.stdin.take().expect("failed to open stdin");
    std::thread::spawn(move || {
        stdin
            .write_all(&input_vec)
            .expect("failed to write to stdin");
    });

    let output = child
        .wait_with_output()
        .expect(&format!("{description} failed"));
    println!("| Time to {description}: {:?}", t.elapsed());

    if !output.status.success() {
        eprintln!(
            "stdout: {}",
            String::from_utf8(output.stdout.clone()).expect("could not read stdout")
        );
        eprintln!(
            "stderr: {}",
            String::from_utf8(output.stderr.clone()).expect("could not read stderr")
        );
        panic!("{description} returned non-zero exit code");
    }
}

/// Compile Zokrates program.
fn compile(program_name: &str, debug: bool, params: Params) {
    println!("> Compiling {program_name}");

    // Replace `N_BEFORE` and `N_AFTER` with actual values and write to a temporary file.
    let mut program =
        fs::read_to_string(&format!("src/{program_name}.zok")).expect("could not read program");
    program = program.replace(
        "N_BEFORE = 120;",
        &format!("N_BEFORE = {};", params.n_before),
    );
    program = program.replace("N_AFTER = 60;", &format!("N_AFTER = {};", params.n_after));
    fs::write(&format!("src/{program_name}.tmp.zok"), program).expect("could not write program");

    let mut c = Command::new("zokrates");
    c.arg("compile");
    if debug {
        c.arg("--debug");
    }
    c.args(["-i", &format!("src/{program_name}.tmp.zok")]);
    c.args(["-o", &format!("{program_name}.out")]);
    c.args(["--r1cs", &format!("{program_name}.r1cs")]);
    c.args(["--abi-spec", &format!("{program_name}.abi.json")]);

    execute_command(&mut c, "compile");
}

/// Run setup for Zokrates program.
fn setup(program_name: &str) {
    println!("> Set up for {program_name}");

    let mut c = Command::new("zokrates");
    c.arg("setup");
    c.args(["-i", &format!("{program_name}.out")]);
    c.args(["--proving-scheme", "g16"]);
    c.args(["-p", &format!("{program_name}.proving.key")]);
    c.args(["-v", &format!("{program_name}.verification.key")]);
    // Proving key is 'sent' to prover.

    execute_command(&mut c, "setup");
}

/// Extract witness from execution_name.json.
fn extract_witness(execution_name: &str) -> HashMap<String, serde_json::Value> {
    let witness_json_path = format!("{execution_name}.json");
    let witness_json = fs::read_to_string(witness_json_path).expect("could not read witness json");
    let witness: HashMap<String, serde_json::Value> =
        serde_json::from_str(&witness_json).expect("could not parse witness json");
    witness
}

/// Execute flexibility program.
fn execute_flexibility(program_name: &str, execution_name: &str, params: Params, data: &Data) {
    println!("> Executing {execution_name}");

    let mut c = Command::new("zokrates");
    c.arg("compute-witness");
    c.arg("--verbose");
    c.arg("--abi");
    c.arg("--stdin");
    c.args(["-i", &format!("{program_name}.out")]);
    c.args(["-o", &format!("{execution_name}.witness")]);
    c.arg("--json"); // Write witness to {execution_name}.json
    c.args(["--abi-spec", &format!("{program_name}.abi.json")]);

    let inputs = generate_inputs_for_flexibility(params, data);
    let inputs_json =
        serde_json::to_string_pretty(&inputs).expect("could not convert inputs to json");
    // eprintln!("Inputs: {inputs_json}");

    execute_command_with_stdin(&mut c, "compute-witness", inputs_json.as_bytes());

    // Print final output
    let witness = extract_witness(execution_name);
    let diff = witness
        .get("~out_0")
        .expect("could not find result difference in witness")
        .as_str()
        .expect("could not parse result difference as string")
        .to_string();
    let sign = witness
        .get("~out_1")
        .expect("could not find result sign in witness")
        .as_str()
        .expect("could not parse result sign as string");
    let sign = if sign == "1" {
        "+"
    } else if sign == "0" {
        "-"
    } else {
        "(invalid sign!)"
    };
    println!("Result: {}{}", sign, diff);
}

/// Generate Zokrates proof.
fn generate_proof(program_name: &str, execution_name: &str) {
    println!("> Generating proof for {execution_name}");

    let mut c = Command::new("zokrates");
    c.arg("generate-proof");
    c.args(["-i", &format!("{program_name}.out")]);
    c.args(["-p", &format!("{program_name}.proving.key")]);
    c.args(["-w", &format!("{execution_name}.witness")]);
    c.args(["-j", &format!("{execution_name}.proof.json")]);

    execute_command(&mut c, "generate-proof");
}

/// Aggregate signatures using BLS.
///
/// If there are no messages, this returns None.
fn aggregate_signatures(messages: &Vec<SignedMessage>) -> Option<BLSAggregateSignature> {
    println!("> Aggregating signatures");
    let t = Instant::now();

    let signatures = get_bls_poseidon_signatures(&messages);
    eprintln!("Number of signatures to aggregate = {}", signatures.len());

    let aggsig = if signatures.is_empty() {
        None
    } else {
        Some(sign::aggregate_bls_signatures(&signatures))
    };

    println!("| Time to aggregate signatures: {:?}", t.elapsed());
    aggsig
}
