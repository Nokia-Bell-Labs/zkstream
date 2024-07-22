//! This file contains the commands to call ZoKrates.

use crate::abi::Abi;
use crate::input::get_bls_poseidon_signatures;
use crate::params::Params;
use datajson::SignedMessageJson;
use hash_sign::sign::{self, BLSAggregateSignature};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

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
pub fn compile(program_name: &str, debug: bool, _params: Params, n_messages: usize) {
    println!("> Compiling {program_name}");

    // Replace constants with actual values and write to a temporary file.
    let mut program =
        fs::read_to_string(&format!("src/{program_name}.zok")).expect("could not read program");
    program = program.replace(
        "N_MESSAGES = 100;",
        &format!("N_MESSAGES = {};", n_messages),
    );
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
pub fn setup(program_name: &str) {
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

/// Execute program, generating the witness.
pub fn compute_witness(
    program_name: &str,
    execution_name: &str,
    inputs: Abi,
) -> Vec<serde_json::Value> {
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

    let inputs_json =
        serde_json::to_string_pretty(&inputs).expect("could not convert inputs to json");
    // eprintln!("Inputs: {inputs_json}");

    execute_command_with_stdin(&mut c, "compute-witness", inputs_json.as_bytes());

    /// From a string like `~out_XX`, extract the number `XX`.
    fn extract_number(s: &str) -> usize {
        s[5..].parse().expect("could not parse number")
    }

    // Print final outputs. These are prefixed with ~out_.
    let witness = extract_witness(execution_name);
    // From witness, filter for keys prefixed with ~out_, then sort on the number.
    let mut outputs_with_key = witness
        .into_iter()
        .filter(|(k, _)| k.starts_with("~out_"))
        .map(|(k, v)| (extract_number(&k), v))
        .collect::<Vec<_>>();
    outputs_with_key.sort_by_key(|(n, _)| *n);
    for (key, value) in &outputs_with_key {
        println!("Output {key}: {value}");
    }

    // We assume the keys will always be consecutive and starting at 0, so we
    // can leave them out.
    let outputs = outputs_with_key.into_iter().map(|(_, v)| v).collect();
    outputs
}

/// Generate Zokrates proof.
pub fn generate_proof(program_name: &str, execution_name: &str) {
    println!("> Generating proof for {execution_name}");

    let mut c = Command::new("zokrates");
    c.arg("generate-proof");
    c.args(["-i", &format!("{program_name}.out")]);
    c.args(["-p", &format!("{program_name}.proving.key")]);
    c.args(["-w", &format!("{execution_name}.witness")]);
    c.args(["-j", &format!("{execution_name}.proof.json")]);

    execute_command(&mut c, "generate-proof");
}

/// Verify proof.
pub fn verify_proof(program_name: &str, execution_name: &str) {
    println!("> Verifying proof for {execution_name}");

    let mut c = Command::new("zokrates");
    c.arg("verify");
    c.args(["-v", &format!("{program_name}.verification.key")]);
    c.args(["-j", &format!("{execution_name}.proof.json")]);

    execute_command(&mut c, "verify");
}

/// Open proof file from `execution_name.proof.json` and parse it as JSON.
pub(crate) fn open_proof_file(execution_name: &str) -> serde_json::Value {
    let proof_path = PathBuf::from(&format!("{}.proof.json", execution_name));
    let proof_file = fs::read_to_string(proof_path).expect("could not read proof file");
    let proof: serde_json::Value =
        serde_json::from_str(&proof_file).expect("could not parse proof file as JSON");
    proof
}

/// Aggregate signatures using BLS.
///
/// If there are no messages, this returns None.
pub fn aggregate_bls_signatures(
    messages: &Vec<SignedMessageJson>,
) -> Option<BLSAggregateSignature> {
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
