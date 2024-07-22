mod abi;
mod input;
mod params;
mod proof;
mod verification;

use crate::abi::{Hash, HistoricalResult, HistoricalResultPoseidon, HistoricalResultSHA256};
use crate::input::{
    generate_inputs_for_challenge1, generate_inputs_for_historical, get_bls_poseidon_signatures,
    get_bls_sha256_signatures, HistoricalInputs, HistoricalOutputs,
};
use crate::params::{Bls, Params};
use chrono::Duration;
use clap::Parser;
use datajson::{Data, DataJson, SignedMessage};
use hash_sign::sign::{self, BLSAggregateSignature};
use params::{HashScheme, SigVariant};
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

    /// Variant to run. One of: poseidon.nosig (default), poseidon, sha256.nosig,
    /// sha256, poseidon.nosig.bls, sha256.nosig.bls.
    #[arg(short = 'v', long, default_value_t = String::from("poseidon.nosig"))]
    variant: String,

    /// Window size in minutes.
    /// This determines the number of messages in a slice, e.g. for 15 minutes there
    /// will be max. 180 messages (one every 5 seconds).
    #[arg(short = 'w', long, default_value_t = 15)]
    window_size: usize,

    /// Number of historical days to use.
    #[arg(short = 'H', long, default_value_t = 30)]
    n_historical: usize,

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

    let window_size = cli.window_size;
    let window_duration = Duration::minutes(window_size as i64);
    let n_messages = window_size * 60 / 5; // 5 seconds per message
    let mut n_historical = cli.n_historical;
    println!("> Window size: {} minutes", window_size);
    println!("> Number of messages: {}", n_messages);
    println!("> Number of historical days: {}", n_historical);

    let debug = cli.debug;
    if debug {
        println!("WARNING: do not enable DEBUG for benchmarking!");
    }

    // Select variant.
    println!("> Variant {}", cli.variant);
    let (hash_scheme, sig_variant, bls) = params::parse_variant(&cli.variant);
    let variant = params::variant_to_string(hash_scheme, sig_variant);
    let challenge1_name = format!("challenge1.{variant}");
    let historical_name = format!("historical.{variant}");
    let historical_i_name = |i: usize| format!("{historical_name}-{i}");

    // Parse data.json.
    println!("> Parsing data.json");
    let data_file = fs::read_to_string(data_path).expect("could not read data.json");
    let data_json: DataJson = serde_json::from_str(&data_file).expect("could not parse data JSON");
    let data: Data = datajson::data_from_json(&data_json);
    // eprintln!("Data: {:?}", data);
    if data.historical.len() < n_historical {
        n_historical = data.historical.len();
        println!("WARNING: insufficient historical data, reducing to {n_historical} days");
    }

    let params = Params {
        hash_scheme,
        sig_variant,
        bls,
        window_duration,
        n_messages,
        n_historical,
    };

    // Compile code.
    if !cli.skip_compilation {
        compile(&historical_name, debug, params);
        setup(&historical_name);
        compile(&challenge1_name, debug, params);
        setup(&challenge1_name);
    }

    // Execute programs and generate proofs.
    if !cli.skip_execution {
        // Run program (= compute witnesses).
        let mut historical_outputs = Vec::new();
        for i in 0..n_historical {
            let outputs =
                execute_historical(&historical_name, &historical_i_name(i), params, &data, i);
            historical_outputs.push(outputs);
        }
        execute_challenge1(
            &challenge1_name,
            &challenge1_name,
            params,
            &data,
            &historical_outputs,
        );

        // Generate proofs.
        for i in 0..n_historical {
            generate_proof(&historical_name, &historical_i_name(i));
        }
        generate_proof(&challenge1_name, &challenge1_name);
    }

    // When using BLS, aggregate signatures.
    // Note: we assume everything is signed with the same public key.
    let aggsig = if bls == Bls::Yes {
        let mut messages: Vec<SignedMessage> = Vec::new();
        for i in 0..n_historical {
            let window_start = data.historical[i].start;
            let window_end = data.historical[i].start + window_duration;
            let these_messages = data.historical[i]
                .messages
                .iter()
                .filter(|m| m.timestamp >= window_start && m.timestamp < window_end)
                .cloned()
                .collect::<Vec<_>>();
            messages.extend(these_messages);
        }
        let window_start = data.current.start;
        let window_end = data.current.start + window_duration;
        let these_messages = data
            .current
            .messages
            .iter()
            .filter(|m| m.timestamp >= window_start && m.timestamp < window_end)
            .cloned()
            .collect::<Vec<_>>();
        messages.extend(these_messages);
        aggregate_signatures(&messages, params)
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

    // Replace `N_MESSAGES` and `N_HISTORICAL` with actual values and write to a
    // temporary file.
    let mut program =
        fs::read_to_string(&format!("src/{program_name}.zok")).expect("could not read program");
    program = program.replace(
        "N_MESSAGES = 180;",
        &format!("N_MESSAGES = {};", params.n_messages),
    );
    program = program.replace(
        "N_HISTORICAL = 30;",
        &format!("N_HISTORICAL = {};", params.n_historical),
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

/// Execute historical program.
fn execute_historical(
    program_name: &str,
    execution_name: &str,
    params: Params,
    data: &Data,
    i: usize,
) -> HistoricalOutputs {
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

    let inputs = generate_inputs_for_historical(params, data, i);
    let inputs_json =
        serde_json::to_string_pretty(&inputs).expect("could not convert inputs to json");
    // eprintln!("Inputs: {inputs_json}");

    execute_command_with_stdin(&mut c, "compute-witness", inputs_json.as_bytes());

    // What we need for the next steps:
    // - the actual output (average) = second last output of the program
    // - the hash of the output = last output of the program
    // - the salt used to calculate the hash = one of the inputs
    //
    // We can parse these from the generated JSON witness. This file is a map from
    // variable names to values. Which variable names we need depends on the variant.
    // Note: every time the outputs are changed in the Zokrates code, this need to be updated.

    let witness = extract_witness(execution_name);

    let average = witness
        .get("~out_0")
        .expect("could not find average in witness")
        .as_str()
        .expect("could not parse average as string")
        .to_string();
    println!("Average: {}", average);

    match params.hash_scheme {
        HashScheme::Poseidon => {
            let hash = witness
                .get("~out_1")
                .expect("could not find hash in witness") // Field encoded as string
                .as_str()
                .expect("could not parse hash as string")
                .to_string();
            let salt = match inputs {
                HistoricalInputs::Poseidon(input) => input.outputSalt.clone(),
                HistoricalInputs::PoseidonNoSig(input) => input.outputSalt.clone(),
                _ => panic!("invalid variant"),
            };
            let result = HistoricalResultPoseidon { average, salt };
            (HistoricalResult::Poseidon(result), Hash::Poseidon(hash))
        }
        HashScheme::Sha256 => {
            let hash = vec![
                "~out_1", "~out_2", "~out_3", "~out_4", "~out_5", "~out_6", "~out_7", "~out_8",
            ]
            .iter()
            .map(|k| {
                witness
                    .get(*k)
                    .expect("could not find SHA256 chunk in witness")
                    .as_str()
                    .expect("could not parse SHA256 chunk as string")
                    .to_string()
            })
            .collect::<Vec<_>>(); // Array of hexadecimal strings
            let salt = match inputs {
                HistoricalInputs::Sha256(input) => input.outputSalt.clone(),
                HistoricalInputs::Sha256NoSig(input) => input.outputSalt.clone(),
                _ => panic!("invalid variant"),
            };
            let result = HistoricalResultSHA256 { average, salt };
            (HistoricalResult::Sha256(result), Hash::Sha256(hash))
        }
    }
}

/// Execute challenge1 program.
fn execute_challenge1(
    program_name: &str,
    execution_name: &str,
    params: Params,
    data: &Data,
    historical_outputs: &Vec<HistoricalOutputs>,
) {
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

    let inputs = generate_inputs_for_challenge1(params, data, historical_outputs);
    let inputs_json =
        serde_json::to_string_pretty(&inputs).expect("could not convert inputs to json");
    // eprintln!("Inputs: {inputs_json}");

    execute_command_with_stdin(&mut c, "compute-witness", inputs_json.as_bytes());

    // Print final output
    let witness = extract_witness(execution_name);
    let result = witness
        .get("~out_0")
        .expect("could not find result in witness")
        .as_str()
        .expect("could not parse result as string")
        .to_string();
    println!("Result: {}", result);
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
fn aggregate_signatures(
    messages: &Vec<SignedMessage>,
    params: Params,
) -> Option<BLSAggregateSignature> {
    println!("> Aggregating signatures");
    let t = Instant::now();

    let signatures = match params.hash_scheme {
        HashScheme::Poseidon => get_bls_poseidon_signatures(messages),
        HashScheme::Sha256 => get_bls_sha256_signatures(messages),
    };
    eprintln!("Number of signatures to aggregate = {}", signatures.len());

    let aggsig = if signatures.is_empty() {
        None
    } else {
        Some(sign::aggregate_bls_signatures(&signatures))
    };

    println!("| Time to aggregate signatures: {:?}", t.elapsed());
    aggsig
}
