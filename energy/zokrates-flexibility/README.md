# Zokrates implementation of the energy flexibility use case

## Dependencies

- Zokrates
- Rust

Installation instructions for Zokrates can be found at
https://zokrates.github.io/gettingstarted.html. Make sure the `zokrates` command
is available in `$PATH`.

## How to run

You can run the program using the bash script `run.sh`. You can set the
following environment variables to modify its behavior:

- `VARIANTS`: space-separated list of variants of the program to run:
    * `poseidon`: using Poseidon hash and EdDSA signature verification.
    * `poseidon.nosig`: using Poseidon hash and signature verification outside
      proof.
    * `poseidon.nosig.bls`: using Poseidon hash, BLS signature aggregation, and
      signature verification outside proof.
- `N_MESSAGES_BEFORE` and `N_MESSAGES_AFTER`: space-separated list of number of
  messages to include before and after the moment of activation of flexibility.
  Defaults are `60` and `30`.
- `DEBUG`: enable Zokrates debug mode. Note that this will slow down the
  execution significantly. Default is `false`.
- `LOG_FILE`: location of log file to which output will be written. Default is
  `log`.
- `SKIP_COMPILATION`, `SKIP_EXECUTION`, `SKIP_VERIFICATION`: set to `1` to skip
  corresponding step. Default is `0`.

The Rust code in src is used to call and provide the input data in the right
format to the Zokrates programs. It expects a `data.json` file in the folder
above this one, generated using the Rust code in `../debs-sensors`. It parses
the required input data from that JSON file, and converts it to the format
expected by Zokrates.

The `run.sh` script will, for each variant, compile both programs, and execute
the program.

It times compilation, set-up, witness generation, proof generation, and
verification times.
