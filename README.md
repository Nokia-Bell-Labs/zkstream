# zkStream: a Framework for Trustworthy Stream Processing

This repository contains the code that is published as part of the artifact evaluation for the paper titled "zkStream: a Framework for Trustworthy Stream Processing".

The paper appears at the [25th ACM/IFIP International Middleware Conference (Middleware 2024)](https://middleware-conf.github.io/2024/) on December 2-6, 2024.

## Repository structure

- `aggsigs`: a wrapper around the [BLST library][blst] to preven the rogue public-key attack.
- `lib`:
  - `hash_sign`: a library to hash and sign data using several hash functions (SHA256, Poseidon) and signature schemes (ECDSA, EdDSA, BLS).
- `energy`: code for the energy use cases (benchmark 1 and 2).
  - `energy/debs-sensors`: code to parse the sensor data from [the DEBS challenge][debs] from CSV and convert it to JSON. It also add hashes and signatures using several schemes.
  - `energy/debs-datajson`: code to parse the JSON file generated in the previous step.
  - `energy/zokrates-debs`: Zokrates implementation of the DEBS challenge (benchmark 1).
  - `energy/zokrates-flexibility`: Zokrates implementation of the energy flexibility use case (benchmark 2).
- `nexmark`: code for the NEXMark benchmark (benchmark 3).
  - `nexmark/data`: input data to the NEXMark benchmarks.
  - `nexmark/nexmark-sensors`: code to parse the data from [NEXMark benchmark][nexmark], convert it to JSON, and add hashes and signatures using several schemes.
  - `nexmark/nexmark-datajson`: code to parse the JSON file generated in the previous step.
  - `nexmark/zokrates-nexmark`: Zokrates implementation of the NEXMark benchmarks.
- `zkgadgets`: a collection of "zero-knowledge gadgets" for the [ZoKrates][zokrates] language.

[blst]: https://github.com/supranational/blst
[debs]: https://debs.org/grand-challenges/2014/
[nexmark]: https://github.com/nexmark/nexmark
[zokrates]: https://zokrates.github.io/

## How to install

The code in this repository requires the following dependencies:

- [Zokrates](https://zokrates.github.io/)
- [Rust](https://www.rust-lang.org/)

There are two ways to install the dependencies: manually or using the Dockerfile.

### 1. Manually

Follow the instructions to install Rust at https://www.rust-lang.org/tools/install.
Then, follow the installation instructions for Zokrates at
https://zokrates.github.io/gettingstarted.html. Make sure the `zokrates` command
is available in `$PATH`.

Typically, the installation process looks like this:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
# Install ZoKrates
curl -LSfs get.zokrat.es | sh
```

### 2. Using the provided Dockerfile

```bash
docker build -t zkstream .
docker run -it zkstream
```

This will build the Docker image, installing all the dependencies and building this repository.
Running the container simply starts a shell session with the code in this repository mounted at `/home/zokrates`.

Note that, to compile the Zokrates code, you will need to have 8 to 16GB of RAM available to the Docker container. (For the variant using SHA256 and signature verification in proof, even more is required.)

## How to run

The code in this repository is organized in three benchmarks: the DEBS challenge, the energy flexibility use case, and the NEXMark benchmark.

### 1. DEBS challenge

The DEBS challenge is a benchmark that predicts the energy consumption of a sensor.
To run the DEBS challenge, follow these steps:

```bash
cd energy/zokrates-debs
cargo run --release
```

This will compile the Zokrates code, run it and generate proofs, for both the historical and current data.

`cargo run -- --help` will show the available options, e.g. to use other hash functions, variants, input sizes, etc.

### 2. Energy flexibility use case

The energy flexibility use case is a benchmark that calculates the increase or decrease in energy consumption of a sensor.
You can run it with the following command:

```bash
cd energy/zokrates-flexibility
cargo run --release
```

This will compile the Zokrates code, run it and generate a proof.

Again, `cargo run -- --help` will show the available options, e.g. to use other hash functions, variants, input sizes, etc.

### 3. NEXMark benchmark

The NEXMark benchmark is a benchmark that simulates an auction system. It consists of several queries.
To run the NEXMark benchmark, follow these steps:

```bash
cd nexmark/zokrates-nexmark
cargo run --release -- -p q4
```

You can replace `q4` with any of the queries: `q1`, `q4`, `q5`, `q6`, `q7`.

`cargo run -- --help` will again show the available options.

## License

This project is licensed under the BSD 3-Clause Clear License - see the [LICENSE](LICENSE) file for details.

Patent pending.

This is a proof-of-concept prototype. The code in this project has not been audited. It has not been reviewed for use in production environments.
