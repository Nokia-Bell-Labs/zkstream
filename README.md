# zkStream: a Framework for Trustworthy Stream Processing

This repository contains the code that is published as the artifact for [the paper titled "zkStream: a Framework for Trustworthy Stream Processing"](https://dl.acm.org/doi/10.1145/3652892.3700763). The paper was published at the [25th ACM/IFIP International Middleware Conference (Middleware 2024)](https://middleware-conf.github.io/2024/).

> In stream processing, managing sensitive information in a timely manner while ensuring trust remains a significant challenge. When parties without a priori trust cooperate to execute a streaming application, it is difficult to ensure that sensitive data is kept confidential while guaranteeing that every party executes their code honestly.
>
> This paper presents zkStream: a framework that leverages signatures and zero-knowledge proofs (ZKP) to add trust to streaming applications that run in the edge cloud, guaranteeing data confidentiality, provenance, and computational integrity. We introduce two optimizations to minimize the computational overhead associated with ZKPs, making our framework suitable for real-world applications.
>
> We validated our solution with existing benchmarks for streaming applications. Our method achieves an end-to-end latency that is between 6.5 and 15× faster than a naive implementation, demonstrating its potential for industrial adoption where trust is critical.

This repository contains the framework (including optimizations), our library of "zero-knowledge gadgets", and the benchmarks.

## Repository structure

The tag `initial-import` contains the code exactly as it was used to run the benchmarks of the paper. The tag `1.0.0` refers to a cleaned-up version of that code (merging some common code between projects, cleaning up the code, adding copyright information). The `master` branch contains the latest version, and is recommended if you want to build on this project.

The repository contains the following folders:

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

`cargo run -- --help` will show the available options, e.g. to use other hash functions, optimizations, input sizes, etc.
In particular, the option `--variant` or `-v` allows you to choose between: poseidon, poseidon.nosig (default), poseidon.nosig.bls, sha256, sha256.nosig, sha256.nosig.bls. The naive version in the paper is variant `poseidon`, the first optimization is `poseidon.nosig`, and the second optimization is `poseidon.nosig.bls`. Note that the variants using sha256 need > 16 GB memory for compilation. Options should be provided after `--`, e.g. `cargo run -- -v poseidon.nosig`.

### 2. Energy flexibility use case

The energy flexibility use case is a benchmark that calculates the increase or decrease in energy consumption of a sensor.
You can run it with the following command:

```bash
cd energy/zokrates-flexibility
cargo run --release
```

This will compile the Zokrates code, run it and generate a proof.

Again, `cargo run -- --help` will show the available options, e.g. to use other hash functions, optimizations, input sizes, etc. There are three variants: poseidon (= naive version in the paper), poseidon.nosig (= first optimization), and poseidon.nosig.bls (= second optimization).

### 3. NEXMark benchmark

The NEXMark benchmark is a benchmark that simulates an auction system. It consists of several queries.
To run the NEXMark benchmark, follow these steps:

```bash
cd nexmark/zokrates-nexmark
cargo run --release -- -p q4
```

You can replace `q4` with any of the queries: `q1`, `q4`, `q5`, `q6`, `q7`.

`cargo run -- --help` will again show the available options. The option `-p` allows you to choose which query to run; `-v` which variant (same as above).

## Limitations

There are some shortcuts and limitations in the current code:

1. As ZoKrates does not support 'private' (secret) outputs, proofs that have private outputs actually return them publicly. This means that, with the given code, the verifier gets access to these secrets! When this happens, this is indicated in the code in a comment. For example, in `energy/zokrates-debs/src/historical.poseidon.zok`, line 33: `// value (private), hashed value (public)` means that the first output should be kept private, while the second one is public. Some other languages than ZoKrates, e.g. RISC-Zero, do not have this limitation: they support private outputs.
2. Leakage profiles may not always be obvious. For example, if the verifier keeps track of subsequent predictions in the DEBS challenge, they may be able to deduce the original input values. Even though theoretically this is part of the allowed leakage profile, it may still be unexpected.
3. In the NEXMark benchmarks, partitioning is not fully checked by the verifier: we check whether all outputs are passed into inputs of the next step, but do not verify whether the partitioning was correct. This is possible by re-executing some of the steps of the prover in the verifier but not implemented.
4. Simulating arithmetic operations in ZKP is slow. Therefore, we have converted floats into integers by multiplying them with 1000, which fits the range defined by the DEBS2014 specification. The verifier must divide by 1000 to get back to the correct values.
5. We assume the public key is unique per (`plug_id`, `household_id`, `house_id`). Each property is represented as an unsigned 32 bit int. To simulate a more realistic setup, the sensor (signer) is not aware of the `house_id`, `household_id`, or `plug_id` as it is identified by a public key. Therefore, we define a device id which is known by the verifier, and can be mapped to the correct `house_id`, `household_id`, or `plug_id`. This additionally implies that the `device_id` uniquely maps to three 32 bit uint properties, which still comfortably fits in a single element (< 254 bits).
6. A salt is split into 6 86-bit fields, similar to [chunking large numeric values in ed25519 where base 85 is used](https://github.com/Electron-Labs/ed25519-circom/blob/c9435c021384a74009c0b2ec2a5e863b2190e63b/circuits/verify.circom#L122). We use 86 bits because a 256 bit salt fits nicely in 6 elements. We are not clear on whether using more bits per element is considered safe.

## License

This project is licensed under the BSD 3-Clause Clear License - see the [LICENSE](LICENSE) file for details.

Patent pending.

This is a proof-of-concept prototype. The code in this project has not been audited. It has not been reviewed for use in production environments.

## Citation

If you build upon this work, you can cite our paper:

```
@inproceedings{10.1145/3652892.3700763,
author = {Swalens, Janwillem and Hoste, Lode and Beni, Emad Heydari and Trappeniers, Lieven},
title = {zkStream: a Framework for Trustworthy Stream Processing},
year = {2024},
isbn = {9798400706233},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3652892.3700763},
doi = {10.1145/3652892.3700763},
booktitle = {Proceedings of the 25th International Middleware Conference},
pages = {252–265},
numpages = {14},
location = {Hong Kong, Hong Kong},
series = {MIDDLEWARE '24}
}
```
