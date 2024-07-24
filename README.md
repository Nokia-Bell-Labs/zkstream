# zkStream: a Framework for Trustworthy Stream Processing

This repository contains the code that is published as part of the artifact evaluation for the paper titled "zkStream: a Framework for Trustworthy Stream Processing".

The paper appears at (TODO).

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

## Dependencies

- Zokrates
- Rust

Installation instructions for Zokrates can be found at
https://zokrates.github.io/gettingstarted.html. Make sure the `zokrates` command
is available in `$PATH`.

## License

This project is licensed under the BSD 3-Clause Clear License - see the [LICENSE](LICENSE) file for details.

Patent pending.

This is a proof-of-concept prototype. The code in this project has not been audited. It has not been reviewed for use in production environments.
