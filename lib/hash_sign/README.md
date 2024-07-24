# hash-sign

This library contains several functions to hash and sign data.

The library supports the following hash functions (with and without salt):

- SHA256
- Poseidon

and the following signature schemes:

- ECDSA
- EdDSA
- BLS

Messages that are hashed/signed should implement the `SerializableMessage` trait. An example implementation for a simple message (with as payload a single `u64`) is provided in the `message` module.

Furthermore, it contains some utility functions to convert between several data types (e.g. BigInt <-> field element <-> decimal string <-> u64 <-> bytes <-> JSON number).
