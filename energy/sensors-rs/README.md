# sensors-rs

This project generates simulated sensor data.

It reads in a CSV file as provided by the DEBS challenge and generates a JSON file containing the
sensor measurements as well as hashes and signatures.

Usage:
    cargo run -- -d ../data.csv -j ../data.json

Note that this may take ~30 minutes to run, as it signs up about 17.000 measurements using several
hashing and signing schemes.
