# sensors-rs

This project generates simulated sensor data.

It reads in a JSON file with NEXMark data and generates a JSON file containing the
bids as well as hashes and signatures.

Usage:
    cargo run -- -i ../data/data.json -o ../data.json

This may take ~1 minute to run.
