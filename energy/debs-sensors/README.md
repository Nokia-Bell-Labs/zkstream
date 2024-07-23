# DEBS sensors

This project generates simulated sensor data based on the data from the [DEBS 2014 Grand Challenge][1].

It reads in a CSV file as provided by the DEBS challenge and generates a JSON file containing the
sensor measurements as well as hashes and signatures.

Usage:
    cargo run -- -d ../data.csv -j ../data.json

Note that this may take ~30 minutes to run, as it signs up about 17.000 measurements using several
hashing and signing schemes.

## Data set

We downloaded the data set from https://debs.org/grand-challenges/2014/. This is a 24 GB zip file that extracts to a 136 GB CSV file.
We filtered out the values for plug id 0 in household 0 in house 0. We also only kept the values for the load property (property = 1).
The resulting filed is included here in data.csv. We used the following command:

    # Get load values (property = 1) from plug id = 0; household id = 0; house = 0.
    grep ',1,0,0,0$' sorted.csv > data.csv

[1]: https://debs.org/grand-challenges/2014/
