#!/usr/bin/env bash

set -euo pipefail

cargo run -- -i ../data/data.json -o ../data.json
