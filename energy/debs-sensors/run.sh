#!/usr/bin/env bash

set -euo pipefail

cargo run -- -d ../data.csv -j ../data.json
