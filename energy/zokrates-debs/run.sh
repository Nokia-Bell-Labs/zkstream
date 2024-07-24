#!/usr/bin/env bash
# Copyright 2024 Nokia
# Licensed under the BSD 3-Clause Clear License.
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
DEBUG="${DEBUG:-}"
VARIANTS="${VARIANTS:-poseidon.nosig poseidon sha256.nosig sha256 poseidon.nosig.bls sha256.nosig.bls}"
WINDOW_SIZES="${WINDOW_SIZES:-15}"
N_HISTORICAL="${N_HISTORICAL:-30}"

# Append all output (stdout and stderr) of the commands below to the log file.
exec &> >(tee -a $LOG_FILE)

echo "Hostname: $(hostname)"
echo "Time: $(date -Iseconds)"
echo "Zokrates version: $(zokrates --version)"
echo "Git revision: $(git describe --always)"
echo "VARIANTS=$VARIANTS"
echo "WINDOW_SIZES=$WINDOW_SIZES"
echo "N_HISTORICAL=$N_HISTORICAL"
echo "LOG_FILE=$LOG_FILE"
echo "DEBUG=$DEBUG"

if [ -n "$DEBUG" ]; then
    DEBUG_FLAG="--debug"
    echo "Warning: do not enable DEBUG for benchmarking!"
else
    DEBUG_FLAG=""
fi

if [ -n "${SKIP_COMPILATION:-}" ]; then
    SKIP_COMPILATION_FLAG="--skip-compilation"
else
    SKIP_COMPILATION_FLAG=""
fi

if [ -n "${SKIP_EXECUTION:-}" ]; then
    SKIP_EXECUTION_FLAG="--skip-execution"
else
    SKIP_EXECUTION_FLAG=""
fi

if [ -n "${SKIP_VERIFICATION:-}" ]; then
    SKIP_VERIFICATION_FLAG="--skip-verification"
else
    SKIP_VERIFICATION_FLAG=""
fi

for window in $WINDOW_SIZES; do
    echo "Window size $window"
    for n_historical in $N_HISTORICAL; do
        echo "Number of historical days $n_historical"
        for variant in $VARIANTS; do
            echo "Variant $variant"
            cargo run -- -d ../data.json -v $variant -w $window -H $n_historical $DEBUG_FLAG $SKIP_COMPILATION_FLAG $SKIP_EXECUTION_FLAG $SKIP_VERIFICATION_FLAG
        done
    done
done
