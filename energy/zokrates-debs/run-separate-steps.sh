#!/usr/bin/env bash
# Copyright 2024 Nokia
# Licensed under the BSD 3-Clause Clear License.
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
DEBUG="${DEBUG:-}"
VARIANTS="${VARIANTS:-poseidon poseidon.only.sig poseidon.only.sig-only-hash poseidon.only.sig-only-verify poseidon.only.hash-hist poseidon.only.predict}"

# Append all output (stdout and stderr) of the commands below to the log file.
exec &> >(tee -a $LOG_FILE)

echo "Hostname: $(hostname)"
echo "Time: $(date -Iseconds)"
echo "Zokrates version: $(zokrates --version)"
echo "Git revision: $(git describe --always)"
echo "VARIANTS=$VARIANTS"
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

if [ -n "${SKIP_VERIFICATION:-}" ]; then
    SKIP_VERIFICATION_FLAG="--skip-verification"
else
    SKIP_VERIFICATION_FLAG=""
fi

for variant in $VARIANTS; do
    echo "Variant $variant"

    cargo run -- -d ../data.json -v poseidon --challenge1-name="challenge1.$variant"
done
