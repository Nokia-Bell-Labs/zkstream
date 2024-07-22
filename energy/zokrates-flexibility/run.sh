#!/usr/bin/env bash

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
DEBUG="${DEBUG:-}"
VARIANTS="${VARIANTS:-poseidon.nosig poseidon poseidon.nosig.bls}"
N_MESSAGES_BEFORE="${N_MESSAGES_BEFORE:-60}"
N_MESSAGES_AFTER="${N_MESSAGES_AFTER:-30}"

# Append all output (stdout and stderr) of the commands below to the log file.
exec &> >(tee -a $LOG_FILE)

echo "Hostname: $(hostname)"
echo "Time: $(date -Iseconds)"
echo "Zokrates version: $(zokrates --version)"
echo "Git revision: $(git describe --always)"
echo "VARIANTS=$VARIANTS"
echo "N_MESSAGES_BEFORE=$N_MESSAGES_BEFORE"
echo "N_MESSAGES_AFTER=$N_MESSAGES_AFTER"
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

for variant in $VARIANTS; do
    echo "Variant $variant"
    cargo run -- -d ../data.json -v $variant -B $N_MESSAGES_BEFORE -A $N_MESSAGES_AFTER $DEBUG_FLAG $SKIP_COMPILATION_FLAG $SKIP_EXECUTION_FLAG $SKIP_VERIFICATION_FLAG
done
