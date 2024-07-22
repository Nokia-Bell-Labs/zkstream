#!/usr/bin/env bash

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
DEBUG="${DEBUG:-}"
PROGRAMS="${PROGRAMS:-q1 q4 q5 q6 q7}"
VARIANTS="${VARIANTS:-poseidon.nosig poseidon.nosig.bls poseidon}"

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

for program in $PROGRAMS; do
    echo "Program $program"
    for variant in $VARIANTS; do
        echo "Variant $variant"
        /usr/bin/time -v cargo run -- -d ../data.json -p $program -v $variant $DEBUG_FLAG $SKIP_COMPILATION_FLAG
    done
done
