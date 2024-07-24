#!/usr/bin/env bash
# Copyright 2024 Nokia
# Licensed under the BSD 3-Clause Clear License.
# SPDX-License-Identifier: BSD-3-Clause-Clear

# This script runs the benchmark for different programs and variants.
# For each program and variant, it runs the compilation only once and then runs
# the actual execution and verification 30 times.

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
PROGRAMS="${PROGRAMS:-q1 q4 q5 q6 q7}"
VARIANTS="${VARIANTS:-poseidon.nosig poseidon.nosig.bls poseidon}"

for program in $PROGRAMS; do
    echo "Program: $program" >> $LOG_FILE
    for variant in $VARIANTS; do
        echo "Variant: $variant; Compilation run" >> $LOG_FILE
        PROGRAMS="$program" VARIANTS="$variant" ./run.sh
        for i in {1..30}; do
            echo "Variant: $variant; Run $i" >> $LOG_FILE
            PROGRAMS="$program" VARIANTS="$variant" SKIP_COMPILATION=1 ./run.sh
        done
    done
done
