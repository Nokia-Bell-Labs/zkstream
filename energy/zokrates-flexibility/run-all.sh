#!/usr/bin/env bash
# Copyright 2024 Nokia
# Licensed under the BSD 3-Clause Clear License.
# SPDX-License-Identifier: BSD-3-Clause-Clear

# This script runs the benchmark for different variants.
# For each variant, it runs the compilation only once and then runs the actual
# execution and verification 30 times.

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
VARIANTS="${VARIANTS:-poseidon poseidon.nosig poseidon.nosig.bls}"

for variant in $VARIANTS; do
    echo "Variant: $variant; Compilation run" >> $LOG_FILE
    VARIANTS="$variant" SKIP_EXECUTION=1 SKIP_VERIFICATION=1 ./run.sh
    for i in {1..30}; do
        echo "Variant: $variant; Run $i" >> $LOG_FILE
        VARIANTS="$variant" SKIP_COMPILATION=1 ./run.sh
    done
done
