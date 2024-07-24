#!/usr/bin/env bash
# Copyright 2024 Nokia
# Licensed under the BSD 3-Clause Clear License.
# SPDX-License-Identifier: BSD-3-Clause-Clear

# This script runs the benchmark for different variants and window sizes.
# For each variant and window size, it runs the compilation only once and then
# runs the actual execution and verification 30 times.

set -euo pipefail

LOG_FILE="${LOG_FILE:-log}"
VARIANTS="${VARIANTS:-poseidon poseidon.nosig poseidon.nosig.bls}"
WINDOW_SIZES="${WINDOW_SIZES:-1 5 15 30 60}"

for window_size in $WINDOW_SIZES; do
    for variant in $VARIANTS; do
        echo "Variant: $variant; Window size: $window_size; Compilation run" >> $LOG_FILE
        VARIANTS="$variant" WINDOW_SIZES="$window_size" SKIP_EXECUTION=1 SKIP_VERIFICATION=1 ./run.sh
        for i in {1..30}; do
            echo "Variant: $variant; Window size: $window_size; Run $i" >> $LOG_FILE
            VARIANTS="$variant" WINDOW_SIZES="$window_size" SKIP_COMPILATION=1 ./run.sh
        done
    done
done
