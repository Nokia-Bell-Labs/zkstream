#!/usr/bin/env bash
# Copyright 2024 Nokia
# Licensed under the BSD 3-Clause Clear License.
# SPDX-License-Identifier: BSD-3-Clause-Clear

set -euxo pipefail

if [ -n "${DEBUG:-}" ]; then
    DEBUG_FLAG="--debug"
else
    DEBUG_FLAG=""
fi

zokrates compile -i gadgets.zok $DEBUG_FLAG
zokrates compute-witness
zokrates generate-proof
cat proof.json
