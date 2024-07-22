#!/usr/bin/env bash

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
