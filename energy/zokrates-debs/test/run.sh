#!/usr/bin/env bash

set -euo pipefail

echo "Hostname: $(hostname)"
echo "Zokrates version: $(zokrates --version)"
echo "Git revision: $(git describe --always)"

DEBUG_FLAG="--debug"

compile () {
    PROGRAM_NAME="$1"

    echo "Compiling $PROGRAM_NAME"

    # 0. Universal setup
    # if [ "$PROVING_SCHEME" == "marlin" ];
    # then
    #     /usr/bin/time -p zokrates universal-setup \
    #         --proving-scheme "$PROVING_SCHEME" --size 23
    # fi

    # 1. Compile
    /usr/bin/time -p zokrates compile $DEBUG_FLAG \
        -i "$PROGRAM_NAME.zok" -o "$PROGRAM_NAME.out" --r1cs "$PROGRAM_NAME.r1cs" --abi-spec "$PROGRAM_NAME.abi.json"

    # X. Create corresponding .ztf file (readable file with instructions)
    # zokrates inspect --verbose --ztf -i $PROGRAM_NAME

    # 2. Perform the setup phase
    /usr/bin/time -p zokrates setup -i "$PROGRAM_NAME.out" \
        -p "$PROGRAM_NAME.proving.key" -v "$PROGRAM_NAME.verification.key"
    # Proving key is 'sent' to prover.
}

execute () {
    PROGRAM_NAME="$1"
    EXECUTION_NAME="$2"
    INPUTS="$3"

    echo "Executing $EXECUTION_NAME"

    # 3. Execute the program
    /usr/bin/time -p zokrates compute-witness \
        --verbose --abi --stdin \
        -i "$PROGRAM_NAME.out" -o "$EXECUTION_NAME.witness" --abi-spec "$PROGRAM_NAME.abi.json" \
        <<< "$INPUTS"

    # 4. Generate a proof of computation
    /usr/bin/time -p zokrates generate-proof \
        -i "$PROGRAM_NAME.out" -j "$EXECUTION_NAME.proof.json" -p "$PROGRAM_NAME.proving.key" -w "$EXECUTION_NAME.witness"

    # 5. Verify
    zokrates verify \
        -j "$EXECUTION_NAME.proof.json" -v "$PROGRAM_NAME.verification.key"
}

compile "test_eddsa_poseidon"
execute "test_eddsa_poseidon" "test_eddsa_poseidon" "[\"123\"]"
