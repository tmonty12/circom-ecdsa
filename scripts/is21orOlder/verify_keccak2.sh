#!/bin/bash

PHASE1=../../circuits/pot21_final.ptau
BUILD_DIR=../../build/keccak2
CIRCUIT_NAME=keccak2
TEST_NAME=input_keccak2

if [ -f "$PHASE1" ]; then
    echo "Found Phase 1 ptau file"
else
    echo "No Phase 1 ptau file found. Exiting..."
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

if [ ! -d "$BUILD_DIR/$TEST_NAME" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR/$TEST_NAME"
fi

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 verify "$BUILD_DIR"/vkey.json "$BUILD_DIR"/"$TEST_NAME"/public.json "$BUILD_DIR"/"$TEST_NAME"/proof.json
end=`date +%s`
echo "DONE ($((end-start))s)"
