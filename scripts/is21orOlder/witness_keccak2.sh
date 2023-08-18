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

echo "****GENERATING WITNESS FOR SAMPLE INPUT****"
start=`date +%s`
node "$BUILD_DIR"/"$CIRCUIT_NAME"_js/generate_witness.js "$BUILD_DIR"/"$CIRCUIT_NAME"_js/"$CIRCUIT_NAME".wasm "./inputs/$TEST_NAME".json "$BUILD_DIR"/"$TEST_NAME"/witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"
