#!/bin/bash

PHASE1=../../circuits/pot20_final.ptau
BUILD_DIR=../../build/pubkeygen
CIRCUIT_NAME=pubkeygen

echo "****GENERATING WITNESS FOR SAMPLE INPUT****"
start=`date +%s`
node "$BUILD_DIR"/"$CIRCUIT_NAME"_js/generate_witness.js "$BUILD_DIR"/"$CIRCUIT_NAME"_js/"$CIRCUIT_NAME".wasm input_pubkeygen.json "$BUILD_DIR"/witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 prove "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/witness.wtns "$BUILD_DIR"/proof.json "$BUILD_DIR"/public.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 verify "$BUILD_DIR"/vkey.json "$BUILD_DIR"/public.json "$BUILD_DIR"/proof.json
end=`date +%s`
echo "DONE ($((end-start))s)"
