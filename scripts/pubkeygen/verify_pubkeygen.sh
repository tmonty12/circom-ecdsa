#!/bin/bash

PHASE1=../../circuits/pot20_final.ptau
BUILD_DIR=../../build/pubkeygen
CIRCUIT_NAME=pubkeygen

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 verify "$BUILD_DIR"/vkey.json "$BUILD_DIR"/public.json "$BUILD_DIR"/proof.json
end=`date +%s`
echo "DONE ($((end-start))s)"
