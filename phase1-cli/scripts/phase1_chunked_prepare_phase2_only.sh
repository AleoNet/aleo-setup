#!/bin/bash -e

rm -f phase1 round_1024

# export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=$1
POWER=19
BATCH=262144
CHUNK_SIZE=262144

if [ "$PROVING_SYSTEM" == "groth16" ]; then
  MAX_CHUNK_INDEX=$((4-1)) # we have 4 chunks, since we have a total of 2^11-1 powers
else
  MAX_CHUNK_INDEX=$((2-1)) # we have 2 chunks, since we have a total of 2^11-1 powers
fi
CURVE="bw6"
SEED1=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED1 > seed1
SEED2=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED2 > seed2

function check_hash() {
  test "`xxd -p -c 64 $1.hash`" = "`b2sum $1 | awk '{print $1}'`"
}


prepare_phase2="cargo run --release --bin prepare_phase2 --features cli -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --proving-system $PROVING_SYSTEM"


echo "Running prepare phase2..."
$prepare_phase2 --phase2-fname round_1024 --response-fname ~/round_1024.verified  --phase2-size 19

echo "Done!"
