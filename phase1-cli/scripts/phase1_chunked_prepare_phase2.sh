#!/bin/bash -e

rm -f challenge* response* new_challenge* new_response* new_new_challenge_* processed* initial_ceremony* response_list* combined* seed* chunk* phase1

# export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=$1
POWER=20
BATCH=524288
CHUNK_SIZE=524288
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

phase1_1="cargo run --release --bin phase1 --features cli -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed1 --proving-system $PROVING_SYSTEM"
phase1_2="cargo run --release --bin phase1 --features cli -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed2 --proving-system $PROVING_SYSTEM"
phase1_combine="cargo run --release --bin phase1 --features cli -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --proving-system $PROVING_SYSTEM"
phase1_full="cargo run --release --bin phase1 --features cli -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --proving-system $PROVING_SYSTEM"
prepare_phase2="cargo run --release --bin prepare_phase2 --features cli -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --proving-system $PROVING_SYSTEM"

####### Phase 1

for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname challenge_$i --response-fname response_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --response-fname response_$i --new-challenge-fname new_challenge_$i
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname new_challenge_$i --response-fname new_response_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_$i --response-fname new_response_$i --new-challenge-fname new_new_challenge_$i
  rm challenge_$i new_challenge_$i new_new_challenge_$i # no longer needed
  echo new_response_$i >> response_list
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname challenge_$i --response-fname response_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --response-fname response_$i --new-challenge-fname new_challenge_$i
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname new_challenge_$i --response-fname new_response_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_$i --response-fname new_response_$i --new-challenge-fname new_new_challenge_$i
  rm challenge_$i new_challenge_$i new_new_challenge_$i # no longer needed
  echo new_response_$i >> response_list
done

$phase1_combine combine --response-list-fname response_list --combined-fname combined
$phase1_full beacon --challenge-fname combined --response-fname response_beacon --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$phase1_full verify-and-transform-pok-and-correctness --challenge-fname combined --response-fname response_beacon --new-challenge-fname response_beacon_new_challenge
$phase1_full verify-and-transform-ratios --response-fname response_beacon_new_challenge

echo "Running prepare phase2..."
$prepare_phase2 --phase2-fname phase1 --response-fname response_beacon --phase2-size $POWER

echo "Done!"
