#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/native-scenario-tests.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
scenario=native_defra_signing
unset NATIVE_STACK_CURVE
cat > "$work/command" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f $COUNT ]]; then count=$(cat "$COUNT"); fi
count=$((count + 1))
printf '%s\n' "$count" > "$COUNT"
[[ $1 == native_defra_signing && $2 == --exact ]]
if [[ $MODE == success || ($count == 2 && ($MODE == collision || $MODE == follow-on || $MODE == full-backtrace)) ]]; then
    echo 'running 1 test'
    echo 'test native_defra_signing ... ok'
    echo 'test result: ok. 1 passed; 0 failed; 0 ignored;'
    exit 0
fi
for node in 0 1 2 3; do
    mkdir -p "$VERA_E2E_DIR/fresh/node$node/logs"
    : > "$VERA_E2E_DIR/fresh/node$node/logs/stdout.log"
    : > "$VERA_E2E_DIR/fresh/node$node/logs/stderr.log"
done
if [[ $MODE == wrong-order ]]; then
    echo 'ERROR vera_node::node: RPC server stopped unexpectedly' >> "$VERA_E2E_DIR/fresh/node0/logs/stdout.log"
fi
if [[ $MODE != timeout && $MODE != stale ]]; then
    echo '2026-10-05T20:40:27Z ERROR vera_jsonrpc::server: Failed to build JSON-RPC server error=Address already in use (os error 48)' \
        >> "$VERA_E2E_DIR/fresh/node0/logs/stdout.log"
fi
if [[ $MODE == follow-on ]]; then
    echo 'ERROR vera_node::node: RPC server stopped unexpectedly' >> "$VERA_E2E_DIR/fresh/node0/logs/stdout.log"
fi
if [[ $MODE == wrong-node ]]; then
    echo 'ERROR vera_node::node: RPC server stopped unexpectedly' >> "$VERA_E2E_DIR/fresh/node1/logs/stdout.log"
fi
if [[ $MODE == product-panic ]]; then
    echo "thread 'worker' (41) panicked at node.rs:1:1: assertion failed" \
        >> "$VERA_E2E_DIR/fresh/node1/logs/stderr.log"
fi
if [[ $MODE == product-error ]]; then
    echo 'ERROR vera_node: database corruption' >> "$VERA_E2E_DIR/fresh/node1/logs/stdout.log"
fi
if [[ $MODE == missing-log ]]; then rm "$VERA_E2E_DIR/fresh/node3/logs/stderr.log"; fi
if [[ $MODE == assertion ]]; then
    echo "thread 'native_defra_signing' (42) panicked at fixture.rs:1:1:"
    echo 'assertion failed: verified_signature'
else
    echo "thread 'native_defra_signing' (42) panicked at bin/orbis-node/tests/native_startup.rs:299:55:"
    echo 'called `Result::unwrap()` on an `Err` value: timeout (30s) waiting for 4 nodes to become healthy'
fi
if [[ $MODE == full-backtrace ]]; then echo '  5: std::panic::catch_unwind'; fi
echo 'running 1 test'
echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored;'
if [[ $MODE == command-failure ]]; then exit 127; fi
exit 101
MOCK
chmod +x "$work/command"

check() {
    local mode=$1 expected_exit=$2 expected_attempts=$3 result=0
    local evidence="$work/$mode"
    mkdir "$evidence"
    if [[ $mode == stale ]]; then
        mkdir -p "$evidence/clusters/old/node0/logs"
        echo 'ERROR vera_jsonrpc::server: Failed to build JSON-RPC server error=Address already in use' \
            > "$evidence/clusters/old/node0/logs/stdout.log"
    fi
    MODE=$mode COUNT="$evidence/count" bash "$scripts/run-native-scenario.sh" \
        "$evidence" "$scenario" "$work/command" "$scenario" --exact > "$evidence/runner.log" 2>&1 || result=$?
    [[ $result == "$expected_exit" ]]
    [[ $(cat "$evidence/count") == "$expected_attempts" ]]
    local attempt dir
    for ((attempt=1; attempt<=expected_attempts; attempt++)); do
        dir="$evidence/scenarios/$scenario/attempt-$attempt"
        [[ -s $dir/command.log && -f $dir/exit-code && $(cat "$dir/tee-exit-code") == 0 ]]
    done
    if [[ $expected_attempts == 2 ]]; then
        [[ $(cat "$evidence/scenarios/$scenario/attempt-1/exit-code") == 101 ]]
        [[ $(cat "$evidence/scenarios/$scenario/attempt-2/exit-code") == "$expected_exit" ]]
        [[ -s $evidence/scenarios/$scenario/retry.log ]]
    fi
    [[ ! -e $evidence/scenarios/$scenario/attempt-3 ]]
    printf 'PASS %s\n' "$mode"
}
check success 0 1
check collision 0 2
check follow-on 0 2
check full-backtrace 0 2
check wrong-node 101 1
check wrong-order 101 1
check stale 101 1
check timeout 101 1
check assertion 101 1
check product-panic 101 1
check product-error 101 1
check missing-log 101 1
check command-failure 127 1
check repeated-collision 101 2

mkdir "$work/tools" "$work/logging-failure"
cat > "$work/tools/tee" <<'MOCK'
#!/usr/bin/env bash
cat >/dev/null
exit 73
MOCK
chmod +x "$work/tools/tee"
result=0
PATH="$work/tools:$PATH" MODE=collision COUNT="$work/logging-failure/count" \
    bash "$scripts/run-native-scenario.sh" "$work/logging-failure" "$scenario" \
    "$work/command" "$scenario" --exact > "$work/logging-failure/runner.log" 2>&1 || result=$?
[[ $result == 73 && $(cat "$work/logging-failure/count") == 1 ]]
[[ $(cat "$work/logging-failure/scenarios/$scenario/attempt-1/exit-code") == 101 ]]
[[ $(cat "$work/logging-failure/scenarios/$scenario/attempt-1/tee-exit-code") == 73 ]]
printf 'PASS logging-failure\n'

# A curve labels evidence only; the command and retry classifier still see the
# original scenario name. Both curves can safely share one evidence root.
mkdir "$work/curves"
for curve in bls12-381 jubjub; do
    NATIVE_STACK_CURVE="$curve" MODE=collision COUNT="$work/curves/$curve-count" \
        bash "$scripts/run-native-scenario.sh" "$work/curves" "$scenario" \
        "$work/command" "$scenario" --exact > "$work/curves/$curve.log" 2>&1
    dir="$work/curves/scenarios/$curve-$scenario"
    [[ $(cat "$work/curves/$curve-count") == 2 ]]
    [[ $(cat "$dir/attempt-1/exit-code") == 101 ]]
    [[ $(cat "$dir/attempt-2/exit-code") == 0 && -s $dir/retry.log ]]
    [[ ! -e $work/curves/scenarios/$scenario ]]
    printf 'PASS curve-%s\n' "$curve"
done
result=0
NATIVE_STACK_CURVE=unsupported MODE=success COUNT="$work/invalid-curve-count" \
    bash "$scripts/run-native-scenario.sh" "$work/invalid-curve" "$scenario" \
    "$work/command" "$scenario" --exact > "$work/invalid-curve.log" 2>&1 || result=$?
[[ $result == 2 && ! -e $work/invalid-curve-count && ! -e $work/invalid-curve ]]
printf 'PASS invalid-curve\n'

# The existing CI shell check also exercises curve selection and binary staging.
bash "$scripts/test-native-stack-driver.sh"
