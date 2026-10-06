#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 EVIDENCE_DIR SCENARIO COMMAND [ARG ...]" >&2
    exit 2
fi
root=$1
scenario=$2
shift 2
case "$scenario" in
    native_startup_registers_and_preserves_identity_on_restart|native_defra_signing|native_distributed_threshold_workflows|native_pet_threshold_workflows) ;;
    *) echo "Unknown native scenario: $scenario" >&2; exit 2 ;;
esac
scripts=$(cd "$(dirname "$0")" && pwd)
case "${NATIVE_STACK_CURVE:-}" in
    ""|bls12-381|jubjub) ;;
    *) echo "Unknown native curve: $NATIVE_STACK_CURVE" >&2; exit 2 ;;
esac
scenario_dir="$root/scenarios/${NATIVE_STACK_CURVE:+$NATIVE_STACK_CURVE-}$scenario"
mkdir -p "$scenario_dir"

for attempt in 1 2; do
    attempt_dir="$scenario_dir/attempt-$attempt"
    mkdir "$attempt_dir"
    mkdir "$attempt_dir/clusters" "$attempt_dir/orbis-clusters"
    # Preserve both statuses: a failed evidence writer must never allow a retry.
    set +e
    VERA_E2E_DIR="$attempt_dir/clusters" ORBIS_NATIVE_E2E_DIR="$attempt_dir/orbis-clusters" \
        "$@" 2>&1 | tee "$attempt_dir/command.log"
    statuses=("${PIPESTATUS[@]}")
    set -e
    printf '%s\n' "${statuses[0]}" > "$attempt_dir/exit-code"
    printf '%s\n' "${statuses[1]}" > "$attempt_dir/tee-exit-code"
    if [[ ${statuses[1]} -ne 0 ]]; then
        exit "${statuses[1]}"
    fi
    if [[ ${statuses[0]} -eq 0 ]]; then
        exit 0
    fi
    if [[ $attempt -eq 1 && ${statuses[0]} -eq 101 ]] &&
        python3 "$scripts/native-bind-race.py" "$attempt_dir" "$scenario"; then
        printf 'Retrying %s once after a confirmed startup RPC bind collision; attempt 1 exited 101.\n' \
            "$scenario" | tee "$scenario_dir/retry.log"
    else
        exit "${statuses[0]}"
    fi
done
