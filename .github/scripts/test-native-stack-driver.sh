#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/native-stack-driver-tests.XXXXXX")
trap 'status=$?; if [[ $status == 0 ]]; then rm -rf -- "$work"; else printf "Mock failure evidence: %s\n" "$work" >&2; fi' EXIT
mkdir -p "$work/tools" "$work/repo/.github/scripts" "$work/repo/.github/docker"
cp "$scripts/test-native-stack.sh" "$scripts/run-native-scenario.sh" \
    "$scripts/native-bind-race.py" "$scripts/native-acp-override.py" "$work/repo/.github/scripts/"
cp "$scripts/../docker/native-stack.Dockerfile" "$work/repo/.github/docker/"
cp "$scripts/fixtures/native-stack/backbone.toml" "$work/repo/backbone.toml"

# Tool doubles exercise dependency leaks, immutable image content, early pin
# rejection and propagation of the shared runner's original failure status.
cp "$scripts/fixtures/native-stack/mock.py" "$work/tools/mock"
chmod +x "$work/tools/mock"
for tool in git cargo rustc docker native-shared-suite; do ln -s mock "$work/tools/$tool"; done
for mode in none bls12-381 jubjub pin-mismatch old-orbis bad-image shared-failure; do
    trace="$work/$mode.trace"
    result=0
    PATH="$work/tools:$PATH" MOCK_TRACE="$trace" MOCK_MODE="$mode" \
        MOCK_DOCKER_STATE="$work/images-$mode" CARGO_TARGET_DIR="$work/target-$mode" \
        CARGO_PROFILE_RELEASE_LTO=false CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS=fixture \
        RUSTFLAGS=fixture CARGO_ENCODED_RUSTFLAGS=fixture CARGO_BUILD_RUSTFLAGS=fixture \
        CARGO_INCREMENTAL=1 CARGO_BUILD_INCREMENTAL=1 CARGO_BUILD_TARGET=fixture \
        RUSTC=fixture RUSTUP_TOOLCHAIN=fixture CARGO_BUILD_RUSTC_WRAPPER=fixture \
        VERA_E2E_DEADLINE_SCALE=8 ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB=32 \
        ORBIS_LOCAL_STORAGE_KDF_T_COST=1 \
        bash "$work/repo/.github/scripts/test-native-stack.sh" > "$work/$mode.log" 2>&1 || result=$?
    run=$(find "$work/repo/target/native-stack-runs" -mindepth 1 -maxdepth 1 -type d)
    [[ $(printf '%s\n' "$run" | wc -l | tr -d ' ') == 1 ]]
    python3 "$scripts/fixtures/native-stack/check.py" "$trace" "$mode" "$result" "$run"
    if grep -q SECRET_PRIVATE_BUILD_DIAGNOSTIC "$work/$mode.log"; then exit 1; fi
    mv "$run" "$work/evidence-$mode"
    printf 'PASS native-stack-driver %s\n' "$mode"
done
