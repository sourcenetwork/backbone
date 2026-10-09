#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/native-stack-driver-tests.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/tools" "$work/repo/.github/scripts"
cp "$scripts/test-native-stack.sh" "$scripts/run-native-scenario.sh" \
    "$scripts/native-bind-race.py" "$work/repo/.github/scripts/"
cp "$scripts/fixtures/native-stack/backbone.toml" "$work/repo/backbone.toml"

# Commands are mocked; the fixture checks immutable runtime image selection.
cp "$scripts/fixtures/native-stack/mock.py" "$work/tools/mock"
chmod +x "$work/tools/mock"
for tool in git cargo rustc docker; do ln -s mock "$work/tools/$tool"; done

for forbidden in none bls12-381 jubjub; do
    evidence_env="$work/$forbidden.env"
    trace="$work/$forbidden.trace"
    result=0
    PATH="$work/tools:$PATH" MOCK_TRACE="$trace" MOCK_FORBIDDEN="$forbidden" \
        GITHUB_ENV="$evidence_env" CARGO_TARGET_DIR="$work/target-$forbidden" \
        CARGO_PROFILE_RELEASE_LTO=false CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS=fixture \
        RUSTFLAGS=fixture CARGO_ENCODED_RUSTFLAGS=fixture CARGO_BUILD_RUSTFLAGS=fixture \
        CARGO_INCREMENTAL=1 CARGO_BUILD_INCREMENTAL=1 CARGO_BUILD_TARGET=fixture \
        ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB=32 ORBIS_LOCAL_STORAGE_KDF_T_COST=1 \
        bash "$work/repo/.github/scripts/test-native-stack.sh" > "$work/$forbidden.log" 2>&1 || result=$?
    run=$(sed -n 's/^NATIVE_STACK_EVIDENCE=//p' "$evidence_env")
    [[ -f $run/vera-Cargo.lock && -f $run/orbis-Cargo.lock ]]
    python3 "$scripts/fixtures/native-stack/check.py" "$trace" "$forbidden" "$result" "$run"
    printf 'PASS native-stack-driver forbidden=%s\n' "$forbidden"
done

for failure in sdk unsafe runtime ignored; do
    case "$failure" in
        sdk) variable=MOCK_SDK_MISMATCH ;;
        unsafe) variable=MOCK_UNSAFE_IMAGE ;;
        runtime) variable=MOCK_RUNTIME_CHANGE ;;
        ignored) variable=MOCK_IGNORED_SCENARIO ;;
    esac
    result=0
    : > "$work/$failure.trace"
    MOCK_SDK_MISMATCH= MOCK_UNSAFE_IMAGE= \
        PATH="$work/tools:$PATH" MOCK_TRACE="$work/$failure.trace" MOCK_FORBIDDEN=none \
        GITHUB_ENV="$work/$failure.env" CARGO_TARGET_DIR="$work/target-$failure" \
        env "$variable=1" \
        bash "$work/repo/.github/scripts/test-native-stack.sh" > "$work/$failure.log" 2>&1 || result=$?
    [[ $result -ne 0 ]]
    [[ $failure == ignored ]] || ! grep -q '^compile ' "$work/$failure.trace"
    printf 'PASS native-stack-driver rejects=%s\n' "$failure"
done
