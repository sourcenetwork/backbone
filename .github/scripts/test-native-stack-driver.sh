#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
real_git=$(command -v git)
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

for runtime in vera orbis; do
    cp "$work/repo/backbone.toml" "$work/backbone.toml.saved"
    python3 - "$work/repo/backbone.toml" "$runtime" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
name = 'vera-native' if sys.argv[2] == 'vera' else 'node-integration'
digest = ('1' if sys.argv[2] == 'vera' else '2') * 64
old = 'ghcr.io/sourcenetwork/orbis-rs/' + name + '@sha256:' + digest
text = p.read_text()
assert text.count(old) == 1
p.write_text(text.replace(old, 'ghcr.io/sourcenetwork/orbis-rs/' + name + ':latest'))
PY
    result=0
    : > "$work/mutable-$runtime.trace"
    PATH="$work/tools:$PATH" MOCK_TRACE="$work/mutable-$runtime.trace" MOCK_FORBIDDEN=none \
        GITHUB_ENV="$work/mutable-$runtime.env" CARGO_TARGET_DIR="$work/target-mutable-$runtime" \
        bash "$work/repo/.github/scripts/test-native-stack.sh" > "$work/mutable-$runtime.log" 2>&1 || result=$?
    [[ $result -eq 1 ]]
    ! grep -q '^compile ' "$work/mutable-$runtime.trace"
    expected=Vera
    [[ $runtime != orbis ]] || expected=Orbis
    grep -Fxq "Expected immutable $expected image digest" "$work/mutable-$runtime.log"
    cp "$work/backbone.toml.saved" "$work/repo/backbone.toml"
    printf 'PASS native-stack-driver rejects=mutable-%s-image\n' "$runtime"
done

for failure in sdk client_tree unsafe diagnostic runtime runtime_rename ignored; do
    case "$failure" in
        sdk) variable=MOCK_SDK_MISMATCH ;;
        client_tree) variable=MOCK_CLIENT_TREE_MISMATCH ;;
        unsafe) variable=MOCK_UNSAFE_IMAGE ;;
        diagnostic) variable=MOCK_DIAGNOSTIC_IMAGE ;;
        runtime) variable=MOCK_RUNTIME_CHANGE ;;
        runtime_rename) variable=MOCK_RUNTIME_RENAME ;;
        ignored) variable=MOCK_IGNORED_SCENARIO ;;
    esac
    result=0
    : > "$work/$failure.trace"
    MOCK_SDK_MISMATCH= MOCK_UNSAFE_IMAGE= \
        PATH="$work/tools:$PATH" MOCK_TRACE="$work/$failure.trace" MOCK_FORBIDDEN=none \
        MOCK_REAL_GIT="$real_git" \
        GITHUB_ENV="$work/$failure.env" CARGO_TARGET_DIR="$work/target-$failure" \
        env "$variable=1" \
        bash "$work/repo/.github/scripts/test-native-stack.sh" > "$work/$failure.log" 2>&1 || result=$?
    [[ $result -ne 0 ]]
    if [[ $failure == runtime_rename ]]; then
        [[ $result -eq 1 ]]
        grep -Fxq 'Orbis fixture changes runtime source: bin/orbis-node/src/runtime/mod.rs' "$work/$failure.log"
    fi
    [[ $failure == ignored ]] || ! grep -q '^compile ' "$work/$failure.trace"
    if [[ $failure == client_tree ]]; then
        [[ $result -eq 1 ]]
        grep -q '^Pinned proof client differs from the qualification source$' "$work/$failure.log"
        ! grep -Eq '^pull (bls12-381|jubjub)$' "$work/$failure.trace"
    fi
    if [[ $failure == diagnostic ]]; then
        [[ $result -eq 1 ]]
        grep -Fxq 'Normal Orbis runtime image enables diagnostic features' "$work/$failure.log"
    fi
    printf 'PASS native-stack-driver rejects=%s\n' "$failure"
done
