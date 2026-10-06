#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/backbone-native.XXXXXX")
images=()
cleanup() {
    local result=$? image
    if [[ -n "${RUN:-}" ]]; then
        for repo in vera orbis; do
            if [[ -f "$WORK/$repo/Cargo.lock" ]]; then
                cp "$WORK/$repo/Cargo.lock" "$RUN/$repo-Cargo.lock" || result=1
            fi
        done
        for image in ${images[@]+"${images[@]}"}; do
            docker image rm "$image" >> "$RUN/cleanup.log" 2>&1 || true
        done
    fi
    rm -rf -- "$WORK" || result=1
    exit "$result"
}
trap cleanup EXIT
target_root="${CARGO_TARGET_DIR:-$ROOT/target/native-stack}"
mkdir -p "$target_root" "$ROOT/target/native-stack-runs" "$WORK/bin"
target_root=$(cd "$target_root" && pwd)
# Archive mtimes can predate cached objects from another source root. Isolate
# workspace artifacts instead of relying on timestamps to prove source identity.
export CARGO_TARGET_DIR
CARGO_TARGET_DIR=$(mktemp -d "$target_root/release.XXXXXX")
RUN=$(mktemp -d "$ROOT/target/native-stack-runs/release.XXXXXX")

# Use repository release profiles and production KDF/deadline defaults.
while IFS= read -r variable; do
    case "$variable" in
        CARGO_PROFILE_*|CARGO_TARGET_*_RUSTFLAGS|CARGO_BUILD_RUSTC*|CARGO_BUILD_RUSTDOC*|ORBIS_LOCAL_STORAGE_KDF_*) unset "$variable" ;;
    esac
done < <(compgen -e)
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
    CARGO_INCREMENTAL CARGO_BUILD_INCREMENTAL CARGO_BUILD_TARGET \
    RUSTC RUSTDOC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTUP_TOOLCHAIN \
    VERA_E2E_DEADLINE_SCALE VERAD_BINARY ORBIS_NODE_BINARY
export CARGO_BUILD_JOBS=2 CARGO_TERM_COLOR=never
export RUST_LOG=info,vera_node::tx_gossip=trace RUST_BACKTRACE=1 VERA_E2E_KEEP=1

private_command() {
    local stage=$1 status=0
    shift
    "$@" > "$RUN/$stage.log" 2>&1 || status=$?
    printf 'native-stack stage=%s exit=%d\n' "$stage" "$status"
    if [[ $status -ne 0 ]]; then exit "$status"; fi
}

ref_for() {
    awk -v section="[components.$1]" '
        $0 == section { found=1; next }
        found && /^\[/ { exit }
        found && /^ref = / { split($0, parts, "\""); print parts[2]; exit }
    ' "$ROOT/backbone.toml"
}

checkout() {
    local repo=$1 ref=$2 destination=$3
    [[ "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo "Expected immutable component revision" >&2; return 1; }
    git init -q "$destination"
    git -C "$destination" fetch -q --depth 1 "https://github.com/sourcenetwork/$repo.git" "$ref"
    git -C "$destination" checkout -q --detach FETCH_HEAD
    [[ $(git -C "$destination" rev-parse HEAD) == "$ref" ]]
}

vera_ref=$(ref_for verad)
orbis_ref=$(ref_for orbis-node)
defra_ref=$(ref_for defra)
backbone_ref=$(git -C "$ROOT" rev-parse HEAD)
private_command checkout-vera checkout vera.rs "$vera_ref" "$WORK/vera"
private_command checkout-orbis checkout orbis-rs "$orbis_ref" "$WORK/orbis"
# The shared entrypoint validates the exact ignored nextest selection and phase
# markers. Require it before any build; old host-only Orbis revisions cannot run it.
for path in scripts/test-native-integration.sh scripts/native-vera-ref.py scripts/native_lifecycle_summary.py; do
    [[ -f "$WORK/orbis/$path" ]] || { echo 'Orbis pin lacks the shared native container suite' >&2; exit 1; }
done
if [[ $(python3 "$WORK/orbis/scripts/native-vera-ref.py") != "$vera_ref" ]]; then
    echo 'Orbis SDK revisions do not match the Vera runtime pin' >&2
    exit 1
fi
[[ "$defra_ref" =~ ^[0-9a-f]{40}$ ]] || exit 1
awk -v dependency='git = "https://github.com/sourcenetwork/defradb.rs"' \
    -v revision="rev = \"$defra_ref\"" '
    index($0, dependency) { found=1; if (!index($0, revision)) mismatch=1 }
    END { exit !found || mismatch }
' "$WORK/orbis/bin/orbis-node/Cargo.toml" || exit 1

# The same immutable Backbone source supplies the proof client to the runtime
# and host fixtures. Put the override in the disposable manifest so the shared
# nextest entrypoint sees it too; never alter the developer's source checkout.
mkdir "$WORK/backbone"
git -C "$ROOT" archive "$backbone_ref" | tar -x -C "$WORK/backbone"
python3 "$ROOT/.github/scripts/native-acp-override.py" \
    "$WORK/orbis/Cargo.toml" "$WORK/backbone/crates/acp-light-client"
{
    echo "backbone=$backbone_ref"
    echo "vera=$vera_ref orbis=$orbis_ref defra=$defra_ref"
    echo 'profile=release curves=bls12-381,jubjub default_features=false'
    echo 'kdf_m_kib=262144 kdf_t=3 kdf_p=1 kdf_version=19 deadline_overrides=false'
    rustc +1.98.0 --version --verbose
    shasum -a 256 "$WORK/orbis/Cargo.toml" "$ROOT/.github/docker/native-stack.Dockerfile"
} > "$RUN/provenance.log"
private_command docker-ready docker info
private_command compose-ready docker compose version
private_command nextest-ready cargo +1.98.0 nextest --version

# Images contain only the staged normal/diagnostic executables. The Ubuntu base
# matches the CI host ABI; running --help also rejects missing runtime libraries.
package_image() {
    local label=$1 binary=$2 target=$3 revision=$4 features=$5
    local context="$WORK/images/$label" id expected actual
    mkdir -p "$context"
    cp "$binary" "$context/runtime-binary"
    expected=$(shasum -a 256 "$context/runtime-binary" | awk '{ print $1 }')
    private_command "image-$label" docker build --file "$ROOT/.github/docker/native-stack.Dockerfile" \
        --target "$target" --iidfile "$context/image-id" \
        --label "org.opencontainers.image.revision=$revision" \
        --label "org.sourcenetwork.backbone.revision=$backbone_ref" \
        --label "org.sourcenetwork.native.features=$features" \
        --label "org.sourcenetwork.native.binary-sha256=$expected" "$context"
    id=$(cat "$context/image-id")
    [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
    images+=("$id")
    actual=$(docker run --rm --entrypoint sha256sum "$id" "/usr/local/bin/$target" 2> "$RUN/hash-$label.log")
    if [[ "${actual%% *}" != "$expected" ]]; then
        echo 'Runtime image binary hash differs from staged executable' >&2
        exit 1
    fi
    private_command "smoke-$label" docker run --rm "$id" --help
    printf '%s image=%s binary_sha256=%s source=%s backbone=%s features=%s\n' \
        "$label" "$id" "$expected" "$revision" "$backbone_ref" "$features" >> "$RUN/images.log"
    IMAGE_ID=$id
}

private_command build-verad cargo +1.98.0 build --release --locked -j2 --manifest-path "$WORK/vera/Cargo.toml" \
    -p verad --bin verad
cp "$CARGO_TARGET_DIR/release/verad" "$WORK/bin/verad"
package_image vera "$WORK/bin/verad" verad "$vera_ref" default
export ORBIS_NATIVE_VERA_IMAGE=$IMAGE_ID
for curve in bls12-381 jubjub; do
    features="native,redb,iroh,$curve"
    native=(--manifest-path "$WORK/orbis/Cargo.toml" -p orbis-node --no-default-features)
    # The local proof-client override resolves only this disposable lockfile.
    # Stage the production executable before unsafe/testing feature unification.
    private_command "build-orbis-$curve" cargo +1.98.0 build --release -j2 "${native[@]}" \
        --features "$features" --bin orbis-node
    mkdir -p "$WORK/bin/$curve"
    cp "$CARGO_TARGET_DIR/release/orbis-node" "$WORK/bin/$curve/orbis-node"
    private_command "native-dependencies-$curve" cargo +1.98.0 tree --locked "${native[@]}" \
        --features "$features" --color never --edges normal,build --prefix none
    if grep -Eq '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v' "$RUN/native-dependencies-$curve.log"; then
        echo 'Normal native dependency boundary failed' >&2
        exit 1
    fi
    package_image "orbis-$curve" "$WORK/bin/$curve/orbis-node" orbis-node "$orbis_ref" "$features"
    export ORBIS_NATIVE_IMAGE=$IMAGE_ID

    private_command "build-diagnostic-$curve" cargo +1.98.0 build --release --locked -j2 "${native[@]}" \
        --features "$features,unsafe-testing" --bin orbis-node
    cp "$CARGO_TARGET_DIR/release/orbis-node" "$WORK/bin/$curve/orbis-node-diagnostic"
    private_command "diagnostic-dependencies-$curve" cargo +1.98.0 tree --locked "${native[@]}" \
        --features "$features,unsafe-testing" --color never --edges normal,build --prefix none
    if grep -Eq '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v' "$RUN/diagnostic-dependencies-$curve.log"; then
        echo 'Diagnostic native dependency boundary failed' >&2
        exit 1
    fi
    package_image "diagnostic-$curve" "$WORK/bin/$curve/orbis-node-diagnostic" orbis-node \
        "$orbis_ref" "$features,unsafe-testing"
    export ORBIS_NATIVE_DIAGNOSTIC_IMAGE=$IMAGE_ID
    shasum -a 256 "$WORK/vera/Cargo.lock" "$WORK/orbis/Cargo.lock" > "$RUN/locks-$curve.log"

    # Orbis owns test selection, fixed summaries, deadlines and container cleanup.
    # Its raw build/runtime output stays below this private per-curve directory.
    mkdir "$RUN/$curve"
    (cd "$WORK/orbis" && RUNNER_TEMP="$RUN/$curve" bash scripts/test-native-integration.sh "$curve") \
        | tee "$RUN/summary-$curve.jsonl"

    # These earlier Backbone gates additionally check persisted identity and
    # graceful BLS restart with the same normal container images. Reuse the
    # shared suite's normal fixture artifacts;
    # its three normal + one diagnostic selection contract stays unchanged.
    shared_work=("$RUN/$curve"/orbis-native-integration.*)
    if [[ ${#shared_work[@]} != 1 || ! -d "${shared_work[0]}/target" ]]; then
        echo 'Expected one shared native build directory' >&2
        exit 1
    fi
    (
        export CARGO_TARGET_DIR="${shared_work[0]}/target"
        export NATIVE_STACK_CURVE="$curve"
        private_command "retained-selection-$curve" cargo +1.98.0 test --release --locked -j2 "${native[@]}" \
            --features "$features" --test native_startup -- --ignored --list
        scenarios=(native_startup_registers_and_preserves_identity_on_restart)
        if [[ $curve == bls12-381 ]]; then scenarios+=(native_defra_signing); fi
        for scenario in "${scenarios[@]}"; do
            grep -Fx "$scenario: test" "$RUN/retained-selection-$curve.log" >/dev/null || exit 1
            private_command "retained-$curve-$scenario" bash "$ROOT/.github/scripts/run-native-scenario.sh" \
                "$RUN" "$scenario" cargo +1.98.0 test --release --locked -j2 "${native[@]}" \
                --features "$features" --test native_startup "$scenario" \
                -- --ignored --exact --test-threads=1 --nocapture
        done
    )
done
