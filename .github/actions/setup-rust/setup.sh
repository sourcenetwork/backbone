#!/usr/bin/env bash
set +x
set -euo pipefail

case "${CI_RUST_COMPONENT:-}" in
    "") ;;
    rustfmt|clippy) ;;
    *) echo 'Unsupported Rust component' >&2; exit 2 ;;
esac
for option in CI_BUILD_DEPENDENCIES CI_FREE_BUILD_SPACE; do
    case "${!option}" in
        true|false) ;;
        *) echo 'Invalid setup option' >&2; exit 2 ;;
    esac
done

if [[ "$CI_FREE_BUILD_SPACE" == true ]]; then
    # These preinstalled SDKs are unused by the native Rust stack.
    sudo rm -rf -- /usr/local/lib/android /usr/share/dotnet
fi
if [[ "$CI_BUILD_DEPENDENCIES" == true ]]; then
    sudo apt-get update
    sudo apt-get install -y clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler libdigest-sha-perl
fi
if [[ "$CI_FREE_BUILD_SPACE" == true ]]; then
    df -h "$GITHUB_WORKSPACE"
fi
if [[ -n "${PRIVATE_REPO_PAT:-}" ]]; then
    if ! git config --global "url.https://${PRIVATE_REPO_PAT}@github.com/sourcenetwork/.insteadOf" \
        "https://github.com/sourcenetwork/" 2>/dev/null; then
        echo 'Unable to configure private dependency access' >&2
        exit 1
    fi
fi
set -- toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
if [[ -n "${CI_RUST_COMPONENT:-}" ]]; then
    set -- "$@" --component "$CI_RUST_COMPONENT"
fi
rustup "$@"
