set shell := ["bash", "-euo", "pipefail", "-c"]
set ignore-comments

cargo_build_sbf_version := "4.2.0"
sbf_tools_version := "v1.56"

export SOLANA_CC_SBF_TOOLS_VERSION := sbf_tools_version

default:
    @just --list

install: install-sbf install-ts

install-sbf:
    #!/usr/bin/env bash
    set -euo pipefail
    installed="$(cargo-build-sbf --version 2>/dev/null | head -n 1 || true)"
    if [[ " $installed " == *" {{ cargo_build_sbf_version }} "* ]]; then
        echo "cargo-build-sbf {{ cargo_build_sbf_version }} is already installed"
    else
        cargo install --locked --version {{ cargo_build_sbf_version }} cargo-build-sbf
    fi

install-ts:
    bun install --cwd sdks/typescript --frozen-lockfile
    bun install --cwd docs-site --frozen-lockfile

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --locked --workspace --all-targets -- -D warnings

check: fmt-check lint

fmt-ts:
    bun run --cwd sdks/typescript format

fmt-check-ts:
    bun run --cwd sdks/typescript format:check

lint-ts:
    bun run --cwd sdks/typescript lint

check-bins:
    cargo check --locked -p solana-confidential-compute-sidecar --all-targets
    cargo check --locked -p solana-confidential-compute-cli --all-targets

build: && build-program build-ts
    cargo build --locked --workspace

build-program:
    # Since solana 4.x a natively linked `processor!` program cannot read any
    # sysvar, so the ProgramTest suites load the real `.so` instead. Both
    # programs are needed: the verifier (solana-confidential-compute-verifier and solana-confidential-compute-sdk tests)
    # and the consumer (solana-confidential-compute-consumer-reference tests). `tests/common/sbf.rs`
    # panics rather than skipping when an artifact is missing.
    #
    # Per-manifest, not workspace-root: a bare `cargo-build-sbf` resolves the
    # whole workspace with platform-tools rustc 1.89 and fails on the newer
    # toolchain required by the non-program crates' dev-dependencies.
    #
    # Default arch (SBPFv0) is deliberate. Do not point this at the `sbpf`
    # job's `--arch v3` artifact; that build targets deployment, not the
    # ProgramTest runtime these suites execute against.
    cargo-build-sbf --manifest-path programs/solana-confidential-compute-verifier/Cargo.toml
    cargo-build-sbf --manifest-path programs/solana-confidential-compute-consumer-reference/Cargo.toml
    ls -l target/deploy/solana_confidential_compute_verifier.so target/deploy/solana_confidential_compute_consumer_reference.so

build-program-anchor:
    #!/usr/bin/env bash
    set -euo pipefail
    # The deployable artifact must still build and link with the front end on,
    # and must not grow a stack frame past the SBF limit.
    cargo-build-sbf \
        --manifest-path programs/solana-confidential-compute-verifier/Cargo.toml \
        --features anchor 2>&1 | tee sbf-anchor.log
    if grep -qiE 'exceeded max offset' sbf-anchor.log; then
        echo "SBF stack frame exceeded the 4096-byte limit"; exit 1
    fi
    ls -l target/deploy/solana_confidential_compute_verifier.so

build-sbpfv3 *args:
    bash scripts/build-sbpfv3.sh {{ args }}

build-ts:
    bun run --cwd sdks/typescript build

unit-test-rs:
    cargo test --locked --workspace --lib --bins

integration-test-rs: build-program
    # `--test '*'` errors on targets whose required-features are off, so the
    # sdk crate that carries them runs in the feature-gated command below.
    cargo test --locked --workspace --exclude solana-confidential-compute-sdk --test '*' --examples
    cargo test --locked -p solana-confidential-compute-sdk --features test-bpf --all-targets
    cargo test --locked -p solana-confidential-compute-verifier --test issue_163_artifact --features test-bpf -- --include-ignored

test-rs: build-program
    cargo test --locked --workspace --all-targets
    # `--workspace --all-targets` SKIPS targets carrying `required-features`
    # rather than failing, so the step above never ran these. `test-bpf`
    # implies `test-utils`, which covers every gated target in the crate:
    # backend_policy_tests, nonce_migration_tests, issue_211, issue_293,
    # issue_294. Keep this after the SBF build step -- issue_164,
    # issue_211 and issue_293 load the real `.so`.
    cargo test --locked -p solana-confidential-compute-sdk --features test-bpf --all-targets
    cargo test --locked -p solana-confidential-compute-verifier --test issue_163_artifact --features test-bpf -- --include-ignored

test-anchor:
    # A separate job on purpose. The Rust Test Suite runner is at its disk
    # limit, and compiling this crate under a second feature set there
    # exhausted it. `idl-build` implies `anchor`, so one library-only feature
    # set covers the discriminator pinning, the program address and IDL
    # generation in a single build.
    cargo clippy --locked -p solana-confidential-compute-verifier --features idl-build --lib -- -D warnings
    cargo test --locked -p solana-confidential-compute-verifier --features idl-build --lib

test-ts: build-ts
    bun run --cwd sdks/typescript typecheck
    node --test sdks/typescript/test/*.test.cjs
    sdks/typescript/node_modules/.bin/tsc -p scripts/tsconfig.json --noEmit

test-scripts:
    python3 -m unittest discover -s scripts -p test_artifact_provenance.py -v
    bash scripts/build-sbpfv3.sh --self-test

test: test-rs test-anchor test-ts test-scripts

record-sbpfv3-provenance:
    #!/usr/bin/env bash
    set -euo pipefail
    {
        rustc --version --verbose
        cargo-build-sbf --version
        "$HOME/.cache/solana/{{ sbf_tools_version }}/platform-tools/rust/bin/rustc" --version --verbose
        printf '%s\n' 'platform-tools={{ sbf_tools_version }}' 'arch=v3' 'features=[]' 'default-features=true' 'cargo-build-sbf={{ cargo_build_sbf_version }}'
        git rev-parse HEAD
        sha256sum Cargo.lock target/deploy/solana_confidential_compute_verifier.so
    } > target/deploy/build-inputs.txt
    python3 scripts/artifact_provenance.py record \
        --artifact target/deploy/solana_confidential_compute_verifier.so --lockfile Cargo.lock \
        --source-sha "$(git rev-parse HEAD)" --manifest target/deploy/artifact-provenance.json \
        --build-inputs target/deploy/build-inputs.txt

sbf-mock-guard:
    #!/usr/bin/env bash
    set -euo pipefail
    for features in mock-crypto mock-crypto,test-bpf all; do
        args=(--features "$features")
        if [[ "$features" == all ]]; then args=(--all-features); fi
        if bash scripts/build-sbpfv3.sh -- --locked -j4 "${args[@]}" > mock-build.log 2>&1; then
            cat mock-build.log
            echo "mock SBF build unexpectedly succeeded: $features" >&2
            exit 1
        fi
        cat mock-build.log
        # A dependency/toolchain failure is not evidence that the guard worked.
        grep -F 'mock-crypto is unavailable on Solana SBF under every feature combination' mock-build.log
    done

verify-sbpfv3-attestation:
    python3 scripts/artifact_provenance.py verify \
        --artifact target/deploy/solana_confidential_compute_verifier.so --lockfile Cargo.lock \
        --source-sha "$(git rev-parse HEAD)" --manifest target/deploy/artifact-provenance.json \
        --build-inputs target/deploy/build-inputs.txt

verify-sbpfv3-integrity:
    python3 scripts/artifact_provenance.py verify-integrity \
        --artifact target/deploy/solana_confidential_compute_verifier.so --lockfile Cargo.lock \
        --source-sha "$(git rev-parse HEAD)" --manifest target/deploy/artifact-provenance.json \
        --build-inputs target/deploy/build-inputs.txt
    bash scripts/build-sbpfv3.sh --verify target/deploy/solana_confidential_compute_verifier.so

# Same steps as compute-regression, with CU_REPORT=1 so the CU tests write cu_report.md.
test-and-benchmark:
    CU_REPORT=1 just compute-regression

compute-regression:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/deploy-compute-v0
    cargo-build-sbf --arch v0 --tools-version {{ sbf_tools_version }} \
        --manifest-path programs/solana-confidential-compute-verifier/Cargo.toml \
        --sbf-out-dir target/deploy-compute-v0 -- --locked -j4 \
        2>&1 | tee target/issue165-v0-build.log
    if grep -Eiq 'stack offset.*exceeded|stack frame.*(exceed|too large)|overflows the maximum allowed frame space' target/issue165-v0-build.log; then
        echo 'Refusing stack-violating SBFv0 artifact' >&2
        exit 1
    fi
    python3 - <<'PYCODE'
    import pathlib, struct
    elf = pathlib.Path('target/deploy-compute-v0/solana_confidential_compute_verifier.so').read_bytes()
    assert len(elf) > 64 and elf[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<H', elf, 18)[0] in (0xF7, 0x107)
    assert struct.unpack_from('<I', elf, 48)[0] == 0, 'runtime 2.2 requires SBFv0'
    PYCODE
    sha256sum Cargo.lock target/deploy-compute-v0/solana_confidential_compute_verifier.so
    export SOLANA_CC_SBF_ARTIFACT="{{ justfile_directory() }}/target/deploy-compute-v0/solana_confidential_compute_verifier.so"
    export SBF_OUT_DIR="{{ justfile_directory() }}/target/deploy-compute-v0"
    # No --ignored: the test used to need a prebuilt artifact and was
    # ignored by default. It now always runs, and passing --ignored here
    # would filter it out rather than select it, leaving the grep below
    # to fail on "0 passed; 0 failed; 1 filtered out".
    cargo test --locked -j4 -p solana-confidential-compute-verifier --test issue_165_compute \
        issue_165_actual_sbf_compute -- --exact --nocapture \
        2>&1 | tee target/issue165-v0-meter.log
    # A filter typo or ignored test is not compute proof.
    grep -F 'test result: ok. 1 passed; 0 failed' target/issue165-v0-meter.log
