# Release artifact integrity and origin (#297)

The JSON release record is an unsigned checksum list. Its source SHA is compared
with a caller-supplied exact Git commit, but its contents alone cannot prove that
source produced those bytes. Replacing an ELF and regenerating its record passes
`verify-integrity`. The old checker already disclaimed authenticity; the previous
substitution test covered changing only the ELF, not both files.

Main CI now prepares official GitHub provenance attestations for both the release
ELF and JSON record, before building any compatibility variants. The record also
hashes the uploaded build-input log and declares the fixed release features,
compiler pin, SBF builder, platform tools, and architecture. The log records the
native compiler and actual platform-tools Rust compiler. These are builder claims;
they do not establish an independent reproducible build.

Consumers must use a trusted copy of this script from a reviewed commit, the
reviewed Cargo.lock, and an independently approved full source SHA:

```bash
python3 scripts/artifact_provenance.py verify \
  --artifact target/deploy/solana_confidential_compute_verifier.so --lockfile Cargo.lock \
  --source-sha "$APPROVED_SOURCE_SHA" \
  --manifest target/deploy/artifact-provenance.json \
  --build-inputs target/deploy/build-inputs.txt
```

The command invokes `gh attestation verify` for both subjects' actual bytes,
requiring github.com, solana-foundation/confidential-compute, its
`.github/workflows/ci.yml`, main ref, exact approved source commit, and
GitHub-hosted runners. It fails on missing
attestations, missing CLI, or verification error. It never falls back to integrity.
Do not take the approved SHA, checker, or Cargo.lock from an untrusted bundle.

PR builds use explicit `verify-integrity` and cannot be accepted as authenticated
main releases. GitHub's attestation service requires a supported plan (private
repositories require Enterprise Cloud); no plan or authorization change is made
here. Service unavailability must fail release verification, not waive it.

Trust remains in GitHub's signing service and the approved workflow execution.
A compromised builder can attest malicious outputs. Governance still needs its
independent build review and deployed program hash checks; this change neither
executes deployment nor establishes an on-chain hash or byte-identical rebuild.
Local tests use controlled verifier doubles, not authentic signed fixtures. Main
CI attestation issuance/verification remains unproven until that workflow runs.

Official references: [GitHub attestation setup](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
[CLI verification policy](https://cli.github.com/manual/gh_attestation_verify),
[pinned action](https://github.com/actions/attest-build-provenance/tree/977bb373ede98d70efdf65b84cb5f73e068dcc2a).

## Verified build (solana-verify)

This is a separate check. It is not the SBPFv3 integrity flow above. The two
hashes are not expected to match. The verified build check runs `solana-verify
build` in a pinned Docker image and prints the SHA-256 of the executable.

Run the check with Docker running:

```bash
just verified-build
```

The recipe passes the image to `solana-verify` by digest. The image is
`solanafoundation/solana-verifiable-build:4.2.0`, pinned as
`sha256:ab0006cccc5bff403fcf5bfb29763c969bfdf7b0cf4b25b9a5a2db1be795e892`.
The image runs on amd64 only. The last line of the output is the executable hash.

The build uses the Rust toolchain and platform tools inside the pinned image
(Rust 1.96.1). It does not use the `SOLANA_CC_SBF_TOOLS_VERSION` pin in the justfile.

The workflow `.github/workflows/verified-build.yml` runs the build twice. It
cleans `target/deploy` before each run. It fails if the two hashes differ.

To compare a deployed program with this build, run:

```bash
solana-verify get-program-hash <PROGRAM_ID> -u <RPC_URL>
```

Compare the printed hash with the hash from `just verified-build`. A match means
that the deployed executable has the same bytes as this build. A mismatch means
that the deployed program was built differently, or from other source. The
command reads from an RPC endpoint. It changes nothing on chain.
