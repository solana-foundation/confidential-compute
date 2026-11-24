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
