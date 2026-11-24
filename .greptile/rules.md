## How to review this repository

This repository is Critical tier in the Solana Foundation SDLC (section 2). It contains an onchain verifier program, attestation parsers and a sidecar that holds signing keys. Your review helps a human reviewer. It is not an approval.

- Review only the code that the pull request changes. Do not report code that the pull request does not change.
- For each finding, give the rule that the code breaks. Use one of these:
  - a rule `id` from `.greptile/config.json`
  - a `@spec SCC-*` identifier from `SECURITY.md` or `docs/intent/confidential-compute-verifier-specs.md`
  - an SDLC section
- Section 3 of `SECURITY.md` is the source of truth for the security invariants. If the code and that document do not agree, report the difference. Do not guess which one is correct.
- Report findings in this order: security and correctness, then documentation that is not correct, then all other findings.
- Do not report formatting. `just fmt-check` and `just lint` examine formatting.
- For each finding, give the input or the account state that causes the failure. If you cannot give it, do not report the finding.

## Pull request description

- These paths are Critical tier:
  - `programs/`
  - `crates/solana-confidential-compute-core/`
  - `crates/solana-confidential-compute-crypto/`
  - `crates/solana-confidential-compute-cpi/`
  - `bins/solana-confidential-compute-sidecar/`
- Report a pull request that changes one of these paths and has the Standard or Low tier.
- Report a pull request that has "N/A" under "Threat model" if it adds or changes one of these items:
  - a trust boundary
  - a signer check or an authority check
  - a path that moves value
- Report a pull request that adds a dependency but does not give a reason for it under "New dependencies".
- Report a behavior change in program or verifier code that does not have a test for that change. For AI-assisted changes, the SDLC recommends that you write the tests first (section 3.2.6).

## Code style (SDLC 3.2.7)

- Report a new comment that only tells what the code does. Use a comment only to explain a workaround, a compatibility constraint or a fragile edge case.
- In a new public API, use `Address` and not `Pubkey` if the dependency supplies `Address`. Do not report existing code or internal code.

## Secrets

- Report a private key, a seed phrase, a keypair JSON file, an API token or a credential in the pull request. This rule also applies to tests and documents.
- Test fixtures must use keys that are made only for tests. The name of each test key must show that it is a test key.
