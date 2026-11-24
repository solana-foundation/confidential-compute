# CLAUDE.md

This repository contains Solana Confidential Compute. It has these parts:

- an onchain verifier for TEE attestations from AMD SEV-SNP, AWS Nitro, Intel TDX and GCP
- the crates that the verifier uses
- a host sidecar that holds the workload signing key
- Rust and TypeScript SDKs

This repository is Critical tier in the Solana Foundation SDLC.

- To see the recipes, run `just --list`.
- The security invariants are in section 3 of [`SECURITY.md`](./SECURITY.md).
- The spec catalog is [`docs/intent/confidential-compute-verifier-specs.md`](./docs/intent/confidential-compute-verifier-specs.md).

## Known problems

**The program does not verify P-384 signatures on chain.** A software P-384 check uses
approximately 46M CU. The transaction limit is 1.4M CU. The verifier accepts a P-384 signature
only if a previous instruction calls `EXPECTED_SIGVERIFY_PROGRAM_ID`. Mainnet has no secp384r1
precompile, thus this path fails closed. The host crates verify P-384 off chain. TDX uses P-256
and the native `secp256r1` precompile.

**Packets are almost full.** An SNP report is 1,184 bytes. Mode B adds an 80-byte header. A
legacy packet is 1,232 bytes. The builders reject a packet that is too large.

**There are two different authorities.** The loader upgrade authority and
`PolicyRegistry.authority` are independent. When you transfer one, the other does not change.
`rotate_root_cert` always refuses the request. This is intentional. Refer to the section
"Administrative authorities and trust roots" in SECURITY.md.

**Change `hash_action` V3 in five places at the same time.** These parts must agree byte for
byte:

- the verifier
- the CPI helpers
- the Rust SDK
- the TypeScript SDK
- the sidecar function `screen_transaction`

There is no fallback to V1 or V2. The contract is in section 4 of
`crates/solana-confidential-compute-cpi/README.md`.

**Used nonces have two layouts.** A legacy 17-byte `UsedNonceAccount` record and a 49-byte
record both show that a nonce is used. You can close only a 49-byte record. You can close it
only after 150 slots.

**Mocks must not get to SBF or to a live sidecar.** `just sbf-mock-guard` makes sure that
`mock-crypto` cannot build for SBF. The sidecar refuses the mock provider if `dry_run` is not
set (`fail_closed_live_mock`).

**The sidecar API is on loopback only.** The default address is `127.0.0.1:8080`. At startup,
`validate_loopback_addr` rejects all other addresses.

**Update the documents in the same pull request as the code.** Some changes alter documented
behavior. Examples are an error code, a PDA seed, an account layout, a limit or a `@spec`
clause. For these changes, update SECURITY.md, the spec catalog and the crate README.

## Conventions

- Do not use `unwrap`, `expect` or `panic!` outside tests.
- Use checked arithmetic in program code.
- Before you use an account, examine its owner, signer flag, writable flag, PDA address and
  discriminator.
- Read the measurement, `REPORT_DATA`, `chip_id` and TCB only from the signed bytes. Do not
  read them from instruction data.
- For a change to verification, write the tests first.
- Before you open a pull request, run `just check` and `just test`.
- Use comments only to explain workarounds and constraints that are not clear from the code.
- Use Conventional Commits.
- Complete the AI disclosure in the pull request template.
