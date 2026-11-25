# Scripts

Build gate, Nitro probe, and Devnet smoke harness.

| Script | Role |
| :--- | :--- |
| [`build-sbpfv3.sh`](build-sbpfv3.sh) | Build `programs/solana-confidential-compute-verifier` as SBPFv3 and check the ELF header. `@spec SCC-DEPLOY-001`. |
| [`run_nitro_hardware_probe.sh`](run_nitro_hardware_probe.sh) | Capture an NSM document on an EC2 Nitro host. `@spec SCC-NITRO-001`. |
| [`smoke_test_devnet.ts`](smoke_test_devnet.ts) | Devnet `verify_nitro_attestation` Mode A smoke test. `@spec SCC-PERF-001`. |

Python 3 is required by the ELF parser and by the vsock receiver. The smoke harness needs Bun or Node, plus `sdks/typescript` dependencies. The probe needs Docker and the Nitro CLI on the EC2 host.

---

## 1. `build-sbpfv3.sh`

The script compiles `programs/solana-confidential-compute-verifier` only.

```bash
bash scripts/build-sbpfv3.sh
bash scripts/build-sbpfv3.sh --verify target/deploy/solana_confidential_compute_verifier.so
bash scripts/build-sbpfv3.sh --self-test
```

Default mode runs `cargo-build-sbf --arch v3 --tools-version v1.56`. `SOLANA_CC_SBF_TOOLS_VERSION` overrides the pin. Extra arguments are forwarded. `--self-test` is consumed by the script and is not forwarded. Do not pass `--features test-bpf` on a release build. Do not pass `--arch v3` to platform-tools older than v1.53.

The checker reads the ELF64 header. `e_flags` at byte 48 must be `0x3`. `e_machine` must be `EM_BPF` (`0xf7`) or `EM_SBF` (`0x107`). It then checks SIMD-0178: syscall immediates are static Murmur3-32 hashes. `SHT_DYNSYM`, `SHT_REL`, and `SHT_RELA` fail the build.

`--self-test` checks the parser with synthetic 64-byte headers. It does not need a Solana toolchain and it does not read `solana_confidential_compute_verifier.so`.

The CU harness that loads the `.so` is `programs/solana-confidential-compute-verifier/tests/cu_benchmarks.rs`.

### 1.1 What this script does not build

`solana-confidential-compute-consumer-reference` is a separate `cargo-build-sbf` target. The Devnet consumer ELF at slot 505,980,264 is **127,744** bytes, `e_machine = 0x107`, `e_flags = 0x0`. That header is not SBPFv3.

---

## 2. Devnet upgrade

| Program | Program id | Program-data account | Slot | ELF bytes | Header |
| :--- | :--- | :--- | ---: | ---: | :--- |
| `solana-confidential-compute-verifier` | `EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh` | `EWShgrBQhkQiTmGTrYm9DuWvUPKRcsbECqXJuGa1BFcX` | 505,980,419 | 673,784 | `e_machine = 0xf7`, `e_flags = 0x3` |
| `solana-confidential-compute-consumer-reference` | `A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ` | `8o22e8hzYPkWAn48wE91CaL4WJQawhUP4YiqdozkE6ym` | 505,980,264 | 127,744 | `e_machine = 0x107`, `e_flags = 0x0` |

Devnet upgrade authority: `BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG`.

Production custody is intended to use Foundation governance (Squads multisig); this repository does not establish a production vault address or executed handoff. The loader upgrade authority and `PolicyRegistry.authority` are separate controls. The registry signer cannot change any trust root: since upstream PR #255, `rotate_root_cert` returns `VerifierError::InvalidInstruction` even when the registry authority signs, and leaves the legacy AMD P-384 `ark_pubkey_xy` field unchanged. Pinned Nitro and Milan RSA roots require a code change. The coordinated upstream #173 fix / PR #226 restricts production AMD to pinned Milan RSA, so that legacy field has no supported vendor-root meaning. A registry signer may be a keypair or a governance PDA signing via CPI; Solana Confidential Compute enforces no threshold or timelock itself. See the [authority and trust-root model](../SECURITY.md#administrative-authorities-and-trust-roots). Do not use the Devnet authority key on mainnet.

Build the verifier, check the header, then upgrade with the authority keypair:

```bash
bash scripts/build-sbpfv3.sh
bash scripts/build-sbpfv3.sh --verify target/deploy/solana_confidential_compute_verifier.so
solana program deploy target/deploy/solana_confidential_compute_verifier.so \
    --program-id EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh \
    --upgrade-authority <UPGRADE_AUTHORITY_KEYPAIR> \
    --url <CLUSTER_URL>
```

Read the program-data account after the upgrade. The ELF starts 45 bytes into that account (4-byte tag, 8-byte slot, 1-byte authority option, 32-byte authority). `e_flags` at ELF offset 48 must be `0x3` for `solana-confidential-compute-verifier`.

Verifier upgrade at slot 505,980,419: [`KHUQUyx8…`](https://explorer.solana.com/tx/KHUQUyx8xQB5VD4KFBsE3hQ4RrtUD8iQ72ZbMEeSiYomU1u1y48oZF73eqTkvQ93Dp8PXUjJdZb2jE5P5JjG2QM?cluster=devnet). Log: `Upgraded program EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh`.

Consumer upgrade at slot 505,980,264: [`5a92Bwn8…`](https://explorer.solana.com/tx/5a92Bwn8p9371LRQhtUJNrbKtCAoe67Wzjd6L9gbCsyGJ5szzoFuLBz5uwAGkrdWnmMRorfeQVXFnKs7VNcTrdMC?cluster=devnet).

---

## 3. `run_nitro_hardware_probe.sh`

Run on an enclave-capable EC2 instance (`c6i.xlarge` or larger, at least 4 vCPUs). The script has no flags.

```bash
bash scripts/run_nitro_hardware_probe.sh
```

It builds a static NSM probe, packages `nitro-probe.eif`, listens on `AF_VSOCK` port 5005, and accepts the document from parent CID 3. Outputs:

- `/tmp/nitro_attestation_hardware.bin`
- `/tmp/nitro_attestation_hardware.b64`

The closeout capture was 4,552 bytes. Operator steps are in [`docs/hardware-testing-runbook.md`](../docs/hardware-testing-runbook.md).

---

## 4. `smoke_test_devnet.ts`

```bash
NODE_PATH=sdks/typescript/node_modules bun scripts/smoke_test_devnet.ts
```

Payer file: `PAYER_KEYPAIR_PATH`, then `SOLANA_KEYPAIR_PATH`, then `~/.config/solana/id.json`.

The harness does four checks:

1. Initialize `PolicyRegistry` when the account is absent.
2. Build a Mode B transaction around a raw 1,184-byte report. `PacketTooLargeError` must fire. The transaction is not sent.
3. Reject an 8,192-byte Nitro document locally against the 1,232-byte packet cap.
4. Submit `verify_nitro_attestation` Mode A (`mode = 0`) with `SetComputeUnitLimit(550000)`. A landed `Custom(2)` is a successful fail-closed run. Compute must stay at or under 550,000 CU.

Recorded grant closeout signature: [`2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH`](https://explorer.solana.com/tx/2iEc1eAmyfu2QzgGjSuSEbCs28egC2z8rn9WLgcjbAZZ1mqmFbdNDhWoXHHZQSwkWHvS4W9ZZRURctnEkEQgbuuH?cluster=devnet). Slot 505,980,579. Verifier log: `consumed 8122 of 549850 compute units`, then `custom program error: 0x2`. Transaction meta: 8,272 CU.
