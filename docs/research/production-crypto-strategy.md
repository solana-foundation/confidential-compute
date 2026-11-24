# Production Cryptographic Verification Strategy

**Document ID:** SCC-RES-005  
**Topic:** Production Curve Verification: Solana Native SIMD Precompile vs Zero-Knowledge Proof Pipeline  
**Status:** Approved Architectural Strategy  
**Last Reviewed:** 2026-09-19  

---

## 1. Executive Summary

Milestone Gate 2 proved that the on-chain AMD SEV-SNP policy, sysvar, TCB, and account validation architecture fits comfortably inside Solana's compute limits. Under `mock-crypto`, on-chain verification consumes between 70,241 CUs (Mode B) and 74,701 CUs (Mode A), well below the 550,000 CU internal engineering design ceiling (and consuming less than 6% of Solana's 1.4M max transaction limit).

However, production on-chain verification of raw AMD silicon reports requires evaluating a **NIST P-384 (secp384r1)** elliptic curve ECDSA signature over a SHA-384 digest.

Evaluating NIST P-384 point multiplication in pure software on Solana Bytecode Format (SBF) consumes approximately **46,000,000 Compute Units (CUs)**. Because Solana transactions enforce a hard ceiling of 1,400,000 CUs, direct pure-software evaluation of P-384 signatures on-chain is impossible.

This document establishes a **two-track production cryptographic verification strategy**:

1. **Option A (Long-Term Gold Standard): Solana Improvement Document (SIMD) for `secp384r1` Native Precompile**  
   Propose and advocate for a native Solana validator syscall for NIST P-384 verification. This path achieves minimal latency, zero prover cost, and an estimated ~25,000 CU execution cost.
2. **Option B (Immediate Production Readiness): Off-Chain Zero-Knowledge Proof (zkVM) Wrapper**  
   Validate the 1,184-byte AMD report and NIST P-384 signature inside an off-chain zero-knowledge virtual machine (SP1 or RISC Zero). Emit a Groth16 proof over the BN254 curve. Verify the Groth16 proof on Solana using the native `alt_bn128` precompile (`solana_program::alt_bn128`), consuming ~150,000 CUs.

---

## 2. Technical Comparison Matrix

| Evaluation Criterion | Option A: Native SIMD Precompile | Option B: zkVM Groth16 Wrapper |
| :--- | :--- | :--- |
| **Curve / Math** | NIST P-384 (`secp384r1`) | Groth16 over BN254 (`alt_bn128`) |
| **On-Chain Sycall** | Dedicated precompile (Proposed) | Native `alt_bn128_pairing` (Live on Mainnet) |
| **On-Chain CUs** | ~25,000 CUs | ~150,000 – 200,000 CUs |
| **Proof / Signature Size** | 96 bytes (`r` and `s`) | 128 bytes (Groth16 $\pi_A, \pi_B, \pi_C$) |
| **Off-Chain Prover Time** | 0 ms (Raw ECDSA signature) | 500 ms – 15,000 ms (zkVM proof generation) |
| **Prover Infrastructure** | None (Direct hardware attestation) | GPU prover instances (SP1 / RISC Zero) |
| **Mainnet Availability** | Requires Solana network upgrade (6–12 mo) | **Available immediately today** |
| **Client Ergonomics** | Enclave submits raw report directly | Enclave submits proof bundle from local prover |

---

## 3. Option A: Native Solana SIMD Precompile (`secp384r1`)

### 3.1 Rationale
Solana currently provides native syscalls for Ed25519 (`ed25519_verify`) and Secp256k1 (`secp256k1_recover`). Both syscalls execute native host CPU instructions on validator nodes outside SBF metering, charging a small, fixed compute unit fee.

AMD SEV-SNP (and AWS Nitro Enclaves with P-384) constitutes the dominant hardware Confidential Computing standard across major cloud providers (AWS, GCP, Azure). Adding native `secp384r1` signature verification benefits not only Solana Confidential Compute, but every hardware attestation, WebAuthn passkey, and enterprise identity protocol building on Solana.

### 3.2 Proposed Syscall Interface

```rust
/// Native SBF syscall proposal: sol_secp384r1_verify
///
/// Parameters:
/// - public_key_xy: &[u8; 96] (Uncompressed 48-byte X and Y affine coordinates)
/// - message_hash:  &[u8; 48] (SHA-384 digest of signed payload)
/// - signature_rs:  &[u8; 96] (48-byte R and S scalars)
///
/// Returns:
/// - 0 on valid signature.
/// - Non-zero error code on invalid signature, malformed curve points, or scalar overflow.
pub fn sol_secp384r1_verify(
    public_key_xy: &[u8; 96],
    message_hash: &[u8; 48],
    signature_rs: &[u8; 96],
) -> u64;
```

### 3.3 Compute Budget Estimation
Comparing native cryptographic syscall costs on Solana:
- `sol_secp256k1_recover`: ~25,000 CUs.
- `alt_bn128_pairing` (two pairings): ~150,000 CUs.
- NIST P-384 point multiplication on modern x86-64 hardware with AVX2 requires ~0.18 milliseconds.

Based on Solana runtime metering standards, `secp384r1_verify` should be priced between **25,000 and 35,000 CUs**.

---

## 4. Option B: Zero-Knowledge Proof Wrapper (Production-Ready Path)

### 4.1 Architecture & Prover Pipeline

To deploy Solana Confidential Compute on Solana mainnet without waiting for consensus changes, Option B wraps the raw P-384 hardware verification inside an off-chain zero-knowledge proof.

```
+-------------------------------------------------------------------------+
| Off-Chain Confidential Compute Enclave (AMD SEV-SNP)                   |
| 1. Enclave runs workload binary.                                        |
| 2. Enclave generates ephemeral Ed25519 keypair.                         |
| 3. Enclave requests AMD hardware report from /dev/sev-guest.             |
| 4. Hardware returns 1,184-byte report signed by AMD VCEK (P-384).       |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
| Off-Chain zkVM Prover (Succinct SP1 or RISC Zero)                       |
| 1. Ingests:                                                             |
|    - 1,184-byte SNP Report                                              |
|    - 96-byte VCEK Public Key                                            |
|    - VCEK Certificate DER & ASK Certificate DER                         |
| 2. Circuit Logic:                                                       |
|    - Parses SNP report header, policy, and measurement.                 |
|    - Evaluates SHA-384 over report body (bytes 0..672).                 |
|    - Verifies P-384 signature (r, s) against VCEK public key.           |
|    - Verifies VCEK signature against AMD ARK/ASK root.                  |
| 3. Output:                                                              |
|    - Public Journal: (measurement, signer_pubkey, chip_id_hash, nonce) |
|    - Groth16 Proof (BN254): 128 bytes (A: 32B, B: 64B, C: 32B)          |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
| On-Chain Solana Verifier (solana-confidential-compute-verifier on Mainnet)                    |
| 1. Receives Public Journal + 128-byte Groth16 Proof.                    |
| 2. Executes solana_program::alt_bn128::alt_bn128_pairing (~150k CUs).   |
| 3. Checks AMD TCB floors in PolicyRegistry; measurement in BackendPolicy. |
| 4. Emits AttestedSignerAccount or approves atomic bundle.               |
+-------------------------------------------------------------------------+
```

### 4.2 On-Chain Groth16 Verification on Solana
Solana supports BN254 elliptic curve operations natively via the `alt_bn128` precompiles (SIMD-0129):
- `alt_bn128_addition` (~3,000 CUs)
- `alt_bn128_multiplication` (~12,000 CUs)
- `alt_bn128_pairing` (~150,000 CUs for a 2-pair pairing check)

A standard Groth16 SNARK verification evaluates one pairing equation with 4 pairings:
$$e(A, B) = e(\alpha, \beta) \cdot e(x \cdot \gamma, \delta) \cdot e(C, \gamma)$$
Combining terms yields a single batch pairing check on Solana:
$$e(-A, B) \cdot e(\alpha, \beta) \cdot e(x \cdot \gamma, \delta) \cdot e(C, \gamma) = 1$$

Total compute cost on Solana is approximately **150,000 to 180,000 CUs**, safely within both the default 200,000 CU limit and the 1,400,000 CU maximum budget.

---

## 5. Phased Production Implementation Roadmap

### Phase 4.1: Deploy Option B (ZK Proof Wrapper)
1. Implement an SP1 guest program in Rust validating AMD report signatures and cert chains.
2. Generate Groth16 proofs using the Succinct prover network.
3. Integrate on-chain BN254 pairing verification into `solana-confidential-compute-verifier`.
4. Deliver fully functional, permissionless on-chain TEE verification on Solana Mainnet.

### Phase 4.2: Draft and Submit Solana SIMD (Option A)
1. Author formal Solana Improvement Document: `SIMD: NIST P-384 (secp384r1) Signature Verification Syscall`.
2. Present empirical data from Solana Confidential Compute Milestone Gate 2.
3. Coordinate with Anza (`agave`), Firedancer, and core contributors for protocol inclusion.
4. Once mainnet activation occurs, update `solana-confidential-compute-verifier` with a zero-overhead native path.
