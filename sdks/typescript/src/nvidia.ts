import { sha256 } from '@noble/hashes/sha256';
/**
 * NVIDIA Hopper `verify_nvidia_attestation` builders.
 *
 * Legacy construction for fixtures only. Both modes fail on chain with
 * NvidiaAttestationUnavailable (custom 18). No hardware evidence or enrollment
 * authority is supplied by these builders.
 *
 * @spec SCC-NVIDIA-002 SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005
 */
import {
    PublicKey,
    SystemProgram,
    SYSVAR_CLOCK_PUBKEY,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SYSVAR_SLOT_HASHES_PUBKEY,
    TransactionInstruction,
} from '@solana/web3.js';

import { deriveBackendPolicyPda } from './backend-policy';
import { SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID } from './index';

/** `sha256("global:verify_nvidia_attestation")[..8]`. */
export const VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR = new Uint8Array([31, 2, 40, 104, 69, 155, 234, 120]);
/** Mode A (`verify_and_register_nvidia`). */
export const VERIFY_NVIDIA_MODE_A = 0;
/** Mode B (`verify_atomic_nvidia`). */
export const VERIFY_NVIDIA_MODE_B = 1;
/** Read-only attested-signer account passed in Mode B. The program does not write it. */
export const NVIDIA_MODE_B_ATTESTED_SIGNER_PLACEHOLDER = new PublicKey(new Uint8Array(32).fill(0xff));

function require32(bytes: Uint8Array, label: string): Uint8Array {
    if (bytes.length !== 32) {
        throw new Error(`${label} must be 32 bytes`);
    }
    return bytes;
}

function concat(parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

function u64Le(value: bigint | number): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(BigInt(value));
    return buf;
}

/**
 * Mode A nonce PDA.
 *
 * `seed = SHA-256(workloadSigner || gpuMeasurement || slotHash)`, then
 * `["nonce", 4, seed]`.
 *
 * @spec SCC-NVIDIA-002 SCC-NVIDIA-004
 */
export function deriveNvidiaNoncePda(
    workloadSigner: PublicKey,
    gpuMeasurement: Uint8Array,
    slotHash: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    require32(gpuMeasurement, 'gpu measurement');
    require32(slotHash, 'slot hash');
    const seed = sha256(concat([workloadSigner.toBytes(), gpuMeasurement, slotHash]));
    return PublicKey.findProgramAddressSync([Buffer.from('nonce'), Buffer.from([4]), Buffer.from(seed)], programId);
}

/**
 * Packs `verify_nvidia_attestation` (Mode A or Mode B).
 *
 * `slotHash` is the SlotHashes entry for `nonceSlot`. Mode A derives the nonce
 * from the workload signer. Mode B derives it from
 * `SHA-256(slotHash || actionHash || consumerProgramId)` and requires
 * `consumerProgramId`. Mode A ignores that argument.
 *
 * @spec SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005
 */
export function buildVerifyNvidiaAttestationIx(
    payer: PublicKey,
    workloadSigner: PublicKey,
    mode: number,
    nonceSlot: bigint | number,
    expectedActionHash: Uint8Array,
    gpuMeasurement: Uint8Array,
    slotHash: Uint8Array,
    consumerProgramId: PublicKey | null = null,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    if (mode !== VERIFY_NVIDIA_MODE_A && mode !== VERIFY_NVIDIA_MODE_B) {
        throw new Error('NVIDIA mode must be 0 (Mode A) or 1 (Mode B)');
    }
    require32(expectedActionHash, 'action hash');
    require32(gpuMeasurement, 'gpu measurement');
    require32(slotHash, 'slot hash');
    const noncePda =
        mode === VERIFY_NVIDIA_MODE_A
            ? deriveNvidiaNoncePda(workloadSigner, gpuMeasurement, slotHash, programId)[0]
            : modeBNoncePda(slotHash, expectedActionHash, gpuMeasurement, consumerProgramId, programId);
    const attestedSigner =
        mode === VERIFY_NVIDIA_MODE_A
            ? PublicKey.findProgramAddressSync(
                  [Buffer.from('attested_signer_v2'), workloadSigner.toBytes()],
                  programId,
              )[0]
            : NVIDIA_MODE_B_ATTESTED_SIGNER_PLACEHOLDER;
    const registry = PublicKey.findProgramAddressSync([Buffer.from('policy_registry')], programId)[0];
    const backend = deriveBackendPolicyPda(4, programId)[0];
    const data = Buffer.concat([
        Buffer.from(VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR),
        Buffer.from([mode]),
        u64Le(nonceSlot),
        Buffer.from(expectedActionHash),
        Buffer.from(gpuMeasurement),
    ]);
    const keys = [
        { isSigner: false, isWritable: mode === VERIFY_NVIDIA_MODE_A, pubkey: attestedSigner },
        { isSigner: false, isWritable: false, pubkey: registry },
        { isSigner: false, isWritable: true, pubkey: noncePda },
        { isSigner: true, isWritable: true, pubkey: payer },
        { isSigner: false, isWritable: false, pubkey: SystemProgram.programId },
        { isSigner: false, isWritable: false, pubkey: SYSVAR_CLOCK_PUBKEY },
        { isSigner: false, isWritable: false, pubkey: SYSVAR_SLOT_HASHES_PUBKEY },
        mode === VERIFY_NVIDIA_MODE_A
            ? { isSigner: true, isWritable: false, pubkey: workloadSigner }
            : { isSigner: false, isWritable: false, pubkey: SYSVAR_INSTRUCTIONS_PUBKEY },
        { isSigner: false, isWritable: false, pubkey: backend },
    ];
    return new TransactionInstruction({ data, keys, programId });
}

function modeBNoncePda(
    slotHash: Uint8Array,
    actionHash: Uint8Array,
    gpuMeasurement: Uint8Array,
    consumerProgramId: PublicKey | null,
    programId: PublicKey,
): PublicKey {
    if (consumerProgramId === null) {
        throw new Error('Mode B requires the consumer program id');
    }
    const commitment = sha256(concat([slotHash, actionHash, consumerProgramId.toBytes()]));
    const seed = sha256(concat([commitment, gpuMeasurement, slotHash]));
    return PublicKey.findProgramAddressSync([Buffer.from('nonce'), Buffer.from([4]), Buffer.from(seed)], programId)[0];
}
