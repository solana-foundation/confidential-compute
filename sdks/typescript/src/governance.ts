import { sha256 } from '@noble/hashes/sha256';
/** Offline governance wire builders. No network or key custody.
 * Registry authority is trusted for key provenance. Mutable-root rotation is
 * unsupported by the pinned-Milan verifier after #172, even though its legacy
 * wire format is available here. Authority rotation requires both signatures.
 */
import { PublicKey, TransactionInstruction, SystemProgram } from '@solana/web3.js';

import {
    SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    derivePolicyRegistryPda,
    deriveSignerPda,
    deriveVcekPda,
} from './index';
export const UPDATE_POLICY_DISCRIMINATOR = new Uint8Array([227, 150, 114, 217, 142, 172, 100, 228]);
export const ROTATE_ROOT_CERT_DISCRIMINATOR = new Uint8Array([137, 212, 96, 71, 222, 5, 133, 104]);
export const REGISTER_JWKS_KEY_DISCRIMINATOR = new Uint8Array([122, 195, 232, 116, 203, 137, 219, 14]);
export const REVOKE_JWKS_KEY_DISCRIMINATOR = new Uint8Array([184, 102, 12, 45, 99, 128, 41, 16]);
export const ROTATE_AUTHORITY_DISCRIMINATOR = new Uint8Array([248, 225, 151, 35, 28, 15, 85, 12]);
export const REVOKE_ATTESTED_SIGNER_DISCRIMINATOR = new Uint8Array([174, 9, 66, 138, 2, 191, 81, 61]);
export const REVOKE_VCEK_DISCRIMINATOR = new Uint8Array([81, 34, 243, 59, 64, 69, 29, 89]);
function u32(value: number): Buffer {
    const out = Buffer.alloc(4);
    out.writeUInt32LE(value);
    return out;
}
function bytes(value: Uint8Array, length: number, label: string): Buffer {
    if (value.length !== length) throw new Error(`${label} must be ${length} bytes`);
    return Buffer.from(value);
}
function metas(authority: PublicKey, programId: PublicKey, writable = true) {
    return [
        { pubkey: authority, isSigner: true, isWritable: false },
        { pubkey: derivePolicyRegistryPda(programId)[0], isSigner: false, isWritable: writable },
    ];
}
/** Updates the retained global registry ABI; minTcb may only increase.
 * Global measurements are deprecated as runtime admission controls. An empty
 * global list does not halt AMD, Nitro, or GCP admission: call
 * buildSetBackendPolicyIx with [] for each relevant backend instead.
 * Revoke existing Mode A signer records separately with buildRevokeAttestedSignerIx.
 */
export function buildUpdatePolicyIx(
    authority: PublicKey,
    minTcb: Uint8Array,
    measurements: Uint8Array[],
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    if (measurements.length > 8) throw new Error('at most eight measurements');
    const data = Buffer.concat([
        Buffer.from(UPDATE_POLICY_DISCRIMINATOR),
        bytes(minTcb, 4, 'minTcb'),
        u32(measurements.length),
        ...measurements.map(m => bytes(m, 48, 'measurement')),
        Buffer.alloc((8 - measurements.length) * 48),
    ]);
    return new TransactionInstruction({ programId, keys: metas(authority, programId), data });
}
/** Legacy ABI only: pinned-Milan verifier rejects mutable root rotation. */
export function buildRotateRootCertIx(
    authority: PublicKey,
    newArkPubkeyXy: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    return new TransactionInstruction({
        programId,
        keys: metas(authority, programId),
        data: Buffer.concat([Buffer.from(ROTATE_ROOT_CERT_DISCRIMINATOR), bytes(newArkPubkeyXy, 96, 'root')]),
    });
}
export function deriveJwksPda(
    kidHash: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([Buffer.from('jwks'), bytes(kidHash, 32, 'kidHash')], programId);
}
export function buildRegisterJwksKeyIx(
    authority: PublicKey,
    payer: PublicKey,
    kid: Uint8Array,
    modulus: Uint8Array,
    exponent = 65537,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    if (kid.length === 0 || kid.length > 64 || kid.includes(0)) throw new Error('kid must contain 1..64 non-NUL bytes');
    const n = bytes(modulus, 256, 'modulus');
    if (exponent !== 65537 || (n[0] & 128) === 0 || (n[255] & 1) === 0) throw new Error('invalid RSA key');
    const keys = [
        ...metas(authority, programId, false),
        { pubkey: deriveJwksPda(sha256(kid), programId)[0], isSigner: false, isWritable: true },
        { pubkey: payer, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];
    return new TransactionInstruction({
        programId,
        keys,
        data: Buffer.concat([
            Buffer.from(REGISTER_JWKS_KEY_DISCRIMINATOR),
            u32(kid.length),
            Buffer.from(kid),
            n,
            u32(exponent),
        ]),
    });
}
export function buildRevokeJwksKeyIx(
    authority: PublicKey,
    kidHash: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    return new TransactionInstruction({
        programId,
        keys: [
            ...metas(authority, programId, false),
            { pubkey: deriveJwksPda(kidHash, programId)[0], isSigner: false, isWritable: true },
        ],
        data: Buffer.concat([Buffer.from(REVOKE_JWKS_KEY_DISCRIMINATOR), bytes(kidHash, 32, 'kidHash')]),
    });
}
export function buildRotateAuthorityIx(
    authority: PublicKey,
    receivingAuthority: PublicKey,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    if (receivingAuthority.equals(authority) || receivingAuthority.equals(PublicKey.default))
        throw new Error('receiving authority must differ and be nonzero');
    return new TransactionInstruction({
        programId,
        keys: [...metas(authority, programId), { pubkey: receivingAuthority, isSigner: true, isWritable: false }],
        data: Buffer.from(ROTATE_AUTHORITY_DISCRIMINATOR),
    });
}
/** Uses the SDK signer namespace, migrating alongside enrollment under #182. */
export function buildRevokeAttestedSignerIx(
    authority: PublicKey,
    signer: PublicKey,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    const account = deriveSignerPda(signer, programId)[0];
    return new TransactionInstruction({
        programId,
        keys: [...metas(authority, programId, false), { pubkey: account, isSigner: false, isWritable: true }],
        data: Buffer.concat([Buffer.from(REVOKE_ATTESTED_SIGNER_DISCRIMINATOR), signer.toBuffer()]),
    });
}
/** Revoke the cache and permanent AMD identity across TCB versions; payer funds the tombstone. */
export function buildRevokeVcekIx(
    authority: PublicKey,
    payer: PublicKey,
    chipIdHash: Uint8Array,
    tcbVersion: bigint | number,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    const hash = bytes(chipIdHash, 32, 'chipIdHash'),
        tcb = Buffer.alloc(8);
    tcb.writeBigUInt64LE(BigInt(tcbVersion));
    const account = deriveVcekPda(hash, tcbVersion, programId)[0];
    return new TransactionInstruction({
        programId,
        keys: [
            ...metas(authority, programId, false),
            { pubkey: account, isSigner: false, isWritable: true },
            { pubkey: deriveAmdRevocationPda(hash, programId)[0], isSigner: false, isWritable: true },
            { pubkey: payer, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([Buffer.from(REVOKE_VCEK_DISCRIMINATOR), hash, tcb]),
    });
}

/** VCEK hash(chip ID) or VLEK hash(endorsement XY), never a cross-key chip assertion. */
export function deriveAmdRevocationPda(
    identity: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
        [Buffer.from('amd_revocation'), bytes(identity, 32, 'identity')],
        programId,
    );
}
