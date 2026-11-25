import { sha256 } from '@noble/hashes/sha2.js';
import {
    Blockhash,
    PublicKey,
    SystemProgram,
    SYSVAR_CLOCK_PUBKEY,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SYSVAR_SLOT_HASHES_PUBKEY,
    Transaction,
    TransactionInstruction,
} from '@solana/web3.js';

import { deriveBackendPolicyPda } from '../backend-policy';
/**
 * Test-only oversized packers. Not part of the supported client API.
 * Do not submit these instructions or transactions to a live cluster.
 *
 * Import from `dist/internal/oversized.js` in harnesses.
 *
 * @spec SCC-SDK-002 SCC-SEC-005 SCC-NITRO-008
 */
import { deriveAmdRevocationPda } from '../governance';
import {
    MAX_NITRO_DOCUMENT_LEN,
    NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER,
    SNP_REPORT_SIZE,
    SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    VERIFY_AND_REGISTER_DISCRIMINATOR,
    VERIFY_AND_REGISTER_IX_LEN,
    VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
    VERIFY_ATOMIC_WITH_NONCE_IX_LEN,
    VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
    VERIFY_NITRO_MODE_A,
    VERIFY_NITRO_MODE_B,
    derivePolicyRegistryPda,
    deriveSignerPda,
    deriveVcekPda,
} from '../index';
import { deriveUsedNoncePdaForSource, deriveLegacyUsedNoncePda } from '../nonce';

function u64Le(value: bigint | number): Uint8Array {
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigUint64(0, BigInt(value), true);
    return buf;
}

function u32Le(value: number): Uint8Array {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value, true);
    return buf;
}

function readU64Le(data: Uint8Array, offset: number): bigint {
    const copy = data.slice(offset, offset + 8);
    return new DataView(copy.buffer, copy.byteOffset, 8).getBigUint64(0, true);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const part of parts) {
        total += part.length;
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

function toIxData(parts: Uint8Array[]): Buffer {
    return Buffer.from(concatBytes(parts));
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

function requireReport(report: Uint8Array): Uint8Array {
    if (report.length !== SNP_REPORT_SIZE) {
        throw new Error(`SNP report must be exactly ${SNP_REPORT_SIZE} bytes`);
    }
    return report;
}

function reportSigner(report: Uint8Array): Uint8Array {
    return report.slice(0x50, 0x70);
}

function reportNonce(report: Uint8Array): Uint8Array {
    return report.slice(0x70, 0x90);
}

function reportMeasurement(report: Uint8Array): Uint8Array {
    return report.slice(0x90, 0xc0);
}

function reportTcb(report: Uint8Array): bigint {
    return readU64Le(report, 0x180);
}

function reportChipIdHash(report: Uint8Array, endorsementXy?: Uint8Array): Uint8Array {
    const flags = new DataView(report.buffer, report.byteOffset, report.byteLength).getUint32(0x48, true);
    const chip = report.slice(0x1a0, 0x1e0);
    if (((flags >>> 2) & 7) === 1 || chip.every(b => b === 0)) {
        if (!endorsementXy || endorsementXy.length !== 96)
            throw new Error('VLEK reports require a 96-byte endorsement public key X || Y');
        return sha256(endorsementXy);
    }
    return sha256(chip);
}

function requireNitroMode(mode: bigint | number): number {
    const value = typeof mode === 'bigint' ? Number(mode) : mode;
    if (value !== VERIFY_NITRO_MODE_A && value !== VERIFY_NITRO_MODE_B) {
        throw new Error('Nitro mode must be 0 (Mode A) or 1 (Mode B)');
    }
    return value;
}

function requireNitroDocument(document: Uint8Array): Uint8Array {
    if (document.length === 0 || document.length > MAX_NITRO_DOCUMENT_LEN) {
        throw new Error(`Nitro document must be 1 to ${MAX_NITRO_DOCUMENT_LEN} bytes`);
    }
    return document;
}

function requireHash32(value: Uint8Array, label: string): Uint8Array {
    if (value.length !== 32) {
        throw new Error(`${label} must be 32 bytes`);
    }
    return value;
}

/**
 * @internal
 * Test-only internal utility. Not part of the supported client API.
 * The raw report does not fit in {@link PACKET_DATA_SIZE}.
 * Do not submit the instruction to a live cluster.
 *
 * @spec SCC-SDK-002
 */
export function buildRegisterSignerIxOversized(
    payer: PublicKey,
    signer: PublicKey,
    reportData: Uint8Array,
    expiresSlot: bigint | number,
    nonceSlot: bigint | number = 0,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    endorsementXy?: Uint8Array,
): TransactionInstruction {
    void expiresSlot;
    const report = requireReport(reportData);
    if (!bytesEq(reportSigner(report), signer.toBytes())) {
        throw new Error('report workload signer does not match signer pubkey');
    }

    const [policyRegistry] = derivePolicyRegistryPda(programId);
    const [vcek] = deriveVcekPda(reportChipIdHash(report, endorsementXy), reportTcb(report), programId);
    const nonce = reportNonce(report);
    const [signerPda, signerBump] = deriveSignerPda(signer, programId);
    const [noncePda, nonceBump] = deriveUsedNoncePdaForSource(1, signer, nonce, programId);

    const payload = concatBytes([VERIFY_AND_REGISTER_DISCRIMINATOR, u64Le(nonceSlot), report]);
    const data = Buffer.alloc(VERIFY_AND_REGISTER_IX_LEN);
    data.set(payload, 0);
    data.writeUInt8(nonceBump, 8 + 8 + SNP_REPORT_SIZE);
    data.writeUInt8(signerBump, 8 + 8 + SNP_REPORT_SIZE + 1);

    return new TransactionInstruction({
        data,
        keys: [
            { isSigner: true, isWritable: true, pubkey: payer },
            { isSigner: false, isWritable: false, pubkey: policyRegistry },
            { isSigner: false, isWritable: false, pubkey: vcek },
            { isSigner: false, isWritable: true, pubkey: signerPda },
            { isSigner: false, isWritable: true, pubkey: noncePda },
            { isSigner: false, isWritable: false, pubkey: SYSVAR_SLOT_HASHES_PUBKEY },
            { isSigner: false, isWritable: false, pubkey: SYSVAR_CLOCK_PUBKEY },
            { isSigner: false, isWritable: false, pubkey: SystemProgram.programId },
            { isSigner: true, isWritable: false, pubkey: signer },
            { isSigner: false, isWritable: false, pubkey: deriveBackendPolicyPda(1, programId)[0] },
            { isSigner: false, isWritable: false, pubkey: deriveLegacyUsedNoncePda(signer, nonce, programId)[0] },
            {
                isSigner: false,
                isWritable: false,
                pubkey: deriveAmdRevocationPda(reportChipIdHash(report, endorsementXy), programId)[0],
            },
        ],
        programId,
    });
}

/**
 * @internal
 * Test-only internal utility. Not part of the supported client API.
 * The raw report does not fit in {@link PACKET_DATA_SIZE}.
 * Do not submit the transaction to a live cluster.
 *
 * @spec SCC-SDK-002 SCC-SEC-005
 */
export function buildAtomicAttestationTxOversized(
    payer: PublicKey,
    consumerProgramId: PublicKey,
    actionHash: Uint8Array,
    measurement: Uint8Array,
    report: Uint8Array,
    consumerIx: TransactionInstruction,
    recentBlockhash: Blockhash,
    nonceSlot: bigint | number = 0,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    endorsementXy?: Uint8Array,
): Transaction {
    const confidentialComputeIx = buildVerifyAtomicWithNonceIxOversized(
        payer,
        consumerProgramId,
        actionHash,
        measurement,
        report,
        nonceSlot,
        programId,
        endorsementXy,
    );
    const tx = new Transaction({
        feePayer: payer,
        recentBlockhash,
    });
    tx.add(confidentialComputeIx, consumerIx);
    return tx;
}

/**
 * @internal
 * Test-only internal utility. Not part of the supported client API.
 * The raw report does not fit in {@link PACKET_DATA_SIZE}.
 * Do not submit the instruction to a live cluster.
 *
 * @spec SCC-SDK-002 SCC-SEC-005
 */
export function buildVerifyAtomicWithNonceIxOversized(
    payer: PublicKey,
    consumerProgramId: PublicKey,
    actionHash: Uint8Array,
    measurement: Uint8Array,
    reportBytes: Uint8Array,
    nonceSlot: bigint | number = 0,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    endorsementXy?: Uint8Array,
): TransactionInstruction {
    const report = requireReport(reportBytes);
    if (actionHash.length !== 32) {
        throw new Error('actionHash must be 32 bytes');
    }
    if (measurement.length !== 48) {
        throw new Error('measurement must be 48 bytes');
    }
    if (!bytesEq(reportMeasurement(report), measurement)) {
        throw new Error('report measurement does not match expected measurement');
    }

    const signerPubkey = new PublicKey(reportSigner(report));
    const commitment = reportNonce(report);
    const [policyRegistry] = derivePolicyRegistryPda(programId);
    const [vcek] = deriveVcekPda(reportChipIdHash(report, endorsementXy), reportTcb(report), programId);
    const [noncePda, nonceBump] = deriveUsedNoncePdaForSource(1, signerPubkey, commitment, programId);

    const payload = concatBytes([
        VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
        u64Le(nonceSlot),
        actionHash,
        consumerProgramId.toBytes(),
        report,
    ]);
    const data = Buffer.alloc(VERIFY_ATOMIC_WITH_NONCE_IX_LEN);
    data.set(payload, 0);
    data.writeUInt8(nonceBump, 8 + 72 + SNP_REPORT_SIZE);

    return new TransactionInstruction({
        data,
        keys: [
            { isSigner: true, isWritable: true, pubkey: payer },
            { isSigner: false, isWritable: false, pubkey: policyRegistry },
            { isSigner: false, isWritable: false, pubkey: vcek },
            { isSigner: false, isWritable: true, pubkey: noncePda },
            { isSigner: false, isWritable: false, pubkey: SYSVAR_SLOT_HASHES_PUBKEY },
            { isSigner: false, isWritable: false, pubkey: SYSVAR_CLOCK_PUBKEY },
            { isSigner: false, isWritable: false, pubkey: SystemProgram.programId },
            { isSigner: false, isWritable: false, pubkey: SYSVAR_INSTRUCTIONS_PUBKEY },
            { isSigner: false, isWritable: false, pubkey: deriveBackendPolicyPda(1, programId)[0] },
            {
                isSigner: false,
                isWritable: false,
                pubkey: deriveLegacyUsedNoncePda(signerPubkey, commitment, programId)[0],
            },
            {
                isSigner: false,
                isWritable: false,
                pubkey: deriveAmdRevocationPda(reportChipIdHash(report, endorsementXy), programId)[0],
            },
        ],
        programId,
    });
}

/**
 * @internal
 * Test-only internal utility. Not part of the supported client API.
 * Do not submit the instruction to a live cluster.
 *
 * Mode B's attested-signer placeholder is read-only. A writable `0xff..ff`
 * account would take a cluster-wide Sealevel write lock.
 *
 * @spec SCC-NITRO-008 SCC-SDK-002 SCC-SEC-005 SCC-PERF-002
 */
export function buildVerifyNitroAttestationIxOversized(
    payer: PublicKey,
    workloadSigner: PublicKey,
    mode: bigint | number,
    nonceSlot: bigint | number,
    expectedActionHash: Uint8Array,
    document: Uint8Array,
    nonce: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    const resolvedMode = requireNitroMode(mode);
    const doc = requireNitroDocument(document);
    const actionHash = requireHash32(expectedActionHash, 'expectedActionHash');
    const nonceBytes = requireHash32(nonce, 'nonce');

    const [policyRegistry] = derivePolicyRegistryPda(programId);
    const [usedNonce] = deriveUsedNoncePdaForSource(2, workloadSigner, nonceBytes, programId);
    const attestedSigner =
        resolvedMode === VERIFY_NITRO_MODE_A
            ? deriveSignerPda(workloadSigner, programId)[0]
            : NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER;

    const data = toIxData([
        VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
        Uint8Array.of(resolvedMode),
        u64Le(nonceSlot),
        actionHash,
        u32Le(doc.length),
        doc,
    ]);

    const keys = [
        { isSigner: true, isWritable: true, pubkey: payer },
        { isSigner: false, isWritable: false, pubkey: policyRegistry },
        {
            isSigner: false,
            isWritable: resolvedMode === VERIFY_NITRO_MODE_A,
            pubkey: attestedSigner,
        },
        { isSigner: false, isWritable: true, pubkey: usedNonce },
        { isSigner: false, isWritable: false, pubkey: SYSVAR_SLOT_HASHES_PUBKEY },
        { isSigner: false, isWritable: false, pubkey: SYSVAR_CLOCK_PUBKEY },
        { isSigner: false, isWritable: false, pubkey: SystemProgram.programId },
    ];
    if (resolvedMode === VERIFY_NITRO_MODE_A) {
        keys.push({ isSigner: true, isWritable: false, pubkey: workloadSigner });
    }
    if (resolvedMode === VERIFY_NITRO_MODE_B) {
        keys.push({
            isSigner: false,
            isWritable: false,
            pubkey: SYSVAR_INSTRUCTIONS_PUBKEY,
        });
    }

    keys.push({ isSigner: false, isWritable: false, pubkey: deriveBackendPolicyPda(2, programId)[0] });
    keys.push({
        isSigner: false,
        isWritable: false,
        pubkey: deriveLegacyUsedNoncePda(workloadSigner, nonceBytes, programId)[0],
    });
    return new TransactionInstruction({
        data,
        keys,
        programId,
    });
}

/**
 * @internal
 * Test-only internal utility. Not part of the supported client API.
 * Do not submit the transaction to a live cluster.
 *
 * @spec SCC-NITRO-008 SCC-SDK-002 SCC-SEC-005
 */
export function buildVerifyNitroAttestationTxOversized(
    payer: PublicKey,
    workloadSigner: PublicKey,
    mode: bigint | number,
    nonceSlot: bigint | number,
    expectedActionHash: Uint8Array,
    document: Uint8Array,
    nonce: Uint8Array,
    recentBlockhash: Blockhash,
    consumerIx: TransactionInstruction | null = null,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): Transaction {
    const resolvedMode = requireNitroMode(mode);
    if (resolvedMode === VERIFY_NITRO_MODE_B && consumerIx === null) {
        throw new Error('Mode B requires a consumer instruction at index 1');
    }
    const confidentialComputeIx = buildVerifyNitroAttestationIxOversized(
        payer,
        workloadSigner,
        resolvedMode,
        nonceSlot,
        expectedActionHash,
        document,
        nonce,
        programId,
    );
    const tx = new Transaction({
        feePayer: payer,
        recentBlockhash,
    });
    if (consumerIx !== null) {
        tx.add(confidentialComputeIx, consumerIx);
    } else {
        tx.add(confidentialComputeIx);
    }
    return tx;
}
