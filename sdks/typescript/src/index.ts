/**
 * TypeScript client SDK for Solana Confidential Compute.
 *
 * @spec SCC-SDK-002 SCC-SEC-005 SCC-NITRO-008
 */

import { sha256 } from '@noble/hashes/sha256';
import {
    Keypair,
    PublicKey,
    AccountMeta,
    Message,
    MessageV0,
    Transaction,
    TransactionInstruction,
} from '@solana/web3.js';

import {
    buildAtomicAttestationTxOversized,
    buildRegisterSignerIxOversized,
    buildVerifyAtomicWithNonceIxOversized,
    buildVerifyNitroAttestationIxOversized,
    buildVerifyNitroAttestationTxOversized,
} from './internal/oversized';

/** Canonical solana-confidential-compute-verifier program id. */
export const SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID = new PublicKey('EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh');

/** V2 cache namespace; old caches require full chain revalidation. */
export const VCEK_SEED = 'vcek_v2';
export const SNP_REPORT_SIZE = 1184;
export const ATTESTATION_TTL_SLOTS = 216_000n;
export const MODE_B_REQUIRE_NONCE_DEFAULT = true;

/** Legacy cluster UDP cap. A serialized transaction above this cannot land. */
export const PACKET_DATA_SIZE = 1232;
/** Discriminator + nonce slot + report + nonce bump + signer bump (1,202). @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001 */
export const VERIFY_AND_REGISTER_IX_LEN = 8 + 8 + SNP_REPORT_SIZE + 2;
/** Discriminator + VerifyAtomicHeader + report + nonce bump (1,265). @spec SCC-SEC-008 SCC-ARCH-001 SCC-SDK-001 */
export const VERIFY_ATOMIC_WITH_NONCE_IX_LEN = 8 + 72 + SNP_REPORT_SIZE + 1;

/** Thrown when a raw 1,184-byte report cannot fit in {@link PACKET_DATA_SIZE}. */
export class PacketTooLargeError extends Error {
    readonly len: number;

    constructor(len: number) {
        super(`serialized transaction is ${len} bytes and exceeds the ${PACKET_DATA_SIZE}-byte packet limit`);
        this.name = 'PacketTooLargeError';
        this.len = len;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export const INIT_POLICY_REGISTRY_DISCRIMINATOR = new Uint8Array([90, 53, 0, 89, 164, 70, 107, 186]);
export const VERIFY_AND_REGISTER_DISCRIMINATOR = new Uint8Array([246, 249, 100, 14, 102, 116, 92, 145]);
export const VERIFY_ATOMIC_DISCRIMINATOR = new Uint8Array([65, 19, 195, 149, 67, 219, 25, 75]);
export const VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR = new Uint8Array([209, 4, 10, 239, 3, 142, 223, 250]);
export const ATTESTED_SIGNER_DISCRIMINATOR = new Uint8Array([43, 255, 114, 40, 233, 28, 127, 238]);
/** `sha256("global:verify_nitro_attestation")[..8]`. @spec SCC-NITRO-008 */
export const VERIFY_NITRO_ATTESTATION_DISCRIMINATOR = new Uint8Array([107, 76, 178, 169, 215, 146, 23, 95]);
/** Mode A: register `AttestedSignerAccount` (`enclave_type = AwsNitro`). */
export const VERIFY_NITRO_MODE_A = 0;
/** Mode B: action commitment + nonce tombstone. @spec SCC-SEC-005 */
export const VERIFY_NITRO_MODE_B = 1;
/** Maximum COSE Sign1 document length accepted on-chain (accommodates 4-certificate AWS PKI chain). */
export const MAX_NITRO_DOCUMENT_LEN = 8192;
/**
 * Discriminator (8) + mode (1) + nonce_slot (8) + expected_action_hash (32) +
 * doc_len (4). Document bytes follow.
 */
export const VERIFY_NITRO_ATTESTATION_HEADER_LEN = 8 + 1 + 8 + 32 + 4;

export const ATTESTED_SIGNER_ACCOUNT_SIZE = 154;

/** Packed 154-byte V2 Mode A `AttestedSignerAccount`. */
export interface AttestedSignerAccount {
    discriminator: Uint8Array;
    signerPubkey: Uint8Array;
    enclaveType: number;
    measurement: Uint8Array;
    chipIdHash: Uint8Array;
    tcbVersion: bigint;
    registeredSlot: bigint;
    expiresSlot: bigint;
    bump: number;
    expiresUnixTimestamp: bigint;
}

/** Consumer-side Mode B expectation. `requireNonce` defaults to true. */
export interface AtomicAttestationExpectation {
    actionHash: Uint8Array;
    expectedMeasurement: Uint8Array;
    expectedSigner: Uint8Array | null;
    requireNonce: boolean;
    verifierIxIndex: number | null;
    /** @deprecated Use `verifierIxIndex` */
    confidentialComputeIxIndex?: number | null;
}

export function defaultAtomicAttestationExpectation(): AtomicAttestationExpectation {
    return {
        actionHash: new Uint8Array(32),
        confidentialComputeIxIndex: null,
        expectedMeasurement: new Uint8Array(48),
        expectedSigner: null,
        requireNonce: MODE_B_REQUIRE_NONCE_DEFAULT,
        verifierIxIndex: null,
    };
}

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

function seed(label: string): Uint8Array {
    return new TextEncoder().encode(label);
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

/** Blockhash bytes do not change the serialized length. */
const PACKET_PROBE_BLOCKHASH = PublicKey.default.toBase58();

function shortvecLen(len: number): number {
    if (len < 128) {
        return 1;
    }
    if (len < 16384) {
        return 2;
    }
    return 3;
}

/**
 * Legacy wire length.
 *
 * `Transaction.serialize` rejects packets above {@link PACKET_DATA_SIZE}, and
 * `Message.serialize` allocates only that many bytes for instruction data.
 * Account keys come from the compiled message. Instruction payloads are read
 * from the source buffers so the check does not walk a base58 BigInt.
 *
 * @spec SCC-SDK-002 SCC-PERF-002
 */
function legacyPacketLen(tx: Transaction): number {
    const message = tx.compileMessage();
    const signatures = message.header.numRequiredSignatures;
    let messageLen = 3 + shortvecLen(message.accountKeys.length) + message.accountKeys.length * 32 + 32;
    messageLen += shortvecLen(message.instructions.length);
    for (let i = 0; i < message.instructions.length; i++) {
        const ix = message.instructions[i];
        const dataLen = tx.instructions[i].data.length;
        messageLen += 1;
        messageLen += shortvecLen(ix.accounts.length);
        messageLen += ix.accounts.length;
        messageLen += shortvecLen(dataLen);
        messageLen += dataLen;
    }
    return shortvecLen(signatures) + signatures * 64 + messageLen;
}

function assertPacketFits(tx: Transaction): void {
    const len = legacyPacketLen(tx);
    if (len > PACKET_DATA_SIZE) {
        throw new PacketTooLargeError(len);
    }
}

function probePacket(payer: PublicKey, ixs: TransactionInstruction[]): void {
    const tx = new Transaction({
        feePayer: payer,
        recentBlockhash: PACKET_PROBE_BLOCKHASH,
    });
    tx.add(...ixs);
    assertPacketFits(tx);
}

/**
 * Derives the `AttestedSignerAccount` PDA.
 *
 * @spec SCC-SDK-002
 */
export function deriveSignerPda(
    signer: PublicKey,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([seed('attested_signer_v2'), signer.toBytes()], programId);
}

/**
 * Derives the PolicyRegistry singleton PDA.
 *
 * @spec SCC-SDK-002
 */
export function derivePolicyRegistryPda(
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    return PublicKey.findProgramAddressSync([seed('policy_registry')], programId);
}

/**
 * Derives the cached VCEK PDA.
 *
 * @spec SCC-SDK-002
 */
export function deriveVcekPda(
    chipIdHash: Uint8Array,
    tcbVersion: bigint | number,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    if (chipIdHash.length !== 32) {
        throw new Error('chipIdHash must be 32 bytes');
    }
    return PublicKey.findProgramAddressSync([seed(VCEK_SEED), chipIdHash, u64Le(tcbVersion)], programId);
}

/** Zero-copy decode of a 154-byte V2 `AttestedSignerAccount`. */
export function parseAttestedSignerAccount(data: Uint8Array): AttestedSignerAccount {
    if (data.length < ATTESTED_SIGNER_ACCOUNT_SIZE) {
        throw new Error('AttestedSignerAccount buffer too short');
    }
    const discriminator = data.slice(0, 8);
    if (!bytesEq(discriminator, ATTESTED_SIGNER_DISCRIMINATOR)) {
        throw new Error('invalid AttestedSignerAccount discriminator');
    }
    return {
        bump: data[145],
        chipIdHash: data.slice(89, 121),
        discriminator,
        enclaveType: data[40],
        expiresSlot: readU64Le(data, 137),
        expiresUnixTimestamp: new DataView(data.buffer, data.byteOffset + 146, 8).getBigInt64(0, true),
        measurement: data.slice(41, 89),
        registeredSlot: readU64Le(data, 129),
        signerPubkey: data.slice(8, 40),
        tcbVersion: readU64Le(data, 121),
    };
}

/** V3 only: V1 pubkey-only digests are never accepted by the consumer. */
export const ACTION_COMMITMENT_DOMAIN = new TextEncoder().encode('solana-confidential-compute:action:v1\0');

/** Hash EFFECTIVE metas from AccountInfo or the complete compiled message.
 * Isolated instruction metas do not include payer/other-instruction elevation.
 * @spec SCC-VERIFY-014 SCC-SDK-002
 */
export function hashAction(discriminator: Uint8Array, accounts: AccountMeta[], data: Uint8Array): Uint8Array {
    const parts: Uint8Array[] = [ACTION_COMMITMENT_DOMAIN, u32Le(accounts.length)];
    for (const account of accounts) {
        if (
            typeof account.isSigner !== 'boolean' ||
            typeof account.isWritable !== 'boolean' ||
            !(account.pubkey instanceof PublicKey)
        ) {
            throw new Error('V3 requires effective pubkey/isSigner/isWritable metas; legacy pubkeys rejected');
        }
        parts.push(account.pubkey.toBytes(), Uint8Array.of(Number(account.isSigner), Number(account.isWritable)));
    }
    parts.push(u32Le(discriminator.length + data.length), discriminator, data);
    return sha256(concatBytes(parts));
}

// Solana 2.3.1 SDK ReservedAccountKeys::all_keys_iter (active AND pending).
// Reject requested writes to these keys rather than guessing feature activation.
// The Rust test `vendored_reserved_keys_match_the_typescript_sdk` parses this list.
// It needs one double-quoted key on each line, so Oxfmt must not change the quotes.
// oxfmt-ignore
const RESERVED_ACTION_KEYS = new Set([
    "AddressLookupTab1e1111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Config1111111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "Feature111111111111111111111111111111111111",
    "LoaderV411111111111111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
    "StakeConfig11111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "Sysvar1111111111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111",
    "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111",
    "Sysvar1nstructions1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarRent111111111111111111111111111111111",
    "SysvarRewards111111111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarS1otHistory11111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
    "ZkTokenProof1111111111111111111111111111111",
    "ZkE1Gama1Proof11111111111111111111111111111",
]);

/** Compile all final instruction account metadata BEFORE obtaining evidence;
 * other instructions' data can be empty. The consumer's data must be final.
 * Digest-derived nonce/upload accounts must not be consumer accounts (a hash
 * fixed point would be required). Validate the final assembled message again.
 * Reject unresolved LUTs and writable reserved accounts; apply Solana program
 * id demotion, including the upgradeable-loader exception.
 */
export function hashCompiledAction(message: Message | MessageV0, consumerIndex: number, _splitHint = 0): Uint8Array {
    if (message instanceof MessageV0 && message.addressTableLookups.length !== 0)
        throw new Error('unresolved address tables');
    const keys = message instanceof Message ? message.accountKeys : message.staticAccountKeys;
    const {
        numRequiredSignatures: signed,
        numReadonlySignedAccounts: roSigned,
        numReadonlyUnsignedAccounts: roUnsigned,
    } = message.header;
    const ixs = message.compiledInstructions;
    if (
        keys.length > 256 ||
        signed > keys.length ||
        roSigned > signed ||
        roUnsigned > keys.length - signed ||
        new Set(keys.map(k => k.toBase58())).size !== keys.length ||
        ixs.some(ix => ix.programIdIndex >= keys.length || ix.accountKeyIndexes.some(i => i >= keys.length))
    )
        throw new Error('malformed message');
    const ix = ixs[consumerIndex];
    if (!Number.isInteger(consumerIndex) || !ix) throw new Error('invalid consumer schema');
    const upgradeable = keys.some(k => k.toBase58() === 'BPFLoaderUpgradeab1e11111111111111111111111');
    const accounts = ix.accountKeyIndexes.map(i => {
        const pubkey = keys[i];
        const requestedWritable = message.isAccountWritable(i);
        if (requestedWritable && RESERVED_ACTION_KEYS.has(pubkey.toBase58()))
            throw new Error('writable reserved account');
        return {
            isSigner: message.isAccountSigner(i),
            isWritable: requestedWritable && (upgradeable || !ixs.some(other => other.programIdIndex === i)),
            pubkey,
        };
    });
    return hashAction(new Uint8Array(), accounts, ix.data);
}

/** Reject legacy digests and privilege changes after metadata preparation. */
export function validateCompiledAction(message: Message | MessageV0, index: number, expected: Uint8Array): void {
    if (bytesEq(hashCompiledAction(message, index), expected)) return;
    throw new Error('consumer does not match V3 effective-privilege commitment');
}

/**
 * SHA-256(`slotHash || actionHash || consumerProgramId`).
 *
 * @spec SCC-VERIFY-012 SCC-SDK-002
 */
export function computeCommitment(
    slotHash: Uint8Array,
    actionHash: Uint8Array,
    consumerProgramId: PublicKey,
): Uint8Array {
    const concat = new Uint8Array(96);
    concat.set(slotHash, 0);
    concat.set(actionHash, 32);
    concat.set(consumerProgramId.toBytes(), 64);
    return sha256(concat);
}

/**
 * Mode A enrollment: `verify_and_register`.
 *
 * Throws {@link PacketTooLargeError} for a raw 1,184-byte report.
 * The quarantined packer lives in `internal/oversized`.
 *
 * `expiresSlot` is caller-side bookkeeping only; on-chain expiry is computed
 * by `clock.slot + ATTESTATION_TTL_SLOTS`. The verifier writes that TTL from
 * `Clock` and does not read this argument.
 *
 * @spec SCC-SDK-002
 */
export function buildRegisterSignerIx(
    payer: PublicKey,
    signer: PublicKey,
    reportData: Uint8Array,
    expiresSlot: bigint | number,
    nonceSlot: bigint | number = 0,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    endorsementXy?: Uint8Array,
): TransactionInstruction {
    const ix = buildRegisterSignerIxOversized(
        payer,
        signer,
        reportData,
        expiresSlot,
        nonceSlot,
        programId,
        endorsementXy,
    );
    probePacket(payer, [ix]);
    return ix;
}

/**
 * Mode A execution: consumer instruction signed by the attested workload key.
 *
 * Keep the workload key inside the enclave; production remote callers should
 * use sidecar `/v1/sign`. This local helper rejects all System Program
 * instructions. It does not authenticate custom consumers or screen their data:
 * callers must apply their application policy before invoking it.
 *
 * @spec SCC-SDK-002
 */
export function buildSessionActionTx(
    payer: PublicKey,
    signerKeypair: Keypair,
    consumerIx: TransactionInstruction,
    recentBlockhash: string,
): Transaction {
    if (consumerIx.programId.equals(PublicKey.default)) {
        throw new Error('workload keys must not sign System Program instructions');
    }
    const signerPk = signerKeypair.publicKey;
    let found = false;
    const keys = consumerIx.keys.map(meta => {
        if (!meta.pubkey.equals(signerPk)) {
            return meta;
        }
        found = true;
        return {
            isSigner: true,
            isWritable: meta.isWritable,
            pubkey: meta.pubkey,
        };
    });
    if (!found && !signerPk.equals(payer)) {
        keys.push({
            isSigner: true,
            isWritable: false,
            pubkey: signerPk,
        });
    }
    const ix = new TransactionInstruction({
        data: consumerIx.data,
        keys,
        programId: consumerIx.programId,
    });
    const tx = new Transaction({
        feePayer: payer,
        recentBlockhash,
    });
    tx.add(ix);
    tx.partialSign(signerKeypair);
    assertPacketFits(tx);
    return tx;
}

/**
 * Mode B atomic transaction: `verify_atomic_with_nonce` at index 0, consumer at index 1.
 *
 * Always packs `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR` (`requireNonce === true`).
 * Throws {@link PacketTooLargeError} for a raw 1,184-byte report.
 * The quarantined packer lives in `internal/oversized`.
 *
 * @spec SCC-SDK-002 SCC-SEC-005
 */
export function buildAtomicAttestationTx(
    payer: PublicKey,
    consumerProgramId: PublicKey,
    actionHash: Uint8Array,
    measurement: Uint8Array,
    report: Uint8Array,
    consumerIx: TransactionInstruction,
    recentBlockhash: string,
    nonceSlot: bigint | number = 0,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    endorsementXy?: Uint8Array,
): Transaction {
    const tx = buildAtomicAttestationTxOversized(
        payer,
        consumerProgramId,
        actionHash,
        measurement,
        report,
        consumerIx,
        recentBlockhash,
        nonceSlot,
        programId,
        endorsementXy,
    );
    assertPacketFits(tx);
    validateCompiledAction(tx.compileMessage(), 1, actionHash);
    return tx;
}

/**
 * Packs `verify_atomic_with_nonce` (never the fail-closed `verify_atomic` path).
 *
 * Throws {@link PacketTooLargeError} for a raw 1,184-byte report.
 *
 * @spec SCC-SDK-002 SCC-SEC-005
 */
export function buildVerifyAtomicWithNonceIx(
    payer: PublicKey,
    consumerProgramId: PublicKey,
    actionHash: Uint8Array,
    measurement: Uint8Array,
    reportBytes: Uint8Array,
    nonceSlot: bigint | number = 0,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    endorsementXy?: Uint8Array,
): TransactionInstruction {
    const ix = buildVerifyAtomicWithNonceIxOversized(
        payer,
        consumerProgramId,
        actionHash,
        measurement,
        reportBytes,
        nonceSlot,
        programId,
        endorsementXy,
    );
    probePacket(payer, [ix]);
    return ix;
}

/** Uninitialized attested-signer placeholder for Mode B. The program does not write it. */
export const NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER = new PublicKey(new Uint8Array(32).fill(0xff));

/**
 * Packs `verify_nitro_attestation` (Mode A or Mode B).
 *
 * Throws {@link PacketTooLargeError} when the legacy packet exceeds
 * {@link PACKET_DATA_SIZE}. The quarantined packer lives in
 * `internal/oversized`.
 *
 * `nonce` is the 32-byte document nonce: the SlotHashes entry in Mode A, and
 * the action commitment in Mode B (`SHA-256(slotHash || actionHash ||
 * consumerProgramId)`).
 *
 * @spec SCC-NITRO-008 SCC-SDK-002 SCC-SEC-005
 */
export function buildVerifyNitroAttestationIx(
    payer: PublicKey,
    workloadSigner: PublicKey,
    mode: bigint | number,
    nonceSlot: bigint | number,
    expectedActionHash: Uint8Array,
    document: Uint8Array,
    nonce: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    const ix = buildVerifyNitroAttestationIxOversized(
        payer,
        workloadSigner,
        mode,
        nonceSlot,
        expectedActionHash,
        document,
        nonce,
        programId,
    );
    probePacket(payer, [ix]);
    return ix;
}

/**
 * Builds a `verify_nitro_attestation` transaction.
 *
 * Mode B packs the Solana Confidential Compute instruction at index 0 and the consumer instruction
 * at index 1 (`requireNonce` is always true). Mode A packs the Solana Confidential Compute
 * instruction and appends `consumerIx` when the caller provides one.
 *
 * Throws {@link PacketTooLargeError} when the legacy packet exceeds
 * {@link PACKET_DATA_SIZE}. The quarantined packer lives in
 * `internal/oversized`.
 *
 * @spec SCC-NITRO-008 SCC-SDK-001 SCC-SDK-002 SCC-SEC-005
 */
export function buildVerifyNitroAttestationTx(
    payer: PublicKey,
    workloadSigner: PublicKey,
    mode: bigint | number,
    nonceSlot: bigint | number,
    expectedActionHash: Uint8Array,
    document: Uint8Array,
    nonce: Uint8Array,
    recentBlockhash: string,
    consumerIx: TransactionInstruction | null = null,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): Transaction {
    const tx = buildVerifyNitroAttestationTxOversized(
        payer,
        workloadSigner,
        mode,
        nonceSlot,
        expectedActionHash,
        document,
        nonce,
        recentBlockhash,
        consumerIx,
        programId,
    );
    assertPacketFits(tx);
    if (Number(mode) === VERIFY_NITRO_MODE_B) validateCompiledAction(tx.compileMessage(), 1, expectedActionHash);
    return tx;
}

/** BackendPolicy controls runtime admission. Empty each relevant backend policy
 * to stop new AMD/Nitro/GCP admissions. Global registry measurements are
 * deprecated as runtime controls (ABI retained); minTcb remains monotonic.
 * Existing Mode A signer records require separate revocation. */
export * from './backend-policy';
export * from './nvidia';
/** V2 time check using trusted cluster Clock values. Does not verify account
 * owner/PDA/platform; authenticate those before using the decoded data. */
export function isAttestedSignerValid(data: Uint8Array, currentSlot: bigint, currentUnixTimestamp: bigint): boolean {
    const account = parseAttestedSignerAccount(data);
    return (
        currentUnixTimestamp >= 0n &&
        currentUnixTimestamp < account.expiresUnixTimestamp &&
        currentSlot <= account.expiresSlot
    );
}
export * from './gcp-policy';
export * from './governance';
export * from './nonce';
