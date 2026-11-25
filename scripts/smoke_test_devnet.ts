import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Solana Devnet smoke harness for solana-confidential-compute-verifier.
 *
 * @spec SCC-DEPLOY-001 SCC-NITRO-008 SCC-PERF-001
 */
import {
    ComputeBudgetProgram,
    Connection,
    Keypair,
    PublicKey,
    SystemProgram,
    Transaction,
    TransactionInstruction,
    sendAndConfirmTransaction,
} from '@solana/web3.js';

import {
    SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    derivePolicyRegistryPda,
    buildAtomicAttestationTx,
    PacketTooLargeError,
    INIT_POLICY_REGISTRY_DISCRIMINATOR,
    SNP_REPORT_SIZE,
    MAX_NITRO_DOCUMENT_LEN,
    PACKET_DATA_SIZE,
    VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
    VERIFY_NITRO_ATTESTATION_HEADER_LEN,
    VERIFY_NITRO_MODE_A,
    buildVerifyNitroAttestationIx,
    buildVerifyNitroAttestationTx,
} from '../sdks/typescript/src/index';
import { buildVerifyNitroAttestationIxOversized } from '../sdks/typescript/src/internal/oversized';

/** @spec SCC-PERF-001 */
const NITRO_CU_CEILING = 550_000;
const UPGRADEABLE_LOADER_ID = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
// sha256("account:PolicyRegistry")[..8], followed by authority at bytes 8..40.
const POLICY_REGISTRY_DISCRIMINATOR = new Uint8Array([175, 179, 180, 44, 5, 161, 62, 240]);

const CONSUMER_PROGRAM_ID = new PublicKey('A5cSGHXvQmAejZSVu3D1HwMuaVBJnrt2khz7GVy4cUZZ');
const EXPECTED_MEASUREMENT = new Uint8Array(48).fill(0x42);
const ACTION_HASH = new Uint8Array(32).fill(0x11);

async function loadKeypair(path: string): Promise<Keypair> {
    const secretKey = Uint8Array.from(JSON.parse(fs.readFileSync(path, 'utf-8')));
    return await Keypair.fromSecretKey(secretKey);
}

function buildMockReport(signer: PublicKey, measurement: Uint8Array, nonce: Uint8Array): Uint8Array {
    const report = new Uint8Array(SNP_REPORT_SIZE);
    // SMT enabled (bit 17)
    report[8] = 0;
    report[9] = 0;
    report[10] = 2; // (1 << 17) at byte 10
    // Signer pubkey at 0x50..0x70
    report.set(signer.toBytes(), 0x50);
    // Nonce at 0x70..0x90
    report.set(nonce, 0x70);
    // Measurement at 0x90..0xC0
    report.set(measurement, 0x90);
    // TCB at 0x180..0x188
    report[0x180] = 1;
    report[0x181] = 1;
    report[0x186] = 1;
    report[0x187] = 1;
    return report;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
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

function unitsFromLogs(logs: readonly string[], reported?: bigint | number | null): number {
    if (typeof reported === 'number' || typeof reported === 'bigint') {
        return Number(reported);
    }
    for (let i = logs.length - 1; i >= 0; i--) {
        const match = logs[i].match(/consumed (\d+) of (\d+) compute units/);
        if (match) {
            return Number(match[1]);
        }
    }
    throw new Error('compute unit consumption was not present in program logs');
}

function pushCborArg(out: number[], major: number, n: number): void {
    const hi = major << 5;
    if (n <= 23) {
        out.push(hi | n);
        return;
    }
    if (n <= 0xff) {
        out.push(hi | 24, n);
        return;
    }
    if (n <= 0xffff) {
        out.push(hi | 25, (n >> 8) & 0xff, n & 0xff);
        return;
    }
    if (n <= 0xffff_ffff) {
        out.push(hi | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
        return;
    }
    const high = Math.floor(n / 0x1_0000_0000);
    const low = n >>> 0;
    out.push(
        hi | 27,
        (high >>> 24) & 0xff,
        (high >>> 16) & 0xff,
        (high >>> 8) & 0xff,
        high & 0xff,
        (low >>> 24) & 0xff,
        (low >>> 16) & 0xff,
        (low >>> 8) & 0xff,
        low & 0xff,
    );
}

function pushCborBstr(out: number[], bytes: Uint8Array): void {
    pushCborArg(out, 2, bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        out.push(bytes[i]);
    }
}

function pushCborTstr(out: number[], value: string): void {
    const encoded = new TextEncoder().encode(value);
    pushCborArg(out, 3, encoded.length);
    for (let i = 0; i < encoded.length; i++) {
        out.push(encoded[i]);
    }
}

/**
 * Compact tagged COSE Sign1 used for Devnet fail-closed verification.
 * Certificates are placeholders; the on-chain chain check rejects them.
 * @spec SCC-NITRO-008
 */
function buildSyntheticNitroDocument(signer: PublicKey, nonce: Uint8Array): Uint8Array {
    const pcr0 = new Uint8Array(48).fill(0x42);
    const pcr1 = new Uint8Array(48).fill(0x01);
    const pcr2 = new Uint8Array(48).fill(0x02);
    const pcr8 = new Uint8Array(48).fill(0x08);
    const pcrs: number[] = [];
    pushCborArg(pcrs, 5, 4);
    pushCborArg(pcrs, 0, 0);
    pushCborBstr(pcrs, pcr0);
    pushCborArg(pcrs, 0, 1);
    pushCborBstr(pcrs, pcr1);
    pushCborArg(pcrs, 0, 2);
    pushCborBstr(pcrs, pcr2);
    pushCborArg(pcrs, 0, 8);
    pushCborBstr(pcrs, pcr8);

    const cabundle: number[] = [];
    pushCborArg(cabundle, 4, 1);
    pushCborBstr(cabundle, new TextEncoder().encode('MOCK-NITRO-ROOT!'));

    const payload: number[] = [];
    pushCborArg(payload, 5, 8);
    pushCborTstr(payload, 'module_id');
    pushCborTstr(payload, 'i-teton-nitro-mock');
    pushCborTstr(payload, 'timestamp');
    pushCborArg(payload, 0, 1_700_000_000_000);
    pushCborTstr(payload, 'digest');
    pushCborTstr(payload, 'SHA384');
    pushCborTstr(payload, 'pcrs');
    for (let i = 0; i < pcrs.length; i++) {
        payload.push(pcrs[i]);
    }
    pushCborTstr(payload, 'certificate');
    pushCborBstr(payload, new TextEncoder().encode('MOCK-NITRO-LEAF!'));
    pushCborTstr(payload, 'cabundle');
    for (let i = 0; i < cabundle.length; i++) {
        payload.push(cabundle[i]);
    }
    pushCborTstr(payload, 'user_data');
    pushCborBstr(payload, signer.toBytes());
    pushCborTstr(payload, 'nonce');
    pushCborBstr(payload, nonce);

    const protectedHeader = [0xa1, 0x01, 0x38, 0x22];
    const doc: number[] = [0xd2];
    pushCborArg(doc, 4, 4);
    pushCborBstr(doc, Uint8Array.from(protectedHeader));
    pushCborArg(doc, 5, 0);
    pushCborBstr(doc, Uint8Array.from(payload));
    pushCborBstr(doc, new Uint8Array(96));
    return Uint8Array.from(doc);
}

async function main() {
    console.log('================================================================================');
    console.log('SOLANA CONFIDENTIAL COMPUTE — DEVNET E2E SMOKE TEST & VERIFICATION HARNESS');
    console.log('================================================================================');

    const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
    const payerPath =
        process.env.PAYER_KEYPAIR_PATH ||
        process.env.SOLANA_KEYPAIR_PATH ||
        path.join(os.homedir(), '.config/solana/id.json');
    const payer = await loadKeypair(payerPath);

    console.log(`Payer:             ${payer.publicKey.toBase58()}`);
    const balance = await connection.getBalance(payer.publicKey);
    console.log(`Payer Devnet SOL:  ${Number(balance) / 1e9} SOL`);
    console.log(`Solana Confidential Compute Verifier:    ${SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID.toBase58()}`);
    console.log(`Consumer Ref:      ${CONSUMER_PROGRAM_ID.toBase58()}`);

    // 1. Verify program accounts are executable
    const verifierInfo = await connection.getAccountInfo(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    if (!verifierInfo || !verifierInfo.executable) {
        throw new Error(
            `Verifier program ${SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID.toBase58()} is not deployed/executable`,
        );
    }
    console.log(
        `\n[✓] solana-confidential-compute-verifier is executable on Devnet (size: ${verifierInfo.data.length} bytes)`,
    );

    const consumerInfo = await connection.getAccountInfo(CONSUMER_PROGRAM_ID);
    if (!consumerInfo || !consumerInfo.executable) {
        throw new Error(`Consumer program ${CONSUMER_PROGRAM_ID.toBase58()} is not deployed/executable`);
    }
    console.log(
        `[✓] solana-confidential-compute-consumer-reference is executable on Devnet (size: ${consumerInfo.data.length} bytes)`,
    );

    // 2. Check/Initialize PolicyRegistry
    const [policyRegistryPda] = derivePolicyRegistryPda(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID);
    console.log(`\nPolicyRegistry PDA: ${policyRegistryPda.toBase58()}`);
    const registryInfo = await connection.getAccountInfo(policyRegistryPda);

    if (!registryInfo || registryInfo.data.length === 0) {
        const [programDataPda] = await PublicKey.findProgramAddress(
            [SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID.toBytes()],
            UPGRADEABLE_LOADER_ID,
        );
        const programData = await connection.getAccountInfo(programDataPda);
        if (
            !programData ||
            !programData.owner.equals(UPGRADEABLE_LOADER_ID) ||
            programData.data.length < 45 ||
            Buffer.from(programData.data).readUInt32LE(0) !== 3 ||
            programData.data[12] !== 1 ||
            !new PublicKey(programData.data.subarray(13, 45)).equals(payer.publicKey)
        ) {
            throw new Error(
                "Initialization requires the program's current upgrade authority; initialize before finalization",
            );
        }
        console.log('PolicyRegistry not initialized. Initializing...');
        const initData = new Uint8Array(8 + 32 + 96 + 4 + 4 + 8 * 48);
        initData.set(INIT_POLICY_REGISTRY_DISCRIMINATOR, 0);
        // authority
        initData.set(payer.publicKey.toBytes(), 8);
        // ark_pubkey_xy (96 bytes)
        initData.fill(0x01, 40, 136);
        // min_tcb (4 bytes: boot_loader=1, tee=1, snp=1, microcode=1)
        initData[136] = 1;
        initData[137] = 1;
        initData[138] = 1;
        initData[139] = 1;
        // measurement_count = 1 (u32 LE)
        initData[140] = 1;
        initData[141] = 0;
        initData[142] = 0;
        initData[143] = 0;
        // measurement 0 = EXPECTED_MEASUREMENT (48 bytes)
        initData.set(EXPECTED_MEASUREMENT, 144);

        const initIx = new TransactionInstruction({
            programId: SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
            keys: [
                { pubkey: payer.publicKey, isSigner: true, isWritable: true },
                { pubkey: policyRegistryPda, isSigner: false, isWritable: true },
                { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
                { pubkey: programDataPda, isSigner: false, isWritable: false },
            ],
            data: Buffer.from(initData),
        });

        const tx = new Transaction().add(initIx);
        const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
        console.log(`[✓] PolicyRegistry initialized: https://explorer.solana.com/tx/${sig}?cluster=devnet`);
    } else {
        if (
            !registryInfo.owner.equals(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID) ||
            registryInfo.data.length !== 529 ||
            !bytesEqual(registryInfo.data.subarray(0, 8), POLICY_REGISTRY_DISCRIMINATOR) ||
            !new PublicKey(registryInfo.data.subarray(8, 40)).equals(payer.publicKey)
        ) {
            throw new Error(
                'Existing PolicyRegistry is invalid or controlled by another authority; refusing to continue',
            );
        }
        console.log('[✓] PolicyRegistry already initialized with the expected authority on Devnet');
    }

    // 3. Test Mode B Atomic Attestation Introspection
    console.log('\n--------------------------------------------------------------------------------');
    console.log('TEST: Mode B Atomic Attestation & Downstream Consumer Introspection');
    console.log('--------------------------------------------------------------------------------');

    const nonce = new Uint8Array(32).fill(0x99);
    const mockSigner = await Keypair.generate();
    const mockReport = buildMockReport(mockSigner.publicKey, EXPECTED_MEASUREMENT, nonce);

    // Consumer instruction: IX_EXECUTE_ATOMIC_ACTION (1) + payload.
    // The reference consumer hashes this payload with `hash_action`.
    const consumerData = new Uint8Array([1, 0xab, 0xcd]);

    const consumerIx = new TransactionInstruction({
        programId: CONSUMER_PROGRAM_ID,
        keys: [
            {
                pubkey: new PublicKey('Sysvar1nstructions1111111111111111111111111'),
                isSigner: false,
                isWritable: false,
            },
        ],
        data: Buffer.from(consumerData),
    });

    const { blockhash } = await connection.getLatestBlockhash();
    console.log('Checking Mode B raw-report packet against the 1,232-byte cap...');
    try {
        buildAtomicAttestationTx(
            payer.publicKey,
            CONSUMER_PROGRAM_ID,
            ACTION_HASH,
            EXPECTED_MEASUREMENT,
            mockReport,
            consumerIx,
            blockhash,
            0n,
            SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        );
        throw new Error('raw Mode B report must fail closed before RPC submission');
    } catch (err) {
        if (!(err instanceof PacketTooLargeError)) {
            throw err;
        }
        console.log(`[✓] Mode B raw report rejected locally (${err.len} bytes > 1,232). Not submitted.`);
    }

    // 4. Nitro Mode A: packet ceiling, oversized packer, live fail-closed CU.
    // @spec SCC-NITRO-008 SCC-PERF-001
    console.log('\n--------------------------------------------------------------------------------');
    console.log('TEST: Nitro verify_nitro_attestation Mode A (SCC-NITRO-008)');
    console.log('--------------------------------------------------------------------------------');

    const nitroSigner = await Keypair.generate();
    const nitroNonce = new Uint8Array(32).fill(0x55);
    const nitroActionHash = new Uint8Array(32);
    const nitroDocument = buildSyntheticNitroDocument(nitroSigner.publicKey, nitroNonce);
    console.log(`Synthetic COSE Sign1: ${nitroDocument.length} bytes`);

    const oversizedIx = buildVerifyNitroAttestationIxOversized(
        payer.publicKey,
        nitroSigner.publicKey,
        VERIFY_NITRO_MODE_A,
        0n,
        nitroActionHash,
        nitroDocument,
        nitroNonce,
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    );
    if (oversizedIx.data.length !== VERIFY_NITRO_ATTESTATION_HEADER_LEN + nitroDocument.length) {
        throw new Error('Nitro oversized packer produced an unexpected payload length');
    }
    if (!bytesEqual(oversizedIx.data.subarray(0, 8), VERIFY_NITRO_ATTESTATION_DISCRIMINATOR)) {
        throw new Error('Nitro oversized packer emitted a wrong discriminator');
    }
    if (oversizedIx.data[8] !== VERIFY_NITRO_MODE_A) {
        throw new Error('Nitro oversized packer emitted a wrong mode');
    }
    console.log(`[✓] Oversized packer: disc + mode A + header + ${nitroDocument.length}-byte document`);

    console.log(`Checking a ${MAX_NITRO_DOCUMENT_LEN}-byte Nitro document against the ${PACKET_DATA_SIZE}-byte cap...`);
    try {
        buildVerifyNitroAttestationIx(
            payer.publicKey,
            nitroSigner.publicKey,
            VERIFY_NITRO_MODE_A,
            0n,
            nitroActionHash,
            new Uint8Array(MAX_NITRO_DOCUMENT_LEN).fill(0xab),
            nitroNonce,
            SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        );
        throw new Error('max-size Nitro document must fail closed before RPC submission');
    } catch (err) {
        if (!(err instanceof PacketTooLargeError)) {
            throw err;
        }
        console.log(
            `[✓] Nitro max-size document rejected locally (${err.len} bytes > ${PACKET_DATA_SIZE}). Not submitted.`,
        );
    }

    const { blockhash: nitroBlockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    const packedTx = buildVerifyNitroAttestationTx(
        payer.publicKey,
        nitroSigner.publicKey,
        VERIFY_NITRO_MODE_A,
        0n,
        nitroActionHash,
        nitroDocument,
        nitroNonce,
        nitroBlockhash,
        null,
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    );
    console.log(
        `[✓] Standard Mode A builder packed a ${nitroDocument.length}-byte document within ${PACKET_DATA_SIZE} bytes`,
    );

    const nitroIx = buildVerifyNitroAttestationIx(
        payer.publicKey,
        nitroSigner.publicKey,
        VERIFY_NITRO_MODE_A,
        0n,
        nitroActionHash,
        nitroDocument,
        nitroNonce,
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    );
    const nitroTx = new Transaction({
        feePayer: payer.publicKey,
        recentBlockhash: nitroBlockhash,
    }).add(ComputeBudgetProgram.setComputeUnitLimit({ units: NITRO_CU_CEILING }), nitroIx);
    if (packedTx.instructions.length !== 1) {
        throw new Error('Nitro Mode A transaction must contain a single Solana Confidential Compute instruction');
    }

    const sim = await connection.simulateTransaction(nitroTx, [payer]);
    const simLogs = sim.value.logs ?? [];
    const simCus = unitsFromLogs(simLogs, sim.value.unitsConsumed);
    console.log('Simulation logs:');
    for (const line of simLogs) {
        console.log(`  ${line}`);
    }
    if (simCus > NITRO_CU_CEILING) {
        throw new Error(`@spec SCC-PERF-001 violated: Nitro Mode A consumed ${simCus} CUs > ${NITRO_CU_CEILING}`);
    }
    if (sim.value.err === null) {
        console.log(`[✓] Nitro Mode A simulation succeeded (${simCus} CUs / ${NITRO_CU_CEILING})`);
    } else {
        console.log(
            `[✓] Nitro Mode A fail-closed in simulation (${JSON.stringify(sim.value.err)}; ${simCus} CUs / ${NITRO_CU_CEILING})`,
        );
    }

    const sig = await connection.sendTransaction(nitroTx, [payer], {
        skipPreflight: true,
    });
    await connection.confirmTransaction(
        { signature: sig, blockhash: nitroBlockhash, lastValidBlockHeight },
        'confirmed',
    );
    const landed = await connection.getTransaction(sig, {
        commitment: 'confirmed',
        maxSupportedTransactionVersion: 0,
    });
    if (!landed || !landed.meta) {
        throw new Error(`Nitro Mode A transaction ${sig} was not found on Devnet`);
    }
    const liveLogs = landed.meta.logMessages ?? [];
    const liveCus = unitsFromLogs(liveLogs, landed.meta.computeUnitsConsumed);
    if (liveCus > NITRO_CU_CEILING) {
        throw new Error(`@spec SCC-PERF-001 violated: Nitro Mode A consumed ${liveCus} CUs > ${NITRO_CU_CEILING}`);
    }
    console.log(`Nitro Mode A signature: ${sig}`);
    console.log(`Explorer: https://explorer.solana.com/tx/${sig}?cluster=devnet`);
    console.log('On-chain logs:');
    for (const line of liveLogs) {
        console.log(`  ${line}`);
    }
    if (landed.meta.err === null) {
        console.log(`[✓] Nitro Mode A landed successfully (${liveCus} CUs / ${NITRO_CU_CEILING})`);
    } else {
        console.log(
            `[✓] Nitro Mode A fail-closed on Devnet (${JSON.stringify(landed.meta.err)}; ${liveCus} CUs / ${NITRO_CU_CEILING})`,
        );
    }

    console.log('\n================================================================================');
    console.log('DEVNET SMOKE TEST COMPLETED SUCCESSFULLY');
    console.log('================================================================================');
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
