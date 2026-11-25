const assert = require('node:assert/strict');
const test = require('node:test');
const { Keypair, PublicKey, TransactionInstruction } = require('@solana/web3.js');
const {
    MAX_NITRO_DOCUMENT_LEN,
    PACKET_DATA_SIZE,
    PacketTooLargeError,
    SNP_REPORT_SIZE,
    VERIFY_AND_REGISTER_IX_LEN,
    VERIFY_ATOMIC_WITH_NONCE_IX_LEN,
    VERIFY_NITRO_ATTESTATION_HEADER_LEN,
    VERIFY_NITRO_MODE_A,
    VERIFY_NITRO_MODE_B,
    buildAtomicAttestationTx,
    buildRegisterSignerIx,
    buildSessionActionTx,
    buildVerifyNitroAttestationIx,
    buildVerifyNitroAttestationTx,
    computeCommitment,
    deriveSignerPda,
    deriveUsedNoncePdaForSource,
    hashAction,
} = require('../dist/index.js');
const {
    buildAtomicAttestationTxOversized,
    buildRegisterSignerIxOversized,
    buildVerifyNitroAttestationIxOversized,
    buildVerifyNitroAttestationTxOversized,
} = require('../dist/internal/oversized.js');

function sampleReport(signer) {
    const report = new Uint8Array(SNP_REPORT_SIZE);
    report.fill(9, 0x1a0, 0x1e0);
    report.set(signer.toBytes(), 0x50);
    report.set(new Uint8Array(32).fill(0x55), 0x70);
    report.set(new Uint8Array(48).fill(0x42), 0x90);
    return report;
}

function expectPacketTooLarge(fn) {
    try {
        fn();
    } catch (err) {
        assert.ok(err instanceof PacketTooLargeError, `expected PacketTooLargeError, got ${err}`);
        assert.ok(err.len > PACKET_DATA_SIZE, `packet len ${err.len} is within the cap`);
        return err.len;
    }
    assert.fail('expected PacketTooLargeError');
}

test('raw report builders fail closed above PACKET_DATA_SIZE', () => {
    const payer = Keypair.generate().publicKey;
    const signer = Keypair.generate().publicKey;
    const report = sampleReport(signer);
    // Enrollment now requires both payer and workload signatures plus the legacy replay guard.
    assert.equal(
        expectPacketTooLarge(() => buildRegisterSignerIx(payer, signer, report, 1)),
        1800,
    );

    const consumer = Keypair.generate().publicKey;
    const consumerIx = new TransactionInstruction({
        programId: consumer,
        keys: [{ pubkey: payer, isSigner: true, isWritable: true }],
        data: Buffer.from([1, 2]),
    });
    const measurement = new Uint8Array(48).fill(0x42);
    const atomicLen = expectPacketTooLarge(() =>
        buildAtomicAttestationTx(
            payer,
            consumer,
            new Uint8Array(32).fill(0x11),
            measurement,
            report,
            consumerIx,
            payer.toBase58(),
        ),
    );
    assert.ok(atomicLen > 1602);
});

test('oversized packers still emit the raw report layout', () => {
    const payer = Keypair.generate().publicKey;
    const signer = Keypair.generate().publicKey;
    const report = sampleReport(signer);
    const ix = buildRegisterSignerIxOversized(payer, signer, report, 1);
    assert.equal(ix.data.length, VERIFY_AND_REGISTER_IX_LEN);
    assert.equal(VERIFY_AND_REGISTER_IX_LEN, 1202);
    const nonce = report.slice(0x70, 0x90);
    const [, nonceBump] = deriveUsedNoncePdaForSource(1, signer, nonce);
    const [, signerBump] = deriveSignerPda(signer);
    assert.equal(ix.data[8 + 8 + SNP_REPORT_SIZE], nonceBump);
    assert.equal(ix.data[8 + 8 + SNP_REPORT_SIZE + 1], signerBump);

    const consumer = PublicKey.unique();
    const consumerIx = new TransactionInstruction({
        programId: consumer,
        keys: [{ pubkey: payer, isSigner: true, isWritable: true }],
        data: Buffer.from([1, 2]),
    });
    const tx = buildAtomicAttestationTxOversized(
        payer,
        consumer,
        new Uint8Array(32).fill(0x11),
        new Uint8Array(48).fill(0x42),
        report,
        consumerIx,
        payer.toBase58(),
    );
    assert.equal(tx.instructions[0].data.length, VERIFY_ATOMIC_WITH_NONCE_IX_LEN);
    assert.equal(VERIFY_ATOMIC_WITH_NONCE_IX_LEN, 1265);
    assert.equal(tx.instructions[0].data[8 + 72 + SNP_REPORT_SIZE], nonceBump);
});

test('buildSessionActionTx marks an existing workload account as signer', () => {
    const payer = Keypair.generate().publicKey;
    const signer = Keypair.generate();
    const consumerIx = new TransactionInstruction({
        programId: PublicKey.unique(),
        keys: [{ pubkey: signer.publicKey, isSigner: false, isWritable: true }],
        data: Buffer.from([0x11]),
    });
    const tx = buildSessionActionTx(payer, signer, consumerIx, payer.toBase58());
    const message = tx.compileMessage();
    const index = message.accountKeys.findIndex(key => key.equals(signer.publicKey));
    assert.ok(index >= 0 && index < message.header.numRequiredSignatures);
});

test('short reports still fail before the packet check', () => {
    const payer = Keypair.generate().publicKey;
    const signer = Keypair.generate().publicKey;
    assert.throws(
        () => buildRegisterSignerIx(payer, signer, new Uint8Array(16), 1),
        err => err instanceof Error && !(err instanceof PacketTooLargeError),
    );
});

// @spec SCC-NITRO-008 SCC-SDK-002 SCC-SEC-005
test('raw nitro documents fail closed above PACKET_DATA_SIZE', () => {
    const payer = Keypair.generate().publicKey;
    const workload = Keypair.generate().publicKey;
    const nonce = new Uint8Array(32).fill(0x55);
    const actionHash = new Uint8Array(32).fill(0x11);
    const document = new Uint8Array(MAX_NITRO_DOCUMENT_LEN);
    const len = expectPacketTooLarge(() =>
        buildVerifyNitroAttestationIx(payer, workload, VERIFY_NITRO_MODE_A, 1, actionHash, document, nonce),
    );
    assert.ok(len > PACKET_DATA_SIZE);

    const consumerIx = new TransactionInstruction({
        programId: PublicKey.unique(),
        keys: [{ pubkey: payer, isSigner: true, isWritable: true }],
        data: Buffer.from([1, 2]),
    });
    const txLen = expectPacketTooLarge(() =>
        buildVerifyNitroAttestationTx(
            payer,
            workload,
            VERIFY_NITRO_MODE_B,
            1,
            actionHash,
            document,
            nonce,
            payer.toBase58(),
            consumerIx,
        ),
    );
    assert.ok(txLen > PACKET_DATA_SIZE); // Mode A now carries a second workload signature.
});

test('oversized nitro packers still emit the raw document layout', () => {
    const payer = Keypair.generate().publicKey;
    const workload = Keypair.generate().publicKey;
    const nonce = new Uint8Array(32).fill(0x55);
    const actionHash = new Uint8Array(32).fill(0x11);
    const document = new Uint8Array(MAX_NITRO_DOCUMENT_LEN);
    const ix = buildVerifyNitroAttestationIxOversized(
        payer,
        workload,
        VERIFY_NITRO_MODE_A,
        1n,
        actionHash,
        document,
        nonce,
    );
    assert.equal(ix.data.length, VERIFY_NITRO_ATTESTATION_HEADER_LEN + MAX_NITRO_DOCUMENT_LEN);

    const consumerIx = new TransactionInstruction({
        programId: PublicKey.unique(),
        keys: [{ pubkey: payer, isSigner: true, isWritable: true }],
        data: Buffer.from([1, 2]),
    });
    const tx = buildVerifyNitroAttestationTxOversized(
        payer,
        workload,
        VERIFY_NITRO_MODE_B,
        1,
        actionHash,
        document,
        nonce,
        payer.toBase58(),
        consumerIx,
    );
    assert.equal(tx.instructions[0].data.length, VERIFY_NITRO_ATTESTATION_HEADER_LEN + MAX_NITRO_DOCUMENT_LEN);
    assert.equal(tx.instructions.length, 2);
});

// @spec SCC-PERF-001 SCC-CONSUMER-001 SCC-CONSUMER-002 SCC-ANCHOR-001
test('shared wire test vector for action-hash and commitment calculation', () => {
    const disc = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const acc1 = new PublicKey(new Uint8Array(32).fill(10));
    const acc2 = new PublicKey(new Uint8Array(32).fill(20));
    const data = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    const actionHash = hashAction(
        disc,
        [acc1, acc2].map(pubkey => ({ pubkey, isSigner: false, isWritable: false })),
        data,
    );

    const expectedActionHash = new Uint8Array([
        235, 83, 105, 10, 187, 214, 226, 188, 61, 43, 63, 19, 184, 121, 255, 58, 52, 126, 160, 114, 12, 209, 122, 216,
        71, 203, 76, 236, 70, 186, 77, 72,
    ]);
    assert.deepEqual(actionHash, expectedActionHash);

    const slotHash = new Uint8Array(32).fill(0x42);
    const consumer = new PublicKey(new Uint8Array(32).fill(30));
    const commitment = computeCommitment(slotHash, actionHash, consumer);

    const expectedCommitment = new Uint8Array([
        14, 199, 119, 170, 190, 142, 1, 96, 135, 78, 206, 131, 174, 75, 39, 221, 193, 93, 1, 176, 24, 11, 0, 50, 19, 98,
        109, 138, 103, 222, 225, 29,
    ]);
    assert.deepEqual(commitment, expectedCommitment);
});
