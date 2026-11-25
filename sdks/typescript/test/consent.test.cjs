const test = require('node:test'),
    assert = require('node:assert/strict');
const { Keypair, Transaction } = require('@solana/web3.js');
const raw = require('../dist/internal/oversized.js');
const { SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID } = require('../dist/index.js');
const { findPda, randomKey } = require('./helpers.cjs');
void test('SNP and Nitro Mode A require workload signature in addition to payer', async () => {
    const payer = await Keypair.generate(),
        workload = await Keypair.generate(),
        report = Buffer.alloc(1184);
    report.fill(9, 0x1a0, 0x1e0);
    report.set(workload.publicKey.toBytes(), 0x50);
    const ixs = [
        raw.buildRegisterSignerIxOversized(payer.publicKey, workload.publicKey, report, 1),
        raw.buildVerifyNitroAttestationIxOversized(
            payer.publicKey,
            workload.publicKey,
            0,
            1,
            new Uint8Array(32),
            new Uint8Array([1]),
            new Uint8Array(32),
        ),
    ];
    // #205: workload signer, then readonly backend policy (AMD 1, Nitro 2), then readonly legacy nonce guard.
    const legacy = (
        await findPda(
            [Buffer.from('nonce'), workload.publicKey.toBytes(), Buffer.alloc(32)],
            SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        )
    )[0];
    for (const [ix, source] of [
        [ixs[0], 1],
        [ixs[1], 2],
    ]) {
        const policy = (
            await findPda(
                [Buffer.from('backend_policy'), Buffer.from([source])],
                SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
            )
        )[0];
        assert.deepEqual(ix.keys.at(source === 1 ? -4 : -3), {
            isSigner: true,
            isWritable: false,
            pubkey: workload.publicKey,
        });
        assert.deepEqual(ix.keys.at(source === 1 ? -3 : -2), { isSigner: false, isWritable: false, pubkey: policy });
        assert.deepEqual(ix.keys.at(source === 1 ? -2 : -1), { isSigner: false, isWritable: false, pubkey: legacy });
        const tx = new Transaction({
            feePayer: payer.publicKey,
            recentBlockhash: randomKey().toBase58(),
        }).add(ix);
        // Raw SNP payload exceeds web3's message buffer. Check required signers via
        // compileMessage without claiming that this raw transaction is sendable.
        const msg = tx.compileMessage();
        assert.equal(msg.header.numRequiredSignatures, 2);
        if (ix.data.length < 1184) {
            await tx.partialSign(payer);
            assert.equal(await tx.verifySignatures(), false);
            await tx.partialSign(workload);
            assert.equal(await tx.verifySignatures(), true);
        }
    }
});
