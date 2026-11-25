const test = require('node:test'),
    assert = require('node:assert/strict');
const { Keypair, PublicKey, Transaction } = require('@solana/web3.js');
const raw = require('../dist/internal/oversized.js');
const { SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID } = require('../dist/index.js');
test('SNP and Nitro Mode A require workload signature in addition to payer', () => {
    const payer = Keypair.generate(),
        workload = Keypair.generate(),
        report = Buffer.alloc(1184);
    report.fill(9, 0x1a0, 0x1e0);
    workload.publicKey.toBuffer().copy(report, 0x50);
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
    const legacy = PublicKey.findProgramAddressSync(
        [Buffer.from('nonce'), workload.publicKey.toBuffer(), Buffer.alloc(32)],
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    )[0];
    for (const [ix, source] of [
        [ixs[0], 1],
        [ixs[1], 2],
    ]) {
        const policy = PublicKey.findProgramAddressSync(
            [Buffer.from('backend_policy'), Buffer.from([source])],
            SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
        )[0];
        assert.deepEqual(ix.keys.at(source === 1 ? -4 : -3), {
            pubkey: workload.publicKey,
            isSigner: true,
            isWritable: false,
        });
        assert.deepEqual(ix.keys.at(source === 1 ? -3 : -2), { pubkey: policy, isSigner: false, isWritable: false });
        assert.deepEqual(ix.keys.at(source === 1 ? -2 : -1), { pubkey: legacy, isSigner: false, isWritable: false });
        const tx = new Transaction({
            feePayer: payer.publicKey,
            recentBlockhash: Keypair.generate().publicKey.toBase58(),
        }).add(ix);
        // Raw SNP payload exceeds web3's message buffer. Check required signers via
        // compileMessage without claiming that this raw transaction is sendable.
        const msg = tx.compileMessage();
        assert.equal(msg.header.numRequiredSignatures, 2);
        if (ix.data.length < 1184) {
            tx.partialSign(payer);
            assert.equal(tx.verifySignatures(), false);
            tx.partialSign(workload);
            assert.equal(tx.verifySignatures(), true);
        }
    }
});
