const test = require('node:test');
const assert = require('node:assert/strict');
const { Keypair, SystemProgram, TransactionInstruction } = require('@solana/web3.js');
const { buildSessionActionTx } = require('../dist/index.js');
const { randomKey } = require('./helpers.cjs');
void test('rejects System Program transfers before workload signing', async () => {
    const signer = await Keypair.generate();
    const ix = SystemProgram.transfer({
        fromPubkey: signer.publicKey,
        lamports: 1e9,
        toPubkey: randomKey(),
    });
    await assert.rejects(
        () => buildSessionActionTx(signer.publicKey, signer, ix, randomKey().toBase58()),
        /System Program/,
    );
});
void test('custom consumer remains supported with valid signature', async () => {
    const signer = await Keypair.generate();
    const ix = new TransactionInstruction({
        data: Buffer.alloc(512, 0xff),
        keys: [{ isSigner: false, isWritable: true, pubkey: signer.publicKey }],
        programId: randomKey(),
    });
    const tx = await buildSessionActionTx(signer.publicKey, signer, ix, randomKey().toBase58());
    assert.equal(await tx.verifySignatures(), true);
});
