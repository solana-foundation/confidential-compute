const test = require('node:test');
const assert = require('node:assert/strict');
const { Keypair, SystemProgram, TransactionInstruction } = require('@solana/web3.js');
const { buildSessionActionTx } = require('../dist/index.js');
test('rejects System Program transfers before workload signing', () => {
    const signer = Keypair.generate();
    const ix = SystemProgram.transfer({
        fromPubkey: signer.publicKey,
        toPubkey: Keypair.generate().publicKey,
        lamports: 1e9,
    });
    assert.throws(
        () => buildSessionActionTx(signer.publicKey, signer, ix, Keypair.generate().publicKey.toBase58()),
        /System Program/,
    );
});
test('custom consumer remains supported with valid signature', () => {
    const signer = Keypair.generate();
    const ix = new TransactionInstruction({
        programId: Keypair.generate().publicKey,
        keys: [{ pubkey: signer.publicKey, isSigner: false, isWritable: true }],
        data: Buffer.alloc(512, 0xff),
    });
    const tx = buildSessionActionTx(signer.publicKey, signer, ix, Keypair.generate().publicKey.toBase58());
    assert.equal(tx.verifySignatures(), true);
});
