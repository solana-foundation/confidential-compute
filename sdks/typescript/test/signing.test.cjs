const test = require('node:test');
const assert = require('node:assert/strict');
const { Keypair, SystemProgram, TransactionInstruction } = require('@solana/web3.js');
const { buildSessionActionTx } = require('../dist/index.js');
test('rejects System Program transfers before workload signing', () => {
    const signer = Keypair.generate();
    const ix = SystemProgram.transfer({
        fromPubkey: signer.publicKey,
        lamports: 1e9,
        toPubkey: Keypair.generate().publicKey,
    });
    assert.throws(
        () => buildSessionActionTx(signer.publicKey, signer, ix, Keypair.generate().publicKey.toBase58()),
        /System Program/,
    );
});
test('custom consumer remains supported with valid signature', () => {
    const signer = Keypair.generate();
    const ix = new TransactionInstruction({
        data: Buffer.alloc(512, 0xff),
        keys: [{ isSigner: false, isWritable: true, pubkey: signer.publicKey }],
        programId: Keypair.generate().publicKey,
    });
    const tx = buildSessionActionTx(signer.publicKey, signer, ix, Keypair.generate().publicKey.toBase58());
    assert.equal(tx.verifySignatures(), true);
});
