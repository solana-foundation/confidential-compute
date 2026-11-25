const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { PublicKey, Transaction, TransactionInstruction } = require('@solana/web3.js');
const sdk = require(process.env.SOLANA_CC_SDK_PATH || '../dist');
const pk = n => new PublicKey(new Uint8Array(32).fill(n));
const accounts = [{ isSigner: false, isWritable: true, pubkey: pk(3) }];
const digest = wire =>
    createHash('sha256')
        .update(
            Buffer.concat([
                Buffer.from('solana-confidential-compute:action:v1\0'),
                Buffer.from([1, 0, 0, 0]),
                pk(3).toBuffer(),
                Buffer.from([0, 1]),
                Buffer.from([wire.length, 0, 0, 0]),
                Buffer.from(wire),
            ]),
        )
        .digest();
test('baseline regression: identical wire has one canonical digest for every split', () => {
    assert.deepEqual(
        sdk.hashAction(Uint8Array.of(1), [], Uint8Array.of(2, 3)),
        sdk.hashAction(Uint8Array.of(1, 2), [], Uint8Array.of(3)),
    );
});
test('V3 binds full wire bytes independently of discriminator split', () => {
    for (const wire of [[], [7], [7, 8], [7, 8, 9, 10, 11, 12, 13, 14, 15]]) {
        for (let split = 0; split <= wire.length; split++) {
            assert.deepEqual(
                Buffer.from(
                    sdk.hashAction(Uint8Array.from(wire.slice(0, split)), accounts, Uint8Array.from(wire.slice(split))),
                ),
                digest(wire),
            );
        }
    }
    assert.notDeepEqual(digest([7]), digest([7, 0]));
});
test('compiled action accepts empty and arbitrary instruction data without guessing a schema', () => {
    for (const wire of [[], [7], [7, 8], [7, 8, 9, 10, 11, 12, 13, 14, 15]]) {
        const ix = new TransactionInstruction({ data: Buffer.from(wire), keys: accounts, programId: pk(2) });
        const message = new Transaction({ feePayer: pk(1), recentBlockhash: pk(9).toBase58() })
            .add(ix)
            .compileMessage();
        assert.deepEqual(Buffer.from(sdk.hashCompiledAction(message, 0, 0)), digest(wire));
        sdk.validateCompiledAction(message, 0, digest(wire));
    }
});
