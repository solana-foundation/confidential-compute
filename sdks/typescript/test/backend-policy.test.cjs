const test = require('node:test'),
    assert = require('node:assert/strict');
const fs = require('node:fs'),
    path = require('node:path');
const { PublicKey, Keypair } = require('@solana/web3.js');
const sdk = require('../dist/index.js'),
    raw = require('../dist/internal/oversized.js');
const key = () => Keypair.generate().publicKey;
test('governed source setter matches verifier discriminator, Borsh and canonical accounts', () => {
    const source = fs.readFileSync(
        path.resolve(__dirname, '../../../programs/solana-confidential-compute-verifier/src/payload.rs'),
        'utf8',
    );
    const expected = source
        .match(/SET_BACKEND_POLICY_DISCRIMINATOR: \[u8; 8\] = \[([^\]]+)\]/)[1]
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
        .map(Number);
    assert.deepEqual([...sdk.SET_BACKEND_POLICY_DISCRIMINATOR], expected);
    const authority = key(),
        payer = key(),
        pid = key();
    for (const tag of [1, 2, 3, 4, 5]) {
        const ix = sdk.buildSetBackendPolicyIx(authority, payer, tag, [new Uint8Array(48).fill(7)], pid);
        const data = Buffer.alloc(397);
        Buffer.from(expected).copy(data);
        data[8] = tag;
        data.writeUInt32LE(1, 9);
        data.fill(7, 13, 61);
        assert.deepEqual(ix.data, data);
        assert.deepEqual(
            ix.keys.map(m => [m.isSigner, m.isWritable]),
            [
                [true, false],
                [false, false],
                [false, true],
                [true, true],
                [false, false],
            ],
        );
        assert.ok(
            ix.keys[2].pubkey.equals(
                PublicKey.findProgramAddressSync([Buffer.from('backend_policy'), Buffer.from([tag])], pid)[0],
            ),
        );
        assert.equal(sdk.buildSetBackendPolicyIx(authority, payer, tag, [], pid).data.readUInt32LE(9), 0);
    }
    for (const tag of [0, 6, 255, NaN, 1.1])
        assert.throws(() => sdk.buildSetBackendPolicyIx(authority, payer, tag, [], pid), /source/);
    assert.throws(() => sdk.buildSetBackendPolicyIx(authority, payer, 1, Array(9).fill(new Uint8Array(48))), /eight/);
    assert.throws(() => sdk.buildSetBackendPolicyIx(authority, payer, 1, [new Uint8Array(47)]), /48/);
});
test('all inline verification builders append readonly policy with correct backend tag', () => {
    const payer = key(),
        signer = key(),
        pid = key(),
        report = Buffer.alloc(1184);
    report.fill(9, 0x1a0, 0x1e0);
    signer.toBuffer().copy(report, 0x50);
    const ixs = [
        [raw.buildRegisterSignerIxOversized(payer, signer, report, 0, 95, pid), 1],
        [
            raw.buildVerifyAtomicWithNonceIxOversized(
                payer,
                signer,
                new Uint8Array(32),
                new Uint8Array(48),
                report,
                95,
                pid,
            ),
            1,
        ],
    ];
    for (const mode of [0, 1])
        ixs.push([
            raw.buildVerifyNitroAttestationIxOversized(
                payer,
                signer,
                mode,
                95,
                new Uint8Array(32),
                new Uint8Array([1]),
                new Uint8Array(32),
                pid,
            ),
            2,
        ]);
    for (const [ix, tag] of ixs) {
        assert.deepEqual(ix.keys.at(tag === 1 ? -3 : -2), {
            isSigner: false,
            isWritable: false,
            pubkey: sdk.deriveBackendPolicyPda(tag, pid)[0],
        });
        assert.ok(
            !ix.keys.at(tag === 1 ? -3 : -2).pubkey.equals(sdk.deriveBackendPolicyPda(tag === 1 ? 2 : 1, pid)[0]),
        );
    }
    const checked = sdk.buildVerifyNitroAttestationIx(
        payer,
        signer,
        0,
        95,
        new Uint8Array(32),
        new Uint8Array([1]),
        new Uint8Array(32),
        pid,
    );
    assert.ok(checked.keys.at(-2).pubkey.equals(sdk.deriveBackendPolicyPda(2, pid)[0]));
});
