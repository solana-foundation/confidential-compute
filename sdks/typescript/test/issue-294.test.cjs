const assert = require('node:assert/strict'),
    test = require('node:test'),
    { createHash } = require('node:crypto');
const { Keypair } = require('@solana/web3.js');
const sdk = require(process.env.SOLANA_CC_SDK_PATH || '../dist');
const raw = require(process.env.SOLANA_CC_RAW_PATH || '../dist/internal/oversized');
const hash = x => createHash('sha256').update(x).digest();
test('VLEK AMD A/B derive from explicit endorsement XY for flag and zero-chip paths', () => {
    const payer = Keypair.generate().publicKey,
        signer = Keypair.generate().publicKey,
        pid = Keypair.generate().publicKey,
        xy = Buffer.alloc(96, 17);
    for (const [flags, chip] of [
        [4, 9],
        [0, 0],
        [1, 9],
    ]) {
        const report = Buffer.alloc(1184);
        report.writeUInt32LE(flags, 0x48);
        signer.toBuffer().copy(report, 0x50);
        report.fill(chip, 0x1a0, 0x1e0);
        const identity = hash(flags === 4 || chip === 0 ? xy : report.subarray(0x1a0, 0x1e0));
        const expected = sdk.deriveVcekPda(identity, 0n, pid)[0];
        const make = [
            () => raw.buildRegisterSignerIxOversized(payer, signer, report, 0, 0, pid, xy),
            () =>
                raw.buildVerifyAtomicWithNonceIxOversized(
                    payer,
                    signer,
                    new Uint8Array(32),
                    new Uint8Array(48),
                    report,
                    0,
                    pid,
                    xy,
                ),
        ];
        for (const build of make) {
            const ix = build();
            assert.ok(ix.keys[2].pubkey.equals(expected));
            assert.deepEqual(ix.keys.at(-1), {
                pubkey: sdk.deriveAmdRevocationPda(identity, pid)[0],
                isSigner: false,
                isWritable: false,
            });
        }
        if (flags === 4 || chip === 0) {
            assert.throws(() => raw.buildRegisterSignerIxOversized(payer, signer, report, 0, 0, pid), /endorsement/);
            assert.throws(
                () => raw.buildRegisterSignerIxOversized(payer, signer, report, 0, 0, pid, xy.subarray(1)),
                /endorsement/,
            );
            assert.throws(
                () => sdk.buildRegisterSignerIx(payer, signer, report, 0, 0, pid, xy),
                sdk.PacketTooLargeError,
            );
        }
    }
});
