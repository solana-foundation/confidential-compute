const test = require('node:test'),
    assert = require('node:assert/strict');
const fs = require('node:fs'),
    path = require('node:path');
const { PublicKey } = require('@solana/web3.js');
const { sha256 } = require('@noble/hashes/sha256');
const sdk = require('../dist/index.js'),
    raw = require('../dist/internal/oversized.js');
test('VCEK client and both AMD packers match verifier V2 seed; legacy differs', () => {
    const source = fs.readFileSync(
        path.resolve(__dirname, '../../../programs/solana-confidential-compute-verifier/src/state.rs'),
        'utf8',
    );
    const seed = source.match(/pub const SEED: &'static \[u8\] = b"([^"]+)"/)[1];
    const pid = new PublicKey(new Uint8Array(32).fill(9)),
        signer = new PublicKey(new Uint8Array(32).fill(8));
    const report = Buffer.alloc(1184);
    signer.toBuffer().copy(report, 0x50);
    report.fill(7, 0x1a0, 0x1e0);
    report.writeBigUInt64LE(0x0102030405060708n, 0x180);
    const chip = sha256(report.subarray(0x1a0, 0x1e0)),
        tcb = report.subarray(0x180, 0x188);
    const expected = PublicKey.findProgramAddressSync([Buffer.from(seed), chip, tcb], pid),
        legacy = PublicKey.findProgramAddressSync([Buffer.from('vcek'), chip, tcb], pid);
    assert.ok(!expected[0].equals(legacy[0]));
    assert.deepEqual(sdk.deriveVcekPda(chip, 0x0102030405060708n, pid), expected);
    for (const ix of [
        raw.buildRegisterSignerIxOversized(signer, signer, report, 0, 1, pid),
        raw.buildVerifyAtomicWithNonceIxOversized(
            signer,
            signer,
            new Uint8Array(32),
            new Uint8Array(48),
            report,
            1,
            pid,
        ),
    ]) {
        assert.ok(ix.keys[2].pubkey.equals(expected[0]));
        assert.equal(ix.keys[2].isWritable, false);
    }
});
