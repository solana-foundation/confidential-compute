const { test } = require('node:test');
const assert = require('node:assert/strict');
const { PublicKey, Keypair } = require('@solana/web3.js');
const { createHash } = require('node:crypto');
const sdk = require('../dist');
const raw = require('../dist/internal/oversized');
test('source-aware nonce tuples, legacy guards, Google raw binding and invalid domains', () => {
    const pid = Keypair.generate().publicKey,
        signer = Keypair.generate().publicKey,
        nonce = Buffer.alloc(32, 7);
    assert.equal(sdk.deriveUsedNoncePda, undefined);
    const legacy = sdk.deriveLegacyUsedNoncePda(signer, nonce, pid)[0];
    for (const source of [1, 2]) {
        assert.deepEqual(
            sdk.deriveUsedNoncePdaForSource(source, signer, nonce, pid),
            PublicKey.findProgramAddressSync(
                [Buffer.from('nonce'), Buffer.from([source]), signer.toBuffer(), nonce],
                pid,
            ),
        );
        assert.ok(!sdk.deriveUsedNoncePdaForSource(source, signer, nonce, pid)[0].equals(legacy));
    }
    assert.ok(
        !sdk
            .deriveUsedNoncePdaForSource(1, signer, nonce, pid)[0]
            .equals(sdk.deriveUsedNoncePdaForSource(2, signer, nonce, pid)[0]),
    );
    for (const source of [0, 3, 4, 255, 1.5, NaN])
        assert.throws(() => sdk.deriveUsedNoncePdaForSource(source, signer, nonce, pid));
    assert.throws(() => sdk.deriveUsedNoncePdaForSource(1, signer, Buffer.alloc(31), pid));
    for (const binding of [nonce, Buffer.concat([signer.toBuffer(), nonce])]) {
        const hash = createHash('sha256').update(binding).digest();
        const active = sdk.deriveGoogleUsedNoncePda(binding, pid);
        assert.deepEqual(active, PublicKey.findProgramAddressSync([Buffer.from('nonce'), Buffer.from([3]), hash], pid));
        assert.deepEqual(
            sdk.deriveLegacyGoogleUsedNoncePda(binding, pid),
            PublicKey.findProgramAddressSync([Buffer.from('nonce'), hash], pid),
        );
        assert.ok(
            !active[0].equals(
                PublicKey.findProgramAddressSync(
                    [Buffer.from('nonce'), Buffer.from([3]), createHash('sha256').update(hash).digest()],
                    pid,
                )[0],
            ),
        );
        assert.throws(() => sdk.deriveGoogleUsedNoncePda(Buffer.from(binding.toString('base64url')), pid));
    }
});
test('AMD and Nitro A/B retain readonly legacy guard last and new active bump', () => {
    const pid = Keypair.generate().publicKey,
        payer = Keypair.generate().publicKey,
        signer = Keypair.generate().publicKey,
        nonce = Buffer.alloc(32, 7),
        report = Buffer.alloc(1184);
    report.fill(9, 0x1a0, 0x1e0);
    signer.toBuffer().copy(report, 0x50);
    nonce.copy(report, 0x70);
    const cases = [
        [raw.buildRegisterSignerIxOversized(payer, signer, report, 0, 95n, pid), 1, 4, 1200],
        [
            raw.buildVerifyAtomicWithNonceIxOversized(
                payer,
                signer,
                new Uint8Array(32),
                new Uint8Array(48),
                report,
                95n,
                pid,
            ),
            1,
            3,
            1264,
        ],
        ...[0, 1].map(mode => [
            raw.buildVerifyNitroAttestationIxOversized(
                payer,
                signer,
                mode,
                95n,
                new Uint8Array(32),
                new Uint8Array([1]),
                nonce,
                pid,
            ),
            2,
            3,
            null,
        ]),
    ];
    for (const [ix, source, index, bumpAt] of cases) {
        const expected = sdk.deriveUsedNoncePdaForSource(source, signer, nonce, pid);
        assert.ok(ix.keys[index].pubkey.equals(expected[0]));
        assert.deepEqual(ix.keys.at(source === 1 ? -2 : -1), {
            pubkey: sdk.deriveLegacyUsedNoncePda(signer, nonce, pid)[0],
            isWritable: false,
            isSigner: false,
        });
        assert.ok(ix.keys.at(source === 1 ? -3 : -2).pubkey.equals(sdk.deriveBackendPolicyPda(source, pid)[0]));
        if (bumpAt !== null) assert.equal(ix.data[bumpAt], expected[1]);
    }
});
