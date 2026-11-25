const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { Keypair, SYSVAR_INSTRUCTIONS_PUBKEY } = require('@solana/web3.js');
const sdk = require('../dist/index.js');
const raw = require('../dist/internal/oversized.js');
test('AMD Mode B supplies readonly Instructions without shifting policy/replay suffix', () => {
    const payer = Keypair.generate().publicKey,
        consumer = Keypair.generate().publicKey;
    const report = new Uint8Array(sdk.SNP_REPORT_SIZE);
    // Explicit VCEK identity, matching the Rust Instructions-sysvar fixture.
    report.fill(9, 0x1a0, 0x1e0);
    const ix = raw.buildVerifyAtomicWithNonceIxOversized(
        payer,
        consumer,
        new Uint8Array(32),
        new Uint8Array(48),
        report,
    );
    assert.deepEqual(ix.keys[7], { isSigner: false, isWritable: false, pubkey: SYSVAR_INSTRUCTIONS_PUBKEY });
    assert.ok(ix.keys.at(-3).pubkey.equals(sdk.deriveBackendPolicyPda(1)[0]));
    assert.ok(
        ix.keys
            .at(-2)
            .pubkey.equals(
                sdk.deriveLegacyUsedNoncePda(
                    new (require('@solana/web3.js').PublicKey)(report.slice(0x50, 0x70)),
                    report.slice(0x70, 0x90),
                )[0],
            ),
    );
    const identity = createHash('sha256').update(report.slice(0x1a0, 0x1e0)).digest();
    assert.deepEqual(ix.keys.at(-1), {
        isSigner: false,
        isWritable: false,
        pubkey: sdk.deriveAmdRevocationPda(identity)[0],
    });
    assert.throws(
        () => sdk.buildVerifyAtomicWithNonceIx(payer, consumer, new Uint8Array(32), new Uint8Array(48), report),
        sdk.PacketTooLargeError,
    );
});
