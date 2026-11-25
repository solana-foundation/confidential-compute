const test = require('node:test');
const assert = require('node:assert/strict');
const { Keypair, PublicKey } = require('@solana/web3.js');
const sdk = require('../dist/index.js');
test('V2 parse and strict Unix boundary; V1 rejects', () => {
    const data = Buffer.alloc(154);
    Buffer.from(sdk.ATTESTED_SIGNER_DISCRIMINATOR).copy(data);
    data.writeBigUInt64LE(200n, 137);
    data[145] = 255;
    data.writeBigInt64LE(500n, 146);
    assert.equal(sdk.parseAttestedSignerAccount(data).expiresUnixTimestamp, 500n);
    assert.equal(sdk.parseAttestedSignerAccount(data).bump, 255);
    assert.equal(sdk.isAttestedSignerValid(data, 200n, 499n), true);
    assert.equal(sdk.isAttestedSignerValid(data, 201n, 499n), false);
    assert.equal(sdk.isAttestedSignerValid(data, 150n, 500n), false);
    assert.equal(sdk.isAttestedSignerValid(data, 150n, -1n), false);
    assert.throws(() => sdk.parseAttestedSignerAccount(data.subarray(0, 146)), /short/);
    const legacy = Buffer.from(data);
    legacy.set([97, 156, 233, 39, 50, 169, 179, 13]);
    assert.throws(() => sdk.parseAttestedSignerAccount(legacy), /discriminator/);
    const key = Keypair.generate().publicKey;
    const v1 = PublicKey.findProgramAddressSync(
        [Buffer.from('attested_signer'), key.toBuffer()],
        sdk.SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
    )[0];
    assert.equal(sdk.deriveSignerPda(key)[0].equals(v1), false);
});
