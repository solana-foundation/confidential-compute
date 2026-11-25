const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { Keypair, PublicKey, SystemProgram } = require('@solana/web3.js');
const sdk = require('../dist/index.js');
const pk = () => Keypair.generate().publicKey;
test('governance discriminators preserve deployed legacy bytes and new Anchor contracts', () => {
    const legacy = {
        REGISTER_JWKS_KEY_DISCRIMINATOR: [122, 195, 232, 116, 203, 137, 219, 14],
        REVOKE_JWKS_KEY_DISCRIMINATOR: [184, 102, 12, 45, 99, 128, 41, 16],
        ROTATE_ROOT_CERT_DISCRIMINATOR: [137, 212, 96, 71, 222, 5, 133, 104],
        UPDATE_POLICY_DISCRIMINATOR: [227, 150, 114, 217, 142, 172, 100, 228],
    };
    for (const [key, value] of Object.entries(legacy)) assert.deepEqual([...sdk[key]], value);
    for (const name of ['rotate_authority', 'revoke_attested_signer', 'revoke_vcek']) {
        const key = name.toUpperCase() + '_DISCRIMINATOR';
        assert.deepEqual(Buffer.from(sdk[key]), createHash('sha256').update(`global:${name}`).digest().subarray(0, 8));
    }
});
test('policy and legacy root builders match fixed Borsh layout', () => {
    const authority = pk(),
        program = pk();
    const ix = sdk.buildUpdatePolicyIx(authority, new Uint8Array([1, 2, 3, 4]), [new Uint8Array(48).fill(7)], program);
    const expected = Buffer.alloc(400);
    Buffer.from(sdk.UPDATE_POLICY_DISCRIMINATOR).copy(expected);
    expected.set([1, 2, 3, 4], 8);
    expected.writeUInt32LE(1, 12);
    expected.fill(7, 16, 64);
    assert.deepEqual(ix.data, expected);
    assert.deepEqual(ix.keys, [
        { isSigner: true, isWritable: false, pubkey: authority },
        { isSigner: false, isWritable: true, pubkey: sdk.derivePolicyRegistryPda(program)[0] },
    ]);
    assert.equal(sdk.buildUpdatePolicyIx(authority, new Uint8Array(4), [], program).data.readUInt32LE(12), 0);
    assert.throws(() => sdk.buildUpdatePolicyIx(authority, new Uint8Array(3), [], program), /minTcb/);
    assert.throws(
        () => sdk.buildUpdatePolicyIx(authority, new Uint8Array(4), Array(9).fill(new Uint8Array(48)), program),
        /eight/,
    );
    assert.throws(
        () => sdk.buildUpdatePolicyIx(authority, new Uint8Array(4), [new Uint8Array(47)], program),
        /measurement/,
    );
    const root = sdk.buildRotateRootCertIx(authority, new Uint8Array(96).fill(9), program);
    assert.deepEqual(root.keys, ix.keys);
    assert.deepEqual(root.data.subarray(8), Buffer.alloc(96, 9));
});
test('JWKS builders hash exact kid and reject malformed key identifiers', () => {
    const authority = pk(),
        payer = pk(),
        program = pk(),
        kid = Buffer.from('kid-1'),
        modulus = Buffer.alloc(256, 255);
    const hash = createHash('sha256').update(kid).digest(),
        jwks = sdk.deriveJwksPda(hash, program)[0];
    const ix = sdk.buildRegisterJwksKeyIx(authority, payer, kid, modulus, 65537, program);
    assert.equal(ix.data.readUInt32LE(8), 5);
    assert.deepEqual(ix.data.subarray(12, 17), kid);
    assert.deepEqual(ix.data.subarray(17, 273), modulus);
    assert.equal(ix.data.readUInt32LE(273), 65537);
    assert.deepEqual(ix.keys, [
        { isSigner: true, isWritable: false, pubkey: authority },
        { isSigner: false, isWritable: false, pubkey: sdk.derivePolicyRegistryPda(program)[0] },
        { isSigner: false, isWritable: true, pubkey: jwks },
        { isSigner: true, isWritable: true, pubkey: payer },
        { isSigner: false, isWritable: false, pubkey: SystemProgram.programId },
    ]);
    const revoke = sdk.buildRevokeJwksKeyIx(authority, hash, program);
    assert.deepEqual(revoke.keys, ix.keys.slice(0, 3));
    assert.deepEqual(revoke.data.subarray(8), hash);
    for (const bad of [Buffer.alloc(0), Buffer.from('a\0b'), Buffer.alloc(65, 1)])
        assert.throws(() => sdk.buildRegisterJwksKeyIx(authority, payer, bad, modulus), /kid/);
    assert.throws(() => sdk.buildRegisterJwksKeyIx(authority, payer, kid, modulus, 3), /RSA/);
    assert.throws(() => sdk.buildRegisterJwksKeyIx(authority, payer, kid, Buffer.alloc(255)), /modulus/);
});
test('authority rotation preserves two signer consent; signer revocation targets canonical record', () => {
    const authority = pk(),
        receiver = pk(),
        program = pk();
    const ix = sdk.buildRotateAuthorityIx(authority, receiver, program);
    assert.deepEqual(ix.data, Buffer.from(sdk.ROTATE_AUTHORITY_DISCRIMINATOR));
    assert.equal(ix.keys.length, 3);
    assert.ok(ix.keys[0].isSigner);
    assert.ok(ix.keys[2].isSigner);
    assert.ok(ix.keys[1].isWritable);
    assert.throws(() => sdk.buildRotateAuthorityIx(authority, authority), /authority/);
    assert.throws(() => sdk.buildRotateAuthorityIx(authority, PublicKey.default), /authority/);
    const revoke = sdk.buildRevokeAttestedSignerIx(authority, receiver, program);
    assert.deepEqual(revoke.data.subarray(8), receiver.toBuffer());
    assert.ok(revoke.keys[2].pubkey.equals(sdk.deriveSignerPda(receiver, program)[0]));
    assert.equal(revoke.keys[1].isWritable, false);
});
test('VCEK revocation targets the canonical V2 cache', () => {
    const authority = pk(),
        program = pk(),
        hash = Buffer.alloc(32, 6);
    const ix = sdk.buildRevokeVcekIx(authority, authority, hash, 77n, program);
    assert.deepEqual(ix.data.subarray(8, 40), hash);
    assert.equal(ix.data.readBigUInt64LE(40), 77n);
    assert.equal(ix.data.length, 48);
    assert.deepEqual(ix.keys, [
        { isSigner: true, isWritable: false, pubkey: authority },
        { isSigner: false, isWritable: false, pubkey: sdk.derivePolicyRegistryPda(program)[0] },
        { isSigner: false, isWritable: true, pubkey: sdk.deriveVcekPda(hash, 77n, program)[0] },
        { isSigner: false, isWritable: true, pubkey: sdk.deriveAmdRevocationPda(hash, program)[0] },
        { isSigner: true, isWritable: true, pubkey: authority },
        { isSigner: false, isWritable: false, pubkey: require('@solana/web3.js').SystemProgram.programId },
    ]);
    assert.throws(() => sdk.buildRevokeVcekIx(authority, authority, Buffer.alloc(31), 1, program), /chipIdHash/);
});
test('new governance discriminator requires a shipped client builder', () => {
    const fs = require('node:fs'),
        path = require('node:path');
    const source = fs.readFileSync(
        path.resolve(__dirname, '../../../programs/solana-confidential-compute-verifier/src/payload.rs'),
        'utf8',
    );
    const governed = name => /^(UPDATE_|ROTATE_|REVOKE_|REGISTER_JWKS_|SET_.*POLICY)/.test(name);
    function requireBuilders(text) {
        for (const match of text.matchAll(/pub const ([A-Z_]+)_DISCRIMINATOR:/g)) {
            const name = match[1];
            if (!governed(name)) continue;
            const camel = name
                .toLowerCase()
                .split('_')
                .map(p => p[0].toUpperCase() + p.slice(1))
                .join('');
            assert.equal(typeof sdk[`build${camel}Ix`], 'function', `missing builder ${name}`);
        }
    }
    requireBuilders(source);
    assert.throws(
        () => requireBuilders('pub const REVOKE_FUTURE_CREDENTIAL_DISCRIMINATOR: [u8;8] = [0;8];'),
        /missing builder/,
    );
});
