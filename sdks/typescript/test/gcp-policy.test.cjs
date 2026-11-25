const test = require('node:test'),
    assert = require('node:assert/strict');
const { Keypair, PublicKey } = require('@solana/web3.js');
const sdk = require('../dist/index.js');
test('tenant setter has exact Borsh byte lengths and canonical accounts', () => {
    const authority = Keypair.generate().publicKey,
        payer = Keypair.generate().publicKey,
        program = Keypair.generate().publicKey;
    const ix = sdk.buildSetGcpTenantPolicyIx(authority, payer, 'aud', 'sub', program);
    assert.deepEqual(
        ix.data,
        Buffer.from([253, 197, 211, 209, 205, 86, 22, 43, 3, 0, 0, 0, 97, 117, 100, 3, 0, 0, 0, 115, 117, 98]),
    );
    assert.equal(ix.keys.length, 5);
    assert.ok(ix.keys[0].isSigner);
    assert.ok(ix.keys[3].isSigner && ix.keys[3].isWritable);
    assert.equal(ix.keys[1].isWritable, false);
    assert.ok(
        ix.keys[2].pubkey.equals(PublicKey.findProgramAddressSync([Buffer.from('gcp_tenant_policy')], program)[0]),
    );
    for (const [a, s] of [
        ['', 's'],
        ['a', ''],
        ['a\0b', 's'],
        ['é'.repeat(65), 's'],
        ['a', 's'.repeat(161)],
    ])
        assert.throws(() => sdk.buildSetGcpTenantPolicyIx(authority, payer, a, s), /tenant/);
});
