// Repository contract gate: runs in the existing node --test CI glob.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const sdk = require('../dist/index.js');
const root = process.env.SOLANA_CC_CONTRACT_ROOT || path.resolve(__dirname, '../../..');
const read = p => fs.readFileSync(path.join(root, p), 'utf8');
const discriminator = name => [...createHash('sha256').update(name).digest().subarray(0, 8)];
function arrayConstant(source, name) {
    const m = source.match(new RegExp(`(?:pub )?const ${name}: \\[u8; 8\\] = \\[([^\\]]+)\\]`));
    assert.ok(m, `missing literal contract ${name}`);
    return m[1]
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
        .map(Number);
}
function equal(name, actual, expected) {
    assert.deepEqual([...actual], [...expected], name);
}

void test('all shared exported instruction/account discriminators match the verifier and Anchor hash', () => {
    for (const [file, namespace] of [
        ['programs/solana-confidential-compute-verifier/src/payload.rs', 'global'],
        ['programs/solana-confidential-compute-verifier/src/state.rs', 'account'],
    ]) {
        const source = read(file);
        for (const name of Object.keys(sdk).filter(n => n.endsWith('_DISCRIMINATOR'))) {
            if (!source.includes(`const ${name}:`)) continue;
            const expected = arrayConstant(source, name);
            equal(name, sdk[name], expected);
            const label =
                namespace === 'global' ? name.replace(/_DISCRIMINATOR$/, '').toLowerCase() : 'AttestedSignerAccountV2';
            // Preserve existing deployed governance bytes even where old literals
            // differ from the nominal Anchor name. Never silently change the ABI.
            if (
                ![
                    'UPDATE_POLICY_DISCRIMINATOR',
                    'ROTATE_ROOT_CERT_DISCRIMINATOR',
                    'REGISTER_JWKS_KEY_DISCRIMINATOR',
                    'REVOKE_JWKS_KEY_DISCRIMINATOR',
                ].includes(name)
            ) {
                equal(`${name} derived`, expected, discriminator(`${namespace}:${label}`));
            }
        }
    }
});
void test('wire lengths, account layout, TTL and mode bytes remain aligned', () => {
    assert.equal(sdk.SNP_REPORT_SIZE, 1184);
    assert.equal(sdk.VERIFY_AND_REGISTER_IX_LEN, 8 + 8 + sdk.SNP_REPORT_SIZE + 2);
    assert.equal(sdk.VERIFY_ATOMIC_WITH_NONCE_IX_LEN, 8 + 72 + sdk.SNP_REPORT_SIZE + 1);
    assert.equal(sdk.VERIFY_NITRO_ATTESTATION_HEADER_LEN, 53);
    assert.equal(sdk.MAX_NITRO_DOCUMENT_LEN, 8192);
    assert.equal(sdk.VERIFY_NITRO_MODE_A, 0);
    assert.equal(sdk.VERIFY_NITRO_MODE_B, 1);
    assert.equal(sdk.ATTESTED_SIGNER_ACCOUNT_SIZE, 154);
    assert.equal(sdk.ATTESTATION_TTL_SLOTS, 216000n);
    for (const file of [
        'crates/solana-confidential-compute-sdk/src/builder.rs',
        'programs/solana-confidential-compute-verifier/src/processor.rs',
        'bins/solana-confidential-compute-sidecar/src/onchain.rs',
    ]) {
        assert.match(read(file), /(?:DEFAULT_)?ATTESTATION_TTL_SLOTS: u64 = 216_000/);
    }
    const data = Buffer.alloc(154);
    Buffer.from(sdk.ATTESTED_SIGNER_DISCRIMINATOR).copy(data);
    data.fill(1, 8, 40);
    data[40] = 2;
    data.fill(3, 41, 89);
    data.fill(4, 89, 121);
    data.writeBigUInt64LE(5n, 121);
    data.writeBigUInt64LE(6n, 129);
    data.writeBigUInt64LE(7n, 137);
    data[145] = 8;
    data.writeBigInt64LE(9n, 146);
    const parsed = sdk.parseAttestedSignerAccount(data);
    assert.deepEqual([...parsed.signerPubkey], Array(32).fill(1));
    assert.equal(parsed.enclaveType, 2);
    assert.deepEqual([...parsed.measurement], Array(48).fill(3));
    assert.deepEqual([...parsed.chipIdHash], Array(32).fill(4));
    assert.equal(parsed.tcbVersion, 5n);
    assert.equal(parsed.registeredSlot, 6n);
    assert.equal(parsed.expiresSlot, 7n);
    assert.equal(parsed.bump, 8);
    assert.equal(parsed.expiresUnixTimestamp, 9n);
});
void test('sidecar JWT builder/screen consume canonical CPI constant, not handwritten bytes', () => {
    equal(
        'sidecar Nitro discriminator',
        arrayConstant(
            read('bins/solana-confidential-compute-sidecar/src/onchain.rs'),
            'VERIFY_NITRO_ATTESTATION_DISCRIMINATOR',
        ),
        sdk.VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
    );

    for (const file of [
        'bins/solana-confidential-compute-sidecar/src/onchain.rs',
        'bins/solana-confidential-compute-sidecar/src/server.rs',
    ]) {
        assert.match(read(file), /VERIFY_GOOGLE_JWT_DISCRIMINATOR/);
        assert.doesNotMatch(read(file), /77,\s*18,\s*140,\s*169,\s*137,\s*219,\s*219,\s*100/);
    }
});
void test('contract gate rejects a deliberately changed discriminator (negative control)', () => {
    const name = 'VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR';
    const expected = arrayConstant(read('programs/solana-confidential-compute-verifier/src/payload.rs'), name);
    const changed = [...expected];
    changed[0] ^= 1;
    assert.throws(() => equal(name, changed, expected), { code: 'ERR_ASSERTION' });
});

void test('CPI private offsets and parser ceilings agree with wire contracts', () => {
    const source = read('crates/solana-confidential-compute-cpi/src/lib.rs');
    for (const [name, value] of Object.entries({
        BUMP_OFFSET: 145,
        COSE_SIGN1_TAG: 18,
        EXPIRES_SLOT_OFFSET: 137,
        JWT_ACTION_HASH_OFFSET: 17,
        JWT_LEN_OFFSET: 49,
        JWT_MODE_OFFSET: 8,
        JWT_NONCE_SLOT_OFFSET: 9,
        JWT_OFFSET: 53,
        MAX_CBOR_SKIP_DEPTH: 8,
        MAX_JWT_LEN: 4096,
        MEASUREMENT_OFFSET: 41,
        NITRO_ACTION_HASH_OFFSET: 17,
        NITRO_DOCUMENT_OFFSET: sdk.VERIFY_NITRO_ATTESTATION_HEADER_LEN,
        NITRO_DOC_LEN_OFFSET: 49,
        NITRO_MODE_OFFSET: 8,
        NITRO_NONCE_SLOT_OFFSET: 9,
        SIGNER_PUBKEY_OFFSET: 8,
        SNP_HEADER_LEN: 80,
    })) {
        const found = source.match(new RegExp(`const ${name}: (?:usize|u8|u64) = ([0-9_]+);`));
        assert.ok(found, name);
        assert.equal(Number(found[1].replaceAll('_', '')), value, name);
    }
    for (const [file, name, value] of [
        ['crates/solana-confidential-compute-core/src/report.rs', 'SNP_REPORT_SIZE', sdk.SNP_REPORT_SIZE],
        ['crates/solana-confidential-compute-core/src/nitro.rs', 'MAX_NITRO_DOCUMENT_LEN', sdk.MAX_NITRO_DOCUMENT_LEN],
        ['crates/solana-confidential-compute-crypto/src/jwt/mod.rs', 'MAX_JWT_LEN', 4096],
    ]) {
        const match = read(file).match(new RegExp(`const ${name}: usize = ([0-9_]+);`));
        assert.ok(match, name);
        assert.equal(Number(match[1].replaceAll('_', '')), value, name);
    }
    assert.match(source, /ATTESTED_SIGNER_SEED: &\[u8\] = b"attested_signer_v2"/);
});
