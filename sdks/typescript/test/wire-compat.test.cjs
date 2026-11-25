/**
 * Wire-compatibility vectors.
 *
 * `fixtures/wire-compat.json` was recorded with the SDK before the TypeScript 7,
 * `@noble/hashes` 2 and `@solana/web3.js` 3 upgrade (TypeScript 5.9.3,
 * `@noble/hashes` 1.8.0, `@solana/web3.js` 1.99.0). This test records the same
 * outputs with the current dependencies and requires them to be identical:
 * PDA addresses and bumps, hashes, instruction data and accounts, compiled
 * message bytes, transaction wire bytes, a deterministic ed25519 signature, and
 * the error messages thrown by the public exports.
 *
 * To record a new fixture after an intended change of the wire format, run the
 * test with SOLANA_CC_WRITE_FIXTURE=1 and review the diff.
 *
 * @spec SCC-SDK-002 SCC-ARCH-001
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const web3 = require('@solana/web3.js');
const sdk = require('../dist/index.js');
const raw = require('../dist/internal/oversized.js');

const FIXTURE = path.join(__dirname, 'fixtures', 'wire-compat.json');
// Key material for this test only. It signs nothing outside this file.
const TEST_ONLY_SESSION_SEED = new Uint8Array(32).fill(0x2a);

const hex = x => Buffer.from(x).toString('hex');
const pk = n => new web3.PublicKey(new Uint8Array(32).fill(n));
const b58 = k => k.toBase58().toString();
const ixJson = ix => ({
    data: hex(ix.data),
    keys: ix.keys.map(k => [b58(k.pubkey), k.isSigner, k.isWritable]),
    programId: b58(ix.programId),
});
const pda = ([k, bump]) => [b58(k), bump];
async function attempt(fn) {
    try {
        return { ok: await fn() };
    } catch (e) {
        return { err: [e && e.constructor ? e.constructor.name : typeof e, String(e && e.message)] };
    }
}

const out = {};
const rec = async (name, fn) => {
    out[name] = await attempt(fn);
};

function report(signer, flags, chip) {
    const r = Buffer.alloc(1184);
    r.writeUInt32LE(flags, 0x48);
    r.set(signer.toBytes(), 0x50);
    r.set(new Uint8Array(32).fill(0x55), 0x70);
    r.set(new Uint8Array(48).fill(0x42), 0x90);
    r.fill(chip, 0x1a0, 0x1e0);
    r.writeBigUInt64LE(0x0102030405060708n, 0x180);
    return r;
}

async function collect() {
    const [payer, signer, authority, receiver, consumerProg, pid] = [1, 2, 3, 4, 5, 6].map(pk);
    const nonce = new Uint8Array(32).fill(7);
    const chip = new Uint8Array(32).fill(8);
    const xy = new Uint8Array(96).fill(17);
    const blockhash = b58(pk(9));
    const doc = Uint8Array.from({ length: 64 }, (_, i) => i & 0xff);

    out.constants = {
        attestedPlaceholder: b58(sdk.NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER),
        programId: b58(sdk.SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID),
    };
    for (const name of Object.keys(sdk).filter(n => n.endsWith('_DISCRIMINATOR'))) out.constants[name] = hex(sdk[name]);

    // PDAs: default program id and an explicit one.
    for (const [label, p] of Object.entries({ default: undefined, pid })) {
        out[`pda.${label}`] = {
            amdRevocation: pda(sdk.deriveAmdRevocationPda(chip, p)),
            backend: [1, 2, 3, 4, 5].map(s => pda(sdk.deriveBackendPolicyPda(s, p))),
            google32: pda(sdk.deriveGoogleUsedNoncePda(nonce, p)),
            google64: pda(sdk.deriveGoogleUsedNoncePda(new Uint8Array(64).fill(3), p)),
            googleLegacy32: pda(sdk.deriveLegacyGoogleUsedNoncePda(nonce, p)),
            googleLegacy64: pda(sdk.deriveLegacyGoogleUsedNoncePda(new Uint8Array(64).fill(3), p)),
            jwks: pda(sdk.deriveJwksPda(chip, p)),
            nonceAmd: pda(sdk.deriveUsedNoncePdaForSource(1, signer, nonce, p)),
            nonceLegacy: pda(sdk.deriveLegacyUsedNoncePda(signer, nonce, p)),
            nonceNitro: pda(sdk.deriveUsedNoncePdaForSource(2, signer, nonce, p)),
            nvidia: pda(sdk.deriveNvidiaNoncePda(signer, chip, nonce, p)),
            registry: pda(sdk.derivePolicyRegistryPda(p)),
            signer: pda(sdk.deriveSignerPda(signer, p)),
            vcek: pda(sdk.deriveVcekPda(chip, 0x0102030405060708n, p)),
        };
    }
    // Many seeds: bump search must agree for 64 distinct signers.
    out.pdaMany = Array.from({ length: 64 }, (_, i) => {
        const s = new web3.PublicKey(Uint8Array.from({ length: 32 }, (_, j) => (i * 7 + j * 13 + 1) & 0xff));
        return pda(sdk.deriveSignerPda(s, pid));
    });

    // Hashes.
    const metas = [pk(10), pk(20)].map(pubkey => ({ isSigner: false, isWritable: false, pubkey }));
    const actionHash = sdk.hashAction(
        Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
        metas,
        Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd),
    );
    out.hashes = {
        actionHash: hex(actionHash),
        commitment: hex(sdk.computeCommitment(new Uint8Array(32).fill(0x42), actionHash, pk(30))),
    };

    // Instruction builders.
    const m48 = new Uint8Array(48).fill(7);
    await rec('ix.setBackendPolicy', () =>
        [1, 2, 3, 4, 5].map(s => ixJson(sdk.buildSetBackendPolicyIx(authority, payer, s, [m48], pid))),
    );
    await rec('ix.setBackendPolicyEmpty', () => ixJson(sdk.buildSetBackendPolicyIx(authority, payer, 2, [])));
    await rec('ix.setGcp', () => ixJson(sdk.buildSetGcpTenantPolicyIx(authority, payer, 'aud', 'sub', pid)));
    await rec('ix.updatePolicy', () =>
        ixJson(sdk.buildUpdatePolicyIx(authority, Uint8Array.of(1, 2, 3, 4), [m48], pid)),
    );
    await rec('ix.rotateRoot', () => ixJson(sdk.buildRotateRootCertIx(authority, new Uint8Array(96).fill(9), pid)));
    const modulus = new Uint8Array(256).fill(255);
    await rec('ix.registerJwks', () =>
        ixJson(sdk.buildRegisterJwksKeyIx(authority, payer, Buffer.from('kid-1'), modulus, 65537, pid)),
    );
    await rec('ix.revokeJwks', () => ixJson(sdk.buildRevokeJwksKeyIx(authority, chip, pid)));
    await rec('ix.rotateAuthority', () => ixJson(sdk.buildRotateAuthorityIx(authority, receiver, pid)));
    await rec('ix.revokeSigner', () => ixJson(sdk.buildRevokeAttestedSignerIx(authority, receiver, pid)));
    await rec('ix.revokeVcek', () => ixJson(sdk.buildRevokeVcekIx(authority, payer, chip, 77n, pid)));

    const rpt = report(signer, 0, 9);
    const rptXy = report(signer, 4, 0);
    await rec('raw.registerSigner', () => ixJson(raw.buildRegisterSignerIxOversized(payer, signer, rpt, 0, 95, pid)));
    await rec('raw.registerSignerVlek', () =>
        ixJson(raw.buildRegisterSignerIxOversized(payer, signer, rptXy, 1, 2, pid, xy)),
    );
    await rec('raw.atomicNonce', () =>
        ixJson(
            raw.buildVerifyAtomicWithNonceIxOversized(
                payer,
                signer,
                new Uint8Array(32).fill(5),
                new Uint8Array(48).fill(0x42),
                rpt,
                95,
                pid,
            ),
        ),
    );
    await rec('raw.atomicNonceVlek', () =>
        ixJson(
            raw.buildVerifyAtomicWithNonceIxOversized(
                payer,
                signer,
                new Uint8Array(32),
                new Uint8Array(48).fill(0x42),
                rptXy,
                0,
                pid,
                xy,
            ),
        ),
    );
    for (const mode of [0, 1]) {
        await rec(`raw.nitroIx.${mode}`, () =>
            ixJson(
                raw.buildVerifyNitroAttestationIxOversized(
                    payer,
                    signer,
                    mode,
                    95n,
                    new Uint8Array(32).fill(2),
                    doc,
                    nonce,
                    pid,
                ),
            ),
        );
        await rec(`ix.nitro.${mode}`, () =>
            ixJson(
                sdk.buildVerifyNitroAttestationIx(
                    payer,
                    signer,
                    mode,
                    95n,
                    new Uint8Array(32).fill(2),
                    doc,
                    nonce,
                    pid,
                ),
            ),
        );
        await rec(`ix.nvidia.${mode}`, () =>
            ixJson(
                sdk.buildVerifyNvidiaAttestationIx(
                    payer,
                    signer,
                    mode,
                    95n,
                    new Uint8Array(32).fill(2),
                    chip,
                    nonce,
                    consumerProg,
                    pid,
                ),
            ),
        );
    }

    // Transactions.
    const consumerIx = new web3.TransactionInstruction({
        data: Buffer.from([1, 2, 3]),
        keys: [{ isSigner: true, isWritable: true, pubkey: payer }],
        programId: consumerProg,
    });
    const txJson = async tx => ({
        instructions: tx.instructions.map(ixJson),
        message: hex(tx.serializeMessage()),
        wire: hex(await tx.serialize({ requireAllSignatures: false, verifySignatures: false })),
    });
    await rec(
        'tx.nitroModeA',
        async () =>
            await txJson(
                sdk.buildVerifyNitroAttestationTx(
                    payer,
                    signer,
                    0,
                    1,
                    new Uint8Array(32).fill(0x12),
                    doc.subarray(0, 8),
                    new Uint8Array(32).fill(0x21),
                    blockhash,
                    consumerIx,
                    pid,
                ),
            ),
    );
    // Mode B: the consumer commitment must match the compiled message.
    const verifier = sdk.buildVerifyNitroAttestationIx(
        payer,
        signer,
        1,
        1,
        new Uint8Array(32),
        doc.subarray(0, 8),
        nonce,
        pid,
    );
    verifier.data = Buffer.alloc(0);
    const probe = new web3.Transaction({ feePayer: payer, recentBlockhash: blockhash }).add(verifier, consumerIx);
    const expected = sdk.hashCompiledAction(probe.compileMessage(), 1);
    out.hashes.compiled = hex(expected);
    await rec(
        'tx.nitroModeB',
        async () =>
            await txJson(
                sdk.buildVerifyNitroAttestationTx(
                    payer,
                    signer,
                    1,
                    1,
                    expected,
                    doc.subarray(0, 8),
                    nonce,
                    blockhash,
                    consumerIx,
                    pid,
                ),
            ),
    );
    await rec(
        'tx.nitroModeBBadHash',
        async () =>
            await txJson(
                sdk.buildVerifyNitroAttestationTx(
                    payer,
                    signer,
                    1,
                    1,
                    new Uint8Array(32),
                    doc.subarray(0, 8),
                    nonce,
                    blockhash,
                    consumerIx,
                    pid,
                ),
            ),
    );
    await rec('tx.rawNitroTooLarge', () =>
        sdk.buildVerifyNitroAttestationIx(payer, signer, 0, 1, new Uint8Array(32), new Uint8Array(8192), nonce, pid),
    );
    await rec('tx.rawRegisterTooLarge', () => sdk.buildRegisterSignerIx(payer, signer, rpt, 1));
    await rec('tx.rawAtomicTooLarge', () =>
        sdk.buildAtomicAttestationTx(
            payer,
            consumerProg,
            new Uint8Array(32).fill(0x11),
            new Uint8Array(48).fill(0x42),
            rpt,
            consumerIx,
            blockhash,
        ),
    );
    await rec('tx.rawAtomicOversized', () => {
        const tx = raw.buildAtomicAttestationTxOversized(
            payer,
            consumerProg,
            new Uint8Array(32).fill(0x11),
            new Uint8Array(48).fill(0x42),
            rpt,
            consumerIx,
            blockhash,
        );
        return { instructions: tx.instructions.map(ixJson) };
    });

    // Session signing: deterministic key from a fixed seed gives a deterministic signature.
    const kp = await web3.Keypair.fromSeed(TEST_ONLY_SESSION_SEED);
    out.sessionKey = b58(kp.publicKey);
    const sessionIx = new web3.TransactionInstruction({
        data: Buffer.alloc(40, 0xff),
        keys: [{ isSigner: false, isWritable: true, pubkey: kp.publicKey }],
        programId: consumerProg,
    });
    await rec('tx.session', async () => {
        const tx = await sdk.buildSessionActionTx(payer, kp, sessionIx, blockhash);
        return {
            message: hex(tx.serializeMessage()),
            signatures: tx.signatures.map(s => [b58(s.publicKey), s.signature ? hex(s.signature) : null]),
            wire: hex(await tx.serialize({ requireAllSignatures: false, verifySignatures: false })),
        };
    });
    await rec('tx.sessionPayerIsSigner', async () => {
        const tx = await sdk.buildSessionActionTx(kp.publicKey, kp, sessionIx, blockhash);
        return { wire: hex(await tx.serialize({ requireAllSignatures: true, verifySignatures: true })) };
    });
    await rec('tx.sessionSystemProgram', async () => {
        const ix = web3.SystemProgram.transfer({ fromPubkey: kp.publicKey, lamports: 1000000000n, toPubkey: pk(4) });
        return await sdk.buildSessionActionTx(kp.publicKey, kp, ix, blockhash);
    });

    // Error behaviour at public exports (sync throws, recorded by message).
    await rec('err.vcekLen', () => sdk.deriveVcekPda(new Uint8Array(31), 1n));
    await rec('err.nonceSource', () => sdk.deriveUsedNoncePdaForSource(3, signer, nonce));
    await rec('err.nonceLen', () => sdk.deriveLegacyUsedNoncePda(signer, new Uint8Array(31)));
    await rec('err.googleLen', () => sdk.deriveGoogleUsedNoncePda(new Uint8Array(31)));
    await rec('err.backendSource', () => sdk.deriveBackendPolicyPda(0));
    await rec('err.policyCount', () => sdk.buildSetBackendPolicyIx(authority, payer, 1, Array(9).fill(m48)));
    await rec('err.policyLen', () => sdk.buildSetBackendPolicyIx(authority, payer, 1, [new Uint8Array(47)]));
    await rec('err.gcp', () => sdk.buildSetGcpTenantPolicyIx(authority, payer, '', 's'));
    await rec('err.rotateSame', () => sdk.buildRotateAuthorityIx(authority, authority));
    await rec('err.rotateDefault', () => sdk.buildRotateAuthorityIx(authority, web3.PublicKey.default));
    await rec('err.jwksKid', () => sdk.buildRegisterJwksKeyIx(authority, payer, Buffer.alloc(0), modulus));
    await rec('err.jwksRsa', () => sdk.buildRegisterJwksKeyIx(authority, payer, Buffer.from('k'), modulus, 3));
    await rec('err.shortReport', () => sdk.buildRegisterSignerIx(payer, signer, new Uint8Array(16), 1));
    await rec('err.nitroEmptyDoc', () =>
        sdk.buildVerifyNitroAttestationIx(payer, signer, 0, 1, new Uint8Array(32), new Uint8Array(0), nonce),
    );
    await rec('err.nitroMode', () =>
        raw.buildVerifyNitroAttestationIxOversized(payer, signer, 2, 1, new Uint8Array(32), doc, nonce),
    );
    await rec('err.nitroNoConsumer', () =>
        raw.buildVerifyNitroAttestationTxOversized(
            payer,
            signer,
            1,
            1,
            new Uint8Array(32),
            doc,
            nonce,
            blockhash,
            null,
        ),
    );
    await rec('err.nvidiaMode', () => sdk.buildVerifyNvidiaAttestationIx(payer, signer, 2, 1, chip, chip, chip));
    await rec('err.nvidiaConsumer', () =>
        sdk.buildVerifyNvidiaAttestationIx(payer, signer, 1, 1, chip, chip, chip, null, pid),
    );
    await rec('err.hashActionLegacy', () => sdk.hashAction(Uint8Array.of(7), [pk(1)], new Uint8Array()));
    await rec('err.parseShort', () => sdk.parseAttestedSignerAccount(new Uint8Array(10)));
    await rec('err.parseDisc', () => sdk.parseAttestedSignerAccount(new Uint8Array(154)));

    // Account parser.
    const acct = Buffer.alloc(154);
    Buffer.from(sdk.ATTESTED_SIGNER_DISCRIMINATOR).copy(acct);
    acct.fill(1, 8, 40);
    acct[40] = 2;
    acct.fill(3, 41, 89);
    acct.fill(4, 89, 121);
    acct.writeBigUInt64LE(5n, 121);
    acct.writeBigUInt64LE(6n, 129);
    acct.writeBigUInt64LE(7n, 137);
    acct[145] = 8;
    acct.writeBigInt64LE(9n, 146);
    const parsed = sdk.parseAttestedSignerAccount(acct);
    out.parsed = Object.fromEntries(
        Object.entries(parsed).map(([k, v]) => [
            k,
            typeof v === 'bigint' ? v.toString() : typeof v === 'number' ? v : hex(v),
        ]),
    );
    out.valid = [
        sdk.isAttestedSignerValid(acct, 7n, 8n),
        sdk.isAttestedSignerValid(acct, 8n, 8n),
        sdk.isAttestedSignerValid(acct, 7n, 9n),
    ];

    return Object.fromEntries(
        Object.keys(out)
            .sort()
            .map(k => [k, out[k]]),
    );
}

// Calls whose vector is an error on purpose. Every other call must record a result.
const EXPECTED_TO_FAIL = new Set([
    'tx.nitroModeBBadHash',
    'tx.rawAtomicTooLarge',
    'tx.rawNitroTooLarge',
    'tx.rawRegisterTooLarge',
    'tx.sessionSystemProgram',
]);

void test('outputs match the vectors recorded before the dependency upgrade', async () => {
    const actual = JSON.parse(JSON.stringify(await collect()));
    for (const [name, result] of Object.entries(actual)) {
        const failed = typeof result === 'object' && result !== null && 'err' in result;
        assert.equal(failed, name.startsWith('err.') || EXPECTED_TO_FAIL.has(name), `${name}: unexpected outcome`);
    }
    if (process.env.SOLANA_CC_WRITE_FIXTURE === '1') {
        fs.mkdirSync(path.dirname(FIXTURE), { recursive: true });
        fs.writeFileSync(FIXTURE, JSON.stringify(actual, null, 1) + '\n');
        return;
    }
    assert.deepEqual(actual, JSON.parse(fs.readFileSync(FIXTURE, 'utf8')));
});
