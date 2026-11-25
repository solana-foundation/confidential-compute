// Exercise the actual smoke initialization block with an in-memory RPC stub.
// This test sends no transactions and requires no web3/package installation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'smoke_test_devnet.ts'), 'utf8');
const block = source.slice(
    source.indexOf('  // 2. Check/Initialize PolicyRegistry'),
    source.indexOf('  // 3. Test Mode B'),
);

async function simulate({ existing = null, programData } = {}) {
    class PublicKey {
        constructor(bytes) {
            this.bytes = Buffer.from(bytes);
        }
        toBytes() {
            return this.bytes;
        }
        toBuffer() {
            return this.bytes;
        }
        toBase58() {
            return this.bytes.toString('hex');
        }
        equals(other) {
            return this.bytes.equals(other.bytes);
        }
        static async findProgramAddress(seeds, owner) {
            assert.equal(seeds.length, 1);
            assert.deepEqual(seeds[0], program.toBuffer());
            assert.ok(owner.equals(loader));
            return [pd];
        }
    }
    const key = n => new PublicKey(Buffer.alloc(32, n));
    const program = key(1),
        payer = { publicKey: key(2) },
        registry = key(3),
        pd = key(4),
        loader = key(5);
    const discriminator = Buffer.from([175, 179, 180, 44, 5, 161, 62, 240]);
    const stored = Buffer.alloc(529);
    discriminator.copy(stored);
    payer.publicKey.toBuffer().copy(stored, 8);
    const metadata = Buffer.alloc(45);
    metadata.writeUInt32LE(3);
    metadata[12] = 1;
    payer.publicKey.toBuffer().copy(metadata, 13);
    const registryInfo = existing === null ? null : { data: stored, owner: program };
    const pdInfo = programData === null ? null : { data: metadata, owner: loader };
    if (typeof existing === 'function') existing(registryInfo, key);
    if (typeof programData === 'function') programData(pdInfo, key);
    const sent = [],
        logs = [];
    const context = {
        Buffer,
        EXPECTED_MEASUREMENT: new Uint8Array(48).fill(0x42),
        INIT_POLICY_REGISTRY_DISCRIMINATOR: [90, 53, 0, 89, 164, 70, 107, 186],
        POLICY_REGISTRY_DISCRIMINATOR: discriminator,
        PublicKey,
        SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID: program,
        SystemProgram: { programId: key(6) },
        Transaction: class {
            add(ix) {
                this.ix = ix;
                return this;
            }
        },
        TransactionInstruction: class {
            constructor(args) {
                Object.assign(this, args);
            }
        },
        UPGRADEABLE_LOADER_ID: loader,
        Uint8Array,
        bytesEqual: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
        connection: {
            getAccountInfo: address => Promise.resolve(address.equals(registry) ? registryInfo : pdInfo),
        },
        console: { log: (...args) => logs.push(args.join(' ')) },
        derivePolicyRegistryPda: () => [registry],
        payer,
        sendAndConfirmTransaction: (_connection, tx) => {
            sent.push(tx.ix);
            return Promise.resolve('test-signature');
        },
    };
    await vm.runInNewContext(`(async () => {${block}\n})()`, context);
    return { logs, payer, pd, sent };
}

void test('fresh initialization binds fourth account and serialized authority', async () => {
    const { sent, pd, payer } = await simulate();
    assert.equal(sent.length, 1);
    assert.equal(sent[0].keys.length, 4);
    assert.ok(sent[0].keys[3].pubkey.equals(pd));
    assert.equal(sent[0].keys[3].isSigner, false);
    assert.equal(sent[0].keys[3].isWritable, false);
    assert.deepEqual(sent[0].data.subarray(8, 40), payer.publicKey.toBuffer());
});
void test('already initialized requires expected owner, shape, discriminator and authority', async () => {
    assert.equal((await simulate({ existing: true })).sent.length, 0);
    for (const mutate of [
        (a, key) => {
            a.owner = key(99);
        },
        a => {
            a.data = Buffer.alloc(39);
        },
        a => {
            a.data[0] ^= 1;
        },
        a => {
            a.data[8] ^= 1;
        },
    ]) {
        await assert.rejects(simulate({ existing: mutate }), /invalid or controlled by another authority/);
    }
});
void test('missing, finalized, malformed or mismatching ProgramData cannot initialize', async () => {
    for (const programData of [
        null,
        (a, key) => {
            a.owner = key(99);
        },
        a => {
            a.data = Buffer.alloc(44);
        },
        a => {
            a.data[0] = 2;
        },
        a => {
            a.data[12] = 0;
        },
        a => {
            a.data[12] = 2;
        },
        a => {
            a.data[13] ^= 1;
        },
    ]) {
        await assert.rejects(simulate({ programData }), /current upgrade authority/);
    }
});
