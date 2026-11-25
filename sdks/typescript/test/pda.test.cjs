const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { PublicKey } = require('@solana/web3.js');
const { findProgramAddress } = require('../dist/internal/pda.js');
const { findPda, randomKey } = require('./helpers.cjs');

// @spec SCC-SDK-002 SCC-ARCH-001
void test('synchronous PDA search equals PublicKey.findProgramAddress', async () => {
    let lowered = 0;
    for (let i = 0; i < 500; i++) {
        const seeds = Array.from({ length: i % 5 }, (_, j) => randomBytes((i + 7 * j) % 33));
        const programId = randomKey();
        const [address, bump] = findProgramAddress(seeds, programId);
        const [expectedAddress, expectedBump] = await findPda(seeds, programId);
        assert.ok(address.equals(expectedAddress), `seeds ${i}`);
        assert.equal(bump, expectedBump, `bump ${i}`);
        assert.equal(PublicKey.isOnCurve(address), false);
        if (bump < 255) lowered++;
    }
    // About half of the hashes at bump 255 are on the curve, so the search must step down.
    assert.ok(lowered > 100, `only ${lowered} searches left bump 255`);
});

void test('synchronous PDA search rejects seeds the runtime rejects', () => {
    const programId = randomKey();
    assert.throws(() => findProgramAddress([new Uint8Array(33)], programId), /32 bytes/);
    assert.throws(
        () =>
            findProgramAddress(
                Array.from({ length: 16 }, () => new Uint8Array(1)),
                programId,
            ),
        /too many/,
    );
    assert.doesNotThrow(() =>
        findProgramAddress(
            Array.from({ length: 15 }, () => new Uint8Array(32)),
            programId,
        ),
    );
    assert.doesNotThrow(() => findProgramAddress([], programId));
});
