import { sha256 } from '@noble/hashes/sha2.js';
import { PublicKey } from '@solana/web3.js';

const PDA_MARKER = new TextEncoder().encode('ProgramDerivedAddress');
const MAX_SEEDS = 16;
const MAX_SEED_LENGTH = 32;

/**
 * Synchronous program-derived-address search.
 *
 * `@solana/web3.js` 3 removed `PublicKey.findProgramAddressSync`. Its
 * `findProgramAddress` is async, and every public derive and builder function
 * in this SDK is synchronous. This function keeps them synchronous. It follows
 * the algorithm that the runtime and `PublicKey.createProgramAddress` use:
 * `SHA-256(seeds || bump || programId || "ProgramDerivedAddress")`, with the
 * bump counting down from 255 to 1 until the hash is off the ed25519 curve.
 * The curve test is the library's own `PublicKey.isOnCurve`.
 * `test/pda.test.cjs` compares the result with `PublicKey.findProgramAddress`.
 *
 * @spec SCC-SDK-002 SCC-ARCH-001
 */
export function findProgramAddress(seeds: Uint8Array[], programId: PublicKey): [PublicKey, number] {
    if (seeds.length >= MAX_SEEDS) {
        throw new Error('too many PDA seeds');
    }
    for (const seed of seeds) {
        if (seed.length > MAX_SEED_LENGTH) {
            throw new Error('PDA seed exceeds 32 bytes');
        }
    }
    const programBytes = programId.toBytes();
    for (let bump = 255; bump > 0; bump--) {
        const hash = sha256.create();
        for (const seed of seeds) {
            hash.update(seed);
        }
        const candidate = hash.update(Uint8Array.of(bump)).update(programBytes).update(PDA_MARKER).digest();
        if (!PublicKey.isOnCurve(candidate)) {
            return [new PublicKey(candidate), bump];
        }
    }
    throw new Error('unable to find a viable program address bump seed');
}
