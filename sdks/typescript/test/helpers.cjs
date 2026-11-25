const { randomBytes } = require('node:crypto');
const { PublicKey } = require('@solana/web3.js');

// web3.js 3 made `Keypair.generate()` async and removed `PublicKey.unique()`.
// Tests that only need a distinct address use this synchronous helper.
const randomKey = () => new PublicKey(randomBytes(32));

// Reference derivation for the SDK's synchronous PDA search: the library call.
const findPda = (seeds, programId) => PublicKey.findProgramAddress(seeds, programId);

// web3.js 3 returns instruction data as a plain Uint8Array, not a Buffer.
const dataOf = ix => Buffer.from(ix.data);

module.exports = { dataOf, findPda, randomKey };
