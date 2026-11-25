import { sha256 } from '@noble/hashes/sha2.js';
/** Source-aware addresses and explicit pre-upgrade replay guards. */
import { PublicKey } from '@solana/web3.js';

import { SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID } from './index';
import { findProgramAddress } from './internal/pda';

function requireNonce(nonce: Uint8Array): void {
    if (nonce.length !== 32) throw new Error('nonce must be 32 bytes');
}

/** Current AMD/Nitro tuple. Google and unknown sources fail closed. */
export function deriveUsedNoncePdaForSource(
    source: number,
    signer: PublicKey,
    nonce: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    if (![1, 2].includes(source)) {
        throw new Error('workload nonce source must be AMD1 or Nitro2; Google uses binding helpers');
    }
    requireNonce(nonce);
    return findProgramAddress([Buffer.from('nonce'), Buffer.from([source]), signer.toBytes(), nonce], programId);
}

/** Canonical pre-upgrade account, required as a readonly migration guard. */
export function deriveLegacyUsedNoncePda(
    signer: PublicKey,
    nonce: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    requireNonce(nonce);
    return findProgramAddress([Buffer.from('nonce'), signer.toBytes(), nonce], programId);
}

function bindingHash(binding: Uint8Array): Uint8Array {
    if (![32, 64].includes(binding.length)) {
        throw new Error('Google binding must be decoded raw Mode A 64 or Mode B 32 bytes');
    }
    return sha256(binding);
}

/** Raw decoded pubkey||slotHash (A) or commitment (B), hashed exactly once.
 * Never pass JSON/base64 strings or a prehashed Mode A binding.
 */
export function deriveGoogleUsedNoncePda(
    binding: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    return findProgramAddress([Buffer.from('nonce'), Buffer.from([3]), bindingHash(binding)], programId);
}

export function deriveLegacyGoogleUsedNoncePda(
    binding: Uint8Array,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): [PublicKey, number] {
    return findProgramAddress([Buffer.from('nonce'), bindingHash(binding)], programId);
}
