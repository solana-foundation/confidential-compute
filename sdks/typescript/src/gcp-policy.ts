/** Offline setter for mandatory governed GCP tenant policy. */
import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

import { SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID, derivePolicyRegistryPda } from './index';
export const SET_GCP_TENANT_POLICY_DISCRIMINATOR = new Uint8Array([253, 197, 211, 209, 205, 86, 22, 43]);
export function buildSetGcpTenantPolicyIx(
    authority: PublicKey,
    payer: PublicKey,
    audience: string,
    subject: string,
    programId: PublicKey = SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
): TransactionInstruction {
    const a = Buffer.from(audience, 'utf8'),
        s = Buffer.from(subject, 'utf8');
    if (a.length === 0 || s.length === 0 || a.length > 128 || s.length > 160 || a.includes(0) || s.includes(0))
        throw new Error('tenant audience/subject must be nonempty non-NUL UTF-8 within128/160 bytes');
    const string = (b: Buffer) => {
        const len = Buffer.alloc(4);
        len.writeUInt32LE(b.length);
        return Buffer.concat([len, b]);
    };
    return new TransactionInstruction({
        programId,
        keys: [
            { pubkey: authority, isSigner: true, isWritable: false },
            { pubkey: derivePolicyRegistryPda(programId)[0], isSigner: false, isWritable: false },
            {
                pubkey: PublicKey.findProgramAddressSync([Buffer.from('gcp_tenant_policy')], programId)[0],
                isSigner: false,
                isWritable: true,
            },
            { pubkey: payer, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([Buffer.from(SET_GCP_TENANT_POLICY_DISCRIMINATOR), string(a), string(s)]),
    });
}
