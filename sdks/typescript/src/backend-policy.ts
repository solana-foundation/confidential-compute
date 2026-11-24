/** Authoritative measurement governance for AMD=1, Nitro=2, GCP=3.
 * Global registry measurements are legacy storage, not runtime admission controls.
 * Set each relevant backend list empty to halt new admission (all three for all
 * backends). Existing Mode A signer records require separate revocation.
 */
import {PublicKey,TransactionInstruction,SystemProgram} from "@solana/web3.js";
import {SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,derivePolicyRegistryPda} from "./index";
export const SET_BACKEND_POLICY_DISCRIMINATOR=new Uint8Array([21,155,245,154,100,138,42,166]);
export const BACKEND_POLICY_SEED="backend_policy";
export function deriveBackendPolicyPda(source:number,programId:PublicKey=SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID):[PublicKey,number]{
 if(![1,2,3,4,5].includes(source))throw new Error("backend source must be AMD1, Nitro2, GCP3, NVIDIA4 or IntelTdx5");
 return PublicKey.findProgramAddressSync([Buffer.from(BACKEND_POLICY_SEED),Buffer.from([source])],programId);
}
export function buildSetBackendPolicyIx(authority:PublicKey,payer:PublicKey,source:number,measurements:Uint8Array[],programId:PublicKey=SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID):TransactionInstruction{
 const backend=deriveBackendPolicyPda(source,programId)[0];if(measurements.length>8)throw new Error("at most eight measurements");
 for(const measurement of measurements)if(measurement.length!==48)throw new Error("measurement must be 48 bytes");
 const count=Buffer.alloc(4);count.writeUInt32LE(measurements.length);
 return new TransactionInstruction({programId,keys:[{pubkey:authority,isSigner:true,isWritable:false},{pubkey:derivePolicyRegistryPda(programId)[0],isSigner:false,isWritable:false},{pubkey:backend,isSigner:false,isWritable:true},{pubkey:payer,isSigner:true,isWritable:true},{pubkey:SystemProgram.programId,isSigner:false,isWritable:false}],data:Buffer.concat([Buffer.from(SET_BACKEND_POLICY_DISCRIMINATOR),Buffer.from([source]),count,...measurements.map(m=>Buffer.from(m)),Buffer.alloc((8-measurements.length)*48)])});
}
