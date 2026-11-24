//! Canonical AMD identity revocation address, shared across TCB versions.
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
pub const AMD_REVOCATION_SEED: &[u8] = b"amd_revocation";
/// Identity is SHA256(chip ID) for VCEK, SHA256(endorsement XY) for VLEK.
/// This address does not assert a physical chip identity across VLEK keys.
pub fn derive_amd_revocation_pda(program_id: &Pubkey, identity: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[AMD_REVOCATION_SEED, identity], program_id)
}
pub(crate) fn with_amd_revocation(mut ix: Instruction, identity: &[u8; 32]) -> Instruction {
    let address = derive_amd_revocation_pda(&ix.program_id, identity).0;
    ix.accounts.push(AccountMeta::new_readonly(address, false));
    ix
}
