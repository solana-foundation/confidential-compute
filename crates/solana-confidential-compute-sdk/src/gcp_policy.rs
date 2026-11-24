//! Offline setter for the mandatory governed GCP audience/subject policy.
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("audience/subject must be nonempty non-NUL UTF-8, at most128/160 bytes")]
pub struct InvalidGcpTenantPolicy;
pub const SET_GCP_TENANT_POLICY_DISCRIMINATOR: [u8; 8] = [253, 197, 211, 209, 205, 86, 22, 43];
pub fn build_set_gcp_tenant_policy_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    audience: &str,
    subject: &str,
) -> Result<Instruction, InvalidGcpTenantPolicy> {
    if audience.is_empty()
        || subject.is_empty()
        || audience.len() > 128
        || subject.len() > 160
        || audience.contains('\0')
        || subject.contains('\0')
    {
        return Err(InvalidGcpTenantPolicy);
    }
    let mut data = SET_GCP_TENANT_POLICY_DISCRIMINATOR.to_vec();
    for value in [audience, subject] {
        data.extend_from_slice(&(value.len() as u32).to_le_bytes());
        data.extend_from_slice(value.as_bytes());
    }
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[b"policy_registry"], program_id).0,
                false,
            ),
            AccountMeta::new(
                Pubkey::find_program_address(&[b"gcp_tenant_policy"], program_id).0,
                false,
            ),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    })
}
