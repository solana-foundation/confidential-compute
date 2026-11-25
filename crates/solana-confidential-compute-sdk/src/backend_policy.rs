//! Authoritative per-backend measurement governance for AMD=1, Nitro=2, GCP=3.
//! Global registry measurements are legacy storage and do not restrict admission.
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
pub const BACKEND_POLICY_SEED: &[u8] = b"backend_policy";
pub const SET_BACKEND_POLICY_DISCRIMINATOR: [u8; 8] = [21, 155, 245, 154, 100, 138, 42, 166];
pub const AMD_SOURCE: u8 = 1;
pub const NITRO_SOURCE: u8 = 2;
pub const GCP_SOURCE: u8 = 3;
pub const NVIDIA_SOURCE: u8 = 4;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackendPolicyError {
    #[error("backend source must be AMD1, Nitro2, GCP3 or NVIDIA4")]
    InvalidSource,
    #[error("at most eight 48-byte measurements are supported")]
    InvalidMeasurements,
}
pub fn derive_backend_policy_pda(program_id: &Pubkey, source: u8) -> Result<(Pubkey, u8), BackendPolicyError> {
    // 5 is Intel TDX. Without it a caller has to hand-encode the
    // governance transaction that seats the TDX policy.
    if !(1..=5).contains(&source) {
        return Err(BackendPolicyError::InvalidSource);
    }
    Ok(backend_policy_pda(program_id, source))
}
/// Address for a source tag that a builder in this crate passes as a constant
/// (`AMD_SOURCE`, `NITRO_SOURCE`, `NVIDIA_SOURCE` or `TDX_SOURCE`).
/// [`derive_backend_policy_pda`] accepts each of them, so this skips its source check.
pub(crate) fn backend_policy_pda(program_id: &Pubkey, source: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[BACKEND_POLICY_SEED, &[source]], program_id)
}
/// An empty list halts new admission for this backend. Set all three backend
/// lists empty to halt all backends. Existing Mode A signers must be revoked
/// separately with `governance::build_revoke_attested_signer_ix`.
pub fn build_set_backend_policy_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    source: u8,
    measurements: &[[u8; 48]],
) -> Result<Instruction, BackendPolicyError> {
    let backend = derive_backend_policy_pda(program_id, source)?.0;
    if measurements.len() > 8 {
        return Err(BackendPolicyError::InvalidMeasurements);
    }
    let mut data = SET_BACKEND_POLICY_DISCRIMINATOR.to_vec();
    data.push(source);
    data.extend_from_slice(&(measurements.len() as u32).to_le_bytes());
    for i in 0..8 {
        data.extend_from_slice(measurements.get(i).unwrap_or(&[0; 48]));
    }
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(Pubkey::find_program_address(&[b"policy_registry"], program_id).0, false),
            AccountMeta::new(backend, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data,
    })
}
/// Builder-internal source tags are fixed constants, not caller-controlled.
pub(crate) fn with_backend_policy(mut ix: Instruction, source: u8) -> Instruction {
    let address = backend_policy_pda(&ix.program_id, source).0;
    ix.accounts.push(AccountMeta::new_readonly(address, false));
    ix
}
