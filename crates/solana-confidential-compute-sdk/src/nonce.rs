//! Source-aware nonce migration. Legacy derivations are only replay guards.
//! Tagged seeds keep the `nonce` prefix; the extra one-byte source seed makes
//! every tagged preimage one byte longer than its untagged legacy form, so the
//! two address families cannot coincide.
use solana_sdk::{
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NonceError {
    #[error("workload nonce source must be AMD1 or Nitro2; Google uses a separate binding API")]
    InvalidSource,
    #[error("Google binding must be decoded raw ModeA64 or ModeB32 bytes")]
    InvalidGoogleBinding,
}
/// Current AMD/Nitro nonce tuple; unknown and Google source tags fail closed.
pub fn derive_used_nonce_pda_for_source(
    program_id: &Pubkey,
    source: u8,
    signer: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<(Pubkey, u8), NonceError> {
    if ![1, 2].contains(&source) {
        return Err(NonceError::InvalidSource);
    }
    Ok(used_nonce_pda(program_id, source, signer, nonce))
}
/// Address for a source tag that a builder in this crate passes as a constant
/// (`AMD_SOURCE` or `NITRO_SOURCE`). [`derive_used_nonce_pda_for_source`] accepts
/// both, so this skips its source check.
pub(crate) fn used_nonce_pda(program_id: &Pubkey, source: u8, signer: &[u8; 32], nonce: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nonce", &[source], signer, nonce], program_id)
}
/// Canonical pre-upgrade account, required as readonly migration guard.
pub fn derive_legacy_used_nonce_pda(program_id: &Pubkey, signer: &[u8; 32], nonce: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nonce", signer, nonce], program_id)
}
fn google_binding_hash(binding: &[u8]) -> Result<[u8; 32], NonceError> {
    if ![32, 64].contains(&binding.len()) {
        return Err(NonceError::InvalidGoogleBinding);
    }
    Ok(hash(binding).to_bytes())
}
/// SHA256 exactly once over decoded pubkey||slotHash64 (A) or commitment32 (B).
/// Never pass JSON/base64 strings or a prehashed ModeA binding.
pub fn derive_google_used_nonce_pda(program_id: &Pubkey, binding: &[u8]) -> Result<(Pubkey, u8), NonceError> {
    let digest = google_binding_hash(binding)?;
    Ok(Pubkey::find_program_address(&[b"nonce", &[3], &digest], program_id))
}
pub fn derive_legacy_google_used_nonce_pda(program_id: &Pubkey, binding: &[u8]) -> Result<(Pubkey, u8), NonceError> {
    let digest = google_binding_hash(binding)?;
    Ok(Pubkey::find_program_address(&[b"nonce", &digest], program_id))
}
pub(crate) fn with_legacy_nonce(mut ix: Instruction, legacy: Pubkey) -> Instruction {
    ix.accounts.push(AccountMeta::new_readonly(legacy, false));
    ix
}
