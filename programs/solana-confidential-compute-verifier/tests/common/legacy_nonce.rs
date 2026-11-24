#[path = "source_policy.rs"]
mod source_policy_fixture;
// Explicit empty canonical legacy nonce fixtures; no production fallback.
use solana_confidential_compute_core::SignatureVerifier;
use solana_confidential_compute_verifier::payload::*;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
pub struct TestProcessor;
fn legacy_address(pid: &Pubkey, data: &[u8]) -> Option<Pubkey> {
    let disc = data.get(..8)?;
    if disc == VERIFY_AND_REGISTER_DISCRIMINATOR || disc == VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR {
        let offset = if disc == VERIFY_AND_REGISTER_DISCRIMINATOR {
            16
        } else {
            80
        };
        let view = solana_confidential_compute_core::SnpReportView::try_from_slice(
            data.get(offset..offset + 1184)?,
        )
        .ok()?;
        return Some(
            Pubkey::find_program_address(&[b"nonce", &view.pubkey(), &view.nonce()], pid).0,
        );
    }
    if disc == VERIFY_NITRO_ATTESTATION_DISCRIMINATOR {
        let (_, view) =
            solana_confidential_compute_crypto::parse_nitro_attestation(data.get(53..)?).ok()?;
        return Some(
            Pubkey::find_program_address(&[b"nonce", &view.user_data, &view.nonce], pid).0,
        );
    }
    if disc == VERIFY_GOOGLE_JWT_DISCRIMINATOR {
        let view = solana_confidential_compute_crypto::jwt::JwtView::parse(
            core::str::from_utf8(data.get(53..)?).ok()?,
        )
        .ok()?;
        let claims =
            solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64)
                .ok()?;
        let raw = if *data.get(8)? == 0 {
            claims.decode_mode_a_binding().ok()?.to_vec()
        } else {
            claims.decode_mode_b_commitment().ok()?.to_vec()
        };
        let seed = solana_confidential_compute_crypto::jwt::eat_nonce_tombstone_seed(&raw);
        return Some(Pubkey::find_program_address(&[b"nonce", &seed], pid).0);
    }
    None
}
fn accounts<'a>(pid: &Pubkey, original: &[AccountInfo<'a>], data: &[u8]) -> Vec<AccountInfo<'a>> {
    let mut accounts = original.to_vec();
    if let Some(key) = legacy_address(pid, data) {
        if !accounts.iter().any(|a| a.key == &key) {
            accounts.push(AccountInfo::new(
                Box::leak(Box::new(key)),
                false,
                false,
                Box::leak(Box::new(0)),
                Box::leak(Vec::new().into_boxed_slice()),
                Box::leak(Box::new(solana_sdk_ids::system_program::ID)),
                false,
            ));
        }
    }
    accounts
}
#[allow(dead_code)]
impl TestProcessor {
    pub fn process(pid: &Pubkey, original: &[AccountInfo], data: &[u8]) -> ProgramResult {
        source_policy_fixture::TestProcessor::process(pid, &accounts(pid, original, data), data)
    }
    pub fn process_with<V: SignatureVerifier>(
        v: &V,
        pid: &Pubkey,
        original: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        source_policy_fixture::TestProcessor::process_with(
            v,
            pid,
            &accounts(pid, original, data),
            data,
        )
    }
    pub fn verify_recent_slot_hash(
        a: &AccountInfo,
        now: u64,
        nonce: u64,
        hash: &[u8; 32],
    ) -> Result<(), solana_confidential_compute_verifier::error::VerifierError> {
        solana_confidential_compute_verifier::processor::Processor::verify_recent_slot_hash(
            a, now, nonce, hash,
        )
    }
}
