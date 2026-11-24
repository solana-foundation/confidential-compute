//! Compiled contracts across the SDK, CPI helpers, core, and verifier.
use solana_confidential_compute_verifier::{payload as wire, state};

#[test]
fn instruction_and_account_constants_agree() {
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_AND_REGISTER_DISCRIMINATOR,
        wire::VERIFY_AND_REGISTER_DISCRIMINATOR
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_ATOMIC_DISCRIMINATOR,
        wire::VERIFY_ATOMIC_DISCRIMINATOR
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
        wire::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
        wire::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR
    );
    assert_eq!(
        solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR,
        wire::VERIFY_GOOGLE_JWT_DISCRIMINATOR
    );
    assert_eq!(
        solana_confidential_compute_sdk::ATTESTED_SIGNER_DISCRIMINATOR,
        state::ATTESTED_SIGNER_DISCRIMINATOR
    );
    assert_eq!(
        solana_confidential_compute_cpi::ATTESTED_SIGNER_ACCOUNT_SIZE,
        state::AttestedSignerAccount::SIZE
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_NITRO_MODE_A,
        wire::VERIFY_NITRO_MODE_A
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_NITRO_MODE_B,
        wire::VERIFY_NITRO_MODE_B
    );
    assert_eq!(
        solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_MODE_B,
        wire::VERIFY_GOOGLE_JWT_MODE_B
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_AND_REGISTER_IX_LEN,
        8 + 8 + solana_confidential_compute_core::SNP_REPORT_SIZE + 2
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_ATOMIC_WITH_NONCE_IX_LEN,
        8 + solana_confidential_compute_core::types::VerifyAtomicHeader::SIZE
            + solana_confidential_compute_core::SNP_REPORT_SIZE
            + 1
    );
    assert_eq!(
        solana_confidential_compute_sdk::VERIFY_NITRO_ATTESTATION_HEADER_LEN,
        53
    );
}
