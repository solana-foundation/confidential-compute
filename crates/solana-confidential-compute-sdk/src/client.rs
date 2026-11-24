//! Client implementation for interacting with Solana Confidential Compute on-chain programs.

use solana_confidential_compute_core::types::AttestedSigner;
use solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::transaction::Transaction;

use crate::builder::{self, SdkError};

/// Primary client for Solana Confidential Compute verifier interactions.
pub struct ConfidentialComputeClient {
    pub program_id: Pubkey,
}

impl ConfidentialComputeClient {
    /// Creates a new ConfidentialComputeClient instance.
    pub fn new(program_id: Pubkey) -> Self {
        Self { program_id }
    }

    /// Derives the PDA for an attested signer given its Ed25519 public key.
    pub fn derive_signer_pda(&self, signer_pubkey: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED, signer_pubkey],
            &self.program_id,
        )
    }

    /// Derives the PDA for a cached VCEK chip key.
    pub fn derive_vcek_pda(&self, chip_id_hash: &[u8; 32], tcb_version: u64) -> (Pubkey, u8) {
        let tcb_bytes = tcb_version.to_le_bytes();
        Pubkey::find_program_address(&[builder::VCEK_SEED, chip_id_hash, &tcb_bytes], &self.program_id)
    }

    /// Derives the PolicyRegistry singleton PDA.
    pub fn derive_policy_registry_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"policy_registry"], &self.program_id)
    }

    /// Explicit current AMD/Nitro source; no default source or legacy fallback.
    pub fn derive_used_nonce_pda_for_source(
        &self,
        source: u8,
        signer: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<(Pubkey, u8), crate::NonceError> {
        crate::nonce::derive_used_nonce_pda_for_source(&self.program_id, source, signer, nonce)
    }
    /// Legacy address required only as the readonly migration guard.
    pub fn derive_legacy_used_nonce_pda(&self, signer: &[u8; 32], nonce: &[u8; 32]) -> (Pubkey, u8) {
        crate::nonce::derive_legacy_used_nonce_pda(&self.program_id, signer, nonce)
    }
    pub fn derive_google_used_nonce_pda(&self, binding: &[u8]) -> Result<(Pubkey, u8), crate::NonceError> {
        crate::nonce::derive_google_used_nonce_pda(&self.program_id, binding)
    }
    pub fn derive_legacy_google_used_nonce_pda(&self, binding: &[u8]) -> Result<(Pubkey, u8), crate::NonceError> {
        crate::nonce::derive_legacy_google_used_nonce_pda(&self.program_id, binding)
    }

    /// Checks both V2 time limits. The deadline must come from an authenticated
    /// V2 account; callers supply trusted cluster Clock values. This local
    /// utility does not authenticate account ownership, address, or platform.
    ///
    /// @spec SCC-VERIFY-008
    pub fn is_signer_valid(
        &self,
        record: &AttestedSigner,
        expires_unix_timestamp: i64,
        current_slot: u64,
        current_unix_timestamp: i64,
    ) -> bool {
        !record.is_expired(current_slot)
            && current_unix_timestamp >= 0
            && current_unix_timestamp < expires_unix_timestamp
    }

    /// Returns whether Mode B must allocate a UsedNonceAccount.
    ///
    /// Always `true`. The `stateless_idempotent` argument is accepted for API
    /// compatibility and is ignored. On-chain `verify_atomic` is fail-closed
    /// with `NonceRequired` (@spec SCC-SEC-005).
    pub fn mode_b_require_nonce(_stateless_idempotent: bool) -> bool {
        true
    }

    /// Returns the Mode B instruction discriminator.
    ///
    /// Always `VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR`. The `stateless_idempotent`
    /// argument is accepted for API compatibility and is ignored; on-chain
    /// `verify_atomic` is fail-closed with `NonceRequired` (@spec SCC-SEC-005).
    pub fn mode_b_discriminator(_stateless_idempotent: bool) -> [u8; 8] {
        VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR
    }

    /// Mode A enrollment against this client's program id.
    ///
    /// @spec SCC-SDK-001
    pub fn build_register_signer_ix(
        &self,
        payer: &Pubkey,
        signer: &Pubkey,
        report_data: &[u8],
        expires_slot: u64,
    ) -> Result<Instruction, SdkError> {
        builder::build_register_signer_ix_for_program(&self.program_id, payer, signer, report_data, expires_slot, 0)
    }

    /// Mode A execution: consumer instruction signed by the attested workload key.
    ///
    /// @spec SCC-SDK-001
    #[allow(clippy::unused_self)]
    /// Local workload-key signing. Rejects System Program instructions; custom
    /// consumer data requires caller policy validation. Keep the key in enclave
    /// memory; production remote callers should use sidecar `/v1/sign`.
    pub fn build_session_action_tx(
        &self,
        payer: &Pubkey,
        signer_keypair: &Keypair,
        consumer_ix: Instruction,
        recent_blockhash: Hash,
    ) -> Result<Transaction, SdkError> {
        builder::build_session_action_tx(payer, signer_keypair, consumer_ix, recent_blockhash)
    }

    /// Mode B atomic transaction: `verify_atomic_with_nonce` at index 0, consumer at index 1.
    ///
    /// @spec SCC-SDK-001 SCC-SEC-005
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_attestation_tx(
        &self,
        payer: &Pubkey,
        consumer_program_id: &Pubkey,
        action_hash: [u8; 32],
        measurement: [u8; 48],
        report: &[u8],
        consumer_ix: Instruction,
        recent_blockhash: Hash,
    ) -> Result<Transaction, SdkError> {
        builder::build_atomic_attestation_tx_for_program(
            &self.program_id,
            payer,
            consumer_program_id,
            action_hash,
            measurement,
            report,
            consumer_ix,
            recent_blockhash,
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_confidential_compute_core::types::EnclaveType;

    #[test]
    fn test_signer_validity() {
        let client = ConfidentialComputeClient::new(Pubkey::new_unique());
        let record = AttestedSigner {
            signer_pubkey: [1u8; 32],
            enclave_type: EnclaveType::AmdSevSnp,
            measurement: solana_confidential_compute_core::MeasurementDigest::new([0u8; 48]),
            chip_id_hash: [0u8; 32],
            tcb_version: 1,
            registered_slot: 100,
            expires_slot: 200,
        };

        assert!(client.is_signer_valid(&record, 500, 150, 499));
        assert!(!client.is_signer_valid(&record, 500, 201, 499));
        assert!(!client.is_signer_valid(&record, 500, 150, 500));
        assert!(!client.is_signer_valid(&record, 500, 150, -1));
    }

    #[test]
    fn test_mode_b_defaults_to_nonce_bound() {
        assert!(ConfidentialComputeClient::mode_b_require_nonce(false));
        assert!(ConfidentialComputeClient::mode_b_require_nonce(true));
        assert_eq!(ConfidentialComputeClient::mode_b_discriminator(false), VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
        assert_eq!(ConfidentialComputeClient::mode_b_discriminator(true), VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
    }
}
