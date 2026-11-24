//! Canonical domain types for Solana Confidential Compute enclaves.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Supported hardware enclave environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EnclaveType {
    /// AMD SEV-SNP (Secure Encrypted Virtualization-Secure Nested Paging).
    AmdSevSnp = 1,
    /// AWS Nitro Enclaves.
    /// @spec SCC-NITRO-008
    AwsNitro = 2,
    /// Google Cloud Confidential Space (OIDC / JWT attestation).
    GcpConfidentialSpace = 3,
    /// NVIDIA Confidential GPU (Hopper H100/H200 or Blackwell B200 composite).
    /// @spec SCC-NVIDIA-001
    NvidiaGpu = 4,
    /// Intel TDX Trust Domain.
    /// @spec SCC-TDX-001
    IntelTdx = 5,
    /// Mock enclave for local test harnesses.
    Mock = 255,
}

/// 48-byte SHA-384 binary measurement digest (MRENCLAVE / PCR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MeasurementDigest(#[serde(with = "serde_bytes")] pub [u8; 48]);

impl MeasurementDigest {
    pub const fn new(digest: [u8; 48]) -> Self {
        Self(digest)
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

/// Intel TDX measurements bound into one proof statement.
///
/// `rtmrs_hash` is the 32-byte RTMR digest, or a 32-byte journal digest.
/// @spec SCC-TDX-002
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct JournalV3 {
    #[serde(with = "serde_bytes")]
    pub mr_td: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_config_id: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rtmrs_hash: [u8; 32],
}

/// SHA-256(`mr_td` || `mr_config_id` || `rtmrs_hash`).
/// @spec SCC-TDX-002
pub fn compute_journal_hash(journal: &JournalV3) -> [u8; 32] {
    solana_program::hash::hashv(&[
        journal.mr_td.as_slice(),
        journal.mr_config_id.as_slice(),
        journal.rtmrs_hash.as_slice(),
    ])
    .to_bytes()
}

/// Attested signer record registered on-chain.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AttestedSigner {
    /// The Ed25519 public key generated and locked in enclave memory.
    pub signer_pubkey: [u8; 32],
    /// The hardware enclave type.
    pub enclave_type: EnclaveType,
    /// The measured digest of the workload binary.
    pub measurement: MeasurementDigest,
    /// SHA-256 hash of the 64-byte physical AMD Chip ID (or VLEK key hash).
    pub chip_id_hash: [u8; 32],
    /// Reported TCB version vector.
    pub tcb_version: u64,
    /// Slot number at which this attestation was verified.
    pub registered_slot: u64,
    /// Expiration slot number after which re-attestation is required.
    pub expires_slot: u64,
}

impl AttestedSigner {
    /// Returns true if the attestation is expired at the given slot (@spec SCC-VERIFY-008).
    #[inline]
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot > self.expires_slot
    }
}

/// Mode B instruction header after the 8-byte discriminator (72 bytes).
/// @spec SCC-VERIFY-010
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifyAtomicHeader {
    pub nonce_slot: u64,
    pub action_hash: [u8; 32],
    pub consumer_program_id: [u8; 32],
}

impl VerifyAtomicHeader {
    /// Byte size of the header after the 8-byte discriminator.
    pub const SIZE: usize = 72;
}

/// SHA-256(slot_hash || action_hash || consumer_program_id) via native `hashv`.
/// @spec SCC-VERIFY-012
pub fn compute_action_commitment(
    slot_hash: &[u8; 32],
    action_hash: &[u8; 32],
    consumer_program_id: &[u8; 32],
) -> [u8; 32] {
    solana_program::hash::hashv(&[slot_hash.as_slice(), action_hash.as_slice(), consumer_program_id.as_slice()])
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_action_commitment_is_deterministic() {
        let slot_hash = [0x11u8; 32];
        let action_hash = [0x22u8; 32];
        let consumer = [0x33u8; 32];
        let first = compute_action_commitment(&slot_hash, &action_hash, &consumer);
        let second = compute_action_commitment(&slot_hash, &action_hash, &consumer);
        assert_eq!(first, second);
        assert_ne!(first, compute_action_commitment(&slot_hash, &[0x44u8; 32], &consumer));
    }

    #[test]
    fn intel_tdx_enclave_type_is_source_five() {
        assert_eq!(EnclaveType::IntelTdx as u8, 5);
        let wire = borsh::to_vec(&EnclaveType::IntelTdx).unwrap();
        assert_eq!(wire, vec![5]);
    }

    #[test]
    fn journal_v3_hash_binds_each_measurement() {
        let journal = JournalV3 { mr_td: [0x11; 48], mr_config_id: [0x22; 48], rtmrs_hash: [0x33; 32] };
        let digest = compute_journal_hash(&journal);
        assert_eq!(
            digest,
            [
                0x37, 0x3e, 0x30, 0x83, 0x48, 0xc3, 0xe5, 0x23, 0x8f, 0xc0, 0x36, 0x0b, 0xf4, 0x6d, 0xe6, 0x0c, 0xd3,
                0x37, 0x75, 0xee, 0xbd, 0xbf, 0x6f, 0xf0, 0x43, 0x79, 0xb7, 0xd0, 0x70, 0x83, 0xe0, 0xb9,
            ]
        );
        assert_eq!(digest, compute_journal_hash(&journal));
        let mut changed = journal;
        changed.mr_td[0] ^= 1;
        assert_ne!(digest, compute_journal_hash(&changed));
        changed = journal;
        changed.mr_config_id[0] ^= 1;
        assert_ne!(digest, compute_journal_hash(&changed));
        changed = journal;
        changed.rtmrs_hash[0] ^= 1;
        assert_ne!(digest, compute_journal_hash(&changed));
    }
}
