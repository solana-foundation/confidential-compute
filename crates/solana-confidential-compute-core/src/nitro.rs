//! AWS Nitro Enclaves attestation payload types and zero-copy views.
//!
//! @spec SCC-NITRO-003 SCC-NITRO-006 SCC-NITRO-008

/// SHA-384 PCR digest length.
pub const NITRO_PCR_LEN: usize = 48;

/// Workload Ed25519 public key embedded in `user_data`.
/// @spec SCC-NITRO-003
pub const NITRO_USER_DATA_LEN: usize = 32;

/// Fresh Solana slot blockhash (or Mode B action commitment) embedded in `nonce`.
/// @spec SCC-NITRO-003 SCC-NITRO-007
pub const NITRO_NONCE_LEN: usize = 32;

/// Maximum DER-encoded certificate length accepted from a Nitro document.
/// @spec SCC-NITRO-003
pub const MAX_NITRO_CERT_LEN: usize = 1024;

/// Maximum number of CA-bundle certificates (root + intermediates).
/// @spec SCC-NITRO-004
pub const MAX_NITRO_CABUNDLE: usize = 8;

/// Maximum on-chain Nitro COSE document length (accommodates 4-certificate AWS PKI chain).
pub const MAX_NITRO_DOCUMENT_LEN: usize = 8192;

/// PCR0 / PCR1 / PCR2 / PCR8 SHA-384 digests.
/// @spec SCC-NITRO-003 SCC-NITRO-006
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NitroPcrs {
    /// EIF image measurement. Must be non-zero and allowlisted on-chain.
    pub pcr0: [u8; NITRO_PCR_LEN],
    /// Kernel / bootstrap measurement.
    pub pcr1: [u8; NITRO_PCR_LEN],
    /// Application measurement.
    pub pcr2: [u8; NITRO_PCR_LEN],
    /// EIF signing-certificate hash (zeros when the EIF is unsigned).
    pub pcr8: [u8; NITRO_PCR_LEN],
}

impl NitroPcrs {
    /// True when PCR0 is the all-zero debug-enclave measurement.
    #[inline]
    pub fn pcr0_is_zero(&self) -> bool {
        self.pcr0.iter().all(|&b| b == 0)
    }
}

/// Zero-copy view over a parsed Nitro attestation payload map.
/// Large certificate fields borrow the input buffer; PCR / key / nonce are copied.
/// @spec SCC-NITRO-003
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NitroAttestationView<'a> {
    /// Nitro hypervisor module identifier.
    pub module_id: &'a str,
    /// UTC milliseconds since UNIX epoch.
    pub timestamp: u64,
    /// Hash algorithm name; must be `"SHA384"`.
    pub digest: &'a str,
    /// Extracted PCR0/1/2/8 values.
    pub pcrs: NitroPcrs,
    /// DER-encoded X.509 leaf certificate.
    pub certificate: &'a [u8],
    /// DER-encoded CA-bundle certificates, root first.
    pub cabundle: [&'a [u8]; MAX_NITRO_CABUNDLE],
    /// Number of populated `cabundle` slots.
    pub cabundle_len: u8,
    /// 32-byte Ed25519 workload public key from `user_data`.
    pub user_data: [u8; NITRO_USER_DATA_LEN],
    /// 32-byte slot blockhash or Mode B action commitment from `nonce`.
    pub nonce: [u8; NITRO_NONCE_LEN],
}

impl<'a> NitroAttestationView<'a> {
    /// Returns the populated CA-bundle slice.
    #[inline]
    pub fn cabundle_certs(&self) -> &[&'a [u8]] {
        &self.cabundle[..self.cabundle_len as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr0_zero_detects_debug_enclave() {
        let mut pcrs = NitroPcrs {
            pcr0: [0u8; 48],
            pcr1: [1u8; 48],
            pcr2: [2u8; 48],
            pcr8: [8u8; 48],
        };
        assert!(pcrs.pcr0_is_zero());
        pcrs.pcr0[0] = 1;
        assert!(!pcrs.pcr0_is_zero());
    }
}
