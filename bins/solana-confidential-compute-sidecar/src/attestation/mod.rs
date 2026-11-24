//! Hardware and cloud attestation providers for Solana Confidential Compute Sidecar.
//!
//! @spec SCC-SIDECAR-002 SCC-SIDECAR-003 SCC-SIDECAR-004

pub mod gcp_oidc;
pub mod intel_tdx;
pub mod mock;
pub mod nitro;
pub mod nvidia_h100;
pub mod sev_snp;
pub mod simulation;

pub use simulation::request_for_submission;

use solana_confidential_compute_core::types::EnclaveType;
use solana_sdk::pubkey::Pubkey;

use crate::error::SidecarError;

/// Hardware attestation report payload emitted by the enclave provider.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AttestationReport {
    /// AMD SEV-SNP 1,184-byte report with optional VCEK certificate chain.
    SevSnp {
        report: Vec<u8>,
        vcek_cert: Option<Vec<u8>>,
    },
    /// Google Cloud Confidential Space OIDC / JWT attestation token.
    GcpJwt { jwt: String },
    /// AWS Nitro Enclaves tagged COSE Sign1 attestation document.
    /// @spec SCC-NITRO-003
    AwsNitro { document: Vec<u8> },
    /// NVIDIA Confidential GPU (Hopper H100/H200) composite report.
    /// @spec SCC-NVIDIA-002
    NvidiaH100 {
        composite_report: Vec<u8>,
        gpu_measurement: [u8; 32],
        spdm_report: Vec<u8>,
    },
    /// Intel TDX quote bound to the composite GPU challenge.
    ///
    /// `report_data` is the 64-byte `REPORTDATA` commitment. A quote that
    /// starts with the synthetic prefix is a dry-run artifact.
    /// @spec SCC-TDX-001 SCC-TDX-002 SCC-SIDECAR-002
    IntelTdx {
        quote: Vec<u8>,
        #[serde(with = "serde_byte_array")]
        report_data: [u8; 64],
        composite_challenge: [u8; 32],
        #[serde(with = "serde_byte_array")]
        mr_td: [u8; 48],
        #[serde(with = "serde_byte_array")]
        mr_config_id: [u8; 48],
        rtmrs_hash: [u8; 32],
    },
}

/// Serde codec for byte arrays longer than 32. Serde's built-in array impl stops at 32.
mod serde_byte_array {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S, const N: usize>(value: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(N)?;
        for byte in value {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of {N} bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; N];
                for (index, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(index, &self))?;
                }
                Ok(out)
            }
        }

        deserializer.deserialize_tuple(N, ArrayVisitor::<N>)
    }
}

/// Abstract hardware attestation provider interface.
pub trait AttestationProvider: Send + Sync {
    /// Returns the hardware enclave type for this provider.
    fn enclave_type(&self) -> EnclaveType;

    /// Requests a fresh hardware attestation binding the ephemeral workload key
    /// and the recent Solana slot hash challenge.
    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>,
    >;
}
