//! Configuration for the Solana Confidential Compute Enclave Sidecar Daemon.
//!
//! @spec SCC-SIDECAR-004 SCC-SIDECAR-005

use clap::{Parser, ValueEnum};
use solana_sdk::pubkey::Pubkey;
use std::net::SocketAddr;

use crate::error::SidecarError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveMode {
    /// AMD SEV-SNP via Linux /dev/sev-guest ioctl.
    AmdSevSnp,
    /// AWS Nitro Enclaves via Linux /dev/nsm ioctl.
    #[value(alias = "aws_nitro")]
    AwsNitro,
    /// Google Cloud Confidential Space launcher OIDC client.
    GcpConfidentialSpace,
    /// NVIDIA Confidential GPU (Hopper H100/H200).
    ///
    /// Dry-run uses a local synthetic measurement. Live appraisal fails closed
    /// and does not emit that measurement.
    /// @spec SCC-NVIDIA-001
    #[value(alias = "nvidia")]
    NvidiaGpu,
    /// Intel TDX guest. Dry-run returns a synthetic quote. Live mode probes
    /// the guest device and the dstack socket, then fails closed.
    /// @spec SCC-TDX-001 SCC-SIDECAR-004
    #[value(alias = "tdx")]
    IntelTdx,
    /// Synthetic mock provider for local development, CI, and test harnesses.
    Mock,
}

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "Solana Confidential Compute Enclave Sidecar Daemon"
)]
pub struct SidecarConfig {
    /// Loopback bind address for local RPC API.
    #[arg(long, env = "SOLANA_CC_BIND_ADDR", default_value = "127.0.0.1:8080")]
    pub bind_addr: SocketAddr,

    /// Operator bearer token file. Unset disables HTTP attest/renew; heartbeat still runs.
    #[arg(long, env = "SOLANA_CC_ENROLLMENT_TOKEN_FILE")]
    pub enrollment_token_file: Option<std::path::PathBuf>,

    /// Minimum seconds between HTTP enrollment attempts, shared by attest and renew.
    #[arg(long, env = "SOLANA_CC_ENROLLMENT_MIN_INTERVAL_SECS", default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(60..=86400))]
    pub enrollment_min_interval_secs: u64,

    /// Solana RPC endpoint URL.
    #[arg(
        long,
        env = "SOLANA_CC_SOLANA_RPC_URL",
        default_value = "https://api.devnet.solana.com"
    )]
    pub solana_rpc_url: String,

    /// Enclave execution environment.
    #[arg(
        long,
        env = "SOLANA_CC_ENCLAVE_MODE",
        value_enum,
        default_value = "mock"
    )]
    pub enclave_mode: EnclaveMode,

    /// Proactive attestation renewal buffer in slots.
    #[arg(long, env = "SOLANA_CC_RENEWAL_BUFFER_SLOTS", default_value_t = 5000)]
    pub renewal_buffer_slots: u64,

    /// Slot polling interval in seconds for background heartbeat.
    #[arg(long, env = "SOLANA_CC_POLL_INTERVAL_SECS", default_value_t = 30)]
    pub poll_interval_secs: u64,

    /// Solana Confidential Compute Verifier program ID.
    #[arg(long, env = "SOLANA_CC_VERIFIER_PROGRAM_ID")]
    pub verifier_program_id: Option<Pubkey>,

    /// Optional path to the fee-payer keypair file. This key is not the workload signer.
    #[arg(long, env = "SOLANA_CC_PAYER_KEYPAIR_PATH")]
    pub payer_keypair_path: Option<String>,

    /// Simulate registration without submission. Status is simulated and signing is disabled.
    #[arg(
        long,
        env = "DRY_RUN",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub dry_run: bool,

    /// `sha256:` image digest. When set, a GCP token with a different `image_digest` fails closed. @spec SCC-SIDECAR-003
    #[arg(long, env = "SOLANA_CC_CONTAINER_IMAGE_DIGEST")]
    pub container_image_digest: Option<String>,

    /// Downstream consumer program the enclave key may sign beside the verifier.
    ///
    /// System transfers and verifier governance instructions stay rejected.
    /// @spec SCC-SIDECAR-001
    #[arg(long, env = "SOLANA_CC_ALLOWED_CONSUMER_PROGRAM_ID")]
    pub allowed_consumer_program_id: Option<Pubkey>,
}

impl SidecarConfig {
    /// Live submission with synthetic evidence is rejected.
    ///
    /// Mock is always synthetic. NVIDIA and Intel TDX synthetic evidence is
    /// selected only while `dry_run` is set. A simulated provider cannot
    /// start for a live submission. Live hardware modes may start.
    /// @spec SCC-SIDECAR-004 SCC-NVIDIA-001 SCC-TDX-001
    pub fn fail_closed_live_mock(&self) -> Result<(), SidecarError> {
        if !self.dry_run && self.enclave_mode == EnclaveMode::Mock {
            return Err(SidecarError::InvalidConfig(
                "enclave mode mock cannot be used when dry_run is false".to_string(),
            ));
        }
        if self.enclave_mode == EnclaveMode::NvidiaGpu {
            // `for_daemon` ties the synthetic RIM to dry-run. Live mode gets
            // the fail-closed appraiser and is allowed to start.
            crate::attestation::nvidia_h100::NvidiaH100Provider::for_daemon(self.dry_run)?;
        }
        if self.enclave_mode == EnclaveMode::IntelTdx {
            // `for_daemon` ties the synthetic quote to dry-run. Live mode
            // probes hardware and is allowed to start.
            crate::attestation::intel_tdx::IntelTdxProvider::for_daemon(self.dry_run)?;
        }
        Ok(())
    }
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".parse().expect("valid loopback"),
            enrollment_token_file: None,
            enrollment_min_interval_secs: 300,
            solana_rpc_url: "https://api.devnet.solana.com".to_string(),
            enclave_mode: EnclaveMode::Mock,
            renewal_buffer_slots: 5000,
            poll_interval_secs: 30,
            verifier_program_id: None,
            payer_keypair_path: None,
            dry_run: true,
            container_image_digest: None,
            allowed_consumer_program_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn live_mock_mode_fails_closed() {
        let live_mock = SidecarConfig {
            dry_run: false,
            enclave_mode: EnclaveMode::Mock,
            ..SidecarConfig::default()
        };
        assert!(live_mock.fail_closed_live_mock().is_err());

        let dry_mock = SidecarConfig {
            dry_run: true,
            enclave_mode: EnclaveMode::Mock,
            ..SidecarConfig::default()
        };
        assert!(dry_mock.fail_closed_live_mock().is_ok());

        let live_sev = SidecarConfig {
            dry_run: false,
            enclave_mode: EnclaveMode::AmdSevSnp,
            ..SidecarConfig::default()
        };
        assert!(live_sev.fail_closed_live_mock().is_ok());

        let live_nvidia = SidecarConfig {
            dry_run: false,
            enclave_mode: EnclaveMode::NvidiaGpu,
            ..SidecarConfig::default()
        };
        assert!(live_nvidia.fail_closed_live_mock().is_ok());

        let dry_nvidia = SidecarConfig {
            dry_run: true,
            enclave_mode: EnclaveMode::NvidiaGpu,
            ..SidecarConfig::default()
        };
        assert!(dry_nvidia.fail_closed_live_mock().is_ok());

        let live_tdx = SidecarConfig {
            dry_run: false,
            enclave_mode: EnclaveMode::IntelTdx,
            ..SidecarConfig::default()
        };
        assert!(live_tdx.fail_closed_live_mock().is_ok());

        let dry_tdx = SidecarConfig {
            dry_run: true,
            enclave_mode: EnclaveMode::IntelTdx,
            ..SidecarConfig::default()
        };
        assert!(dry_tdx.fail_closed_live_mock().is_ok());
    }

    #[test]
    fn intel_tdx_mode_accepts_name_and_alias() {
        let by_name = SidecarConfig::try_parse_from([
            "solana-confidential-compute-sidecar",
            "--enclave-mode",
            "intel-tdx",
        ])
        .expect("intel-tdx");
        assert_eq!(by_name.enclave_mode, EnclaveMode::IntelTdx);
        assert!(by_name.dry_run);

        let by_alias = SidecarConfig::try_parse_from([
            "solana-confidential-compute-sidecar",
            "--enclave-mode",
            "tdx",
            "--dry-run",
            "false",
        ])
        .expect("tdx alias");
        assert_eq!(by_alias.enclave_mode, EnclaveMode::IntelTdx);
        assert!(!by_alias.dry_run);
        assert!(by_alias.fail_closed_live_mock().is_ok());
    }

    #[test]
    fn enrollment_flags_default_closed_and_enforce_interval_floor() {
        let parsed =
            SidecarConfig::try_parse_from(["solana-confidential-compute-sidecar"]).unwrap();
        assert!(parsed.enrollment_token_file.is_none());
        assert_eq!(parsed.enrollment_min_interval_secs, 300);
        let parsed = SidecarConfig::try_parse_from([
            "solana-confidential-compute-sidecar",
            "--enrollment-token-file",
            "/run/secrets/enrollment",
            "--enrollment-min-interval-secs",
            "60",
        ])
        .unwrap();
        assert_eq!(
            parsed.enrollment_token_file.unwrap(),
            std::path::PathBuf::from("/run/secrets/enrollment")
        );
        assert_eq!(parsed.enrollment_min_interval_secs, 60);
        for interval in ["0", "59", "86401"] {
            assert!(SidecarConfig::try_parse_from([
                "solana-confidential-compute-sidecar",
                "--enrollment-min-interval-secs",
                interval
            ])
            .is_err());
        }
    }

    #[test]
    fn allowed_consumer_program_id_flag_and_env_name() {
        let consumer = Pubkey::new_unique();
        let parsed = SidecarConfig::try_parse_from([
            "solana-confidential-compute-sidecar",
            "--allowed-consumer-program-id",
            &consumer.to_string(),
        ])
        .expect("parse flag");
        assert_eq!(parsed.allowed_consumer_program_id, Some(consumer));

        let command = SidecarConfig::command();
        let arg = command
            .get_arguments()
            .find(|argument| argument.get_id() == "allowed_consumer_program_id")
            .expect("flag");
        assert_eq!(arg.get_long(), Some("allowed-consumer-program-id"));
        assert_eq!(
            arg.get_env().and_then(|name| name.to_str()),
            Some("SOLANA_CC_ALLOWED_CONSUMER_PROGRAM_ID")
        );
    }
}
