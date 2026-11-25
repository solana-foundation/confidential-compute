//! Solana Confidential Compute Hardware Enclave Sidecar Daemon.
//!
//! @spec SCC-SIDECAR-001 through SCC-SIDECAR-006

use clap::Parser;
use solana_sdk::signature::Keypair;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::{Zeroize, Zeroizing};

use solana_confidential_compute_sidecar::{
    attestation::{
        gcp_oidc::GcpOidcProvider, mock::MockAttestationProvider, nitro::AwsNitroProvider,
        nvidia_h100::NvidiaH100Provider, sev_snp::SevSnpProvider, AttestationProvider,
    },
    config::{EnclaveMode, SidecarConfig},
    control::EnrollmentControl,
    error::SidecarError,
    heartbeat::HeartbeatDaemon,
    keys::EphemeralKeyManager,
    onchain::OnchainAttestor,
    server::{create_router, validate_loopback_addr, AttestationSessionStatus, SidecarAppState},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,solana_confidential_compute_sidecar=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 2. Parse configuration
    let config = SidecarConfig::parse();
    config.fail_closed_live_mock()?;
    validate_loopback_addr(&config.bind_addr)?;
    let token = config
        .enrollment_token_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(Zeroizing::new)
                .map_err(|_| SidecarError::InvalidConfig("cannot read enrollment token file".into()))
        })
        .transpose()?;
    // Accept the trailing newline produced by ordinary secret-file tooling.
    let token = token.map(|raw| Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned()));
    let enrollment = EnrollmentControl::new(token, config.enrollment_min_interval_secs)?;

    tracing::info!(
        bind_addr = %config.bind_addr,
        enclave_mode = ?config.enclave_mode,
        solana_rpc = %config.solana_rpc_url,
        "Starting Solana Confidential Compute Enclave Sidecar Daemon"
    );

    // 3. Initialize ephemeral key manager in RAM
    let keys = EphemeralKeyManager::new();
    let initial_pubkey = keys.pubkey();
    tracing::info!(ephemeral_pubkey = %initial_pubkey, "Generated ephemeral Ed25519 workload signer in enclave RAM");

    // 4. Instantiate attestation provider
    let provider: Arc<dyn AttestationProvider> = match config.enclave_mode {
        EnclaveMode::AmdSevSnp => Arc::new(SevSnpProvider::default()),
        EnclaveMode::AwsNitro => Arc::new(AwsNitroProvider::default()),
        EnclaveMode::GcpConfidentialSpace => {
            Arc::new(GcpOidcProvider::with_image_digest(None, None, config.container_image_digest.as_deref())?)
        }
        EnclaveMode::NvidiaGpu => Arc::new(NvidiaH100Provider::for_daemon(config.dry_run)?),
        EnclaveMode::IntelTdx => Arc::new(
            solana_confidential_compute_sidecar::attestation::intel_tdx::IntelTdxProvider::for_daemon(config.dry_run)?,
        ),
        EnclaveMode::Mock => Arc::new(MockAttestationProvider::default()),
    };

    // 5. Load the fee-payer key. It is never the workload signer.
    let payer = if let Some(path) = &config.payer_keypair_path { Some(load_payer_keypair(path)?) } else { None };

    // 6. Initialize on-chain attestor. DRY_RUN skips transaction submission.
    let onchain =
        Arc::new(OnchainAttestor::new(&config.solana_rpc_url, config.verifier_program_id, payer, config.dry_run));

    // 7. Assemble application state
    let state = Arc::new(SidecarAppState {
        enrollment,
        enclave_mode: config.enclave_mode,
        keys: RwLock::new(keys),
        provider,
        onchain,
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: config.allowed_consumer_program_id,
    });

    // 8. Install the SIGTERM handler before any background work starts. The
    // sidecar does not start without it.
    let terminate = TerminateSignal::install()?;

    // 9. Spawn autonomous heartbeat daemon
    let heartbeat = HeartbeatDaemon::new(Arc::clone(&state), config.poll_interval_secs, config.renewal_buffer_slots);
    let heartbeat_handle = heartbeat.spawn();

    // 10. Bind TCP listener on loopback
    let listener = TcpListener::bind(config.bind_addr).await?;
    let app = create_router(Arc::clone(&state));

    tracing::info!(bind_addr = %config.bind_addr, "Loopback HTTP server listening");

    // 11. Serve with graceful shutdown. The shutdown future records why it
    // finished, so that main can fail the process when the cause is a broken
    // Ctrl+C handler.
    let (reason_tx, reason_rx) = oneshot::channel();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // The receiver lives until main reads it, so a send error cannot happen.
            let _ = reason_tx.send(wait_for_shutdown(tokio::signal::ctrl_c(), terminate.recv()).await);
        })
        .await?;

    // 12. Abort heartbeat and drop state (zeroizes secret key)
    heartbeat_handle.abort();

    let reason = reason_rx.await.map_err(|_| SidecarError::ServerError("shutdown reason was not recorded".into()))?;
    reason.into_result()?;
    tracing::info!("Sidecar shut down cleanly; ephemeral keys zeroized from memory");

    Ok(())
}

fn load_payer_keypair(path: &str) -> Result<Keypair, SidecarError> {
    let mut raw = std::fs::read_to_string(path)
        .map_err(|e| SidecarError::InvalidConfig(format!("Failed to read payer keypair: {e}")))?;
    let parsed = parse_payer_material(&raw);
    raw.zeroize();
    parsed
}

fn parse_payer_material(raw: &str) -> Result<Keypair, SidecarError> {
    let trimmed = raw.trim();
    let mut bytes = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<u8>>(trimmed)
            .map_err(|e| SidecarError::InvalidConfig(format!("Failed to parse payer keypair JSON: {e}")))?
    } else {
        bs58::decode(trimmed)
            .into_vec()
            .map_err(|e| SidecarError::InvalidConfig(format!("Payer keypair is not JSON or base58: {e}")))?
    };
    let parsed = Keypair::try_from(bytes.as_slice())
        .map_err(|e| SidecarError::InvalidConfig(format!("Payer keypair bytes are invalid: {e}")));
    bytes.zeroize();
    parsed
}

/// The SIGTERM stream. It is created before the server starts, so a failure
/// to install it stops the sidecar at startup.
#[cfg(unix)]
struct TerminateSignal(tokio::signal::unix::Signal);

#[cfg(unix)]
impl TerminateSignal {
    fn install() -> std::io::Result<Self> {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map(Self)
    }

    async fn recv(mut self) {
        self.0.recv().await;
    }
}

/// Platforms without SIGTERM never receive it.
#[cfg(not(unix))]
struct TerminateSignal;

#[cfg(not(unix))]
impl TerminateSignal {
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn recv(self) {
        std::future::pending::<()>().await;
    }
}

/// Why the sidecar stopped waiting for a shutdown signal.
#[derive(Debug, PartialEq, Eq)]
enum ShutdownReason {
    CtrlC,
    Terminate,
    /// The Ctrl+C handler could not be installed. The process must exit with a
    /// non-zero status, so that a supervisor with `Restart=on-failure` restarts it.
    CtrlCHandlerFailed(String),
}

impl ShutdownReason {
    fn into_result(self) -> Result<(), SidecarError> {
        match self {
            Self::CtrlC | Self::Terminate => Ok(()),
            Self::CtrlCHandlerFailed(err) => {
                Err(SidecarError::ServerError(format!("Failed to install Ctrl+C handler: {err}")))
            }
        }
    }
}

/// Waits for the first of Ctrl+C, SIGTERM or a Ctrl+C handler failure.
async fn wait_for_shutdown(
    ctrl_c: impl std::future::Future<Output = std::io::Result<()>>,
    terminate: impl std::future::Future<Output = ()>,
) -> ShutdownReason {
    let reason = tokio::select! {
        result = ctrl_c => match result {
            Ok(()) => ShutdownReason::CtrlC,
            Err(err) => ShutdownReason::CtrlCHandlerFailed(err.to_string()),
        },
        () = terminate => ShutdownReason::Terminate,
    };
    match &reason {
        ShutdownReason::CtrlC => tracing::info!("Received Ctrl+C; shutting down"),
        ShutdownReason::Terminate => tracing::info!("Received SIGTERM; shutting down"),
        ShutdownReason::CtrlCHandlerFailed(err) => {
            tracing::error!(%err, "Failed to install Ctrl+C handler; exiting with an error");
        }
    }
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};

    #[tokio::test]
    async fn ctrl_c_is_a_clean_shutdown() {
        let reason = wait_for_shutdown(ready(Ok(())), pending()).await;
        assert_eq!(reason, ShutdownReason::CtrlC);
        assert!(reason.into_result().is_ok());
    }

    #[tokio::test]
    async fn sigterm_is_a_clean_shutdown() {
        let reason = wait_for_shutdown(pending(), ready(())).await;
        assert_eq!(reason, ShutdownReason::Terminate);
        assert!(reason.into_result().is_ok());
    }

    #[tokio::test]
    async fn ctrl_c_handler_failure_is_an_error_exit() {
        let failure = std::io::Error::other("no signal support");
        let reason = wait_for_shutdown(ready(Err(failure)), pending()).await;
        assert_eq!(reason, ShutdownReason::CtrlCHandlerFailed("no signal support".into()));
        let err = reason.into_result().expect_err("a handler failure must not be a clean shutdown");
        assert!(matches!(err, SidecarError::ServerError(ref msg) if msg.contains("no signal support")));
    }
}
