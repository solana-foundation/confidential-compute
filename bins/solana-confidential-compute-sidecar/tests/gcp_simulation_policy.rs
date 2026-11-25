// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Local launcher simulation only: no Google signature or hardware proof.
#![cfg(unix)]

use solana_confidential_compute_sidecar::{
    attestation::gcp_oidc::GcpOidcProvider,
    config::EnclaveMode,
    keys::EphemeralKeyManager,
    onchain::{MockCluster, OnchainAttestor},
    server::{attest_current_key, create_router, AttestationSessionStatus, SidecarAppState},
};
use solana_sdk::signature::Keypair;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

struct Launcher {
    path: PathBuf,
    count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Launcher {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn launcher_counter() -> Launcher {
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    let app = axum::Router::new().route(
        "/v1/token",
        axum::routing::post(move || {
            let requests = requests.clone();
            async move {
                requests.fetch_add(1, Ordering::SeqCst);
                (axum::http::StatusCode::SERVICE_UNAVAILABLE, "local launcher sentinel")
            }
        }),
    );
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    // `SystemTime` granularity is coarser than the gap between two launchers
    // started from parallel tests, so the clock alone collides and `bind` fails
    // with `AlreadyExists`. The counter makes the path unique within the
    // process; the pid makes it unique across concurrent `cargo test` runs.
    static LAUNCHER_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = LAUNCHER_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("scc-gcp-policy-{}-{unique}-{seq}.sock", std::process::id()));
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Launcher { path, count, task }
}

#[tokio::test]
async fn gcp_dry_run_builds_locally_without_launcher_or_verified_session() {
    let launcher = launcher_counter().await;
    let cluster = MockCluster::new(100, vec![(95, [0x11; 32])]);
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::GcpConfidentialSpace,
        keys: RwLock::new(EphemeralKeyManager::new()),
        provider: Arc::new(GcpOidcProvider::new(Some(launcher.path.to_str().unwrap()), None)),
        onchain: Arc::new(OnchainAttestor::mock(cluster.clone(), None, Some(Keypair::new()))),
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    });
    let result = attest_current_key(&state).await;
    assert_eq!(launcher.count.load(Ordering::SeqCst), 0, "dry run must skip the launcher before provider invocation");
    result.expect("synthetic local registration construction succeeds");
    assert_eq!(cluster.submitted().len(), 1, "one local recorded transaction, no submission");
    assert!(state.onchain.validate_registered_session(&state.keys.read().await.pubkey()).await.is_err());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = create_router(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let status: serde_json::Value =
        reqwest::get(format!("http://{address}/v1/status")).await.unwrap().json().await.unwrap();
    assert_eq!(status["attestation_status"], "simulated");
    server.abort();
}

#[tokio::test]
async fn live_gcp_provider_still_requests_launcher() {
    let launcher = launcher_counter().await;
    let provider = GcpOidcProvider::new(Some(launcher.path.to_str().unwrap()), None);
    let keys = EphemeralKeyManager::new();
    let result = solana_confidential_compute_sidecar::attestation::request_for_submission(
        &provider,
        false,
        &keys.pubkey(),
        &[0x11; 32],
    )
    .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("launcher returned HTTP 503"), "{err}");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
}
