//! Controlled HTTP/provider/cluster tests; no live chain or hardware proof.
use reqwest::{Client, StatusCode};
use serde_json::Value;
use solana_confidential_compute_sidecar::{
    attestation::{mock::MockAttestationProvider, AttestationProvider, AttestationReport},
    config::EnclaveMode,
    control::EnrollmentControl,
    keys::EphemeralKeyManager,
    onchain::{MockCluster, OnchainAttestor},
    server::{attest_current_key, create_router, AttestationSessionStatus, SidecarAppState},
    SidecarError,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{RwLock, Semaphore},
};
use zeroize::Zeroizing;

const TOKEN: &str = "operator-only-test-token-0123456789abcdef";

struct ControlledProvider {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
    block: bool,
    fail: bool,
}
impl ControlledProvider {
    fn new(block: bool, fail: bool) -> Self {
        Self { calls: AtomicUsize::new(0), entered: Semaphore::new(0), release: Semaphore::new(0), block, fail }
    }
}
impl AttestationProvider for ControlledProvider {
    fn enclave_type(&self) -> solana_confidential_compute_core::types::EnclaveType {
        solana_confidential_compute_core::types::EnclaveType::AmdSevSnp
    }
    fn request_attestation<'a>(
        &'a self,
        key: &'a Pubkey,
        hash: &'a [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.add_permits(1);
            if self.block {
                self.release.acquire().await.unwrap().forget();
            }
            if self.fail {
                return Err(SidecarError::AttestationError("controlled provider failure".into()));
            }
            MockAttestationProvider::default().request_attestation(key, hash).await
        })
    }
}
fn state(provider: Arc<ControlledProvider>, authorized: bool, payer: bool) -> Arc<SidecarAppState> {
    Arc::new(SidecarAppState {
        enrollment: EnrollmentControl::new(authorized.then(|| Zeroizing::new(TOKEN.into())), 300).unwrap(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(EphemeralKeyManager::new()),
        provider,
        onchain: Arc::new(OnchainAttestor::mock(
            MockCluster::new(100, vec![(95, [0x11; 32])]),
            None,
            payer.then(Keypair::new),
        )),
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(90),
            expires_slot: Some(200),
            expires_unix_timestamp: Some(300),
            last_nonce_slot: Some(90),
        }),
        allowed_consumer_program_id: None,
    })
}
async fn serve(state: Arc<SidecarAppState>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, create_router(state)).await.unwrap() });
    (url, task)
}
async fn snapshot(state: &SidecarAppState) -> (Pubkey, Value) {
    (state.keys.read().await.pubkey(), serde_json::to_value(state.status.read().await.clone()).unwrap())
}

#[tokio::test]
async fn enrollment_denies_missing_wrong_malformed_and_duplicate_tokens_without_effects() {
    for authorized in [false, true] {
        let provider = Arc::new(ControlledProvider::new(false, false));
        let state = state(provider.clone(), authorized, true);
        let before = snapshot(&state).await;
        let (url, task) = serve(state.clone()).await;
        for route in ["attest", "renew"] {
            for token in [None, Some("Bearer wrong"), Some(TOKEN), Some("Basic ignored")] {
                let mut request = Client::new().post(format!("{url}/v1/{route}"));
                if let Some(value) = token {
                    request = request.header("Authorization", value);
                }
                let response = request.send().await.unwrap();
                assert_eq!(
                    response.status(),
                    if authorized { StatusCode::UNAUTHORIZED } else { StatusCode::FORBIDDEN }
                );
                if authorized {
                    assert_eq!(response.headers()["www-authenticate"], "Bearer");
                }
            }
            let response = Client::new()
                .post(format!("{url}/v1/{route}"))
                .header("Authorization", format!("Bearer {TOKEN}"))
                .header("Authorization", format!("Bearer {TOKEN}"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_client_error());
        }
        assert_eq!(snapshot(&state).await, before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(state.onchain.mock_cluster().unwrap().submitted().is_empty());
        // Unauthenticated status remains available and doesn't invoke enrollment.
        assert_eq!(Client::new().get(format!("{url}/v1/status")).send().await.unwrap().status(), 200);
        task.abort();
    }
}

#[tokio::test]
async fn successful_attest_and_renew_share_one_cooldown_and_submit_once() {
    for first in ["attest", "renew"] {
        let provider = Arc::new(ControlledProvider::new(false, false));
        let state = state(provider.clone(), true, true);
        let before = state.keys.read().await.pubkey();
        let (url, task) = serve(state.clone()).await;
        assert_eq!(
            Client::new().post(format!("{url}/v1/{first}")).bearer_auth(TOKEN).send().await.unwrap().status(),
            200
        );
        let after = snapshot(&state).await;
        assert_eq!(before == after.0, first == "attest");
        for route in ["attest", "renew", "renew", "attest"] {
            let response = Client::new().post(format!("{url}/v1/{route}")).bearer_auth(TOKEN).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(response.headers()["retry-after"].to_str().unwrap().parse::<u64>().unwrap() > 0);
        }
        assert_eq!(snapshot(&state).await, after);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.onchain.mock_cluster().unwrap().submitted().len(), 1);
        task.abort();
    }
}

#[tokio::test]
async fn failed_rotation_retains_key_and_all_deadlines_and_still_charges_cooldown() {
    // Fail separately before submission (provider) and in submission (missing payer).
    for (provider_fails, payer) in [(true, true), (false, false)] {
        let provider = Arc::new(ControlledProvider::new(false, provider_fails));
        let state = state(provider.clone(), true, payer);
        let before = snapshot(&state).await;
        let (url, task) = serve(state.clone()).await;
        let response = Client::new().post(format!("{url}/v1/renew")).bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(response.status(), 500);
        assert_eq!(snapshot(&state).await, before);
        let keys = state.keys.read().await;
        assert!(Signature::from(keys.sign_message(b"retained session")).verify(before.0.as_ref(), b"retained session"));
        drop(keys);
        assert_eq!(
            Client::new().post(format!("{url}/v1/attest")).bearer_auth(TOKEN).send().await.unwrap().status(),
            429
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        task.abort();
    }
}

#[tokio::test]
async fn in_flight_rotation_keeps_old_session_and_rejects_concurrent_http_attempts() {
    let provider = Arc::new(ControlledProvider::new(true, false));
    let state = state(provider.clone(), true, true);
    let before = snapshot(&state).await;
    let (url, task) = serve(state.clone()).await;
    let request = Client::new().post(format!("{url}/v1/renew")).bearer_auth(TOKEN);
    let pending = tokio::spawn(async move { request.send().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.acquire()).await.unwrap().unwrap().forget();
    assert_eq!(snapshot(&state).await, before);
    let keys = state.keys.read().await;
    assert!(Signature::from(keys.sign_message(b"in flight")).verify(before.0.as_ref(), b"in flight"));
    drop(keys);
    for route in ["attest", "renew"] {
        assert_eq!(
            Client::new().post(format!("{url}/v1/{route}")).bearer_auth(TOKEN).send().await.unwrap().status(),
            429
        );
    }
    provider.release.add_permits(1);
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), pending).await.unwrap().unwrap().status(), 200);
    assert_ne!(snapshot(&state).await.0, before.0);
    assert_eq!(state.onchain.mock_cluster().unwrap().submitted().len(), 1);
    task.abort();
}

#[tokio::test]
async fn heartbeat_enrollment_remains_available_without_http_token() {
    let provider = Arc::new(ControlledProvider::new(false, false));
    let state = state(provider.clone(), false, true);
    let before = state.keys.read().await.pubkey();
    attest_current_key(&state).await.unwrap();
    assert_eq!(state.keys.read().await.pubkey(), before);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn live_rotation_publishes_only_after_valid_confirmed_candidate_deadlines() {
    use axum::{routing::post, Json, Router};
    use serde_json::json;
    use solana_sdk::{hash::Hash, transaction::Transaction};
    // Confirmed reads fail after a paid submission, or expire between the
    // attestor's completion check and the final read used for publication.
    for mode in ["missing", "expired-final-read", "valid"] {
        let workload = Arc::new(std::sync::Mutex::new(None::<Pubkey>));
        let reads = Arc::new(AtomicUsize::new(0));
        let submissions = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_addr = listener.local_addr().unwrap();
        let w = workload.clone();
        let r = reads.clone();
        let s = submissions.clone();
        let rpc = Router::new().route("/", post(move |Json(request): Json<Value>| {
            let workload = w.clone(); let reads = r.clone(); let submissions = s.clone();
            async move {
                let account = |owner: Pubkey, data: Vec<u8>| json!({"lamports":1,"owner":owner.to_string(),"executable":false,"rentEpoch":0,"data":[base64::Engine::encode(&base64::engine::general_purpose::STANDARD,data),"base64"]});
                let result = match request["method"].as_str().unwrap() {
                    "getSlot" => json!(100),
                    "getVersion" => json!({"solana-core":"2.2.0","feature-set":0}),
                    "getLatestBlockhash" => json!({"context":{"slot":100},"value":{"blockhash":Hash::new_from_array([7;32]).to_string(),"lastValidBlockHeight":200}}),
                    "getAccountInfo" => {
                        let mut bytes=1u64.to_le_bytes().to_vec(); bytes.extend(95u64.to_le_bytes()); bytes.extend([0x11;32]);
                        json!({"context":{"slot":100},"value":account(solana_sdk::sysvar::ID,bytes)})
                    },
                    "sendTransaction" => {
                        let raw=base64::Engine::decode(&base64::engine::general_purpose::STANDARD,request["params"][0].as_str().unwrap()).unwrap();
                        let tx:Transaction=bincode::deserialize(&raw).unwrap(); assert!(tx.verify().is_ok());
                        assert_eq!(tx.message.header.num_required_signatures,2);
                        *workload.lock().unwrap()=Some(tx.message.account_keys[1]);
                        submissions.fetch_add(1,Ordering::SeqCst);
                        json!(tx.signatures[0].to_string())
                    },
                    "getSignatureStatuses" => json!({"context":{"slot":100},"value":[{"slot":100,"confirmations":1,"err":null,"confirmationStatus":"confirmed","status":{"Ok":null}}]}),
                    "getMultipleAccounts" => {
                        let read=reads.fetch_add(1,Ordering::SeqCst);
                        if mode=="missing" { json!({"context":{"slot":100},"value":[null,null]}) }
                        else {
                            let workload=workload.lock().unwrap().unwrap(); let pid=solana_confidential_compute_cpi::ID;
                            let (pda,bump)=Pubkey::find_program_address(&[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,workload.as_ref()],&pid);
                            assert_eq!(request["params"][0][0],pda.to_string());
                            let mut data=vec![0;154]; data[..8].copy_from_slice(&solana_confidential_compute_cpi::ATTESTED_SIGNER_DISCRIMINATOR); data[8..40].copy_from_slice(workload.as_ref()); data[40]=3;
                            data[129..137].copy_from_slice(&99u64.to_le_bytes()); data[137..145].copy_from_slice(&170u64.to_le_bytes()); data[145]=bump;
                            let deadline=if mode=="expired-final-read" && read>0 {100i64} else {130i64};
                            data[146..154].copy_from_slice(&deadline.to_le_bytes());
                            let clock=solana_sdk::clock::Clock{slot:100,unix_timestamp:100,..Default::default()};
                            json!({"context":{"slot":100},"value":[account(pid,data),account(solana_sdk::sysvar::ID,bincode::serialize(&clock).unwrap())]})
                        }
                    },
                    method => panic!("unexpected local RPC {method}"),
                };
                Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
            }
        }));
        let rpc_task = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
        let mut state = state(Arc::new(ControlledProvider::new(false, false)), true, true);
        let owned = Arc::get_mut(&mut state).unwrap();
        owned.onchain =
            Arc::new(OnchainAttestor::new(&format!("http://{rpc_addr}"), None, Some(Keypair::new()), false));
        owned.provider = Arc::new(MockAttestationProvider::new_gcp(None));
        let before = snapshot(&state).await;
        let (url, task) = serve(state.clone()).await;
        let response = Client::new().post(format!("{url}/v1/renew")).bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        if mode == "valid" {
            assert_eq!(response.status(), 200);
            let after = snapshot(&state).await;
            assert_ne!(after.0, before.0);
            assert_eq!(Some(after.0), *workload.lock().unwrap());
            assert_eq!(after.1["expires_slot"], 170);
            assert_eq!(after.1["expires_unix_timestamp"], 130);
        } else {
            assert_eq!(response.status(), 500);
            assert_eq!(snapshot(&state).await, before);
            assert_eq!(
                Client::new().post(format!("{url}/v1/renew")).bearer_auth(TOKEN).send().await.unwrap().status(),
                429
            );
        }
        task.abort();
        rpc_task.abort();
    }
}

#[tokio::test]
async fn cancelled_candidate_preserves_session_and_releases_enrollment_lock() {
    let provider = Arc::new(ControlledProvider::new(true, false));
    let state = state(provider.clone(), true, true);
    let before = snapshot(&state).await;
    let shared = state.clone();
    let operation =
        tokio::spawn(async move { solana_confidential_compute_sidecar::rotate_zeroize_and_attest(&shared).await });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.acquire()).await.unwrap().unwrap().forget();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    assert_eq!(snapshot(&state).await, before);
    let (url, task) = serve(state.clone()).await;
    provider.release.add_permits(1);
    assert_eq!(Client::new().post(format!("{url}/v1/attest")).bearer_auth(TOKEN).send().await.unwrap().status(), 200);
    task.abort();
}
