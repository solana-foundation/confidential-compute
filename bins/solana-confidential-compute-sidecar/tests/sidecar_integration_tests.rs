//! Integration test suite for Solana Confidential Compute Enclave Sidecar Daemon.
//!
//! @spec SCC-SIDECAR-001 through SCC-SIDECAR-006

use reqwest::Client;
use serde_json::Value;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{v0::Message, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::VersionedTransaction,
};
#[allow(deprecated)]
use solana_system_interface::instruction as system_instruction;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use solana_confidential_compute_sidecar::{
    attestation::{mock::MockAttestationProvider, AttestationProvider, AttestationReport},
    config::EnclaveMode,
    heartbeat::reattest_current_key,
    keys::EphemeralKeyManager,
    onchain::{MockCluster, OnchainAttestor},
    server::{create_router, validate_loopback_addr, AttestationSessionStatus, SidecarAppState},
};

fn mock_onchain(payer: Option<Keypair>) -> Arc<OnchainAttestor> {
    let cluster = MockCluster::new(100, vec![(95, [0x11u8; 32])]);
    Arc::new(OnchainAttestor::mock(cluster, None, payer))
}

// Signing-handler tests inject an already attested session. This local RPC stub
// supplies only the clock slot; it does not model or prove chain verification.
async fn signing_onchain(workload: Pubkey) -> Arc<OnchainAttestor> {
    signing_onchain_with_deadline(workload, i64::MAX).await
}
async fn signing_onchain_with_deadline(workload: Pubkey, deadline: i64) -> Arc<OnchainAttestor> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rpc=axum::Router::new().route("/",axum::routing::post(move |axum::Json(request):axum::Json<Value>|async move {
        let result=if request["method"]=="getSlot" {serde_json::json!(100)} else if request["method"]=="getAccountInfo" {
            return axum::Json(serde_json::json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"test refresh unavailable"}}));
        } else {
            assert_eq!(request["method"],"getMultipleAccounts");
            let pid=solana_confidential_compute_cpi::ID;let (pda,bump)=Pubkey::find_program_address(&[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,workload.as_ref()],&pid);
            assert_eq!(request["params"][0],serde_json::json!([pda.to_string(),solana_sdk::sysvar::clock::ID.to_string()]));
            let mut data=vec![0;154];data[..8].copy_from_slice(&solana_confidential_compute_cpi::ATTESTED_SIGNER_DISCRIMINATOR);data[8..40].copy_from_slice(workload.as_ref());data[40]=1;data[137..145].copy_from_slice(&u64::MAX.to_le_bytes());data[145]=bump;data[146..154].copy_from_slice(&deadline.to_le_bytes());
            let clock=solana_sdk::clock::Clock{slot:100,unix_timestamp:100,..solana_sdk::clock::Clock::default()};
            let json_account=|owner:Pubkey,data:Vec<u8>|serde_json::json!({"lamports":1,"owner":owner.to_string(),"executable":false,"rentEpoch":0,"data":[base64::Engine::encode(&base64::engine::general_purpose::STANDARD,data),"base64"]});
            serde_json::json!({"context":{"slot":100},"value":[json_account(pid,data),json_account(solana_sdk::sysvar::ID,bincode::serialize(&clock).unwrap())]})
        };
        axum::Json(serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }));
    tokio::spawn(async move {
        axum::serve(listener, rpc).await.unwrap();
    });
    Arc::new(OnchainAttestor::new(
        &format!("http://{addr}"),
        None,
        None,
        false,
    ))
}

async fn spawn_test_server(
    state: Arc<SidecarAppState>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback port 0");
    let addr = listener.local_addr().expect("local addr");
    let app = create_router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn test_loopback_address_validation() {
    let loopback_ipv4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let loopback_ipv6: SocketAddr = "[::1]:8080".parse().unwrap();
    let external_wildcard: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let external_lan: SocketAddr = "192.168.1.50:8080".parse().unwrap();
    let other_loopback: SocketAddr = "127.0.0.2:8080".parse().unwrap();

    assert!(validate_loopback_addr(&loopback_ipv4).is_ok());
    assert!(validate_loopback_addr(&loopback_ipv6).is_ok());
    assert!(validate_loopback_addr(&external_wildcard).is_err());
    assert!(validate_loopback_addr(&external_lan).is_err());
    assert!(validate_loopback_addr(&other_loopback).is_err());
}

#[tokio::test]
async fn test_status_and_renew_endpoints() {
    let keys = EphemeralKeyManager::new();
    let initial_pubkey = keys.pubkey();
    let provider = Arc::new(MockAttestationProvider::default());
    let payer = Keypair::new();
    let payer_pubkey = payer.pubkey();
    let onchain = mock_onchain(Some(payer));

    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::new(
            Some(zeroize::Zeroizing::new(
                "test-operator-token-0123456789abcdef".into(),
            )),
            300,
        )
        .unwrap(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider,
        onchain: Arc::clone(&onchain),
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    });

    let (addr, handle) = spawn_test_server(Arc::clone(&state)).await;
    let client = Client::new();

    // 1. GET /v1/status
    let res = client
        .get(format!("http://{addr}/v1/status"))
        .send()
        .await
        .expect("status request");
    assert_eq!(res.status(), 200);

    let json: Value = res.json().await.expect("json");
    assert_eq!(json["enclave_mode"], "mock");
    assert_eq!(json["public_key"], initial_pubkey.to_string());
    assert_eq!(json["attestation_status"], "unattested");

    // 2. POST /v1/renew
    let res = client
        .post(format!("http://{addr}/v1/renew"))
        .bearer_auth("test-operator-token-0123456789abcdef")
        .send()
        .await
        .expect("renew request");
    assert_eq!(res.status(), 200);

    let renew_json: Value = res.json().await.expect("json");
    assert_eq!(renew_json["success"], true);
    assert_eq!(renew_json["previous_key"], initial_pubkey.to_string());
    assert_ne!(renew_json["new_key"], initial_pubkey.to_string());
    assert_ne!(renew_json["new_key"], payer_pubkey.to_string());
    assert!(renew_json["expires_slot"].is_u64());
    let submitted = onchain.mock_cluster().expect("mock").submitted();
    assert_eq!(submitted.len(), 1);
    assert_eq!(
        submitted[0].message.account_keys.first().copied(),
        Some(payer_pubkey)
    );

    // 3. GET /v1/status confirms new key
    let res2 = client
        .get(format!("http://{addr}/v1/status"))
        .send()
        .await
        .expect("status request 2");
    let json2: Value = res2.json().await.expect("json");
    assert_eq!(json2["public_key"], renew_json["new_key"]);

    handle.abort();
}

/// An unattested session (`expires_slot == None`) must not sign.
/// @spec SCC-SIDECAR-001
#[tokio::test]
async fn test_sign_endpoint_rejects_unattested_session() {
    let keys = EphemeralKeyManager::new();
    let provider = Arc::new(MockAttestationProvider::default());
    let onchain = signing_onchain(keys.pubkey()).await;

    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider,
        onchain,
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    });

    let (addr, handle) = spawn_test_server(Arc::clone(&state)).await;
    let client = Client::new();

    let res = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({ "transaction": "" }))
        .send()
        .await
        .expect("sign request");

    assert_eq!(res.status(), 403);
    let json: Value = res.json().await.expect("json");
    assert_eq!(json["error"], "enclave session is not attested");

    handle.abort();
}

#[tokio::test]
async fn test_sign_endpoint_happy_path() {
    let keys = EphemeralKeyManager::new();
    let pubkey = keys.pubkey();
    let provider = Arc::new(MockAttestationProvider::default());
    let onchain = signing_onchain(keys.pubkey()).await;

    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider,
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(100),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(100),
        }),
        allowed_consumer_program_id: None,
    });

    let (addr, handle) = spawn_test_server(Arc::clone(&state)).await;
    let client = Client::new();

    // Verifier attestation instruction. System transfers are not allowlisted.
    let ix = Instruction {
        program_id: Pubkey::from_str_const("EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh"),
        accounts: vec![AccountMeta::new_readonly(pubkey, true)],
        data: solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec(),
    };
    let message = VersionedMessage::V0(
        Message::try_compile(&Pubkey::new_unique(), &[ix], &[], Hash::default()).expect("compile"),
    );
    let tx = VersionedTransaction {
        signatures: vec![Signature::default(); 2],
        message,
    };
    let tx_bytes = bincode::serialize(&tx).expect("serialize");
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tx_bytes);

    let res = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({ "transaction": tx_b64 }))
        .send()
        .await
        .expect("sign request");

    assert_eq!(res.status(), 200);
    let json: Value = res.json().await.expect("json");
    let sig_str = json["signature"].as_str().expect("signature string");
    let returned_tx_b64 = json["transaction"].as_str().expect("tx string");

    let returned_tx_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, returned_tx_b64)
            .expect("decode");
    let returned_tx: VersionedTransaction =
        bincode::deserialize(&returned_tx_bytes).expect("deser");

    // Verify signature matches
    let signature: Signature = sig_str.parse().expect("parse sig");
    assert_eq!(returned_tx.signatures[1], signature);
    assert!(signature.verify(pubkey.as_ref(), &returned_tx.message.serialize()));

    handle.abort();
}

#[tokio::test]
async fn test_sign_endpoint_rejects_missing_signer() {
    let keys = EphemeralKeyManager::new();
    let other_key = Pubkey::new_unique();
    let provider = Arc::new(MockAttestationProvider::default());
    let onchain = signing_onchain(keys.pubkey()).await;

    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider,
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(100),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(100),
        }),
        allowed_consumer_program_id: None,
    });

    let (addr, handle) = spawn_test_server(Arc::clone(&state)).await;
    let client = Client::new();

    // Transaction only requiring other_key as signer
    let recipient = Pubkey::new_unique();
    let ix = system_instruction::transfer(&other_key, &recipient, 5_000);
    let message = VersionedMessage::V0(
        Message::try_compile(&other_key, &[ix], &[], Hash::default()).expect("compile"),
    );
    let tx = VersionedTransaction {
        signatures: vec![Signature::default()],
        message,
    };
    let tx_bytes = bincode::serialize(&tx).expect("serialize");
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tx_bytes);

    let res = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({ "transaction": tx_b64 }))
        .send()
        .await
        .expect("sign request");

    assert_eq!(res.status(), 400);
    let json: Value = res.json().await.expect("json");
    let error = json["error"].as_str().unwrap_or("");
    assert!(
        error.contains("not allowlisted") || error.contains("Unauthorized signer"),
        "{error}"
    );

    handle.abort();
}

#[tokio::test]
async fn test_sign_endpoint_rejects_system_transfer() {
    let keys = EphemeralKeyManager::new();
    let pubkey = keys.pubkey();
    let provider = Arc::new(MockAttestationProvider::default());
    let onchain = signing_onchain(keys.pubkey()).await;

    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider,
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(100),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(100),
        }),
        allowed_consumer_program_id: None,
    });

    let (addr, handle) = spawn_test_server(Arc::clone(&state)).await;
    let client = Client::new();

    let recipient = Pubkey::new_unique();
    let ix = system_instruction::transfer(&pubkey, &recipient, 5_000);
    let message = VersionedMessage::V0(
        Message::try_compile(&pubkey, &[ix], &[], Hash::default()).expect("compile"),
    );
    let tx = VersionedTransaction {
        signatures: vec![Signature::default()],
        message,
    };
    let tx_bytes = bincode::serialize(&tx).expect("serialize");
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tx_bytes);

    let res = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({ "transaction": tx_b64 }))
        .send()
        .await
        .expect("sign request");

    assert_eq!(res.status(), 400);
    let json: Value = res.json().await.expect("json");
    assert_eq!(json["error"], "system transfer is not allowlisted");

    handle.abort();
}

#[tokio::test]
async fn test_sign_endpoint_rejects_oversized_body() {
    let keys = EphemeralKeyManager::new();
    let provider = Arc::new(MockAttestationProvider::default());
    let onchain = signing_onchain(keys.pubkey()).await;
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider,
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(100),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(100),
        }),
        allowed_consumer_program_id: None,
    });

    let (addr, handle) = spawn_test_server(Arc::clone(&state)).await;
    let client = Client::new();
    let body = vec![b'{'; 70_000];
    let res = client
        .post(format!("http://{addr}/v1/sign"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("oversized sign request");

    assert_eq!(res.status(), 413);
    handle.abort();
}

#[tokio::test]
async fn test_mock_attestation_providers_emit_valid_challenges() {
    let signer = Pubkey::new_unique();
    let slot_hash = [0x77u8; 32];

    // 1. SEV-SNP mock provider
    let snp_provider = MockAttestationProvider::new_sev_snp();
    let snp_report = snp_provider
        .request_attestation(&signer, &slot_hash)
        .await
        .expect("attest snp");

    match snp_report {
        AttestationReport::SevSnp { report, .. } => {
            assert_eq!(
                report.len(),
                solana_confidential_compute_core::SNP_REPORT_SIZE
            );
            // Verify user_data binds signer and slot_hash at offset 80..144
            assert_eq!(&report[80..112], signer.as_ref());
            assert_eq!(&report[112..144], &slot_hash);
        }
        _ => panic!("Expected SevSnp report"),
    }

    // 2. GCP Confidential Space mock provider
    let gcp_provider = MockAttestationProvider::new_gcp(None);
    let gcp_report = gcp_provider
        .request_attestation(&signer, &slot_hash)
        .await
        .expect("attest gcp");

    match gcp_report {
        AttestationReport::GcpJwt { jwt } => {
            let view =
                solana_confidential_compute_crypto::jwt::JwtView::parse(&jwt).expect("jwt view");
            let claims =
                solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64)
                    .expect("claims");
            assert!(claims.secboot);
            assert_eq!(claims.dbgstat(), b"disabled-since-boot");
            let raw = claims.decode_mode_a_binding().expect("mode a nonces");
            assert_eq!(&raw[..32], signer.as_ref());
            assert_eq!(&raw[32..], &slot_hash);
        }
        _ => panic!("Expected GcpJwt report"),
    }
}

#[tokio::test]
async fn test_heartbeat_reattests_the_same_key() {
    let keys = EphemeralKeyManager::new();
    let pubkey = keys.pubkey();
    let payer = Keypair::new();
    let onchain = mock_onchain(Some(payer));
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::default()),
        onchain,
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    });

    let expires = reattest_current_key(&state).await.expect("reattest");
    assert_eq!(state.keys.read().await.pubkey(), pubkey);
    assert_eq!(state.status.read().await.expires_slot, Some(expires));
    assert_eq!(
        state
            .onchain
            .mock_cluster()
            .expect("mock")
            .submitted()
            .len(),
        1
    );
}

fn canonical_action_hash(payer: &Pubkey, action: &Instruction) -> [u8; 32] {
    let message = VersionedMessage::V0(
        Message::try_compile(payer, std::slice::from_ref(action), &[], Hash::default()).unwrap(),
    );
    solana_confidential_compute_sdk::hash_compiled_action(&message, 0, 0).expect("complete action")
}

fn b64_tx(_payer: &Pubkey, ixs: &[Instruction]) -> String {
    let message = VersionedMessage::V0(
        Message::try_compile(&Pubkey::new_unique(), ixs, &[], Hash::default()).expect("compile"),
    );
    let tx = VersionedTransaction {
        signatures: vec![Signature::default(); message.header().num_required_signatures as usize],
        message,
    };
    let bytes = bincode::serialize(&tx).expect("serialize");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
}

/// `POST /v1/sign` accepts the pinned consumer and still rejects transfers and governance.
/// @spec SCC-SIDECAR-001
#[tokio::test]
async fn test_sign_endpoint_screens_allowlisted_consumer() {
    let keys = EphemeralKeyManager::new();
    let pubkey = keys.pubkey();
    let consumer = Pubkey::new_unique();
    let onchain = signing_onchain(keys.pubkey()).await;
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::AmdSevSnp,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::default()),
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(100),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(100),
        }),
        allowed_consumer_program_id: Some(consumer),
    });

    let (addr, handle) = spawn_test_server(state).await;
    let client = Client::new();
    let mut verifier = Instruction {
        program_id: solana_confidential_compute_cpi::ID,
        accounts: vec![AccountMeta::new_readonly(pubkey, true)],
        data: solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec(),
    };
    let consumer_ix = Instruction {
        program_id: consumer,
        accounts: vec![AccountMeta::new(pubkey, true)],
        data: vec![1, 2, 3, 4],
    };

    let hash = canonical_action_hash(&pubkey, &consumer_ix);
    verifier.data =
        solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
    verifier.data.extend_from_slice(&95u64.to_le_bytes());
    verifier.data.extend_from_slice(&hash);
    verifier.data.extend_from_slice(consumer.as_ref());
    verifier
        .data
        .resize(80 + solana_confidential_compute_core::SNP_REPORT_SIZE, 0);
    verifier.data[80 + 0x50..80 + 0x70].copy_from_slice(pubkey.as_ref());

    let accepted = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({
            "transaction": b64_tx(&pubkey, &[verifier.clone(), consumer_ix.clone()])
        }))
        .send()
        .await
        .expect("sign consumer");
    assert_eq!(accepted.status(), 200);

    let recipient = Pubkey::new_unique();
    let transfer = system_instruction::transfer(&pubkey, &recipient, 5_000);
    let rejected_transfer = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({
            "transaction": b64_tx(&pubkey, &[verifier.clone(), consumer_ix.clone(), transfer])
        }))
        .send()
        .await
        .expect("sign transfer");
    assert_eq!(rejected_transfer.status(), 400);
    let transfer_json: Value = rejected_transfer.json().await.expect("json");
    assert_eq!(transfer_json["error"], "system transfer is not allowlisted");

    let governance = Instruction {
        program_id: solana_confidential_compute_cpi::ID,
        accounts: vec![AccountMeta::new_readonly(pubkey, true)],
        data: vec![90, 53, 0, 89, 164, 70, 107, 186],
    };
    let rejected_governance = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({
            "transaction": b64_tx(&pubkey, &[governance, consumer_ix])
        }))
        .send()
        .await
        .expect("sign governance");
    assert_eq!(rejected_governance.status(), 400);
    let governance_json: Value = rejected_governance.json().await.expect("json");
    assert_eq!(
        governance_json["error"],
        "verifier instruction is not allowlisted"
    );

    let stranger = Pubkey::new_unique();
    let stranger_ix = Instruction {
        program_id: stranger,
        accounts: vec![AccountMeta::new_readonly(pubkey, true)],
        data: vec![7],
    };
    let rejected_stranger = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({
            "transaction": b64_tx(&pubkey, &[verifier, stranger_ix])
        }))
        .send()
        .await
        .expect("sign stranger");
    assert_eq!(rejected_stranger.status(), 400);
    let stranger_json: Value = rejected_stranger.json().await.expect("json");
    let error = stranger_json["error"].as_str().unwrap_or("");
    assert!(error.contains("not allowlisted"), "{error}");

    handle.abort();
}

/// Claims-only metadata (including a tampered signature) must never activate signing.
#[tokio::test]
async fn simulated_gcp_registration_cannot_authorize_signing() {
    use std::{future::Future, pin::Pin};
    struct UnauthenticatedGcp {
        signature: &'static str,
    }
    impl AttestationProvider for UnauthenticatedGcp {
        fn enclave_type(&self) -> solana_confidential_compute_core::types::EnclaveType {
            solana_confidential_compute_core::types::EnclaveType::GcpConfidentialSpace
        }
        fn request_attestation<'a>(
            &'a self,
            signer: &'a Pubkey,
            slot_hash: &'a [u8; 32],
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            AttestationReport,
                            solana_confidential_compute_sidecar::error::SidecarError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                use base64::Engine;
                let (n0, n1) =
                    solana_confidential_compute_sidecar::attestation::gcp_oidc::mode_a_eat_nonces(
                        signer, slot_hash,
                    );
                let payload = serde_json::json!({"aud":"solana-confidential-compute-verifier","dbgstat":"disabled-since-boot","eat_nonce":[n0,n1],"exp":4102444800u64,"iat":1700000000,"iss":"https://confidentialcomputing.googleapis.com","secboot":true,"sub":"s","submods":{"container":{"image_digest":format!("sha256:{}","ab".repeat(32))}}});
                let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let jwt = format!(
                    "{}.{}.{}",
                    engine.encode(r#"{"alg":"RS256","kid":"teton-test"}"#),
                    engine.encode(payload.to_string()),
                    self.signature
                );
                solana_confidential_compute_sidecar::attestation::gcp_oidc::validate_gcp_token(
                    &jwt, signer, slot_hash, None,
                )?;
                Ok(AttestationReport::GcpJwt { jwt })
            })
        }
    }
    // Both an unsigned placeholder and altered signature pass claims preflight.
    for signature in ["e30", "dGFtcGVyZWQ"] {
        let keys = EphemeralKeyManager::new();
        let pubkey = keys.pubkey();
        let onchain = mock_onchain(Some(Keypair::new()));
        let state = Arc::new(SidecarAppState {
            enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
            enclave_mode: EnclaveMode::GcpConfidentialSpace,
            keys: RwLock::new(keys),
            provider: Arc::new(UnauthenticatedGcp { signature }),
            onchain,
            status: RwLock::new(AttestationSessionStatus::default()),
            allowed_consumer_program_id: None,
        });
        solana_confidential_compute_sidecar::server::attest_current_key(&state)
            .await
            .expect("simulate");
        let (addr, handle) = spawn_test_server(state).await;
        let client = Client::new();
        let status: Value = client
            .get(format!("http://{addr}/v1/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status["attestation_status"], "simulated");
        let ix = Instruction {
            program_id: solana_confidential_compute_cpi::ID,
            accounts: vec![AccountMeta::new_readonly(pubkey, true)],
            data: solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec(),
        };
        let tx = VersionedTransaction {
            signatures: vec![Signature::default()],
            message: VersionedMessage::V0(
                Message::try_compile(&pubkey, &[ix], &[], Hash::default()).unwrap(),
            ),
        };
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bincode::serialize(&tx).unwrap(),
        );
        let response = client
            .post(format!("http://{addr}/v1/sign"))
            .json(&serde_json::json!({"transaction":encoded}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let body: Value = response.json().await.unwrap();
        assert!(body["signature"].is_null());
        assert!(body["transaction"].is_null());
        handle.abort();
    }
}

#[tokio::test]
async fn signing_binds_each_consumer_action() {
    let keys = EphemeralKeyManager::new();
    let pubkey = keys.pubkey();
    let consumer = Pubkey::new_unique();
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::AmdSevSnp,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::default()),
        onchain: signing_onchain(pubkey).await,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(95),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(95),
        }),
        allowed_consumer_program_id: Some(consumer),
    });
    let (addr, handle) = spawn_test_server(state).await;
    let action = Instruction {
        program_id: consumer,
        accounts: vec![AccountMeta::new(pubkey, true)],
        data: vec![1, 9, 9],
    };
    let hash = canonical_action_hash(&pubkey, &action);
    let mut data = solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&95u64.to_le_bytes());
    data.extend_from_slice(&hash);
    data.extend_from_slice(consumer.as_ref());
    data.resize(80 + solana_confidential_compute_core::SNP_REPORT_SIZE, 0);
    data[80 + 0x50..80 + 0x70].copy_from_slice(pubkey.as_ref());
    let verify = Instruction {
        program_id: solana_confidential_compute_cpi::ID,
        accounts: vec![AccountMeta::new_readonly(pubkey, true)],
        data,
    };
    let mut changed = action.clone();
    changed.data[2] ^= 1;
    let cases = [
        (vec![verify.clone(), action.clone()], 200),
        (vec![verify.clone(), action.clone(), action.clone()], 400),
        (vec![action.clone(), verify.clone()], 400),
        (vec![verify, changed], 400),
    ];
    for (ixs, expected) in cases {
        let tx = VersionedTransaction {
            signatures: vec![Signature::default(); 2],
            message: VersionedMessage::V0(
                Message::try_compile(&Pubkey::new_unique(), &ixs, &[], Hash::default()).unwrap(),
            ),
        };
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bincode::serialize(&tx).unwrap(),
        );
        let response = Client::new()
            .post(format!("http://{addr}/v1/sign"))
            .json(&serde_json::json!({"transaction":encoded}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let body: Value = response.json().await.unwrap();
        if expected == 200 {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                body["transaction"].as_str().unwrap(),
            )
            .unwrap();
            let signed: VersionedTransaction = bincode::deserialize(&bytes).unwrap();
            assert_eq!(signed.message, tx.message);
            assert!(signed.signatures[1].verify(pubkey.as_ref(), &signed.message.serialize()));
        } else {
            assert!(body["signature"].is_null());
            assert!(body["transaction"].is_null());
        }
    }
    handle.abort();
}

#[tokio::test]
async fn expired_confirmed_unix_deadline_cannot_release_signature() {
    let keys = EphemeralKeyManager::new();
    let workload = keys.pubkey();
    let onchain = signing_onchain_with_deadline(workload, 100).await;
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::default()),
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(95),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(95),
        }),
        allowed_consumer_program_id: None,
    });
    let (addr, handle) = spawn_test_server(state).await;
    let response = Client::new()
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({"transaction":"unparsed-before-expiry-check"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("invalid or expired"));
    assert!(body.get("signature").is_none());
    assert!(body.get("transaction").is_none());
    handle.abort();
    let valid = signing_onchain_with_deadline(workload, 101).await;
    assert!(valid.validate_registered_session(&workload).await.is_ok());
}

#[tokio::test]
async fn status_does_not_claim_active_at_confirmed_unix_expiry() {
    let keys = EphemeralKeyManager::new();
    let onchain = signing_onchain_with_deadline(keys.pubkey(), 100).await;
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::default()),
        onchain,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(95),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(95),
        }),
        allowed_consumer_program_id: None,
    });
    let (addr, handle) = spawn_test_server(state).await;
    let response: Value = Client::new()
        .get(format!("http://{addr}/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(response["attestation_status"], "active");
    handle.abort();
}

#[tokio::test]
async fn heartbeat_renews_at_unix_buffer_and_preserves_failed_refresh() {
    for (deadline, expected_renewal) in [(101, true), (1000, false), (100, true)] {
        let keys = EphemeralKeyManager::new();
        let onchain = signing_onchain_with_deadline(keys.pubkey(), deadline).await;
        let state = Arc::new(SidecarAppState {
            enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
            enclave_mode: EnclaveMode::Mock,
            keys: RwLock::new(keys),
            provider: Arc::new(MockAttestationProvider::default()),
            onchain,
            status: RwLock::new(AttestationSessionStatus {
                registered_slot: Some(95),
                expires_slot: Some(u64::MAX),
                expires_unix_timestamp: Some(deadline),
                last_nonce_slot: Some(95),
            }),
            allowed_consumer_program_id: None,
        });
        // Provider refresh cannot complete: local RPC intentionally serves only
        // confirmed record + Clock, and no SlotHashes. No real RPC is contacted.
        let heartbeat =
            solana_confidential_compute_sidecar::HeartbeatDaemon::new(state.clone(), 1, 0)
                .with_renewal_buffer_seconds(1);
        let result = heartbeat.poll_once().await;
        if expected_renewal {
            assert!(result.is_err());
        } else {
            assert!(!result.unwrap());
        }
        let retained = state.status.read().await;
        assert_eq!(retained.expires_unix_timestamp, Some(deadline));
        assert_eq!(retained.expires_slot, Some(u64::MAX));
    }
}

/// A dry-run must never request a real GCP metadata credential.
struct ForbiddenMetadata;
impl AttestationProvider for ForbiddenMetadata {
    fn enclave_type(&self) -> solana_confidential_compute_core::types::EnclaveType {
        solana_confidential_compute_core::types::EnclaveType::GcpConfidentialSpace
    }
    fn request_attestation<'a>(
        &'a self,
        _: &'a Pubkey,
        _: &'a [u8; 32],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        AttestationReport,
                        solana_confidential_compute_sidecar::SidecarError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        panic!("dry-run requested metadata")
    }
}
#[tokio::test]
async fn gcp_dry_run_http_enrolls_without_metadata_and_cannot_sign() {
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::new(
            Some(zeroize::Zeroizing::new(
                "test-operator-token-0123456789abcdef".into(),
            )),
            300,
        )
        .unwrap(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(EphemeralKeyManager::new()),
        provider: Arc::new(ForbiddenMetadata),
        onchain: mock_onchain(Some(Keypair::new())),
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    });
    let (addr, handle) = spawn_test_server(state).await;
    let client = Client::new();
    let enrolled = client
        .post(format!("http://{addr}/v1/attest"))
        .bearer_auth("test-operator-token-0123456789abcdef")
        .send()
        .await
        .unwrap();
    assert_eq!(enrolled.status(), 200);
    let status: Value = client
        .get(format!("http://{addr}/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["attestation_status"], "simulated");
    let denied = client
        .post(format!("http://{addr}/v1/sign"))
        .json(&serde_json::json!({"transaction":"unused"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let body: Value = denied.json().await.unwrap();
    assert!(body.get("signature").is_none());
    handle.abort();
}

// Controlled provider/RPC component test: no hardware or vendor admission proof.
#[tokio::test]
async fn issue_292_heartbeat_recovers_initial_and_repeated_enrollment_failures() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct FlakyProvider(AtomicUsize);
    impl AttestationProvider for FlakyProvider {
        fn enclave_type(&self) -> solana_confidential_compute_core::types::EnclaveType {
            solana_confidential_compute_core::types::EnclaveType::AmdSevSnp
        }
        fn request_attestation<'a>(
            &'a self,
            key: &'a Pubkey,
            hash: &'a [u8; 32],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            AttestationReport,
                            solana_confidential_compute_sidecar::error::SidecarError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                if self.0.fetch_add(1, Ordering::SeqCst) < 2 {
                    return Err(
                        solana_confidential_compute_sidecar::error::SidecarError::OnchainError(
                            "controlled transient failure".into(),
                        ),
                    );
                }
                MockAttestationProvider::default()
                    .request_attestation(key, hash)
                    .await
            })
        }
    }
    let keys = EphemeralKeyManager::new();
    let original = keys.pubkey();
    let provider = Arc::new(FlakyProvider(AtomicUsize::new(0)));
    let onchain = mock_onchain(Some(Keypair::new()));
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::Mock,
        keys: RwLock::new(keys),
        provider: provider.clone(),
        onchain: onchain.clone(),
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    });
    assert!(reattest_current_key(&state).await.is_err());
    assert!(state.status.read().await.expires_slot.is_none());
    let heartbeat = solana_confidential_compute_sidecar::heartbeat::HeartbeatDaemon::new(
        state.clone(),
        1,
        5000,
    )
    .spawn();
    let recovered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if state.status.read().await.expires_slot.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    heartbeat.abort();
    assert!(
        recovered.is_ok(),
        "heartbeat must retry while unattested after each transient failure"
    );
    assert_eq!(state.keys.read().await.pubkey(), original);
    assert_eq!(provider.0.load(Ordering::SeqCst), 3);
    assert_eq!(onchain.mock_cluster().unwrap().submitted().len(), 1);
}

// A controlled RPC record supplies own identity. Evidence parsing here does not
// establish signatures, live admission, hardware origin, or action commitments.
#[tokio::test]
async fn issue_301_foreign_mode_b_cannot_authorize_sidecar_session() {
    let keys = EphemeralKeyManager::new();
    let own = keys.pubkey();
    let consumer = Pubkey::new_unique();
    let action = Instruction {
        program_id: consumer,
        accounts: vec![AccountMeta::new(own, true)],
        data: vec![0],
    };
    let hash = solana_confidential_compute_cpi::hash_action(
        &action.data,
        &[AccountMeta::new(own, true)],
        &[],
    );
    let state = Arc::new(SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::AmdSevSnp,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::default()),
        onchain: signing_onchain(own).await,
        status: RwLock::new(AttestationSessionStatus {
            registered_slot: Some(95),
            expires_slot: Some(u64::MAX),
            expires_unix_timestamp: None,
            last_nonce_slot: Some(95),
        }),
        allowed_consumer_program_id: Some(consumer),
    });
    let (addr, handle) = spawn_test_server(state).await;
    let mut snp = solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
    snp.extend_from_slice(&95u64.to_le_bytes());
    snp.extend_from_slice(&hash);
    snp.extend_from_slice(consumer.as_ref());
    snp.resize(80 + solana_confidential_compute_core::SNP_REPORT_SIZE, 0);
    snp[80 + 0x50..80 + 0x70].copy_from_slice(own.as_ref());
    let mut foreign = snp.clone();
    foreign[80 + 0x50] ^= 1;
    let mut measurement = snp.clone();
    measurement[80 + 0x90] ^= 1;
    let mut gcp = solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
    gcp.push(1);
    gcp.extend_from_slice(&95u64.to_le_bytes());
    gcp.extend_from_slice(&hash);
    gcp.extend_from_slice(&1u32.to_le_bytes());
    gcp.push(b'x');
    let document = include_bytes!("../../../fixtures/nitro_hardware_document.cose");
    let mut nitro =
        solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR.to_vec();
    nitro.push(1);
    nitro.extend_from_slice(&95u64.to_le_bytes());
    nitro.extend_from_slice(&hash);
    nitro.extend_from_slice(&(document.len() as u32).to_le_bytes());
    nitro.extend_from_slice(document);
    for (label, data, expected) in [
        ("foreign key", foreign, 400),
        ("foreign measurement", measurement, 400),
        ("identityless GCP", gcp, 400),
        ("foreign Nitro backend", nitro, 400),
        ("own SNP", snp, 200),
    ] {
        let verify = Instruction {
            program_id: solana_confidential_compute_cpi::ID,
            accounts: vec![AccountMeta::new_readonly(own, true)],
            data,
        };
        let response = Client::new()
            .post(format!("http://{addr}/v1/sign"))
            .json(&serde_json::json!({"transaction": b64_tx(&own, &[verify, action.clone()])}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{label}");
        let body: Value = response.json().await.unwrap();
        if expected != 200 {
            assert!(body["signature"].is_null());
            assert!(body["transaction"].is_null());
        }
    }
    handle.abort();
}
