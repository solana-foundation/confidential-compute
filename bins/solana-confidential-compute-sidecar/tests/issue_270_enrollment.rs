//! Local RPC protocol fake: no cryptographic verification or external chain claim.
use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use solana_confidential_compute_sidecar::{
    attestation::mock::MockAttestationProvider,
    config::EnclaveMode,
    keys::EphemeralKeyManager,
    onchain::OnchainAttestor,
    server::{attest_current_key, AttestationSessionStatus, SidecarAppState},
};
use solana_sdk::{hash::Hash, pubkey::Pubkey, signature::Keypair, transaction::Transaction};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::RwLock};

#[tokio::test]
async fn enrollment_stores_confirmed_limits_instead_of_estimated_ttl() {
    let keys = EphemeralKeyManager::new();
    let workload = keys.pubkey();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rpc = Router::new().route("/", post(move |Json(request): Json<Value>| async move {
        let account = |owner: Pubkey, data: Vec<u8>| json!({"lamports":1,"owner":owner.to_string(),"executable":false,"rentEpoch":0,"data":[base64::Engine::encode(&base64::engine::general_purpose::STANDARD,data),"base64"]});
        let result = match request["method"].as_str().unwrap() {
            "getSlot" => json!(100),
            "getVersion" => json!({"solana-core":"2.2.0","feature-set":0}),
            "getLatestBlockhash" => json!({"context":{"slot":100},"value":{"blockhash":Hash::new_from_array([7;32]).to_string(),"lastValidBlockHeight":200}}),
            "getAccountInfo" => {
                assert_eq!(request["params"][0], solana_sdk::sysvar::slot_hashes::ID.to_string());
                let mut bytes=1u64.to_le_bytes().to_vec(); bytes.extend(95u64.to_le_bytes()); bytes.extend([0x11;32]);
                json!({"context":{"slot":100},"value":account(solana_sdk::sysvar::ID,bytes)})
            },
            "sendTransaction" => {
                let raw=base64::Engine::decode(&base64::engine::general_purpose::STANDARD,request["params"][0].as_str().unwrap()).unwrap();
                let tx:Transaction=bincode::deserialize(&raw).unwrap(); assert!(tx.verify().is_ok());
                json!(tx.signatures[0].to_string())
            },
            "getSignatureStatuses" => json!({"context":{"slot":100},"value":[{"slot":100,"confirmations":1,"err":null,"confirmationStatus":"confirmed","status":{"Ok":null}}]}),
            "getMultipleAccounts" => {
                assert_eq!(request["params"][1]["commitment"],"confirmed");
                let pid=solana_confidential_compute_cpi::ID;
                let mut data=vec![0;154]; data[..8].copy_from_slice(&solana_confidential_compute_cpi::ATTESTED_SIGNER_DISCRIMINATOR); data[8..40].copy_from_slice(workload.as_ref()); data[40]=3;
                data[129..137].copy_from_slice(&99u64.to_le_bytes()); data[137..145].copy_from_slice(&170u64.to_le_bytes());
                data[145]=Pubkey::find_program_address(&[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,workload.as_ref()],&pid).1;
                data[146..154].copy_from_slice(&130i64.to_le_bytes());
                let clock=solana_sdk::clock::Clock{slot:100,unix_timestamp:100,..Default::default()};
                json!({"context":{"slot":100},"value":[account(pid,data),account(solana_sdk::sysvar::ID,bincode::serialize(&clock).unwrap())]})
            },
            method => panic!("unexpected local RPC {method}"),
        };
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }));
    let task = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
    let state = SidecarAppState {
        enrollment: solana_confidential_compute_sidecar::control::EnrollmentControl::default(),
        enclave_mode: EnclaveMode::GcpConfidentialSpace,
        keys: RwLock::new(keys),
        provider: Arc::new(MockAttestationProvider::new_gcp(None)),
        onchain: Arc::new(OnchainAttestor::new(
            &format!("http://{addr}"),
            None,
            Some(Keypair::new()),
            false,
        )),
        status: RwLock::new(AttestationSessionStatus::default()),
        allowed_consumer_program_id: None,
    };
    assert_eq!(attest_current_key(&state).await.unwrap(), 170);
    let status = state.status.read().await;
    assert_eq!(status.registered_slot, Some(99));
    assert_eq!(status.expires_slot, Some(170));
    assert_eq!(status.expires_unix_timestamp, Some(130));
    task.abort();
}
