// Test code: unwrap, expect and panic! report a failed test (SDLC 3.2.8 covers production code).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable)]
//! RPC routing proof only. Fixture bindings are changed to local test keys,
//! invalidating their signatures; this fake does not claim crypto feasibility.
use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use solana_confidential_compute_sidecar::{AttestationReport, EphemeralKeyManager, OnchainAttestor};
use solana_sdk::{hash::Hash, signature::Keypair, transaction::Transaction};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

async fn route(
    nitro: bool,
    fail_packet: Option<usize>,
) -> (Result<u64, solana_confidential_compute_sidecar::SidecarError>, Vec<Transaction>, Vec<u8>) {
    let workload = EphemeralKeyManager::new();
    let report = if nitro {
        let mut bytes = include_bytes!("../../../fixtures/nitro_hardware_document.cose").to_vec();
        let (_, view) = solana_confidential_compute_crypto::parse_nitro_attestation(&bytes).unwrap();
        let at = bytes.windows(32).position(|w| w == view.user_data).unwrap();
        bytes[at..at + 32].copy_from_slice(workload.pubkey().as_ref());
        assert_eq!(bytes.len(), 4526);
        AttestationReport::AwsNitro { document: bytes }
    } else {
        let mut bytes = include_bytes!("../../../fixtures/snp_hardware_report_milan.bin").to_vec();
        bytes[0x50..0x70].copy_from_slice(workload.pubkey().as_ref());
        assert_eq!(bytes.len(), 1184);
        AttestationReport::SevSnp { report: bytes, vcek_cert: None }
    };
    let evidence = match &report {
        AttestationReport::AwsNitro { document } => document.clone(),
        AttestationReport::SevSnp { report, .. } => report.clone(),
        _ => unreachable!(),
    };
    let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
    let captured = submitted.clone();
    let identity = workload.pubkey();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rpc=Router::new().route("/",post(move |Json(request):Json<Value>| {
        let captured=captured.clone(); async move {
        let result=match request["method"].as_str().unwrap() {
            "getSlot"=>json!(100),
            "getVersion"=>json!({"solana-core":"2.2.0","feature-set":0}),
            "getLatestBlockhash"=>json!({"context":{"slot":100},"value":{"blockhash":Hash::new_unique().to_string(),"lastValidBlockHeight":200}}),
            "sendTransaction"=>{
                let raw=base64::Engine::decode(&base64::engine::general_purpose::STANDARD,request["params"][0].as_str().unwrap()).unwrap();
                let tx:Transaction=bincode::deserialize(&raw).unwrap(); assert!(tx.verify().is_ok());
                let signature=tx.signatures[0].to_string();
                let mut guard=captured.lock().unwrap();let index=guard.len();guard.push(tx);
                if raw.len()>1232 || fail_packet==Some(index) {
                    return Json(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32002,"message":"injected packet failure"}}));
                }
                json!(signature)
            },
                    "getMultipleAccounts" => {
                        let pid=solana_confidential_compute_cpi::ID;
                        let account=|owner:solana_sdk::pubkey::Pubkey,data:Vec<u8>| json!({"lamports":1,"owner":owner.to_string(),"executable":false,"rentEpoch":0,"data":[base64::Engine::encode(&base64::engine::general_purpose::STANDARD,data),"base64"]});
                        let mut data=vec![0;154];data[..8].copy_from_slice(&solana_confidential_compute_cpi::ATTESTED_SIGNER_DISCRIMINATOR);data[8..40].copy_from_slice(identity.as_ref());data[40]=if nitro{2}else{1};data[129..137].copy_from_slice(&99u64.to_le_bytes());data[137..145].copy_from_slice(&170u64.to_le_bytes());data[145]=solana_sdk::pubkey::Pubkey::find_program_address(&[solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,identity.as_ref()],&pid).1;data[146..154].copy_from_slice(&130i64.to_le_bytes());
                        let clock=solana_sdk::clock::Clock{slot:100,unix_timestamp:100,..Default::default()};
                        json!({"context":{"slot":100},"value":[account(pid,data),account(solana_sdk::sysvar::ID,bincode::serialize(&clock).unwrap())]})
                    },
            "getSignatureStatuses"=>json!({"context":{"slot":100},"value":[{"slot":100,"confirmations":1,"err":null,"confirmationStatus":"confirmed","status":{"Ok":null}}]}),
            method=>panic!("unexpected RPC {method}"),
        };
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }}));
    let task = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
    let attestor = OnchainAttestor::new(&format!("http://{addr}"), None, Some(Keypair::new()), false);
    let result = attestor.submit_attestation(&workload, 95, &report).await;
    task.abort();
    let transactions = submitted.lock().unwrap().clone();
    (result, transactions, evidence)
}
fn tags(txs: &[Transaction]) -> Vec<Vec<u8>> {
    txs.iter().map(|tx| tx.message.instructions.last().unwrap().data[..8].to_vec()).collect()
}
#[tokio::test]
async fn live_hardware_sizes_snp_use_ordered_bounded_packets() {
    assert_routing(false).await;
}
#[tokio::test]
async fn live_hardware_sizes_nitro_use_ordered_bounded_packets() {
    assert_routing(true).await;
}
async fn assert_routing(nitro: bool) {
    let (result, txs, evidence) = route(nitro, None).await;
    assert!(result.is_ok(), "{result:?}");
    let t = tags(&txs);
    assert_eq!(t.first().unwrap(), b"stagebeg");
    assert_eq!(&t[t.len() - 3..], &[b"stagesea".to_vec(), b"stageuse".to_vec(), b"stagedel".to_vec()]);
    let mut payload = Vec::<u8>::new();
    for tx in &txs[1..txs.len() - 3] {
        let ix = tx.message.instructions.last().unwrap();
        assert_eq!(&ix.data[..8], b"stageput");
        assert_eq!(u32::from_le_bytes(ix.data[8..12].try_into().unwrap()) as usize, payload.len());
        payload.extend_from_slice(&ix.data[12..]);
    }
    assert_eq!(&payload[if nitro { 53 } else { 16 }..][..evidence.len()], evidence);
    for tx in txs {
        assert!(bincode::serialized_size(&tx).unwrap() <= 1232);
        assert!(tx.verify().is_ok());
    }
}
#[tokio::test]
async fn partial_upload_failure_closes_without_consume_or_retry() {
    let (result, txs, _) = route(false, Some(2)).await;
    assert!(result.is_err());
    assert_eq!(tags(&txs), [b"stagebeg", b"stageput", b"stageput", b"stagedel"].map(|x| x.to_vec()));
    assert!(result.unwrap_err().to_string().contains("cleanup"));
}
#[tokio::test]
async fn cleanup_failure_after_consume_reports_nonce_already_consumed() {
    // SNP payload1202 => two uploads; close is packet5.
    let (result, txs, _) = route(false, Some(5)).await;
    assert_eq!(tags(&txs).last().unwrap(), b"stagedel");
    assert!(result.unwrap_err().to_string().contains("nonce consumed"));
}
