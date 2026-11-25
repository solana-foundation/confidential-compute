//! Local loopback HTTP RPC server and route handlers.
//!
//! @spec SCC-SIDECAR-004

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use bincode::Options;
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, transaction::VersionedTransaction};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::RwLock;

use crate::{
    attestation::AttestationProvider, config::EnclaveMode, control::EnrollmentControl, error::SidecarError,
    keys::EphemeralKeyManager, onchain::OnchainAttestor,
};

pub struct SidecarAppState {
    pub enrollment: EnrollmentControl,
    pub enclave_mode: EnclaveMode,
    pub keys: RwLock<EphemeralKeyManager>,
    pub provider: Arc<dyn AttestationProvider>,
    pub onchain: Arc<OnchainAttestor>,
    pub status: RwLock<AttestationSessionStatus>,
    /// When set, `POST /v1/sign` may include instructions for this program.
    /// @spec SCC-SIDECAR-001
    pub allowed_consumer_program_id: Option<Pubkey>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationSessionStatus {
    pub registered_slot: Option<u64>,
    pub expires_slot: Option<u64>,
    pub expires_unix_timestamp: Option<i64>,
    pub last_nonce_slot: Option<u64>,
}

/// HTTP body cap for every route, including `POST /v1/sign`.
const MAX_SIGN_BODY: usize = 65_536;

/// Signature vector length accepted before bincode walks the message.
const MAX_SIGNATURES: u64 = 64;

/// `RequestUnits` (deprecated), `RequestHeapFrame`, `SetComputeUnitLimit`,
/// `SetComputeUnitPrice`, and `SetLoadedAccountsDataSizeLimit`.
const COMPUTE_BUDGET_PROGRAM_ID: Pubkey = Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");

/// Workload attestation instructions the enclave key may sign.
/// Governance discriminators are absent on purpose.
const ALLOWED_VERIFIER_DISCRIMINATORS: [[u8; 8]; 5] = [
    [246, 249, 100, 14, 102, 116, 92, 145], // verify_and_register
    solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
    solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR,
    solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
    crate::onchain::VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR,
];

pub fn create_router(state: Arc<SidecarAppState>) -> Router {
    Router::new()
        .route("/v1/status", get(status_handler))
        .route("/v1/attest", post(attest_handler))
        .route("/v1/sign", post(sign_handler))
        .route("/v1/renew", post(renew_handler))
        .layer(DefaultBodyLimit::max(MAX_SIGN_BODY))
        .with_state(state)
}

/// Accepts only `127.0.0.1` and `::1`. Other loopback addresses fail closed.
pub fn validate_loopback_addr(addr: &SocketAddr) -> Result<(), SidecarError> {
    let allowed = match addr.ip() {
        IpAddr::V4(ip) => ip == Ipv4Addr::LOCALHOST,
        IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
    };
    if !allowed {
        return Err(SidecarError::InvalidConfig(format!(
            "Sidecar HTTP server must bind to 127.0.0.1 or ::1, got {}",
            addr.ip()
        )));
    }
    Ok(())
}

/// Re-attest the key currently in memory. Does not rotate it.
/// @spec SCC-SIDECAR-005
pub async fn attest_current_key(state: &SidecarAppState) -> Result<u64, SidecarError> {
    let _operation = state.enrollment.lock().await;
    attest_current_key_locked(state).await
}

async fn attest_current_key_locked(state: &SidecarAppState) -> Result<u64, SidecarError> {
    let keys = state.keys.read().await;
    let (status, expires_slot) = enroll_key(state, &keys).await?;
    *state.status.write().await = status;
    Ok(expires_slot)
}

/// Enroll a candidate without publishing it as the active signer. Returns the
/// new status and its expiry slot.
async fn enroll_key(
    state: &SidecarAppState,
    keys: &EphemeralKeyManager,
) -> Result<(AttestationSessionStatus, u64), SidecarError> {
    let (target_slot, slot_hash) = state.onchain.get_recent_slot_challenge().await?;
    let pubkey = keys.pubkey();
    let report = crate::attestation::request_for_submission(
        state.provider.as_ref(),
        state.onchain.is_dry_run(),
        &pubkey,
        &slot_hash,
    )
    .await?;
    let expires_slot = state.onchain.submit_attestation(keys, target_slot, &report).await?;
    let confirmed = if state.onchain.is_dry_run() {
        None
    } else {
        let session = state.onchain.confirmed_session(&pubkey).await?;
        if !session.is_valid() {
            return Err(SidecarError::OnchainError("confirmed enrollment is invalid or expired".into()));
        }
        Some(session)
    };
    let expires_slot = confirmed.map_or(expires_slot, |s| s.expires_slot);
    let status = AttestationSessionStatus {
        registered_slot: Some(confirmed.map_or(target_slot, |s| s.registered_slot)),
        expires_unix_timestamp: confirmed.map(|s| s.expires_unix_timestamp),
        expires_slot: Some(expires_slot),
        last_nonce_slot: Some(target_slot),
    };
    Ok((status, expires_slot))
}

/// Attest a candidate, then atomically replace the key and deadlines. Dropping
/// the replaced key zeroizes it. Failure/cancellation preserves the old session.
/// @spec SCC-SIDECAR-001 SCC-SIDECAR-005
pub async fn rotate_zeroize_and_attest(state: &SidecarAppState) -> Result<(Pubkey, Pubkey, u64), SidecarError> {
    let _operation = state.enrollment.lock().await;
    rotate_locked(state).await
}

async fn rotate_locked(state: &SidecarAppState) -> Result<(Pubkey, Pubkey, u64), SidecarError> {
    let candidate = EphemeralKeyManager::new();
    let (status, expires_slot) = enroll_key(state, &candidate).await?;
    let new_key = candidate.pubkey();
    let mut keys = state.keys.write().await;
    let mut current_status = state.status.write().await;
    let previous = keys.pubkey();
    *keys = candidate;
    *current_status = status;
    Ok((previous, new_key, expires_slot))
}

// ---------------------------------------------------------------------------
// GET /v1/status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct StatusResponse {
    pub enclave_mode: EnclaveMode,
    pub public_key: String,
    pub attestation_status: String,
    pub current_slot: Option<u64>,
    pub current_unix_timestamp: Option<i64>,
    pub remaining_seconds: Option<u64>,
    pub registered_slot: Option<u64>,
    pub expires_slot: Option<u64>,
    pub expires_unix_timestamp: Option<i64>,
    pub remaining_slots: Option<u64>,
}

async fn status_handler(State(state): State<Arc<SidecarAppState>>) -> impl IntoResponse {
    let keys = state.keys.read().await;
    let pubkey = keys.pubkey();
    let status = state.status.read().await.clone();
    drop(keys);
    let confirmed = if state.onchain.is_dry_run() { None } else { state.onchain.confirmed_session(&pubkey).await.ok() };
    let current_slot = confirmed.map(|s| s.current_slot);
    let current_unix_timestamp = confirmed.map(|s| s.current_unix_timestamp);
    let expires_slot = confirmed.map(|s| s.expires_slot).or(status.expires_slot);
    let expires_unix_timestamp = confirmed.map(|s| s.expires_unix_timestamp).or(status.expires_unix_timestamp);
    let attestation_status = if status.expires_slot.is_none() {
        "unattested"
    } else if state.onchain.is_dry_run() {
        "simulated"
    } else if let Some(session) = confirmed {
        if session.is_valid() {
            "active"
        } else {
            "expired"
        }
    } else {
        "unknown"
    }
    .to_string();
    Json(StatusResponse {
        enclave_mode: state.enclave_mode,
        public_key: pubkey.to_string(),
        attestation_status,
        current_slot,
        current_unix_timestamp,
        registered_slot: confirmed.map(|s| s.registered_slot).or(status.registered_slot),
        expires_slot,
        expires_unix_timestamp,
        remaining_slots: confirmed.map(|s| s.expires_slot.saturating_sub(s.current_slot)),
        remaining_seconds: confirmed
            .map(|s| s.expires_unix_timestamp.saturating_sub(s.current_unix_timestamp).max(0) as u64),
    })
}

// ---------------------------------------------------------------------------
// POST /v1/attest
// ---------------------------------------------------------------------------

async fn attest_handler(State(state): State<Arc<SidecarAppState>>, headers: HeaderMap) -> impl IntoResponse {
    let _operation = match state.enrollment.begin_http(&headers) {
        Ok(operation) => operation,
        Err(error) => return error.into_response(),
    };
    let pubkey = state.keys.read().await.pubkey();
    match attest_current_key_locked(&state).await {
        Ok(expires_slot) => {
            let nonce_slot = state.status.read().await.last_nonce_slot;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                "simulated": state.onchain.is_dry_run(),
                    "public_key": pubkey.to_string(),
                    "nonce_slot": nonce_slot,
                    "expires_slot": expires_slot,
                    "expires_unix_timestamp": state.status.read().await.expires_unix_timestamp,
                })),
            )
                .into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// POST /v1/sign
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignRequest {
    /// Base64-encoded bincode-serialized Solana VersionedTransaction.
    pub transaction: String,
}

async fn sign_handler(
    State(state): State<Arc<SidecarAppState>>,
    Json(payload): Json<SignRequest>,
) -> impl IntoResponse {
    // Acquire key read lock first so rotate_zeroize_and_attest cannot rotate concurrently.
    // @spec SCC-SIDECAR-001
    let keys = state.keys.read().await;
    let status = state.status.read().await.clone();
    let Some(expires_slot) = status.expires_slot else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "enclave session is not attested"
            })),
        )
            .into_response();
    };
    if state.onchain.is_dry_run() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "dry-run attestation is simulated; signing is disabled"
            })),
        )
            .into_response();
    }
    let current_slot = match state.onchain.get_current_slot().await {
        Ok(slot) => slot,
        Err(e) => {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": e.to_string() })))
                .into_response();
        }
    };
    if current_slot > expires_slot {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "attestation_expired",
                "current_slot": current_slot,
                "expires_slot": expires_slot
            })),
        )
            .into_response();
    }

    let registered = match state.onchain.registered_session_identity(&keys.pubkey()).await {
        Ok(registered) => registered,
        Err(error) => {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":error.to_string()}))).into_response()
        }
    };

    // 2. Decode serialized transaction
    let tx_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload.transaction.trim())
    {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("Invalid base64: {e}") })))
                .into_response();
        }
    };

    let mut tx = match deserialize_sign_transaction(&tx_bytes) {
        Ok(t) => t,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": error }))).into_response();
        }
    };

    if let Err(error) =
        screen_transaction(&tx, &state.onchain.verifier_program_id(), state.allowed_consumer_program_id.as_ref())
            .and_then(|()| {
                screen_consumer_identity(
                    &tx,
                    &state.onchain.verifier_program_id(),
                    &keys.pubkey(),
                    state.enclave_mode,
                    &registered,
                )
            })
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": error }))).into_response();
    }

    // 3. Sign with ephemeral key
    let sig = match keys.sign_transaction(&mut tx) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response();
        }
    };

    // 4. Re-encode transaction
    let new_tx_bytes = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Serialization failed: {e}") })),
            )
                .into_response();
        }
    };

    let new_tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &new_tx_bytes);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "signature": sig.to_string(),
            "transaction": new_tx_b64,
        })),
    )
        .into_response()
}

/// Decodes a sign-request payload with a hard byte cap.
///
/// The signature-count prefix is rejected before `bincode` asks `serde` for a
/// sequence of that length.
fn deserialize_sign_transaction(bytes: &[u8]) -> Result<VersionedTransaction, String> {
    if bytes.len() > MAX_SIGN_BODY {
        return Err(format!("transaction bincode is {} bytes; limit is {MAX_SIGN_BODY}", bytes.len()));
    }
    if bytes.len() < 8 {
        return Err("transaction bincode is shorter than a signature count".to_string());
    }
    let mut count_bytes = [0u8; 8];
    count_bytes.copy_from_slice(&bytes[..8]);
    let signature_count = u64::from_le_bytes(count_bytes);
    if signature_count > MAX_SIGNATURES {
        return Err(format!("transaction declares {signature_count} signatures; limit is {MAX_SIGNATURES}"));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_SIGN_BODY as u64)
        .deserialize(bytes)
        .map_err(|e| format!("Invalid transaction bincode: {e}"))
}

/// Rejects transactions the enclave key must not sign.
///
/// Every instruction program id is checked. System transfers are rejected
/// before the consumer id is consulted, including when that id is the System
/// Program. The verifier program is limited to attestation discriminators.
/// Compute Budget is limited to its fee and limit instructions. When
/// `allowed_consumer_program_id` is set, instructions for that program are
/// accepted only immediately after their own nonce-protected Mode B verifier,
/// with a V3 commitment to complete wire data and ordered effective privileges.
/// At least one instruction must call `verifier_program_id`.
/// @spec SCC-SIDECAR-001
fn screen_transaction(
    tx: &VersionedTransaction,
    verifier_program_id: &Pubkey,
    allowed_consumer_program_id: Option<&Pubkey>,
) -> Result<(), String> {
    crate::signing_policy::validate_compute_budget(tx)?;
    let keys = tx.message.static_account_keys();
    let instructions = tx.message.instructions();
    if instructions.is_empty() {
        return Err("transaction has no instructions".to_string());
    }
    let mut saw_verifier = false;
    for ix in instructions {
        let program_id = keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| "instruction program id is outside the static account keys".to_string())?;
        if program_id == verifier_program_id {
            let disc_bytes = ix.data.get(..8).ok_or_else(|| "verifier instruction is not allowlisted".to_string())?;
            let mut disc = [0u8; 8];
            disc.copy_from_slice(disc_bytes);
            if !ALLOWED_VERIFIER_DISCRIMINATORS.contains(&disc) {
                return Err("verifier instruction is not allowlisted".to_string());
            }
            saw_verifier = true;
        } else if *program_id == COMPUTE_BUDGET_PROGRAM_ID {
            if !crate::signing_policy::compute_budget_allowed(&ix.data) {
                return Err("compute budget instruction is not allowlisted".to_string());
            }
        } else if *program_id == SYSTEM_PROGRAM_ID {
            // Checked before the consumer id so a System Program id cannot
            // authorize transfers or other system instructions.
            if ix.data.first() == Some(&2) || ix.data.first() == Some(&11) {
                return Err("system transfer is not allowlisted".to_string());
            }
            return Err("system program instruction is not allowlisted".to_string());
        } else if !allowed_consumer_program_id.is_some_and(|allowed| allowed == program_id) {
            return Err(format!("program {program_id} is not allowlisted"));
        }
    }
    if !saw_verifier {
        return Err("transaction does not call the verifier program".to_string());
    }
    // Loaded addresses are not available in the message; do not guess their identities.
    if tx.message.address_table_lookups().is_some_and(|tables| !tables.is_empty()) {
        return Err("address-table lookups are not supported by the signing policy".to_string());
    }
    for (index, consumer) in instructions.iter().enumerate() {
        let program = &keys[consumer.program_id_index as usize];
        if program == verifier_program_id || *program == COMPUTE_BUDGET_PROGRAM_ID {
            continue;
        }
        let previous = index
            .checked_sub(1)
            .and_then(|i| instructions.get(i))
            .ok_or_else(|| "consumer must immediately follow its own Mode B verifier".to_string())?;
        if keys.get(previous.program_id_index as usize) != Some(verifier_program_id) {
            return Err("consumer must immediately follow its own Mode B verifier".to_string());
        }
        let expected = mode_b_action_hash(&previous.data, program)?;
        // The SDK resolves final compiled privileges (including payer and
        // other instructions) and hashes complete wire data without a split guess.
        if solana_confidential_compute_sdk::validate_compiled_action(&tx.message, index, &expected).is_err() {
            return Err("consumer data/accounts do not match the verifier action hash".to_string());
        }
    }
    Ok(())
}

/// A foreign Mode B proof must not authorize a signature by our Mode A key.
/// Parsing is only a local identity screen: the on-chain verifier still checks
/// signatures, trust roots, freshness, commitments, tenant and backend policy.
fn screen_consumer_identity(
    tx: &VersionedTransaction,
    verifier_program_id: &Pubkey,
    workload: &Pubkey,
    mode: EnclaveMode,
    registered: &solana_confidential_compute_cpi::AttestedSignerAccount,
) -> Result<(), String> {
    let keys = tx.message.static_account_keys();
    for (index, instruction) in tx.message.instructions().iter().enumerate() {
        let program = keys.get(instruction.program_id_index as usize).ok_or("invalid instruction program index")?;
        if program == verifier_program_id || *program == COMPUTE_BUDGET_PROGRAM_ID {
            continue;
        }
        let backend = match mode {
            EnclaveMode::AmdSevSnp => 1,
            EnclaveMode::AwsNitro => 2,
            // GCP Mode B binds only an action commitment, not a workload key.
            _ => return Err("backend has no workload-bound Mode B signing authorization".into()),
        };
        if registered.enclave_type != backend {
            return Err("configured backend does not match the confirmed signer record".into());
        }
        let data = &index
            .checked_sub(1)
            .and_then(|previous| tx.message.instructions().get(previous))
            .ok_or("consumer requires preceding Mode B identity")?
            .data;
        let discriminator = data.get(..8).ok_or("missing Mode B discriminator")?;
        let (key, measurement) = if backend == 1
            && discriminator == solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR
        {
            let report = solana_confidential_compute_core::SnpReportView::try_from_slice(
                data.get(80..).ok_or("missing SNP report")?,
            )
            .map_err(|_| "malformed SNP report")?;
            (report.pubkey(), report.measurement())
        } else if backend == 2
            && discriminator == solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR
        {
            let (_, document) = solana_confidential_compute_crypto::nitro::parse_nitro_attestation(
                data.get(53..).ok_or("missing Nitro document")?,
            )
            .map_err(|_| "malformed Nitro document")?;
            (document.user_data, document.pcrs.pcr0)
        } else {
            return Err("Mode B verifier is not for the sidecar backend".into());
        };
        if key != workload.to_bytes() || measurement != registered.measurement {
            return Err("Mode B workload key or measurement differs from the confirmed sidecar identity".into());
        }
    }
    Ok(())
}

/// Read only nonce-protected Mode B layouts; registration is never action authorization.
fn mode_b_action_hash(data: &[u8], consumer_program: &Pubkey) -> Result<[u8; 32], String> {
    let malformed = || "consumer requires a well-formed nonce-protected Mode B verifier".to_string();
    let disc = data.get(..8).ok_or_else(malformed)?;
    let hash = if disc == solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR {
        if data.len() != 80 + solana_confidential_compute_core::SNP_REPORT_SIZE
            || data[48..80] != consumer_program.to_bytes()
        {
            return Err(malformed());
        }
        data.get(16..48)
    } else if disc == solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR
        || disc == solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR
    {
        if data.len() < 53 || data[8] != 1 {
            return Err(malformed());
        }
        let length = u32::from_le_bytes(data[49..53].try_into().map_err(|_| malformed())?) as usize;
        let maximum = if disc == solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR {
            solana_confidential_compute_crypto::jwt::MAX_JWT_LEN
        } else {
            solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN
        };
        if length == 0 || length > maximum || data.len() != 53 + length {
            return Err(malformed());
        }
        data.get(17..49)
    } else if disc == crate::onchain::VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR {
        // Fixed layout: mode @ 8, action hash @ 17..49, measurement @ 49..81.
        // There is no length prefix. Mode A is not action authorization.
        if data.len() != crate::onchain::VERIFY_NVIDIA_IX_LEN || data[8] != crate::onchain::VERIFY_NVIDIA_MODE_B {
            return Err(malformed());
        }
        data.get(17..49)
    } else {
        return Err(malformed());
    };
    hash.and_then(|bytes| bytes.try_into().ok()).ok_or_else(malformed)
}

// ---------------------------------------------------------------------------
// POST /v1/renew
// ---------------------------------------------------------------------------

async fn renew_handler(State(state): State<Arc<SidecarAppState>>, headers: HeaderMap) -> impl IntoResponse {
    let _operation = match state.enrollment.begin_http(&headers) {
        Ok(operation) => operation,
        Err(error) => return error.into_response(),
    };
    match rotate_locked(&state).await {
        Ok((previous, new_key, expires_slot)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "simulated": state.onchain.is_dry_run(),
                "previous_key": previous.to_string(),
                "new_key": new_key.to_string(),
                "expires_slot": expires_slot,
            })),
        )
            .into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{
        hash::Hash,
        instruction::{AccountMeta, Instruction},
        message::{v0::Message, VersionedMessage},
        signature::Signature,
    };
    use solana_system_interface::instruction as system_instruction;

    fn compiled(payer: &Pubkey, ixs: &[Instruction]) -> VersionedTransaction {
        let message = VersionedMessage::V0(Message::try_compile(payer, ixs, &[], Hash::default()).expect("compile"));
        VersionedTransaction { signatures: vec![Signature::default()], message }
    }

    fn canonical_action_hash(payer: &Pubkey, action: &Instruction) -> [u8; 32] {
        solana_confidential_compute_sdk::hash_compiled_action(
            &compiled(payer, std::slice::from_ref(action)).message,
            0,
            0,
        )
        .expect("complete action")
    }

    fn verifier_ix(payer: &Pubkey, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: solana_confidential_compute_cpi::ID,
            accounts: vec![AccountMeta::new_readonly(*payer, true)],
            data,
        }
    }

    #[test]
    fn caller_screen_rejects_failed_tags_and_unbounded_fees() {
        use solana_compute_budget_interface::ComputeBudgetInstruction as Budget;
        let payer = Pubkey::new_unique();
        let raw = compiled(
            &payer,
            &[verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_DISCRIMINATOR.to_vec())],
        );
        assert!(screen_transaction(&raw, &solana_confidential_compute_cpi::ID, None).is_err());
        let verifier =
            verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec());
        let cap = Budget::set_compute_unit_limit(1_400_000);
        assert!(screen_transaction(
            &compiled(&payer, &[cap.clone(), verifier.clone()]),
            &solana_confidential_compute_cpi::ID,
            None
        )
        .is_ok());
        let deprecated = Instruction { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: vec![0; 9] };
        for budgets in [vec![Budget::set_compute_unit_price(1)], vec![deprecated], vec![cap.clone(), cap]] {
            let mut instructions = budgets;
            instructions.push(verifier.clone());
            assert!(screen_transaction(&compiled(&payer, &instructions), &solana_confidential_compute_cpi::ID, None)
                .is_err());
        }
    }

    #[test]
    fn allowlist_accepts_verifier_and_compute_budget() {
        let payer = Pubkey::new_unique();
        let budget = Instruction {
            program_id: COMPUTE_BUDGET_PROGRAM_ID,
            accounts: vec![],
            data: vec![2, 0xc0, 0x5c, 0x15, 0x00],
        };
        let tx = compiled(
            &payer,
            &[
                budget,
                verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec()),
            ],
        );
        assert!(screen_transaction(&tx, &solana_confidential_compute_cpi::ID, None).is_ok());
    }

    #[test]
    fn allowlist_rejects_system_transfer_and_governance() {
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let transfer = system_instruction::transfer(&payer, &recipient, 5_000);
        let verify =
            verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec());
        let mixed = compiled(&payer, &[verify, transfer]);
        let err = screen_transaction(&mixed, &solana_confidential_compute_cpi::ID, None).unwrap_err();
        assert!(err.contains("system transfer"), "{err}");

        let governance = compiled(&payer, &[verifier_ix(&payer, vec![90, 53, 0, 89, 164, 70, 107, 186])]);
        let err = screen_transaction(&governance, &solana_confidential_compute_cpi::ID, None).unwrap_err();
        assert!(err.contains("verifier instruction is not allowlisted"), "{err}");

        let only_budget = compiled(
            &payer,
            &[Instruction {
                program_id: COMPUTE_BUDGET_PROGRAM_ID,
                accounts: vec![],
                data: vec![3, 0, 0, 0, 0, 0, 0, 0, 0],
            }],
        );
        let err = screen_transaction(&only_budget, &solana_confidential_compute_cpi::ID, None).unwrap_err();
        assert!(err.contains("does not call the verifier program"), "{err}");
    }

    #[test]
    fn issue_301_nitro_identity_uses_confirmed_key_backend_and_measurement() {
        // The archived bytes are authentic, but this is parser/screen testing.
        // It does not prove this document commits to our action or possession
        // of the archived workload's secret. No chain verification is modeled.
        let document = include_bytes!("../../../fixtures/nitro_hardware_document.cose");
        let (_, parsed) = solana_confidential_compute_crypto::nitro::parse_nitro_attestation(document).unwrap();
        let workload = Pubkey::new_from_array(parsed.user_data);
        let consumer = Pubkey::new_unique();
        let mut bytes = vec![0; solana_confidential_compute_cpi::ATTESTED_SIGNER_ACCOUNT_SIZE];
        bytes[..8].copy_from_slice(&solana_confidential_compute_cpi::ATTESTED_SIGNER_DISCRIMINATOR);
        bytes[8..40].copy_from_slice(workload.as_ref());
        bytes[40] = 2;
        bytes[41..89].copy_from_slice(&parsed.pcrs.pcr0);
        let registered = solana_confidential_compute_cpi::AttestedSignerAccount::try_from_slice(&bytes).unwrap();
        let mut data = solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR.to_vec();
        data.push(1);
        data.extend_from_slice(&95u64.to_le_bytes());
        data.extend_from_slice(&[0; 32]);
        data.extend_from_slice(&(document.len() as u32).to_le_bytes());
        data.extend_from_slice(document);
        let tx = compiled(
            &workload,
            &[
                verifier_ix(&workload, data),
                Instruction {
                    program_id: consumer,
                    accounts: vec![AccountMeta::new_readonly(workload, true)],
                    data: vec![0],
                },
            ],
        );
        let check = |key: &Pubkey, mode, record: &solana_confidential_compute_cpi::AttestedSignerAccount| {
            screen_consumer_identity(&tx, &solana_confidential_compute_cpi::ID, key, mode, record)
        };
        assert!(check(&workload, EnclaveMode::AwsNitro, &registered).is_ok());
        assert!(check(&Pubkey::new_unique(), EnclaveMode::AwsNitro, &registered).is_err());
        assert!(check(&workload, EnclaveMode::AmdSevSnp, &registered).is_err());
        let mut other = registered;
        other.measurement[0] ^= 1;
        assert!(check(&workload, EnclaveMode::AwsNitro, &other).is_err());
        other = registered;
        other.enclave_type = 1;
        assert!(check(&workload, EnclaveMode::AwsNitro, &other).is_err());
        assert!(check(&workload, EnclaveMode::GcpConfidentialSpace, &registered).is_err());
    }

    #[test]
    fn issue_300_screen_accepts_full_wire_v3_for_any_discriminator_split() {
        let payer = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        for length in [0, 1, 2, 7, 8, 12] {
            let action = Instruction {
                program_id: consumer,
                accounts: vec![AccountMeta::new(payer, true)],
                data: vec![9; length],
            };
            let hash = solana_confidential_compute_core::action::hash_instruction(&action);
            let mut data = solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
            data.extend_from_slice(&95u64.to_le_bytes());
            data.extend_from_slice(&hash);
            data.extend_from_slice(consumer.as_ref());
            data.resize(80 + solana_confidential_compute_core::SNP_REPORT_SIZE, 0);
            let tx = compiled(&payer, &[verifier_ix(&payer, data), action]);
            assert!(
                screen_transaction(&tx, &solana_confidential_compute_cpi::ID, Some(&consumer)).is_ok(),
                "canonical V3 full wire length {length} must pass without guessing a split"
            );
        }
    }

    #[test]
    fn issue_300_screen_has_no_v1_or_v2_digest_fallback() {
        let payer = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        let action =
            Instruction { program_id: consumer, accounts: vec![AccountMeta::new(payer, true)], data: vec![1, 9, 9] };
        for v2 in [false, true] {
            // Historical encodings retained only as rejection controls.
            let mut hash = solana_sdk::hash::Hasher::default();
            if v2 {
                hash.hash(b"teton:action:v2\0");
            }
            hash.hash(&1u32.to_le_bytes());
            hash.hash(&action.data[..1]);
            hash.hash(&1u32.to_le_bytes());
            hash.hash(payer.as_ref());
            if v2 {
                hash.hash(&[1, 1]);
            }
            hash.hash(&2u32.to_le_bytes());
            hash.hash(&action.data[1..]);
            let mut data = solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
            data.extend_from_slice(&95u64.to_le_bytes());
            data.extend_from_slice(hash.result().as_ref());
            data.extend_from_slice(consumer.as_ref());
            data.resize(80 + solana_confidential_compute_core::SNP_REPORT_SIZE, 0);
            let tx = compiled(&payer, &[verifier_ix(&payer, data), action.clone()]);
            assert!(screen_transaction(&tx, &solana_confidential_compute_cpi::ID, Some(&consumer)).is_err());
        }
    }

    #[test]
    fn consumers_require_adjacent_mode_b_and_matching_full_action() {
        let payer = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        let action =
            Instruction { program_id: consumer, accounts: vec![AccountMeta::new(payer, true)], data: vec![1, 9, 9] };
        let hash = canonical_action_hash(&payer, &action);
        let mut data = solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
        data.push(1);
        data.extend_from_slice(&95u64.to_le_bytes());
        data.extend_from_slice(&hash);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(b'x');
        let verify = verifier_ix(&payer, data);
        let check = |ixs: &[Instruction]| {
            screen_transaction(&compiled(&payer, ixs), &solana_confidential_compute_cpi::ID, Some(&consumer))
        };
        assert!(check(&[verify.clone(), action.clone()]).is_ok());
        assert!(check(&[verify.clone(), action.clone(), action.clone()]).is_err());
        assert!(check(&[action.clone(), verify.clone()]).is_err());
        let mut changed = action.clone();
        changed.data[2] ^= 1;
        assert!(check(&[verify.clone(), changed]).is_err());
        let mut changed = action.clone();
        changed.accounts.push(AccountMeta::new_readonly(Pubkey::new_unique(), false));
        assert!(check(&[verify.clone(), changed]).is_err());
        let mut mode_a = verify.clone();
        mode_a.data[8] = 0;
        assert!(check(&[mode_a, action.clone()]).is_err());
        let mut malformed = verify.clone();
        malformed.data.pop();
        assert!(check(&[malformed, action.clone()]).is_err());
        let budget = Instruction { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: vec![2, 1, 0, 0, 0] };
        assert!(check(&[verify.clone(), budget, action.clone()]).is_err());
        let mut foreign = action.clone();
        foreign.program_id = Pubkey::new_unique();
        assert!(check(&[verify.clone(), foreign]).is_err());
        // The same Mode B envelope is used by Nitro; the Anchor data split is eight bytes.
        let mut anchor = action.clone();
        anchor.data = vec![7; 12];
        let anchor_hash = canonical_action_hash(&payer, &anchor);
        let mut nitro = verify.clone();
        nitro.data[..8].copy_from_slice(&solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
        nitro.data[17..49].copy_from_slice(&anchor_hash);
        assert!(check(&[nitro, anchor]).is_ok());
        let mut nvidia = vec![0u8; crate::onchain::VERIFY_NVIDIA_IX_LEN];
        nvidia[..8].copy_from_slice(&crate::onchain::VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR);
        nvidia[8] = crate::onchain::VERIFY_NVIDIA_MODE_B;
        nvidia[17..49].copy_from_slice(&hash);
        assert!(check(&[verifier_ix(&payer, nvidia.clone()), action.clone()]).is_ok());
        nvidia[8] = 0;
        assert!(check(&[verifier_ix(&payer, nvidia), action.clone()]).is_err());
        assert!(screen_transaction(
            &compiled(
                &payer,
                &[verifier_ix(&payer, crate::onchain::VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR.to_vec(),)],
            ),
            &solana_confidential_compute_cpi::ID,
            None,
        )
        .is_ok());
        let nonce_free = verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_DISCRIMINATOR.to_vec());
        assert!(check(&[nonce_free, action.clone()]).is_err());
        let mut bad_index = compiled(&payer, &[verify.clone(), action.clone()]);
        if let VersionedMessage::V0(message) = &mut bad_index.message {
            message.instructions[1].accounts[0] = 255;
        }
        assert!(screen_transaction(&bad_index, &solana_confidential_compute_cpi::ID, Some(&consumer)).is_err());
        let mut with_lookup = compiled(&payer, &[verify.clone(), action.clone()]);
        if let VersionedMessage::V0(message) = &mut with_lookup.message {
            message.address_table_lookups.push(solana_sdk::message::v0::MessageAddressTableLookup {
                account_key: Pubkey::new_unique(),
                writable_indexes: vec![0],
                readonly_indexes: vec![],
            });
        }
        assert!(screen_transaction(&with_lookup, &solana_confidential_compute_cpi::ID, Some(&consumer)).is_err());
        let second_key = Pubkey::new_unique();
        let mut ordered = action.clone();
        ordered.accounts.push(AccountMeta::new_readonly(second_key, false));
        let ordered_hash = canonical_action_hash(&payer, &ordered);
        let mut ordered_verify = verify.clone();
        ordered_verify.data[17..49].copy_from_slice(&ordered_hash);
        assert!(check(&[ordered_verify.clone(), ordered.clone()]).is_ok());
        ordered.accounts.swap(0, 1);
        assert!(check(&[ordered_verify, ordered]).is_err());
        assert!(check(&[verify.clone(), action.clone(), verify, action]).is_ok());
    }

    #[test]
    fn compiled_privilege_elevation_requires_fresh_commitment() {
        let payer = Pubkey::new_unique();
        let subject = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        let action = Instruction {
            program_id: consumer,
            accounts: vec![AccountMeta::new_readonly(subject, false)],
            data: vec![1, 8],
        };
        let mut data = solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
        data.push(1);
        data.extend(95u64.to_le_bytes());
        data.extend([0; 32]);
        data.extend(1u32.to_le_bytes());
        data.push(b'x');
        let mut verifier = verifier_ix(&payer, data);
        let template = compiled(&payer, &[verifier.clone(), action.clone()]);
        let original = solana_confidential_compute_sdk::hash_compiled_action(&template.message, 1, 1).unwrap();
        verifier.data[17..49].copy_from_slice(&original);
        assert!(screen_transaction(
            &compiled(&payer, &[verifier.clone(), action.clone()]),
            &solana_confidential_compute_cpi::ID,
            Some(&consumer)
        )
        .is_ok());
        // Same consumer program, ordered keys and bytes; its effective rights change.
        for new_payer in [false, true] {
            let mut elevated = verifier.clone();
            if !new_payer {
                elevated.accounts.push(AccountMeta::new(subject, true));
            }
            let payer = if new_payer { subject } else { payer };
            let stale = compiled(&payer, &[elevated.clone(), action.clone()]);
            assert!(screen_transaction(&stale, &solana_confidential_compute_cpi::ID, Some(&consumer)).is_err());
            let fresh = solana_confidential_compute_sdk::hash_compiled_action(&stale.message, 1, 1).unwrap();
            assert_ne!(fresh, original);
            elevated.data[17..49].copy_from_slice(&fresh);
            assert!(screen_transaction(
                &compiled(&payer, &[elevated, action.clone()]),
                &solana_confidential_compute_cpi::ID,
                Some(&consumer)
            )
            .is_ok());
        }
    }

    #[test]
    fn hostile_signature_count_is_rejected_without_panic() {
        let mut bytes = vec![0u8; 16];
        bytes[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        let decoded = std::panic::catch_unwind(|| deserialize_sign_transaction(&bytes));
        let err = decoded.expect("deserializer panicked").unwrap_err();
        assert!(err.contains("signatures"), "{err}");

        let oversized = vec![0u8; MAX_SIGN_BODY + 1];
        let err = deserialize_sign_transaction(&oversized).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }

    #[test]
    fn bounded_deserialize_round_trips_an_allowlisted_transaction() {
        let payer = Pubkey::new_unique();
        let tx = compiled(
            &payer,
            &[verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR.to_vec())],
        );
        let bytes = bincode::serialize(&tx).expect("serialize");
        let decoded = deserialize_sign_transaction(&bytes).expect("decode");
        screen_transaction(&decoded, &solana_confidential_compute_cpi::ID, None).expect("allowlist");
    }

    #[test]
    fn allowlist_accepts_pinned_consumer_and_keeps_transfer_and_governance_closed() {
        let payer = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        let consumer_ix =
            Instruction { program_id: consumer, accounts: vec![AccountMeta::new(payer, true)], data: vec![9, 9, 9] };
        let hash = canonical_action_hash(&payer, &consumer_ix);
        let mut data = solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&95u64.to_le_bytes());
        data.extend_from_slice(&hash);
        data.extend_from_slice(consumer.as_ref());
        data.resize(80 + solana_confidential_compute_core::SNP_REPORT_SIZE, 0);
        let verify = verifier_ix(&payer, data);
        let tx = compiled(&payer, &[verify, consumer_ix]);
        assert!(screen_transaction(&tx, &solana_confidential_compute_cpi::ID, Some(&consumer)).is_ok());

        let missing = screen_transaction(&tx, &solana_confidential_compute_cpi::ID, None).unwrap_err();
        assert!(missing.contains("not allowlisted"), "{missing}");

        let other = Pubkey::new_unique();
        let wrong = screen_transaction(&tx, &solana_confidential_compute_cpi::ID, Some(&other)).unwrap_err();
        assert!(wrong.contains(&consumer.to_string()), "{wrong}");

        let only_consumer = compiled(&payer, &[Instruction { program_id: consumer, accounts: vec![], data: vec![1] }]);
        let err =
            screen_transaction(&only_consumer, &solana_confidential_compute_cpi::ID, Some(&consumer)).unwrap_err();
        assert!(err.contains("does not call the verifier program"), "{err}");

        let governance = compiled(
            &payer,
            &[
                verifier_ix(&payer, vec![90, 53, 0, 89, 164, 70, 107, 186]),
                Instruction { program_id: consumer, accounts: vec![], data: vec![1] },
            ],
        );
        let err = screen_transaction(&governance, &solana_confidential_compute_cpi::ID, Some(&consumer)).unwrap_err();
        assert!(err.contains("verifier instruction is not allowlisted"), "{err}");

        let recipient = Pubkey::new_unique();
        let transfer = system_instruction::transfer(&payer, &recipient, 5_000);
        let mixed = compiled(
            &payer,
            &[
                verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec()),
                Instruction { program_id: consumer, accounts: vec![], data: vec![1] },
                transfer,
            ],
        );
        let err = screen_transaction(&mixed, &solana_confidential_compute_cpi::ID, Some(&consumer)).unwrap_err();
        assert!(err.contains("system transfer"), "{err}");

        let system_as_consumer = compiled(
            &payer,
            &[
                verifier_ix(&payer, solana_confidential_compute_cpi::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.to_vec()),
                system_instruction::transfer(&payer, &recipient, 1),
            ],
        );
        let err =
            screen_transaction(&system_as_consumer, &solana_confidential_compute_cpi::ID, Some(&SYSTEM_PROGRAM_ID))
                .unwrap_err();
        assert!(err.contains("system transfer"), "{err}");
    }
}
