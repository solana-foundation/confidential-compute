//! Solana on-chain attestation client.
//!
//! Live RPC submission is used only when `dry_run` is false. Tests use [`MockCluster`].
//!
//! @spec SCC-SIDECAR-005

use std::sync::{Arc, Mutex};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::v1::TransactionConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    sysvar::{clock, slot_hashes},
    transaction::{Transaction, VersionedTransaction},
};

use crate::{
    attestation::{
        intel_tdx::{synthetic_tdx_evidence, IntelTdxProvider},
        AttestationReport,
    },
    error::SidecarError,
    keys::EphemeralKeyManager,
    tdx_enrolment::{
        decode_challenge_account, dry_run_quote_parts, split_tdx_quote,
        validate_challenge_readback, ChallengeRecord, TdxQuoteParts,
    },
};

pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 216_000;

/// Anchor discriminator `sha256("global:verify_nitro_attestation")[..8]`.
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_ATTESTATION_DISCRIMINATOR: [u8; 8] = [107, 76, 178, 169, 215, 146, 23, 95];
/// Mode A (`verify_and_register_nitro`).
/// @spec SCC-NITRO-008
pub const VERIFY_NITRO_MODE_A: u8 = 0;
/// Anchor discriminator `sha256("global:verify_nvidia_attestation")[..8]`.
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR: [u8; 8] = [31, 2, 40, 104, 69, 155, 234, 120];
/// Mode B (`verify_atomic_nvidia`).
/// @spec SCC-NVIDIA-005
pub const VERIFY_NVIDIA_MODE_B: u8 = 1;
/// Discriminator + mode + nonce slot + action hash + GPU measurement.
pub const VERIFY_NVIDIA_IX_LEN: usize = 8 + 1 + 8 + 32 + 32;

/// Compute unit limit requested for the single-transaction TDX enrolment.
///
/// A v1 transaction carries its compute budget as a message config field, and
/// omitting it means zero, so this is not optional. The number is requested
/// headroom over the measured per-handler bands -- `verify_tdx_qe_report` at
/// 12k-22k CU and `verify_tdx_quote` at 40k-70k, plus the two secp256r1
/// precompile verifications. It is a client limit, not a measurement of this
/// transaction.
/// @spec SCC-TDX-001 SCC-TDX-002
pub const TDX_ENROLMENT_COMPUTE_UNITS: u32 = 300_000;

/// What a completed Intel TDX enrolment leaves behind.
///
/// `attested_signer` is the `AttestedSignerAccount` PDA, which is what a
/// caller needs to build a Solscan link.
#[derive(Debug, Clone, Copy)]
pub struct TdxEnrolmentOutcome {
    /// `["attested_signer_v2", workload]` under the verifier program.
    pub attested_signer: Pubkey,
    pub expires_slot: u64,
    /// The nonce the challenge was issued under. Random, never the slot hash.
    pub challenge_nonce: [u8; 32],
    pub nonce_slot: u64,
    /// Serialized size of the signed v1 enrolment transaction.
    pub enrolment_tx_len: usize,
}

/// Effective limits and trusted time read together from confirmed chain state.
#[derive(Debug, Clone, Copy)]
pub struct SessionDeadlines {
    pub registered_slot: u64,
    pub expires_slot: u64,
    pub expires_unix_timestamp: i64,
    pub current_slot: u64,
    pub current_unix_timestamp: i64,
}
impl SessionDeadlines {
    pub fn is_valid(&self) -> bool {
        self.current_unix_timestamp >= 0
            && self.current_unix_timestamp < self.expires_unix_timestamp
            && self.current_slot <= self.expires_slot
    }
    pub fn needs_renewal(&self, slots: u64, seconds: u64) -> bool {
        !self.is_valid()
            || self.expires_slot.saturating_sub(self.current_slot) <= slots
            || self
                .expires_unix_timestamp
                .saturating_sub(self.current_unix_timestamp)
                <= i64::try_from(seconds).unwrap_or(i64::MAX)
    }
}

enum Cluster {
    Rpc(Arc<RpcClient>),
    Mock(MockCluster),
}

pub struct OnchainAttestor {
    cluster: Cluster,
    verifier_program_id: Pubkey,
    payer: Option<Arc<Keypair>>,
    dry_run: bool,
}

/// In-memory Solana stand-in. It never opens a socket.
#[derive(Clone)]
pub struct MockCluster {
    inner: Arc<Mutex<MockClusterInner>>,
}

struct MockClusterInner {
    slot: u64,
    entries: Vec<(u64, [u8; 32])>,
    blockhash: Hash,
    submitted: Vec<Transaction>,
    submitted_versioned: Vec<VersionedTransaction>,
}

impl MockCluster {
    pub fn new(slot: u64, entries: Vec<(u64, [u8; 32])>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockClusterInner {
                slot,
                entries,
                blockhash: Hash::new_from_array([7u8; 32]),
                submitted: Vec::new(),
                submitted_versioned: Vec::new(),
            })),
        }
    }

    pub fn submitted(&self) -> Vec<Transaction> {
        self.lock().submitted.clone()
    }

    /// Versioned transactions recorded by this cluster. The TDX enrolment is
    /// a v1 transaction and cannot be represented as a legacy `Transaction`.
    pub fn submitted_versioned(&self) -> Vec<VersionedTransaction> {
        self.lock().submitted_versioned.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockClusterInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn slot_hashes_account(&self) -> Vec<u8> {
        let guard = self.lock();
        let mut data = Vec::with_capacity(8 + guard.entries.len() * 40);
        data.extend_from_slice(&(guard.entries.len() as u64).to_le_bytes());
        for (slot, hash) in &guard.entries {
            data.extend_from_slice(&slot.to_le_bytes());
            data.extend_from_slice(hash);
        }
        data
    }

    fn record(&self, tx: Transaction) {
        self.lock().submitted.push(tx);
    }

    fn record_versioned(&self, tx: VersionedTransaction) {
        self.lock().submitted_versioned.push(tx);
    }
}

impl OnchainAttestor {
    pub fn new(
        rpc_url: &str,
        verifier_program_id: Option<Pubkey>,
        payer: Option<Keypair>,
        dry_run: bool,
    ) -> Self {
        let rpc = Arc::new(RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        ));
        Self {
            cluster: Cluster::Rpc(rpc),
            verifier_program_id: verifier_program_id.unwrap_or(solana_confidential_compute_cpi::ID),
            payer: payer.map(Arc::new),
            dry_run,
        }
    }

    /// Test constructor. `dry_run` is forced on so this client cannot submit.
    pub fn mock(
        cluster: MockCluster,
        verifier_program_id: Option<Pubkey>,
        payer: Option<Keypair>,
    ) -> Self {
        Self {
            cluster: Cluster::Mock(cluster),
            verifier_program_id: verifier_program_id.unwrap_or(solana_confidential_compute_cpi::ID),
            payer: payer.map(Arc::new),
            dry_run: true,
        }
    }

    /// Test constructor. `dry_run` is caller-selected so a live refusal can be
    /// observed without opening a socket. Production `mock` stays dry-run.
    #[cfg(test)]
    fn mock_with_dry_run(
        cluster: MockCluster,
        verifier_program_id: Option<Pubkey>,
        payer: Option<Keypair>,
        dry_run: bool,
    ) -> Self {
        Self {
            cluster: Cluster::Mock(cluster),
            verifier_program_id: verifier_program_id.unwrap_or(solana_confidential_compute_cpi::ID),
            payer: payer.map(Arc::new),
            dry_run,
        }
    }

    /// Simulation never establishes a chain-verified signing session.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Program id this attestor submits to. `POST /v1/sign` allowlists the same id.
    pub fn verifier_program_id(&self) -> Pubkey {
        self.verifier_program_id
    }

    pub fn mock_cluster(&self) -> Option<MockCluster> {
        match &self.cluster {
            Cluster::Mock(cluster) => Some(cluster.clone()),
            Cluster::Rpc(_) => None,
        }
    }

    /// Fetches the current cluster slot.
    pub async fn get_current_slot(&self) -> Result<u64, SidecarError> {
        match &self.cluster {
            Cluster::Rpc(rpc) => rpc.get_slot().await.map_err(|e| {
                SidecarError::OnchainError(format!("Failed to get current slot: {e}"))
            }),
            Cluster::Mock(cluster) => Ok(cluster.lock().slot),
        }
    }

    /// Fetches a recent slot and its 32-byte slot hash.
    pub async fn get_recent_slot_challenge(&self) -> Result<(u64, [u8; 32]), SidecarError> {
        let current_slot = self.get_current_slot().await?;
        let target_slot = current_slot.saturating_sub(5);
        let data = self.account_data(&slot_hashes::ID).await?;
        let slot_hash = parse_slot_hash_from_sysvar(&data, target_slot).ok_or_else(|| {
            SidecarError::OnchainError(format!(
                "Slot {target_slot} not found in cluster SlotHashes sysvar"
            ))
        })?;
        Ok((target_slot, slot_hash))
    }

    /// Builds the registration transaction.
    ///
    /// When `dry_run` is set, the signed transaction is recorded and not submitted.
    pub async fn submit_attestation(
        &self,
        workload: &EphemeralKeyManager,
        nonce_slot: u64,
        report: &AttestationReport,
    ) -> Result<u64, SidecarError> {
        let payer = self.payer.as_ref().ok_or_else(|| {
            SidecarError::OnchainError("No transaction payer keypair configured".to_string())
        })?;
        let workload_signer = workload.pubkey();

        let submitted_staged = if !self.dry_run {
            let now = self.get_current_slot().await?;
            let expiry = now
                .checked_add(solana_confidential_compute_sdk::staged::MAX_LIFETIME_SLOTS)
                .ok_or_else(|| SidecarError::OnchainError("staging deadline overflow".into()))?;
            let plan = match report {
                AttestationReport::SevSnp { report, .. } => Some(
                    solana_confidential_compute_sdk::staged::build_staged_snp_registration(
                        self.verifier_program_id,
                        payer.pubkey(),
                        workload_signer,
                        nonce_slot,
                        report,
                        now,
                        expiry,
                    ),
                ),
                AttestationReport::AwsNitro { document } => {
                    // Parse and check workload binding before uploading any bytes.
                    build_verify_nitro_mode_a_ix(
                        &self.verifier_program_id,
                        &payer.pubkey(),
                        &workload_signer,
                        nonce_slot,
                        document,
                    )?;
                    let (_, view) =
                        solana_confidential_compute_crypto::parse_nitro_attestation(document)
                            .map_err(|e| {
                                SidecarError::AttestationError(format!("Nitro parse: {e:?}"))
                            })?;
                    Some(
                        solana_confidential_compute_sdk::staged::build_staged_nitro_registration(
                            self.verifier_program_id,
                            payer.pubkey(),
                            workload_signer,
                            nonce_slot,
                            document,
                            view.nonce,
                            now,
                            expiry,
                        ),
                    )
                }
                // Intel TDX uploads the raw quote through the DCAP verify
                // instruction, not the staged SNP/Nitro registration plans.
                AttestationReport::GcpJwt { .. }
                | AttestationReport::NvidiaH100 { .. }
                | AttestationReport::IntelTdx { .. } => None,
            };
            if let Some(plan) = plan {
                let plan = plan
                    .map_err(|e| SidecarError::OnchainError(format!("staged enrollment: {e}")))?;
                self.submit_stage(workload, &plan).await?;
                true
            } else {
                false
            }
        } else {
            false
        };

        if !submitted_staged {
            let (ix, sign_workload) = match report {
                AttestationReport::SevSnp { report, .. } => {
                    // Hardware live submissions use bounded staging above.
                    // This raw instruction is recorded only for simulation.
                    let ix = solana_confidential_compute_sdk::internal::build_register_signer_ix_for_program_oversized(
                        &self.verifier_program_id,
                        &payer.pubkey(),
                        &workload_signer,
                        report,
                        0,
                        nonce_slot,
                    )
                    .map_err(|e| {
                        SidecarError::OnchainError(format!("Failed to build SEV-SNP ix: {e}"))
                    })?;
                    (ix, true)
                }
                AttestationReport::GcpJwt { jwt } => {
                    let ix = build_verify_google_jwt_mode_a_ix(
                        &self.verifier_program_id,
                        &payer.pubkey(),
                        &workload_signer,
                        nonce_slot,
                        jwt,
                    )?;
                    (ix, true)
                }
                AttestationReport::AwsNitro { document } => {
                    let ix = build_verify_nitro_mode_a_ix(
                        &self.verifier_program_id,
                        &payer.pubkey(),
                        &workload_signer,
                        nonce_slot,
                        document,
                    )?;
                    (ix, true)
                }
                AttestationReport::NvidiaH100 {
                    gpu_measurement,
                    spdm_report,
                    ..
                } => {
                    // The dry-run provider fabricates this prefix. Live mode must
                    // not broadcast that measurement as hardware evidence.
                    if !self.dry_run
                        && crate::attestation::nvidia_h100::synthetic_spdm_evidence(spdm_report)
                    {
                        return Err(SidecarError::GpuAttestationFailed);
                    }
                    let slot_hash_data = self.account_data(&slot_hashes::ID).await?;
                    let slot_hash = parse_slot_hash_from_sysvar(&slot_hash_data, nonce_slot)
                        .ok_or_else(|| {
                            SidecarError::OnchainError(format!(
                                "Slot {nonce_slot} not found in cluster SlotHashes sysvar"
                            ))
                        })?;
                    let ix = build_verify_nvidia_mode_a_ix(
                        &self.verifier_program_id,
                        &payer.pubkey(),
                        &workload_signer,
                        nonce_slot,
                        &slot_hash,
                        gpu_measurement,
                    )?;
                    (ix, true)
                }
                // Intel TDX does not fit this helper's shape: the quote has to
                // answer a challenge that is already on chain, so enrolment is
                // two transactions in sequence rather than one instruction.
                // The report handed in here was collected before any challenge
                // existed, so `enrol_intel_tdx` discards it and asks the
                // collector again once the challenge is readable.
                //
                // No address lookup table is involved. The quote is never
                // uploaded either: the secp256r1 precompile reads its message
                // from instruction data, so both signed regions ride inline
                // and both handlers read them back out of those instructions.
                // Under transaction v1 the whole enrolment is one 4,096-byte
                // packet.
                AttestationReport::IntelTdx { .. } => {
                    let provider = IntelTdxProvider::for_daemon(self.dry_run)?;
                    let outcome = self.enrol_intel_tdx(workload, &provider).await?;
                    tracing::info!(
                        attested_signer = %outcome.attested_signer,
                        nonce_slot = outcome.nonce_slot,
                        enrolment_tx_len = outcome.enrolment_tx_len,
                        dry_run = self.dry_run,
                        "Intel TDX enrolment complete"
                    );
                    return Ok(outcome.expires_slot);
                }
            };

            let recent_blockhash = self.latest_blockhash().await?;
            let mut instructions = Vec::with_capacity(2);
            if matches!(report, AttestationReport::GcpJwt { .. }) {
                // Explicit requested headroom for the complete verifier policy path.
                // This is a client limit, not a measured CU result or feasibility proof.
                instructions.push(ComputeBudgetInstruction::set_compute_unit_limit(400_000));
            }
            instructions.push(ix);
            let mut tx = Transaction::new_with_payer(&instructions, Some(&payer.pubkey()));
            tx.try_partial_sign(&[payer.as_ref()], recent_blockhash)
                .map_err(|e| SidecarError::OnchainError(format!("payer sign failed: {e}")))?;
            if sign_workload {
                workload.partial_sign(&mut tx, recent_blockhash)?;
            }

            if self.dry_run {
                if let Cluster::Mock(cluster) = &self.cluster {
                    cluster.record(tx);
                }
                let current_slot = self.get_current_slot().await?;
                return Ok(current_slot.saturating_add(DEFAULT_ATTESTATION_TTL_SLOTS));
            }

            match &self.cluster {
                Cluster::Rpc(rpc) => {
                    rpc.send_and_confirm_transaction(&tx).await.map_err(|e| {
                        SidecarError::OnchainError(format!(
                            "Attestation tx confirmation failed: {e}"
                        ))
                    })?;
                }
                Cluster::Mock(cluster) => {
                    cluster.record(tx);
                }
            }
        }
        // Single completion path for staged and inline live submissions. Both
        // read the canonical confirmed record rather than estimating from the
        // slot TTL, so the returned deadline is the one the chain will enforce.
        let session = self.confirmed_session(&workload_signer).await?;
        if !session.is_valid() {
            return Err(SidecarError::OnchainError(
                "confirmed enrollment is expired".into(),
            ));
        }
        Ok(session.expires_slot)
    }

    /// Submit ordered packets with fresh blockhashes. Once begin succeeds, always
    /// attempt rent cleanup; a failed cleanup after consume is reported distinctly
    /// so callers do not mistake enrollment failure for permission to reuse a nonce.
    async fn submit_stage(
        &self,
        workload: &EphemeralKeyManager,
        plan: &solana_confidential_compute_sdk::staged::StagePlan,
    ) -> Result<(), SidecarError> {
        if let Err(error) = self
            .submit_packet(workload, std::slice::from_ref(&plan.begin))
            .await
        {
            let cleanup = self
                .submit_packet(workload, std::slice::from_ref(&plan.close))
                .await;
            return Err(SidecarError::OnchainError(format!(
                "stage begin failed: {error}; cleanup: {cleanup:?}"
            )));
        }
        let result = async {
            for upload in &plan.uploads {
                self.submit_packet(workload, std::slice::from_ref(upload))
                    .await?;
            }
            self.submit_packet(workload, std::slice::from_ref(&plan.seal))
                .await?;
            self.submit_packet(
                workload,
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                    plan.consume.clone(),
                ],
            )
            .await
        }
        .await;
        let cleanup = self
            .submit_packet(workload, std::slice::from_ref(&plan.close))
            .await;
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), cleanup) => Err(SidecarError::OnchainError(format!(
                "staged enrollment failed: {error}; stage {}; cleanup: {cleanup:?}",
                plan.address
            ))),
            (Ok(()), Err(error)) => Err(SidecarError::OnchainError(format!(
                "enrollment confirmed (nonce consumed), but stage {} cleanup failed: {error}",
                plan.address
            ))),
        }
    }

    async fn submit_packet(
        &self,
        workload: &EphemeralKeyManager,
        instructions: &[Instruction],
    ) -> Result<(), SidecarError> {
        let payer = self
            .payer
            .as_ref()
            .ok_or_else(|| SidecarError::OnchainError("missing payer".into()))?;
        let blockhash = self.latest_blockhash().await?;
        let mut tx = Transaction::new_with_payer(instructions, Some(&payer.pubkey()));
        tx.try_partial_sign(&[payer.as_ref()], blockhash)
            .map_err(|e| SidecarError::OnchainError(format!("payer sign failed: {e}")))?;
        if tx.message.account_keys[..tx.message.header.num_required_signatures as usize]
            .contains(&workload.pubkey())
        {
            workload.partial_sign(&mut tx, blockhash)?;
        }
        let size = bincode::serialized_size(&tx)
            .map_err(|e| SidecarError::OnchainError(format!("packet serialization: {e}")))?;
        if size > solana_confidential_compute_sdk::PACKET_DATA_SIZE as u64 {
            return Err(SidecarError::OnchainError(format!(
                "packet exceeds limit: {size}"
            )));
        }
        match &self.cluster {
            Cluster::Rpc(rpc) => {
                rpc.send_and_confirm_transaction(&tx).await.map_err(|e| {
                    SidecarError::OnchainError(format!("staged packet confirmation failed: {e}"))
                })?;
            }
            Cluster::Mock(cluster) => cluster.record(tx),
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Intel TDX enrolment
    // -----------------------------------------------------------------

    /// Fresh 32 bytes from the OS CSPRNG.
    ///
    /// The nonce alone selects the challenge PDA, so it has to be unique
    /// across everyone issuing challenges, not merely unpredictable. Deriving
    /// it from the slot hash -- the convention the generic provider interface
    /// is stuck with -- makes two workloads that pick the same recent slot
    /// collide on one PDA, and `issue_tdx_challenge` refuses to reissue over a
    /// live or consumed record.
    /// @spec SCC-TDX-005
    fn new_challenge_nonce() -> [u8; 32] {
        use rand_core::{OsRng, RngCore};
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Send `issue_tdx_challenge` as its own transaction.
    ///
    /// This cannot be merged into the enrolment transaction. The enclave has
    /// to read back the slot hash the program recorded before it can produce a
    /// quote that answers the challenge, and it cannot read an account the
    /// same transaction is still writing.
    ///
    /// Returns the serialized size, so a dry run still proves the packet fits.
    /// @spec SCC-TDX-005
    async fn send_issue_tdx_challenge(
        &self,
        payer: &Keypair,
        nonce: &[u8; 32],
        nonce_slot: u64,
    ) -> Result<usize, SidecarError> {
        let ix = solana_confidential_compute_sdk::tdx::build_issue_tdx_challenge_ix_for_program(
            &self.verifier_program_id,
            &payer.pubkey(),
            nonce,
            nonce_slot,
        );
        let blockhash = self.latest_blockhash().await?;
        let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
        tx.try_sign(&[payer], blockhash)
            .map_err(|e| SidecarError::OnchainError(format!("challenge payer sign failed: {e}")))?;
        let size = bincode::serialized_size(&tx)
            .map_err(|e| SidecarError::OnchainError(format!("challenge serialization: {e}")))?
            as usize;
        if size > solana_confidential_compute_sdk::PACKET_DATA_SIZE {
            return Err(SidecarError::OnchainError(format!(
                "challenge transaction is {size} bytes, over the {}-byte packet",
                solana_confidential_compute_sdk::PACKET_DATA_SIZE
            )));
        }

        if self.dry_run {
            if let Cluster::Mock(cluster) = &self.cluster {
                cluster.record(tx);
            }
            return Ok(size);
        }
        match &self.cluster {
            Cluster::Rpc(rpc) => {
                rpc.send_and_confirm_transaction(&tx).await.map_err(|e| {
                    SidecarError::OnchainError(format!("issue_tdx_challenge failed: {e}"))
                })?;
            }
            Cluster::Mock(cluster) => cluster.record(tx),
        }
        Ok(size)
    }

    /// Read the `ChallengeAccount` the program wrote.
    /// @spec SCC-TDX-005
    async fn read_tdx_challenge(&self, nonce: &[u8; 32]) -> Result<ChallengeRecord, SidecarError> {
        let (challenge, _) = solana_confidential_compute_sdk::tdx::derive_tdx_challenge_pda(
            &self.verifier_program_id,
            nonce,
        );
        let data = self.account_data(&challenge).await?;
        decode_challenge_account(&data)
    }

    /// Enrol an Intel TDX workload signer.
    ///
    /// Five steps, in order:
    ///
    /// 1. `issue_tdx_challenge`, its own transaction.
    /// 2. Read the `ChallengeAccount` back and check it is the one issued.
    /// 3. Ask `provider` for a quote bound to that challenge's recorded slot
    ///    hash and nonce.
    /// 4. Build and send the enrolment as one transaction v1 packet --
    ///    `secp256r1(QE report)`, `verify_tdx_qe_report`,
    ///    `secp256r1(quote body)`, `verify_tdx_quote`.
    /// 5. Read the confirmed `AttestedSignerAccount` back and return it.
    ///
    /// When `dry_run` is set, nothing is broadcast: both transactions are
    /// built, signed and size-checked, and the challenge read-back is skipped
    /// because there is no record to read.
    ///
    /// @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 SCC-SIDECAR-004
    pub async fn enrol_intel_tdx(
        &self,
        workload: &EphemeralKeyManager,
        provider: &IntelTdxProvider,
    ) -> Result<TdxEnrolmentOutcome, SidecarError> {
        let payer = self.payer.as_ref().ok_or_else(|| {
            SidecarError::OnchainError("No transaction payer keypair configured".to_string())
        })?;
        // Fail closed before a single byte is broadcast: a provider that
        // fabricates its evidence may not run against a live cluster.
        provider.reject_simulated_live(self.dry_run)?;

        let workload_signer = workload.pubkey();
        let (nonce_slot, sysvar_slot_hash) = self.get_recent_slot_challenge().await?;
        let challenge_nonce = Self::new_challenge_nonce();

        // 1. The challenge, on its own.
        self.send_issue_tdx_challenge(payer, &challenge_nonce, nonce_slot)
            .await?;

        // 2. Read back what the program recorded.
        let challenge = if self.dry_run {
            // Nothing was broadcast, so there is nothing to read. The slot
            // hash is the one the sysvar reported, which is what the program
            // would have recorded for this slot.
            ChallengeRecord {
                source: solana_confidential_compute_sdk::tdx::TDX_SOURCE,
                challenge_slot: nonce_slot,
                slot_hash: sysvar_slot_hash,
                nonce: challenge_nonce,
                expires_slot: u64::MAX,
                bump: 0,
            }
        } else {
            let record = self.read_tdx_challenge(&challenge_nonce).await?;
            validate_challenge_readback(
                &record,
                solana_confidential_compute_sdk::tdx::TDX_SOURCE,
                &challenge_nonce,
                nonce_slot,
                &sysvar_slot_hash,
            )?;
            record
        };

        // 3. A quote that answers this challenge, and only this challenge.
        let report = provider
            .request_attestation_for_challenge(
                &workload_signer,
                &challenge.slot_hash,
                &challenge.nonce,
            )
            .await?;
        let AttestationReport::IntelTdx {
            quote, report_data, ..
        } = &report
        else {
            return Err(SidecarError::OnchainError(
                "Intel TDX provider returned a report of another kind".to_string(),
            ));
        };
        let simulated = synthetic_tdx_evidence(quote);
        if simulated && !self.dry_run {
            // Belt and braces over `reject_simulated_live`: that checks how
            // the provider was configured, this checks what it produced.
            return Err(SidecarError::TdxAttestationFailed);
        }
        let parts: TdxQuoteParts = if simulated {
            dry_run_quote_parts(report_data)
        } else {
            split_tdx_quote(quote)?
        };
        let (gpu_rim_digest, model_digest) = provider.binding_digests()?;

        // 4. One v1 transaction for both halves.
        let blockhash = self.latest_blockhash().await?;
        let enrolment = solana_confidential_compute_sdk::tdx::TdxEnrolment {
            payer: payer.pubkey(),
            workload_signer,
            attestation_pubkey_xy: &parts.attestation_pubkey_xy,
            pck_pubkey: &parts.pck_pubkey,
            gpu_rim_digest: &gpu_rim_digest,
            model_digest: &model_digest,
            qe_auth_data: &parts.qe_auth_data,
            qe_report: &parts.qe_report,
            qe_report_signature: &parts.qe_report_signature,
            isv_signed: &parts.isv_signed,
            isv_signature: &parts.isv_signature,
            slot_hash: &challenge.slot_hash,
            challenge_nonce: &challenge.nonce,
            nonce_slot,
        };
        let mut tx = solana_confidential_compute_sdk::tdx::build_tdx_enrolment_tx_for_program(
            &self.verifier_program_id,
            &enrolment,
            blockhash,
            TransactionConfig::default().with_compute_unit_limit(TDX_ENROLMENT_COMPUTE_UNITS),
        )
        .map_err(|e| SidecarError::OnchainError(format!("TDX enrolment build failed: {e}")))?;

        sign_versioned_with_payer(&mut tx, payer)?;
        workload.sign_transaction(&mut tx)?;
        let enrolment_tx_len = versioned_v1_size(&tx)?;

        let attested_signer = solana_confidential_compute_sdk::tdx::derive_attested_signer_pda(
            &self.verifier_program_id,
            &workload_signer,
        )
        .0;

        if self.dry_run {
            if let Cluster::Mock(cluster) = &self.cluster {
                cluster.record_versioned(tx);
            }
            let current_slot = self.get_current_slot().await?;
            return Ok(TdxEnrolmentOutcome {
                attested_signer,
                expires_slot: current_slot.saturating_add(DEFAULT_ATTESTATION_TTL_SLOTS),
                challenge_nonce,
                nonce_slot,
                enrolment_tx_len,
            });
        }

        match &self.cluster {
            Cluster::Rpc(rpc) => {
                rpc.send_and_confirm_transaction(&tx).await.map_err(|e| {
                    SidecarError::OnchainError(format!("TDX enrolment confirmation failed: {e}"))
                })?;
            }
            Cluster::Mock(cluster) => cluster.record_versioned(tx),
        }

        // 5. The confirmed record is the answer, not the TTL estimate.
        let session = self.confirmed_session(&workload_signer).await?;
        if !session.is_valid() {
            return Err(SidecarError::OnchainError(
                "confirmed TDX enrollment is expired".into(),
            ));
        }
        Ok(TdxEnrolmentOutcome {
            attested_signer,
            expires_slot: session.expires_slot,
            challenge_nonce,
            nonce_slot,
            enrolment_tx_len,
        })
    }

    /// Re-read the canonical confirmed V2 record and trusted cluster Clock
    /// together before releasing a local signature. Cached slot TTL is insufficient.
    pub async fn validate_registered_session(&self, workload: &Pubkey) -> Result<(), SidecarError> {
        if self.confirmed_session(workload).await?.is_valid() {
            Ok(())
        } else {
            Err(SidecarError::OnchainError(
                "confirmed V2 session or Clock is invalid or expired".into(),
            ))
        }
    }

    pub async fn confirmed_session(
        &self,
        workload: &Pubkey,
    ) -> Result<SessionDeadlines, SidecarError> {
        let Cluster::Rpc(rpc) = &self.cluster else {
            return Err(SidecarError::OnchainError(
                "simulated sessions cannot authorize signing".into(),
            ));
        };
        let address = Pubkey::find_program_address(
            &[
                solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
                workload.as_ref(),
            ],
            &self.verifier_program_id,
        )
        .0;
        let accounts = rpc
            .get_multiple_accounts(&[address, clock::ID])
            .await
            .map_err(|e| {
                SidecarError::OnchainError(format!(
                    "failed to load confirmed session and Clock: {e}"
                ))
            })?;
        let Some(Some(record)) = accounts.first() else {
            return Err(SidecarError::OnchainError(
                "confirmed V2 session missing".into(),
            ));
        };
        let Some(Some(clock_account)) = accounts.get(1) else {
            return Err(SidecarError::OnchainError("trusted Clock missing".into()));
        };
        read_session_accounts(&self.verifier_program_id, workload, record, clock_account)
    }

    /// Identity behind the confirmed session, validated by exactly the same
    /// rules as `confirmed_session`. The signing screen needs the attested
    /// record itself (own pubkey, platform, measurement), not just deadlines,
    /// so it can refuse a Mode B attestation that belongs to another key.
    pub async fn registered_session_identity(
        &self,
        workload: &Pubkey,
    ) -> Result<solana_confidential_compute_cpi::AttestedSignerAccount, SidecarError> {
        let Cluster::Rpc(rpc) = &self.cluster else {
            return Err(SidecarError::OnchainError(
                "simulated sessions cannot authorize signing".into(),
            ));
        };
        let address = Pubkey::find_program_address(
            &[
                solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
                workload.as_ref(),
            ],
            &self.verifier_program_id,
        )
        .0;
        let accounts = rpc
            .get_multiple_accounts(&[address, clock::ID])
            .await
            .map_err(|e| {
                SidecarError::OnchainError(format!(
                    "failed to load confirmed session and Clock: {e}"
                ))
            })?;
        let Some(Some(record)) = accounts.first() else {
            return Err(SidecarError::OnchainError(
                "confirmed V2 session missing".into(),
            ));
        };
        let Some(Some(clock_account)) = accounts.get(1) else {
            return Err(SidecarError::OnchainError("trusted Clock missing".into()));
        };
        // Validate first, then decode, so identity and deadline paths can never
        // drift apart. `read_session_accounts` only reports the deadlines; the
        // expiry decision is `is_valid()`, exactly as `validate_registered_session`
        // does. Omitting it would let an expired session authorize signing.
        let invalid = || {
            SidecarError::OnchainError("confirmed V2 session or Clock is invalid or expired".into())
        };
        if !read_session_accounts(&self.verifier_program_id, workload, record, clock_account)?
            .is_valid()
        {
            return Err(invalid());
        }
        solana_confidential_compute_cpi::AttestedSignerAccount::try_from_slice(&record.data)
            .map_err(|_| invalid())
    }

    async fn account_data(&self, key: &Pubkey) -> Result<Vec<u8>, SidecarError> {
        match &self.cluster {
            Cluster::Rpc(rpc) => rpc.get_account_data(key).await.map_err(|e| {
                SidecarError::OnchainError(format!("Failed to read account {key}: {e}"))
            }),
            Cluster::Mock(cluster) => {
                if key != &slot_hashes::ID {
                    return Err(SidecarError::OnchainError(
                        "mock cluster does not serve that account".to_string(),
                    ));
                }
                Ok(cluster.slot_hashes_account())
            }
        }
    }

    async fn latest_blockhash(&self) -> Result<Hash, SidecarError> {
        match &self.cluster {
            Cluster::Rpc(rpc) => rpc.get_latest_blockhash().await.map_err(|e| {
                SidecarError::OnchainError(format!("Failed to get latest blockhash: {e}"))
            }),
            Cluster::Mock(cluster) => Ok(cluster.lock().blockhash),
        }
    }
}

#[cfg(test)]
fn validate_session_accounts(
    program_id: &Pubkey,
    workload: &Pubkey,
    record: &solana_sdk::account::Account,
    clock_account: &solana_sdk::account::Account,
) -> Result<(), SidecarError> {
    let session = read_session_accounts(program_id, workload, record, clock_account)?;
    if session.is_valid() {
        Ok(())
    } else {
        Err(SidecarError::OnchainError("expired".into()))
    }
}

fn read_session_accounts(
    program_id: &Pubkey,
    workload: &Pubkey,
    record: &solana_sdk::account::Account,
    clock_account: &solana_sdk::account::Account,
) -> Result<SessionDeadlines, SidecarError> {
    let invalid =
        || SidecarError::OnchainError("confirmed V2 session or Clock is invalid or expired".into());
    if record.owner != *program_id || clock_account.owner != solana_sdk::sysvar::ID {
        return Err(invalid());
    }
    let state =
        solana_confidential_compute_cpi::AttestedSignerAccount::try_from_slice(&record.data)
            .map_err(|_| invalid())?;
    let clock: solana_sdk::clock::Clock =
        bincode::deserialize(&clock_account.data).map_err(|_| invalid())?;
    let bump = Pubkey::find_program_address(
        &[
            solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
            workload.as_ref(),
        ],
        program_id,
    )
    .1;
    if state.signer_pubkey != workload.to_bytes()
        || state.bump != bump
        || !accepted_enclave_type(state.enclave_type)
    {
        return Err(invalid());
    }
    Ok(SessionDeadlines {
        registered_slot: u64::from_le_bytes(state.registered_slot),
        expires_slot: state.expires_slot(),
        expires_unix_timestamp: state.expires_unix_timestamp(),
        current_slot: clock.slot,
        current_unix_timestamp: clock.unix_timestamp,
    })
}

/// SEV-SNP, Nitro, Confidential Space, NVIDIA GPU, and Intel TDX.
/// Mock (`255`) stays rejected.
///
/// Intel TDX belongs here because `verify_tdx_quote` writes
/// `EnclaveType::IntelTdx` onto the record it creates. Without it a completed
/// enrolment would read back as an unacceptable session and the sidecar would
/// refuse to sign with the key it had just enrolled.
fn accepted_enclave_type(enclave_type: u8) -> bool {
    use solana_confidential_compute_core::types::EnclaveType;
    enclave_type == EnclaveType::AmdSevSnp as u8
        || enclave_type == EnclaveType::AwsNitro as u8
        || enclave_type == EnclaveType::GcpConfidentialSpace as u8
        || enclave_type == EnclaveType::NvidiaGpu as u8
        || enclave_type == EnclaveType::IntelTdx as u8
}

/// Put the payer's signature in its slot on a versioned transaction.
///
/// `Transaction::try_partial_sign` has no `VersionedTransaction` counterpart,
/// and the workload path (`EphemeralKeyManager::sign_transaction`) deliberately
/// refuses to sign as account zero, so the payer needs its own helper.
fn sign_versioned_with_payer(
    tx: &mut VersionedTransaction,
    payer: &Keypair,
) -> Result<(), SidecarError> {
    let required = tx.message.header().num_required_signatures as usize;
    let index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| key == &payer.pubkey())
        .ok_or_else(|| {
            SidecarError::OnchainError("payer is not an account of the transaction".to_string())
        })?;
    if index >= required {
        return Err(SidecarError::OnchainError(format!(
            "payer is at index {index} but only {required} signatures are required"
        )));
    }
    if tx.signatures.len() < required {
        tx.signatures.resize(required, Signature::default());
    }
    tx.signatures[index] = payer.sign_message(&tx.message.serialize());
    Ok(())
}

/// Serialized size of a signed v1 transaction.
///
/// V1 writes signatures as a fixed-length array sized by the header, with no
/// length prefix, and prefixes the message with one version byte, so the
/// `bincode` shape legacy transactions use does not apply.
fn versioned_v1_size(tx: &VersionedTransaction) -> Result<usize, SidecarError> {
    match &tx.message {
        solana_sdk::message::VersionedMessage::V1(message) => {
            let len = solana_confidential_compute_sdk::tdx::v1_transaction_size(message);
            if len > solana_confidential_compute_sdk::tdx::V1_MAX_TRANSACTION_SIZE {
                return Err(SidecarError::OnchainError(format!(
                    "TDX enrolment transaction is {len} bytes, over the {}-byte v1 limit",
                    solana_confidential_compute_sdk::tdx::V1_MAX_TRANSACTION_SIZE
                )));
            }
            Ok(len)
        }
        solana_sdk::message::VersionedMessage::V0(_) => Err(SidecarError::OnchainError(
            "TDX enrolment must be a v1 transaction, got v0".to_string(),
        )),
        solana_sdk::message::VersionedMessage::Legacy(_) => Err(SidecarError::OnchainError(
            "TDX enrolment must be a v1 transaction, got legacy".to_string(),
        )),
    }
}

/// Parses the SlotHashes sysvar buffer to find the entry matching `target_slot`.
pub fn parse_slot_hash_from_sysvar(data: &[u8], target_slot: u64) -> Option<[u8; 32]> {
    if data.len() < 8 {
        return None;
    }
    let count = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
    let mut offset = 8;
    for _ in 0..count {
        if offset + 40 > data.len() {
            break;
        }
        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        if slot == target_slot {
            return data[offset + 8..offset + 40].try_into().ok();
        }
        offset += 40;
    }
    None
}

/// Builds the VerifyGoogleJwt Mode A instruction.
fn build_verify_google_jwt_mode_a_ix(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    nonce_slot: u64,
    jwt: &str,
) -> Result<Instruction, SidecarError> {
    let view = solana_confidential_compute_crypto::jwt::JwtView::parse(jwt).map_err(|e| {
        SidecarError::AttestationError(format!(
            "Failed to parse JWT for instruction building: {e:?}"
        ))
    })?;
    let kid_padded = solana_confidential_compute_crypto::jwt::parse_header_kid_b64(view.header_b64)
        .map_err(|e| {
            SidecarError::AttestationError(format!("Failed to parse header kid: {e:?}"))
        })?;
    let kid_len = kid_padded.iter().take_while(|b| **b != 0).count();
    if kid_len == 0 {
        return Err(SidecarError::AttestationError(
            "JWT header is missing kid".to_string(),
        ));
    }
    let kh = solana_confidential_compute_crypto::jwt::kid_hash(&kid_padded[..kid_len]);

    let claims = solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64)
        .map_err(|e| SidecarError::AttestationError(format!("Failed to parse claims: {e:?}")))?;
    let raw = claims.decode_mode_a_binding().map_err(|_| {
        SidecarError::AttestationError("JWT eat_nonce is not the Mode A base64url pair".to_string())
    })?;
    if raw[..32] != workload_signer.to_bytes() {
        return Err(SidecarError::AttestationError(
            "JWT eat_nonce does not bind the workload pubkey".to_string(),
        ));
    }
    // SHA256 exactly once over the decoded 64-byte binding, matching the verifier.

    let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
    let (jwks_pda, _) = Pubkey::find_program_address(
        &[solana_confidential_compute_crypto::jwt::JWKS_SEED, &kh],
        program_id,
    );
    let (signer_pda, _) = Pubkey::find_program_address(
        &[
            solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
            workload_signer.as_ref(),
        ],
        program_id,
    );
    let (nonce_pda, _) =
        solana_confidential_compute_sdk::derive_google_used_nonce_pda(program_id, &raw)
            .expect("decoded Google ModeA binding");
    let legacy =
        solana_confidential_compute_sdk::derive_legacy_google_used_nonce_pda(program_id, &raw)
            .expect("decoded Google ModeA binding")
            .0;

    let mut accounts = vec![
        AccountMeta::new(signer_pda, false),
        AccountMeta::new_readonly(registry_pda, false),
        AccountMeta::new_readonly(jwks_pda, false),
        AccountMeta::new(nonce_pda, false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        AccountMeta::new_readonly(clock::ID, false),
        AccountMeta::new_readonly(slot_hashes::ID, false),
        AccountMeta::new_readonly(*workload_signer, true),
        AccountMeta::new_readonly(
            Pubkey::find_program_address(&[b"gcp_tenant_policy"], program_id).0,
            false,
        ),
    ];

    accounts.push(AccountMeta::new_readonly(
        solana_confidential_compute_sdk::derive_backend_policy_pda(program_id, 3)
            .expect("fixed GCP backend")
            .0,
        false,
    ));
    accounts.push(AccountMeta::new_readonly(legacy, false));
    let mut data = solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR.to_vec();
    data.push(0);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(&[0u8; 32]);
    let jwt_len = u32::try_from(jwt.len()).map_err(|_| {
        SidecarError::AttestationError("JWT is too long for the instruction".to_string())
    })?;
    data.extend_from_slice(&jwt_len.to_le_bytes());
    data.extend_from_slice(jwt.as_bytes());

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Builds the VerifyNitroAttestation Mode A instruction.
///
/// Wire: `disc (8) + mode (1) + nonce_slot (8) + action_hash (32) + doc_len (4) + document`.
/// @spec SCC-NITRO-007 SCC-NITRO-008
fn build_verify_nitro_mode_a_ix(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    nonce_slot: u64,
    document: &[u8],
) -> Result<Instruction, SidecarError> {
    if document.is_empty()
        || document.len() > solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN
    {
        return Err(SidecarError::AttestationError(format!(
            "Nitro document length {} is outside 1..={}",
            document.len(),
            solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN
        )));
    }
    let (_cose, view) = solana_confidential_compute_crypto::parse_nitro_attestation(document)
        .map_err(|e| {
            SidecarError::AttestationError(format!("Failed to parse Nitro document: {e:?}"))
        })?;
    if view.user_data != workload_signer.to_bytes() {
        return Err(SidecarError::AttestationError(
            "Nitro document user_data does not bind the workload pubkey".to_string(),
        ));
    }

    let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
    let (signer_pda, _) = Pubkey::find_program_address(
        &[
            solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
            workload_signer.as_ref(),
        ],
        program_id,
    );
    let (nonce_pda, _) = solana_confidential_compute_sdk::derive_used_nonce_pda_for_source(
        program_id,
        2,
        &workload_signer.to_bytes(),
        &view.nonce,
    )
    .expect("fixed Nitro source");
    let legacy = solana_confidential_compute_sdk::derive_legacy_used_nonce_pda(
        program_id,
        &workload_signer.to_bytes(),
        &view.nonce,
    )
    .0;

    let mut accounts = vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(registry_pda, false),
        AccountMeta::new(signer_pda, false),
        AccountMeta::new(nonce_pda, false),
        AccountMeta::new_readonly(slot_hashes::ID, false),
        AccountMeta::new_readonly(clock::ID, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        AccountMeta::new_readonly(*workload_signer, true),
    ];

    accounts.push(AccountMeta::new_readonly(
        solana_confidential_compute_sdk::derive_backend_policy_pda(program_id, 2)
            .expect("fixed Nitro backend")
            .0,
        false,
    ));
    accounts.push(AccountMeta::new_readonly(legacy, false));
    let mut data = Vec::with_capacity(8 + 1 + 8 + 32 + 4 + document.len());
    data.extend_from_slice(&VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
    data.push(VERIFY_NITRO_MODE_A);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(&[0u8; 32]);
    let doc_len = u32::try_from(document.len()).map_err(|_| {
        SidecarError::AttestationError("Nitro document is too long for the instruction".to_string())
    })?;
    data.extend_from_slice(&doc_len.to_le_bytes());
    data.extend_from_slice(document);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

fn build_verify_nvidia_mode_a_ix(
    program_id: &Pubkey,
    payer: &Pubkey,
    workload_signer: &Pubkey,
    nonce_slot: u64,
    slot_hash: &[u8; 32],
    gpu_measurement: &[u8; 32],
) -> Result<Instruction, SidecarError> {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
    let (signer_pda, _) = Pubkey::find_program_address(
        &[b"attested_signer_v2", workload_signer.as_ref()],
        program_id,
    );
    let (backend_policy_pda, _) =
        Pubkey::find_program_address(&[b"backend_policy", &[4]], program_id);
    // @spec SCC-NVIDIA-002 SCC-NVIDIA-004
    let nonce_seed =
        solana_sdk::hash::hashv(&[workload_signer.as_ref(), gpu_measurement, slot_hash]).to_bytes();
    let (nonce_pda, _) = Pubkey::find_program_address(&[b"nonce", &[4], &nonce_seed], program_id);

    let mut data = Vec::with_capacity(VERIFY_NVIDIA_IX_LEN);
    data.extend_from_slice(&VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR);
    data.push(0);
    data.extend_from_slice(&nonce_slot.to_le_bytes());
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(gpu_measurement);

    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(signer_pda, false),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(nonce_pda, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
            AccountMeta::new_readonly(*workload_signer, true),
            AccountMeta::new_readonly(backend_policy_pda, false),
        ],
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::gcp_oidc::mode_a_eat_nonces;
    use base64::Engine;

    #[test]
    fn slot_hash_parser_returns_exact_sysvar_bytes_and_rejects_incomplete_entries() {
        let older = Keypair::new().pubkey().to_bytes();
        let newer = Keypair::new().pubkey().to_bytes();
        let mut data = 2u64.to_le_bytes().to_vec();
        for (slot, hash) in [(91u64, older), (95u64, newer)] {
            data.extend_from_slice(&slot.to_le_bytes());
            data.extend_from_slice(&hash);
        }
        assert_eq!(parse_slot_hash_from_sysvar(&data, 91), Some(older));
        assert_eq!(parse_slot_hash_from_sysvar(&data, 95), Some(newer));
        assert_eq!(parse_slot_hash_from_sysvar(&data, 94), None);
        assert_eq!(parse_slot_hash_from_sysvar(&data[..7], 95), None);
        data.pop();
        assert_eq!(parse_slot_hash_from_sysvar(&data, 95), None);
        assert_eq!(parse_slot_hash_from_sysvar(&data, 91), Some(older));
    }

    #[test]
    fn nvidia_mode_a_nonce_binds_signer_measurement_and_slot_hash() {
        let program_id = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let workload = Pubkey::new_unique();
        let slot_hash = [0x5au8; 32];
        let gpu_measurement = [0x11u8; 32];
        let ix = build_verify_nvidia_mode_a_ix(
            &program_id,
            &payer,
            &workload,
            105,
            &slot_hash,
            &gpu_measurement,
        )
        .expect("ix");
        assert_eq!(ix.data[..8], VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR);
        assert_eq!(ix.data[8], 0);
        assert_eq!(&ix.data[9..17], &105u64.to_le_bytes());
        assert_eq!(&ix.data[49..81], &gpu_measurement);
        let seed =
            solana_sdk::hash::hashv(&[workload.as_ref(), &gpu_measurement, &slot_hash]).to_bytes();
        let (nonce_pda, _) = Pubkey::find_program_address(&[b"nonce", &[4], &seed], &program_id);
        assert_eq!(ix.accounts[2].pubkey, nonce_pda);
        let zero_seed =
            solana_sdk::hash::hashv(&[workload.as_ref(), &gpu_measurement, &[0u8; 32]]).to_bytes();
        let (zero_pda, _) =
            Pubkey::find_program_address(&[b"nonce", &[4], &zero_seed], &program_id);
        assert_ne!(nonce_pda, zero_pda);
    }

    #[test]
    fn mode_a_tombstone_hashes_the_raw_binding() {
        let program_id = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let workload = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x11u8; 32];
        let (n0, n1) = mode_a_eat_nonces(&workload, &slot_hash);
        let payload = format!(
            r#"{{"aud":"solana-confidential-compute-verifier","dbgstat":"disabled-since-boot","eat_nonce":["{n0}","{n1}"],"exp":4102444800,"iat":1700000000,"iss":"https://confidentialcomputing.googleapis.com","secboot":true,"sub":"s","submods":{{"container":{{"image_digest":"sha256:abababababababababababababababababababababababababababababababab"}}}}}}"#
        );
        let header = r#"{"alg":"RS256","kid":"solana-cc-test","typ":"JWT"}"#;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwt = format!(
            "{}.{}.{}",
            engine.encode(header.as_bytes()),
            engine.encode(payload.as_bytes()),
            engine.encode([0u8; 8])
        );
        let ix = build_verify_google_jwt_mode_a_ix(&program_id, &payer, &workload, 95, &jwt)
            .expect("ix");
        // Canonical verifier dispatch and complete Mode A wire contract.
        assert_eq!(
            &ix.data[..8],
            &solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR
        );
        assert_eq!(&ix.data[..8], &[104, 38, 12, 199, 131, 240, 78, 165]);
        assert_eq!(ix.data[8], 0);
        assert_eq!(&ix.data[9..17], &95u64.to_le_bytes());
        assert_eq!(&ix.data[17..49], &[0u8; 32]);
        assert_eq!(&ix.data[49..53], &(jwt.len() as u32).to_le_bytes());
        assert_eq!(&ix.data[53..], jwt.as_bytes());
        assert_eq!(ix.accounts.len(), 12);
        assert_eq!(ix.accounts[5].pubkey, solana_sdk_ids::system_program::ID);
        assert_eq!(ix.accounts[6].pubkey, clock::ID);
        assert_eq!(ix.accounts[7].pubkey, slot_hashes::ID);
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(workload.as_ref());
        raw[32..].copy_from_slice(&slot_hash);
        let seed = solana_confidential_compute_crypto::jwt::eat_nonce_tombstone_seed(&raw);
        let (nonce_pda, _) = Pubkey::find_program_address(&[b"nonce", &[3], &seed], &program_id);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(
                    Pubkey::find_program_address(
                        &[b"attested_signer_v2", workload.as_ref()],
                        &program_id
                    )
                    .0,
                    false
                ),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(&[b"policy_registry"], &program_id).0,
                    false
                ),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(
                        &[
                            b"jwks",
                            &solana_confidential_compute_crypto::jwt::kid_hash(b"solana-cc-test")
                        ],
                        &program_id
                    )
                    .0,
                    false
                ),
                AccountMeta::new(nonce_pda, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                AccountMeta::new_readonly(clock::ID, false),
                AccountMeta::new_readonly(slot_hashes::ID, false),
                AccountMeta::new_readonly(workload, true),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(&[b"gcp_tenant_policy"], &program_id).0,
                    false
                ),
                AccountMeta::new_readonly(
                    solana_confidential_compute_sdk::derive_backend_policy_pda(&program_id, 3)
                        .unwrap()
                        .0,
                    false
                ),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(&[b"nonce", &seed], &program_id).0,
                    false
                ),
            ]
        );
        assert_eq!(ix.accounts[3].pubkey, nonce_pda);
        assert_eq!(
            ix.accounts.last(),
            Some(&AccountMeta::new_readonly(
                Pubkey::find_program_address(&[b"nonce", &seed], &program_id).0,
                false
            ))
        );
        assert_eq!(ix.accounts[4].pubkey, payer);
        assert!(ix.accounts[4].is_signer);
        assert_eq!(ix.accounts[8].pubkey, workload);
        assert!(ix.accounts[8].is_signer);
        assert!(!ix.accounts[8].is_writable);
        assert_eq!(ix.accounts.len(), 12);
        assert_eq!(
            ix.accounts[9].pubkey,
            Pubkey::find_program_address(&[b"gcp_tenant_policy"], &program_id).0
        );
        assert!(!ix.accounts[9].is_writable && !ix.accounts[9].is_signer);
        assert_eq!(
            ix.accounts.get(ix.accounts.len() - 2),
            Some(&AccountMeta::new_readonly(
                solana_confidential_compute_sdk::derive_backend_policy_pda(&program_id, 3)
                    .unwrap()
                    .0,
                false
            ))
        );
    }

    #[test]
    fn nitro_mode_a_instruction_layout_and_pdas() {
        let program_id = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let workload = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x11u8; 32];
        let document =
            crate::attestation::nitro::synthetic_cose_sign1(&workload.to_bytes(), &slot_hash);
        let nonce_slot = 95u64;
        let ix =
            build_verify_nitro_mode_a_ix(&program_id, &payer, &workload, nonce_slot, &document)
                .expect("ix");

        assert_eq!(ix.program_id, program_id);
        assert_eq!(&ix.data[0..8], &VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
        assert_eq!(ix.data[8], VERIFY_NITRO_MODE_A);
        assert_eq!(&ix.data[9..17], &nonce_slot.to_le_bytes());
        assert_eq!(&ix.data[17..49], &[0u8; 32]);
        let doc_len = u32::from_le_bytes(ix.data[49..53].try_into().expect("len"));
        assert_eq!(doc_len as usize, document.len());
        assert_eq!(&ix.data[53..], document.as_slice());
        assert_eq!(ix.data.len(), 53 + document.len());

        assert_eq!(ix.accounts.len(), 10);
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);
        let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &program_id);
        assert_eq!(ix.accounts[1].pubkey, registry_pda);
        assert!(!ix.accounts[1].is_writable);
        let (signer_pda, _) = Pubkey::find_program_address(
            &[
                solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
                workload.as_ref(),
            ],
            &program_id,
        );
        assert_eq!(ix.accounts[2].pubkey, signer_pda);
        assert!(ix.accounts[2].is_writable);
        let (nonce_pda, _) = Pubkey::find_program_address(
            &[b"nonce", &[2], workload.as_ref(), &slot_hash],
            &program_id,
        );
        assert_eq!(ix.accounts[3].pubkey, nonce_pda);
        assert!(ix.accounts[3].is_writable);
        assert_eq!(
            ix.accounts.last(),
            Some(&AccountMeta::new_readonly(
                Pubkey::find_program_address(
                    &[b"nonce", workload.as_ref(), &slot_hash],
                    &program_id
                )
                .0,
                false
            ))
        );
        assert_eq!(ix.accounts[4].pubkey, slot_hashes::ID);
        assert_eq!(ix.accounts[5].pubkey, clock::ID);
        assert_eq!(ix.accounts[6].pubkey, solana_sdk_ids::system_program::ID);
        assert_eq!(ix.accounts[7], AccountMeta::new_readonly(workload, true));
        assert_eq!(
            ix.accounts.get(ix.accounts.len() - 2),
            Some(&AccountMeta::new_readonly(
                solana_confidential_compute_sdk::derive_backend_policy_pda(&program_id, 2)
                    .unwrap()
                    .0,
                false
            ))
        );
    }

    #[tokio::test]
    async fn submit_attestation_records_nitro_mode_a_tx() {
        let keys = crate::keys::EphemeralKeyManager::new();
        let slot_hash = [0x11u8; 32];
        let document =
            crate::attestation::nitro::synthetic_cose_sign1(&keys.pubkey().to_bytes(), &slot_hash);
        let payer = Keypair::new();
        let cluster = MockCluster::new(100, vec![(95, slot_hash)]);
        let onchain = OnchainAttestor::mock(cluster, None, Some(payer));
        let expires = onchain
            .submit_attestation(&keys, 95, &AttestationReport::AwsNitro { document })
            .await
            .expect("submit");
        assert_eq!(expires, 100 + DEFAULT_ATTESTATION_TTL_SLOTS);
        let submitted = onchain.mock_cluster().expect("mock").submitted();
        assert_eq!(submitted.len(), 1);
        assert!(submitted[0].verify().is_ok());
        assert_eq!(
            submitted[0].message.instructions[0].data[0..8],
            VERIFY_NITRO_ATTESTATION_DISCRIMINATOR
        );
        assert_eq!(
            submitted[0].message.instructions[0].data[8],
            VERIFY_NITRO_MODE_A
        );
    }
    #[tokio::test]
    async fn gcp_submission_requests_explicit_budget_before_verifier() {
        let program_id = Pubkey::new_unique();
        let workload = EphemeralKeyManager::new();
        let cluster = MockCluster::new(100, vec![(95, [0x11; 32])]);
        let attestor =
            OnchainAttestor::mock(cluster.clone(), Some(program_id), Some(Keypair::new()));
        let (n0, n1) = mode_a_eat_nonces(&workload.pubkey(), &[0x11; 32]);
        let payload = format!(
            r#"{{"aud":"a","sub":"s","iss":"https://confidentialcomputing.googleapis.com","exp":4102444800,"iat":1700000000,"secboot":true,"dbgstat":"disabled-since-boot","eat_nonce":["{n0}","{n1}"],"image_digest":"sha256:abababababababababababababababababababababababababababababababab"}}"#
        );
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwt = format!(
            "{}.{}.{}",
            engine.encode(br#"{"alg":"RS256","kid":"test"}"#),
            engine.encode(payload),
            engine.encode([0; 256])
        );
        attestor
            .submit_attestation(
                &workload,
                95,
                &AttestationReport::GcpJwt { jwt: jwt.clone() },
            )
            .await
            .unwrap();
        let tx = cluster.submitted().pop().unwrap();
        assert!(tx.verify().is_ok());
        assert_eq!(tx.message.instructions.len(), 2);
        let budget = &tx.message.instructions[0];
        let expected = ComputeBudgetInstruction::set_compute_unit_limit(400_000);
        assert_eq!(
            tx.message.account_keys[budget.program_id_index as usize],
            expected.program_id
        );
        assert_eq!(budget.data, expected.data);
        assert!(budget.accounts.is_empty());
        let verifier = &tx.message.instructions[1];
        let raw = build_verify_google_jwt_mode_a_ix(
            &program_id,
            &tx.message.account_keys[0],
            &workload.pubkey(),
            95,
            &jwt,
        )
        .unwrap();
        assert_eq!(
            tx.message.account_keys[verifier.program_id_index as usize],
            program_id
        );
        assert_eq!(
            &verifier.data[..8],
            &solana_confidential_compute_cpi::VERIFY_GOOGLE_JWT_DISCRIMINATOR
        );
        assert_eq!(verifier.data, raw.data);
        assert_eq!(verifier.accounts.len(), raw.accounts.len());
        for (index, meta) in verifier.accounts.iter().zip(raw.accounts.iter()) {
            assert_eq!(tx.message.account_keys[*index as usize], meta.pubkey);
        }
    }
    #[tokio::test]
    async fn snp_dry_run_collects_both_payer_and_workload_signatures() {
        let workload = EphemeralKeyManager::new();
        let payer = Keypair::new();
        let cluster = MockCluster::new(100, vec![(95, [7; 32])]);
        let onchain = OnchainAttestor::mock(cluster.clone(), None, Some(payer));
        let mut report = [0u8; 1184];
        // This signature-collection fixture models VCEK, not zero-chip VLEK.
        report[0x1a0..0x1e0].fill(9);
        report[0x50..0x70].copy_from_slice(workload.pubkey().as_ref());
        report[0x70..0x90].copy_from_slice(&[7; 32]);
        onchain
            .submit_attestation(
                &workload,
                95,
                &AttestationReport::SevSnp {
                    report: report.to_vec(),
                    vcek_cert: None,
                },
            )
            .await
            .unwrap();
        let txs = cluster.submitted();
        assert_eq!(txs[0].message.header.num_required_signatures, 2);
        assert!(txs[0].verify().is_ok());
    }
    #[test]
    fn confirmed_v2_record_requires_both_deadlines_and_authentic_identity() {
        use solana_sdk::{account::Account, clock::Clock};
        let program = Pubkey::new_unique();
        let workload = Pubkey::new_unique();
        let mut data = vec![0; 154];
        data[..8].copy_from_slice(&solana_confidential_compute_cpi::ATTESTED_SIGNER_DISCRIMINATOR);
        data[8..40].copy_from_slice(workload.as_ref());
        data[40] = 1;
        data[137..145].copy_from_slice(&200u64.to_le_bytes());
        data[145] = Pubkey::find_program_address(
            &[
                solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
                workload.as_ref(),
            ],
            &program,
        )
        .1;
        data[146..154].copy_from_slice(&500i64.to_le_bytes());
        let record = Account {
            owner: program,
            data,
            ..Account::default()
        };
        let clock = Clock {
            slot: 150,
            unix_timestamp: 499,
            ..Clock::default()
        };
        let clock_account = Account {
            owner: solana_sdk::sysvar::ID,
            data: bincode::serialize(&clock).unwrap(),
            ..Account::default()
        };
        assert!(validate_session_accounts(&program, &workload, &record, &clock_account).is_ok());
        let mut nvidia = record.clone();
        nvidia.data[40] = solana_confidential_compute_core::types::EnclaveType::NvidiaGpu as u8;
        assert!(validate_session_accounts(&program, &workload, &nvidia, &clock_account).is_ok());
        let mut mock_type = record.clone();
        mock_type.data[40] = solana_confidential_compute_core::types::EnclaveType::Mock as u8;
        assert!(
            validate_session_accounts(&program, &workload, &mock_type, &clock_account).is_err()
        );
        for (slot, unix) in [(201, 499), (150, 500), (150, -1)] {
            let bad = Account {
                data: bincode::serialize(&Clock {
                    slot,
                    unix_timestamp: unix,
                    ..clock
                })
                .unwrap(),
                ..clock_account.clone()
            };
            assert!(validate_session_accounts(&program, &workload, &record, &bad).is_err());
        }
        let mut bad = record.clone();
        bad.owner = Pubkey::new_unique();
        assert!(validate_session_accounts(&program, &workload, &bad, &clock_account).is_err());
        let mut bad = clock_account.clone();
        bad.owner = program;
        assert!(validate_session_accounts(&program, &workload, &record, &bad).is_err());
        for offset in [0, 8, 145] {
            let mut bad = record.clone();
            bad.data[offset] ^= 1;
            assert!(validate_session_accounts(&program, &workload, &bad, &clock_account).is_err());
        }
        let mut legacy = record.clone();
        legacy.data.truncate(146);
        assert!(validate_session_accounts(&program, &workload, &legacy, &clock_account).is_err());
    }

    #[tokio::test]
    async fn synthetic_nvidia_evidence_is_not_broadcast_when_live() {
        use crate::attestation::nvidia_h100::NvidiaH100Provider;
        use crate::attestation::AttestationProvider;

        let program_id = Pubkey::new_unique();
        let cluster = MockCluster::new(100, vec![(95, [0x5a; 32])]);
        let attestor = OnchainAttestor::mock_with_dry_run(
            cluster.clone(),
            Some(program_id),
            Some(Keypair::new()),
            false,
        );
        let workload = EphemeralKeyManager::new();
        let report = NvidiaH100Provider::new(None, true)
            .request_attestation(&workload.pubkey(), &[0x5a; 32])
            .await
            .expect("dry-run provider");
        let err = attestor
            .submit_attestation(&workload, 95, &report)
            .await
            .expect_err("synthetic evidence must not be submitted live");
        assert!(matches!(err, SidecarError::GpuAttestationFailed));
        assert!(cluster.submitted().is_empty());

        let dry = OnchainAttestor::mock(cluster.clone(), Some(program_id), Some(Keypair::new()));
        dry.submit_attestation(&workload, 95, &report)
            .await
            .expect("dry-run records the synthetic registration");
        assert_eq!(cluster.submitted().len(), 1);
    }
}
