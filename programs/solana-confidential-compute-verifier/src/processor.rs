//! Instruction processor for Solana Confidential Compute Verifier.
//! Routes via standard 8-byte Anchor instruction discriminators.

use crate::payload::{SetBackendPolicyArgs, SET_BACKEND_POLICY_DISCRIMINATOR};
#[path = "transport.rs"]
pub mod transport;

use crate::payload::{RevokeAttestedSignerArgs, REVOKE_ATTESTED_SIGNER_DISCRIMINATOR};
use crate::payload::{RevokeVcekArgs, REVOKE_VCEK_DISCRIMINATOR};
use crate::payload::{SetGcpTenantPolicyArgs, SET_GCP_TENANT_POLICY_DISCRIMINATOR};
use crate::payload::{CLOSE_ATTESTED_SIGNER_DISCRIMINATOR, CLOSE_STALE_NONCE_DISCRIMINATOR};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha384};
use solana_confidential_compute_core::{
    error::ConfidentialComputeError,
    nitro::MAX_NITRO_DOCUMENT_LEN,
    report::SnpReportView,
    types::{compute_action_commitment, AttestedSigner, EnclaveType, MeasurementDigest, VerifyAtomicHeader},
    NitroAttestationView, SignatureVerifier, SNP_REPORT_SIZE,
};
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    hash::{hashv, Hash},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::{
        clock,
        instructions::{self, load_current_index_checked, load_instruction_at_checked},
        slot_hashes, Sysvar,
    },
};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use solana_system_interface::instruction as system_instruction;
#[allow(deprecated)]
use solana_sysvar::SysvarSerialize;

#[cfg(feature = "mock-crypto")]
use solana_confidential_compute_core::MockVerifier;

use crate::error::VerifierError;
use crate::payload::{
    nvidia_attestation_statement, nvidia_nonce_seed, nvidia_proof_points_well_formed, nvidia_public_inputs_canonical,
    nvidia_public_inputs_from_statement, nvidia_verifier_message, parse_nvidia_proof_packet, NvidiaStatement,
    NVIDIA_ATTESTATION_SOURCE,
};
use crate::payload::{
    InitPolicyRegistryArgs, RegisterJwksKeyArgs, RegisterVcekArgs, RevokeJwksKeyArgs, RotateRootCertArgs,
    UpdatePolicyArgs, INIT_POLICY_REGISTRY_DISCRIMINATOR, MAX_VCEK_CERT_LEN, REGISTER_JWKS_KEY_DISCRIMINATOR,
    REGISTER_VCEK_DISCRIMINATOR, REGISTER_VCEK_HEADER_SIZE, REVOKE_JWKS_KEY_DISCRIMINATOR,
    ROTATE_ROOT_CERT_DISCRIMINATOR, UPDATE_POLICY_DISCRIMINATOR, VERIFY_AND_REGISTER_DISCRIMINATOR,
    VERIFY_ATOMIC_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR, VERIFY_GOOGLE_JWT_DISCRIMINATOR,
    VERIFY_GOOGLE_JWT_MODE_A, VERIFY_GOOGLE_JWT_MODE_B, VERIFY_NITRO_ATTESTATION_DISCRIMINATOR, VERIFY_NITRO_MODE_A,
    VERIFY_NITRO_MODE_B, VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR, VERIFY_NVIDIA_LEGACY_LEN, VERIFY_NVIDIA_MODE_A,
    VERIFY_NVIDIA_MODE_B, VERIFY_NVIDIA_PROOF_PACKET_LEN,
};
use crate::state::{
    AmdIdentityRevocation, AttestedSignerAccount, JwksAccount, PolicyRegistry, PolicyRegistryView, UsedNonceAccount,
    VcekAccount, VcekAccountView, ATTESTED_SIGNER_DISCRIMINATOR, JWKS_ACCOUNT_DISCRIMINATOR,
    POLICY_REGISTRY_DISCRIMINATOR, USED_NONCE_DISCRIMINATOR, VCEK_ACCOUNT_DISCRIMINATOR,
};

/// Independent slot cap; elapsed wall time is bounded separately.
const ATTESTATION_TTL_SLOTS: u64 = 216_000;
const ATTESTATION_TTL_SECONDS: i64 = 86_400;

/// Software P-384 backend. Prehashed equivalent of
/// `solana_confidential_compute_crypto::verify_snp_report_signature`.
/// @spec SCC-ARCH-003
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectCryptoVerifier;

impl SignatureVerifier for DirectCryptoVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError> {
        let _ = instructions_sysvar;
        // Software P-384 exceeds the 550,000 CU ceiling on SBF.
        // @spec SCC-PERF-001
        #[cfg(target_os = "solana")]
        {
            let _ = (public_key_xy, message_digest, signature_rs);
            return Err(VerifierError::InvalidSignature.into());
        }
        #[cfg(not(target_os = "solana"))]
        {
            match solana_confidential_compute_crypto::verify_p384_signature(public_key_xy, message_digest, signature_rs)
            {
                Ok(true) => Ok(()),
                Ok(false) | Err(_) => Err(VerifierError::InvalidSignature.into()),
            }
        }
    }
}

/// Production SBF backend. Introspects a preceding sigverify instruction.
/// Software P-384 is not the entrypoint on `target_os = "solana"`.
/// @spec SCC-PERF-001 SCC-VERIFY-016 SCC-ARCH-003
#[cfg(all(not(feature = "mock-crypto"), target_os = "solana"))]
#[derive(Debug, Clone, Copy)]
pub struct SolanaDefaultVerifier {
    inner: crate::introspection::InstructionIntrospectionVerifier,
}

/// Pinned sigverify program for [`SolanaDefaultVerifier`].
/// No mainnet secp384r1 precompile id is assigned. Introspection fails closed
/// until that program is deployed.
/// @spec SCC-VERIFY-016 SCC-PERF-001
#[cfg(all(not(feature = "mock-crypto"), target_os = "solana"))]
pub const EXPECTED_SIGVERIFY_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x53, 0x45, 0x43, 0x50, 0x33, 0x38, 0x34, 0x52, 0x31, 0x53, 0x49, 0x47, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

#[cfg(all(not(feature = "mock-crypto"), target_os = "solana"))]
impl Default for SolanaDefaultVerifier {
    fn default() -> Self {
        Self { inner: crate::introspection::InstructionIntrospectionVerifier::new(EXPECTED_SIGVERIFY_PROGRAM_ID) }
    }
}

#[cfg(all(not(feature = "mock-crypto"), target_os = "solana"))]
impl SignatureVerifier for SolanaDefaultVerifier {
    fn verify_p384(
        &self,
        public_key_xy: &[u8; 96],
        message_digest: &[u8; 48],
        signature_rs: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(), ProgramError> {
        self.inner.verify_p384(public_key_xy, message_digest, signature_rs, instructions_sysvar)
    }
}

/// Default backend selected at compile time.
/// @spec SCC-ARCH-003
#[cfg(feature = "mock-crypto")]
pub type DefaultVerifier = MockVerifier;
#[cfg(all(not(feature = "mock-crypto"), not(target_os = "solana")))]
pub type DefaultVerifier = DirectCryptoVerifier;
#[cfg(all(not(feature = "mock-crypto"), target_os = "solana"))]
pub type DefaultVerifier = SolanaDefaultVerifier;

/// Anchor discriminator: sha256("global:rotate_authority")[..8].
/// Empty payload; accounts [current authority signer, registry writable,
/// receiving authority signer]. Both signatures provide atomic acceptance;
/// signer PDAs controlled by governance programs are supported.
pub const ROTATE_AUTHORITY_DISCRIMINATOR: [u8; 8] = [248, 225, 151, 35, 28, 15, 85, 12];

pub struct Processor;

impl Processor {
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
        Self::process_with(&DefaultVerifier::default(), program_id, accounts, instruction_data)
    }

    /// Dispatch with an explicit `SignatureVerifier` backend.
    /// @spec SCC-ARCH-003
    pub fn process_with<V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if instruction_data.len() < 8 {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let (discriminator, rest) = instruction_data.split_at(8);

        if transport::is_transport(discriminator) {
            return Self::process_transport(verifier, program_id, accounts, discriminator, rest);
        }

        match discriminator {
            d if d == SET_GCP_TENANT_POLICY_DISCRIMINATOR => {
                Self::process_set_gcp_tenant_policy(program_id, accounts, rest)
            }
            d if d == SET_BACKEND_POLICY_DISCRIMINATOR => Self::process_set_backend_policy(program_id, accounts, rest),
            d if d == REVOKE_VCEK_DISCRIMINATOR => Self::process_revoke_vcek(program_id, accounts, rest),

            d if d == REVOKE_ATTESTED_SIGNER_DISCRIMINATOR => {
                Self::process_revoke_attested_signer(program_id, accounts, rest)
            }

            d if d == CLOSE_STALE_NONCE_DISCRIMINATOR => Self::process_close_stale_nonce(program_id, accounts, rest),
            d if d == CLOSE_ATTESTED_SIGNER_DISCRIMINATOR => {
                Self::process_close_attested_signer(program_id, accounts, rest)
            }

            d if d == INIT_POLICY_REGISTRY_DISCRIMINATOR => {
                Self::process_init_policy_registry(program_id, accounts, rest)
            }
            d if d == UPDATE_POLICY_DISCRIMINATOR => Self::process_update_policy(program_id, accounts, rest),
            d if d == ROTATE_AUTHORITY_DISCRIMINATOR => Self::process_rotate_authority(program_id, accounts, rest),
            d if d == ROTATE_ROOT_CERT_DISCRIMINATOR => Self::process_rotate_root_cert(program_id, accounts, rest),
            d if d == REGISTER_VCEK_DISCRIMINATOR => Self::process_register_vcek(program_id, accounts, rest),
            d if d == VERIFY_AND_REGISTER_DISCRIMINATOR => {
                Self::process_verify_and_register(verifier, program_id, accounts, rest)
            }
            d if d == VERIFY_ATOMIC_DISCRIMINATOR => Self::process_verify_atomic(verifier, program_id, accounts, rest),
            d if d == VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR => {
                Self::process_verify_atomic_with_nonce(verifier, program_id, accounts, rest)
            }
            d if d == REGISTER_JWKS_KEY_DISCRIMINATOR => Self::process_register_jwks_key(program_id, accounts, rest),
            d if d == REVOKE_JWKS_KEY_DISCRIMINATOR => Self::process_revoke_jwks_key(program_id, accounts, rest),
            d if d == VERIFY_GOOGLE_JWT_DISCRIMINATOR => Self::process_verify_google_jwt(program_id, accounts, rest),
            d if d == VERIFY_NITRO_ATTESTATION_DISCRIMINATOR => {
                Self::process_verify_nitro_attestation(verifier, program_id, accounts, rest)
            }
            d if d == crate::payload::ISSUE_TDX_CHALLENGE_DISCRIMINATOR => {
                Self::process_issue_tdx_challenge(program_id, accounts, rest)
            }
            d if d == crate::payload::VERIFY_TDX_QE_REPORT_DISCRIMINATOR => {
                Self::process_verify_tdx_qe_report(program_id, accounts, rest)
            }
            d if d == crate::payload::VERIFY_TDX_QUOTE_DISCRIMINATOR => {
                Self::process_verify_tdx_quote(program_id, accounts, rest)
            }
            d if d == VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR => {
                Self::process_verify_nvidia_attestation(verifier, program_id, accounts, rest)
            }
            _ => Err(VerifierError::InvalidDiscriminator.into()),
        }
    }

    /// Allocates a program PDA via System Program CPI when unallocated.
    /// Pre-allocated accounts of the exact size skip CPI (unit-test mocks).
    /// A pre-funded zero-data account is allocated and assigned in place.
    /// `create_account` rejects that account with `AccountAlreadyInUse`.
    /// @spec SCC-ARCH-001
    fn create_pda_if_needed<'a>(
        payer: &AccountInfo<'a>,
        pda: &AccountInfo<'a>,
        system_program_acc: Option<&AccountInfo<'a>>,
        program_id: &Pubkey,
        signer_seeds: &[&[u8]],
        space: usize,
    ) -> ProgramResult {
        if !pda.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }

        let data_len = pda.data_len();
        if data_len == space {
            if pda.owner != program_id {
                return Err(ProgramError::IllegalOwner);
            }
            return Ok(());
        }
        if data_len != 0 {
            return Err(ProgramError::InvalidAccountData);
        }

        if !payer.is_signer || !payer.is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let system_program_acc = system_program_acc.ok_or(ProgramError::NotEnoughAccountKeys)?;
        if system_program_acc.key != &system_program::ID {
            return Err(ProgramError::IncorrectProgramId);
        }

        let lamports = Rent::get().map_err(|_| VerifierError::InvalidAccountAddress)?.minimum_balance(space);
        // @spec SCC-ARCH-001
        if pda.lamports() > 0 {
            let deficit = lamports.saturating_sub(pda.lamports());
            if deficit > 0 {
                invoke(
                    &system_instruction::transfer(payer.key, pda.key, deficit),
                    &[payer.clone(), pda.clone(), system_program_acc.clone()],
                )?;
            }
            invoke_signed(
                &system_instruction::allocate(pda.key, space as u64),
                &[pda.clone(), system_program_acc.clone()],
                &[signer_seeds],
            )?;
            invoke_signed(
                &system_instruction::assign(pda.key, program_id),
                &[pda.clone(), system_program_acc.clone()],
                &[signer_seeds],
            )?;
            return Ok(());
        }
        invoke_signed(
            &system_instruction::create_account(payer.key, pda.key, lamports, space as u64, program_id),
            &[payer.clone(), pda.clone(), system_program_acc.clone()],
            &[signer_seeds],
        )
    }

    fn account_has_discriminator(account: &AccountInfo, discriminator: &[u8; 8]) -> Result<bool, ProgramError> {
        let data = account.try_borrow_data()?;
        Ok(data.len() >= 8 && data[0..8] == discriminator[..])
    }

    fn assert_expected_pda(account: &AccountInfo, expected: &Pubkey) -> ProgramResult {
        if account.key != expected {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        Ok(())
    }

    /// Validates the canonical address and its client-provided or stored bump.
    /// @spec SCC-ARCH-001
    fn assert_pda(account: &AccountInfo, seeds: &[&[u8]], program_id: &Pubkey) -> ProgramResult {
        let (stored_bump, address_seeds) = seeds.split_last().ok_or(VerifierError::InvalidAccountAddress)?;
        let (expected, canonical_bump) =
            Pubkey::try_find_program_address(address_seeds, program_id).ok_or(VerifierError::InvalidAccountAddress)?;
        if *stored_bump != [canonical_bump] {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        Self::assert_expected_pda(account, &expected)
    }

    /// Mode A registers or renews a key only with that workload's consent.
    /// Clients may append the readonly signer without moving existing accounts;
    /// a workload that is also the signed payer needs no duplicate account.
    fn assert_workload_consent(accounts: &[AccountInfo], signer_pubkey: &[u8; 32]) -> ProgramResult {
        let workload = accounts
            .iter()
            .find(|account| account.key.as_ref() == signer_pubkey)
            .ok_or(VerifierError::SignerMismatch)?;
        if !workload.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        Ok(())
    }

    fn map_crypto_error(err: solana_confidential_compute_crypto::CryptoError) -> ProgramError {
        match err {
            solana_confidential_compute_crypto::CryptoError::PolicyViolation => {
                VerifierError::UnauthorizedPolicy.into()
            }
            solana_confidential_compute_crypto::CryptoError::InvalidJwtSignature
            | solana_confidential_compute_crypto::CryptoError::InvalidPadding
            | solana_confidential_compute_crypto::CryptoError::InvalidSignature
            | solana_confidential_compute_crypto::CryptoError::InvalidP384Signature => {
                VerifierError::InvalidSignature.into()
            }
            solana_confidential_compute_crypto::CryptoError::MalformedJwt
            | solana_confidential_compute_crypto::CryptoError::DuplicateJwtClaim
            | solana_confidential_compute_crypto::CryptoError::UnsupportedJwtAlgorithm
            | solana_confidential_compute_crypto::CryptoError::MalformedCbor
            | solana_confidential_compute_crypto::CryptoError::InvalidCoseStructure
            | solana_confidential_compute_crypto::CryptoError::InvalidAttestationPayload => {
                VerifierError::InvalidInstruction.into()
            }
            solana_confidential_compute_crypto::CryptoError::CertificateChainInvalid
            | solana_confidential_compute_crypto::CryptoError::VcekExtensionMissing => {
                VerifierError::VerificationFailed.into()
            }
            _ => VerifierError::VerificationFailed.into(),
        }
    }

    fn map_confidential_compute_error(err: ConfidentialComputeError) -> VerifierError {
        match err {
            ConfidentialComputeError::DebugModeProhibited | ConfidentialComputeError::UnauthorizedPolicy => {
                VerifierError::UnauthorizedPolicy
            }
            ConfidentialComputeError::InvalidMeasurement => VerifierError::DisallowedMeasurement,
            ConfidentialComputeError::InvalidSignature
            | ConfidentialComputeError::InvalidSignaturePadding
            | ConfidentialComputeError::InvalidSignatureAlgorithm => VerifierError::InvalidSignature,
            ConfidentialComputeError::ReportSizeInvalid => VerifierError::InvalidInstruction,
            _ => VerifierError::VerificationFailed,
        }
    }

    fn optional_instructions_sysvar<'a, 'b>(accounts: &'a [AccountInfo<'b>]) -> Option<&'a AccountInfo<'b>> {
        accounts.iter().find(|account| account.key == &instructions::ID)
    }

    fn verify_snp_signature<V: SignatureVerifier>(
        verifier: &V,
        view: &SnpReportView,
        public_key_xy: &[u8; 96],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> ProgramResult {
        let r_be = view.signature_r_be().map_err(|_| VerifierError::InvalidSignature)?;
        let s_be = view.signature_s_be().map_err(|_| VerifierError::InvalidSignature)?;
        let mut sig_rs = [0u8; 96];
        sig_rs[..48].copy_from_slice(&r_be);
        sig_rs[48..].copy_from_slice(&s_be);

        let mut hasher = Sha384::new();
        hasher.update(view.signed_body());
        let digest: [u8; 48] = hasher.finalize().into();

        verifier.verify_p384(public_key_xy, &digest, &sig_rs, instructions_sysvar)
    }

    /// Shared Stage 2 kernel: parse report, enforce policy, verify VCEK, allowlist, TCB.
    /// @spec SCC-SEC-001 SCC-VERIFY-002 SCC-VERIFY-003 SCC-VERIFY-007 SCC-ARCH-002 SCC-ARCH-003
    #[allow(clippy::too_many_arguments)]
    fn verify_report_and_policy<'a, V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        registry_acc: &AccountInfo,
        vcek_acc: &AccountInfo,
        accounts: &[AccountInfo],
        report_bytes: &'a [u8],
        instructions_sysvar: Option<&AccountInfo>,
        clock: &Clock,
    ) -> Result<(SnpReportView<'a>, [u8; 32]), ProgramError> {
        let view = SnpReportView::try_from_slice(report_bytes).map_err(Self::map_confidential_compute_error)?;
        view.validate_security_invariants().map_err(Self::map_confidential_compute_error)?;

        let (public_key_xy, chip_id_hash) = {
            if vcek_acc.owner != program_id {
                return Err(ProgramError::IllegalOwner);
            }
            let vcek_data = vcek_acc.try_borrow_data()?;
            let vcek = VcekAccountView::try_from_slice(&vcek_data)?;
            if !vcek.is_trusted_at_unix(clock.unix_timestamp) {
                return Err(VerifierError::UnauthorizedPolicy.into());
            }
            let public_key_xy = *vcek.public_key_xy();
            let vcek_bump_seed = [vcek.bump()];
            // Zero chip id or SIGNING_KEY == 1 derives the VLEK seed from the
            // endorsement public key. @spec SCC-VERIFY-009
            let chip_id_hash: [u8; 32] =
                if view.is_vlek() { hashv(&[&public_key_xy]).to_bytes() } else { hashv(&[view.chip_id()]).to_bytes() };
            let tcb_bytes = view.reported_tcb().to_le_bytes();
            Self::assert_pda(vcek_acc, &[b"vcek_v2", &chip_id_hash, &tcb_bytes, &vcek_bump_seed], program_id)?;
            (public_key_xy, chip_id_hash)
        };

        Self::assert_amd_identity_allowed(program_id, accounts, &chip_id_hash)?;
        Self::verify_snp_signature(verifier, &view, &public_key_xy, instructions_sysvar)?;

        let registry_data = registry_acc.try_borrow_data()?;
        let registry = PolicyRegistryView::try_from_slice(&registry_data)?;
        let registry_bump_seed = [registry.bump()];
        Self::assert_pda(registry_acc, &[b"policy_registry", &registry_bump_seed], program_id)?;
        let measurement = view.measurement();
        Self::assert_backend_measurement(program_id, accounts, 1, &measurement)?;
        let tcb_reported = view.reported_tcb_components();
        if tcb_reported[0] < registry.min_tcb_boot_loader()
            || tcb_reported[1] < registry.min_tcb_tee()
            || tcb_reported[6] < registry.min_tcb_snp()
            || tcb_reported[7] < registry.min_tcb_microcode()
        {
            return Err(VerifierError::TcbBelowMinimum.into());
        }

        Ok((view, chip_id_hash))
    }

    /// Initializes the singleton PolicyRegistry PDA (@spec SCC-VERIFY-005).
    fn process_init_policy_registry(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = InitPolicyRegistryArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;

        // Legacy global measurements are retained for ABI compatibility and ignored
        // by AMD/Nitro/GCP admission. Clear each relevant BackendPolicy to stop new
        // admission. Counts must fit the fixed legacy measurement array.
        if args.measurement_count as usize > args.measurements.len() {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let [authority_acc, registry_acc, rest_accs @ ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        if !authority_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if authority_acc.key.to_bytes() != args.authority || args.authority == [0u8; 32] {
            return Err(VerifierError::InvalidAuthority.into());
        }

        // Initialization seats every trust root. Require the canonical loader-owned
        // ProgramData and authenticate its current upgrade authority before any write.
        // Initialize before finalization: an immutable program has no such authority.
        // Accounts: [authority, registry, system_program, program_data].
        // @spec SCC-VERIFY-005 SCC-SEC-004
        let program_data_acc = rest_accs.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
        let loader = bpf_loader_upgradeable::id();
        let (expected_program_data, _) = Pubkey::find_program_address(&[program_id.as_ref()], &loader);
        if program_data_acc.key != &expected_program_data || program_data_acc.owner != &loader {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        {
            let data = program_data_acc.try_borrow_data()?;
            // UpgradeableLoaderState::ProgramData: u32 variant, u64 slot,
            // Option<Pubkey>. Program bytes may follow the 45-byte metadata.
            if data.len() < 45 || data[0..4] != [3, 0, 0, 0] || data[12] != 1 {
                return Err(VerifierError::InvalidAuthority.into());
            }
            if authority_acc.key.as_ref() != &data[13..45] {
                return Err(VerifierError::InvalidAuthority.into());
            }
        }

        let (expected_pda, bump) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
        Self::assert_expected_pda(registry_acc, &expected_pda)?;

        // Re-initialization guard: discriminator match means the registry exists.
        // @spec SCC-VERIFY-005
        if Self::account_has_discriminator(registry_acc, &POLICY_REGISTRY_DISCRIMINATOR)? {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        let bump_seed = [bump];
        Self::create_pda_if_needed(
            authority_acc,
            registry_acc,
            rest_accs.first(),
            program_id,
            &[b"policy_registry", &bump_seed],
            PolicyRegistry::SIZE,
        )?;

        let registry = PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: args.authority,
            ark_pubkey_xy: args.ark_pubkey_xy,
            min_tcb_boot_loader: args.min_tcb_boot_loader,
            min_tcb_tee: args.min_tcb_tee,
            min_tcb_snp: args.min_tcb_snp,
            min_tcb_microcode: args.min_tcb_microcode,
            measurement_count: args.measurement_count,
            measurements: args.measurements,
            bump,
        };

        Self::write_governance_data(b"init_policy_registry", authority_acc, registry_acc, &registry)
    }

    /// Updates minimum TCB floors and ABI-compatible legacy global measurements.
    /// AMD/Nitro/GCP admission uses BackendPolicy; clear each relevant backend policy
    /// to stop new admission (@spec SCC-VERIFY-005).
    fn process_update_policy(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = UpdatePolicyArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;

        // Legacy global measurements are retained for ABI compatibility and ignored
        // by AMD/Nitro/GCP admission. Clear each relevant BackendPolicy to stop new
        // admission. Counts must fit the fixed legacy measurement array.
        if args.measurement_count as usize > args.measurements.len() {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let authority_acc = accounts.first().ok_or(VerifierError::InvalidAccountAddress)?;
        let registry_acc = accounts.get(1).ok_or(VerifierError::InvalidAccountAddress)?;

        if !authority_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let (expected_pda, bump) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
        Self::assert_expected_pda(registry_acc, &expected_pda)?;
        // A matching address owned by another program is not this registry.
        // @spec SCC-SEC-004
        if registry_acc.owner != program_id {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        let mut registry = PolicyRegistry::try_from_slice(&registry_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if registry.discriminator != POLICY_REGISTRY_DISCRIMINATOR {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        if registry.authority != *authority_acc.key.as_ref() {
            return Err(VerifierError::InvalidAuthority.into());
        }

        // Ordinary allowlist maintenance must not silently undo a firmware
        // retirement. Each security-version component is independently monotonic.
        if args.min_tcb_boot_loader < registry.min_tcb_boot_loader
            || args.min_tcb_tee < registry.min_tcb_tee
            || args.min_tcb_snp < registry.min_tcb_snp
            || args.min_tcb_microcode < registry.min_tcb_microcode
        {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }

        registry.min_tcb_boot_loader = args.min_tcb_boot_loader;
        registry.min_tcb_tee = args.min_tcb_tee;
        registry.min_tcb_snp = args.min_tcb_snp;
        registry.min_tcb_microcode = args.min_tcb_microcode;
        registry.measurement_count = args.measurement_count;
        registry.measurements = args.measurements;
        registry.bump = bump;

        Self::write_governance_data(b"update_policy", authority_acc, registry_acc, &registry)
    }

    /// Transfers governance with consent from both the current and new authority.
    /// No pending-state layout or one-sided transfer can strand governance on a typo.
    fn process_rotate_authority(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        if !rest.is_empty() {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let [authority_acc, registry_acc, new_authority_acc, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        let mut registry = Self::assert_registry_authority(program_id, authority_acc, registry_acc)?;
        if !new_authority_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if new_authority_acc.key == &Pubkey::default() || new_authority_acc.key == authority_acc.key {
            return Err(VerifierError::InvalidAuthority.into());
        }
        if !registry_acc.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }
        registry.authority = new_authority_acc.key.to_bytes();
        Self::write_governance_data(b"rotate_authority", authority_acc, registry_acc, &registry)
    }

    /// Multisig rotation of trusted AMD Root Key (ARK) (@spec SCC-VERIFY-005).
    fn process_rotate_root_cert(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = RotateRootCertArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;

        let authority_acc = accounts.first().ok_or(VerifierError::InvalidAccountAddress)?;
        let registry_acc = accounts.get(1).ok_or(VerifierError::InvalidAccountAddress)?;

        if !authority_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let (expected_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
        Self::assert_expected_pda(registry_acc, &expected_pda)?;
        // A matching address owned by another program is not this registry.
        // @spec SCC-SEC-004
        if registry_acc.owner != program_id {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        let registry = PolicyRegistry::try_from_slice(&registry_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if registry.discriminator != POLICY_REGISTRY_DISCRIMINATOR {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        if registry.authority != *authority_acc.key.as_ref() {
            return Err(VerifierError::InvalidAuthority.into());
        }

        // Production AMD verification pins the Milan RSA root in solana-confidential-compute-crypto.
        // This legacy P-384 slot cannot rotate that root. Preserve the ABI but
        // refuse misleading governance writes; a new vendor profile requires
        // explicit reviewed code and cache-profile migration.
        let _ = args;
        Err(VerifierError::InvalidInstruction.into())
    }

    /// Registers and caches a physical AMD chip VCEK public key.
    /// @spec SCC-VERIFY-003, SCC-VERIFY-009
    fn process_register_vcek(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let [payer_acc, registry_acc, vcek_acc, system_program_acc, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        if rest.len() < REGISTER_VCEK_HEADER_SIZE {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let args = RegisterVcekArgs::try_from_slice(&rest[..REGISTER_VCEK_HEADER_SIZE])
            .map_err(|_| VerifierError::InvalidInstruction)?;

        if args.ask_cert_len > MAX_VCEK_CERT_LEN || args.vcek_cert_len > MAX_VCEK_CERT_LEN {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let ask_len = args.ask_cert_len as usize;
        let vcek_len = args.vcek_cert_len as usize;
        let trailing_end = REGISTER_VCEK_HEADER_SIZE
            .checked_add(ask_len)
            .and_then(|v| v.checked_add(vcek_len))
            .ok_or(VerifierError::InvalidInstruction)?;
        if rest.len() != trailing_end {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let ask_der = &rest[REGISTER_VCEK_HEADER_SIZE..REGISTER_VCEK_HEADER_SIZE + ask_len];
        let vcek_der = &rest[REGISTER_VCEK_HEADER_SIZE + ask_len..trailing_end];

        let (expected_registry, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
        Self::assert_expected_pda(registry_acc, &expected_registry)?;
        // A matching address owned by another program is not this registry.
        // @spec SCC-SEC-004
        if registry_acc.owner != program_id {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        let registry = PolicyRegistry::try_from_slice(&registry_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if registry.discriminator != POLICY_REGISTRY_DISCRIMINATOR {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        // Gate attacker-controlled DER and crypto, including preallocated caches.
        if !payer_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        let clock = Clock::get().map_err(|_| VerifierError::InvalidAccountAddress)?;
        let now_unix = u64::try_from(clock.unix_timestamp).map_err(|_| VerifierError::InvalidInstruction)?;
        let valid_until_unix = solana_confidential_compute_crypto::validate_vcek_chain_at(
            &registry.ark_pubkey_xy,
            ask_der,
            vcek_der,
            &args.public_key_xy,
            now_unix,
        )
        .map_err(|_| VerifierError::VerificationFailed)?;

        // Bind the immutable PDA identity to the signed certificate extensions.
        // Caller-supplied chip_id / tcb_version cannot squat another chip.
        // @spec SCC-VERIFY-003 SCC-VERIFY-009
        let identity = solana_confidential_compute_crypto::parse_vcek_identity(vcek_der)
            .map_err(|_| VerifierError::VerificationFailed)?;
        if identity.chip_id != args.chip_id || identity.tcb_version != args.tcb_version {
            return Err(VerifierError::VerificationFailed.into());
        }

        // VLEK subject (`CN=SEV-VLEK`) or a zero hwID. A report with
        // `SIGNING_KEY == 1` resolves this same pubkey seed when `chip_id`
        // is non-zero. @spec SCC-VERIFY-009
        let chip_id_hash: [u8; 32] = if identity.subject_is_vlek || identity.chip_id == [0u8; 64] {
            hashv(&[&args.public_key_xy]).to_bytes()
        } else {
            hashv(&[&args.chip_id]).to_bytes()
        };

        Self::assert_amd_identity_allowed(program_id, accounts, &chip_id_hash)?;
        let tcb_bytes = args.tcb_version.to_le_bytes();
        let (expected_pda, bump) = Pubkey::find_program_address(&[b"vcek_v2", &chip_id_hash, &tcb_bytes], program_id);
        Self::assert_expected_pda(vcek_acc, &expected_pda)?;

        if Self::account_has_discriminator(vcek_acc, &VCEK_ACCOUNT_DISCRIMINATOR)? {
            if vcek_acc.owner != program_id {
                return Err(ProgramError::IllegalOwner);
            }
            let existing = VcekAccount::try_from_slice(&vcek_acc.try_borrow_data()?)
                .map_err(|_| VerifierError::InvalidAccountAddress)?;
            // Only an expired, nonrevoked cache may be revalidated with a fresh chain.
            if existing.is_revoked || now_unix < existing.valid_until_unix {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
        }

        let bump_seed = [bump];
        Self::create_pda_if_needed(
            payer_acc,
            vcek_acc,
            Some(system_program_acc),
            program_id,
            &[b"vcek_v2", &chip_id_hash, &tcb_bytes, &bump_seed],
            VcekAccount::SIZE,
        )?;

        let current_slot = clock.slot;
        let vcek = VcekAccount {
            discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
            chip_id_hash,
            tcb_version: args.tcb_version,
            public_key_xy: args.public_key_xy,
            registered_slot: current_slot,
            bump,

            trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
            valid_until_unix,
            is_revoked: false,
        };

        Self::write_account_data(vcek_acc, &vcek)?;
        Self::log_registration(b"register_vcek", b"amd_sev_snp", &args.public_key_xy, vcek_acc)
    }

    /// Stage 2: Verifies AMD report, enforces policies, and registers AttestedSignerAccount.
    ///
    /// Accounts: `[payer, registry, vcek, attested_signer, used_nonce, slot_hashes,
    /// clock, system_program, workload_signer, instructions_sysvar?]`. The workload
    /// signer must match REPORT_DATA; it may also occupy the payer position.
    /// Rest layout: `nonce_slot` (8) || report (1184) || `nonce_bump` || `signer_bump`.
    /// Nonce and attested-signer bumps must be the canonical `find_program_address` values.
    /// An off-curve bump that is not canonical is rejected.
    /// @spec SCC-VERIFY-001, 002, 004, 006, 007, SCC-SEC-001, SCC-SEC-002, SCC-SEC-005, SCC-SEC-008, SCC-SEC-009, SCC-ARCH-001, 002, SCC-PERF-001
    pub(crate) fn process_verify_and_register<V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        rest: &[u8],
    ) -> ProgramResult {
        let [payer_acc, registry_acc, vcek_acc, attested_signer_acc, used_nonce_acc, slot_hashes_acc, clock_acc, system_program_acc, ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        // nonce_slot || report || nonce bump || signer bump. Trailing bytes are rejected.
        // @spec SCC-SEC-008 SCC-ARCH-001
        const REST_LEN: usize = 8 + SNP_REPORT_SIZE + 2;
        if rest.len() != REST_LEN {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let nonce_slot = u64::from_le_bytes(rest[0..8].try_into().map_err(|_| VerifierError::InvalidInstruction)?);
        let report_bytes = &rest[8..8 + SNP_REPORT_SIZE];
        let nonce_bump = rest[8 + SNP_REPORT_SIZE];
        let signer_bump = rest[8 + SNP_REPORT_SIZE + 1];

        if clock_acc.key != &clock::ID || clock_acc.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let clock = Clock::from_account_info(clock_acc)?;

        let (view, chip_id_hash) = Self::verify_report_and_policy(
            verifier,
            program_id,
            registry_acc,
            vcek_acc,
            accounts,
            report_bytes,
            Self::optional_instructions_sysvar(accounts),
            &clock,
        )?;

        // Sysvar SlotHashes pinned scan & nonce freshness (@spec SCC-VERIFY-001)
        Self::verify_recent_slot_hash(slot_hashes_acc, clock.slot, nonce_slot, &view.nonce())?;

        // Canonical anti-replay nonce PDA. A merely off-curve bump derives a
        // different address and would let the same report be replayed.
        // @spec SCC-SEC-005 SCC-VERIFY-006 SCC-ARCH-001
        let signer_pubkey = view.pubkey();
        Self::assert_workload_consent(accounts, &signer_pubkey)?;
        let nonce = view.nonce();
        Self::assert_legacy_nonce_migration(program_id, accounts, &[b"nonce", &signer_pubkey, &nonce], clock.slot)?;
        let (expected_nonce_pda, expected_nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[1], &signer_pubkey, &nonce], program_id);
        Self::assert_expected_pda(used_nonce_acc, &expected_nonce_pda)?;
        if nonce_bump != expected_nonce_bump {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let nonce_bump_seed = [expected_nonce_bump];

        if Self::nonce_already_used(used_nonce_acc)? {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }

        Self::create_pda_if_needed(
            payer_acc,
            used_nonce_acc,
            Some(system_program_acc),
            program_id,
            &[b"nonce", &[1], &signer_pubkey, &nonce, &nonce_bump_seed],
            UsedNonceAccount::SIZE,
        )?;

        // Attested signer lifecycle. Bump must be canonical.
        // @spec SCC-VERIFY-004 SCC-SEC-005 SCC-ARCH-001
        let (expected_signer_pda, expected_signer_bump) =
            Pubkey::find_program_address(&[b"attested_signer_v2", &signer_pubkey], program_id);
        Self::assert_expected_pda(attested_signer_acc, &expected_signer_pda)?;
        if signer_bump != expected_signer_bump {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let signer_bump_seed = [expected_signer_bump];

        if Self::account_has_discriminator(attested_signer_acc, &ATTESTED_SIGNER_DISCRIMINATOR)? {
            let existing = AttestedSignerAccount::try_from_slice(&attested_signer_acc.try_borrow_data()?)
                .map_err(|_| VerifierError::InvalidAccountAddress)?;
            if existing.is_revoked() {
                return Err(VerifierError::UnauthorizedPolicy.into());
            }
            let expired = clock.slot > existing.record.expires_slot;
            let matching_pubkey = existing.record.signer_pubkey == signer_pubkey;
            let matching_enclave = existing.record.enclave_type == EnclaveType::AmdSevSnp;
            if !expired && (!matching_pubkey || !matching_enclave) {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
        } else {
            Self::create_pda_if_needed(
                payer_acc,
                attested_signer_acc,
                Some(system_program_acc),
                program_id,
                &[b"attested_signer_v2", &signer_pubkey, &signer_bump_seed],
                AttestedSignerAccount::SIZE,
            )?;
        }

        let signer_record = AttestedSignerAccount {
            discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
            record: AttestedSigner {
                signer_pubkey,
                enclave_type: EnclaveType::AmdSevSnp,
                measurement: MeasurementDigest::new(view.measurement()),
                chip_id_hash,
                tcb_version: view.reported_tcb(),
                registered_slot: clock.slot,
                expires_slot: clock.slot.saturating_add(ATTESTATION_TTL_SLOTS),
            },
            bump: expected_signer_bump,
            expires_unix_timestamp: Self::session_unix_deadline(
                clock.unix_timestamp,
                Some(VcekAccountView::try_from_slice(&vcek_acc.try_borrow_data()?)?.valid_until_unix()),
            )?,
        };
        Self::write_account_data(attested_signer_acc, &signer_record)?;

        let used_nonce = UsedNonceAccount::new(clock.slot, expected_nonce_bump).with_refund(payer_acc.key.to_bytes());
        Self::write_account_data(used_nonce_acc, &used_nonce)?;
        Self::log_registration(b"register_signer", b"amd_sev_snp", &signer_pubkey, attested_signer_acc)
    }

    /// Loads the 32-byte slot hash from the pinned SlotHashes sysvar.
    /// The account must be owned by the sysvar program.
    /// @spec SCC-VERIFY-010 SCC-SEC-004
    fn load_slot_hash(
        slot_hashes_acc: &AccountInfo,
        nonce_slot: u64,
        clock_slot: u64,
    ) -> Result<[u8; 32], ProgramError> {
        if slot_hashes_acc.key != &slot_hashes::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        if slot_hashes_acc.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        if clock_slot < nonce_slot || clock_slot.saturating_sub(nonce_slot) > 150 {
            return Err(VerifierError::StaleNonce.into());
        }
        let data = slot_hashes_acc.try_borrow_data()?;
        if data.len() < 8 {
            return Err(VerifierError::StaleNonce.into());
        }
        let num_entries = u64::from_le_bytes(data[0..8].try_into().map_err(|_| VerifierError::StaleNonce)?) as usize;
        for i in 0..num_entries.min(150) {
            let start = 8 + i * 40;
            let end = start + 40;
            if data.len() < end {
                break;
            }
            let slot = u64::from_le_bytes(data[start..start + 8].try_into().map_err(|_| VerifierError::StaleNonce)?);
            if slot == nonce_slot {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[start + 8..end]);
                return Ok(hash);
            }
        }
        Err(VerifierError::StaleNonce.into())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_verify_atomic_common<'a, V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        registry_acc: &AccountInfo,
        vcek_acc: &AccountInfo,
        slot_hashes_acc: &AccountInfo,
        clock_acc: &AccountInfo,
        rest: &'a [u8],
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<(SnpReportView<'a>, [u8; 32], Clock), ProgramError> {
        if clock_acc.key != &clock::ID || clock_acc.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let clock = Clock::from_account_info(clock_acc)?;

        // Header || report || client nonce bump. Trailing bytes are rejected.
        // @spec SCC-SEC-008 SCC-ARCH-001
        const REST_LEN: usize = VerifyAtomicHeader::SIZE + SNP_REPORT_SIZE + 1;
        if rest.len() != REST_LEN {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let header = VerifyAtomicHeader::try_from_slice(&rest[..VerifyAtomicHeader::SIZE])
            .map_err(|_| VerifierError::InvalidInstruction)?;
        let report_bytes = &rest[VerifyAtomicHeader::SIZE..VerifyAtomicHeader::SIZE + SNP_REPORT_SIZE];

        // The next instruction must be the attested consumer. A copied
        // verifier instruction cannot burn the nonce by itself.
        // @spec SCC-VERIFY-010 SCC-VERIFY-011 SCC-SEC-005
        let instructions_sysvar = instructions_sysvar.ok_or(ProgramError::NotEnoughAccountKeys)?;
        if instructions_sysvar.key != &instructions::ID {
            return Err(ProgramError::IncorrectProgramId);
        }
        let current_index = load_current_index_checked(instructions_sysvar)?;
        let next_index = current_index.checked_add(1).ok_or(ProgramError::InvalidInstructionData)?;
        let consumer_ix = load_instruction_at_checked(next_index as usize, instructions_sysvar)?;
        if consumer_ix.program_id.to_bytes() != header.consumer_program_id
            || solana_confidential_compute_core::action::hash_instruction(&consumer_ix) != header.action_hash
        {
            return Err(VerifierError::ActionHashMismatch.into());
        }

        let (view, _chip_id_hash) = Self::verify_report_and_policy(
            verifier,
            program_id,
            registry_acc,
            vcek_acc,
            accounts,
            report_bytes,
            Some(instructions_sysvar),
            &clock,
        )?;

        let slot_hash = Self::load_slot_hash(slot_hashes_acc, header.nonce_slot, clock.slot)?;
        let expected_commitment =
            compute_action_commitment(&slot_hash, &header.action_hash, &header.consumer_program_id);
        if view.nonce() != expected_commitment {
            return Err(VerifierError::ActionHashMismatch.into());
        }

        Ok((view, expected_commitment, clock))
    }

    /// Mode B without nonce is fail-closed. Replay defense requires
    /// `verify_atomic_with_nonce`.
    /// @spec SCC-VERIFY-010 SCC-SEC-005
    fn process_verify_atomic<V: SignatureVerifier>(
        _verifier: &V,
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        _rest: &[u8],
    ) -> ProgramResult {
        Err(VerifierError::NonceRequired.into())
    }

    /// Mode B: nonce-bound atomic attestation preventing replay.
    /// Accounts: [payer, registry, vcek, used_nonce, slot_hashes, clock, system_program]
    /// The last rest byte must be the canonical nonce bump from `find_program_address`.
    /// @spec SCC-VERIFY-006, SCC-VERIFY-010, SCC-VERIFY-011, SCC-VERIFY-012, SCC-SEC-005, SCC-ARCH-001, SCC-PERF-001
    fn process_verify_atomic_with_nonce<V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        rest: &[u8],
    ) -> ProgramResult {
        let [payer_acc, registry_acc, vcek_acc, used_nonce_acc, slot_hashes_acc, clock_acc, system_program_acc, ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        let (view, expected_commitment, clock) = Self::process_verify_atomic_common(
            verifier,
            program_id,
            accounts,
            registry_acc,
            vcek_acc,
            slot_hashes_acc,
            clock_acc,
            rest,
            Self::optional_instructions_sysvar(accounts),
        )?;

        let signer_pubkey = view.pubkey();
        let nonce_bump = rest[VerifyAtomicHeader::SIZE + SNP_REPORT_SIZE];
        // Canonical UsedNonceAccount bump. Alternate off-curve bumps are distinct
        // addresses and must not consume a fresh nonce for the same report.
        // @spec SCC-SEC-005 SCC-VERIFY-006 SCC-VERIFY-011
        Self::assert_legacy_nonce_migration(
            program_id,
            accounts,
            &[b"nonce", &signer_pubkey, &expected_commitment],
            clock.slot,
        )?;
        let (expected_nonce_pda, expected_nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[1], &signer_pubkey, &expected_commitment], program_id);
        Self::assert_expected_pda(used_nonce_acc, &expected_nonce_pda)?;
        if nonce_bump != expected_nonce_bump {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let nonce_bump_seed = [expected_nonce_bump];
        if Self::nonce_already_used(used_nonce_acc)? {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }
        Self::create_pda_if_needed(
            payer_acc,
            used_nonce_acc,
            Some(system_program_acc),
            program_id,
            &[b"nonce", &[1], &signer_pubkey, &expected_commitment, &nonce_bump_seed],
            UsedNonceAccount::SIZE,
        )?;
        Self::write_account_data(
            used_nonce_acc,
            &UsedNonceAccount::new(clock.slot, expected_nonce_bump).with_refund(payer_acc.key.to_bytes()),
        )?;
        Ok(())
    }

    /// Verifies recent slot hash against sysvar::slot_hashes with bounded 150-entry scan
    /// (@spec SCC-VERIFY-001).
    pub fn verify_recent_slot_hash(
        slot_hashes_account: &AccountInfo,
        current_slot: u64,
        nonce_slot: u64,
        expected_hash: &[u8; 32],
    ) -> Result<(), VerifierError> {
        let hash = Self::load_slot_hash(slot_hashes_account, nonce_slot, current_slot).map_err(|err| match err {
            ProgramError::Custom(c) if c == VerifierError::InvalidAccountAddress as u32 => {
                VerifierError::InvalidAccountAddress
            }
            _ => VerifierError::StaleNonce,
        })?;
        if &hash != expected_hash {
            return Err(VerifierError::StaleNonce);
        }
        Ok(())
    }

    fn assert_backend_measurement(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        source: u8,
        measurement: &[u8; 48],
    ) -> ProgramResult {
        use crate::state::BackendPolicy;
        let (key, bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[source]], program_id);
        let account = accounts.iter().find(|a| a.key == &key).ok_or(VerifierError::UnauthorizedPolicy)?;
        if account.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let policy = BackendPolicy::try_from_slice(&account.try_borrow_data()?)
            .map_err(|_| VerifierError::UnauthorizedPolicy)?;
        if policy.bump != bump || !policy.is_measurement_allowed(source, measurement) {
            return Err(VerifierError::DisallowedMeasurement.into());
        }
        Ok(())
    }

    fn process_set_backend_policy(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        use crate::state::BackendPolicy;
        let args = SetBackendPolicyArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;
        let [authority, registry, policy, payer, system, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::assert_registry_authority(program_id, authority, registry)?;
        if !(1..=5).contains(&args.source) || args.measurement_count > 8 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let (key, bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[args.source]], program_id);
        Self::assert_expected_pda(policy, &key)?;
        let value = BackendPolicy {
            discriminator: BackendPolicy::DISCRIMINATOR,
            source: args.source,
            measurement_count: args.measurement_count,
            measurements: args.measurements,
            bump,
        };
        Self::create_pda_if_needed(
            payer,
            policy,
            Some(system),
            program_id,
            &[BackendPolicy::SEED, &[args.source], &[bump]],
            BackendPolicy::SIZE,
        )?;
        // Re-setting the current policy is a no-op: no write and no event.
        if BackendPolicy::try_from_slice(&policy.try_borrow_data()?).is_ok_and(|current| current == value) {
            return Ok(());
        }
        Self::write_governance_data(b"set_backend_policy", authority, policy, &value)
    }

    /// Helper to serialize data into an account.
    /// Unix timestamps are never inferred from variable-duration slots.
    fn session_unix_deadline(now: i64, credential_exp: Option<u64>) -> Result<i64, ProgramError> {
        if now < 0 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let deadline = now.checked_add(ATTESTATION_TTL_SECONDS).ok_or(VerifierError::InvalidInstruction)?;
        let deadline = match credential_exp {
            Some(exp) => deadline.min(i64::try_from(exp).unwrap_or(i64::MAX)),
            None => deadline,
        };
        if deadline <= now {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        Ok(deadline)
    }

    fn assert_legacy_nonce_migration(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        seeds: &[&[u8]],
        now: u64,
    ) -> ProgramResult {
        let (key, _) = Pubkey::find_program_address(seeds, program_id);
        let account = accounts.iter().find(|a| a.key == &key).ok_or(VerifierError::InvalidAccountAddress)?;
        if account.data_is_empty() {
            if account.owner == &system_program::ID || account.owner == program_id {
                return Ok(());
            }
            return Err(ProgramError::IllegalOwner);
        }
        if account.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        if !Self::nonce_already_used(account)? {
            return Err(ProgramError::InvalidAccountData);
        }
        let data = account.try_borrow_data()?;
        let consumed = u64::from_le_bytes(data.get(8..16).ok_or(ProgramError::InvalidAccountData)?.try_into().unwrap());
        if now.checked_sub(consumed).is_none_or(|age| age <= 150) {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }
        Ok(())
    }

    fn process_revoke_vcek(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = RevokeVcekArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;
        let [authority, registry, cache, revocation, payer, system, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::assert_registry_authority(program_id, authority, registry)?;
        let (key, bump) = Pubkey::find_program_address(
            &[VcekAccount::SEED, &args.chip_id_hash, &args.tcb_version.to_le_bytes()],
            program_id,
        );
        Self::assert_expected_pda(cache, &key)?;
        if !cache.is_writable || !revocation.is_writable || !payer.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }
        if !payer.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if system.key != &system_program::ID || !system.executable {
            return Err(ProgramError::IncorrectProgramId);
        }
        let (identity_key, identity_bump) =
            Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &args.chip_id_hash], program_id);
        Self::assert_expected_pda(revocation, &identity_key)?;
        // Validate all inputs before allocating or writing either account.
        let cached = if cache.owner == program_id {
            let value = VcekAccount::try_from_slice(&cache.try_borrow_data()?)
                .map_err(|_| VerifierError::InvalidAccountAddress)?;
            if value.discriminator != VCEK_ACCOUNT_DISCRIMINATOR
                || value.bump != bump
                || value.chip_id_hash != args.chip_id_hash
                || value.tcb_version != args.tcb_version
            {
                return Err(VerifierError::InvalidAccountAddress.into());
            }
            Some(value)
        } else if cache.owner == &system_program::ID && cache.data_is_empty() && !cache.executable {
            None
        } else {
            return Err(ProgramError::IllegalOwner);
        };
        let tombstone = AmdIdentityRevocation {
            discriminator: AmdIdentityRevocation::DISCRIMINATOR,
            identity: args.chip_id_hash,
            bump: identity_bump,
        };
        if revocation.owner == program_id {
            if AmdIdentityRevocation::try_from_slice(&revocation.try_borrow_data()?)
                .map_err(|_| VerifierError::InvalidAccountAddress)?
                != tombstone
            {
                return Err(VerifierError::InvalidAccountAddress.into());
            }
        } else if revocation.owner != &system_program::ID || !revocation.data_is_empty() || revocation.executable {
            return Err(ProgramError::IllegalOwner);
        }
        Self::create_pda_if_needed(
            payer,
            revocation,
            Some(system),
            program_id,
            &[AmdIdentityRevocation::SEED, &args.chip_id_hash, &[identity_bump]],
            AmdIdentityRevocation::SIZE,
        )?;
        Self::write_governance_data(b"revoke_amd_identity", authority, revocation, &tombstone)?;
        if let Some(mut value) = cached {
            value.is_revoked = true;
            Self::write_governance_data(b"revoke_vcek", authority, cache, &value)?;
        }
        solana_program::msg!("solana-confidential-compute:revoke_amd_identity:v1 {}", revocation.key);
        Ok(())
    }

    /// Every AMD admission must supply the canonical identity account, even
    /// when absent. Omitting it cannot bypass a governance tombstone.
    fn assert_amd_identity_allowed(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        identity: &[u8; 32],
    ) -> ProgramResult {
        let (key, _) = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, identity], program_id);
        let account = accounts.iter().find(|a| a.key == &key).ok_or(ProgramError::NotEnoughAccountKeys)?;
        if account.owner == program_id {
            // Fail closed even for malformed program-owned denylist state.
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        if account.owner != &system_program::ID || !account.data_is_empty() || account.executable {
            return Err(ProgramError::IllegalOwner);
        }
        Ok(())
    }

    fn nonce_already_used(account: &AccountInfo) -> Result<bool, ProgramError> {
        Ok(Self::account_has_discriminator(account, &USED_NONCE_DISCRIMINATOR)?
            || Self::account_has_discriminator(account, &crate::state::LEGACY_USED_NONCE_DISCRIMINATOR)?)
    }

    fn close_owned_account(account: &AccountInfo, refund: &AccountInfo) -> ProgramResult {
        if !account.is_writable || !refund.is_writable || account.key == refund.key {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let total = refund.lamports().checked_add(account.lamports()).ok_or(ProgramError::ArithmeticOverflow)?;
        account.resize(0)?;
        **refund.try_borrow_mut_lamports()? = total;
        **account.try_borrow_mut_lamports()? = 0;
        account.assign(&system_program::ID);
        Ok(())
    }

    fn cleanup_clock(account: &AccountInfo) -> Result<Clock, ProgramError> {
        if account.key != &clock::ID || account.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        Clock::from_account_info(account)
    }

    fn process_close_stale_nonce(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        if !rest.is_empty() {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let [nonce, refund, clock, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        if nonce.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        // Legacy accounts lack refund provenance and are intentionally not closable.
        let value = UsedNonceAccount::try_from_slice(&nonce.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if value.discriminator != USED_NONCE_DISCRIMINATOR
            || value.refund_pubkey == [0; 32]
            || value.refund_pubkey != refund.key.to_bytes()
        {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        if !value.is_reclaimable_at_slot(Self::cleanup_clock(clock)?.slot) {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        // Permissionless cleanup: the event actor is the recorded refund account.
        Self::close_governance_account(b"close_stale_nonce", refund, nonce, refund)
    }

    fn process_close_attested_signer(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        if !rest.is_empty() {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let [record, signer, clock, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        if !signer.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if record.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let value = AttestedSignerAccount::try_from_slice(&record.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        let (expected, bump) = Pubkey::find_program_address(&[b"attested_signer_v2", signer.key.as_ref()], program_id);
        if record.key != &expected
            || value.bump != bump
            || value.discriminator != ATTESTED_SIGNER_DISCRIMINATOR
            || value.record.signer_pubkey != signer.key.to_bytes()
        {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let cleanup_clock = Self::cleanup_clock(clock)?;
        if cleanup_clock.unix_timestamp < 0 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        if value.is_revoked()
            || (!value.record.is_expired(cleanup_clock.slot)
                && cleanup_clock.unix_timestamp < value.expires_unix_timestamp)
        {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        Self::close_governance_account(b"close_attested_signer", signer, record, signer)
    }

    fn write_account_data<T: BorshSerialize>(account: &AccountInfo, value: &T) -> ProgramResult {
        let mut data = account.try_borrow_mut_data()?;
        let mut writer = &mut data[..];
        value.serialize(&mut writer).map_err(|_| ProgramError::AccountDataTooSmall)?;
        Ok(())
    }

    /// Version 1 registration event: domain, operation, source, subject key,
    /// affected account, SHA-256(final account bytes). The VCEK subject is its
    /// 96-byte P-384 key; signer subjects are 32-byte workload keys. Require
    /// transaction success when indexing these logs, as for governance events.
    fn log_registration(operation: &[u8], source: &[u8], subject: &[u8], account: &AccountInfo) -> ProgramResult {
        let state_hash = hashv(&[&account.try_borrow_data()?]);
        solana_program::log::sol_log_data(&[
            b"solana-confidential-compute:registration:v1",
            operation,
            source,
            subject,
            account.key.as_ref(),
            state_hash.as_ref(),
        ]);
        Ok(())
    }

    /// Version 1 governance event fields: domain, operation, authority, account,
    /// SHA-256(old account bytes), SHA-256(new account bytes).
    /// Indexers must require transaction success: later instructions can roll back
    /// a successful write while retaining its execution logs.
    fn write_governance_data<T: BorshSerialize>(
        operation: &[u8],
        authority: &AccountInfo,
        account: &AccountInfo,
        value: &T,
    ) -> ProgramResult {
        let before = hashv(&[&account.try_borrow_data()?]);
        Self::write_account_data(account, value)?;
        Self::log_governance(operation, authority, account, &before)
    }

    /// Closes `account` into `refund`, then emits the version 1 governance event.
    /// The new hash covers the closed account's empty data: SHA-256("").
    fn close_governance_account(
        operation: &[u8],
        authority: &AccountInfo,
        account: &AccountInfo,
        refund: &AccountInfo,
    ) -> ProgramResult {
        let before = hashv(&[&account.try_borrow_data()?]);
        Self::close_owned_account(account, refund)?;
        Self::log_governance(operation, authority, account, &before)
    }

    fn log_governance(
        operation: &[u8],
        authority: &AccountInfo,
        account: &AccountInfo,
        before: &Hash,
    ) -> ProgramResult {
        let after = hashv(&[&account.try_borrow_data()?]);
        solana_program::log::sol_log_data(&[
            b"solana-confidential-compute:governance:v1",
            operation,
            authority.key.as_ref(),
            account.key.as_ref(),
            before.as_ref(),
            after.as_ref(),
        ]);
        Ok(())
    }

    fn assert_registry_authority(
        program_id: &Pubkey,
        authority_acc: &AccountInfo,
        registry_acc: &AccountInfo,
    ) -> Result<PolicyRegistry, ProgramError> {
        if !authority_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        let (expected_registry, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
        Self::assert_expected_pda(registry_acc, &expected_registry)?;
        // A matching address owned by another program is not this registry.
        // @spec SCC-SEC-004
        if registry_acc.owner != program_id {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let registry = PolicyRegistry::try_from_slice(&registry_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if registry.discriminator != POLICY_REGISTRY_DISCRIMINATOR {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        if registry.authority != *authority_acc.key.as_ref() {
            return Err(VerifierError::InvalidAuthority.into());
        }
        Ok(registry)
    }

    /// Permanent targeted containment for this workload public key, across sources.
    /// Retain the record as a tombstone; expiry zero is never issued by admission.
    fn process_revoke_attested_signer(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = RevokeAttestedSignerArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;
        let [authority, registry, signer, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::assert_registry_authority(program_id, authority, registry)?;
        let (expected, bump) = Pubkey::find_program_address(&[b"attested_signer_v2", &args.signer_pubkey], program_id);
        Self::assert_expected_pda(signer, &expected)?;
        if signer.owner != program_id || !signer.is_writable {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let mut value = AttestedSignerAccount::try_from_slice(&signer.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if value.discriminator != ATTESTED_SIGNER_DISCRIMINATOR
            || value.record.signer_pubkey != args.signer_pubkey
            || value.bump != bump
        {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        value.record.expires_slot = 0;
        value.expires_unix_timestamp = 0;
        Self::write_governance_data(b"revoke_attested_signer", authority, signer, &value)?;
        solana_program::msg!("solana-confidential-compute:revoke_attested_signer:v1 {}", signer.key);
        Ok(())
    }

    /// Accounts: authority signer, global registry, tenant policy writable,
    /// payer signer writable, system program. Existing global policy ABI is unchanged.
    fn process_set_gcp_tenant_policy(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        use crate::state::GcpTenantPolicy;
        // Bound dynamic Borsh payload before deserializing untrusted strings.
        if rest.len() > 8 + 128 + 160 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let args = SetGcpTenantPolicyArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;
        let [authority, registry, policy, payer, system, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::assert_registry_authority(program_id, authority, registry)?;
        let (expected, bump) = Pubkey::find_program_address(&[GcpTenantPolicy::SEED], program_id);
        Self::assert_expected_pda(policy, &expected)?;
        let value = GcpTenantPolicy::new(args.expected_audience.as_bytes(), args.expected_subject.as_bytes(), bump)?;
        Self::create_pda_if_needed(
            payer,
            policy,
            Some(system),
            program_id,
            &[GcpTenantPolicy::SEED, &[bump]],
            GcpTenantPolicy::SIZE,
        )?;
        // Re-setting the current policy is a no-op: no write and no event.
        if GcpTenantPolicy::try_from_slice(&policy.try_borrow_data()?).is_ok_and(|current| current == value) {
            return Ok(());
        }
        Self::write_governance_data(b"set_gcp_tenant_policy", authority, policy, &value)
    }

    /// Registers an immutable Google JWKS RSA-2048 key with precomputed Montgomery constants.
    /// Accounts: `[authority, registry, jwks_account, payer, system_program]`
    /// @spec SCC-JWT-003 SCC-JWT-006
    fn process_register_jwks_key(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = RegisterJwksKeyArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;
        let [authority_acc, registry_acc, jwks_acc, payer_acc, system_program_acc, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        let _registry = Self::assert_registry_authority(program_id, authority_acc, registry_acc)?;

        if args.kid.is_empty()
            || args.kid.len() > solana_confidential_compute_crypto::jwt::MAX_KID
            || args.kid.contains(&0)
        {
            return Err(VerifierError::InvalidInstruction.into());
        }
        if args.exponent != solana_confidential_compute_crypto::jwt::RSA_EXPONENT {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let kid_hash = solana_confidential_compute_crypto::jwt::kid_hash(&args.kid);
        let (expected_pda, bump) =
            Pubkey::find_program_address(&[solana_confidential_compute_crypto::jwt::JWKS_SEED, &kid_hash], program_id);
        Self::assert_expected_pda(jwks_acc, &expected_pda)?;

        let current_slot = Clock::get().map_err(|_| VerifierError::InvalidAccountAddress)?.slot;
        if Self::account_has_discriminator(jwks_acc, &JWKS_ACCOUNT_DISCRIMINATOR)? {
            if jwks_acc.owner != program_id {
                return Err(ProgramError::IllegalOwner);
            }
            let existing = JwksAccount::try_from_slice(&jwks_acc.try_borrow_data()?)
                .map_err(|_| VerifierError::InvalidAccountAddress)?;
            // Refresh is explicit governance reauthorization of identical key material.
            // Revocation cannot be undone by refreshing, nor can live keys be replaced.
            let permitted = if existing.is_revoked {
                // Re-seat a revoked namespace only with different key material.
                existing.modulus != args.modulus
            } else {
                !existing.is_fresh_at_slot(current_slot)
                    && current_slot >= existing.registered_slot
                    && existing.modulus == args.modulus
                    && existing.exponent == args.exponent
            };
            if existing.kid_hash != kid_hash || !permitted {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
        }

        let (n0, r2) = solana_confidential_compute_crypto::jwt::compute_n0_and_r2(&args.modulus)
            .map_err(Self::map_crypto_error)?;

        let bump_seed = [bump];
        Self::create_pda_if_needed(
            payer_acc,
            jwks_acc,
            Some(system_program_acc),
            program_id,
            &[solana_confidential_compute_crypto::jwt::JWKS_SEED, &kid_hash, &bump_seed],
            JwksAccount::SIZE,
        )?;

        let jwks = JwksAccount::new(kid_hash, args.modulus, args.exponent, n0, r2, current_slot, bump);
        Self::write_governance_data(b"register_jwks_key", authority_acc, jwks_acc, &jwks)
    }

    /// Marks a registered JWKS key as revoked. The modulus is never mutated.
    /// Accounts: `[authority, registry, jwks_account]`
    /// @spec SCC-JWT-006
    fn process_revoke_jwks_key(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        let args = RevokeJwksKeyArgs::try_from_slice(rest).map_err(|_| VerifierError::InvalidInstruction)?;
        let [authority_acc, registry_acc, jwks_acc, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        let _registry = Self::assert_registry_authority(program_id, authority_acc, registry_acc)?;

        let (expected_pda, bump) = Pubkey::find_program_address(
            &[solana_confidential_compute_crypto::jwt::JWKS_SEED, &args.kid_hash],
            program_id,
        );
        Self::assert_expected_pda(jwks_acc, &expected_pda)?;
        if jwks_acc.owner != program_id {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        let mut jwks = JwksAccount::try_from_slice(&jwks_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if jwks.discriminator != JWKS_ACCOUNT_DISCRIMINATOR || jwks.kid_hash != args.kid_hash {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        jwks.is_revoked = true;
        jwks.bump = bump;
        Self::write_governance_data(b"revoke_jwks_key", authority_acc, jwks_acc, &jwks)
    }

    /// Verifies a Google Confidential Space JWT (Mode A session or Mode B atomic).
    /// Accounts: `[attested_signer, policy_registry, jwks_account, used_nonce, payer,
    /// system_program, clock, slot_hashes, workload_signer / instructions_sysvar?]`
    /// @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003 SCC-JWT-005 SCC-JWT-006
    fn process_verify_google_jwt(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        // Zero-copy header unpacking (zero-heap, bounds-safe against OOM)
        const HEADER_LEN: usize = 1 + 8 + 32 + 4;
        if rest.len() < HEADER_LEN {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let mode = rest[0];
        if mode != VERIFY_GOOGLE_JWT_MODE_A && mode != VERIFY_GOOGLE_JWT_MODE_B {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let nonce_slot = u64::from_le_bytes(rest[1..9].try_into().map_err(|_| VerifierError::InvalidInstruction)?);
        let mut expected_action_hash = [0u8; 32];
        expected_action_hash.copy_from_slice(&rest[9..41]);
        let jwt_len =
            u32::from_le_bytes(rest[41..45].try_into().map_err(|_| VerifierError::InvalidInstruction)?) as usize;

        if jwt_len > solana_confidential_compute_crypto::jwt::MAX_JWT_LEN || rest.len() < HEADER_LEN + jwt_len {
            return Err(VerifierError::InvalidInstruction.into());
        }

        let jwt_bytes = &rest[HEADER_LEN..HEADER_LEN + jwt_len];
        let jwt_str = core::str::from_utf8(jwt_bytes).map_err(|_| VerifierError::InvalidInstruction)?;

        let [attested_signer_acc, registry_acc, jwks_acc, used_nonce_acc, payer_acc, system_program_acc, clock_acc, slot_hashes_acc, rest_accs @ ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        if jwks_acc.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }

        if clock_acc.key != &clock::ID || clock_acc.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let clock = Clock::from_account_info(clock_acc)?;
        let now_unix = u64::try_from(clock.unix_timestamp).map_err(|_| VerifierError::InvalidInstruction)?;

        let jwks = JwksAccount::try_from_slice(&jwks_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if jwks.discriminator != JWKS_ACCOUNT_DISCRIMINATOR {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        if !jwks.is_fresh_at_slot(clock.slot) {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        let jwks_bump_seed = [jwks.bump];
        Self::assert_pda(
            jwks_acc,
            &[solana_confidential_compute_crypto::jwt::JWKS_SEED, &jwks.kid_hash, &jwks_bump_seed],
            program_id,
        )?;

        let view = solana_confidential_compute_crypto::jwt::JwtView::parse(jwt_str).map_err(Self::map_crypto_error)?;
        let kid_padded = solana_confidential_compute_crypto::jwt::parse_header_kid_b64(view.header_b64)
            .map_err(Self::map_crypto_error)?;
        let kid_len =
            kid_padded.iter().position(|&b| b == 0).unwrap_or(solana_confidential_compute_crypto::jwt::MAX_KID);
        if kid_len == 0 {
            return Err(VerifierError::InvalidInstruction.into());
        }
        if solana_confidential_compute_crypto::jwt::kid_hash(&kid_padded[..kid_len]) != jwks.kid_hash {
            return Err(VerifierError::InvalidAccountAddress.into());
        }

        let claims = solana_confidential_compute_crypto::jwt::verify_jwt_rs256_with_montgomery(
            jwt_str,
            &jwks.modulus,
            jwks.exponent,
            jwks.n0,
            &jwks.r2,
            Some(now_unix),
        )
        .map_err(Self::map_crypto_error)?;

        // No unsigned request field or token claim chooses its own trust scope.
        let (tenant_key, tenant_bump) =
            Pubkey::find_program_address(&[crate::state::GcpTenantPolicy::SEED], program_id);
        let tenant_acc = rest_accs.iter().find(|a| a.key == &tenant_key).ok_or(VerifierError::UnauthorizedPolicy)?;
        if tenant_acc.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let tenant = crate::state::GcpTenantPolicy::try_from_slice(&tenant_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::UnauthorizedPolicy)?;
        if tenant.bump != tenant_bump {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        let (expected_aud, expected_sub) = tenant.expected()?;
        solana_confidential_compute_crypto::jwt::enforce_google_tenant(&claims, expected_aud, expected_sub)
            .map_err(Self::map_crypto_error)?;

        if !claims.secboot || claims.dbgstat() != solana_confidential_compute_crypto::jwt::REQUIRED_DBGSTAT {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }

        let mut measurement = [0u8; 48];
        measurement[..32].copy_from_slice(&claims.image_digest);

        let registry_data = registry_acc.try_borrow_data()?;
        let registry = PolicyRegistryView::try_from_slice(&registry_data)?;
        let registry_bump_seed = [registry.bump()];
        Self::assert_pda(registry_acc, &[b"policy_registry", &registry_bump_seed], program_id)?;
        Self::assert_backend_measurement(program_id, accounts, 3, &measurement)?;

        if claims.eat_nonce().is_empty() {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }

        let slot_hash = Self::load_slot_hash(slot_hashes_acc, nonce_slot, clock.slot)?;

        let nonce_seed = if mode == VERIFY_GOOGLE_JWT_MODE_A {
            let workload_signer = rest_accs.first().ok_or(VerifierError::InvalidAccountAddress)?;
            if !workload_signer.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            // Nonce 0 and nonce 1 are unpadded base64url. Compare the raw bytes.
            // Tombstone seed is SHA-256(pubkey || slot_hash). @spec SCC-JWT-005
            let raw = claims.decode_mode_a_binding().map_err(|_| VerifierError::SignerMismatch)?;
            if raw[..32] != workload_signer.key.to_bytes() || raw[32..] != slot_hash {
                return Err(VerifierError::SignerMismatch.into());
            }
            solana_confidential_compute_crypto::jwt::eat_nonce_tombstone_seed(&raw)
        } else {
            let instructions_sysvar =
                Self::optional_instructions_sysvar(accounts).ok_or(ProgramError::NotEnoughAccountKeys)?;
            if instructions_sysvar.key != &instructions::ID {
                return Err(ProgramError::IncorrectProgramId);
            }
            let current_index = load_current_index_checked(instructions_sysvar)?;
            let next_index = current_index.checked_add(1).ok_or(ProgramError::InvalidInstructionData)?;
            let consumer_ix = load_instruction_at_checked(next_index as usize, instructions_sysvar)?;
            if solana_confidential_compute_core::action::hash_instruction(&consumer_ix) != expected_action_hash {
                return Err(VerifierError::ActionHashMismatch.into());
            }
            let consumer_program_id = consumer_ix.program_id.to_bytes();
            let commitment = compute_action_commitment(&slot_hash, &expected_action_hash, &consumer_program_id);
            // Unpadded base64url of the 32-byte commitment. Decode before compare.
            // Tombstone seed is SHA-256 of those raw bytes. @spec SCC-JWT-005
            let raw = claims.decode_mode_b_commitment().map_err(Self::map_crypto_error)?;
            if raw != commitment {
                return Err(VerifierError::ActionHashMismatch.into());
            }
            solana_confidential_compute_crypto::jwt::eat_nonce_tombstone_seed(&raw)
        };
        Self::assert_legacy_nonce_migration(program_id, accounts, &[b"nonce", &nonce_seed], clock.slot)?;
        let (expected_nonce_pda, nonce_bump) = Pubkey::find_program_address(&[b"nonce", &[3], &nonce_seed], program_id);
        Self::assert_expected_pda(used_nonce_acc, &expected_nonce_pda)?;
        if Self::nonce_already_used(used_nonce_acc)? {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }
        let nonce_bump_seed = [nonce_bump];
        Self::create_pda_if_needed(
            payer_acc,
            used_nonce_acc,
            Some(system_program_acc),
            program_id,
            &[b"nonce", &[3], &nonce_seed, &nonce_bump_seed],
            UsedNonceAccount::SIZE,
        )?;
        Self::write_account_data(
            used_nonce_acc,
            &UsedNonceAccount::new(clock.slot, nonce_bump).with_refund(payer_acc.key.to_bytes()),
        )?;

        if mode == VERIFY_GOOGLE_JWT_MODE_A {
            let workload_signer = rest_accs.first().ok_or(VerifierError::InvalidAccountAddress)?;
            let signer_pubkey = workload_signer.key.to_bytes();
            let (expected_signer_pda, signer_bump) =
                Pubkey::find_program_address(&[b"attested_signer_v2", &signer_pubkey], program_id);
            Self::assert_expected_pda(attested_signer_acc, &expected_signer_pda)?;

            if Self::account_has_discriminator(attested_signer_acc, &ATTESTED_SIGNER_DISCRIMINATOR)? {
                let existing = AttestedSignerAccount::try_from_slice(&attested_signer_acc.try_borrow_data()?)
                    .map_err(|_| VerifierError::InvalidAccountAddress)?;
                if existing.is_revoked() {
                    return Err(VerifierError::UnauthorizedPolicy.into());
                }
                let expired = clock.slot > existing.record.expires_slot;
                let matching_pubkey = existing.record.signer_pubkey == signer_pubkey;
                let matching_enclave = existing.record.enclave_type == EnclaveType::GcpConfidentialSpace;
                if !expired && (!matching_pubkey || !matching_enclave) {
                    return Err(ProgramError::AccountAlreadyInitialized);
                }
            } else {
                let signer_bump_seed = [signer_bump];
                Self::create_pda_if_needed(
                    payer_acc,
                    attested_signer_acc,
                    Some(system_program_acc),
                    program_id,
                    &[b"attested_signer_v2", &signer_pubkey, &signer_bump_seed],
                    AttestedSignerAccount::SIZE,
                )?;
            }

            let signer_record = AttestedSignerAccount {
                discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
                record: AttestedSigner {
                    signer_pubkey,
                    enclave_type: EnclaveType::GcpConfidentialSpace,
                    measurement: MeasurementDigest::new(measurement),
                    chip_id_hash: [0u8; 32],
                    tcb_version: 0,
                    registered_slot: clock.slot,
                    expires_slot: clock.slot.saturating_add(ATTESTATION_TTL_SLOTS),
                },
                bump: signer_bump,
                expires_unix_timestamp: Self::session_unix_deadline(clock.unix_timestamp, Some(claims.exp))?,
            };
            Self::write_account_data(attested_signer_acc, &signer_record)?;
            Self::log_registration(b"register_signer", b"gcp_confidential_space", &signer_pubkey, attested_signer_acc)?;
        }

        Ok(())
    }

    /// NVIDIA Hopper attestation.
    ///
    /// A 73-byte legacy packet has no proof. Both modes return
    /// `NvidiaAttestationUnavailable` before any account read or write.
    /// A 361-byte packet carries two public-input limbs and uncompressed
    /// Groth16 points. The processor checks those bytes, binds the statement,
    /// and asks `SignatureVerifier` to accept it.
    ///
    /// Accounts: attested signer, policy registry, nonce PDA, payer, system
    /// program, clock, slot hashes, workload signer (Mode A) or instructions
    /// sysvar (Mode B), source-4 backend policy.
    ///
    /// @spec SCC-NVIDIA-001 SCC-NVIDIA-002 SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005
    fn process_verify_nvidia_attestation<V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        rest: &[u8],
    ) -> ProgramResult {
        if rest.len() == VERIFY_NVIDIA_LEGACY_LEN {
            let mode = rest.first().copied().ok_or(VerifierError::InvalidInstruction)?;
            if mode != VERIFY_NVIDIA_MODE_A && mode != VERIFY_NVIDIA_MODE_B {
                return Err(VerifierError::InvalidInstruction.into());
            }
            return Err(VerifierError::NvidiaAttestationUnavailable.into());
        }
        if rest.len() != VERIFY_NVIDIA_PROOF_PACKET_LEN {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let packet = parse_nvidia_proof_packet(rest)?;
        if !nvidia_proof_points_well_formed(packet.proof_a, packet.proof_b, packet.proof_c)
            || !nvidia_public_inputs_canonical(&packet.public_inputs)
        {
            return Err(VerifierError::InvalidProof.into());
        }

        let [attested_signer_acc, registry_acc, used_nonce_acc, payer_acc, system_program_acc, clock_acc, slot_hashes_acc, mode_acc, backend_policy_acc, ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::require_pinned_sysvar(clock_acc, &clock::ID)?;
        let clock = Clock::from_account_info(clock_acc)?;
        let slot_hash = Self::load_slot_hash(slot_hashes_acc, packet.nonce_slot, clock.slot)?;
        let subject = Self::nvidia_subject(packet.mode, packet.expected_action_hash, &slot_hash, mode_acc)?;
        let statement = nvidia_attestation_statement(&NvidiaStatement {
            program_id: program_id.as_ref(),
            mode: packet.mode,
            nonce_slot: packet.nonce_slot,
            expected_action_hash: packet.expected_action_hash,
            measurement: packet.measurement,
            slot_hash: &slot_hash,
            subject: &subject,
        });
        let expected_inputs = nvidia_public_inputs_from_statement(&statement);
        if packet.public_inputs != expected_inputs || !nvidia_public_inputs_canonical(&expected_inputs) {
            return Err(VerifierError::InvalidProof.into());
        }
        let message = nvidia_verifier_message(&statement, packet.proof_a, packet.proof_b, packet.proof_c);
        verifier.verify_p384(
            &message.public_key_xy,
            &message.message_digest,
            &message.signature_rs,
            Self::optional_instructions_sysvar(accounts),
        )?;

        if registry_acc.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let registry_bump = {
            let registry_data = registry_acc.try_borrow_data()?;
            PolicyRegistryView::try_from_slice(&registry_data)?.bump()
        };
        Self::assert_pda(registry_acc, &[b"policy_registry", &[registry_bump]], program_id)?;
        let mut measurement = [0u8; 48];
        measurement[..32].copy_from_slice(packet.measurement);
        Self::assert_nvidia_backend_policy(program_id, backend_policy_acc, &measurement)?;

        if packet.mode == VERIFY_NVIDIA_MODE_B && attested_signer_acc.is_writable {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        if packet.mode == VERIFY_NVIDIA_MODE_A && !attested_signer_acc.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }
        if !payer_acc.is_signer || !payer_acc.is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if system_program_acc.key != &system_program::ID {
            return Err(ProgramError::IncorrectProgramId);
        }

        let signer_pubkey = if packet.mode == VERIFY_NVIDIA_MODE_A { Some(subject) } else { None };
        if let Some(signer_pubkey) = signer_pubkey {
            Self::reject_nvidia_tombstone(program_id, attested_signer_acc, &signer_pubkey, clock.slot)?;
        }
        Self::consume_nvidia_nonce(
            program_id,
            payer_acc,
            system_program_acc,
            used_nonce_acc,
            &subject,
            packet.measurement,
            &slot_hash,
            clock.slot,
        )?;
        if let Some(signer_pubkey) = signer_pubkey {
            Self::write_nvidia_signer(
                program_id,
                payer_acc,
                system_program_acc,
                attested_signer_acc,
                &signer_pubkey,
                &measurement,
                packet.measurement,
                &clock,
            )?;
        }
        Ok(())
    }

    fn require_pinned_sysvar(account: &AccountInfo, id: &Pubkey) -> ProgramResult {
        if account.key != id || account.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        Ok(())
    }

    /// Mode A subject is the workload signer. Mode B subject is the action commitment.
    /// @spec SCC-NVIDIA-002 SCC-NVIDIA-004
    fn nvidia_subject(
        mode: u8,
        action_hash: &[u8; 32],
        slot_hash: &[u8; 32],
        mode_account: &AccountInfo,
    ) -> Result<[u8; 32], ProgramError> {
        match mode {
            VERIFY_NVIDIA_MODE_A => {
                if !mode_account.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                Ok(mode_account.key.to_bytes())
            }
            VERIFY_NVIDIA_MODE_B => {
                Self::require_pinned_sysvar(mode_account, &instructions::ID)?;
                if mode_account.data_len() < 2 {
                    return Err(VerifierError::InvalidInstruction.into());
                }
                let current_index = load_current_index_checked(mode_account)?;
                let next_index = current_index.checked_add(1).ok_or(ProgramError::InvalidInstructionData)?;
                let consumer = load_instruction_at_checked(next_index as usize, mode_account)?;
                Ok(compute_action_commitment(slot_hash, action_hash, &consumer.program_id.to_bytes()))
            }
            _ => Err(VerifierError::InvalidInstruction.into()),
        }
    }

    fn assert_nvidia_backend_policy(
        program_id: &Pubkey,
        backend_policy: &AccountInfo,
        measurement: &[u8; 48],
    ) -> ProgramResult {
        use crate::state::BackendPolicy;
        let (policy_pda, _) =
            Pubkey::find_program_address(&[BackendPolicy::SEED, &[NVIDIA_ATTESTATION_SOURCE]], program_id);
        if backend_policy.key != &policy_pda {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        Self::assert_backend_measurement(
            program_id,
            std::slice::from_ref(backend_policy),
            NVIDIA_ATTESTATION_SOURCE,
            measurement,
        )
    }

    /// A revoked Mode A record stays in place. The nonce is not consumed.
    /// @spec SCC-NVIDIA-004 SCC-NVIDIA-005
    fn reject_nvidia_tombstone(
        program_id: &Pubkey,
        attested_signer: &AccountInfo,
        signer_pubkey: &[u8; 32],
        clock_slot: u64,
    ) -> ProgramResult {
        if attested_signer.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let (expected_signer, signer_bump) =
            Pubkey::find_program_address(&[b"attested_signer_v2", signer_pubkey], program_id);
        Self::assert_expected_pda(attested_signer, &expected_signer)?;
        if !Self::account_has_discriminator(attested_signer, &ATTESTED_SIGNER_DISCRIMINATOR)? {
            return Ok(());
        }
        let existing = AttestedSignerAccount::try_from_slice(&attested_signer.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if existing.is_revoked() {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        if existing.bump != signer_bump {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let expired = clock_slot > existing.record.expires_slot;
        let matching_pubkey = existing.record.signer_pubkey == *signer_pubkey;
        let matching_enclave = existing.record.enclave_type == EnclaveType::NvidiaGpu;
        if !expired && (!matching_pubkey || !matching_enclave) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        Ok(())
    }

    /// Allocate and fill the source-4 nonce PDA at `["nonce", 4, seed]`.
    /// @spec SCC-NVIDIA-004
    #[allow(clippy::too_many_arguments)]
    fn consume_nvidia_nonce<'a>(
        program_id: &Pubkey,
        payer: &AccountInfo<'a>,
        system_program_acc: &AccountInfo<'a>,
        used_nonce: &AccountInfo<'a>,
        subject: &[u8; 32],
        measurement: &[u8; 32],
        slot_hash: &[u8; 32],
        clock_slot: u64,
    ) -> ProgramResult {
        let seed = nvidia_nonce_seed(subject, measurement, slot_hash);
        let (expected_nonce, nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[NVIDIA_ATTESTATION_SOURCE], &seed], program_id);
        Self::assert_expected_pda(used_nonce, &expected_nonce)?;
        if Self::nonce_already_used(used_nonce)? {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }
        let nonce_bump_seed = [nonce_bump];
        Self::create_pda_if_needed(
            payer,
            used_nonce,
            Some(system_program_acc),
            program_id,
            &[b"nonce", &[NVIDIA_ATTESTATION_SOURCE], &seed, &nonce_bump_seed],
            UsedNonceAccount::SIZE,
        )?;
        Self::write_account_data(
            used_nonce,
            &UsedNonceAccount::new(clock_slot, nonce_bump).with_refund(payer.key.to_bytes()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_nvidia_signer<'a>(
        program_id: &Pubkey,
        payer: &AccountInfo<'a>,
        system_program_acc: &AccountInfo<'a>,
        attested_signer: &AccountInfo<'a>,
        signer_pubkey: &[u8; 32],
        measurement: &[u8; 48],
        chip_id_hash: &[u8; 32],
        clock: &Clock,
    ) -> ProgramResult {
        let (expected_signer, signer_bump) =
            Pubkey::find_program_address(&[b"attested_signer_v2", signer_pubkey], program_id);
        Self::assert_expected_pda(attested_signer, &expected_signer)?;
        if !Self::account_has_discriminator(attested_signer, &ATTESTED_SIGNER_DISCRIMINATOR)? {
            let signer_bump_seed = [signer_bump];
            Self::create_pda_if_needed(
                payer,
                attested_signer,
                Some(system_program_acc),
                program_id,
                &[b"attested_signer_v2", signer_pubkey, &signer_bump_seed],
                AttestedSignerAccount::SIZE,
            )?;
        }
        let signer_record = AttestedSignerAccount {
            discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
            record: AttestedSigner {
                signer_pubkey: *signer_pubkey,
                enclave_type: EnclaveType::NvidiaGpu,
                measurement: MeasurementDigest::new(*measurement),
                chip_id_hash: *chip_id_hash,
                tcb_version: 0,
                registered_slot: clock.slot,
                expires_slot: clock.slot.saturating_add(ATTESTATION_TTL_SLOTS),
            },
            bump: signer_bump,
            expires_unix_timestamp: Self::session_unix_deadline(clock.unix_timestamp, None)?,
        };
        Self::write_account_data(attested_signer, &signer_record)?;
        Self::log_registration(b"register_signer", b"nvidia_h100", signer_pubkey, attested_signer)
    }

    /// Verifies an AWS Nitro COSE Sign1 attestation (Mode A register / Mode B atomic).
    /// Accounts: `[payer, registry, attested_signer, used_nonce, slot_hashes, clock,
    /// system_program, workload_signer (Mode A), instructions_sysvar?]`. Mode A
    /// requires a signed account matching user_data; the payer may be that key.
    /// @spec SCC-NITRO-006 SCC-NITRO-007 SCC-NITRO-008
    fn process_verify_nitro_attestation<V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        rest: &[u8],
    ) -> ProgramResult {
        const HEADER_LEN: usize = 1 + 8 + 32 + 4;
        if rest.len() < HEADER_LEN {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let mode = rest[0];
        if mode != VERIFY_NITRO_MODE_A && mode != VERIFY_NITRO_MODE_B {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let nonce_slot = u64::from_le_bytes(rest[1..9].try_into().map_err(|_| VerifierError::InvalidInstruction)?);
        let mut expected_action_hash = [0u8; 32];
        expected_action_hash.copy_from_slice(&rest[9..41]);
        let doc_len =
            u32::from_le_bytes(rest[41..45].try_into().map_err(|_| VerifierError::InvalidInstruction)?) as usize;
        if doc_len == 0 || doc_len > MAX_NITRO_DOCUMENT_LEN || rest.len() != HEADER_LEN + doc_len {
            return Err(VerifierError::InvalidInstruction.into());
        }
        let document = &rest[HEADER_LEN..HEADER_LEN + doc_len];

        let [payer_acc, registry_acc, attested_signer_acc, used_nonce_acc, slot_hashes_acc, clock_acc, system_program_acc, ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };

        if clock_acc.key != &clock::ID || clock_acc.owner != &solana_program::sysvar::ID {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let clock = Clock::from_account_info(clock_acc)?;
        let now_unix = u64::try_from(clock.unix_timestamp).map_err(|_| VerifierError::InvalidInstruction)?;

        let (cose, view) =
            solana_confidential_compute_crypto::parse_nitro_attestation(document).map_err(Self::map_crypto_error)?;

        let registry_bump = {
            let registry_data = registry_acc.try_borrow_data()?;
            // Zero-copy view avoids a 529-byte stack copy of PolicyRegistry.
            // @spec SCC-ARCH-002 SCC-NITRO-004 SCC-SEC-002 SCC-SEC-003
            let registry = PolicyRegistryView::try_from_slice(&registry_data)?;
            registry.bump()
        };
        let registry_bump_seed = [registry_bump];
        Self::assert_pda(registry_acc, &[b"policy_registry", &registry_bump_seed], program_id)?;

        Self::assert_backend_measurement(program_id, accounts, 2, &view.pcrs.pcr0)?;
        let pcr0_allowed = true;
        let instructions_sysvar = Self::optional_instructions_sysvar(accounts);
        let (leaf_xy, credential_exp) = Self::verify_nitro_cert_chain(
            verifier,
            &solana_confidential_compute_crypto::AWS_NITRO_ROOT_CA_PUBKEY_XY,
            &view,
            now_unix,
            instructions_sysvar,
        )?;

        let digest = solana_confidential_compute_crypto::hash_cose_sig_structure(cose.protected, cose.payload)
            .map_err(Self::map_crypto_error)?;
        verifier.verify_p384(&leaf_xy, &digest, &cose.signature_rs, instructions_sysvar)?;

        // @spec SCC-NITRO-006
        if view.pcrs.pcr0_is_zero() || !pcr0_allowed {
            return Err(VerifierError::DisallowedMeasurement.into());
        }

        let slot_hash = Self::load_slot_hash(slot_hashes_acc, nonce_slot, clock.slot)?;
        let signer_pubkey = view.user_data;

        let nonce_bytes = if mode == VERIFY_NITRO_MODE_A {
            // @spec SCC-NITRO-007
            if view.nonce != slot_hash {
                return Err(VerifierError::StaleNonce.into());
            }
            Self::assert_workload_consent(accounts, &signer_pubkey)?;
            view.nonce
        } else {
            let instructions_sysvar = instructions_sysvar.ok_or(ProgramError::NotEnoughAccountKeys)?;
            if instructions_sysvar.key != &instructions::ID {
                return Err(ProgramError::IncorrectProgramId);
            }
            let current_index = load_current_index_checked(instructions_sysvar)?;
            let next_index = current_index.checked_add(1).ok_or(ProgramError::InvalidInstructionData)?;
            let consumer_ix = load_instruction_at_checked(next_index as usize, instructions_sysvar)?;
            if solana_confidential_compute_core::action::hash_instruction(&consumer_ix) != expected_action_hash {
                return Err(VerifierError::ActionHashMismatch.into());
            }
            let consumer_program_id = consumer_ix.program_id.to_bytes();
            let commitment = compute_action_commitment(&slot_hash, &expected_action_hash, &consumer_program_id);
            if view.nonce != commitment {
                return Err(VerifierError::ActionHashMismatch.into());
            }
            commitment
        };

        Self::assert_legacy_nonce_migration(
            program_id,
            accounts,
            &[b"nonce", &signer_pubkey, &nonce_bytes],
            clock.slot,
        )?;
        let (expected_nonce_pda, nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[2], &signer_pubkey, &nonce_bytes], program_id);
        Self::assert_expected_pda(used_nonce_acc, &expected_nonce_pda)?;
        if Self::nonce_already_used(used_nonce_acc)? {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }
        let nonce_bump_seed = [nonce_bump];
        Self::create_pda_if_needed(
            payer_acc,
            used_nonce_acc,
            Some(system_program_acc),
            program_id,
            &[b"nonce", &[2], &signer_pubkey, &nonce_bytes, &nonce_bump_seed],
            UsedNonceAccount::SIZE,
        )?;
        Self::write_account_data(
            used_nonce_acc,
            &UsedNonceAccount::new(clock.slot, nonce_bump).with_refund(payer_acc.key.to_bytes()),
        )?;

        if mode == VERIFY_NITRO_MODE_A {
            let (expected_signer_pda, signer_bump) =
                Pubkey::find_program_address(&[b"attested_signer_v2", &signer_pubkey], program_id);
            Self::assert_expected_pda(attested_signer_acc, &expected_signer_pda)?;

            if Self::account_has_discriminator(attested_signer_acc, &ATTESTED_SIGNER_DISCRIMINATOR)? {
                let existing = AttestedSignerAccount::try_from_slice(&attested_signer_acc.try_borrow_data()?)
                    .map_err(|_| VerifierError::InvalidAccountAddress)?;
                if existing.is_revoked() {
                    return Err(VerifierError::UnauthorizedPolicy.into());
                }
                let expired = clock.slot > existing.record.expires_slot;
                let matching_pubkey = existing.record.signer_pubkey == signer_pubkey;
                let matching_enclave = existing.record.enclave_type == EnclaveType::AwsNitro;
                if !expired && (!matching_pubkey || !matching_enclave) {
                    return Err(ProgramError::AccountAlreadyInitialized);
                }
            } else {
                let signer_bump_seed = [signer_bump];
                Self::create_pda_if_needed(
                    payer_acc,
                    attested_signer_acc,
                    Some(system_program_acc),
                    program_id,
                    &[b"attested_signer_v2", &signer_pubkey, &signer_bump_seed],
                    AttestedSignerAccount::SIZE,
                )?;
            }

            let chip_id_hash = hashv(&[view.module_id.as_bytes()]).to_bytes();
            let signer_record = AttestedSignerAccount {
                discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
                record: AttestedSigner {
                    signer_pubkey,
                    enclave_type: EnclaveType::AwsNitro,
                    measurement: MeasurementDigest::new(view.pcrs.pcr0),
                    chip_id_hash,
                    tcb_version: 0,
                    registered_slot: clock.slot,
                    expires_slot: clock.slot.saturating_add(ATTESTATION_TTL_SLOTS),
                },
                bump: signer_bump,
                expires_unix_timestamp: Self::session_unix_deadline(clock.unix_timestamp, Some(credential_exp))?,
            };
            Self::write_account_data(attested_signer_acc, &signer_record)?;
            Self::log_registration(b"register_signer", b"aws_nitro", &signer_pubkey, attested_signer_acc)?;
        }

        Ok(())
    }

    /// Walks cabundle[0] (AWS Nitro Root CA G1) → intermediates → leaf.
    ///
    /// `root_xy` must be `AWS_NITRO_ROOT_CA_PUBKEY_XY`. The AMD ARK stored on
    /// `PolicyRegistry` is rejected as a Nitro root.
    /// @spec SCC-NITRO-004 SCC-SEC-003
    fn verify_nitro_cert_chain<V: SignatureVerifier>(
        verifier: &V,
        root_xy: &[u8; 96],
        view: &NitroAttestationView<'_>,
        now_unix: u64,
        instructions_sysvar: Option<&AccountInfo>,
    ) -> Result<([u8; 96], u64), ProgramError> {
        if root_xy != &solana_confidential_compute_crypto::AWS_NITRO_ROOT_CA_PUBKEY_XY {
            return Err(VerifierError::VerificationFailed.into());
        }
        if view.cabundle_len == 0 {
            return Err(VerifierError::VerificationFailed.into());
        }
        solana_confidential_compute_crypto::validate_nitro_path_constraints(view.cabundle_certs(), view.certificate)
            .map_err(Self::map_crypto_error)?;
        let mut issuer_xy = *root_xy;
        let mut credential_exp = u64::MAX;
        for (i, der) in view.cabundle_certs().iter().enumerate() {
            let cert = solana_confidential_compute_crypto::parse_nitro_cert(der).map_err(Self::map_crypto_error)?;
            if now_unix < cert.not_before || now_unix > cert.not_after {
                return Err(VerifierError::VerificationFailed.into());
            }
            if i == 0 {
                if &cert.pubkey_xy != root_xy {
                    return Err(VerifierError::VerificationFailed.into());
                }
            } else {
                let mut hasher = Sha384::new();
                hasher.update(cert.tbs_der);
                let digest: [u8; 48] = hasher.finalize().into();
                verifier.verify_p384(&issuer_xy, &digest, &cert.signature_rs, instructions_sysvar)?;
            }
            credential_exp = credential_exp.min(cert.not_after);
            issuer_xy = cert.pubkey_xy;
        }
        let leaf =
            solana_confidential_compute_crypto::parse_nitro_cert(view.certificate).map_err(Self::map_crypto_error)?;
        if now_unix < leaf.not_before || now_unix > leaf.not_after {
            return Err(VerifierError::VerificationFailed.into());
        }
        let mut hasher = Sha384::new();
        hasher.update(leaf.tbs_der);
        let digest: [u8; 48] = hasher.finalize().into();
        verifier.verify_p384(&issuer_xy, &digest, &leaf.signature_rs, instructions_sysvar)?;
        Ok((leaf.pubkey_xy, credential_exp.min(leaf.not_after)))
    }

    /// First half of Intel TDX verification: certify the attestation key.
    ///
    /// Establishes that an allowlisted platform key signed a QE report, and
    /// that the report commits to one particular attestation key. The second
    /// half may then accept a quote body signed by that key, and no other.
    ///
    /// Accounts: session PDA (writable), source-5 backend policy, payer
    /// (signer, writable), system program, clock, instructions sysvar.
    ///
    /// @spec SCC-TDX-001
    fn process_verify_tdx_qe_report(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        use crate::state::TdxSessionAccount;
        use crate::tdx;

        let args = crate::payload::parse_tdx_qe_report_args(rest)?;

        let [session_acc, backend_policy_acc, payer_acc, system_program_acc, clock_acc, instructions_acc, ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::require_pinned_sysvar(clock_acc, &clock::ID)?;
        let clock = Clock::from_account_info(clock_acc)?;
        if !payer_acc.is_signer || !payer_acc.is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if system_program_acc.key != &system_program::ID {
            return Err(ProgramError::IncorrectProgramId);
        }

        // What the precompile actually verified. The key it names carries no
        // authority yet -- anyone can have a signature of their own checked.
        let verified = tdx::extract_secp256r1_verified(instructions_acc, tdx::QE_REPORT_LEN)?;
        if verified.compressed_pubkey != *args.pck_pubkey {
            return Err(VerifierError::InvalidSignature.into());
        }

        // Now it carries authority: the platform key is on the source-5
        // allowlist. Without this a self-signed QE report would certify any
        // attestation key the caller liked.
        let mut pck_measurement = [0u8; 48];
        pck_measurement[..33].copy_from_slice(args.pck_pubkey);
        Self::assert_tdx_backend_policy(program_id, backend_policy_acc, &pck_measurement)?;

        // Intel's binding: the QE report's REPORTDATA is
        // SHA-256(attestation_key || qe_auth_data) followed by 32 zero bytes.
        // This is what ties the caller-supplied attestation key to a QE the
        // platform vouched for. Both halves are checked -- treating the tail
        // as free space would hand an attacker 32 bytes inside signed
        // hardware evidence.
        let qe_report = verified.message.as_slice();

        // The PCK key signs every enclave on its platform, not only the
        // Quoting Enclave, so an allowlisted platform key alone would let any
        // enclave on an approved machine certify any attestation key.
        // Governance pins which enclave is the QE.
        tdx::reject_debug_qe(qe_report)?;
        let mut qe_identity = [0u8; 48];
        qe_identity[..32].copy_from_slice(&tdx::qe_identity_digest(qe_report)?);
        Self::assert_tdx_backend_policy(program_id, backend_policy_acc, &qe_identity)?;

        let report_data = qe_report
            .get(tdx::QE_REPORT_DATA_OFFSET..tdx::QE_REPORT_DATA_OFFSET + 64)
            .ok_or(VerifierError::InvalidSignature)?;
        let commitment = hashv(&[args.attestation_pubkey_xy, args.qe_auth_data]).to_bytes();
        if report_data[..32] != commitment || report_data[32..] != [0u8; 32] {
            return Err(VerifierError::InvalidSignature.into());
        }

        let attestation_pubkey = tdx::compress_p256(args.attestation_pubkey_xy);
        let qe_report_digest = hashv(&[qe_report]).to_bytes();

        // Seeded by a digest of the compressed key, not the key itself: a
        // PDA seed is capped at 32 bytes and a compressed point is 33. Using
        // only the X coordinate would let the two parities of the same X
        // share a session.
        let session_seed = TdxSessionAccount::seed_for(&attestation_pubkey);
        let (expected_session, session_bump) =
            Pubkey::find_program_address(&[TdxSessionAccount::SEED, &session_seed], program_id);
        Self::assert_expected_pda(session_acc, &expected_session)?;
        // A live session may not have its bindings rewritten.
        //
        // Step one is permissionless and replayable: the QE report and the
        // PCK signature over it both travel in the public quote, so anyone
        // can resubmit them. Without this guard an observer who sees a
        // pending step two can front-run it with a step one for the same
        // attestation key carrying different GPU and model digests. Step two
        // then recomputes `expected_report_data` from the rewritten session,
        // it no longer matches the signed REPORTDATA, and the honest
        // enrolment fails. The attacker gains nothing except the ability to
        // stop anyone enrolling, indefinitely and for free.
        //
        // Re-running step one with the *same* digests stays allowed, so an
        // honest retry after a dropped transaction still works, and an
        // expired session can be replaced outright because nothing is
        // relying on it any more.
        if session_acc.data_len() == TdxSessionAccount::SIZE && session_acc.owner == program_id {
            if let Ok(existing) = TdxSessionAccount::try_from_slice(&session_acc.try_borrow_data()?) {
                if existing.discriminator == TdxSessionAccount::DISCRIMINATOR
                    && existing.is_live_at(clock.slot)
                    && (existing.gpu_rim_digest != *args.gpu_rim_digest || existing.model_digest != *args.model_digest)
                {
                    return Err(VerifierError::InvalidInstruction.into());
                }
            }
        }

        let bump_seed = [session_bump];
        Self::create_pda_if_needed(
            payer_acc,
            session_acc,
            Some(system_program_acc),
            program_id,
            &[TdxSessionAccount::SEED, &session_seed, &bump_seed],
            TdxSessionAccount::SIZE,
        )?;
        Self::write_account_data(
            session_acc,
            &TdxSessionAccount {
                discriminator: TdxSessionAccount::DISCRIMINATOR,
                attestation_pubkey,
                qe_report_digest,
                gpu_rim_digest: *args.gpu_rim_digest,
                model_digest: *args.model_digest,
                slot: clock.slot,
                bump: session_bump,
            },
        )?;
        Self::log_registration(b"tdx_qe_report", b"intel_tdx", &attestation_pubkey[1..], session_acc)
    }

    /// Second half of Intel TDX verification: admit the workload signer.
    ///
    /// Takes a quote body signed by an attestation key an earlier
    /// `verify_tdx_qe_report` certified, checks its measurements against the
    /// source-5 allowlist, confirms the enclave bound the workload signer into
    /// `REPORTDATA`, and writes the attested-signer record.
    ///
    /// Accounts: attested signer PDA (writable), session PDA, source-5 backend
    /// policy, nonce PDA (writable), payer (signer, writable), system program,
    /// clock, challenge PDA, workload signer (signer), instructions sysvar.
    ///
    /// @spec SCC-TDX-002
    fn process_verify_tdx_quote(program_id: &Pubkey, accounts: &[AccountInfo], rest: &[u8]) -> ProgramResult {
        use crate::tdx;

        let args = crate::payload::parse_tdx_quote_args(rest)?;

        let [attested_signer_acc, session_acc, backend_policy_acc, used_nonce_acc, payer_acc, system_program_acc, clock_acc, challenge_acc, workload_signer_acc, instructions_acc, ..] =
            accounts
        else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::require_pinned_sysvar(clock_acc, &clock::ID)?;
        let clock = Clock::from_account_info(clock_acc)?;
        if !payer_acc.is_signer || !payer_acc.is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if system_program_acc.key != &system_program::ID {
            return Err(ProgramError::IncorrectProgramId);
        }
        // Mode A binds the record to a key that signed this transaction, so a
        // third party cannot enrol a signer it does not control.
        if !workload_signer_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !attested_signer_acc.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }

        let challenge = Self::load_tdx_challenge(program_id, challenge_acc, clock.slot, args.nonce_slot)?;
        // The quote body, as verified by the precompile.
        let verified = tdx::extract_secp256r1_verified(instructions_acc, tdx::ISV_SIGNED_LEN)?;

        // The key that signed it must be the one an allowlisted platform
        // certified. Without this check the body is signed by nobody in
        // particular: the precompile is happy to verify an attacker's own key.
        let session = Self::load_tdx_session(program_id, session_acc, &verified.compressed_pubkey, clock.slot)?;
        // Redundant by construction -- `load_tdx_session` derives the PDA
        // from `verified.compressed_pubkey`, and the QE step wrote the record
        // under the same derivation, so a session found at that address
        // cannot hold a different key. A mutation sweep confirmed removing
        // this changes no test. It stays as a cheap assertion that the two
        // derivations have not drifted apart.
        if session.attestation_pubkey != verified.compressed_pubkey {
            return Err(VerifierError::InvalidSignature.into());
        }

        // Only now is the body trustworthy enough to read fields out of.
        let body = &verified.message[tdx::QUOTE_HEADER_LEN..];
        let mr_td: [u8; 48] = body[136..184].try_into().map_err(|_| VerifierError::InvalidInstruction)?;
        let mr_config_id: [u8; 48] = body[184..232].try_into().map_err(|_| VerifierError::InvalidInstruction)?;
        let rtmrs_hash = hashv(&[&body[328..520]]).to_bytes();
        let report_data: [u8; 64] = body[520..584].try_into().map_err(|_| VerifierError::InvalidInstruction)?;

        // A debug TD has the approved measurement and no protection: the host
        // can read the workload's keys straight out of its memory.
        tdx::reject_debug_td(body)?;

        // One allowlist entry covers the pinned TD fields through a single
        // digest. Listing them separately looks stricter but is not:
        // MRCONFIGID and the RTMRs are legitimately all-zero on a TD that
        // extends neither, and `is_measurement_allowed` rejects a zero
        // measurement outright as a guard against uninitialised policy slots.
        // An ordinary TD could therefore never be admitted. Hashing the tuple
        // keeps the conjunctive property -- change any field and the hash
        // changes -- without that dead end.
        //
        // The digest covers MRTD, MRCONFIGID, RTMR0..2, TEE_TCB_SVN, MRSEAM,
        // TD_ATTRIBUTES and XFAM. Without the last four an approved workload
        // measurement would be admitted under a down-level TDX module or a
        // different execution environment -- the measurement says what ran,
        // not what it ran on. RTMR3 is excluded because it changes every
        // boot; see `td_platform_digest` for why, and for what that costs.
        let mut platform_measurement = [0u8; 48];
        platform_measurement[..32].copy_from_slice(&tdx::td_platform_digest(body)?);
        Self::assert_tdx_backend_policy(program_id, backend_policy_acc, &platform_measurement)?;

        // Recorded on the signer so a consumer can tell two admitted TDs
        // apart by their measurements alone.
        let journal_hash = solana_confidential_compute_core::types::compute_journal_hash(
            &solana_confidential_compute_core::types::JournalV3 { mr_td, mr_config_id, rtmrs_hash },
        );
        let mut journal_measurement = [0u8; 48];
        journal_measurement[..32].copy_from_slice(&journal_hash);
        // The GPU RIM rides in the same quote's REPORTDATA and governance
        // allowlists which values may appear.
        //
        // Read what that does and does not say. REPORTDATA is chosen by the
        // TD, so this proves an approved TD *declared* one of the approved GPU
        // configurations. It is not GPU attestation: nothing here checks an
        // NVIDIA signature, a RIM, or a device certificate, and nothing in the
        // sidecar derives this value from a GPU -- it comes from the TD's
        // measured launch configuration.
        //
        // Nor would verifying NVIDIA's signature on chain fix that. An NVIDIA
        // attestation report binds a device and a nonce, not the device to a
        // TD, so a genuine report can be relayed from a GPU attached to some
        // other machine. Only TDISP/TEE-IO device binding closes that gap.
        //
        // The appraisal that does happen is dstack's: at boot, before key
        // provisioning, it runs NVIDIA's `nvattest` over every GPU and halts
        // the launch if the policy fails. That verdict lands in RTMR3 as a
        // `gpu-attestation` event, and the policy that produced it is bound by
        // MRCONFIGID -- which the platform digest above does pin. Reading the
        // verdict itself needs an event-log replay this program does not do.
        let mut gpu_measurement = [0u8; 48];
        gpu_measurement[..32].copy_from_slice(&session.gpu_rim_digest);
        Self::assert_tdx_backend_policy(program_id, backend_policy_acc, &gpu_measurement)?;

        // The binding that gives the whole chain its meaning. A valid quote
        // proves genuine hardware ran a known measurement; it says nothing
        // about which key speaks for it unless the enclave put that key in
        // REPORTDATA. Without this, anyone holding any valid quote for this
        // challenge could enrol a signer of their choosing.
        let signer_pubkey = workload_signer_acc.key.to_bytes();
        let expected_report_data = tdx::expected_report_data(
            &signer_pubkey,
            &challenge.slot_hash,
            &session.gpu_rim_digest,
            &session.model_digest,
            &challenge.nonce,
        );
        if report_data != expected_report_data {
            return Err(VerifierError::InvalidSignature.into());
        }

        let quote_body_digest = hashv(&[verified.message.as_slice()]).to_bytes();
        let seed =
            crate::payload::tdx_nonce_seed(&signer_pubkey, &quote_body_digest, &challenge.slot_hash, &challenge.nonce);
        Self::consume_tdx_nonce(program_id, payer_acc, system_program_acc, used_nonce_acc, &seed, clock.slot)?;

        // Retire the challenge permanently.
        //
        // The nonce tombstone alone leaves a window: `UsedNonceAccount` may be
        // reclaimed 150 slots after consumption, while a challenge lives for
        // 1,500. Inside that gap the same signed quote could be submitted
        // again -- replay the public QE report to refresh the session, find
        // the nonce PDA empty, and the challenge still inside its window.
        // Marking the challenge closes that at the source, so the nonce
        // cleanup rule does not have to grow a TDX special case.
        Self::consume_tdx_challenge(challenge_acc, &challenge)?;

        Self::write_tdx_signer(
            program_id,
            payer_acc,
            system_program_acc,
            attested_signer_acc,
            &signer_pubkey,
            &journal_measurement,
            &mr_td,
            &clock,
        )
    }

    /// Write the `expires_slot == 0` tombstone onto an accepted challenge.
    /// @spec SCC-TDX-005
    fn consume_tdx_challenge(challenge_acc: &AccountInfo, challenge: &crate::state::ChallengeAccount) -> ProgramResult {
        if !challenge_acc.is_writable {
            return Err(ProgramError::InvalidAccountData);
        }
        let retired = crate::state::ChallengeAccount { expires_slot: 0, ..*challenge };
        let encoded = borsh::to_vec(&retired).map_err(|_| VerifierError::InvalidInstruction)?;
        challenge_acc.try_borrow_mut_data()?[..encoded.len()].copy_from_slice(&encoded);
        Ok(())
    }

    /// Load a live source-5 challenge.
    ///
    /// `SlotHashes` keeps roughly 512 entries, about three and a half
    /// minutes. Fetching a quote and submitting two transactions can take
    /// longer, so the slot hash is recorded up front by `issue_challenge` and
    /// read from the account here rather than from the sysvar at proof time.
    /// @spec SCC-TDX-002
    fn load_tdx_challenge(
        program_id: &Pubkey,
        challenge_acc: &AccountInfo,
        clock_slot: u64,
        nonce_slot: u64,
    ) -> Result<crate::state::ChallengeAccount, ProgramError> {
        use crate::payload::TDX_ATTESTATION_SOURCE;
        use crate::state::ChallengeAccount;

        if challenge_acc.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let challenge = ChallengeAccount::try_from_slice(&challenge_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if challenge.discriminator != ChallengeAccount::DISCRIMINATOR || challenge.source != TDX_ATTESTATION_SOURCE {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        let (expected, _) = Pubkey::find_program_address(
            &[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], &challenge.nonce],
            program_id,
        );
        Self::assert_expected_pda(challenge_acc, &expected)?;
        // Slot equality, not a range: the quote names the slot it answered.
        if challenge.challenge_slot != nonce_slot || !challenge.is_live_at(clock_slot) {
            return Err(VerifierError::StaleNonce.into());
        }
        Ok(challenge)
    }

    /// Issue a TDX challenge the enclave must answer.
    ///
    /// Without this the TDX path is unreachable from ordinary chain state:
    /// `load_tdx_challenge` requires a program-owned, initialized PDA, and no
    /// caller can sign for a PDA or write program-owned data themselves. The
    /// handler tests injected the account directly, which hid that.
    ///
    /// The caller picks the nonce, which only has to be unique because it
    /// selects the PDA. Freshness comes from `slot_hash`, read here from the
    /// SlotHashes sysvar rather than accepted from the caller: an enclave
    /// cannot pre-compute a quote for a slot hash that does not exist yet,
    /// and `load_slot_hash` already bounds the age at 150 slots and pins the
    /// sysvar's address and owner.
    ///
    /// Reissuing over a live or consumed challenge is refused. Allowing it
    /// would let a caller extend a challenge indefinitely, or resurrect one
    /// that a quote has already been accepted against.
    ///
    /// @spec SCC-TDX-005
    fn process_issue_tdx_challenge<'a>(
        program_id: &Pubkey,
        accounts: &[AccountInfo<'a>],
        rest: &[u8],
    ) -> ProgramResult {
        use crate::payload::TDX_ATTESTATION_SOURCE;
        use crate::state::ChallengeAccount;

        let args = crate::payload::parse_issue_tdx_challenge_args(rest)?;

        let [challenge_acc, payer_acc, system_program_acc, clock_acc, slot_hashes_acc, ..] = accounts else {
            return Err(VerifierError::InvalidAccountAddress.into());
        };
        Self::require_pinned_sysvar(clock_acc, &clock::ID)?;
        let clock = Clock::from_account_info(clock_acc)?;
        if !payer_acc.is_signer || !payer_acc.is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if system_program_acc.key != &system_program::ID {
            return Err(ProgramError::IncorrectProgramId);
        }

        // Authenticated, not asserted: the hash comes from the sysvar.
        let slot_hash = Self::load_slot_hash(slot_hashes_acc, args.nonce_slot, clock.slot)?;

        let (expected, bump) =
            Pubkey::find_program_address(&[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], args.nonce], program_id);
        Self::assert_expected_pda(challenge_acc, &expected)?;

        // Checked before allocation so an existing record is never clobbered.
        if challenge_acc.data_len() == ChallengeAccount::SIZE && challenge_acc.owner == program_id {
            if let Ok(existing) = ChallengeAccount::try_from_slice(&challenge_acc.try_borrow_data()?) {
                if existing.discriminator == ChallengeAccount::DISCRIMINATOR
                    && (existing.is_consumed() || existing.is_live_at(clock.slot))
                {
                    return Err(VerifierError::StaleNonce.into());
                }
            }
        }

        Self::create_pda_if_needed(
            payer_acc,
            challenge_acc,
            Some(system_program_acc),
            program_id,
            &[ChallengeAccount::SEED, &[TDX_ATTESTATION_SOURCE], args.nonce, &[bump]],
            ChallengeAccount::SIZE,
        )?;

        let record = ChallengeAccount {
            discriminator: ChallengeAccount::DISCRIMINATOR,
            source: TDX_ATTESTATION_SOURCE,
            challenge_slot: args.nonce_slot,
            slot_hash,
            nonce: *args.nonce,
            expires_slot: clock.slot.saturating_add(ChallengeAccount::TTL_SLOTS),
            bump,
        };
        let encoded = borsh::to_vec(&record).map_err(|_| VerifierError::InvalidInstruction)?;
        challenge_acc.try_borrow_mut_data()?[..encoded.len()].copy_from_slice(&encoded);
        Ok(())
    }

    /// Allocate and fill the source-5 nonce PDA at `["nonce", 5, seed]`.
    /// @spec SCC-TDX-002
    fn consume_tdx_nonce<'a>(
        program_id: &Pubkey,
        payer: &AccountInfo<'a>,
        system_program_acc: &AccountInfo<'a>,
        used_nonce: &AccountInfo<'a>,
        seed: &[u8; 32],
        clock_slot: u64,
    ) -> ProgramResult {
        use crate::payload::TDX_ATTESTATION_SOURCE;
        let (expected_nonce, nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[TDX_ATTESTATION_SOURCE], seed], program_id);
        Self::assert_expected_pda(used_nonce, &expected_nonce)?;
        if Self::nonce_already_used(used_nonce)? {
            return Err(VerifierError::NonceAlreadyUsed.into());
        }
        let nonce_bump_seed = [nonce_bump];
        Self::create_pda_if_needed(
            payer,
            used_nonce,
            Some(system_program_acc),
            program_id,
            &[b"nonce", &[TDX_ATTESTATION_SOURCE], seed, &nonce_bump_seed],
            UsedNonceAccount::SIZE,
        )?;
        Self::write_account_data(
            used_nonce,
            &UsedNonceAccount::new(clock_slot, nonce_bump).with_refund(payer.key.to_bytes()),
        )
    }

    /// Create or refresh the attested-signer record for a TDX workload.
    /// @spec SCC-TDX-002
    #[allow(clippy::too_many_arguments)]
    fn write_tdx_signer<'a>(
        program_id: &Pubkey,
        payer: &AccountInfo<'a>,
        system_program_acc: &AccountInfo<'a>,
        attested_signer: &AccountInfo<'a>,
        signer_pubkey: &[u8; 32],
        measurement: &[u8; 48],
        mr_td: &[u8; 48],
        clock: &Clock,
    ) -> ProgramResult {
        let (expected_signer, signer_bump) =
            Pubkey::find_program_address(&[b"attested_signer_v2", signer_pubkey], program_id);
        Self::assert_expected_pda(attested_signer, &expected_signer)?;

        if Self::account_has_discriminator(attested_signer, &ATTESTED_SIGNER_DISCRIMINATOR)? {
            let existing = AttestedSignerAccount::try_from_slice(&attested_signer.try_borrow_data()?)
                .map_err(|_| VerifierError::InvalidAccountAddress)?;
            // A governance tombstone outranks a fresh quote.
            if existing.is_revoked() {
                return Err(VerifierError::UnauthorizedPolicy.into());
            }
            // Re-attesting the same signer under the same backend is a
            // renewal. Anything else would silently repurpose a record a
            // consumer may already be gating on.
            let expired = clock.slot > existing.record.expires_slot;
            let matching = existing.record.signer_pubkey == *signer_pubkey
                && existing.record.enclave_type == EnclaveType::IntelTdx;
            if !expired && !matching {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
        } else {
            let signer_bump_seed = [signer_bump];
            Self::create_pda_if_needed(
                payer,
                attested_signer,
                Some(system_program_acc),
                program_id,
                &[b"attested_signer_v2", signer_pubkey, &signer_bump_seed],
                AttestedSignerAccount::SIZE,
            )?;
        }

        let mut chip_id_hash = [0u8; 32];
        chip_id_hash.copy_from_slice(&hashv(&[mr_td]).to_bytes());
        let record = AttestedSignerAccount {
            discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
            record: AttestedSigner {
                signer_pubkey: *signer_pubkey,
                enclave_type: EnclaveType::IntelTdx,
                measurement: MeasurementDigest::new(*measurement),
                chip_id_hash,
                tcb_version: 0,
                registered_slot: clock.slot,
                expires_slot: clock.slot.saturating_add(ATTESTATION_TTL_SLOTS),
            },
            bump: signer_bump,
            expires_unix_timestamp: Self::session_unix_deadline(clock.unix_timestamp, None)?,
        };
        Self::write_account_data(attested_signer, &record)?;
        Self::log_registration(b"register_signer", b"intel_tdx", signer_pubkey, attested_signer)
    }

    /// Load and bounds-check a live TDX session written by the QE step.
    /// @spec SCC-TDX-002
    fn load_tdx_session(
        program_id: &Pubkey,
        session_acc: &AccountInfo,
        attestation_pubkey: &[u8; 33],
        clock_slot: u64,
    ) -> Result<crate::state::TdxSessionAccount, ProgramError> {
        use crate::state::TdxSessionAccount;
        let session_seed = TdxSessionAccount::seed_for(attestation_pubkey);
        let (expected, _) = Pubkey::find_program_address(&[TdxSessionAccount::SEED, &session_seed], program_id);
        Self::assert_expected_pda(session_acc, &expected)?;
        if session_acc.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let session = TdxSessionAccount::try_from_slice(&session_acc.try_borrow_data()?)
            .map_err(|_| VerifierError::InvalidAccountAddress)?;
        if session.discriminator != TdxSessionAccount::DISCRIMINATOR {
            return Err(VerifierError::InvalidAccountAddress.into());
        }
        // A session is a half-finished verification. Letting it sit
        // indefinitely would allow a quote body chosen much later to be
        // matched against a certification made under earlier conditions.
        if !session.is_live_at(clock_slot) {
            return Err(VerifierError::StaleNonce.into());
        }
        Ok(session)
    }

    /// Source-5 allowlist lookup.
    /// @spec SCC-TDX-001
    fn assert_tdx_backend_policy(
        program_id: &Pubkey,
        backend_policy: &AccountInfo,
        measurement: &[u8; 48],
    ) -> ProgramResult {
        use crate::payload::TDX_ATTESTATION_SOURCE;
        use crate::state::BackendPolicy;
        let (policy_pda, _) =
            Pubkey::find_program_address(&[BackendPolicy::SEED, &[TDX_ATTESTATION_SOURCE]], program_id);
        if backend_policy.key != &policy_pda {
            return Err(VerifierError::UnauthorizedPolicy.into());
        }
        Self::assert_backend_measurement(
            program_id,
            std::slice::from_ref(backend_policy),
            TDX_ATTESTATION_SOURCE,
            measurement,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issue_205_fixtures::TestProcessor as Processor;

    use crate::payload::VerifyAndRegisterArgs;
    use solana_program::program_stubs::{set_syscall_stubs, SyscallStubs};

    #[test]
    fn issue_202_rejects_noncanonical_and_mismatched_bumps() {
        let program = Pubkey::new_unique();
        let (canonical, bump) = Pubkey::find_program_address(&[b"policy_registry"], &program);
        let (other, other_bump) = (0..bump)
            .rev()
            .find_map(|b| {
                Pubkey::create_program_address(&[b"policy_registry", &[b]], &program).ok().map(|key| (key, b))
            })
            .expect("another valid off-curve address");
        let check = |key: &Pubkey, stored: u8| {
            let mut lamports = 1;
            let mut data = [];
            let account = AccountInfo::new(key, false, false, &mut lamports, &mut data, &program, false);
            Processor::assert_pda(&account, &[b"policy_registry", &[stored]], &program)
        };
        assert_eq!(check(&canonical, bump), Ok(()));
        assert_eq!(check(&other, other_bump), Err(VerifierError::InvalidAccountAddress.into()));
        assert_eq!(check(&canonical, other_bump), Err(VerifierError::InvalidAccountAddress.into()));
        assert_eq!(check(&other, bump), Err(VerifierError::InvalidAccountAddress.into()));
    }

    fn smt_policy() -> u64 {
        1u64 << 17
    }

    mod registration_events {
        include!("../tests/support/registration_events.rs");
    }

    struct ClockSyscallStub(u64);

    impl SyscallStubs for ClockSyscallStub {
        fn sol_log_data(&self, fields: &[&[u8]]) {
            registration_events::record(fields);
        }
        fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
            let clock = Clock {
                slot: self.0,
                epoch_start_timestamp: 0,
                epoch: 0,
                leader_schedule_epoch: 0,
                unix_timestamp: 1_800_000_000,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&clock as *const Clock).cast::<u8>(),
                    var_addr,
                    core::mem::size_of::<Clock>(),
                );
            }
            0
        }
    }

    static SYSCALL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct SyscallGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<Box<dyn SyscallStubs>>,
    }

    impl SyscallGuard {
        fn install_clock(slot: u64) -> Self {
            let lock = SYSCALL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            Self { _lock: lock, previous: Some(set_syscall_stubs(Box::new(ClockSyscallStub(slot)))) }
        }
    }

    impl Drop for SyscallGuard {
        fn drop(&mut self) {
            if let Some(prev) = self.previous.take() {
                set_syscall_stubs(prev);
            }
        }
    }

    fn system_program_account<'a>(key: &'a Pubkey, lamports: &'a mut u64, data: &'a mut [u8]) -> AccountInfo<'a> {
        AccountInfo::new(key, false, false, lamports, data, key, false)
    }

    #[test]
    fn test_rejects_unknown_discriminator() {
        let ix_data = [0u8; 16];
        let pid = Pubkey::new_unique();
        let res = Processor::process(&pid, &[], &ix_data);
        assert_eq!(res, Err(VerifierError::InvalidDiscriminator.into()));
    }

    #[test]
    fn test_rejects_short_instruction_data() {
        let ix_data = [0u8; 7];
        let pid = Pubkey::new_unique();
        let res = Processor::process(&pid, &[], &ix_data);
        assert_eq!(res, Err(VerifierError::InvalidInstruction.into()));
    }

    #[test]
    fn test_verify_recent_slot_hash_success() {
        let slot_hashes_key = slot_hashes::ID;
        let mut lamports = 0u64;
        let mut data = vec![0u8; 8 + 40];
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..48].copy_from_slice(&[0xAA; 32]);

        let owner = solana_program::sysvar::ID;
        let acc = AccountInfo::new(&slot_hashes_key, false, false, &mut lamports, &mut data, &owner, false);

        let res = Processor::verify_recent_slot_hash(&acc, 120, 100, &[0xAA; 32]);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_recent_slot_hash_stale() {
        let slot_hashes_key = slot_hashes::ID;
        let mut lamports = 0u64;
        let mut data = vec![0u8; 8 + 40];
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..48].copy_from_slice(&[0xAA; 32]);

        let owner = solana_program::sysvar::ID;
        let acc = AccountInfo::new(&slot_hashes_key, false, false, &mut lamports, &mut data, &owner, false);

        let res = Processor::verify_recent_slot_hash(&acc, 251, 100, &[0xAA; 32]);
        assert_eq!(res, Err(VerifierError::StaleNonce));
    }

    #[test]
    fn test_verify_recent_slot_hash_rejects_non_sysvar_owner() {
        let slot_hashes_key = slot_hashes::ID;
        let mut lamports = 0u64;
        let mut data = vec![0u8; 8 + 40];
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[8..16].copy_from_slice(&100u64.to_le_bytes());
        data[16..48].copy_from_slice(&[0xAA; 32]);

        let owner = Pubkey::new_unique();
        let acc = AccountInfo::new(&slot_hashes_key, false, false, &mut lamports, &mut data, &owner, false);

        let res = Processor::verify_recent_slot_hash(&acc, 120, 100, &[0xAA; 32]);
        assert_eq!(res, Err(VerifierError::InvalidAccountAddress));
    }

    #[test]
    fn test_verify_recent_slot_hash_unpinned() {
        let fake_key = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 48];
        let owner = Pubkey::default();
        let acc = AccountInfo::new(&fake_key, false, false, &mut lamports, &mut data, &owner, false);

        let res = Processor::verify_recent_slot_hash(&acc, 120, 100, &[0xAA; 32]);
        assert_eq!(res, Err(VerifierError::InvalidAccountAddress));
    }

    #[test]
    fn test_init_policy_registry() {
        let pid = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let (registry_pda, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

        let mut auth_lamports = 1000;
        let mut auth_data = vec![];
        let auth_acc = AccountInfo::new(&authority_key, true, true, &mut auth_lamports, &mut auth_data, &pid, false);

        let mut reg_lamports = 1000;
        let mut reg_data = vec![0u8; PolicyRegistry::SIZE];
        let reg_acc = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports, &mut reg_data, &pid, false);

        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&INIT_POLICY_REGISTRY_DISCRIMINATOR);
        let args = InitPolicyRegistryArgs {
            authority: authority_key.to_bytes(),
            ark_pubkey_xy: [3u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 5,
            min_tcb_microcode: 10,
            measurement_count: 1,
            measurements: [[42u8; 48]; 8],
        };
        args.serialize(&mut ix_data).unwrap();

        let loader = bpf_loader_upgradeable::id();
        let (program_data_key, _) = Pubkey::find_program_address(&[pid.as_ref()], &loader);
        let mut pd_lamports = 1;
        let mut pd_data = program_data_bytes(authority_key.as_ref());
        let program_data =
            AccountInfo::new(&program_data_key, false, false, &mut pd_lamports, &mut pd_data, &loader, false);
        let system_key = system_program::id();
        let mut system_lamports = 1;
        let mut system_data = vec![];
        let system = placeholder(&system_key, &loader, &mut system_lamports, &mut system_data);
        let accounts = vec![auth_acc, reg_acc, system, program_data];
        let res = Processor::process(&pid, &accounts, &ix_data);
        assert!(res.is_ok());

        let saved = PolicyRegistry::try_from_slice(&accounts[1].try_borrow_data().unwrap()).unwrap();
        assert_eq!(saved.discriminator, POLICY_REGISTRY_DISCRIMINATOR);
        assert_eq!(saved.authority, *authority_key.as_ref());
        assert_eq!(saved.bump, bump);
        assert!(saved.is_measurement_allowed(&[42u8; 48]));
        assert!(!saved.is_measurement_allowed(&[99u8; 48]));

        // Re-initialization must fail (@spec SCC-VERIFY-005)
        let res_reinit = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res_reinit, Err(ProgramError::AccountAlreadyInitialized));

        // PR84-04: reject trailing instruction bytes
        let mut ix_trailing = ix_data.clone();
        ix_trailing.push(0xDE);
        let res_trailing = Processor::process(&pid, &accounts, &ix_trailing);
        assert_eq!(res_trailing, Err(VerifierError::InvalidInstruction.into()));
    }

    #[test]
    fn test_governance_handlers_reject_wrong_discriminator() {
        let pid = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let (registry_pda, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

        let mut auth_lamports = 1000;
        let mut auth_data = vec![];
        let auth_acc = AccountInfo::new(&authority_key, true, true, &mut auth_lamports, &mut auth_data, &pid, false);

        let mut registry = PolicyRegistry {
            discriminator: [0u8; 8],
            authority: authority_key.to_bytes(),
            ark_pubkey_xy: [3u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 3,
            measurement_count: 0,
            measurements: [[0u8; 48]; 8],
            bump,
        };
        let mut reg_lamports = 1000;
        let mut reg_data = vec![0u8; PolicyRegistry::SIZE];
        registry.serialize(&mut &mut reg_data[..]).unwrap();
        let reg_acc = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports, &mut reg_data, &pid, false);

        let mut update_ix = Vec::from(UPDATE_POLICY_DISCRIMINATOR);
        UpdatePolicyArgs {
            min_tcb_boot_loader: 9,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 3,
            measurement_count: 0,
            measurements: [[0u8; 48]; 8],
        }
        .serialize(&mut update_ix)
        .unwrap();
        let accounts = [auth_acc, reg_acc];
        assert_eq!(Processor::process(&pid, &accounts, &update_ix), Err(VerifierError::InvalidAccountAddress.into()));

        let mut rotate_ix = Vec::from(ROTATE_ROOT_CERT_DISCRIMINATOR);
        RotateRootCertArgs { new_ark_pubkey_xy: [9u8; 96] }.serialize(&mut rotate_ix).unwrap();
        assert_eq!(Processor::process(&pid, &accounts, &rotate_ix), Err(VerifierError::InvalidAccountAddress.into()));

        registry.discriminator = POLICY_REGISTRY_DISCRIMINATOR;
        registry.serialize(&mut &mut accounts[1].try_borrow_mut_data().unwrap()[..]).unwrap();
        assert!(Processor::process(&pid, &accounts, &update_ix).is_ok());
        let saved = PolicyRegistry::try_from_slice(&accounts[1].try_borrow_data().unwrap()).unwrap();
        assert_eq!(saved.discriminator, POLICY_REGISTRY_DISCRIMINATOR);
        assert_eq!(saved.min_tcb_boot_loader, 9);
    }

    #[test]
    fn test_governance_handlers_reject_foreign_registry_owner() {
        let pid = Pubkey::new_unique();
        let foreign = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let (registry_pda, bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

        let mut auth_lamports = 1000;
        let mut auth_data = vec![];
        let auth_acc = AccountInfo::new(&authority_key, true, true, &mut auth_lamports, &mut auth_data, &pid, false);

        let registry = PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: authority_key.to_bytes(),
            ark_pubkey_xy: [3u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 3,
            measurement_count: 0,
            measurements: [[0u8; 48]; 8],
            bump,
        };
        let mut reg_lamports = 1000;
        let mut reg_data = vec![0u8; PolicyRegistry::SIZE];
        registry.serialize(&mut &mut reg_data[..]).unwrap();
        let reg_acc = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports, &mut reg_data, &foreign, false);

        let mut update_ix = Vec::from(UPDATE_POLICY_DISCRIMINATOR);
        UpdatePolicyArgs {
            min_tcb_boot_loader: 9,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 3,
            measurement_count: 0,
            measurements: [[0u8; 48]; 8],
        }
        .serialize(&mut update_ix)
        .unwrap();
        let accounts = [auth_acc, reg_acc];
        assert_eq!(Processor::process(&pid, &accounts, &update_ix), Err(VerifierError::InvalidAccountAddress.into()));

        let mut rotate_ix = Vec::from(ROTATE_ROOT_CERT_DISCRIMINATOR);
        RotateRootCertArgs { new_ark_pubkey_xy: [9u8; 96] }.serialize(&mut rotate_ix).unwrap();
        assert_eq!(Processor::process(&pid, &accounts, &rotate_ix), Err(VerifierError::InvalidAccountAddress.into()));
    }

    #[test]
    fn test_init_policy_registry_rejects_unauthorized_or_mismatched_authority() {
        let pid = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let attacker_key = Pubkey::new_unique();
        let (registry_pda, _bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);

        // Case 1: authority is not a signer -> MissingRequiredSignature
        let mut auth_lamports = 1000;
        let mut auth_data = vec![];
        let auth_acc_unsigned =
            AccountInfo::new(&authority_key, false, true, &mut auth_lamports, &mut auth_data, &pid, false);
        let mut reg_lamports = 1000;
        let mut reg_data = vec![0u8; PolicyRegistry::SIZE];
        let reg_acc = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports, &mut reg_data, &pid, false);
        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&INIT_POLICY_REGISTRY_DISCRIMINATOR);
        let args = InitPolicyRegistryArgs {
            authority: authority_key.to_bytes(),
            ark_pubkey_xy: [3u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 5,
            min_tcb_microcode: 10,
            measurement_count: 1,
            measurements: [[42u8; 48]; 8],
        };
        args.serialize(&mut ix_data).unwrap();
        let res_unsigned = Processor::process(&pid, &[auth_acc_unsigned, reg_acc], &ix_data);
        assert_eq!(res_unsigned, Err(ProgramError::MissingRequiredSignature));

        // Case 2: attacker signs but sets args.authority to someone else -> InvalidAuthority
        let mut attacker_lamports = 1000;
        let mut attacker_data = vec![];
        let attacker_acc =
            AccountInfo::new(&attacker_key, true, true, &mut attacker_lamports, &mut attacker_data, &pid, false);
        let mut reg_lamports2 = 1000;
        let mut reg_data2 = vec![0u8; PolicyRegistry::SIZE];
        let reg_acc2 = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports2, &mut reg_data2, &pid, false);
        let res_mismatch = Processor::process(&pid, &[attacker_acc, reg_acc2], &ix_data);
        assert_eq!(res_mismatch, Err(VerifierError::InvalidAuthority.into()));

        // Case 3: args.authority is default pubkey (zeroes) -> InvalidAuthority
        let mut default_auth_lamports = 1000;
        let mut default_auth_data = vec![];
        let default_auth_key = Pubkey::default();
        let default_auth_acc = AccountInfo::new(
            &default_auth_key,
            true,
            true,
            &mut default_auth_lamports,
            &mut default_auth_data,
            &pid,
            false,
        );
        let mut reg_lamports3 = 1000;
        let mut reg_data3 = vec![0u8; PolicyRegistry::SIZE];
        let reg_acc3 = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports3, &mut reg_data3, &pid, false);
        let mut ix_data_default = Vec::new();
        ix_data_default.extend_from_slice(&INIT_POLICY_REGISTRY_DISCRIMINATOR);
        let mut args_default = args;
        args_default.authority = [0u8; 32];
        args_default.serialize(&mut ix_data_default).unwrap();
        let res_default = Processor::process(&pid, &[default_auth_acc, reg_acc3], &ix_data_default);
        assert_eq!(res_default, Err(VerifierError::InvalidAuthority.into()));
    }

    #[test]
    fn test_full_stage2_verify_and_register_pipeline() {
        stage2_registration_case(false);
        stage2_registration_case(true);
    }

    fn stage2_registration_case(renewal: bool) {
        let _clock = SyscallGuard::install_clock(520);
        registration_events::clear();
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use p384::ecdsa::SigningKey;
        use sha2::{Digest, Sha384};

        let pid = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let workload_pubkey = [0x99u8; 32];
        let slot_hash = [0x55u8; 32];
        let nonce_slot = 500u64;
        let current_slot = 520u64;
        let measurement = [42u8; 48];

        let mut seed = [0u8; 48];
        seed[47] = 0x07;
        let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let mut vcek_pubkey_xy = [0u8; 96];
        vcek_pubkey_xy[..48].copy_from_slice(encoded_point.x().unwrap());
        vcek_pubkey_xy[48..].copy_from_slice(encoded_point.y().unwrap());

        let mut report = [0u8; solana_confidential_compute_core::SNP_REPORT_SIZE];
        report[0..4].copy_from_slice(&1u32.to_le_bytes());
        report[8..16].copy_from_slice(&smt_policy().to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        report[0x50..0x70].copy_from_slice(&workload_pubkey);
        report[0x70..0x90].copy_from_slice(&slot_hash);
        report[0x90..0xC0].copy_from_slice(&measurement);
        report[0x180] = 1;
        report[0x181] = 0;
        report[0x186] = 2;
        report[0x187] = 5;
        let tcb_version = u64::from_le_bytes(report[0x180..0x188].try_into().unwrap());

        let chip_id_hash = hashv(&[&vcek_pubkey_xy]).to_bytes();
        let (vcek_pda, vcek_bump) =
            Pubkey::find_program_address(&[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()], &pid);

        let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let mut registry_data = vec![0u8; PolicyRegistry::SIZE];
        let registry = PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: [0u8; 32],
            ark_pubkey_xy: [0u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 5,
            measurement_count: 1,
            measurements: {
                let mut m = [[0u8; 48]; 8];
                m[0] = measurement;
                m
            },
            bump: registry_bump,
        };
        registry.serialize(&mut &mut registry_data[..]).unwrap();

        let mut vcek_data = vec![0u8; VcekAccount::SIZE];
        let vcek = VcekAccount {
            discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
            chip_id_hash,
            tcb_version,
            public_key_xy: vcek_pubkey_xy,
            registered_slot: 100,
            bump: vcek_bump,

            trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
            valid_until_unix: 1_800_000_001,
            is_revoked: false,
        };
        vcek.serialize(&mut &mut vcek_data[..]).unwrap();

        let slot_hashes_key = slot_hashes::ID;
        let mut slot_hashes_data = vec![0u8; 8 + 40];
        slot_hashes_data[0..8].copy_from_slice(&1u64.to_le_bytes());
        slot_hashes_data[8..16].copy_from_slice(&nonce_slot.to_le_bytes());
        slot_hashes_data[16..48].copy_from_slice(&slot_hash);

        let (signer_pda, signer_bump) = Pubkey::find_program_address(&[b"attested_signer_v2", &workload_pubkey], &pid);
        let (nonce_pda, nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[1], &workload_pubkey, &slot_hash], &pid);

        let mut hasher = Sha384::new();
        hasher.update(&report[0..672]);
        let digest: [u8; 48] = hasher.finalize().into();

        let (signature, _) = signing_key.sign_prehash(&digest).expect("sign succeeds");
        let sig_bytes = signature.to_bytes();
        let mut r_le = [0u8; 72];
        for i in 0..48 {
            r_le[i] = sig_bytes[47 - i];
        }
        let mut s_le = [0u8; 72];
        for i in 0..48 {
            s_le[i] = sig_bytes[95 - i];
        }
        report[0x2A0..0x2E8].copy_from_slice(&r_le);
        report[0x2E8..0x330].copy_from_slice(&s_le);

        let mut payer_lamports = 1000;
        let mut payer_data = vec![];
        let payer_acc = AccountInfo::new(&payer_key, true, true, &mut payer_lamports, &mut payer_data, &pid, false);

        let mut signer_lamports = 1000;
        let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
        AttestedSignerAccount {
            discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
            record: AttestedSigner {
                signer_pubkey: workload_pubkey,
                enclave_type: EnclaveType::AwsNitro,
                measurement: MeasurementDigest::new(measurement),
                chip_id_hash: [0u8; 32],
                tcb_version: 0,
                registered_slot: current_slot,
                expires_slot: current_slot + 1_000,
            },
            bump: 0,
            expires_unix_timestamp: i64::MAX,
        }
        .serialize(&mut &mut signer_data[..])
        .unwrap();
        let signer_acc =
            AccountInfo::new(&signer_pda, false, true, &mut signer_lamports, &mut signer_data, &pid, false);

        let mut vcek_lamports = 1000;
        let vcek_acc = AccountInfo::new(&vcek_pda, false, false, &mut vcek_lamports, &mut vcek_data, &pid, false);

        let mut reg_lamports = 1000;
        let reg_acc = AccountInfo::new(&registry_pda, false, false, &mut reg_lamports, &mut registry_data, &pid, false);

        let mut nonce_lamports = 1000;
        let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
        let nonce_acc = AccountInfo::new(&nonce_pda, false, true, &mut nonce_lamports, &mut nonce_data, &pid, false);

        let mut sh_lamports = 1000;
        let sh_acc = AccountInfo::new(
            &slot_hashes_key,
            false,
            false,
            &mut sh_lamports,
            &mut slot_hashes_data,
            &solana_program::sysvar::ID,
            false,
        );

        let mut clock_lamports = 1000;
        let mut clock_data = vec![0u8; 40];
        clock_data[0..8].copy_from_slice(&current_slot.to_le_bytes());
        clock_data[32..40].copy_from_slice(&1_800_000_000i64.to_le_bytes());
        let clock_key = clock::ID;
        let clock_acc = AccountInfo::new(
            &clock_key,
            false,
            false,
            &mut clock_lamports,
            &mut clock_data,
            &solana_program::sysvar::ID,
            false,
        );

        let sys_key = system_program::ID;
        let mut sys_lamports = 1;
        let mut sys_data = vec![];
        let sys_acc = system_program_account(&sys_key, &mut sys_lamports, &mut sys_data);

        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
        let args = VerifyAndRegisterArgs { nonce_slot, report };
        args.serialize(&mut ix_data).unwrap();
        ix_data.push(nonce_bump);
        ix_data.push(signer_bump);

        let workload_key = Pubkey::new_from_array(workload_pubkey);
        let mut workload_lamports = 1;
        let mut workload_data = [];
        let workload_acc =
            AccountInfo::new(&workload_key, true, false, &mut workload_lamports, &mut workload_data, &pid, false);
        let mut accounts = vec![
            payer_acc,
            reg_acc,
            vcek_acc,
            signer_acc.clone(),
            nonce_acc.clone(),
            sh_acc,
            clock_acc,
            sys_acc,
            workload_acc,
        ];

        // Consent must be checked before either registration or nonce mutation.
        let foreign_before = signer_acc.try_borrow_data().unwrap().to_vec();
        signer_acc.try_borrow_mut_data().unwrap().fill(0);
        if renewal {
            let mut existing = AttestedSignerAccount::try_from_slice(&foreign_before).unwrap();
            existing.record.enclave_type = EnclaveType::AmdSevSnp;
            existing.serialize(&mut &mut signer_acc.try_borrow_mut_data().unwrap()[..]).unwrap();
        }
        let signer_before = signer_acc.try_borrow_data().unwrap().to_vec();
        let nonce_before = nonce_acc.try_borrow_data().unwrap().to_vec();
        accounts[8].is_signer = false;
        assert_eq!(Processor::process(&pid, &accounts, &ix_data), Err(ProgramError::MissingRequiredSignature));
        let workload = accounts.pop().unwrap();
        assert_eq!(Processor::process(&pid, &accounts, &ix_data), Err(VerifierError::SignerMismatch.into()));
        assert_eq!(*signer_acc.try_borrow_data().unwrap(), signer_before);
        assert_eq!(*nonce_acc.try_borrow_data().unwrap(), nonce_before);
        accounts.push(workload);
        accounts[8].is_signer = true;
        signer_acc.try_borrow_mut_data().unwrap().copy_from_slice(&foreign_before);

        let mut wrong_bump = ix_data.clone();
        let bump_at = wrong_bump.len() - 1;
        wrong_bump[bump_at] ^= 0xff;
        assert_eq!(Processor::process(&pid, &accounts, &wrong_bump), Err(VerifierError::InvalidAccountAddress.into()));

        let foreign = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(foreign, Err(ProgramError::AccountAlreadyInitialized));
        signer_acc.try_borrow_mut_data().unwrap().fill(0);

        if renewal {
            signer_acc.try_borrow_mut_data().unwrap().copy_from_slice(&signer_before);
        }
        // A legacy governance revocation must survive fresh, correctly signed
        // evidence, workload consent and an otherwise unused nonce.
        let before = signer_acc.try_borrow_data().unwrap().to_vec();
        let mut revoked = AttestedSignerAccount::try_from_slice(&foreign_before).unwrap();
        revoked.record.enclave_type = EnclaveType::AmdSevSnp;
        revoked.record.expires_slot = 0;
        // Old revocations retained their Unix deadline: recognize them too.
        revoked.expires_unix_timestamp = 86_400;
        revoked.serialize(&mut &mut signer_acc.try_borrow_mut_data().unwrap()[..]).unwrap();
        let tombstone = signer_acc.try_borrow_data().unwrap().to_vec();
        let nonce_before = nonce_acc.try_borrow_data().unwrap().to_vec();
        assert_eq!(Processor::process(&pid, &accounts, &ix_data), Err(VerifierError::UnauthorizedPolicy.into()));
        assert_eq!(*signer_acc.try_borrow_data().unwrap(), tombstone);
        assert_eq!(*nonce_acc.try_borrow_data().unwrap(), nonce_before);
        signer_acc.try_borrow_mut_data().unwrap().copy_from_slice(&before);
        registration_events::assert_empty();
        let res = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res, Ok(()));
        registration_events::assert_event(b"register_signer", b"amd_sev_snp", &workload_pubkey, &signer_acc);

        let saved_signer = AttestedSignerAccount::try_from_slice(&signer_acc.try_borrow_data().unwrap()).unwrap();
        assert_eq!(saved_signer.discriminator, ATTESTED_SIGNER_DISCRIMINATOR);
        assert_eq!(saved_signer.bump, signer_bump);
        assert_eq!(saved_signer.record.signer_pubkey, workload_pubkey);
        assert_eq!(saved_signer.record.enclave_type, EnclaveType::AmdSevSnp);
        assert_eq!(saved_signer.record.registered_slot, current_slot);
        assert_eq!(saved_signer.record.expires_slot, current_slot + ATTESTATION_TTL_SLOTS);
        assert_eq!(saved_signer.expires_unix_timestamp, 1_800_000_001);
        assert!(!saved_signer.record.is_expired(current_slot + 100));
        assert!(saved_signer.record.is_expired(current_slot + ATTESTATION_TTL_SLOTS + 1));

        let saved_nonce = UsedNonceAccount::try_from_slice(&nonce_acc.try_borrow_data().unwrap()).unwrap();
        assert_eq!(saved_nonce.discriminator, USED_NONCE_DISCRIMINATOR);
        assert_eq!(saved_nonce.slot, current_slot);

        let original_cache = accounts[2].try_borrow_data().unwrap().to_vec();
        for kind in 0..3 {
            {
                let mut cache = accounts[2].try_borrow_mut_data().unwrap();
                if kind == 0 {
                    cache[VcekAccount::VALID_UNTIL_OFFSET..VcekAccount::VALID_UNTIL_OFFSET + 8]
                        .copy_from_slice(&0u64.to_le_bytes());
                }
                if kind == 1 {
                    cache[VcekAccount::REVOKED_OFFSET] = 1;
                }
                if kind == 2 {
                    cache[VcekAccount::TRUST_PROFILE_OFFSET..VcekAccount::TRUST_PROFILE_OFFSET + 32].fill(0);
                }
            }
            assert_eq!(Processor::process(&pid, &accounts, &ix_data), Err(VerifierError::UnauthorizedPolicy.into()));
            accounts[2].try_borrow_mut_data().unwrap().copy_from_slice(&original_cache);
        }

        let res_replay = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res_replay, Err(VerifierError::NonceAlreadyUsed.into()));
        registration_events::assert_empty();
    }

    fn dummy_clock_account<'a>(key: &'a Pubkey, lamports: &'a mut u64, data: &'a mut [u8]) -> AccountInfo<'a> {
        data[0..8].copy_from_slice(&100u64.to_le_bytes());
        AccountInfo::new(key, false, false, lamports, data, &solana_program::sysvar::ID, false)
    }

    #[test]
    fn test_stage2_rejects_debug_mode() {
        let pid = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let mut report = [0u8; solana_confidential_compute_core::SNP_REPORT_SIZE];
        report[0..4].copy_from_slice(&1u32.to_le_bytes());
        let debug_policy = 1u64 << 19;
        report[8..16].copy_from_slice(&debug_policy.to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        report[0x90..0xC0].copy_from_slice(&[42u8; 48]);

        let mut payer_lamports = 1000;
        let mut payer_data = vec![];
        let payer_acc = AccountInfo::new(&payer_key, true, true, &mut payer_lamports, &mut payer_data, &pid, false);

        let dummy_key = Pubkey::new_unique();
        let mut d_lamports = 1000;
        let mut d_data = vec![0u8; 200];
        let dummy_acc = AccountInfo::new(&dummy_key, false, true, &mut d_lamports, &mut d_data, &pid, false);

        let clock_key = clock::ID;
        let mut clock_lamports = 1000;
        let mut clock_data = vec![0u8; 40];
        let clock_acc = dummy_clock_account(&clock_key, &mut clock_lamports, &mut clock_data);

        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
        let args = VerifyAndRegisterArgs { nonce_slot: 100, report };
        args.serialize(&mut ix_data).unwrap();
        ix_data.extend_from_slice(&[0, 0]);

        let accounts = vec![
            payer_acc,
            dummy_acc.clone(),
            dummy_acc.clone(),
            dummy_acc.clone(),
            dummy_acc.clone(),
            dummy_acc.clone(),
            clock_acc,
            dummy_acc,
        ];
        let res = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res, Err(VerifierError::UnauthorizedPolicy.into()));
    }

    #[test]
    fn test_stage2_rejects_zero_measurement() {
        let pid = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let mut report = [0u8; solana_confidential_compute_core::SNP_REPORT_SIZE];
        report[0..4].copy_from_slice(&1u32.to_le_bytes());
        report[8..16].copy_from_slice(&smt_policy().to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let mut payer_lamports = 1000;
        let mut payer_data = vec![];
        let payer_acc = AccountInfo::new(&payer_key, true, true, &mut payer_lamports, &mut payer_data, &pid, false);

        let dummy_key = Pubkey::new_unique();
        let mut d_lamports = 1000;
        let mut d_data = vec![0u8; 200];
        let dummy_acc = AccountInfo::new(&dummy_key, false, true, &mut d_lamports, &mut d_data, &pid, false);

        let clock_key = clock::ID;
        let mut clock_lamports = 1000;
        let mut clock_data = vec![0u8; 40];
        let clock_acc = dummy_clock_account(&clock_key, &mut clock_lamports, &mut clock_data);

        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
        let args = VerifyAndRegisterArgs { nonce_slot: 100, report };
        args.serialize(&mut ix_data).unwrap();
        ix_data.extend_from_slice(&[0, 0]);

        let accounts = vec![
            payer_acc,
            dummy_acc.clone(),
            dummy_acc.clone(),
            dummy_acc.clone(),
            dummy_acc.clone(),
            dummy_acc.clone(),
            clock_acc,
            dummy_acc,
        ];
        let res = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res, Err(VerifierError::DisallowedMeasurement.into()));

        ix_data.push(0xff);
        let res = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res, Err(VerifierError::InvalidInstruction.into()));
    }

    fn test_keypair(seed_lsb: u8) -> (p384::ecdsa::SigningKey, [u8; 96]) {
        let mut seed = [0u8; 48];
        seed[47] = seed_lsb;
        let signing_key = p384::ecdsa::SigningKey::from_slice(&seed).expect("valid scalar");
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let mut xy = [0u8; 96];
        xy[..48].copy_from_slice(encoded.x().unwrap().as_slice());
        xy[48..].copy_from_slice(encoded.y().unwrap().as_slice());
        (signing_key, xy)
    }

    fn acc<'a>(key: &'a Pubkey, lamports: &'a mut u64, data: &'a mut [u8], owner: &'a Pubkey) -> AccountInfo<'a> {
        AccountInfo::new(key, false, false, lamports, data, owner, false)
    }

    fn serialize_instructions(ixs: &[(Pubkey, &[u8])], current_index: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(ixs.len() as u16).to_le_bytes());
        let offsets_at = data.len();
        data.extend(vec![0u8; ixs.len() * 2]);
        for (i, (program_id, ix_data)) in ixs.iter().enumerate() {
            let offset = data.len() as u16;
            let start = offsets_at + i * 2;
            data[start..start + 2].copy_from_slice(&offset.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(program_id.as_ref());
            data.extend_from_slice(&(ix_data.len() as u16).to_le_bytes());
            data.extend_from_slice(ix_data);
        }
        data.extend_from_slice(&current_index.to_le_bytes());
        data
    }

    fn sign_snp_report(report: &mut [u8; 1184], seed_lsb: u8) -> [u8; 96] {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha384};
        let (signing_key, xy) = test_keypair(seed_lsb);
        let mut hasher = Sha384::new();
        hasher.update(&report[0..672]);
        let digest: [u8; 48] = hasher.finalize().into();
        let (signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = signature.to_bytes();
        for i in 0..48 {
            report[0x2A0 + i] = sig_bytes[47 - i];
            report[0x2E8 + i] = sig_bytes[95 - i];
        }
        xy
    }

    #[test]
    fn test_verify_atomic_requires_nonce() {
        let pid = Pubkey::new_unique();
        let mut ix = Vec::from(VERIFY_ATOMIC_DISCRIMINATOR);
        ix.extend_from_slice(&[0u8; 16]);
        assert_eq!(Processor::process(&pid, &[], &ix), Err(VerifierError::NonceRequired.into()));
    }

    #[test]
    fn test_verify_atomic_with_nonce_happy_mismatch_and_replay() {
        let pid = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let consumer = Pubkey::new_unique();
        let workload_pubkey = [0x99u8; 32];
        let slot_hash = [0x55u8; 32];
        let action_hash =
            solana_confidential_compute_core::action::hash_action_parts(&[], 0, core::iter::empty(), &[0u8; 4]);
        let nonce_slot = 500u64;
        let current_slot = 520u64;
        let measurement = [42u8; 48];
        let commitment = compute_action_commitment(&slot_hash, &action_hash, &consumer.to_bytes());

        let mut report = [0u8; solana_confidential_compute_core::SNP_REPORT_SIZE];
        report[0..4].copy_from_slice(&1u32.to_le_bytes());
        report[8..16].copy_from_slice(&smt_policy().to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        report[0x50..0x70].copy_from_slice(&workload_pubkey);
        report[0x70..0x90].copy_from_slice(&commitment);
        report[0x90..0xC0].copy_from_slice(&measurement);
        report[0x180] = 1;
        report[0x186] = 2;
        report[0x187] = 5;
        let tcb_version = u64::from_le_bytes(report[0x180..0x188].try_into().unwrap());
        let vcek_xy = sign_snp_report(&mut report, 0x07);
        let chip_id_hash = hashv(&[&vcek_xy]).to_bytes();
        let (vcek_pda, vcek_bump) =
            Pubkey::find_program_address(&[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()], &pid);
        let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let (nonce_pda, nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[1], &workload_pubkey, &commitment], &pid);

        let mut measurements = [[0u8; 48]; 8];
        measurements[0] = measurement;
        let mut registry_data = vec![0u8; PolicyRegistry::SIZE];
        PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: [0u8; 32],
            ark_pubkey_xy: [0u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 5,
            measurement_count: 1,
            measurements,
            bump: registry_bump,
        }
        .serialize(&mut &mut registry_data[..])
        .unwrap();
        let mut vcek_data = vec![0u8; VcekAccount::SIZE];
        VcekAccount {
            discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
            chip_id_hash,
            tcb_version,
            public_key_xy: vcek_xy,
            registered_slot: 100,
            bump: vcek_bump,

            trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
            valid_until_unix: u64::MAX,
            is_revoked: false,
        }
        .serialize(&mut &mut vcek_data[..])
        .unwrap();
        let slot_hashes_key = slot_hashes::ID;
        let mut slot_hashes_data = vec![0u8; 8 + 40];
        slot_hashes_data[0..8].copy_from_slice(&1u64.to_le_bytes());
        slot_hashes_data[8..16].copy_from_slice(&nonce_slot.to_le_bytes());
        slot_hashes_data[16..48].copy_from_slice(&slot_hash);
        let clock_key = clock::ID;
        let mut clock_data = vec![0u8; 40];
        clock_data[0..8].copy_from_slice(&current_slot.to_le_bytes());
        let sys_key = system_program::ID;
        let mut sys_data = vec![];
        let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
        let mut payer_data = vec![];

        let mut ix_ok = Vec::from(VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
        VerifyAtomicHeader { nonce_slot, action_hash, consumer_program_id: consumer.to_bytes() }
            .serialize(&mut ix_ok)
            .unwrap();
        ix_ok.extend_from_slice(&report);
        ix_ok.push(nonce_bump);
        let mut ix_bad = Vec::from(VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
        VerifyAtomicHeader { nonce_slot, action_hash: [0x22u8; 32], consumer_program_id: consumer.to_bytes() }
            .serialize(&mut ix_bad)
            .unwrap();
        ix_bad.extend_from_slice(&report);
        ix_bad.push(nonce_bump);

        let ix_key = instructions::ID;
        let mut ix_sysvar = serialize_instructions(&[(pid, ix_ok.as_slice()), (consumer, &[0u8; 4])], 0);
        let mut ix_lp = 1u64;
        let mut p_lp = 1_000u64;
        let mut r_lp = 1u64;
        let mut v_lp = 1u64;
        let mut n_lp = 1u64;
        let mut s_lp = 1u64;
        let mut c_lp = 1u64;
        let mut sys_lp = 1u64;
        let accounts = [
            AccountInfo::new(&payer_key, true, true, &mut p_lp, &mut payer_data, &pid, false),
            acc(&registry_pda, &mut r_lp, &mut registry_data, &pid),
            acc(&vcek_pda, &mut v_lp, &mut vcek_data, &pid),
            AccountInfo::new(&nonce_pda, false, true, &mut n_lp, &mut nonce_data, &pid, false),
            acc(&slot_hashes_key, &mut s_lp, &mut slot_hashes_data, &solana_program::sysvar::ID),
            acc(&clock_key, &mut c_lp, &mut clock_data, &solana_program::sysvar::ID),
            system_program_account(&sys_key, &mut sys_lp, &mut sys_data),
            acc(&ix_key, &mut ix_lp, &mut ix_sysvar, &ix_key),
        ];
        assert_eq!(
            Processor::process(&pid, &accounts[..accounts.len() - 1], &ix_bad),
            Err(ProgramError::NotEnoughAccountKeys)
        );
        assert_eq!(Processor::process(&pid, &accounts, &ix_bad), Err(VerifierError::ActionHashMismatch.into()));
        let mut trailing = ix_ok.clone();
        trailing.push(0);
        assert_eq!(Processor::process(&pid, &accounts, &trailing), Err(VerifierError::InvalidInstruction.into()));
        let mut wrong_bump = ix_ok.clone();
        let bump_at = wrong_bump.len() - 1;
        wrong_bump[bump_at] ^= 0xff;
        assert_eq!(Processor::process(&pid, &accounts, &wrong_bump), Err(VerifierError::InvalidAccountAddress.into()));
        assert!(Processor::process(&pid, &accounts, &ix_ok).is_ok());
        assert_eq!(Processor::process(&pid, &accounts, &ix_ok), Err(VerifierError::NonceAlreadyUsed.into()));
    }
    #[test]
    fn test_vlek_report_with_nonzero_chip_id_resolves_pubkey_seed() {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use p384::ecdsa::SigningKey;
        use sha2::{Digest, Sha384};

        let pid = Pubkey::new_unique();
        let workload_pubkey = [0x77u8; 32];
        // A workload that pays also provides the required consent without an extra meta.
        let payer_key = Pubkey::new_from_array(workload_pubkey);
        let slot_hash = [0x88u8; 32];
        let nonce_slot = 500u64;
        let current_slot = 520u64;
        let measurement = [33u8; 48];
        let chip_id = [0x55u8; 64];

        let mut seed = [0u8; 48];
        seed[47] = 0x09;
        let signing_key = SigningKey::from_slice(&seed).expect("valid scalar");
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let mut vcek_pubkey_xy = [0u8; 96];
        vcek_pubkey_xy[..48].copy_from_slice(encoded_point.x().unwrap());
        vcek_pubkey_xy[48..].copy_from_slice(encoded_point.y().unwrap());

        let mut report = [0u8; solana_confidential_compute_core::SNP_REPORT_SIZE];
        report[0..4].copy_from_slice(&1u32.to_le_bytes());
        report[8..16].copy_from_slice(&smt_policy().to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        // FLAGS word 4 = SIGNING_KEY 1 (VLEK)
        report[0x48..0x4C].copy_from_slice(&4u32.to_le_bytes());
        report[0x50..0x70].copy_from_slice(&workload_pubkey);
        report[0x70..0x90].copy_from_slice(&slot_hash);
        report[0x90..0xC0].copy_from_slice(&measurement);
        report[0x180] = 1;
        report[0x181] = 0;
        report[0x186] = 2;
        report[0x187] = 5;
        report[0x1A0..0x1E0].copy_from_slice(&chip_id);
        let tcb_version = u64::from_le_bytes(report[0x180..0x188].try_into().unwrap());

        // key_sel == 1 is a VLEK even when chip_id is non-zero.
        // @spec SCC-VERIFY-009
        let chip_id_hash = hashv(&[&vcek_pubkey_xy]).to_bytes();
        let (vcek_pda, vcek_bump) =
            Pubkey::find_program_address(&[b"vcek_v2", &chip_id_hash, &tcb_version.to_le_bytes()], &pid);

        let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let mut registry_data = vec![0u8; PolicyRegistry::SIZE];
        let registry = PolicyRegistry {
            discriminator: POLICY_REGISTRY_DISCRIMINATOR,
            authority: [0u8; 32],
            ark_pubkey_xy: [0u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 2,
            min_tcb_microcode: 5,
            measurement_count: 1,
            measurements: {
                let mut m = [[0u8; 48]; 8];
                m[0] = measurement;
                m
            },
            bump: registry_bump,
        };
        registry.serialize(&mut &mut registry_data[..]).unwrap();

        let mut vcek_data = vec![0u8; VcekAccount::SIZE];
        let vcek = VcekAccount {
            discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
            chip_id_hash,
            tcb_version,
            public_key_xy: vcek_pubkey_xy,
            registered_slot: 100,
            bump: vcek_bump,

            trust_profile: VcekAccount::MILAN_TRUST_PROFILE,
            valid_until_unix: u64::MAX,
            is_revoked: false,
        };
        vcek.serialize(&mut &mut vcek_data[..]).unwrap();

        let slot_hashes_key = slot_hashes::ID;
        let mut slot_hashes_data = vec![0u8; 8 + 40];
        slot_hashes_data[0..8].copy_from_slice(&1u64.to_le_bytes());
        slot_hashes_data[8..16].copy_from_slice(&nonce_slot.to_le_bytes());
        slot_hashes_data[16..48].copy_from_slice(&slot_hash);

        let (signer_pda, signer_bump) = Pubkey::find_program_address(&[b"attested_signer_v2", &workload_pubkey], &pid);
        let (nonce_pda, nonce_bump) =
            Pubkey::find_program_address(&[b"nonce", &[1], &workload_pubkey, &slot_hash], &pid);

        let mut hasher = Sha384::new();
        hasher.update(&report[0..672]);
        let digest: [u8; 48] = hasher.finalize().into();

        let (signature, _) = signing_key.sign_prehash(&digest).expect("sign succeeds");
        let sig_bytes = signature.to_bytes();
        let mut r_le = [0u8; 72];
        for i in 0..48 {
            r_le[i] = sig_bytes[47 - i];
        }
        let mut s_le = [0u8; 72];
        for i in 0..48 {
            s_le[i] = sig_bytes[95 - i];
        }
        report[0x2A0..0x2E8].copy_from_slice(&r_le);
        report[0x2E8..0x330].copy_from_slice(&s_le);

        let mut payer_lamports = 1000;
        let mut payer_data = vec![];
        let payer_acc = AccountInfo::new(&payer_key, true, true, &mut payer_lamports, &mut payer_data, &pid, false);

        let mut reg_lamports = 1000;
        let reg_acc = AccountInfo::new(&registry_pda, false, false, &mut reg_lamports, &mut registry_data, &pid, false);

        let mut v_lamports = 1000;
        let vcek_account = AccountInfo::new(&vcek_pda, false, false, &mut v_lamports, &mut vcek_data, &pid, false);

        let mut signer_lamports = 1000;
        let mut signer_data = vec![0u8; AttestedSignerAccount::SIZE];
        let signer_acc =
            AccountInfo::new(&signer_pda, false, true, &mut signer_lamports, &mut signer_data, &pid, false);

        let mut nonce_lamports = 1000;
        let mut nonce_data = vec![0u8; UsedNonceAccount::SIZE];
        let nonce_acc = AccountInfo::new(&nonce_pda, false, true, &mut nonce_lamports, &mut nonce_data, &pid, false);

        let mut sh_lamports = 1000;
        let sh_acc = AccountInfo::new(
            &slot_hashes_key,
            false,
            false,
            &mut sh_lamports,
            &mut slot_hashes_data,
            &solana_program::sysvar::ID,
            false,
        );

        let mut clock_lamports = 1000;
        let mut clock_data = vec![0u8; 40];
        clock_data[0..8].copy_from_slice(&current_slot.to_le_bytes());
        let clock_key = clock::ID;
        let clock_acc = AccountInfo::new(
            &clock_key,
            false,
            false,
            &mut clock_lamports,
            &mut clock_data,
            &solana_program::sysvar::ID,
            false,
        );

        let sys_key = system_program::ID;
        let mut sys_lamports = 1;
        let mut sys_data = vec![];
        let sys_acc = system_program_account(&sys_key, &mut sys_lamports, &mut sys_data);

        let mut ix_data = Vec::new();
        ix_data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
        let args = VerifyAndRegisterArgs { nonce_slot, report };
        args.serialize(&mut ix_data).unwrap();
        ix_data.push(nonce_bump);
        ix_data.push(signer_bump);

        let accounts = vec![payer_acc, reg_acc, vcek_account, signer_acc, nonce_acc, sh_acc, clock_acc, sys_acc];

        let res = Processor::process(&pid, &accounts, &ix_data);
        assert_eq!(res, Ok(()), "VLEK report with non-zero chip_id should resolve from the public key");
    }

    fn placeholder<'a>(
        key: &'a Pubkey,
        owner: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
    ) -> AccountInfo<'a> {
        AccountInfo::new(key, false, true, lamports, data, owner, false)
    }

    fn clock_with_timestamp<'a>(
        owner: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
        unix_timestamp: i64,
    ) -> AccountInfo<'a> {
        data[32..40].copy_from_slice(&unix_timestamp.to_le_bytes());
        AccountInfo::new(&clock::ID, false, false, lamports, data, owner, false)
    }

    #[test]
    fn test_rejects_non_sysvar_clock_owner() {
        let pid = Pubkey::new_unique();
        let foreign = Pubkey::new_unique();
        let dummy_key = Pubkey::new_unique();
        let mut dummy_lamports = 1u64;
        let mut dummy_data = vec![0u8; 8];
        let dummy = placeholder(&dummy_key, &pid, &mut dummy_lamports, &mut dummy_data);

        let mut clock_lamports = 1u64;
        let mut clock_data = vec![0u8; 40];
        let clock_acc = clock_with_timestamp(&foreign, &mut clock_lamports, &mut clock_data, 0);

        let mut verify_ix = Vec::from(VERIFY_AND_REGISTER_DISCRIMINATOR);
        verify_ix.extend(vec![0u8; 8 + SNP_REPORT_SIZE + 2]);
        let verify_accounts = vec![
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            clock_acc.clone(),
            dummy.clone(),
        ];
        assert_eq!(
            Processor::process(&pid, &verify_accounts, &verify_ix),
            Err(VerifierError::InvalidAccountAddress.into())
        );

        let atomic_accounts = vec![
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            clock_acc.clone(),
            dummy.clone(),
        ];
        assert_eq!(
            Processor::process(&pid, &atomic_accounts, &VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR),
            Err(VerifierError::InvalidAccountAddress.into())
        );

        let mut jwt_ix = Vec::from(VERIFY_GOOGLE_JWT_DISCRIMINATOR);
        jwt_ix.extend(vec![0u8; 45]);
        jwt_ix[8] = VERIFY_GOOGLE_JWT_MODE_A;
        let jwt_accounts = vec![
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            clock_acc.clone(),
            dummy.clone(),
        ];
        assert_eq!(Processor::process(&pid, &jwt_accounts, &jwt_ix), Err(VerifierError::InvalidAccountAddress.into()));

        let mut nitro_ix = Vec::from(VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
        nitro_ix.extend(vec![0u8; 46]);
        nitro_ix[8] = VERIFY_NITRO_MODE_A;
        nitro_ix[49..53].copy_from_slice(&1u32.to_le_bytes());
        let nitro_accounts =
            vec![dummy.clone(), dummy.clone(), dummy.clone(), dummy.clone(), dummy.clone(), clock_acc, dummy.clone()];
        assert_eq!(
            Processor::process(&pid, &nitro_accounts, &nitro_ix),
            Err(VerifierError::InvalidAccountAddress.into())
        );
    }

    #[test]
    fn test_rejects_negative_unix_timestamp() {
        let pid = Pubkey::new_unique();
        let sysvar_owner = solana_program::sysvar::ID;
        let dummy_key = Pubkey::new_unique();
        let mut dummy_lamports = 1u64;
        let mut dummy_data = vec![0u8; 8];
        let dummy = placeholder(&dummy_key, &pid, &mut dummy_lamports, &mut dummy_data);

        let mut clock_lamports = 1u64;
        let mut clock_data = vec![0u8; 40];
        let clock_acc = clock_with_timestamp(&sysvar_owner, &mut clock_lamports, &mut clock_data, -1);

        let mut jwt_ix = Vec::from(VERIFY_GOOGLE_JWT_DISCRIMINATOR);
        jwt_ix.extend(vec![0u8; 45]);
        jwt_ix[8] = VERIFY_GOOGLE_JWT_MODE_A;
        let jwt_accounts = vec![
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            dummy.clone(),
            clock_acc.clone(),
            dummy.clone(),
        ];
        assert_eq!(Processor::process(&pid, &jwt_accounts, &jwt_ix), Err(VerifierError::InvalidInstruction.into()));

        let mut nitro_ix = Vec::from(VERIFY_NITRO_ATTESTATION_DISCRIMINATOR);
        nitro_ix.extend(vec![0u8; 46]);
        nitro_ix[8] = VERIFY_NITRO_MODE_A;
        nitro_ix[49..53].copy_from_slice(&1u32.to_le_bytes());
        let nitro_accounts =
            vec![dummy.clone(), dummy.clone(), dummy.clone(), dummy.clone(), dummy.clone(), clock_acc, dummy];
        assert_eq!(Processor::process(&pid, &nitro_accounts, &nitro_ix), Err(VerifierError::InvalidInstruction.into()));
    }

    #[test]
    fn test_register_vcek_rejects_foreign_registry_owner() {
        let pid = Pubkey::new_unique();
        let foreign = Pubkey::new_unique();
        let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let payer_key = Pubkey::new_unique();
        let vcek_key = Pubkey::new_unique();
        let sys_key = Pubkey::new_unique();
        let mut payer_lamports = 1u64;
        let mut reg_lamports = 1u64;
        let mut vcek_lamports = 1u64;
        let mut sys_lamports = 1u64;
        let mut payer_data = vec![0u8; 1];
        let mut reg_data = vec![0u8; 8];
        let mut vcek_data = vec![0u8; 8];
        let mut sys_data = vec![0u8; 1];
        let accounts = [
            placeholder(&payer_key, &pid, &mut payer_lamports, &mut payer_data),
            placeholder(&registry_pda, &foreign, &mut reg_lamports, &mut reg_data),
            placeholder(&vcek_key, &pid, &mut vcek_lamports, &mut vcek_data),
            placeholder(&sys_key, &pid, &mut sys_lamports, &mut sys_data),
        ];
        let mut ix = Vec::from(REGISTER_VCEK_DISCRIMINATOR);
        RegisterVcekArgs {
            chip_id: [0u8; 64],
            tcb_version: 0,
            public_key_xy: [0u8; 96],
            ask_cert_len: 0,
            vcek_cert_len: 0,
        }
        .serialize(&mut ix)
        .unwrap();
        assert_eq!(Processor::process(&pid, &accounts, &ix), Err(VerifierError::InvalidAccountAddress.into()));
    }

    #[test]
    fn test_assert_registry_authority_rejects_foreign_owner() {
        let pid = Pubkey::new_unique();
        let foreign = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let jwks_key = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let sys_key = Pubkey::new_unique();
        let mut auth_lamports = 1u64;
        let mut reg_lamports = 1u64;
        let mut jwks_lamports = 1u64;
        let mut payer_lamports = 1u64;
        let mut sys_lamports = 1u64;
        let mut auth_data = vec![];
        let mut reg_data = vec![0u8; 8];
        let mut jwks_data = vec![0u8; 8];
        let mut payer_data = vec![];
        let mut sys_data = vec![];
        let authority = AccountInfo::new(&authority_key, true, true, &mut auth_lamports, &mut auth_data, &pid, false);
        let accounts = [
            authority,
            placeholder(&registry_pda, &foreign, &mut reg_lamports, &mut reg_data),
            placeholder(&jwks_key, &pid, &mut jwks_lamports, &mut jwks_data),
            placeholder(&payer_key, &pid, &mut payer_lamports, &mut payer_data),
            placeholder(&sys_key, &pid, &mut sys_lamports, &mut sys_data),
        ];
        let mut ix = Vec::from(REGISTER_JWKS_KEY_DISCRIMINATOR);
        RegisterJwksKeyArgs { kid: vec![1], modulus: [2u8; 256], exponent: 65537 }.serialize(&mut ix).unwrap();
        assert_eq!(Processor::process(&pid, &accounts, &ix), Err(VerifierError::InvalidAccountAddress.into()));
    }

    fn program_data_bytes(authority: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 45];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[12] = 1;
        data[13..45].copy_from_slice(authority);
        data
    }

    #[test]
    fn test_init_policy_registry_binds_upgrade_authority() {
        let pid = Pubkey::new_unique();
        let authority_key = Pubkey::new_unique();
        let (registry_pda, _) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
        let (program_data_key, _) = Pubkey::find_program_address(&[pid.as_ref()], &bpf_loader_upgradeable::id());
        let loader = bpf_loader_upgradeable::id();

        let mut ix = Vec::from(INIT_POLICY_REGISTRY_DISCRIMINATOR);
        InitPolicyRegistryArgs {
            authority: authority_key.to_bytes(),
            ark_pubkey_xy: [3u8; 96],
            min_tcb_boot_loader: 1,
            min_tcb_tee: 0,
            min_tcb_snp: 5,
            min_tcb_microcode: 10,
            measurement_count: 0,
            measurements: [[0u8; 48]; 8],
        }
        .serialize(&mut ix)
        .unwrap();

        let mut auth_lamports = 1000u64;
        let mut auth_data = vec![];
        let auth_acc = AccountInfo::new(&authority_key, true, true, &mut auth_lamports, &mut auth_data, &pid, false);
        let mut reg_lamports = 1000u64;
        let mut reg_data = vec![0u8; PolicyRegistry::SIZE];
        let reg_acc = AccountInfo::new(&registry_pda, false, true, &mut reg_lamports, &mut reg_data, &pid, false);
        let filler_key = Pubkey::new_unique();
        let mut filler_lamports = 1u64;
        let mut filler_data = vec![];
        let filler = placeholder(&filler_key, &pid, &mut filler_lamports, &mut filler_data);
        let mut pd_lamports = 1u64;
        let mut pd_data = program_data_bytes(authority_key.as_ref());
        let pd_acc = AccountInfo::new(&program_data_key, false, false, &mut pd_lamports, &mut pd_data, &loader, false);
        let accounts = [auth_acc, reg_acc, filler, pd_acc];
        assert!(Processor::process(&pid, &accounts, &ix).is_ok());
        let saved = PolicyRegistry::try_from_slice(&accounts[1].try_borrow_data().unwrap()).unwrap();
        assert_eq!(saved.authority, authority_key.to_bytes());

        let mut mismatch_lamports = 1000u64;
        let mut mismatch_auth_data = vec![];
        let mismatch_auth =
            AccountInfo::new(&authority_key, true, true, &mut mismatch_lamports, &mut mismatch_auth_data, &pid, false);
        let mut mismatch_reg_lamports = 1000u64;
        let mut mismatch_reg_data = vec![0u8; PolicyRegistry::SIZE];
        let mismatch_reg = AccountInfo::new(
            &registry_pda,
            false,
            true,
            &mut mismatch_reg_lamports,
            &mut mismatch_reg_data,
            &pid,
            false,
        );
        let mut mismatch_filler_lamports = 1u64;
        let mut mismatch_filler_data = vec![];
        let mismatch_filler = placeholder(&filler_key, &pid, &mut mismatch_filler_lamports, &mut mismatch_filler_data);
        let mut bad_pd_lamports = 1u64;
        let mut bad_pd_data = program_data_bytes(&[9u8; 32]);
        let bad_pd =
            AccountInfo::new(&program_data_key, false, false, &mut bad_pd_lamports, &mut bad_pd_data, &loader, false);
        assert_eq!(
            Processor::process(&pid, &[mismatch_auth, mismatch_reg, mismatch_filler, bad_pd], &ix),
            Err(VerifierError::InvalidAuthority.into())
        );
    }
}

#[cfg(test)]
mod issue_183_fixtures {
    // Explicit governance policy fixtures for tests that previously configured the global allowlist.
    use crate::state::{BackendPolicy, PolicyRegistry};
    use solana_confidential_compute_core::SignatureVerifier;
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
    pub struct TestProcessor;
    fn with_policies<'a>(program_id: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> Vec<AccountInfo<'a>> {
        let mut output = accounts.to_vec();
        if ![
            crate::payload::VERIFY_AND_REGISTER_DISCRIMINATOR,
            crate::payload::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
            crate::payload::VERIFY_GOOGLE_JWT_DISCRIMINATOR,
            crate::payload::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
        ]
        .iter()
        .any(|d| data.get(..8) == Some(d.as_slice()))
        {
            return output;
        }

        if data.get(..8) == Some(crate::payload::VERIFY_AND_REGISTER_DISCRIMINATOR.as_slice())
            || data.get(..8) == Some(crate::payload::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.as_slice())
        {
            if let Some(cache) = accounts
                .get(2)
                .and_then(|a| a.try_borrow_data().ok())
                .and_then(|d| borsh::from_slice::<crate::state::VcekAccount>(&d).ok())
            {
                let key = Pubkey::find_program_address(
                    &[crate::state::AmdIdentityRevocation::SEED, &cache.chip_id_hash],
                    program_id,
                )
                .0;
                if !output.iter().any(|a| a.key == &key) {
                    output.push(AccountInfo::new(
                        Box::leak(Box::new(key)),
                        false,
                        false,
                        Box::leak(Box::new(0)),
                        Box::leak(Box::new([])),
                        Box::leak(Box::new(solana_sdk_ids::system_program::ID)),
                        false,
                    ));
                }
            }
        }
        let (global, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
        let registry = accounts
            .iter()
            .find(|a| a.key == &global)
            .and_then(|a| a.try_borrow_data().ok().and_then(|d| borsh::from_slice::<PolicyRegistry>(&d).ok()));
        if let Some(registry) = registry.filter(|r| r.discriminator == crate::state::POLICY_REGISTRY_DISCRIMINATOR) {
            for source in 1..=4 {
                let (key, bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[source]], program_id);
                if output.iter().any(|a| a.key == &key) {
                    continue;
                }
                let value = BackendPolicy {
                    discriminator: BackendPolicy::DISCRIMINATOR,
                    source,
                    measurement_count: registry.measurement_count,
                    measurements: registry.measurements,
                    bump,
                };
                output.push(AccountInfo::new(
                    Box::leak(Box::new(key)),
                    false,
                    false,
                    Box::leak(Box::new(1)),
                    Box::leak(borsh::to_vec(&value).unwrap().into_boxed_slice()),
                    Box::leak(Box::new(*program_id)),
                    false,
                ));
            }
        }
        output
    }
    #[allow(dead_code)]
    impl TestProcessor {
        pub fn verify_recent_slot_hash(
            account: &AccountInfo,
            current: u64,
            nonce: u64,
            hash: &[u8; 32],
        ) -> Result<(), crate::error::VerifierError> {
            crate::processor::Processor::verify_recent_slot_hash(account, current, nonce, hash)
        }

        pub fn assert_pda(account: &AccountInfo, seeds: &[&[u8]], program_id: &Pubkey) -> ProgramResult {
            crate::processor::Processor::assert_pda(account, seeds, program_id)
        }

        pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
            crate::processor::Processor::process(program_id, &with_policies(program_id, accounts, data), data)
        }
        pub fn process_with<V: SignatureVerifier>(
            v: &V,
            program_id: &Pubkey,
            accounts: &[AccountInfo],
            data: &[u8],
        ) -> ProgramResult {
            crate::processor::Processor::process_with(v, program_id, &with_policies(program_id, accounts, data), data)
        }
    }
}

#[cfg(test)]
mod issue_183 {
    use super::*;
    use crate::state::BackendPolicy;
    #[test]
    fn identical_measurement_is_not_authorized_for_another_backend() {
        let pid = Pubkey::new_unique();
        let measurement = [7; 48];
        let (key, bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[3]], &pid);
        for stored_source in [1, 2, 3] {
            let value = BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source: stored_source,
                measurement_count: 1,
                measurements: [measurement; 8],
                bump,
            };
            let mut bytes = borsh::to_vec(&value).unwrap();
            let mut lamports = 1;
            let account = AccountInfo::new(&key, false, false, &mut lamports, &mut bytes, &pid, false);
            let result = Processor::assert_backend_measurement(&pid, &[account], 3, &measurement);
            assert_eq!(result.is_ok(), stored_source == 3);
        }
        assert!(Processor::assert_backend_measurement(&pid, &[], 3, &measurement).is_err());
    }
}

#[cfg(test)]
mod issue_182 {
    use super::*;
    #[test]
    fn unix_deadline_clamps_to_credential_and_rejects_invalid_time() {
        assert_eq!(Processor::session_unix_deadline(100, Some(101)).unwrap(), 101);
        assert_eq!(Processor::session_unix_deadline(100, Some(u64::MAX)).unwrap(), 86500);
        assert_eq!(Processor::session_unix_deadline(100, None).unwrap(), 86500);
        assert!(Processor::session_unix_deadline(100, Some(100)).is_err());
        assert!(Processor::session_unix_deadline(-1, None).is_err());
        assert!(Processor::session_unix_deadline(i64::MAX, None).is_err());
    }
}

#[cfg(test)]
mod issue_205_fixtures {
    // Explicit empty canonical legacy nonce fixtures; no production fallback.
    use crate::payload::*;
    use solana_confidential_compute_core::SignatureVerifier;
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
    pub struct TestProcessor;
    fn legacy_address(pid: &Pubkey, data: &[u8]) -> Option<Pubkey> {
        let disc = data.get(..8)?;
        if disc == VERIFY_AND_REGISTER_DISCRIMINATOR || disc == VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR {
            let offset = if disc == VERIFY_AND_REGISTER_DISCRIMINATOR { 16 } else { 80 };
            let view =
                solana_confidential_compute_core::SnpReportView::try_from_slice(data.get(offset..offset + 1184)?)
                    .ok()?;
            return Some(Pubkey::find_program_address(&[b"nonce", &view.pubkey(), &view.nonce()], pid).0);
        }
        if disc == VERIFY_NITRO_ATTESTATION_DISCRIMINATOR {
            let (_, view) = solana_confidential_compute_crypto::parse_nitro_attestation(data.get(53..)?).ok()?;
            return Some(Pubkey::find_program_address(&[b"nonce", &view.user_data, &view.nonce], pid).0);
        }
        if disc == VERIFY_GOOGLE_JWT_DISCRIMINATOR {
            let view =
                solana_confidential_compute_crypto::jwt::JwtView::parse(core::str::from_utf8(data.get(53..)?).ok()?)
                    .ok()?;
            let claims = solana_confidential_compute_crypto::jwt::parse_google_claims_b64(view.payload_b64).ok()?;
            let raw = if *data.get(8)? == 0 {
                claims.decode_mode_a_binding().ok()?.to_vec()
            } else {
                claims.decode_mode_b_commitment().ok()?.to_vec()
            };
            let seed = solana_confidential_compute_crypto::jwt::eat_nonce_tombstone_seed(&raw);
            return Some(Pubkey::find_program_address(&[b"nonce", &seed], pid).0);
        }
        None
    }
    fn accounts<'a>(pid: &Pubkey, original: &[AccountInfo<'a>], data: &[u8]) -> Vec<AccountInfo<'a>> {
        let mut accounts = original.to_vec();
        if let Some(key) = legacy_address(pid, data) {
            if !accounts.iter().any(|a| a.key == &key) {
                accounts.push(AccountInfo::new(
                    Box::leak(Box::new(key)),
                    false,
                    false,
                    Box::leak(Box::new(0)),
                    Box::leak(Vec::new().into_boxed_slice()),
                    Box::leak(Box::new(solana_sdk_ids::system_program::ID)),
                    false,
                ));
            }
        }
        accounts
    }
    #[allow(dead_code)]
    impl TestProcessor {
        pub fn process(pid: &Pubkey, original: &[AccountInfo], data: &[u8]) -> ProgramResult {
            crate::processor::issue_183_fixtures::TestProcessor::process(pid, &accounts(pid, original, data), data)
        }
        pub fn process_with<V: SignatureVerifier>(
            v: &V,
            pid: &Pubkey,
            original: &[AccountInfo],
            data: &[u8],
        ) -> ProgramResult {
            crate::processor::issue_183_fixtures::TestProcessor::process_with(
                v,
                pid,
                &accounts(pid, original, data),
                data,
            )
        }
        pub fn verify_recent_slot_hash(
            a: &AccountInfo,
            now: u64,
            nonce: u64,
            hash: &[u8; 32],
        ) -> Result<(), crate::error::VerifierError> {
            crate::processor::Processor::verify_recent_slot_hash(a, now, nonce, hash)
        }
        pub fn assert_pda(a: &AccountInfo, seeds: &[&[u8]], pid: &Pubkey) -> ProgramResult {
            crate::processor::Processor::assert_pda(a, seeds, pid)
        }
    }
}

#[cfg(test)]
mod issue_205 {
    use super::*;
    #[test]
    fn source_namespaces_are_disjoint_while_legacy_tombstones_remain_protected() {
        let pid = Pubkey::new_unique();
        let signer = [7; 32];
        let nonce = [8; 32];
        // Original SNP/Nitro tuples are exactly identical, not a hash collision.
        let old_snp = Pubkey::find_program_address(&[b"nonce", &signer, &nonce], &pid).0;
        let old_nitro = Pubkey::find_program_address(&[b"nonce", &signer, &nonce], &pid).0;
        assert_eq!(old_snp, old_nitro);
        let snp = Pubkey::find_program_address(&[b"nonce", &[1], &signer, &nonce], &pid).0;
        let nitro = Pubkey::find_program_address(&[b"nonce", &[2], &signer, &nonce], &pid).0;
        assert_ne!(snp, nitro);
        assert_ne!(snp, old_snp);
        let (legacy, bump) = Pubkey::find_program_address(&[b"nonce", &signer, &nonce], &pid);
        for consumed in [500, u64::MAX] {
            let mut bytes = crate::state::LEGACY_USED_NONCE_DISCRIMINATOR.to_vec();
            bytes.extend_from_slice(&consumed.to_le_bytes());
            bytes.push(bump);
            let mut lamports = 1000;
            let account = AccountInfo::new(&legacy, false, false, &mut lamports, &mut bytes, &pid, false);
            for now in [499, 650, 651] {
                let result = Processor::assert_legacy_nonce_migration(
                    &pid,
                    core::slice::from_ref(&account),
                    &[b"nonce", &signer, &nonce],
                    now,
                );
                assert_eq!(result.is_ok(), consumed == 500 && now == 651);
            }
        }
        assert!(Processor::assert_legacy_nonce_migration(&pid, &[], &[b"nonce", &signer, &nonce], 651).is_err());
    }
}

#[cfg(test)]
mod issue_289 {
    use super::*;
    #[test]
    fn identity_admission_is_mandatory_and_fails_closed_across_tcbs() {
        let pid = Pubkey::new_unique();
        let identity = [17; 32];
        let key = Pubkey::find_program_address(&[AmdIdentityRevocation::SEED, &identity], &pid).0;
        let system = system_program::ID;
        let foreign = Pubkey::new_unique();
        assert_eq!(
            Processor::assert_amd_identity_allowed(&pid, &[], &identity),
            Err(ProgramError::NotEnoughAccountKeys)
        );
        for owner in [&system, &pid, &foreign] {
            for bytes in [vec![], vec![0; AmdIdentityRevocation::SIZE]] {
                let mut lamports = 1;
                let mut bytes = bytes;
                let mut account = AccountInfo::new(&key, false, false, &mut lamports, &mut bytes, owner, false);
                let result = Processor::assert_amd_identity_allowed(&pid, std::slice::from_ref(&account), &identity);
                assert_eq!(result.is_ok(), owner == &system && account.data_is_empty());
                account.executable = true;
                assert!(Processor::assert_amd_identity_allowed(&pid, &[account], &identity).is_err());
            }
        }
        let mut lamports = 1;
        let mut bytes = vec![];
        let account = AccountInfo::new(&key, false, false, &mut lamports, &mut bytes, &pid, false);
        for tcb in [0u64, 1, 99, u64::MAX] {
            // Changing TCB changes the cache, never this canonical identity key.
            let cache = Pubkey::find_program_address(&[VcekAccount::SEED, &identity, &tcb.to_le_bytes()], &pid).0;
            assert_ne!(cache, key);
            assert_eq!(
                Processor::assert_amd_identity_allowed(&pid, std::slice::from_ref(&account), &identity),
                Err(VerifierError::UnauthorizedPolicy.into())
            );
        }
        assert!(Processor::assert_amd_identity_allowed(&pid, &[account], &[18; 32]).is_err());
    }
}
