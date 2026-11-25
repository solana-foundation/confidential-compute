//! Attestation transaction assembly and local cryptographic pre-flight.
//!
//! @spec SCC-CLI-002 SCC-CLI-003 SCC-CLI-004 SCC-CLI-005 SCC-SEC-010

use sha2::{Digest, Sha256};
use solana_confidential_compute_core::types::VerifyAtomicHeader;
use solana_confidential_compute_core::{SnpReportView, SNP_REPORT_SIZE};
use solana_confidential_compute_sdk::ConfidentialComputeClient;
use solana_sdk::hash::hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

use crate::CliError;

/// Compute-unit limit injected ahead of attestation instructions.
/// @spec SCC-CLI-004
pub const COMPUTE_UNIT_LIMIT: u32 = 700_000;

/// Anchor discriminator for `verify_and_register`.
pub use solana_confidential_compute_sdk::VERIFY_AND_REGISTER_DISCRIMINATOR;
/// Anchor discriminator for `verify_atomic`.
pub use solana_confidential_compute_sdk::VERIFY_ATOMIC_DISCRIMINATOR;
/// Anchor discriminator for `verify_atomic_with_nonce`.
pub use solana_confidential_compute_sdk::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR;

/// NIST P-384 group order `n`.
pub const P384_N: [u8; 48] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0,
    0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
];

const fn n_half(n: [u8; 48]) -> [u8; 48] {
    let mut half = [0u8; 48];
    let mut carry = 0u8;
    let mut i = 0;
    while i < 48 {
        let b = n[i];
        half[i] = (b >> 1) | (carry << 7);
        carry = b & 1;
        i += 1;
    }
    half
}

/// `floor(n / 2)` for P-384.
pub const P384_N_HALF: [u8; 48] = n_half(P384_N);

/// High-S telemetry line recorded by the developer CLI.
/// @spec SCC-SEC-010 SCC-CLI-005
pub const HIGH_S_WARN: &str = "[WARN] High-S signature detected (s > n/2). Hardware vendor: AMD PSP. Valid under FIPS 186-4; non-canonical under BIP-62.";

/// Returns true when scalar `s` is strictly greater than `floor(n / 2)`.
pub fn is_high_s(s_be: &[u8; 48]) -> bool {
    s_be.as_slice() > P384_N_HALF.as_slice()
}

/// Emits the high-S warning when `s > floor(n / 2)`.
///
/// @spec SCC-SEC-010 SCC-CLI-005
pub fn log_high_s_if_needed(s_be: &[u8; 48]) -> bool {
    let high = is_high_s(s_be);
    if high {
        eprintln!("{HIGH_S_WARN}");
    }
    high
}

/// Computes `n - s` (big-endian) for constructing the complementary ECDSA scalar.
pub fn negate_s_mod_n(s_be: &[u8; 48]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut borrow = 0u16;
    let mut i = 48;
    while i > 0 {
        i -= 1;
        let n = u16::from(P384_N[i]);
        let s = u16::from(s_be[i]) + borrow;
        if n >= s {
            out[i] = (n - s) as u8;
            borrow = 0;
        } else {
            out[i] = (n + 256 - s) as u8;
            borrow = 1;
        }
    }
    out
}

/// Validates the report view and verifies the P-384 signature against the VCEK public key.
///
/// High-S signatures are accepted (FIPS 186-4) and logged.
///
/// @spec SCC-CLI-005 SCC-SEC-010
pub fn verify_report_locally(report: &[u8; SNP_REPORT_SIZE], vcek_pubkey_xy: &[u8; 96]) -> Result<(), CliError> {
    let view = SnpReportView::from_array(report);
    view.validate_security_invariants().map_err(CliError::Report)?;
    let r = view.signature_r_be().map_err(CliError::Report)?;
    let s = view.signature_s_be().map_err(CliError::Report)?;
    log_high_s_if_needed(&s);

    let mut sig_rs = [0u8; 96];
    sig_rs[..48].copy_from_slice(&r);
    sig_rs[48..].copy_from_slice(&s);
    match solana_confidential_compute_crypto::verify_snp_report_signature(vcek_pubkey_xy, view.signed_body(), &sig_rs) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(CliError::InvalidSignature),
    }
}

/// Attestation modality packaged into the transaction.
pub enum AttestationMode {
    /// Mode A: `verify_and_register`.
    Stateful,
    /// Mode B: `verify_atomic` or `verify_atomic_with_nonce`.
    Atomic { action_hash: [u8; 32], consumer_program: Pubkey, require_nonce: bool },
}

/// Inputs required to assemble an attestation transaction.
pub struct TxBuildParams<'a> {
    pub program_id: Pubkey,
    pub payer: Pubkey,
    pub report: &'a [u8; SNP_REPORT_SIZE],
    pub vcek_pubkey_xy: &'a [u8; 96],
    pub nonce_slot: u64,
    pub mode: AttestationMode,
    pub priority_fee: Option<u64>,
}

/// Assembles compute-budget instructions plus the Mode A or Mode B attestation instruction.
///
/// @spec SCC-CLI-002 SCC-CLI-003 SCC-CLI-004
pub fn assemble_attestation_tx(params: &TxBuildParams<'_>) -> Result<Transaction, CliError> {
    let mut ixs = vec![set_compute_unit_limit(COMPUTE_UNIT_LIMIT)];
    if let Some(micro_lamports) = params.priority_fee {
        ixs.push(set_compute_unit_price(micro_lamports));
    }
    ixs.push(build_attestation_instruction(params)?);
    Ok(Transaction::new_unsigned(Message::new(&ixs, Some(&params.payer))))
}

/// Serializes a transaction to `(base64, hex)` for `--dry-run` stdout.
///
/// @spec SCC-CLI-004
pub fn encode_transaction_payload(tx: &Transaction) -> Result<(String, String), CliError> {
    let bytes = bincode::serialize(tx).map_err(|err| CliError::Serialization(err.to_string()))?;
    Ok((encode_base64(&bytes), hex::encode(&bytes)))
}

fn build_attestation_instruction(params: &TxBuildParams<'_>) -> Result<Instruction, CliError> {
    let view = SnpReportView::from_array(params.report);
    let client = ConfidentialComputeClient::new(params.program_id);
    let (policy_registry, _) = client.derive_policy_registry_pda();
    let chip_id_hash = derive_chip_id_hash(&view, params.vcek_pubkey_xy);
    let (vcek_pda, _) = client.derive_vcek_pda(&chip_id_hash, view.reported_tcb());
    let (amd_backend_policy, _) = solana_confidential_compute_sdk::derive_backend_policy_pda(&params.program_id, 1)
        .map_err(|err| CliError::InvalidArgument(err.to_string()))?;

    match &params.mode {
        AttestationMode::Stateful => {
            let signer_pubkey = view.pubkey();
            let nonce = view.nonce();
            let (attested_signer, _) = client.derive_signer_pda(&signer_pubkey);
            let (used_nonce, _) = client
                .derive_used_nonce_pda_for_source(1, &signer_pubkey, &nonce)
                .map_err(|err| CliError::InvalidArgument(err.to_string()))?;
            let mut data = Vec::with_capacity(8 + 8 + SNP_REPORT_SIZE);
            data.extend_from_slice(&VERIFY_AND_REGISTER_DISCRIMINATOR);
            data.extend_from_slice(&params.nonce_slot.to_le_bytes());
            data.extend_from_slice(params.report);
            Ok(Instruction {
                program_id: params.program_id,
                accounts: vec![
                    AccountMeta::new(params.payer, true),
                    AccountMeta::new_readonly(policy_registry, false),
                    AccountMeta::new_readonly(vcek_pda, false),
                    AccountMeta::new(attested_signer, false),
                    AccountMeta::new(used_nonce, false),
                    AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                    AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                    AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                    AccountMeta::new_readonly(Pubkey::new_from_array(signer_pubkey), true),
                    AccountMeta::new_readonly(amd_backend_policy, false),
                    AccountMeta::new_readonly(
                        client.derive_legacy_used_nonce_pda(&view.pubkey(), &view.nonce()).0,
                        false,
                    ),
                ],
                data,
            })
        }
        AttestationMode::Atomic { action_hash, consumer_program, require_nonce } => {
            let header = VerifyAtomicHeader {
                nonce_slot: params.nonce_slot,
                action_hash: *action_hash,
                consumer_program_id: consumer_program.to_bytes(),
            };
            let disc =
                if *require_nonce { VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR } else { VERIFY_ATOMIC_DISCRIMINATOR };
            let mut data = Vec::with_capacity(8 + 72 + SNP_REPORT_SIZE);
            data.extend_from_slice(&disc);
            data.extend_from_slice(&encode_atomic_header(&header));
            data.extend_from_slice(params.report);

            if *require_nonce {
                let commitment = compute_commitment_from_report(&view);
                let (used_nonce, _) = client
                    .derive_used_nonce_pda_for_source(1, &view.pubkey(), &commitment)
                    .map_err(|err| CliError::InvalidArgument(err.to_string()))?;
                Ok(Instruction {
                    program_id: params.program_id,
                    accounts: vec![
                        AccountMeta::new(params.payer, true),
                        AccountMeta::new_readonly(policy_registry, false),
                        AccountMeta::new_readonly(vcek_pda, false),
                        AccountMeta::new(used_nonce, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
                        AccountMeta::new_readonly(amd_backend_policy, false),
                        AccountMeta::new_readonly(
                            client.derive_legacy_used_nonce_pda(&view.pubkey(), &view.nonce()).0,
                            false,
                        ),
                    ],
                    data,
                })
            } else {
                Ok(Instruction {
                    program_id: params.program_id,
                    accounts: vec![
                        AccountMeta::new_readonly(policy_registry, false),
                        AccountMeta::new_readonly(vcek_pda, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
                        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
                        AccountMeta::new_readonly(amd_backend_policy, false),
                        AccountMeta::new_readonly(
                            client.derive_legacy_used_nonce_pda(&view.pubkey(), &view.nonce()).0,
                            false,
                        ),
                    ],
                    data,
                })
            }
        }
    }
}

fn encode_atomic_header(header: &VerifyAtomicHeader) -> [u8; 72] {
    let mut out = [0u8; 72];
    out[0..8].copy_from_slice(&header.nonce_slot.to_le_bytes());
    out[8..40].copy_from_slice(&header.action_hash);
    out[40..72].copy_from_slice(&header.consumer_program_id);
    out
}

fn derive_chip_id_hash(view: &SnpReportView<'_>, vcek_pubkey_xy: &[u8; 96]) -> [u8; 32] {
    if view.chip_id() == &[0u8; 64] {
        hash(vcek_pubkey_xy).to_bytes()
    } else {
        hash(view.chip_id()).to_bytes()
    }
}

fn compute_commitment_from_report(view: &SnpReportView<'_>) -> [u8; 32] {
    view.nonce()
}

/// Compute Budget: `SetComputeUnitLimit` (discriminator 2).
fn set_compute_unit_limit(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: compute_budget_program_id(), accounts: vec![], data }
}

/// Compute Budget: `SetComputeUnitPrice` (discriminator 3).
fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction { program_id: compute_budget_program_id(), accounts: vec![], data }
}

fn compute_budget_program_id() -> Pubkey {
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111")
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// SHA-256 of the three Mode B commitment inputs.
///
/// @spec SCC-CLI-003 SCC-VERIFY-012
pub fn mode_b_commitment(slot_hash: &[u8; 32], action_hash: &[u8; 32], consumer_program_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(slot_hash);
    hasher.update(action_hash);
    hasher.update(consumer_program_id);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{generate_mock_report, mock_vcek_public_key_xy, write_signature_s_be};
    use solana_confidential_compute_core::types::compute_action_commitment;
    use solana_confidential_compute_core::ReportData;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;

    fn sample_stateful_params<'a>(
        report: &'a [u8; SNP_REPORT_SIZE],
        vcek: &'a [u8; 96],
        payer: Pubkey,
    ) -> TxBuildParams<'a> {
        TxBuildParams {
            program_id: Pubkey::new_unique(),
            payer,
            report,
            vcek_pubkey_xy: vcek,
            nonce_slot: 500,
            mode: AttestationMode::Stateful,
            priority_fee: Some(1_000),
        }
    }

    #[test]
    fn test_low_s_vs_high_s_detection() {
        let user_data = ReportData::new(&[0x07u8; 32], &[0x55u8; 32]).raw;
        let mut report = generate_mock_report(&user_data).unwrap();
        let vcek = mock_vcek_public_key_xy();
        let view = SnpReportView::from_array(&report);
        let s = view.signature_s_be().expect("valid s padding");

        let (low, high) = if is_high_s(&s) { (negate_s_mod_n(&s), s) } else { (s, negate_s_mod_n(&s)) };
        assert!(!is_high_s(&low), "canonical s must be low-S");
        assert!(is_high_s(&high), "n - s must be high-S");
        assert_eq!(negate_s_mod_n(&high), low);

        verify_report_locally(&report, &vcek).expect("original mock signature verifies");

        write_signature_s_be(&mut report, &high);
        let view_high = SnpReportView::from_array(&report);
        assert!(is_high_s(&view_high.signature_s_be().expect("high-S padding")));
        verify_report_locally(&report, &vcek).expect("high-S remains valid under FIPS 186-4");
    }

    #[test]
    fn test_n_half_is_n_shifted() {
        assert_eq!(P384_N_HALF[0] & 0x80, 0);
        assert_eq!(P384_N[0], 0xFF);
    }

    #[test]
    fn test_dry_run_mode_a_transaction_assembly() {
        let payer = Keypair::new();
        let workload = [0x07u8; 32];
        let slot_hash = [0x55u8; 32];
        let user_data = ReportData::new(&workload, &slot_hash).raw;
        let report = generate_mock_report(&user_data).unwrap();
        let vcek = mock_vcek_public_key_xy();
        verify_report_locally(&report, &vcek).expect("local verify");

        let params = sample_stateful_params(&report, &vcek, payer.pubkey());
        let tx = assemble_attestation_tx(&params).expect("mode A tx");
        assert_eq!(tx.message.instructions.len(), 3);

        let cu_ix = &tx.message.instructions[0];
        assert_eq!(cu_ix.data[0], 2);
        assert_eq!(&cu_ix.data[1..5], &COMPUTE_UNIT_LIMIT.to_le_bytes());
        assert_eq!(tx.message.instructions[1].data[0], 3);

        let att = &tx.message.instructions[2];
        assert_eq!(&att.data[..8], &VERIFY_AND_REGISTER_DISCRIMINATOR);
        assert_eq!(&att.data[8..16], &500u64.to_le_bytes());
        assert_eq!(&att.data[16..], report.as_slice());

        let (b64, hx) = encode_transaction_payload(&tx).expect("serialize");
        assert!(!b64.is_empty());
        assert!(!hx.is_empty());
        assert_eq!(hx.len() % 2, 0);
    }

    #[test]
    fn test_dry_run_mode_b_transaction_assembly() {
        let payer = Keypair::new();
        let slot_hash = [0x55u8; 32];
        let action_hash = [0x11u8; 32];
        let consumer = Pubkey::new_unique();
        let commitment = compute_action_commitment(&slot_hash, &action_hash, &consumer.to_bytes());
        assert_eq!(mode_b_commitment(&slot_hash, &action_hash, &consumer.to_bytes()), commitment);

        let mut user_data = [0u8; 64];
        user_data[32..].copy_from_slice(&commitment);
        let report = generate_mock_report(&user_data).unwrap();
        let vcek = mock_vcek_public_key_xy();
        verify_report_locally(&report, &vcek).expect("local verify");

        let params = TxBuildParams {
            program_id: Pubkey::new_unique(),
            payer: payer.pubkey(),
            report: &report,
            vcek_pubkey_xy: &vcek,
            nonce_slot: 500,
            mode: AttestationMode::Atomic { action_hash, consumer_program: consumer, require_nonce: false },
            priority_fee: None,
        };
        let tx = assemble_attestation_tx(&params).expect("mode B tx");
        assert_eq!(tx.message.instructions.len(), 2);

        let att = &tx.message.instructions[1];
        assert_eq!(&att.data[..8], &VERIFY_ATOMIC_DISCRIMINATOR);
        assert_eq!(&att.data[8..16], &500u64.to_le_bytes());
        assert_eq!(&att.data[16..48], &action_hash);
        assert_eq!(&att.data[48..80], consumer.as_ref());
        assert_eq!(&att.data[80..], report.as_slice());
        assert_eq!(att.data.len(), 8 + 72 + SNP_REPORT_SIZE);

        let (b64, hx) = encode_transaction_payload(&tx).expect("serialize");
        assert!(b64.is_ascii());
        assert!(hx.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_dry_run_mode_b_defaults_to_nonce_bound() {
        let payer = Keypair::new();
        let slot_hash = [0x55u8; 32];
        let action_hash = [0x11u8; 32];
        let consumer = Pubkey::new_unique();
        let commitment = compute_action_commitment(&slot_hash, &action_hash, &consumer.to_bytes());
        let mut user_data = [0u8; 64];
        user_data[32..].copy_from_slice(&commitment);
        let report = generate_mock_report(&user_data).unwrap();
        let vcek = mock_vcek_public_key_xy();

        let params = TxBuildParams {
            program_id: Pubkey::new_unique(),
            payer: payer.pubkey(),
            report: &report,
            vcek_pubkey_xy: &vcek,
            nonce_slot: 500,
            mode: AttestationMode::Atomic {
                action_hash,
                consumer_program: consumer,
                require_nonce: ConfidentialComputeClient::mode_b_require_nonce(false),
            },
            priority_fee: None,
        };
        let tx = assemble_attestation_tx(&params).expect("mode B nonce tx");
        let att = &tx.message.instructions[1];
        assert_eq!(&att.data[..8], &VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
        assert!(att.accounts.len() >= 7);
    }
}
