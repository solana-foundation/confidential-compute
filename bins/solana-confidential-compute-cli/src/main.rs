//! Solana Confidential Compute CLI: One-command proof of hardware enclave execution.

pub mod governance;
pub mod hardware;
pub mod mock;
pub mod tx;

use clap::{Parser, Subcommand, ValueEnum};
use solana_confidential_compute_core::ReportData;
use solana_confidential_compute_sdk::ConfidentialComputeClient;
use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

use crate::hardware::fetch_snp_report;
use crate::mock::mock_vcek_public_key_xy;
use crate::tx::{
    assemble_attestation_tx, encode_transaction_payload, mode_b_commitment, verify_report_locally,
    AttestationMode, TxBuildParams,
};

const DEFAULT_PROGRAM_ID: &str = "EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh";
const DEFAULT_SLOT_HASH: [u8; 32] = [0x55; 32];

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Hardware unavailable: {0}")]
    HardwareUnavailable(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Report error: {0:?}")]
    Report(solana_confidential_compute_core::ConfidentialComputeError),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

#[derive(Parser, Debug)]
#[command(name = "solana-confidential-compute", alias = "solana-cc")]
#[command(about = "Verifiable Compute CLI for Solana hardware enclaves", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum ProveMode {
    #[default]
    Stateful,
    Atomic,
}

#[derive(clap::Args, Debug)]
struct ProveArgs {
    /// Attestation modality (Mode A stateful vs Mode B atomic).
    #[arg(long, value_enum, default_value_t = ProveMode::Stateful)]
    mode: ProveMode,

    /// Workload Ed25519 public key (required for --mode stateful).
    #[arg(short, long)]
    pubkey: Option<String>,

    /// Emulate AMD SEV-SNP report locally.
    #[arg(long, default_value_t = false)]
    mock: bool,

    /// Target VCEK public key: 96-byte uncompressed X||Y, hex.
    /// Required unless `--mock`. When set, this key is the preflight key even with `--mock`.
    #[arg(long)]
    vcek_pubkey: Option<String>,

    /// SEV-guest device path (default: /dev/sev-guest).
    #[arg(long)]
    device: Option<String>,

    /// Solana Confidential Compute verifier program ID.
    #[arg(long, default_value = DEFAULT_PROGRAM_ID)]
    program_id: String,

    /// Transaction fee payer public key.
    #[arg(long)]
    payer: Option<String>,

    /// Slot number bound into the instruction header.
    #[arg(long, default_value_t = 500)]
    nonce_slot: u64,

    /// 32-byte slot hash as hex (default: 0x55 repeating).
    #[arg(long)]
    slot_hash: Option<String>,

    /// Mode B action hash (32-byte hex).
    #[arg(long)]
    action_hash: Option<String>,

    /// Mode B consumer program ID.
    #[arg(long)]
    consumer_program: Option<String>,

    /// Deprecated. Stateless Mode B is disabled on-chain to prevent replay (H-01).
    /// Passing this flag returns an error; all Mode B transactions require nonce consumption.
    #[arg(long, default_value_t = false)]
    stateless_idempotent: bool,

    /// Optional compute-unit price in microlamports.
    #[arg(long)]
    priority_fee: Option<u64>,

    /// Print base64/hex transaction without submitting (default: true).
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Export unsigned governance transaction; set blockhash and collect signatures externally.
    Governance(governance::GovernanceArgs),
    /// Prove that an Ed25519 keypair is hosted in an AMD SEV-SNP confidential VM.
    Prove(ProveArgs),
    /// Verify an on-chain registration status of an attested signer.
    Verify {
        #[arg(short, long)]
        pubkey: String,

        #[arg(long, default_value = DEFAULT_PROGRAM_ID)]
        program_id: String,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Governance(args) => {
            let tx = governance::build_transaction(&args)?;
            if args.is_legacy_policy_update() {
                eprintln!("warning: update-policy measurements are deprecated and do NOT halt admission; use emergency-halt --source 1|2|3 or set-backend-policy. AMD TCB floors remain active.");
            }
            let (b64, hx) = encode_transaction_payload(&tx)?;
            println!("unsigned_transaction_base64={b64}");
            println!("unsigned_transaction_hex={hx}");
            println!("Replace the zero blockhash and collect every required signature before submission.");
            Ok(())
        }
        Commands::Prove(args) => {
            let (b64, hx) = run_prove(&args)?;
            println!("transaction_base64={b64}");
            println!("transaction_hex={hx}");
            Ok(())
        }
        Commands::Verify { pubkey, program_id } => {
            let pid = parse_pubkey(&program_id)?;
            let client = ConfidentialComputeClient::new(pid);
            let user_pk = parse_pubkey(&pubkey)?;
            let (pda, bump) = client.derive_signer_pda(&user_pk.to_bytes());
            println!("Derived AttestedSigner PDA: {pda} (bump: {bump}) for {pubkey}");
            Ok(())
        }
    }
}

/// Builds and locally verifies a Mode A or Mode B attestation transaction.
///
/// @spec SCC-CLI-001 SCC-CLI-002 SCC-CLI-003 SCC-CLI-004 SCC-CLI-005
fn run_prove(args: &ProveArgs) -> Result<(String, String), CliError> {
    if args.stateless_idempotent {
        return Err(CliError::InvalidArgument(
            "Stateless Mode B is disabled on-chain to prevent replay attacks (finding H-01). All Mode B transactions require nonce consumption.".to_string(),
        ));
    }
    if !args.dry_run {
        return Err(CliError::InvalidArgument(
            "live broadcast is not enabled; pass --dry-run".into(),
        ));
    }

    let program_id = parse_pubkey(&args.program_id)?;
    let slot_hash = match &args.slot_hash {
        Some(hex_str) => parse_hex32(hex_str)?,
        None => DEFAULT_SLOT_HASH,
    };

    let (user_data, mode, default_payer) = match args.mode {
        ProveMode::Stateful => {
            let pubkey_str = args.pubkey.as_ref().ok_or_else(|| {
                CliError::InvalidArgument("--pubkey is required for --mode stateful".into())
            })?;
            let workload = parse_pubkey(pubkey_str)?;
            let user_data = ReportData::new(&workload.to_bytes(), &slot_hash).raw;
            (user_data, AttestationMode::Stateful, workload)
        }
        ProveMode::Atomic => {
            let action_hex = args.action_hash.as_ref().ok_or_else(|| {
                CliError::InvalidArgument("--action-hash is required for --mode atomic".into())
            })?;
            let consumer_str = args.consumer_program.as_ref().ok_or_else(|| {
                CliError::InvalidArgument("--consumer-program is required for --mode atomic".into())
            })?;
            let action_hash = parse_hex32(action_hex)?;
            let consumer = parse_pubkey(consumer_str)?;
            let commitment = mode_b_commitment(&slot_hash, &action_hash, &consumer.to_bytes());
            let mut user_data = [0u8; 64];
            user_data[0..32].fill(0);
            user_data[32..64].copy_from_slice(&commitment);
            (
                user_data,
                AttestationMode::Atomic {
                    action_hash,
                    consumer_program: consumer,
                    require_nonce: ConfidentialComputeClient::mode_b_require_nonce(
                        args.stateless_idempotent,
                    ),
                },
                consumer,
            )
        }
    };

    // Explicit `--vcek-pubkey` wins. `mock_vcek_public_key_xy()` runs only for `--mock`
    // when no target key was supplied.
    let vcek_xy = solana_confidential_compute_cli::resolve_vcek_public_key(
        args.mock,
        args.vcek_pubkey.as_deref(),
        mock_vcek_public_key_xy,
    )
    .map_err(|err| CliError::InvalidArgument(err.to_string()))?;
    let report = fetch_snp_report(&user_data, args.mock, args.device.as_deref())?;
    verify_report_locally(&report, &vcek_xy)?;

    let payer = match &args.payer {
        Some(s) => parse_pubkey(s)?,
        None => default_payer,
    };

    let tx = assemble_attestation_tx(&TxBuildParams {
        program_id,
        payer,
        report: &report,
        vcek_pubkey_xy: &vcek_xy,
        nonce_slot: args.nonce_slot,
        mode,
        priority_fee: args.priority_fee,
    })?;

    encode_transaction_payload(&tx)
}

fn parse_pubkey(s: &str) -> Result<Pubkey, CliError> {
    s.parse::<Pubkey>()
        .map_err(|_| CliError::InvalidArgument(format!("invalid pubkey: {s}")))
}

fn parse_hex32(s: &str) -> Result<[u8; 32], CliError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let raw = hex::decode(s).map_err(|err| CliError::InvalidArgument(err.to_string()))?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| {
        CliError::InvalidArgument("expected 32-byte hex value (64 hex characters)".into())
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{VERIFY_AND_REGISTER_DISCRIMINATOR, VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR};

    fn test_pubkey_str() -> String {
        Pubkey::from([7u8; 32]).to_string()
    }

    fn test_consumer_str() -> String {
        Pubkey::from([9u8; 32]).to_string()
    }

    fn stateful_args() -> ProveArgs {
        ProveArgs {
            mode: ProveMode::Stateful,
            pubkey: Some(test_pubkey_str()),
            mock: true,
            vcek_pubkey: None,
            device: None,
            program_id: DEFAULT_PROGRAM_ID.to_string(),
            payer: None,
            nonce_slot: 500,
            slot_hash: None,
            action_hash: None,
            consumer_program: None,
            stateless_idempotent: false,
            priority_fee: None,
            dry_run: true,
        }
    }

    #[test]
    fn test_parse_prove_stateful_defaults() {
        let cli = Cli::try_parse_from([
            "solana-confidential-compute",
            "prove",
            "--pubkey",
            &test_pubkey_str(),
            "--mock",
        ])
        .expect("parse stateful prove");
        match cli.command {
            Commands::Prove(args) => {
                assert_eq!(args.mode, ProveMode::Stateful);
                assert_eq!(args.pubkey.as_deref(), Some(test_pubkey_str().as_str()));
                assert!(args.mock);
                assert!(args.vcek_pubkey.is_none());
                assert!(args.dry_run);
                assert_eq!(args.nonce_slot, 500);
                assert_eq!(args.program_id, DEFAULT_PROGRAM_ID);
                assert!(!args.stateless_idempotent);
            }
            Commands::Verify { .. } | Commands::Governance(..) => panic!("expected prove"),
        }
    }

    #[test]
    fn test_parse_prove_atomic_flags() {
        let action = "11".repeat(32);
        let consumer = test_consumer_str();
        let cli = Cli::try_parse_from([
            "solana-confidential-compute",
            "prove",
            "--mode",
            "atomic",
            "--action-hash",
            &action,
            "--consumer-program",
            &consumer,
            "--mock",
            "--stateless-idempotent",
            "--priority-fee",
            "1000",
            "--nonce-slot",
            "520",
        ])
        .expect("parse atomic prove");
        match cli.command {
            Commands::Prove(args) => {
                assert_eq!(args.mode, ProveMode::Atomic);
                assert_eq!(args.action_hash.as_deref(), Some(action.as_str()));
                assert_eq!(args.consumer_program.as_deref(), Some(consumer.as_str()));
                assert!(args.stateless_idempotent);
                assert_eq!(args.priority_fee, Some(1000));
                assert_eq!(args.nonce_slot, 520);
                assert!(args.mock);
                assert!(args.dry_run);
            }
            Commands::Verify { .. } | Commands::Governance(..) => panic!("expected prove"),
        }
    }

    #[test]
    fn test_run_prove_stateful_mock_dry_run() {
        let (b64, hx) = run_prove(&stateful_args()).expect("stateful prove");
        assert!(!b64.is_empty());
        assert!(!hx.is_empty());
        assert_eq!(hx.len() % 2, 0);
        let disc = hex::encode(VERIFY_AND_REGISTER_DISCRIMINATOR);
        assert!(
            hx.to_ascii_lowercase().contains(&disc),
            "mode A discriminator missing from dry-run hex"
        );
    }

    #[test]
    fn test_run_prove_atomic_requires_action_hash() {
        let mut args = stateful_args();
        args.mode = ProveMode::Atomic;
        args.pubkey = None;
        args.consumer_program = Some(test_consumer_str());
        let err = run_prove(&args).expect_err("atomic without action-hash");
        match err {
            CliError::InvalidArgument(msg) => assert!(msg.contains("action-hash")),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn test_run_prove_atomic_requires_consumer_program() {
        let mut args = stateful_args();
        args.mode = ProveMode::Atomic;
        args.action_hash = Some("11".repeat(32));
        args.consumer_program = None;
        let err = run_prove(&args).expect_err("atomic without consumer");
        match err {
            CliError::InvalidArgument(msg) => assert!(msg.contains("consumer-program")),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn test_run_prove_atomic_mock_dry_run() {
        let mut args = stateful_args();
        args.mode = ProveMode::Atomic;
        args.action_hash = Some("11".repeat(32));
        args.consumer_program = Some(test_consumer_str());
        let (b64, hx) = run_prove(&args).expect("atomic prove");
        assert!(b64.is_ascii());
        let disc = hex::encode(VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR);
        assert!(
            hx.to_ascii_lowercase().contains(&disc),
            "mode B nonce-bound discriminator missing from dry-run hex"
        );
    }

    #[test]
    fn test_run_prove_atomic_stateless_idempotent() {
        let mut args = stateful_args();
        args.mode = ProveMode::Atomic;
        args.action_hash = Some("11".repeat(32));
        args.consumer_program = Some(test_consumer_str());
        args.stateless_idempotent = true;
        let err = run_prove(&args).expect_err("stateless Mode B must be rejected");
        match err {
            CliError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("Stateless Mode B is disabled on-chain to prevent replay attacks (finding H-01)"),
                    "unexpected error: {msg}"
                );
                assert!(
                    msg.contains("All Mode B transactions require nonce consumption"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn test_run_prove_stateful_requires_pubkey() {
        let mut args = stateful_args();
        args.pubkey = None;
        let err = run_prove(&args).expect_err("stateful without pubkey");
        match err {
            CliError::InvalidArgument(msg) => assert!(msg.contains("pubkey")),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_vcek_pubkey_flag() {
        let hex_key = "ab".repeat(96);
        let cli = Cli::try_parse_from([
            "solana-confidential-compute",
            "prove",
            "--pubkey",
            &test_pubkey_str(),
            "--vcek-pubkey",
            &hex_key,
        ])
        .expect("parse vcek pubkey");
        match cli.command {
            Commands::Prove(args) => {
                assert!(!args.mock);
                assert_eq!(args.vcek_pubkey.as_deref(), Some(hex_key.as_str()));
            }
            Commands::Verify { .. } | Commands::Governance(..) => panic!("expected prove"),
        }
    }

    #[test]
    fn test_run_prove_requires_vcek_pubkey_without_mock() {
        let mut args = stateful_args();
        args.mock = false;
        args.vcek_pubkey = None;
        let err = run_prove(&args).expect_err("hardware prove without target VCEK");
        match err {
            CliError::InvalidArgument(msg) => {
                assert!(msg.contains("--vcek-pubkey"), "{msg}");
                assert!(msg.contains("--mock"), "{msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn test_run_prove_rejects_mismatched_vcek_pubkey() {
        let mut args = stateful_args();
        args.mock = true;
        args.vcek_pubkey = Some("11".repeat(96));
        let err = run_prove(&args).expect_err("mock report must not verify under a foreign VCEK");
        assert!(
            matches!(err, CliError::InvalidSignature),
            "expected InvalidSignature, got {err:?}"
        );
    }

    #[test]
    fn test_run_prove_accepts_explicit_mock_vcek_pubkey() {
        let mut args = stateful_args();
        args.mock = true;
        args.vcek_pubkey = Some(hex::encode(mock_vcek_public_key_xy()));
        let (b64, hx) = run_prove(&args).expect("explicit mock VCEK verifies the mock report");
        assert!(!b64.is_empty());
        assert!(!hx.is_empty());
    }

    #[test]
    fn test_parse_hex32_accepts_0x_prefix() {
        let bytes = parse_hex32(&("0x55".to_string() + &"55".repeat(31))).expect("hex");
        assert_eq!(bytes, DEFAULT_SLOT_HASH);
    }
}
