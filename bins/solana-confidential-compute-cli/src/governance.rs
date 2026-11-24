//! Offline governance transactions. Never reads keys or broadcasts.
/// Backend sources governance may address.
///
/// 4 (NVIDIA) is absent on purpose: those records carry no authenticated
/// evidence, so there is nothing for a policy to gate on. The gap is why this
/// is a list rather than a `clap` range.
const GOVERNABLE_SOURCES: [u8; 4] = [1, 2, 3, 5];

fn parse_backend_source(value: &str) -> Result<u8, String> {
    let source: u8 = value.parse().map_err(|_| format!("`{value}` is not a backend source"))?;
    if !GOVERNABLE_SOURCES.contains(&source) {
        return Err(format!(
            "backend source must be one of {GOVERNABLE_SOURCES:?} \
             (1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space, 5 = Intel TDX)"
        ));
    }
    Ok(source)
}

use crate::{parse_pubkey, CliError, DEFAULT_PROGRAM_ID};
use clap::{Args, Subcommand};
use solana_confidential_compute_sdk::governance as sdk;
use solana_confidential_compute_sdk::{backend_policy, gcp_policy};
use solana_sdk::{instruction::Instruction, transaction::Transaction};

#[derive(Args, Debug)]
pub struct GovernanceArgs {
    #[arg(long, global = true, default_value = DEFAULT_PROGRAM_ID)]
    program_id: String,
    /// Current registry authority; must sign the exported transaction externally.
    #[arg(long)]
    authority: String,
    /// Fee payer for the exported transaction (defaults to authority).
    #[arg(long, global = true)]
    fee_payer: Option<String>,
    #[command(subcommand)]
    command: GovernanceCommand,
}
impl GovernanceArgs {
    pub fn is_legacy_policy_update(&self) -> bool {
        matches!(self.command, GovernanceCommand::UpdatePolicy { .. })
    }
}

#[derive(Subcommand, Debug)]
pub enum GovernanceCommand {
    /// Update monotonic AMD TCB floors and legacy global measurements.
    /// Global measurements are deprecated as runtime controls: clearing them does
    /// not halt admission. Use emergency-halt or set-backend-policy with no measurements
    /// for each relevant backend (1=AMD, 2=Nitro, 3=GCP); revoke existing signers separately.
    UpdatePolicy {
        /// Boot loader, TEE, SNP, microcode (four byte values).
        #[arg(long, num_args = 4, required = true)]
        min_tcb: Vec<u8>,
        /// Deprecated global list, retained for ABI compatibility; does not control admission.
        #[arg(long)]
        measurement: Vec<String>,
    },
    /// Halt this backend's new admission/verification by emptying its authoritative policy.
    /// Export only: sign, submit, and verify on-chain. Existing Mode A sessions remain valid.
    EmergencyHalt {
        /// Backend: 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space, 5 = Intel TDX.
        #[arg(long, value_parser = parse_backend_source)]
        source: u8,
    },
    /// Replace a backend allowlist; empty halts it, explicit reviewed measurements resume it.
    /// Use sources 1, 2 and 3 to halt all backends; revoke existing Mode A signers separately.
    SetBackendPolicy {
        /// Backend: 1 = AMD SEV-SNP, 2 = AWS Nitro, 3 = GCP Confidential Space, 5 = Intel TDX.
        #[arg(long, value_parser = parse_backend_source)]
        source: u8,
        /// Repeat for up to eight 48-byte hex measurements (GCP: digest then 16 zero bytes).
        #[arg(long)]
        measurement: Vec<String>,
    },
    /// Set the mandatory GCP audience/subject policy; does not change its backend allowlist.
    SetGcpTenantPolicy {
        #[arg(long)]
        audience: String,
        #[arg(long)]
        subject: String,
    },
    /// Permanently revoke an AMD identity across TCB versions and its selected V2 cache.
    /// Stop AMD admission first; the fee payer funds the identity tombstone.
    RevokeVcek {
        /// Effective AMD identity hash, as 32-byte hex (normally SHA-256 of the chip ID).
        #[arg(long)]
        chip_id_hash: String,
        /// Packed reported TCB version, as an unsigned decimal integer.
        #[arg(long)]
        tcb_version: u64,
    },
    /// Legacy ABI only; pinned-Milan verifier rejects this operation after #172.
    RotateRootCert {
        #[arg(long)]
        root: String,
    },
    /// Register authenticated RSA-2048 key material; provenance is operator responsibility.
    RegisterJwksKey {
        #[arg(long)]
        kid: String,
        #[arg(long)]
        modulus: String,
    },
    RevokeJwksKey {
        /// SHA-256 of the exact key-id bytes.
        #[arg(long)]
        kid_hash: String,
    },
    /// Both current and receiving authority must sign (requires verifier #167).
    RotateAuthority {
        #[arg(long)]
        new_authority: String,
    },
    /// Expire a known signer record (requires verifier #171).
    RevokeAttestedSigner {
        #[arg(long)]
        signer: String,
    },
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], CliError> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| CliError::InvalidArgument(e.to_string()))?
        .try_into()
        .map_err(|_| CliError::InvalidArgument(format!("expected {N} bytes")))
}
fn argument(e: sdk::GovernanceError) -> CliError {
    CliError::InvalidArgument(e.to_string())
}

pub fn build_transaction(args: &GovernanceArgs) -> Result<Transaction, CliError> {
    let pid = parse_pubkey(&args.program_id)?;
    let authority = parse_pubkey(&args.authority)?;
    let payer = args.fee_payer.as_deref().map(parse_pubkey).transpose()?.unwrap_or(authority);
    let ix: Instruction = match &args.command {
        GovernanceCommand::EmergencyHalt { source } => {
            backend_policy::build_set_backend_policy_ix(&pid, &authority, &payer, *source, &[])
                .map_err(|e| CliError::InvalidArgument(e.to_string()))?
        }
        GovernanceCommand::SetBackendPolicy { source, measurement } => {
            let measurements = measurement.iter().map(|m| fixed::<48>(m)).collect::<Result<Vec<_>, _>>()?;
            backend_policy::build_set_backend_policy_ix(&pid, &authority, &payer, *source, &measurements)
                .map_err(|e| CliError::InvalidArgument(e.to_string()))?
        }
        GovernanceCommand::SetGcpTenantPolicy { audience, subject } => {
            gcp_policy::build_set_gcp_tenant_policy_ix(&pid, &authority, &payer, audience, subject)
                .map_err(|e| CliError::InvalidArgument(e.to_string()))?
        }
        GovernanceCommand::RevokeVcek { chip_id_hash, tcb_version } => {
            sdk::build_revoke_vcek_ix(&pid, &authority, &payer, &fixed::<32>(chip_id_hash)?, *tcb_version)
        }
        GovernanceCommand::UpdatePolicy { min_tcb, measurement } => {
            let min_tcb: [u8; 4] =
                min_tcb.clone().try_into().map_err(|_| CliError::InvalidArgument("four TCB bytes required".into()))?;
            let measurements = measurement.iter().map(|m| fixed::<48>(m)).collect::<Result<Vec<_>, _>>()?;
            sdk::build_update_policy_ix(&pid, &authority, &sdk::PolicyUpdate { min_tcb, measurements })
                .map_err(argument)?
        }
        GovernanceCommand::RotateRootCert { root } => {
            sdk::build_rotate_root_cert_ix(&pid, &authority, &fixed::<96>(root)?)
        }
        GovernanceCommand::RegisterJwksKey { kid, modulus } => {
            sdk::build_register_jwks_key_ix(&pid, &authority, &payer, kid.as_bytes(), &fixed::<256>(modulus)?, 65537)
                .map_err(argument)?
        }
        GovernanceCommand::RevokeJwksKey { kid_hash } => {
            sdk::build_revoke_jwks_key_ix(&pid, &authority, fixed::<32>(kid_hash)?)
        }
        GovernanceCommand::RotateAuthority { new_authority } => {
            sdk::build_rotate_authority_ix(&pid, &authority, &parse_pubkey(new_authority)?).map_err(argument)?
        }
        GovernanceCommand::RevokeAttestedSigner { signer } => {
            sdk::build_revoke_attested_signer_ix(&pid, &authority, &parse_pubkey(signer)?)
        }
    };
    Ok(Transaction::new_with_payer(&[ix], Some(&payer)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Commands};
    use clap::Parser;
    use solana_sdk::pubkey::Pubkey;

    fn export(authority: Pubkey, payer: Pubkey, pid: Pubkey, command: &[&str]) -> Transaction {
        let mut argv = vec![
            "solana-confidential-compute".into(),
            "governance".into(),
            "--authority".into(),
            authority.to_string(),
            "--fee-payer".into(),
            payer.to_string(),
            "--program-id".into(),
            pid.to_string(),
        ];
        argv.extend(command.iter().map(|s| s.to_string()));
        let Commands::Governance(args) = Cli::try_parse_from(argv).unwrap().command else { panic!("wrong command") };
        build_transaction(&args).unwrap()
    }

    #[test]
    fn issue_296_halt_and_resume_export_authoritative_packet_sized_policies() {
        let authority = Pubkey::new_unique();
        let pid = Pubkey::new_unique();
        for payer in [authority, Pubkey::new_unique()] {
            for source in 1..=3 {
                for (command, measurements) in [
                    (vec!["emergency-halt", "--source"], vec![]),
                    (vec!["set-backend-policy", "--source"], vec![]),
                    (vec!["set-backend-policy", "--source"], vec![[0x42; 48]]),
                ] {
                    let source_arg = source.to_string();
                    let measurement_arg = hex::encode([0x42; 48]);
                    let mut command = command;
                    command.push(&source_arg);
                    if !measurements.is_empty() {
                        command.extend(["--measurement", &measurement_arg]);
                    }
                    let tx = export(authority, payer, pid, &command);
                    let expected =
                        backend_policy::build_set_backend_policy_ix(&pid, &authority, &payer, source, &measurements)
                            .unwrap();
                    assert_eq!(tx, Transaction::new_with_payer(&[expected], Some(&payer)));
                    // Serializing the unsigned transaction reserves every signature's space.
                    assert!(bincode::serialized_size(&tx).unwrap() <= solana_packet::PACKET_DATA_SIZE as u64);
                    assert_eq!(tx.message.header.num_required_signatures, if payer == authority { 1 } else { 2 });
                    assert_eq!(tx.message.instructions.len(), 1);
                    assert_eq!(tx.message.instructions[0].data[8], source);
                    assert_eq!(&tx.message.instructions[0].data[9..13], &(measurements.len() as u32).to_le_bytes());
                }
            }
        }
    }

    #[test]
    fn issue_296_incident_exports_preserve_exact_targets_and_privileges() {
        let authority = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let pid = Pubkey::new_unique();
        for payer in [authority, payer] {
            let tx = export(
                authority,
                payer,
                pid,
                &["revoke-vcek", "--chip-id-hash", &hex::encode([7; 32]), "--tcb-version", &u64::MAX.to_string()],
            );
            assert_eq!(
                tx,
                Transaction::new_with_payer(
                    &[sdk::build_revoke_vcek_ix(&pid, &authority, &payer, &[7; 32], u64::MAX),],
                    Some(&payer)
                )
            );
            let tx = export(
                authority,
                payer,
                pid,
                &[
                    "set-gcp-tenant-policy",
                    "--audience",
                    "solana-confidential-compute-verifier",
                    "--subject",
                    "tenant/é",
                ],
            );
            assert_eq!(
                tx,
                Transaction::new_with_payer(
                    &[gcp_policy::build_set_gcp_tenant_policy_ix(
                        &pid,
                        &authority,
                        &payer,
                        "solana-confidential-compute-verifier",
                        "tenant/é"
                    )
                    .unwrap(),],
                    Some(&payer)
                )
            );
        }
    }

    #[test]
    fn issue_296_incident_commands_reject_invalid_or_missing_targets() {
        let authority = Pubkey::new_unique().to_string();
        for command in [
            vec!["emergency-halt"],
            vec!["emergency-halt", "--source", "0"],
            // 4 is NVIDIA: no authenticated evidence, so nothing to govern.
            vec!["emergency-halt", "--source", "4"],
            vec!["set-backend-policy", "--source", "256"],
            vec!["revoke-vcek", "--chip-id-hash", "aa"],
            vec!["set-gcp-tenant-policy", "--audience", "aud"],
        ] {
            let mut argv = vec!["solana-confidential-compute", "governance", "--authority", &authority];
            argv.extend(command);
            assert!(Cli::try_parse_from(argv).is_err());
        }
        let too_many = [
            "--measurement",
            "424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242",
        ]
        .repeat(9);
        let mut oversized = vec!["set-backend-policy", "--source", "1"];
        oversized.extend(too_many);
        let long_aud = "é".repeat(65);
        let long_sub = "x".repeat(161);
        for command in [
            vec!["set-backend-policy", "--source", "1", "--measurement", "aa"],
            oversized,
            vec!["revoke-vcek", "--chip-id-hash", "zz", "--tcb-version", "0"],
            vec!["set-gcp-tenant-policy", "--audience", "", "--subject", "sub"],
            vec!["set-gcp-tenant-policy", "--audience", &long_aud, "--subject", "sub"],
            vec!["set-gcp-tenant-policy", "--audience", "aud", "--subject", &long_sub],
        ] {
            let mut argv = vec!["solana-confidential-compute", "governance", "--authority", &authority];
            argv.extend(command);
            let Commands::Governance(args) = Cli::try_parse_from(argv).unwrap().command else { panic!() };
            assert!(build_transaction(&args).is_err());
        }
    }
    #[test]
    fn issue_266_backend_halt_is_explicit_and_offline() {
        let authority = Pubkey::new_unique().to_string();
        for source in [1, 2, 3] {
            let cli = Cli::try_parse_from([
                "solana-confidential-compute",
                "governance",
                "--authority",
                &authority,
                "set-backend-policy",
                "--source",
                &source.to_string(),
            ])
            .unwrap();
            let Commands::Governance(args) = cli.command else { panic!("wrong command") };
            let tx = build_transaction(&args).unwrap();
            let data = &tx.message.instructions[0].data;
            assert_eq!(&data[..8], &solana_confidential_compute_sdk::backend_policy::SET_BACKEND_POLICY_DISCRIMINATOR);
            assert_eq!(data[8], source);
            assert_eq!(&data[9..13], &0u32.to_le_bytes());
            assert_eq!(data.len(), 8 + 1 + 4 + 8 * 48);
            assert!(data[13..].iter().all(|b| *b == 0));
            let backend = solana_confidential_compute_sdk::backend_policy::derive_backend_policy_pda(
                &parse_pubkey(DEFAULT_PROGRAM_ID).unwrap(),
                source,
            )
            .unwrap()
            .0;
            assert!(tx.message.account_keys.contains(&backend));
            assert!(tx.signatures.iter().all(|s| *s == solana_sdk::signature::Signature::default()));
            assert_eq!(tx.message.recent_blockhash, solana_sdk::hash::Hash::default());
        }
    }

    #[test]
    fn offline_rotate_requires_two_authorities_and_rejects_self_transfer() {
        let authority = Pubkey::new_unique();
        let receiving = Pubkey::new_unique();
        for target in [receiving, authority] {
            let cli = Cli::try_parse_from([
                "solana-confidential-compute",
                "governance",
                "--authority",
                &authority.to_string(),
                "rotate-authority",
                "--new-authority",
                &target.to_string(),
            ])
            .unwrap();
            let Commands::Governance(args) = cli.command else { panic!("wrong command") };
            let result = build_transaction(&args);
            if target == authority {
                assert!(result.is_err());
            } else {
                let tx = result.unwrap();
                assert_eq!(tx.message.header.num_required_signatures, 2);
                assert_eq!(tx.message.instructions[0].data, sdk::ROTATE_AUTHORITY_DISCRIMINATOR);
                assert!(tx.signatures.iter().all(|s| *s == solana_sdk::signature::Signature::default()));
                assert_eq!(tx.message.recent_blockhash, solana_sdk::hash::Hash::default());
            }
        }
    }
    #[test]
    fn policy_cli_rejects_malformed_measurement_and_tcb() {
        let authority = Pubkey::new_unique().to_string();
        assert!(Cli::try_parse_from([
            "solana-confidential-compute",
            "governance",
            "--authority",
            &authority,
            "update-policy",
            "--min-tcb",
            "1",
            "2"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "solana-confidential-compute",
            "governance",
            "--authority",
            &authority,
            "update-policy",
            "--min-tcb",
            "1",
            "2",
            "3",
            "4",
            "--measurement",
            "aa",
        ])
        .unwrap();
        let Commands::Governance(args) = cli.command else { panic!() };
        assert!(build_transaction(&args).is_err());
    }
}
