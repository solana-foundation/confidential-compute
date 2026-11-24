//! Offline governance instruction builders. These never submit transactions.
//!
//! Governance trusts the registry authority. Registration does not authenticate
//! Google's key provenance. Callers must authenticate key material independently.
//! Global measurements are deprecated as runtime controls and retained for ABI
//! compatibility: clearing them does not halt AMD/Nitro/GCP admission. Use
//! `backend_policy::build_set_backend_policy_ix` with an empty list for each
//! backend to halt new admission; revoke existing Mode A signers separately.
//! TCB floors cannot be lowered
//! after the verifier's monotonic-policy upgrade. Authority transfer requires both signatures.
use solana_sdk::{
    hash::hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use thiserror::Error;

pub const UPDATE_POLICY_DISCRIMINATOR: [u8; 8] = [227, 150, 114, 217, 142, 172, 100, 228];
pub const ROTATE_ROOT_CERT_DISCRIMINATOR: [u8; 8] = [137, 212, 96, 71, 222, 5, 133, 104];
pub const REGISTER_JWKS_KEY_DISCRIMINATOR: [u8; 8] = [122, 195, 232, 116, 203, 137, 219, 14];
pub const REVOKE_JWKS_KEY_DISCRIMINATOR: [u8; 8] = [184, 102, 12, 45, 99, 128, 41, 16];
pub const ROTATE_AUTHORITY_DISCRIMINATOR: [u8; 8] = [248, 225, 151, 35, 28, 15, 85, 12];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GovernanceError {
    #[error("at most eight 48-byte measurements are supported")]
    InvalidMeasurements,
    #[error("kid must contain 1..=64 non-NUL bytes")]
    InvalidKid,
    #[error("RSA exponent must be 65537; modulus must be odd with its high bit set")]
    InvalidRsaKey,
    #[error("new authority must be nonzero and differ from current authority")]
    InvalidAuthority,
}

/// Minimum TCB components in boot-loader, TEE, SNP, microcode order.
#[derive(Clone, Debug)]
pub struct PolicyUpdate {
    pub min_tcb: [u8; 4],
    /// Deprecated as a runtime control; legacy wire storage only (max eight).
    pub measurements: Vec<[u8; 48]>,
}

fn registry(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"policy_registry"], program_id).0
}
fn authority_accounts(program_id: &Pubkey, authority: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new(registry(program_id), false),
    ]
}

/// Updates monotonic AMD TCB floors and legacy measurements, not backend policy.
/// An empty global list does not halt admission.
pub fn build_update_policy_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    policy: &PolicyUpdate,
) -> Result<Instruction, GovernanceError> {
    if policy.measurements.len() > 8 {
        return Err(GovernanceError::InvalidMeasurements);
    }
    let mut data = UPDATE_POLICY_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&policy.min_tcb);
    data.extend_from_slice(&(policy.measurements.len() as u32).to_le_bytes());
    for i in 0..8 {
        data.extend_from_slice(policy.measurements.get(i).unwrap_or(&[0; 48]));
    }
    Ok(Instruction {
        program_id: *program_id,
        accounts: authority_accounts(program_id, authority),
        data,
    })
}

/// Legacy wire builder. The pinned-Milan verifier rejects mutable root rotation
/// after #172; constructing this instruction does not make that operation supported.
pub fn build_rotate_root_cert_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    new_ark_pubkey_xy: &[u8; 96],
) -> Instruction {
    let mut data = ROTATE_ROOT_CERT_DISCRIMINATOR.to_vec();
    data.extend_from_slice(new_ark_pubkey_xy);
    Instruction {
        program_id: *program_id,
        accounts: authority_accounts(program_id, authority),
        data,
    }
}

pub fn derive_jwks_pda(program_id: &Pubkey, kid_hash: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"jwks", kid_hash], program_id).0
}

pub fn build_register_jwks_key_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    kid: &[u8],
    modulus: &[u8; 256],
    exponent: u32,
) -> Result<Instruction, GovernanceError> {
    if kid.is_empty() || kid.len() > 64 || kid.contains(&0) {
        return Err(GovernanceError::InvalidKid);
    }
    if exponent != 65537 || modulus[0] & 0x80 == 0 || modulus[255] & 1 == 0 {
        return Err(GovernanceError::InvalidRsaKey);
    }
    let mut accounts = authority_accounts(program_id, authority);
    accounts.push(AccountMeta::new(
        derive_jwks_pda(program_id, &hash(kid).to_bytes()),
        false,
    ));
    // Registry is read-only for key registration.
    accounts[1].is_writable = false;
    accounts.push(AccountMeta::new(*payer, true));
    accounts.push(AccountMeta::new_readonly(
        solana_sdk_ids::system_program::ID,
        false,
    ));
    let mut data = REGISTER_JWKS_KEY_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&(kid.len() as u32).to_le_bytes());
    data.extend_from_slice(kid);
    data.extend_from_slice(modulus);
    data.extend_from_slice(&exponent.to_le_bytes());
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

pub fn build_revoke_jwks_key_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    kid_hash: [u8; 32],
) -> Instruction {
    let mut accounts = authority_accounts(program_id, authority);
    accounts[1].is_writable = false;
    accounts.push(AccountMeta::new(
        derive_jwks_pda(program_id, &kid_hash),
        false,
    ));
    let mut data = REVOKE_JWKS_KEY_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&kid_hash);
    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

/// Both the current and receiving authority must sign the resulting transaction.
pub fn build_rotate_authority_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    receiving_authority: &Pubkey,
) -> Result<Instruction, GovernanceError> {
    if receiving_authority == authority || *receiving_authority == Pubkey::default() {
        return Err(GovernanceError::InvalidAuthority);
    }
    let mut accounts = authority_accounts(program_id, authority);
    accounts.push(AccountMeta::new_readonly(*receiving_authority, true));
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data: ROTATE_AUTHORITY_DISCRIMINATOR.to_vec(),
    })
}

/// Discriminator for the additive governance revocation operation (#171).
pub const REVOKE_ATTESTED_SIGNER_DISCRIMINATOR: [u8; 8] = [174, 9, 66, 138, 2, 191, 81, 61];
/// Canonical CPI signer namespace; migrates with enrollment.
pub fn build_revoke_attested_signer_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    signer: &Pubkey,
) -> Instruction {
    let mut accounts = authority_accounts(program_id, authority);
    accounts[1].is_writable = false;
    accounts.push(AccountMeta::new(
        Pubkey::find_program_address(
            &[
                solana_confidential_compute_cpi::ATTESTED_SIGNER_SEED,
                signer.as_ref(),
            ],
            program_id,
        )
        .0,
        false,
    ));
    let mut data = REVOKE_ATTESTED_SIGNER_DISCRIMINATOR.to_vec();
    data.extend_from_slice(signer.as_ref());
    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

/// Discriminator for governed V2 VCEK cache revocation (#176).
pub const REVOKE_VCEK_DISCRIMINATOR: [u8; 8] = [81, 34, 243, 59, 64, 69, 29, 89];
/// Revoke the canonical cache and its AMD identity across TCB versions.
/// `payer` funds the permanent identity tombstone; authority remains governance.
pub fn build_revoke_vcek_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    chip_id_hash: &[u8; 32],
    tcb_version: u64,
) -> Instruction {
    let mut accounts = authority_accounts(program_id, authority);
    accounts[1].is_writable = false;
    accounts.push(AccountMeta::new(
        crate::builder::derive_vcek_pda(program_id, chip_id_hash, tcb_version),
        false,
    ));
    accounts.extend([
        AccountMeta::new(
            crate::derive_amd_revocation_pda(program_id, chip_id_hash).0,
            false,
        ),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
    ]);
    let mut data = REVOKE_VCEK_DISCRIMINATOR.to_vec();
    data.extend_from_slice(chip_id_hash);
    data.extend_from_slice(&tcb_version.to_le_bytes());
    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}
