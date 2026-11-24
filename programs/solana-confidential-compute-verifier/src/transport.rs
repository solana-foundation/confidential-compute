//! Bounded, authority-bound transport. Sealing authenticates bytes, never attestations.
//! Consume runs the existing on-chain handler; its trust, identity and replay checks apply.
use super::Processor;
use crate::payload::{
    REGISTER_VCEK_DISCRIMINATOR, VERIFY_AND_REGISTER_DISCRIMINATOR,
    VERIFY_NITRO_ATTESTATION_DISCRIMINATOR, VERIFY_NITRO_MODE_A,
};
use solana_confidential_compute_core::SignatureVerifier;
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult, hash::hash,
    program_error::ProgramError, pubkey::Pubkey, sysvar::Sysvar,
};

pub const BEGIN: [u8; 8] = *b"stagebeg";
pub const UPLOAD: [u8; 8] = *b"stageput";
pub const SEAL: [u8; 8] = *b"stagesea";
pub const CONSUME: [u8; 8] = *b"stageuse";
pub const CLOSE: [u8; 8] = *b"stagedel";
pub const MAX_PAYLOAD: usize = 9000;
pub const MAX_CHUNK: usize = 700;
pub const MAX_LIFETIME_SLOTS: u64 = 150;
// magic8, authority32, digest32, expiry8, length4, written4, state1.
pub const HEADER: usize = 89;
const MAGIC: &[u8; 8] = b"TETSTG01";
const SEED: &[u8] = b"attestation_stage";

pub fn is_transport(tag: &[u8]) -> bool {
    [BEGIN, UPLOAD, SEAL, CONSUME, CLOSE]
        .iter()
        .any(|t| tag == t)
}

fn invalid() -> ProgramError {
    ProgramError::InvalidInstructionData
}
fn u32_at(data: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize
}
fn allowed(payload: &[u8]) -> bool {
    payload.starts_with(&VERIFY_AND_REGISTER_DISCRIMINATOR)
        || payload.starts_with(&REGISTER_VCEK_DISCRIMINATOR)
        || (payload.starts_with(&VERIFY_NITRO_ATTESTATION_DISCRIMINATOR)
            && payload.get(8) == Some(&VERIFY_NITRO_MODE_A))
}

impl Processor {
    pub(super) fn process_transport<V: SignatureVerifier>(
        verifier: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        tag: &[u8],
        rest: &[u8],
    ) -> ProgramResult {
        let [authority, stage, remaining @ ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !authority.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        if !stage.is_writable || authority.key == stage.key {
            return Err(invalid());
        }
        if tag == BEGIN {
            // digest32 || length4 || expiry8; exact size, no arbitrary allocation.
            if rest.len() != 44 {
                return Err(invalid());
            }
            let length = u32_at(rest, 32);
            let expiry = u64::from_le_bytes(rest[36..44].try_into().unwrap());
            let now = Clock::get()?.slot;
            if !(8..=MAX_PAYLOAD).contains(&length)
                || expiry <= now
                || expiry - now > MAX_LIFETIME_SLOTS
            {
                return Err(invalid());
            }
            let (expected, bump) = Pubkey::find_program_address(
                &[SEED, authority.key.as_ref(), &rest[..32]],
                program_id,
            );
            if stage.key != &expected {
                return Err(ProgramError::InvalidSeeds);
            }
            // Never reinitialize any live stage, including consumed records.
            if stage.data_len() != 0 && stage.try_borrow_data()?.iter().any(|b| *b != 0) {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
            Self::create_pda_if_needed(
                authority,
                stage,
                remaining.first(),
                program_id,
                &[SEED, authority.key.as_ref(), &rest[..32], &[bump]],
                HEADER + length,
            )?;
            let mut data = stage.try_borrow_mut_data()?;
            data[..8].copy_from_slice(MAGIC);
            data[8..40].copy_from_slice(authority.key.as_ref());
            data[40..72].copy_from_slice(&rest[..32]);
            data[72..80].copy_from_slice(&expiry.to_le_bytes());
            data[80..84].copy_from_slice(&(length as u32).to_le_bytes());
            return Ok(());
        }
        if stage.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let mut data = stage.try_borrow_mut_data()?;
        if data.len() < HEADER || &data[..8] != MAGIC || &data[8..40] != authority.key.as_ref() {
            return Err(ProgramError::InvalidAccountData);
        }
        let (expected, _) = Pubkey::find_program_address(
            &[SEED, authority.key.as_ref(), &data[40..72]],
            program_id,
        );
        if stage.key != &expected {
            return Err(ProgramError::InvalidSeeds);
        }
        let length = u32_at(&data, 80);
        let written = u32_at(&data, 84);
        if length > MAX_PAYLOAD || data.len() != HEADER + length || written > length {
            return Err(invalid());
        }
        if tag == CLOSE {
            if !rest.is_empty() || !authority.is_writable {
                return Err(invalid());
            }
            // Owner may cancel any stage. Refund only its authenticated authority.
            let balance = authority
                .lamports()
                .checked_add(stage.lamports())
                .ok_or(ProgramError::ArithmeticOverflow)?;
            **authority.try_borrow_mut_lamports()? = balance;
            **stage.try_borrow_mut_lamports()? = 0;
            data.fill(0);
            return Ok(());
        }
        let expiry = u64::from_le_bytes(data[72..80].try_into().unwrap());
        if Clock::get()?.slot >= expiry {
            return Err(invalid());
        }
        if tag == UPLOAD {
            if data[88] != 0 || rest.len() <= 4 || rest.len() > 4 + MAX_CHUNK {
                return Err(invalid());
            }
            let offset = u32_at(rest, 0);
            let end = offset.checked_add(rest.len() - 4).ok_or_else(invalid)?;
            if offset != written || end > length {
                return Err(invalid());
            }
            data[HEADER + offset..HEADER + end].copy_from_slice(&rest[4..]);
            data[84..88].copy_from_slice(&(end as u32).to_le_bytes());
            return Ok(());
        }
        if !rest.is_empty() {
            return Err(invalid());
        }
        if tag == SEAL {
            if data[88] != 0
                || written != length
                || hash(&data[HEADER..]).as_ref() != &data[40..72]
                || !allowed(&data[HEADER..])
            {
                return Err(invalid());
            }
            data[88] = 1;
            return Ok(());
        }
        if tag != CONSUME || data[88] != 1 {
            return Err(invalid());
        }
        // Stage cannot alias any handler account. The handler payer must be this
        // authority (so uploads confer no signing authority on another payer).
        if remaining.first().map(|a| a.key) != Some(authority.key)
            || remaining.iter().any(|a| a.key == stage.key)
        {
            return Err(invalid());
        }
        if !allowed(&data[HEADER..]) {
            return Err(invalid());
        }
        // Borrow bytes in place; no unbounded heap copy or recursive dispatch.
        if data[HEADER..].starts_with(&REGISTER_VCEK_DISCRIMINATOR) {
            Self::process_register_vcek(program_id, remaining, &data[HEADER + 8..])?;
        } else if data[HEADER..].starts_with(&VERIFY_AND_REGISTER_DISCRIMINATOR) {
            Self::process_verify_and_register(
                verifier,
                program_id,
                remaining,
                &data[HEADER + 8..],
            )?;
        } else {
            // No staged atomic consumer adapter exists. `allowed` rejects Mode B
            // both at seal and consume; never downgrade to Mode A.
            Self::process_verify_nitro_attestation(
                verifier,
                program_id,
                remaining,
                &data[HEADER + 8..],
            )?;
        }
        data[88] = 2;
        Ok(())
    }
}
