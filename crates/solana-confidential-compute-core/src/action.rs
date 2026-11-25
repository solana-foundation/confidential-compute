//! Canonical Mode B action commitments. V3 binds complete instruction bytes and
//! ordered effective message privileges. V1/V2 digests are not a fallback.

use alloc::vec::Vec;
use solana_program::{hash::hashv, instruction::Instruction, pubkey::Pubkey};

pub const ACTION_COMMITMENT_DOMAIN: &[u8] = b"solana-confidential-compute:action:v1\0";

/// Stream a complete instruction, allowing callers to retain their local
/// discriminator/payload split without committing that split as wire metadata.
/// Flags must describe the final compiled message (or top-level AccountInfo),
/// including payer/other-instruction elevation and Solana program demotion.
/// Preserve account order and duplicates; do not pass unresolved lookup tables.
pub fn hash_action_parts<'a>(
    discriminator: &[u8],
    count: usize,
    accounts: impl Iterator<Item = (&'a Pubkey, bool, bool)>,
    payload: &[u8],
) -> [u8; 32] {
    // MIGRATION NOTE: solana-program 4.x removes the incremental `hash::Hasher` on
    // the SBF target (`#[cfg(not(target_os = "solana"))]`). `hashv` over the same
    // ordered byte segments is bit-identical to streaming them through `Hasher`,
    // so the committed digest is unchanged.
    let count_le = (count as u32).to_le_bytes();
    // A slice holds at most `isize::MAX` bytes, so this sum is at most
    // `usize::MAX - 1` and the saturation never applies.
    let len_le = (discriminator.len().saturating_add(payload.len()) as u32).to_le_bytes();
    let mut flag_bytes: Vec<[u8; 2]> = Vec::new();
    let mut segments: Vec<&[u8]> = Vec::new();
    let collected: Vec<(&Pubkey, bool, bool)> = accounts.collect();
    for (_, signer, writable) in &collected {
        flag_bytes.push([u8::from(*signer), u8::from(*writable)]);
    }
    segments.push(ACTION_COMMITMENT_DOMAIN);
    segments.push(&count_le);
    for (i, (key, _, _)) in collected.iter().enumerate() {
        segments.push(key.as_ref());
        segments.push(&flag_bytes[i]);
    }
    segments.push(&len_le);
    segments.push(discriminator);
    segments.push(payload);
    hashv(&segments).to_bytes()
}

/// Hash an instruction reconstructed from the Instructions sysvar. Its account
/// flags are effective transaction privileges, not isolated declared metas.
/// Off-chain callers must first resolve the final compiled message.
pub fn hash_instruction(instruction: &Instruction) -> [u8; 32] {
    hash_action_parts(
        &[],
        instruction.accounts.len(),
        instruction.accounts.iter().map(|a| (&a.pubkey, a.is_signer, a.is_writable)),
        &instruction.data,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::instruction::AccountMeta;

    #[test]
    fn full_wire_is_independent_of_discriminator_split_and_binds_metadata() {
        let key = Pubkey::new_unique();
        let ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(key, true), AccountMeta::new_readonly(key, false)],
            data: vec![1, 2, 3, 4],
        };
        let expected = hash_instruction(&ix);
        for split in 0..=ix.data.len() {
            assert_eq!(
                expected,
                hash_action_parts(
                    &ix.data[..split],
                    ix.accounts.len(),
                    ix.accounts.iter().map(|a| (&a.pubkey, a.is_signer, a.is_writable)),
                    &ix.data[split..]
                )
            );
        }
        let mut changed = ix.clone();
        changed.accounts[0].is_signer = false;
        assert_ne!(expected, hash_instruction(&changed));
        changed = ix.clone();
        changed.accounts[0].is_writable = false;
        assert_ne!(expected, hash_instruction(&changed));
        changed = ix.clone();
        changed.accounts.reverse();
        assert_ne!(expected, hash_instruction(&changed));
        changed = ix.clone();
        changed.accounts.pop();
        assert_ne!(expected, hash_instruction(&changed));
        changed = ix.clone();
        changed.data.push(0);
        assert_ne!(expected, hash_instruction(&changed));
    }
}
