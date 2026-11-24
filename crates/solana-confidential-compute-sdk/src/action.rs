//! V3 commitments from complete compiled transaction metadata.
//!
//! Before obtaining evidence, compile a metadata template with the final payer,
//! program ids and account metas for EVERY instruction. Other instruction data
//! may be empty: it does not affect compilation privileges. Consumer data must
//! be final. Keep digest-derived nonce/upload accounts out of consumer accounts;
//! otherwise constructing their keys may create a hash fixed-point problem.
//! Replace template bytes/derived keys with evidence, then validate the FINAL
//! message before signing. Any key alias or added instruction can change flags.
use solana_sdk::{instruction::AccountMeta, message::VersionedMessage};
use std::collections::HashSet;
use thiserror::Error;

// MIGRATION STUB (needs decision): `solana_sdk::reserved_account_keys` was removed in
// solana-sdk 4.x. Upstream replacement `agave-reserved-account-keys` is only published
// as 4.5.0-alpha.2 and is itself gated behind `agave-unstable-api`. This vendored set
// MUST exactly reproduce `ReservedAccountKeys::new_all_activated()` from solana-sdk 2.2,
// or client-computed action commitments will diverge from on-chain ones.
fn reserved_account_keys_all_activated() -> HashSet<solana_sdk::pubkey::Pubkey> {
    #[allow(deprecated)]
    [
        solana_sdk_ids::address_lookup_table::ID,
        solana_sdk_ids::bpf_loader::ID,
        solana_sdk_ids::bpf_loader_deprecated::ID,
        solana_sdk_ids::bpf_loader_upgradeable::ID,
        solana_sdk_ids::compute_budget::ID,
        solana_sdk_ids::config::ID,
        solana_sdk_ids::ed25519_program::ID,
        solana_sdk_ids::feature::ID,
        solana_sdk_ids::loader_v4::ID,
        solana_sdk_ids::native_loader::ID,
        solana_sdk_ids::secp256k1_program::ID,
        solana_sdk_ids::secp256r1_program::ID,
        solana_sdk_ids::stake::config::ID,
        solana_sdk_ids::stake::ID,
        solana_sdk_ids::system_program::ID,
        solana_sdk_ids::vote::ID,
        solana_sdk_ids::sysvar::ID,
        solana_sdk_ids::sysvar::clock::ID,
        solana_sdk_ids::sysvar::epoch_rewards::ID,
        solana_sdk_ids::sysvar::epoch_schedule::ID,
        solana_sdk_ids::sysvar::fees::ID,
        solana_sdk_ids::sysvar::instructions::ID,
        solana_sdk_ids::sysvar::last_restart_slot::ID,
        solana_sdk_ids::sysvar::recent_blockhashes::ID,
        solana_sdk_ids::sysvar::rent::ID,
        solana_sdk_ids::sysvar::rewards::ID,
        solana_sdk_ids::sysvar::slot_hashes::ID,
        solana_sdk_ids::sysvar::slot_history::ID,
        solana_sdk_ids::sysvar::stake_history::ID,
        solana_sdk_ids::zk_token_proof_program::ID,
        solana_sdk_ids::zk_elgamal_proof_program::ID,
    ]
    .into_iter()
    .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ActionCommitmentError {
    #[error("malformed message, unresolved address tables, or unsupported discriminator")]
    InvalidMessage,
    #[error("writable reserved account requires runtime feature resolution; refusing to guess")]
    ReservedWritable,
    #[error("consumer does not match the V3 effective-privilege commitment")]
    Mismatch,
}

/// Resolve effective privileges using Solana's compiled message rules.
/// `split_hint` is retained for source compatibility and has no effect on the
/// digest: all instruction bytes are hashed, including empty/short data.
/// LUT messages are rejected until fully resolved. Writable reserved keys are
/// rejected conservatively across feature activations, rather than assigning
/// them guessed runtime privileges. Program-id demotion uses the SDK rule.
#[allow(deprecated)]
pub fn hash_compiled_action(
    message: &VersionedMessage,
    consumer_index: usize,
    _split_hint: usize,
) -> Result<[u8; 32], ActionCommitmentError> {
    use ActionCommitmentError::*;
    message.sanitize().map_err(|_| InvalidMessage)?;
    if message.address_table_lookups().is_some_and(|t| !t.is_empty()) {
        return Err(InvalidMessage);
    }
    let ix = message.instructions().get(consumer_index).ok_or(InvalidMessage)?;
    let keys = message.static_account_keys();
    let reserved = reserved_account_keys_all_activated();
    let header = message.header();
    let requested_writable = |i: usize| {
        if i < header.num_required_signatures as usize {
            i < (header.num_required_signatures - header.num_readonly_signed_accounts) as usize
        } else {
            i < keys.len() - header.num_readonly_unsigned_accounts as usize
        }
    };
    let accounts = ix
        .accounts
        .iter()
        .map(|index| {
            let i = usize::from(*index);
            let pubkey = *keys.get(i).ok_or(InvalidMessage)?;
            if requested_writable(i) && reserved.contains(&pubkey) {
                return Err(ReservedWritable);
            }
            Ok(AccountMeta {
                pubkey,
                is_signer: message.is_signer(i),
                is_writable: message.is_maybe_writable_with_reserved_addresses(i, Some(&reserved)),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(solana_confidential_compute_cpi::hash_action(&[], &accounts, &ix.data))
}

/// Final-message guard over the complete consumer wire data.
/// Must be rerun after changing payer, account keys, or the instruction list.
pub fn validate_compiled_action(
    message: &VersionedMessage,
    index: usize,
    expected: &[u8; 32],
) -> Result<(), ActionCommitmentError> {
    if hash_compiled_action(message, index, 0).is_ok_and(|digest| digest == *expected) {
        return Ok(());
    }
    Err(ActionCommitmentError::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client-side writability approximation feeds the Mode B action
    /// commitment, and the Rust and TypeScript SDKs must agree byte for byte:
    /// a single key of drift silently changes the digest and breaks every
    /// deployed consumer. `solana_sdk::reserved_account_keys` was removed in
    /// solana-sdk 4.x with no stable replacement (`agave-reserved-account-keys`
    /// is prerelease only), so both SDKs vendor the list. Pin them together.
    #[test]
    fn vendored_reserved_keys_match_the_typescript_sdk() {
        let ts_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../sdks/typescript/src/index.ts");
        let ts_src = std::fs::read_to_string(ts_path).unwrap_or_else(|e| panic!("read {ts_path}: {e}"));

        let start =
            ts_src.find("const RESERVED_ACTION_KEYS").expect("RESERVED_ACTION_KEYS not found in the TypeScript SDK");
        let block_end = ts_src[start..].find("]);").expect("unterminated RESERVED_ACTION_KEYS") + start;

        let ts_keys: std::collections::BTreeSet<String> = ts_src[start..block_end]
            .lines()
            .filter_map(|line| {
                let raw = line.trim().trim_end_matches(',');
                let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
                inner.parse::<solana_sdk::pubkey::Pubkey>().ok()?;
                Some(inner.to_string())
            })
            .collect();
        assert!(!ts_keys.is_empty(), "parsed zero keys from the TypeScript RESERVED_ACTION_KEYS set");

        let rust_keys: std::collections::BTreeSet<String> =
            reserved_account_keys_all_activated().iter().map(|k| k.to_string()).collect();

        let missing_in_rust: Vec<_> = ts_keys.difference(&rust_keys).collect();
        let missing_in_ts: Vec<_> = rust_keys.difference(&ts_keys).collect();
        assert!(
            missing_in_rust.is_empty() && missing_in_ts.is_empty(),
            "reserved-key sets drifted.\n  in TypeScript but not Rust: {missing_in_rust:?}\n  \
             in Rust but not TypeScript: {missing_in_ts:?}"
        );
    }
}
