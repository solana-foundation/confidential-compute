//! Resource and fee policy for caller transactions signed by the workload.
//!
//! Protocol resource ceilings preserve legitimate 1.4M CU staging. Callers may
//! request no added priority fee: `SetComputeUnitPrice` must be zero. Base fees
//! remain the responsibility of a distinct external payer, enforced by the key
//! manager. This screen does not establish attestation or action consent.

use solana_sdk::{pubkey::Pubkey, transaction::VersionedTransaction};

const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

/// Accept supported Compute Budget instructions within protocol resource bounds.
/// Deprecated `RequestUnits` and unknown tags are rejected. A zero priority
/// price prevents caller-selected priority fees without an arbitrary price cap.
pub fn compute_budget_allowed(data: &[u8]) -> bool {
    match data {
        [1, a, b, c, d] => {
            let bytes = u32::from_le_bytes([*a, *b, *c, *d]);
            (32 * 1024..=256 * 1024).contains(&bytes) && bytes % 1024 == 0
        }
        [2, a, b, c, d] => (1..=1_400_000).contains(&u32::from_le_bytes([*a, *b, *c, *d])),
        [3, 0, 0, 0, 0, 0, 0, 0, 0] => true,
        [4, a, b, c, d] => (1..=64 * 1024 * 1024).contains(&u32::from_le_bytes([*a, *b, *c, *d])),
        _ => false,
    }
}

/// Check the complete Compute Budget instruction set before signature release.
/// Duplicate settings fail on chain, so reject them here too. No accounts are
/// needed by these instructions; account-bearing variants fail closed.
pub fn validate_compute_budget(tx: &VersionedTransaction) -> Result<(), String> {
    let keys = tx.message.static_account_keys();
    let mut seen = [false; 5];
    for ix in tx.message.instructions() {
        if keys.get(ix.program_id_index as usize) != Some(&COMPUTE_BUDGET_PROGRAM_ID) {
            continue;
        }
        if !ix.accounts.is_empty() || !compute_budget_allowed(&ix.data) {
            return Err(
                "compute budget instruction is not allowlisted by resource/fee policy".into(),
            );
        }
        let tag = ix.data[0] as usize;
        if std::mem::replace(&mut seen[tag], true) {
            return Err("duplicate compute budget setting is not allowlisted".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_compute_budget_interface::ComputeBudgetInstruction as Budget;
    use solana_sdk::message::Message;

    fn encoded(tag: u8, n: u32) -> Vec<u8> {
        let mut data = vec![tag];
        data.extend_from_slice(&n.to_le_bytes());
        data
    }

    #[test]
    fn resource_limits_include_full_staging_headroom_and_reject_invalid_values() {
        for n in [1, 400_000, 1_400_000] {
            assert!(compute_budget_allowed(&encoded(2, n)));
        }
        for n in [0, 1_400_001, u32::MAX] {
            assert!(!compute_budget_allowed(&encoded(2, n)));
        }
        for n in [32 * 1024, 33 * 1024, 256 * 1024] {
            assert!(compute_budget_allowed(&encoded(1, n)));
        }
        for n in [0, 31 * 1024, 32 * 1024 + 1, 256 * 1024 + 1, u32::MAX] {
            assert!(!compute_budget_allowed(&encoded(1, n)));
        }
        for n in [1, 64 * 1024 * 1024] {
            assert!(compute_budget_allowed(&encoded(4, n)));
        }
        for n in [0, 64 * 1024 * 1024 + 1, u32::MAX] {
            assert!(!compute_budget_allowed(&encoded(4, n)));
        }
    }

    #[test]
    fn fee_bounds_and_guaranteed_failure_tags() {
        assert!(compute_budget_allowed(
            &Budget::set_compute_unit_price(0).data
        ));
        for price in [1, 1_000_000, u64::MAX] {
            assert!(!compute_budget_allowed(
                &Budget::set_compute_unit_price(price).data
            ));
        }
        assert!(!compute_budget_allowed(&[0; 9]));
        assert!(!compute_budget_allowed(&[5, 0, 0, 0, 0]));
        assert!(!compute_budget_allowed(&[]));
        for tag in 1..=4 {
            let valid = if tag == 3 {
                Budget::set_compute_unit_price(0).data
            } else {
                encoded(tag, 32 * 1024)
            };
            let mut trailing = valid.clone();
            trailing.push(0);
            assert!(!compute_budget_allowed(&trailing));
            assert!(!compute_budget_allowed(&valid[..valid.len() - 1]));
        }
    }

    #[test]
    fn duplicate_budget_settings_and_extra_accounts_are_rejected() {
        let payer = Pubkey::new_unique();
        let limit = Budget::set_compute_unit_limit(1_400_000);
        let check = |instructions: &[solana_sdk::instruction::Instruction]| {
            let tx = VersionedTransaction {
                signatures: vec![],
                message: solana_sdk::message::VersionedMessage::Legacy(Message::new(
                    instructions,
                    Some(&payer),
                )),
            };
            validate_compute_budget(&tx)
        };
        assert!(check(&[
            limit.clone(),
            Budget::set_compute_unit_price(0),
            Budget::request_heap_frame(256 * 1024),
            Budget::set_loaded_accounts_data_size_limit(64 * 1024 * 1024)
        ])
        .is_ok());
        assert!(check(&[limit.clone(), limit.clone()]).is_err());
        let mut extra = limit;
        extra
            .accounts
            .push(solana_sdk::instruction::AccountMeta::new_readonly(
                payer, true,
            ));
        assert!(check(&[extra]).is_err());
    }
}
