//! Exercise the shipped binary's incident-response output, without RPC or keys.
use solana_sdk::{pubkey::Pubkey, transaction::Transaction};
use std::process::Command;

#[test]
fn legacy_update_warns_while_emergency_halt_exports_the_runtime_control() {
    let authority = Pubkey::new_unique().to_string();
    for (command, deprecated) in [
        (vec!["update-policy", "--min-tcb", "0", "0", "0", "0"], true),
        (vec!["emergency-halt", "--source", "3"], false),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_solana-confidential-compute"))
            .args(["governance", "--authority", &authority])
            .args(command)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.contains("do NOT halt admission"), deprecated);
        if deprecated {
            assert!(stderr.contains("emergency-halt --source"));
        }
        let stdout = String::from_utf8(output.stdout).unwrap();
        let encoded = stdout.lines().find_map(|line| line.strip_prefix("unsigned_transaction_hex=")).unwrap();
        let tx: Transaction = bincode::deserialize(&hex::decode(encoded).unwrap()).unwrap();
        let disc = if deprecated {
            solana_confidential_compute_sdk::governance::UPDATE_POLICY_DISCRIMINATOR
        } else {
            solana_confidential_compute_sdk::backend_policy::SET_BACKEND_POLICY_DISCRIMINATOR
        };
        assert_eq!(&tx.message.instructions[0].data[..8], &disc);
        assert_eq!(tx.message.recent_blockhash, solana_sdk::hash::Hash::default());
        assert!(tx.signatures.iter().all(|sig| *sig == solana_sdk::signature::Signature::default()));
        assert!(stdout.contains("before submission"));
    }
}
