//! Bank component test of SDK AMD Mode B account plumbing: the instructions
//! sysvar reaches the handler and the nonce is consumed. Preloaded VCEK trust
//! is a test fixture, not vendor/hardware proof.
//!
//! MIGRATION (solana 2.2 -> 4.x): the bank already drove this through
//! `ProgramTest`, but the program was `processor!(Processor::process_with(
//! MockVerifier))`. In 4.x `Clock::get()` resolves through
//! `solana_get_sysvar::sol_get_sysvar`, whose non-solana branch is a hardcoded
//! `UNSUPPORTED_SYSVAR` that never consults `program_stubs`, so a natively
//! linked program can no longer read any sysvar. `MockVerifier` cannot follow
//! the program onto SBF either -- `solana-confidential-compute-core` gates it behind
//! `not(target_os = "solana")`, so the `mock-crypto` feature does not build for
//! the SBF target. The simulated signature is therefore replaced by a real
//! P-384 one over a locally generated report, with the matching public key
//! preloaded into the VCEK cache (the same device the verifier would have
//! admitted via `register_vcek`). Signature arithmetic is no longer simulated;
//! every other account, instruction and assertion is unchanged, except that
//! the nonce slot and slot hash now come from the bank instead of being
//! injected, so the recorded slot is the bank's rather than a hardcoded 520.
//!
//! One asserted property genuinely changes. On `target_os = "solana"` the
//! verifier's backend is `SolanaDefaultVerifier`, which does no P-384
//! arithmetic: it scans `sysvar::instructions` for a preceding sigverify
//! precompile instruction carrying `pubkey || digest || signature` and compares
//! those bytes against the report. So this test no longer observes signature
//! arithmetic at all (native `MockVerifier` at least stood in for it); it now
//! observes the Mode B precompile binding, which `MockVerifier` used to skip
//! entirely. The signature is still a genuine P-384 one over the report body,
//! so the instruction handed to the precompile is one a real precompile would
//! accept once `EXPECTED_SIGVERIFY_PROGRAM_ID` is deployed.
#![cfg(feature = "test-utils")]
use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha384};
use solana_confidential_compute_sdk::{internal::build_verify_atomic_with_nonce_ix_oversized, SNP_REPORT_SIZE};
use solana_confidential_compute_verifier::state::{
    BackendPolicy, PolicyRegistry, UsedNonceAccount, VcekAccount, POLICY_REGISTRY_DISCRIMINATOR,
    VCEK_ACCOUNT_DISCRIMINATOR,
};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};
use solana_program_test::processor;
use solana_sdk::{
    account::Account, clock::Clock, hash::hash, instruction::Instruction, pubkey::Pubkey, signature::Signer,
    slot_hashes::SlotHashes, transaction::Transaction,
};

#[path = "support/sbf.rs"]
mod sbf;

fn consumer(_: &Pubkey, _: &[AccountInfo], _: &[u8]) -> ProgramResult {
    Ok(())
}
/// Stand-in for the unassigned secp384r1 precompile. The verifier only reads
/// its instruction data out of `sysvar::instructions`, so the program itself
/// never has to run the curve arithmetic.
fn sigverify(_: &Pubkey, _: &[AccountInfo], _: &[u8]) -> ProgramResult {
    Ok(())
}
/// `solana_confidential_compute_verifier::processor::EXPECTED_SIGVERIFY_PROGRAM_ID` is gated behind
/// `target_os = "solana"`, so the host build re-states the literal: ASCII
/// "SECP384R1SIGVERIFY", zero padded.
const SIGVERIFY_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x53, 0x45, 0x43, 0x50, 0x33, 0x38, 0x34, 0x52, 0x31, 0x53, 0x49, 0x47, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
/// `pubkey (96) || digest (48) || signature (96)`.
fn sigverify_ix(public_key_xy: &[u8; 96], digest: &[u8; 48], signature_rs: &[u8; 96]) -> Instruction {
    let mut data = Vec::with_capacity(240);
    data.extend_from_slice(public_key_xy);
    data.extend_from_slice(digest);
    data.extend_from_slice(signature_rs);
    Instruction::new_with_bytes(SIGVERIFY_PROGRAM_ID, &data, vec![])
}
fn account(data: Vec<u8>, owner: Pubkey) -> Account {
    Account { lamports: 100_000_000, data, owner, executable: false, rent_epoch: 0 }
}
#[tokio::test]
async fn sdk_amd_mode_b_supplies_instructions_sysvar_and_consumes_nonce() {
    let pid = solana_confidential_compute_verifier::id();
    let consumer_id = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let measurement = [42; 48];
    let mut scalar = [0; 48];
    scalar[47] = 33;
    let signing = SigningKey::from_slice(&scalar).unwrap();
    let encoded = signing.verifying_key().to_sec1_point(false);
    let xy: [u8; 96] = encoded.as_bytes()[1..].try_into().unwrap();
    let consumer_ix = Instruction::new_with_bytes(consumer_id, &[], vec![]);
    let action_hash = solana_confidential_compute_core::action::hash_instruction(&consumer_ix);
    let identity = hash(&[9; 64]).to_bytes();
    let (vcek, vb) = Pubkey::find_program_address(&[b"vcek_v2", &identity, &0u64.to_le_bytes()], &pid);
    let mut cache = vec![0; VcekAccount::SIZE];
    cache[..8].copy_from_slice(&VCEK_ACCOUNT_DISCRIMINATOR);
    cache[8..40].copy_from_slice(&identity);
    cache[VcekAccount::PUBLIC_KEY_OFFSET..VcekAccount::PUBLIC_KEY_OFFSET + 96].copy_from_slice(&xy);
    cache[VcekAccount::BUMP_OFFSET] = vb;
    cache[VcekAccount::TRUST_PROFILE_OFFSET..VcekAccount::VALID_UNTIL_OFFSET]
        .copy_from_slice(&VcekAccount::MILAN_TRUST_PROFILE);
    cache[VcekAccount::VALID_UNTIL_OFFSET..VcekAccount::REVOKED_OFFSET].copy_from_slice(&u64::MAX.to_le_bytes());
    let (registry, rb) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let mut policy = vec![0; PolicyRegistry::SIZE];
    policy[..8].copy_from_slice(&POLICY_REGISTRY_DISCRIMINATOR);
    policy[PolicyRegistry::BUMP_OFFSET] = rb;
    let (backend, bb) = solana_confidential_compute_sdk::derive_backend_policy_pda(&pid, 1).unwrap();
    let mut backend_data = vec![0; BackendPolicy::SIZE];
    backend_data[..8].copy_from_slice(&BackendPolicy::DISCRIMINATOR);
    backend_data[8] = 1;
    backend_data[9..13].copy_from_slice(&1u32.to_le_bytes());
    backend_data[13..61].copy_from_slice(&measurement);
    *backend_data.last_mut().unwrap() = bb;
    let mut test = sbf::verifier_program_test(pid);
    test.add_program("consumer", consumer_id, processor!(consumer));
    test.add_program("sigverify", SIGVERIFY_PROGRAM_ID, processor!(sigverify));
    test.add_account(registry, account(policy, pid));
    test.add_account(vcek, account(cache, pid));
    test.add_account(backend, account(backend_data, pid));
    let ctx = test.start_with_context().await;
    // The bank's own clock and slot hashes: the enclave commits to a hash the
    // runtime will actually serve, rather than one injected after the fact.
    let clock: Clock = ctx.banks_client.get_sysvar().await.unwrap();
    let slots: SlotHashes = ctx.banks_client.get_sysvar().await.unwrap();
    let (nonce_slot, nonce_hash) = slots.first().unwrap();
    let commitment =
        solana_confidential_compute_sdk::compute_commitment(&nonce_hash.to_bytes(), &action_hash, &consumer_id);
    let mut report = [0; SNP_REPORT_SIZE];
    report[..4].copy_from_slice(&1u32.to_le_bytes());
    report[8..16].copy_from_slice(&(1u64 << 17).to_le_bytes());
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    report[0x50..0x70].copy_from_slice(signer.as_ref());
    report[0x70..0x90].copy_from_slice(&commitment);
    report[0x90..0xc0].copy_from_slice(&measurement);
    report[0x1a0..0x1e0].fill(9);
    let digest: [u8; 48] = Sha384::digest(&report[..solana_confidential_compute_core::SNP_SIGNED_BODY_SIZE]).into();
    let signature: Signature = signing.sign_prehash(&digest).unwrap();
    let bytes = signature.to_bytes();
    // The report stores r and s little-endian; `signature_r_be`/`_s_be` undo it.
    for i in 0..48 {
        report[0x2a0 + i] = bytes[47 - i];
        report[0x2e8 + i] = bytes[95 - i];
    }
    let signature_rs: [u8; 96] = bytes.as_slice().try_into().unwrap();
    let ix = build_verify_atomic_with_nonce_ix_oversized(
        &pid,
        &ctx.payer.pubkey(),
        &consumer_id,
        action_hash,
        measurement,
        &report,
        *nonce_slot,
    )
    .unwrap();
    let nonce = ix.accounts[3].pubkey;
    // The precompile must precede the verifier; the consumer must follow it.
    let tx = Transaction::new_signed_with_payer(
        &[sigverify_ix(&xy, &digest, &signature_rs), ix, consumer_ix],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let used = ctx.banks_client.get_account(nonce).await.unwrap().unwrap();
    assert_eq!(used.owner, pid);
    assert_eq!(used.data.len(), UsedNonceAccount::SIZE);
    assert_eq!(u64::from_le_bytes(used.data[8..16].try_into().unwrap()), clock.slot);
}
