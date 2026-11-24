//! Regressions for PR #325's unauthenticated NVIDIA authority creation.
//! These are attacker inputs, not NVIDIA hardware evidence.
//! Proof-backed packets are covered below.
//! @spec SCC-NVIDIA-001 SCC-NVIDIA-002 SCC-NVIDIA-003 SCC-NVIDIA-004 SCC-NVIDIA-005

use borsh::BorshDeserialize;
use solana_confidential_compute_core::{
    types::{AttestedSigner, EnclaveType, MeasurementDigest},
    MockVerifier,
};
use solana_confidential_compute_verifier::{
    error::VerifierError,
    payload::{
        nvidia_attestation_statement, nvidia_nonce_seed, nvidia_public_inputs_canonical,
        nvidia_public_inputs_from_statement, NvidiaStatement, NVIDIA_ATTESTATION_SOURCE,
        VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR, VERIFY_NVIDIA_LEGACY_LEN, VERIFY_NVIDIA_MODE_A,
        VERIFY_NVIDIA_MODE_B, VERIFY_NVIDIA_PROOF_PACKET_LEN,
    },
    processor::{DirectCryptoVerifier, Processor},
    state::{
        AttestedSignerAccount, BackendPolicy, PolicyRegistry, UsedNonceAccount,
        ATTESTED_SIGNER_DISCRIMINATOR, POLICY_REGISTRY_DISCRIMINATOR,
    },
    Groth16SyscallVerifier, Groth16VerifyingKey,
};
use solana_program::{
    account_info::AccountInfo,
    instruction::Instruction,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::{clock, instructions, slot_hashes},
};
use solana_sdk::signature::{Keypair, Signer};

const COPIED_MEASUREMENT: [u8; 32] = [0xab; 32];
const SLOT: u64 = 100;
const SLOT_HASH: [u8; 32] = [0x77; 32];

fn account(
    key: Pubkey,
    owner: Pubkey,
    signer: bool,
    writable: bool,
    data: Vec<u8>,
) -> AccountInfo<'static> {
    AccountInfo::new(
        Box::leak(Box::new(key)),
        signer,
        writable,
        Box::leak(Box::new(10_000_000)),
        Box::leak(data.into_boxed_slice()),
        Box::leak(Box::new(owner)),
        false,
    )
}

fn packet(mode: u8, action_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR.to_vec();
    data.push(mode);
    data.extend_from_slice(&SLOT.to_le_bytes());
    data.extend_from_slice(action_hash);
    data.extend_from_slice(&COPIED_MEASUREMENT);
    data
}

fn attack(mode: u8, existing_expiry: Option<u64>) {
    let pid = Pubkey::new_unique();
    // The attacker owns this fresh key. No GPU or attester key is involved.
    let signer = Keypair::new().pubkey();
    let consumer = Pubkey::new_unique();
    let action_hash = [0x44; 32];
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: Pubkey::new_unique().to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump: registry_bump,
    };
    let (policy_pda, policy_bump) =
        Pubkey::find_program_address(&[BackendPolicy::SEED, &[4]], &pid);
    let mut measurements = [[0; 48]; 8];
    measurements[0][..32].copy_from_slice(&COPIED_MEASUREMENT);
    let policy = BackendPolicy {
        discriminator: BackendPolicy::DISCRIMINATOR,
        source: 4,
        measurement_count: 1,
        measurements,
        bump: policy_bump,
    };
    let (signer_pda, signer_bump) =
        Pubkey::find_program_address(&[b"attested_signer_v2", signer.as_ref()], &pid);
    let seed = if mode == VERIFY_NVIDIA_MODE_A {
        solana_program::hash::hashv(&[signer.as_ref(), &COPIED_MEASUREMENT, &SLOT_HASH]).to_bytes()
    } else {
        let commitment = solana_confidential_compute_core::compute_action_commitment(
            &SLOT_HASH,
            &action_hash,
            &consumer.to_bytes(),
        );
        solana_program::hash::hashv(&[&commitment, &COPIED_MEASUREMENT, &SLOT_HASH]).to_bytes()
    };
    let (nonce_pda, _) = Pubkey::find_program_address(&[b"nonce", &[4], &seed], &pid);
    let mut clock_data = vec![0; 40];
    clock_data[..8].copy_from_slice(&(SLOT + 5).to_le_bytes());
    clock_data[32..].copy_from_slice(&1_700_000_000i64.to_le_bytes());
    let mut hashes = 1u64.to_le_bytes().to_vec();
    hashes.extend_from_slice(&SLOT.to_le_bytes());
    hashes.extend_from_slice(&SLOT_HASH);
    let signer_data = if let Some(expires_slot) = existing_expiry {
        borsh::to_vec(&AttestedSignerAccount {
            discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
            record: solana_confidential_compute_core::types::AttestedSigner {
                signer_pubkey: signer.to_bytes(),
                enclave_type: EnclaveType::NvidiaGpu,
                measurement: solana_confidential_compute_core::types::MeasurementDigest::new(
                    measurements[0],
                ),
                chip_id_hash: COPIED_MEASUREMENT,
                tcb_version: 0,
                registered_slot: SLOT,
                expires_slot,
            },
            bump: signer_bump,
            expires_unix_timestamp: 1_800_000_000,
        })
        .unwrap()
    } else {
        vec![0; AttestedSignerAccount::SIZE]
    };
    let data = packet(mode, &action_hash);
    let ixs = [
        Instruction::new_with_bytes(pid, &data, vec![]),
        Instruction::new_with_bytes(consumer, &[1, 2, 3], vec![]),
    ];
    let borrowed: Vec<_> = ixs
        .iter()
        .map(|ix| instructions::BorrowedInstruction {
            program_id: &ix.program_id,
            accounts: vec![],
            data: &ix.data,
        })
        .collect();
    // The constructor initializes the current top-level instruction index to zero.
    let instructions_data = instructions::construct_instructions_data(&borrowed).unwrap();
    let accounts = vec![
        account(signer_pda, pid, false, true, signer_data),
        account(
            registry_pda,
            pid,
            false,
            false,
            borsh::to_vec(&registry).unwrap(),
        ),
        account(nonce_pda, pid, false, true, vec![0; UsedNonceAccount::SIZE]),
        account(
            Pubkey::new_unique(),
            solana_sdk_ids::system_program::ID,
            true,
            true,
            vec![],
        ),
        account(
            solana_sdk_ids::system_program::ID,
            solana_sdk_ids::system_program::ID,
            false,
            false,
            vec![],
        ),
        account(
            clock::ID,
            solana_program::sysvar::ID,
            false,
            false,
            clock_data,
        ),
        account(
            slot_hashes::ID,
            solana_program::sysvar::ID,
            false,
            false,
            hashes,
        ),
        account(
            signer,
            solana_sdk_ids::system_program::ID,
            true,
            false,
            vec![],
        ),
        account(
            policy_pda,
            pid,
            false,
            false,
            borsh::to_vec(&policy).unwrap(),
        ),
        account(
            instructions::ID,
            solana_program::sysvar::ID,
            false,
            false,
            instructions_data,
        ),
    ];
    let before: Vec<_> = accounts
        .iter()
        .map(|a| (a.lamports(), a.data.borrow().to_vec()))
        .collect();
    // Exercise the normal entrypoint and explicit signature-verifier dispatch.
    // A permissive crypto mock must not turn this evidence-free packet into authority.
    for result in [
        Processor::process(&pid, &accounts, &data),
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
    ] {
        assert_eq!(
            result,
            Err(VerifierError::NvidiaAttestationUnavailable.into())
        );
    }
    let after: Vec<_> = accounts
        .iter()
        .map(|a| (a.lamports(), a.data.borrow().to_vec()))
        .collect();
    assert_eq!(
        after, before,
        "no record creation, renewal or nonce consumption"
    );
}

#[test]
fn mode_a_copied_allowlisted_measurement_with_fresh_key_fails() {
    attack(VERIFY_NVIDIA_MODE_A, None);
}

#[test]
fn mode_b_copied_allowlisted_measurement_with_fresh_key_fails() {
    attack(VERIFY_NVIDIA_MODE_B, None);
}

#[test]
fn unauthenticated_renewal_and_revoked_record_stay_unchanged() {
    for expiry in [0, SLOT - 1, SLOT + 1000] {
        attack(VERIFY_NVIDIA_MODE_A, Some(expiry));
    }
}

#[test]
fn malformed_nvidia_packet_is_rejected() {
    let pid = Pubkey::new_unique();
    for mode in [VERIFY_NVIDIA_MODE_A, VERIFY_NVIDIA_MODE_B] {
        let valid = packet(mode, &[0; 32]);
        for len in 8..valid.len() {
            assert_eq!(
                Processor::process(&pid, &[], &valid[..len]),
                Err(VerifierError::InvalidInstruction.into())
            );
        }
        let mut long = valid;
        long.push(0xff);
        assert_eq!(
            Processor::process(&pid, &[], &long),
            Err(VerifierError::InvalidInstruction.into())
        );
    }
    assert_eq!(
        Processor::process(&pid, &[], &packet(2, &[0; 32])),
        Err(VerifierError::InvalidInstruction.into())
    );
}

const ACTION: [u8; 32] = [0x44; 32];
const TTL_SLOTS: u64 = 216_000;
const TTL_SECONDS: i64 = 86_400;
const UNIX_NOW: i64 = 1_700_000_000;

#[derive(Clone, Copy)]
enum SignerState {
    Fresh,
    Revoked,
    Expired,
    ActiveNvidia,
    ActiveAmd,
}

#[derive(Clone, Copy)]
enum InputMode {
    Canonical,
    Zeros,
}

struct ProofOpts {
    mode: u8,
    slot_age: u64,
    slot_hash_present: bool,
    on_policy: bool,
    inputs: InputMode,
    signer_state: SignerState,
    next_instruction: bool,
    consumer_mismatch: bool,
    workload_signs: bool,
    payer_signs: bool,
    wrong_nonce: bool,
    wrong_system_program: bool,
    mode_b_signer_writable: bool,
}

impl Default for ProofOpts {
    fn default() -> Self {
        Self {
            mode: VERIFY_NVIDIA_MODE_A,
            slot_age: 5,
            slot_hash_present: true,
            on_policy: true,
            inputs: InputMode::Canonical,
            signer_state: SignerState::Fresh,
            next_instruction: true,
            consumer_mismatch: false,
            workload_signs: true,
            payer_signs: true,
            wrong_nonce: false,
            wrong_system_program: false,
            mode_b_signer_writable: false,
        }
    }
}

struct ProofMeta {
    measurement: [u8; 32],
    signer: Pubkey,
    payer: Pubkey,
    clock_slot: u64,
}

fn well_formed_points() -> ([u8; 64], [u8; 128], [u8; 64]) {
    let mut proof_a = [0u8; 64];
    proof_a[31] = 1;
    proof_a[63] = 2;
    let mut proof_b = [0u8; 128];
    proof_b[31] = 1;
    proof_b[63] = 2;
    proof_b[95] = 3;
    proof_b[127] = 4;
    (proof_a, proof_b, proof_a)
}

fn pack_proof(
    mode: u8,
    action: &[u8; 32],
    measurement: &[u8; 32],
    inputs: &[[u8; 16]; 2],
    points: ([u8; 64], [u8; 128], [u8; 64]),
) -> Vec<u8> {
    let mut data = VERIFY_NVIDIA_ATTESTATION_DISCRIMINATOR.to_vec();
    data.push(mode);
    data.extend_from_slice(&SLOT.to_le_bytes());
    data.extend_from_slice(action);
    data.extend_from_slice(measurement);
    data.extend_from_slice(&inputs[0]);
    data.extend_from_slice(&inputs[1]);
    data.extend_from_slice(&points.0);
    data.extend_from_slice(&points.1);
    data.extend_from_slice(&points.2);
    data
}

fn select_measurement(
    program_id: &Pubkey,
    mode: u8,
    action: &[u8; 32],
    subject: &[u8; 32],
) -> ([u8; 32], [[u8; 16]; 2]) {
    for n in 0..2048u16 {
        let mut measurement = [0x5a; 32];
        measurement[30..].copy_from_slice(&n.to_le_bytes());
        let statement = nvidia_attestation_statement(&NvidiaStatement {
            program_id: program_id.as_ref(),
            mode,
            nonce_slot: SLOT,
            expected_action_hash: action,
            measurement: &measurement,
            slot_hash: &SLOT_HASH,
            subject,
        });
        let inputs = nvidia_public_inputs_from_statement(&statement);
        if nvidia_public_inputs_canonical(&inputs) {
            return (measurement, inputs);
        }
    }
    panic!("expected an in-field NVIDIA statement");
}

fn padded_measurement(measurement: &[u8; 32]) -> [u8; 48] {
    let mut digest = [0u8; 48];
    digest[..32].copy_from_slice(measurement);
    digest
}

fn snapshot(accounts: &[AccountInfo]) -> Vec<(u64, Vec<u8>)> {
    accounts
        .iter()
        .map(|account| (account.lamports(), account.data.borrow().to_vec()))
        .collect()
}

fn build_proof(opts: &ProofOpts) -> (Pubkey, Vec<u8>, Vec<AccountInfo<'static>>, ProofMeta) {
    let pid = Pubkey::new_unique();
    let signer = Keypair::new().pubkey();
    let payer = Pubkey::new_unique();
    let consumer = Pubkey::new_unique();
    let other_consumer = Pubkey::new_unique();
    let subject = if opts.mode == VERIFY_NVIDIA_MODE_A {
        signer.to_bytes()
    } else {
        solana_confidential_compute_core::compute_action_commitment(
            &SLOT_HASH,
            &ACTION,
            &consumer.to_bytes(),
        )
    };
    let (measurement, canonical_inputs) = select_measurement(&pid, opts.mode, &ACTION, &subject);
    let inputs = match opts.inputs {
        InputMode::Canonical => canonical_inputs,
        InputMode::Zeros => [[0u8; 16]; 2],
    };
    let data = pack_proof(
        opts.mode,
        &ACTION,
        &measurement,
        &inputs,
        well_formed_points(),
    );
    let clock_slot = SLOT + opts.slot_age;
    let (registry_pda, registry_bump) = Pubkey::find_program_address(&[b"policy_registry"], &pid);
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: Pubkey::new_unique().to_bytes(),
        ark_pubkey_xy: [0; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump: registry_bump,
    };
    let (policy_pda, policy_bump) =
        Pubkey::find_program_address(&[BackendPolicy::SEED, &[NVIDIA_ATTESTATION_SOURCE]], &pid);
    let mut measurements = [[0u8; 48]; 8];
    if opts.on_policy {
        measurements[0] = padded_measurement(&measurement);
    } else {
        measurements[0] = padded_measurement(&[0xcd; 32]);
    }
    let policy = BackendPolicy {
        discriminator: BackendPolicy::DISCRIMINATOR,
        source: NVIDIA_ATTESTATION_SOURCE,
        measurement_count: 1,
        measurements,
        bump: policy_bump,
    };
    let nonce_subject = if opts.wrong_nonce {
        [0x9a; 32]
    } else {
        subject
    };
    let seed = nvidia_nonce_seed(&nonce_subject, &measurement, &SLOT_HASH);
    let (nonce_pda, _nonce_bump) =
        Pubkey::find_program_address(&[b"nonce", &[NVIDIA_ATTESTATION_SOURCE], &seed], &pid);
    let (signer_pda, signer_bump) =
        Pubkey::find_program_address(&[b"attested_signer_v2", signer.as_ref()], &pid);
    let signer_data = match opts.signer_state {
        SignerState::Fresh => vec![0; AttestedSignerAccount::SIZE],
        SignerState::Revoked => signer_record(
            &signer,
            signer_bump,
            &measurement,
            0,
            EnclaveType::NvidiaGpu,
        ),
        SignerState::Expired => signer_record(
            &signer,
            signer_bump,
            &measurement,
            SLOT,
            EnclaveType::NvidiaGpu,
        ),
        SignerState::ActiveNvidia => signer_record(
            &signer,
            signer_bump,
            &measurement,
            clock_slot + 1_000,
            EnclaveType::NvidiaGpu,
        ),
        SignerState::ActiveAmd => signer_record(
            &signer,
            signer_bump,
            &measurement,
            clock_slot + 1_000,
            EnclaveType::AmdSevSnp,
        ),
    };
    let nonce_data = vec![0; UsedNonceAccount::SIZE];
    let mut clock_data = vec![0; 40];
    clock_data[..8].copy_from_slice(&clock_slot.to_le_bytes());
    clock_data[32..].copy_from_slice(&UNIX_NOW.to_le_bytes());
    let hashes = if opts.slot_hash_present {
        let mut hashes = 1u64.to_le_bytes().to_vec();
        hashes.extend_from_slice(&SLOT.to_le_bytes());
        hashes.extend_from_slice(&SLOT_HASH);
        hashes
    } else {
        0u64.to_le_bytes().to_vec()
    };
    let sysvar_consumer = if opts.consumer_mismatch {
        other_consumer
    } else {
        consumer
    };
    let ix_list = if opts.next_instruction {
        vec![
            Instruction::new_with_bytes(pid, &data, vec![]),
            Instruction::new_with_bytes(sysvar_consumer, &[1, 2, 3], vec![]),
        ]
    } else {
        vec![Instruction::new_with_bytes(pid, &data, vec![])]
    };
    let borrowed: Vec<_> = ix_list
        .iter()
        .map(|ix| instructions::BorrowedInstruction {
            program_id: &ix.program_id,
            accounts: vec![],
            data: &ix.data,
        })
        .collect();
    let instructions_data = instructions::construct_instructions_data(&borrowed).unwrap();
    let system_key = if opts.wrong_system_program {
        Pubkey::new_unique()
    } else {
        solana_sdk_ids::system_program::ID
    };
    let signer_account_key = if opts.mode == VERIFY_NVIDIA_MODE_A {
        signer_pda
    } else {
        Pubkey::new_from_array([0xff; 32])
    };
    let signer_writable = opts.mode == VERIFY_NVIDIA_MODE_A || opts.mode_b_signer_writable;
    let mode_account = if opts.mode == VERIFY_NVIDIA_MODE_A {
        account(signer, system_key, opts.workload_signs, false, vec![])
    } else {
        account(
            instructions::ID,
            solana_program::sysvar::ID,
            false,
            false,
            instructions_data,
        )
    };
    let accounts = vec![
        account(
            signer_account_key,
            pid,
            false,
            signer_writable,
            if opts.mode == VERIFY_NVIDIA_MODE_A {
                signer_data
            } else {
                vec![0x11; 8]
            },
        ),
        account(
            registry_pda,
            pid,
            false,
            false,
            borsh::to_vec(&registry).unwrap(),
        ),
        account(nonce_pda, pid, false, true, nonce_data),
        account(payer, system_key, opts.payer_signs, true, vec![]),
        account(system_key, system_key, false, false, vec![]),
        account(
            clock::ID,
            solana_program::sysvar::ID,
            false,
            false,
            clock_data,
        ),
        account(
            slot_hashes::ID,
            solana_program::sysvar::ID,
            false,
            false,
            hashes,
        ),
        mode_account,
        account(
            policy_pda,
            pid,
            false,
            false,
            borsh::to_vec(&policy).unwrap(),
        ),
    ];
    (
        pid,
        data,
        accounts,
        ProofMeta {
            measurement,
            signer,
            payer,
            clock_slot,
        },
    )
}

fn signer_record(
    signer: &Pubkey,
    bump: u8,
    measurement: &[u8; 32],
    expires_slot: u64,
    enclave_type: EnclaveType,
) -> Vec<u8> {
    borsh::to_vec(&AttestedSignerAccount {
        discriminator: ATTESTED_SIGNER_DISCRIMINATOR,
        record: AttestedSigner {
            signer_pubkey: signer.to_bytes(),
            enclave_type,
            measurement: MeasurementDigest::new(padded_measurement(measurement)),
            chip_id_hash: *measurement,
            tcb_version: 0,
            registered_slot: SLOT,
            expires_slot,
        },
        bump,
        expires_unix_timestamp: 1_800_000_000,
    })
    .unwrap()
}

fn assert_unchanged(before: &[(u64, Vec<u8>)], accounts: &[AccountInfo]) {
    assert_eq!(snapshot(accounts), *before);
}

fn zero_vk() -> Groth16VerifyingKey {
    Groth16VerifyingKey {
        alpha_g1: [0; 64],
        beta_g2: [0; 128],
        gamma_g2: [0; 128],
        delta_g2: [0; 128],
        ic: [[0; 64], [0; 64]],
    }
}

#[test]
fn proof_packet_lengths_match_the_layer_1_layout() {
    assert_eq!(VERIFY_NVIDIA_LEGACY_LEN, 73);
    assert_eq!(
        VERIFY_NVIDIA_PROOF_PACKET_LEN,
        1 + 8 + 32 + 32 + 32 + 64 + 128 + 64
    );
    assert_eq!(VERIFY_NVIDIA_PROOF_PACKET_LEN, 361);
}

#[test]
fn malformed_proof_packet_does_not_reach_accounts() {
    let pid = Pubkey::new_unique();
    let points = well_formed_points();
    let measurement = [0x5a; 32];
    let canonical = [[0u8; 16]; 2];
    let mut high = canonical;
    high[0] = [0xff; 16];
    high[1] = [0xff; 16];
    for (inputs, points, expected) in [
        (high, points, Err(VerifierError::InvalidProof.into())),
        (
            canonical,
            ([0u8; 64], [0u8; 128], [0u8; 64]),
            Err(VerifierError::InvalidProof.into()),
        ),
    ] {
        let data = pack_proof(VERIFY_NVIDIA_MODE_A, &ACTION, &measurement, &inputs, points);
        assert_eq!(Processor::process(&pid, &[], &data), expected);
    }
    let mut high_coord = points;
    high_coord.0[..32].copy_from_slice(&[0xff; 32]);
    let data = pack_proof(
        VERIFY_NVIDIA_MODE_A,
        &ACTION,
        &measurement,
        &canonical,
        high_coord,
    );
    assert_eq!(
        Processor::process(&pid, &[], &data),
        Err(VerifierError::InvalidProof.into())
    );
    let data = pack_proof(2, &ACTION, &measurement, &canonical, well_formed_points());
    assert_eq!(data.len(), 8 + VERIFY_NVIDIA_PROOF_PACKET_LEN);
    assert_eq!(
        Processor::process(&pid, &[], &data),
        Err(VerifierError::InvalidInstruction.into())
    );
    let valid = pack_proof(
        VERIFY_NVIDIA_MODE_A,
        &ACTION,
        &measurement,
        &canonical,
        well_formed_points(),
    );
    assert_eq!(
        Processor::process(&pid, &[], &valid[..valid.len() - 1]),
        Err(VerifierError::InvalidInstruction.into())
    );
    let mut long = valid;
    long.push(0);
    assert_eq!(
        Processor::process(&pid, &[], &long),
        Err(VerifierError::InvalidInstruction.into())
    );
}

#[test]
fn mode_a_proof_mints_nvidia_signer_when_backend_accepts() {
    let (pid, data, accounts, meta) = build_proof(&ProofOpts::default());
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Ok(())
    );
    let signer = AttestedSignerAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    assert_eq!(signer.record.enclave_type, EnclaveType::NvidiaGpu);
    assert_eq!(signer.record.signer_pubkey, meta.signer.to_bytes());
    assert_eq!(
        signer.record.measurement.0,
        padded_measurement(&meta.measurement)
    );
    assert_eq!(signer.record.chip_id_hash, meta.measurement);
    assert_eq!(signer.record.registered_slot, meta.clock_slot);
    assert_eq!(signer.record.expires_slot, meta.clock_slot + TTL_SLOTS);
    assert_eq!(signer.expires_unix_timestamp, UNIX_NOW + TTL_SECONDS);
    let nonce = UsedNonceAccount::try_from_slice(&accounts[2].data.borrow()).unwrap();
    assert_eq!(nonce.slot, meta.clock_slot);
    assert_eq!(nonce.refund_pubkey, meta.payer.to_bytes());
    assert_eq!(accounts[3].lamports(), 10_000_000);
}

#[test]
fn mode_a_renews_expired_and_active_matching_signers() {
    for signer_state in [SignerState::Expired, SignerState::ActiveNvidia] {
        let opts = ProofOpts {
            signer_state,
            ..ProofOpts::default()
        };
        let (pid, data, accounts, meta) = build_proof(&opts);
        assert_eq!(
            Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
            Ok(())
        );
        let signer = AttestedSignerAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
        assert_eq!(signer.record.enclave_type, EnclaveType::NvidiaGpu);
        assert_eq!(signer.record.expires_slot, meta.clock_slot + TTL_SLOTS);
        assert_ne!(signer.record.expires_slot, 0);
    }
}

#[test]
fn mode_a_preserves_revoked_and_other_enclave_records() {
    for (signer_state, expected) in [
        (
            SignerState::Revoked,
            Err(VerifierError::UnauthorizedPolicy.into()),
        ),
        (
            SignerState::ActiveAmd,
            Err(ProgramError::AccountAlreadyInitialized),
        ),
    ] {
        let opts = ProofOpts {
            signer_state,
            ..ProofOpts::default()
        };
        let (pid, data, accounts, _) = build_proof(&opts);
        let before = snapshot(&accounts);
        assert_eq!(
            Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
            expected
        );
        assert_unchanged(&before, &accounts);
    }
}

#[test]
fn mode_a_enforces_slot_freshness_policy_and_replay() {
    let stale = ProofOpts {
        slot_age: 151,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&stale);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::StaleNonce.into())
    );
    assert_unchanged(&before, &accounts);

    let missing = ProofOpts {
        slot_hash_present: false,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&missing);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::StaleNonce.into())
    );
    assert_unchanged(&before, &accounts);

    let age_ok = ProofOpts {
        slot_age: 150,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, meta) = build_proof(&age_ok);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Ok(())
    );
    let signer = AttestedSignerAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
    assert_eq!(signer.record.registered_slot, meta.clock_slot);

    let off_policy = ProofOpts {
        on_policy: false,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&off_policy);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::DisallowedMeasurement.into())
    );
    assert_unchanged(&before, &accounts);

    let (pid, data, accounts, _) = build_proof(&ProofOpts::default());
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Ok(())
    );
    let after_first = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::NonceAlreadyUsed.into())
    );
    assert_eq!(snapshot(&accounts), after_first);
}

#[test]
fn mode_a_backend_rejection_leaves_accounts_unchanged() {
    let (pid, data, accounts, _) = build_proof(&ProofOpts::default());
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::failing(), &pid, &accounts, &data),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        Processor::process_with(&DirectCryptoVerifier, &pid, &accounts, &data),
        Err(VerifierError::InvalidSignature.into())
    );
    assert_eq!(
        Processor::process(&pid, &accounts, &data),
        Err(VerifierError::InvalidSignature.into())
    );
    let groth16 = Groth16SyscallVerifier::new([0u8; 128], [1u8; 32], zero_vk());
    assert_eq!(
        Processor::process_with(&groth16, &pid, &accounts, &data),
        Err(VerifierError::InvalidProof.into())
    );
    assert_unchanged(&before, &accounts);
}

#[test]
fn mode_a_rejects_bad_accounts_and_unbound_inputs() {
    let zeros = ProofOpts {
        inputs: InputMode::Zeros,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&zeros);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::InvalidProof.into())
    );
    assert_unchanged(&before, &accounts);

    let unsigned = ProofOpts {
        workload_signs: false,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&unsigned);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(ProgramError::MissingRequiredSignature)
    );
    assert_unchanged(&before, &accounts);

    let payer = ProofOpts {
        payer_signs: false,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&payer);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(ProgramError::MissingRequiredSignature)
    );
    assert_unchanged(&before, &accounts);

    let system = ProofOpts {
        wrong_system_program: true,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&system);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(ProgramError::IncorrectProgramId)
    );
    assert_unchanged(&before, &accounts);

    let nonce = ProofOpts {
        wrong_nonce: true,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&nonce);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::InvalidAccountAddress.into())
    );
    assert_unchanged(&before, &accounts);
}

#[test]
fn mode_b_binds_the_next_instruction_and_does_not_write_the_signer() {
    let opts = ProofOpts {
        mode: VERIFY_NVIDIA_MODE_B,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&opts);
    let signer_before = accounts[0].data.borrow().to_vec();
    assert!(!accounts[0].is_writable);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Ok(())
    );
    assert_eq!(accounts[0].data.borrow().as_ref(), signer_before.as_slice());
    let nonce = UsedNonceAccount::try_from_slice(&accounts[2].data.borrow()).unwrap();
    assert!(nonce.slot > 0);

    let missing = ProofOpts {
        mode: VERIFY_NVIDIA_MODE_B,
        next_instruction: false,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&missing);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(ProgramError::InvalidArgument)
    );
    assert_unchanged(&before, &accounts);

    let mismatch = ProofOpts {
        mode: VERIFY_NVIDIA_MODE_B,
        consumer_mismatch: true,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&mismatch);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::InvalidProof.into())
    );
    assert_unchanged(&before, &accounts);

    let writable = ProofOpts {
        mode: VERIFY_NVIDIA_MODE_B,
        mode_b_signer_writable: true,
        ..ProofOpts::default()
    };
    let (pid, data, accounts, _) = build_proof(&writable);
    let before = snapshot(&accounts);
    assert_eq!(
        Processor::process_with(&MockVerifier::succeeding(), &pid, &accounts, &data),
        Err(VerifierError::InvalidAccountAddress.into())
    );
    assert_unchanged(&before, &accounts);
}
