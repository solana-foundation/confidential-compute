use solana_confidential_compute_sdk::PACKET_DATA_SIZE;
use solana_sdk::{message::Message, pubkey::Pubkey, transaction::Transaction};

// Raw Nitro packers are quarantined behind `test-utils` (#209).
#[cfg(feature = "test-utils")]
#[test]
fn real_hardware_nitro_document_exceeds_serialized_packet_and_is_rejected() {
    use solana_confidential_compute_sdk::nitro::build_verify_nitro_attestation_ix_oversized;
    use solana_confidential_compute_sdk::{build_verify_nitro_attestation_ix, SdkError, VERIFY_NITRO_MODE_A};
    let doc = include_bytes!("../../../fixtures/nitro_hardware_document.cose");
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let nonce = Pubkey::new_unique().to_bytes();
    let raw =
        build_verify_nitro_attestation_ix_oversized(&payer, &workload, VERIFY_NITRO_MODE_A, 1, [0; 32], doc, &nonce)
            .unwrap();
    let instruction_len = raw.data.len();
    let tx = Transaction::new_unsigned(Message::new(&[raw], Some(&payer)));
    let size = bincode::serialize(&tx).unwrap().len();
    eprintln!(
        "Nitro document={} instruction={} serialized_transaction={} limit={}",
        doc.len(),
        instruction_len,
        size,
        PACKET_DATA_SIZE
    );
    assert_eq!(doc.len(), 4526);
    assert_eq!(instruction_len, 4579);
    assert!(size > PACKET_DATA_SIZE);
    assert!(matches!(
        build_verify_nitro_attestation_ix(&payer, &workload, VERIFY_NITRO_MODE_A, 1, [0; 32], doc, &nonce),
        Err(SdkError::PacketTooLarge { .. })
    ));
    assert!(
        build_verify_nitro_attestation_ix(&payer, &workload, VERIFY_NITRO_MODE_A, 1, [0; 32], &[1; 64], &nonce).is_ok()
    );
}

#[test]
fn real_nitro_staged_packets_and_mode_b_fail_closed() {
    use solana_confidential_compute_sdk::staged::*;
    let doc = include_bytes!("../../../fixtures/nitro_hardware_document.cose");
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_unique();
    let nonce = Pubkey::new_unique().to_bytes();
    let plan = build_staged_nitro_registration(
        solana_confidential_compute_verifier::id(),
        payer,
        workload,
        100,
        doc,
        nonce,
        100,
        150,
    )
    .unwrap();
    let backend =
        Pubkey::find_program_address(&[b"backend_policy", &[2]], &solana_confidential_compute_verifier::id()).0;
    let active = Pubkey::find_program_address(
        &[b"nonce", &[2], workload.as_ref(), &nonce],
        &solana_confidential_compute_verifier::id(),
    )
    .0;
    let legacy = Pubkey::find_program_address(
        &[b"nonce", workload.as_ref(), &nonce],
        &solana_confidential_compute_verifier::id(),
    )
    .0;
    let amd = Pubkey::find_program_address(
        &[b"nonce", &[1], workload.as_ref(), &nonce],
        &solana_confidential_compute_verifier::id(),
    )
    .0;
    assert_eq!(plan.consume.accounts[5].pubkey, active);
    assert_ne!(active, legacy);
    assert_ne!(active, amd);
    assert_eq!(plan.consume.accounts.len(), 12);
    assert_eq!(plan.consume.accounts[9], solana_sdk::instruction::AccountMeta::new_readonly(workload, true));
    assert_eq!(
        plan.consume.accounts.get(10),
        Some(&solana_sdk::instruction::AccountMeta::new_readonly(backend, false))
    );
    assert_eq!(plan.consume.accounts.last(), Some(&solana_sdk::instruction::AccountMeta::new_readonly(legacy, false)));
    let budgeted = plan.consume_transaction(solana_sdk::hash::Hash::new_unique(), 1_400_000).unwrap();
    assert_eq!(budgeted.signatures.len(), 2);
    assert!(bincode::serialize(&budgeted).unwrap().len() <= PACKET_DATA_SIZE);
    let payload = plan.uploads.iter().flat_map(|ix| ix.data[12..].iter().copied()).collect::<Vec<_>>();
    assert_eq!(&payload[53..], doc);
    assert_eq!(payload.len(), 4579);
    assert!(plan.consume.accounts.iter().any(|m| m.pubkey == workload && m.is_signer));
    for ix in std::iter::once(&plan.begin).chain(plan.uploads.iter()).chain([&plan.seal, &plan.consume, &plan.close]) {
        let tx = Transaction::new_unsigned(Message::new(std::slice::from_ref(ix), Some(&payer)));
        let size = bincode::serialize(&tx).unwrap().len();
        assert!(size <= PACKET_DATA_SIZE);
        eprintln!("staged Nitro packet {}", size);
    }
    let mut source = solana_sdk::instruction::Instruction {
        program_id: solana_confidential_compute_verifier::id(),
        accounts: plan.consume.accounts[2..].to_vec(),
        data: payload,
    };
    source.data[8] = 1;
    assert!(matches!(stage_nitro_registration(source, payer, 100, 150), Err(StageError::UnsupportedInstruction)));
}

#[test]
fn authentic_snp_mode_a_payload_is_preserved_in_bounded_staged_packets() {
    use solana_confidential_compute_sdk::staged::*;
    let report = include_bytes!("../../../fixtures/snp_hardware_report_milan.bin");
    assert_eq!(report.len(), 1184);
    let view = solana_confidential_compute_core::SnpReportView::try_from_slice(report).unwrap();
    let program = solana_confidential_compute_verifier::id();
    let payer = Pubkey::new_unique();
    let workload = Pubkey::new_from_array(view.pubkey());
    assert!(matches!(
        solana_confidential_compute_sdk::build_register_signer_ix_for_program(
            &program, &payer, &workload, report, 0, 100
        ),
        Err(solana_confidential_compute_sdk::SdkError::PacketTooLarge { .. })
    ));
    let plan = build_staged_snp_registration(program, payer, workload, 100, report, 100, 150).unwrap();
    let payload: Vec<u8> = plan.uploads.iter().flat_map(|ix| ix.data[12..].iter().copied()).collect();
    assert_eq!(payload.len(), 1202);
    assert_eq!(&payload[16..1200], report);
    assert_eq!(plan.consume.accounts[10], solana_sdk::instruction::AccountMeta::new_readonly(workload, true));
    for ix in std::iter::once(&plan.begin).chain(&plan.uploads).chain([&plan.seal, &plan.consume, &plan.close]) {
        let tx = Transaction::new_unsigned(Message::new(std::slice::from_ref(ix), Some(&payer)));
        assert!(bincode::serialized_size(&tx).unwrap() <= 1232);
        assert_eq!(tx.message.header.num_required_signatures, if ix.data == CONSUME { 2 } else { 1 });
    }
    assert!(
        bincode::serialized_size(&plan.consume_transaction(solana_sdk::hash::Hash::default(), 1_400_000).unwrap())
            .unwrap()
            <= 1232
    );
    assert!(build_staged_snp_registration(program, payer, workload, 100, &report[..1183], 100, 150).is_err());
    assert!(build_staged_snp_registration(program, payer, workload, 100, report, 100, 251).is_err());
}
