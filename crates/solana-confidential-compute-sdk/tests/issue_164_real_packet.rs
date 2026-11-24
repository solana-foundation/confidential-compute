use solana_confidential_compute_sdk::PACKET_DATA_SIZE;
use solana_confidential_compute_verifier::payload::{REGISTER_VCEK_DISCRIMINATOR, REGISTER_VCEK_HEADER_SIZE};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    transaction::Transaction,
};

#[test]
fn real_milan_chain_cannot_fit_inline_registration() {
    let ask = include_bytes!("../../solana-confidential-compute-crypto/tests/data/milan_ask.der");
    let leaf = include_bytes!("../../../fixtures/vcek_milan.der");
    let mut data = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    data.extend([0; 64 + 8 + 96]);
    data.extend((ask.len() as u16).to_le_bytes());
    data.extend((leaf.len() as u16).to_le_bytes());
    data.extend(ask);
    data.extend(leaf);
    let instruction_len = data.len();
    assert_eq!(instruction_len, 8 + REGISTER_VCEK_HEADER_SIZE + ask.len() + leaf.len());
    // Even a minimal account set is too large; real registration adds accounts.
    let payer = Pubkey::new_unique();
    let ix = Instruction { program_id: Pubkey::new_unique(), accounts: vec![AccountMeta::new(payer, true)], data };
    let tx = Transaction::new_unsigned(Message::new(&[ix], Some(&payer)));
    let size = bincode::serialize(&tx).unwrap().len();
    eprintln!(
        "Milan ASK={} VCEK={} instruction={} minimal_serialized_tx={} limit={}",
        ask.len(),
        leaf.len(),
        instruction_len,
        size,
        PACKET_DATA_SIZE
    );
    assert_eq!(instruction_len, 3208);
    assert!(instruction_len > PACKET_DATA_SIZE);
    assert!(size > PACKET_DATA_SIZE);
    let control = Transaction::new_unsigned(Message::new(
        &[Instruction { program_id: Pubkey::new_unique(), accounts: vec![], data: vec![0; 16] }],
        Some(&payer),
    ));
    assert!(bincode::serialize(&control).unwrap().len() < PACKET_DATA_SIZE);
}

#[test]
fn authentic_milan_stages_into_bounded_signed_packets() {
    use solana_confidential_compute_sdk::staged::*;
    let payer = Pubkey::new_unique();
    let ask = include_bytes!("../../solana-confidential-compute-crypto/tests/data/milan_ask.der");
    let leaf = include_bytes!("../../../fixtures/vcek_milan.der");
    let mut data = REGISTER_VCEK_DISCRIMINATOR.to_vec();
    data.extend([0; REGISTER_VCEK_HEADER_SIZE - 4]);
    data.extend((ask.len() as u16).to_le_bytes());
    data.extend((leaf.len() as u16).to_le_bytes());
    data.extend(ask);
    data.extend(leaf);
    let ix = Instruction {
        program_id: solana_confidential_compute_verifier::id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(
                Pubkey::find_program_address(
                    &[b"vcek_v2", &solana_sdk::hash::hash(&[0; 64]).to_bytes(), &0u64.to_le_bytes()],
                    &solana_confidential_compute_verifier::id(),
                )
                .0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        ],
        data: data.clone(),
    };
    let plan = stage_vcek_registration(ix.clone(), payer, 100, 150).unwrap();
    let recovered = plan.uploads.iter().flat_map(|i| i.data[12..].iter().copied()).collect::<Vec<_>>();
    assert_eq!(recovered, data);
    for i in std::iter::once(&plan.begin).chain(plan.uploads.iter()).chain([&plan.seal, &plan.consume, &plan.close]) {
        let tx = Transaction::new_unsigned(Message::new(std::slice::from_ref(i), Some(&payer)));
        let bytes = bincode::serialize(&tx).unwrap();
        assert!(bytes.len() <= PACKET_DATA_SIZE);
        assert_eq!(tx.signatures.len(), 1);
        eprintln!("staged packet {}", bytes.len());
    }
    let budgeted = plan.consume_transaction(solana_sdk::hash::Hash::new_unique(), 1_400_000).unwrap();
    assert!(bincode::serialize(&budgeted).unwrap().len() <= PACKET_DATA_SIZE);
    assert!(matches!(
        plan.consume_transaction(solana_sdk::hash::Hash::new_unique(), 0),
        Err(StageError::InvalidComputeBudget)
    ));
    assert_eq!(plan.consume.data, CONSUME);
    assert_eq!(plan.consume.accounts[2..2 + ix.accounts.len()], ix.accounts);
    assert_eq!(
        plan.consume.accounts.last(),
        Some(&AccountMeta::new_readonly(
            solana_confidential_compute_sdk::derive_amd_revocation_pda(
                &ix.program_id,
                &solana_sdk::hash::hash(&[0; 64]).to_bytes()
            )
            .0,
            false
        ))
    );
    assert!(matches!(stage_vcek_registration(ix.clone(), payer, 100, 251), Err(StageError::InvalidDeadline)));
    let mut huge = ix.clone();
    huge.data.resize(MAX_PAYLOAD + 1, 0);
    assert!(matches!(stage_vcek_registration(huge, payer, 100, 150), Err(StageError::InvalidSize)));
    let mut foreign = ix;
    foreign.accounts[0].is_signer = false;
    assert!(matches!(stage_vcek_registration(foreign, payer, 100, 150), Err(StageError::InvalidAuthority)));
}
