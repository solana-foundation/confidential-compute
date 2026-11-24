//! Packet-bounded transport of exact verifier instruction bytes.
//!
//! This only transports evidence. Consume still performs on-chain cryptographic
//! verification. Uploads must finish before the nonce/certificate/slot deadlines.
//!
//! Submit `begin`, every `uploads` instruction in order, `seal`, and `consume`
//! as separate transactions; `close` cancels or refunds the upload afterward.
//! The SDK measures each transaction with all required signature slots. Adding
//! instructions or signers requires checking the final signed packet again.
//! Payloads are limited to 9,000 bytes, chunks to 700 bytes and upload lifetime
//! to 150 slots. Expiry never extends certificate or attestation freshness.
//! This module transports AMD endorsement chains and Nitro Mode A documents.
//! SNP Mode A reports are also supported; staged atomic Mode B is rejected.
//! Any future staged Mode B adapter must bind V3 final compiled-message effective
//! privileges, validate that final message before signing, and invoke the real
//! nonce-protected handler. Mode A staging grants no atomic action authority. Native
//! Nitro verification does not prove SBF compute or hardware feasibility.
//! Use the published crypto and artifact fixes together before deployment.
//! Authentic Milan consume exceeded the default 200,000 CU in the SBPFv0
//! regression. Request an explicit measured budget with `consume_transaction`;
//! packet success alone never guarantees a sufficient compute budget.
use solana_sdk::{
    hash::hash,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    transaction::Transaction,
};

pub const BEGIN: [u8; 8] = *b"stagebeg";
pub const UPLOAD: [u8; 8] = *b"stageput";
pub const SEAL: [u8; 8] = *b"stagesea";
pub const CONSUME: [u8; 8] = *b"stageuse";
pub const CLOSE: [u8; 8] = *b"stagedel";
pub const MAX_PAYLOAD: usize = 9000;
pub const MAX_CHUNK: usize = 700;
pub const MAX_LIFETIME_SLOTS: u64 = 150;
const REGISTER_VCEK: [u8; 8] = [228, 65, 209, 71, 242, 135, 131, 17];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    UnsupportedInstruction,
    InvalidSize,
    InvalidDeadline,
    InvalidAuthority,
    PacketTooLarge,
    InvalidComputeBudget,
}
impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StageError {}

/// Execute begin, uploads in order, seal, then consume, each in its own
/// transaction. Close refunds rent to the uploader, including on cancellation.
/// Changing the message (adding signers/instructions) requires a fresh packet check.
#[derive(Debug, Clone)]
pub struct StagePlan {
    pub address: Pubkey,
    pub begin: Instruction,
    pub uploads: Vec<Instruction>,
    pub seal: Instruction,
    pub consume: Instruction,
    pub close: Instruction,
}

impl StagePlan {
    /// Build the unsigned consume transaction with an explicit compute budget.
    /// Sign with every signer required by its message, including Nitro workload
    /// consent when present. This does not measure or promise execution cost.
    pub fn consume_transaction(
        &self,
        blockhash: solana_sdk::hash::Hash,
        units: u32,
    ) -> Result<Transaction, StageError> {
        if units == 0 || units > 1_400_000 {
            return Err(StageError::InvalidComputeBudget);
        }
        let payer = self
            .consume
            .accounts
            .first()
            .ok_or(StageError::InvalidAuthority)?
            .pubkey;
        let instructions = [
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                units,
            ),
            self.consume.clone(),
        ];
        let tx = Transaction::new_unsigned(Message::new_with_blockhash(
            &instructions,
            Some(&payer),
            &blockhash,
        ));
        if bincode::serialized_size(&tx).map_err(|_| StageError::PacketTooLarge)?
            > crate::PACKET_DATA_SIZE as u64
        {
            return Err(StageError::PacketTooLarge);
        }
        Ok(tx)
    }
}

/// Stage a canonical `register_vcek` instruction. The commitment includes its
/// complete wire payload, including identity and certificate lengths.
pub fn stage_vcek_registration(
    mut source: Instruction,
    authority: Pubkey,
    current_slot: u64,
    expiry_slot: u64,
) -> Result<StagePlan, StageError> {
    if !source.data.starts_with(&REGISTER_VCEK) {
        return Err(StageError::UnsupportedInstruction);
    }
    // Select the identity whose canonical tuple address the caller supplied.
    // This is account plumbing only: consume still authenticates the certificate.
    if source.data.len() < 176 || source.accounts.len() < 3 {
        return Err(StageError::InvalidSize);
    }
    let tcb = u64::from_le_bytes(source.data[72..80].try_into().unwrap());
    let candidates = [
        hash(&source.data[8..72]).to_bytes(),
        hash(&source.data[80..176]).to_bytes(),
    ];
    let identity = candidates
        .iter()
        .find(|identity| {
            crate::builder::derive_vcek_pda(&source.program_id, identity, tcb)
                == source.accounts[2].pubkey
        })
        .ok_or(StageError::InvalidAuthority)?;
    let canonical = crate::derive_amd_revocation_pda(&source.program_id, identity).0;
    match source.accounts.iter().find(|meta| meta.pubkey == canonical) {
        Some(meta) if meta.is_writable || meta.is_signer => {
            return Err(StageError::InvalidAuthority)
        }
        Some(_) => {}
        None => source
            .accounts
            .push(AccountMeta::new_readonly(canonical, false)),
    }
    build_plan(source, authority, current_slot, expiry_slot)
}

/// Stage only Nitro Mode A. The actual consumer transaction must carry the
/// workload signature; this is not a pre-attested atomic action (Mode B).
pub fn stage_nitro_registration(
    source: Instruction,
    authority: Pubkey,
    current_slot: u64,
    expiry_slot: u64,
) -> Result<StagePlan, StageError> {
    if !source
        .data
        .starts_with(&crate::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR)
        || source.data.get(8) != Some(&crate::VERIFY_NITRO_MODE_A)
    {
        return Err(StageError::UnsupportedInstruction);
    }
    if source.data.len() < 53 {
        return Err(StageError::InvalidSize);
    }
    let doc_len = u32::from_le_bytes(source.data[49..53].try_into().unwrap()) as usize;
    if doc_len == 0
        || doc_len > solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN
        || source.data.len() != 53 + doc_len
    {
        return Err(StageError::InvalidSize);
    }
    build_plan(source, authority, current_slot, expiry_slot)
}

/// Build a canonical staged Nitro Mode A upload directly from a document.
/// `nonce` is the slot hash signed inside the document. The on-chain handler
/// authenticates it, the workload key, certificate chain and measurement.
#[allow(clippy::too_many_arguments)]
pub fn build_staged_nitro_registration(
    program_id: Pubkey,
    authority: Pubkey,
    workload: Pubkey,
    nonce_slot: u64,
    document: &[u8],
    nonce: [u8; 32],
    current_slot: u64,
    expiry_slot: u64,
) -> Result<StagePlan, StageError> {
    if document.is_empty()
        || document.len() > solana_confidential_compute_core::MAX_NITRO_DOCUMENT_LEN
    {
        return Err(StageError::InvalidSize);
    }
    let registry = crate::builder::derive_policy_registry_pda(&program_id);
    let (signer, _) = crate::builder::derive_signer_pda(&program_id, &workload.to_bytes());
    let (used_nonce, _) =
        crate::derive_used_nonce_pda_for_source(&program_id, 2, &workload.to_bytes(), &nonce)
            .expect("fixed Nitro source");
    let accounts = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(registry, false),
        AccountMeta::new(signer, false),
        AccountMeta::new(used_nonce, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::slot_hashes::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false),
        AccountMeta::new_readonly(workload, true),
        AccountMeta::new_readonly(
            Pubkey::find_program_address(&[b"backend_policy", &[2]], &program_id).0,
            false,
        ),
        AccountMeta::new_readonly(
            crate::derive_legacy_used_nonce_pda(&program_id, &workload.to_bytes(), &nonce).0,
            false,
        ),
    ];
    let mut data = crate::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR.to_vec();
    data.push(crate::VERIFY_NITRO_MODE_A);
    data.extend(nonce_slot.to_le_bytes());
    data.extend([0; 32]);
    data.extend((document.len() as u32).to_le_bytes());
    data.extend(document);
    stage_nitro_registration(
        Instruction {
            program_id,
            accounts,
            data,
        },
        authority,
        current_slot,
        expiry_slot,
    )
}

/// Build bounded AMD SNP Mode A transport. Only the staged packets are sendable;
/// consume delegates the unchanged report, consent, policy and nonce checks.
pub fn build_staged_snp_registration(
    program_id: Pubkey,
    authority: Pubkey,
    workload: Pubkey,
    nonce_slot: u64,
    report: &[u8],
    current_slot: u64,
    expiry_slot: u64,
) -> Result<StagePlan, StageError> {
    if report.len() != solana_confidential_compute_core::SNP_REPORT_SIZE {
        return Err(StageError::InvalidSize);
    }
    let source = crate::internal::build_register_signer_ix_for_program_oversized(
        &program_id,
        &authority,
        &workload,
        report,
        0,
        nonce_slot,
    )
    .map_err(|_| StageError::InvalidSize)?;
    build_plan(source, authority, current_slot, expiry_slot)
}

fn build_plan(
    source: Instruction,
    authority: Pubkey,
    current_slot: u64,
    expiry_slot: u64,
) -> Result<StagePlan, StageError> {
    if !(8..=MAX_PAYLOAD).contains(&source.data.len()) {
        return Err(StageError::InvalidSize);
    }
    if expiry_slot <= current_slot || expiry_slot - current_slot > MAX_LIFETIME_SLOTS {
        return Err(StageError::InvalidDeadline);
    }
    if source
        .accounts
        .first()
        .map(|a| (a.pubkey, a.is_signer, a.is_writable))
        != Some((authority, true, true))
    {
        return Err(StageError::InvalidAuthority);
    }
    let digest = hash(&source.data);
    let (address, _) = Pubkey::find_program_address(
        &[b"attestation_stage", authority.as_ref(), digest.as_ref()],
        &source.program_id,
    );
    let base = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(address, false),
    ];
    let make = |tag: [u8; 8], rest: &[u8], accounts: Vec<AccountMeta>| {
        let mut data = tag.to_vec();
        data.extend_from_slice(rest);
        Instruction {
            program_id: source.program_id,
            accounts,
            data,
        }
    };
    let mut args = digest.to_bytes().to_vec();
    args.extend_from_slice(&(source.data.len() as u32).to_le_bytes());
    args.extend_from_slice(&expiry_slot.to_le_bytes());
    let mut begin_accounts = base.clone();
    begin_accounts.push(AccountMeta::new_readonly(
        solana_sdk_ids::system_program::ID,
        false,
    ));
    let begin = make(BEGIN, &args, begin_accounts);
    let uploads = source
        .data
        .chunks(MAX_CHUNK)
        .enumerate()
        .map(|(i, chunk)| {
            let mut args = ((i * MAX_CHUNK) as u32).to_le_bytes().to_vec();
            args.extend_from_slice(chunk);
            make(UPLOAD, &args, base.clone())
        })
        .collect::<Vec<_>>();
    let seal = make(SEAL, &[], base.clone());
    let close = make(CLOSE, &[], base.clone());
    let mut consume_accounts = base;
    consume_accounts.extend_from_slice(&source.accounts);
    let consume = make(CONSUME, &[], consume_accounts);
    for ix in std::iter::once(&begin)
        .chain(uploads.iter())
        .chain([&seal, &consume, &close])
    {
        let tx =
            Transaction::new_unsigned(Message::new(std::slice::from_ref(ix), Some(&authority)));
        if bincode::serialized_size(&tx).map_err(|_| StageError::PacketTooLarge)?
            > crate::PACKET_DATA_SIZE as u64
        {
            return Err(StageError::PacketTooLarge);
        }
    }
    Ok(StagePlan {
        address,
        begin,
        uploads,
        seal,
        consume,
        close,
    })
}
