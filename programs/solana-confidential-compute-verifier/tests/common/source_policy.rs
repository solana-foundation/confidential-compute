// Explicit governance policy fixtures for tests that previously configured the global allowlist.
use solana_confidential_compute_core::SignatureVerifier;
use solana_confidential_compute_verifier::state::{BackendPolicy, PolicyRegistry};
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
pub struct TestProcessor;
fn with_policies<'a>(program_id: &Pubkey, accounts: &[AccountInfo<'a>], data: &[u8]) -> Vec<AccountInfo<'a>> {
    let mut output = accounts.to_vec();
    if ![
        solana_confidential_compute_verifier::payload::VERIFY_AND_REGISTER_DISCRIMINATOR,
        solana_confidential_compute_verifier::payload::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR,
        solana_confidential_compute_verifier::payload::VERIFY_GOOGLE_JWT_DISCRIMINATOR,
        solana_confidential_compute_verifier::payload::VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
    ]
    .iter()
    .any(|d| data.get(..8) == Some(d.as_slice()))
    {
        return output;
    }

    if data.get(..8)
        == Some(solana_confidential_compute_verifier::payload::VERIFY_AND_REGISTER_DISCRIMINATOR.as_slice())
        || data.get(..8)
            == Some(solana_confidential_compute_verifier::payload::VERIFY_ATOMIC_WITH_NONCE_DISCRIMINATOR.as_slice())
    {
        if let Some(cache) = accounts
            .get(2)
            .and_then(|a| a.try_borrow_data().ok())
            .and_then(|d| borsh::from_slice::<solana_confidential_compute_verifier::state::VcekAccount>(&d).ok())
        {
            let key = Pubkey::find_program_address(
                &[solana_confidential_compute_verifier::state::AmdIdentityRevocation::SEED, &cache.chip_id_hash],
                program_id,
            )
            .0;
            if !output.iter().any(|a| a.key == &key) {
                output.push(AccountInfo::new(
                    Box::leak(Box::new(key)),
                    false,
                    false,
                    Box::leak(Box::new(0)),
                    Box::leak(Box::new([])),
                    Box::leak(Box::new(solana_sdk_ids::system_program::ID)),
                    false,
                ));
            }
        }
    }
    let (global, _) = Pubkey::find_program_address(&[b"policy_registry"], program_id);
    let registry = accounts
        .iter()
        .find(|a| a.key == &global)
        .and_then(|a| a.try_borrow_data().ok().and_then(|d| borsh::from_slice::<PolicyRegistry>(&d).ok()));
    if let Some(registry) = registry
        .filter(|r| r.discriminator == solana_confidential_compute_verifier::state::POLICY_REGISTRY_DISCRIMINATOR)
    {
        for source in 1..=3 {
            let (key, bump) = Pubkey::find_program_address(&[BackendPolicy::SEED, &[source]], program_id);
            if output.iter().any(|a| a.key == &key) {
                continue;
            }
            let value = BackendPolicy {
                discriminator: BackendPolicy::DISCRIMINATOR,
                source,
                measurement_count: registry.measurement_count,
                measurements: registry.measurements,
                bump,
            };
            output.push(AccountInfo::new(
                Box::leak(Box::new(key)),
                false,
                false,
                Box::leak(Box::new(1)),
                Box::leak(borsh::to_vec(&value).unwrap().into_boxed_slice()),
                Box::leak(Box::new(*program_id)),
                false,
            ));
        }
    }
    output
}
#[allow(dead_code)]
impl TestProcessor {
    pub fn verify_recent_slot_hash(
        account: &AccountInfo,
        current: u64,
        nonce: u64,
        hash: &[u8; 32],
    ) -> Result<(), solana_confidential_compute_verifier::error::VerifierError> {
        solana_confidential_compute_verifier::processor::Processor::verify_recent_slot_hash(
            account, current, nonce, hash,
        )
    }

    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        solana_confidential_compute_verifier::processor::Processor::process(
            program_id,
            &with_policies(program_id, accounts, data),
            data,
        )
    }
    pub fn process_with<V: SignatureVerifier>(
        v: &V,
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        data: &[u8],
    ) -> ProgramResult {
        solana_confidential_compute_verifier::processor::Processor::process_with(
            v,
            program_id,
            &with_policies(program_id, accounts, data),
            data,
        )
    }
}
