//! Governance authorization errors must identify the failed condition.
use borsh::BorshSerialize;
use solana_confidential_compute_verifier::{
    error::VerifierError, payload::*, processor::Processor, state::*,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

fn exercise(
    discriminator: [u8; 8],
    signed: bool,
    correct: bool,
    foreign: bool,
) -> (Result<(), ProgramError>, Vec<u8>, Vec<u8>) {
    let program = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let actor = if correct {
        authority
    } else {
        Pubkey::new_unique()
    };
    let (registry_key, bump) = Pubkey::find_program_address(&[b"policy_registry"], &program);
    let registry = PolicyRegistry {
        discriminator: POLICY_REGISTRY_DISCRIMINATOR,
        authority: authority.to_bytes(),
        ark_pubkey_xy: [1; 96],
        min_tcb_boot_loader: 0,
        min_tcb_tee: 0,
        min_tcb_snp: 0,
        min_tcb_microcode: 0,
        measurement_count: 0,
        measurements: [[0; 48]; 8],
        bump,
    };
    let mut registry_data = borsh::to_vec(&registry).unwrap();
    let kid_hash = [7; 32];
    let (jwks_key, jwks_bump) = Pubkey::find_program_address(
        &[
            solana_confidential_compute_crypto::jwt::JWKS_SEED,
            &kid_hash,
        ],
        &program,
    );
    let mut jwks_data = borsh::to_vec(&JwksAccount::new(
        kid_hash, [1; 256], 65537, 0, [0; 256], 0, jwks_bump,
    ))
    .unwrap();
    let mut ix = discriminator.to_vec();
    if discriminator == UPDATE_POLICY_DISCRIMINATOR {
        UpdatePolicyArgs {
            min_tcb_boot_loader: 1,
            min_tcb_tee: 1,
            min_tcb_snp: 1,
            min_tcb_microcode: 1,
            measurement_count: 0,
            measurements: [[0; 48]; 8],
        }
        .serialize(&mut ix)
        .unwrap();
    } else if discriminator == ROTATE_ROOT_CERT_DISCRIMINATOR {
        RotateRootCertArgs {
            new_ark_pubkey_xy: [2; 96],
        }
        .serialize(&mut ix)
        .unwrap();
    } else {
        RevokeJwksKeyArgs { kid_hash }.serialize(&mut ix).unwrap();
    }
    let before_registry = registry_data.clone();
    let before_jwks = jwks_data.clone();
    let (mut a, mut r, mut j) = (1, 1, 1);
    let mut empty = [];
    let accounts = [
        AccountInfo::new(&actor, signed, false, &mut a, &mut empty, &owner, false),
        AccountInfo::new(
            &registry_key,
            false,
            true,
            &mut r,
            &mut registry_data,
            &program,
            false,
        ),
        AccountInfo::new(
            &jwks_key,
            false,
            true,
            &mut j,
            &mut jwks_data,
            if foreign { &owner } else { &program },
            false,
        ),
    ];
    let result = Processor::process(&program, &accounts, &ix);
    drop(accounts);
    if result.is_err() {
        assert_eq!(registry_data, before_registry);
        assert_eq!(jwks_data, before_jwks);
    }
    (result, registry_data, jwks_data)
}

#[test]
fn issue_192_governance_errors_and_negative_controls() {
    for ix in [
        UPDATE_POLICY_DISCRIMINATOR,
        ROTATE_ROOT_CERT_DISCRIMINATOR,
        REVOKE_JWKS_KEY_DISCRIMINATOR,
    ] {
        assert_eq!(
            exercise(ix, false, true, false).0,
            Err(ProgramError::MissingRequiredSignature)
        );
        assert_eq!(
            exercise(ix, true, false, false).0,
            Err(VerifierError::InvalidAuthority.into())
        );
        // Issue #172: authorized root rotation is refused (registry unchanged).
        let expected = if ix == ROTATE_ROOT_CERT_DISCRIMINATOR {
            Err(VerifierError::InvalidInstruction.into())
        } else {
            Ok(())
        };
        assert_eq!(exercise(ix, true, true, false).0, expected);
    }
    assert_eq!(
        exercise(REVOKE_JWKS_KEY_DISCRIMINATOR, true, true, true).0,
        Err(VerifierError::InvalidAccountAddress.into())
    );
}
