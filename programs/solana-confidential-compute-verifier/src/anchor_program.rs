//! Anchor front end for Solana Confidential Compute Verifier.
//!
//! This module adds an Anchor `#[program]` surface — and therefore a generated
//! IDL and Anchor-native clients — without changing a single line of the audited
//! validation logic in [`crate::processor`].
//!
//! This is the facade stage. The IDL describes instructions and payloads, but
//! every handler takes an empty [`Passthrough`] context, so it declares no
//! accounts and a client must still assemble `remainingAccounts` itself.
//! Defining typed `Accounts` with signer and PDA constraints is the next stage
//! and is deliberately not attempted here: it moves validation into
//! constraints, which changes behaviour and needs its own review.
//!
//! # How the wire format is preserved
//!
//! The native program already dispatched on 8-byte Anchor discriminators
//! (`sha256("global:<name>")[..8]`). Every handler below pins its discriminator
//! to the existing constant with `#[instruction(discriminator = ...)]` instead of
//! letting Anchor derive one from the Rust function name. Four of the historical
//! constants are not reproducible from their obvious snake_case name, so pinning
//! — not renaming — is the only way to keep those instructions callable. See
//! `anchor_discriminators_match_native_constants` in the tests below, which fails
//! the build if any byte ever drifts.
//!
//! # Why governance instructions and hot paths are treated differently
//!
//! Governance instructions each decode exactly one Borsh `*Args` struct, so they
//! translate to idiomatic Anchor handlers directly: Anchor's own Borsh decode of
//! that same struct is byte-for-byte what `Args::try_from_slice(rest)` did.
//!
//! Two governance instructions are also excluded, because their payload is not
//! one canonical struct. `register_vcek` carries a 172-byte header followed by
//! `ask_cert_len` and `vcek_cert_len` bytes of certificate DER, and the
//! processor requires the exact total length; re-encoding the header alone
//! dropped the certificates and made registration impossible. `rotate_authority`
//! takes no payload at all — the new authority arrives as a signing account —
//! so any re-encoded body fails its `rest.is_empty()` check. Both now reach the
//! processor through [`fallback`] with their bytes untouched.
//!
//! The attestation hot paths do not. `verify_and_register`, `verify_atomic*`,
//! the TDX trio, Nitro and NVIDIA parse their payloads without constructing an
//! owned `*Args` value, deliberately, to stay inside the compute budget
//! (`@spec SCC-PERF-001`); several are also generic over
//! `V: SignatureVerifier` so tests can inject a mock, which an Anchor handler
//! signature cannot express. Routing them through [`fallback`] hands them the
//! untouched instruction bytes and keeps both properties intact. Converting them
//! into typed Anchor handlers would reintroduce exactly the allocation and
//! deserialization cost that was engineered away: deserializing an 8 KiB Nitro
//! document or a 4 KiB JWT into owned structs allocates past the 32 KiB SBF
//! heap.
//!
//! # Wire strictness
//!
//! Anchor dispatches with `Instruction::deserialize`, which stops reading once
//! the payload is complete, while the native path used `Args::try_from_slice`,
//! which fails when bytes remain. Every handler therefore takes a trailing
//! [`NoTrailingBytes`] argument, so a padded instruction is rejected here
//! exactly as the deployed program rejects it. That also preserves the
//! processor's own pre-decode length caps, such as the 296-byte bound on
//! `set_gcp_tenant_policy`, which a lenient decode would have skipped.
//!
//! # Accounts
//!
//! Handlers take an empty [`Passthrough`] context, so every account arrives
//! through `ctx.remaining_accounts` in its original position. The processor's
//! positional destructuring and all of its ownership, signer and PDA checks
//! therefore remain the single source of truth. Declaring typed Anchor account
//! contexts per instruction is a follow-up: it improves the IDL but would move
//! validation into constraints, which is a behavioural change that belongs in its
//! own reviewed step.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::entrypoint::ProgramResult;

// `#[program]` refers to the program address as a bare `ID`; the native crate
// declares it at the root.
use crate::payload as native_ix;
use crate::processor::Processor;
use crate::ID;

/// Empty account context: all accounts reach the processor positionally through
/// `remaining_accounts`, exactly as the native entrypoint delivered them.
#[derive(Accounts)]
pub struct Passthrough {}

/// Rebuilds the original instruction payload and replays it through the native
/// dispatcher.
///
/// Anchor has already decoded `args`; re-encoding it costs one Borsh round trip
/// on administrative instructions and buys a conversion that leaves
/// `processor.rs` untouched. Borsh is canonical for these fixed layouts, so the
/// bytes handed to the processor equal the bytes the client sent.
fn replay<A: AnchorSerialize>(
    discriminator: &[u8; 8],
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: &A,
) -> Result<()> {
    let mut data = Vec::with_capacity(8 + 256);
    data.extend_from_slice(discriminator);
    args.serialize(&mut data).map_err(|_| error!(AnchorFrontEndError::ArgumentReencode))?;
    to_anchor_result(Processor::process(program_id, accounts, &data))
}

fn to_anchor_result(result: ProgramResult) -> Result<()> {
    result.map_err(Error::from)
}

#[error_code]
pub enum AnchorFrontEndError {
    #[msg("instruction arguments could not be re-encoded for dispatch")]
    ArgumentReencode,
}

/// A payload that must consume the whole instruction body.
///
/// Anchor dispatches with `Instruction::deserialize`, which stops reading once
/// the payload is complete and ignores the remainder. The native path used
/// `Args::try_from_slice`, which fails when bytes remain. Wrapping the payload
/// restores that contract, so a padded instruction is rejected here exactly as
/// the deployed program rejects it. That also preserves the processor's own
/// pre-decode length caps, such as the 296-byte bound on
/// `set_gcp_tenant_policy`, which a lenient decode would have skipped.
///
/// Serialization and the IDL both forward to the inner type, so this wrapper is
/// invisible to clients: the generated IDL names the payload itself.
pub struct Strict<T>(pub T);

impl<T: borsh::BorshDeserialize> borsh::BorshDeserialize for Strict<T> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let value = T::deserialize_reader(reader)?;
        let mut probe = [0u8; 1];
        if reader.read(&mut probe)? == 0 {
            Ok(Self(value))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "trailing instruction bytes"))
        }
    }
}

impl<T: borsh::BorshSerialize> borsh::BorshSerialize for Strict<T> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

#[cfg(feature = "idl-build")]
impl<T: anchor_lang::IdlBuild> anchor_lang::IdlBuild for Strict<T> {
    fn create_type() -> Option<anchor_lang::idl::types::IdlTypeDef> {
        T::create_type()
    }
    fn insert_types(types: &mut std::collections::BTreeMap<String, anchor_lang::idl::types::IdlTypeDef>) {
        T::insert_types(types)
    }
    fn get_full_path() -> String {
        T::get_full_path()
    }
}

#[program]
pub mod solana_confidential_compute_verifier {
    use super::*;

    #[instruction(discriminator = &native_ix::INIT_POLICY_REGISTRY_DISCRIMINATOR)]
    pub fn init_policy_registry(
        ctx: Context<Passthrough>,
        args: Strict<native_ix::InitPolicyRegistryArgs>,
    ) -> Result<()> {
        replay(&native_ix::INIT_POLICY_REGISTRY_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::UPDATE_POLICY_DISCRIMINATOR)]
    pub fn update_policy(ctx: Context<Passthrough>, args: Strict<native_ix::UpdatePolicyArgs>) -> Result<()> {
        replay(&native_ix::UPDATE_POLICY_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::ROTATE_ROOT_CERT_DISCRIMINATOR)]
    pub fn rotate_root_cert(ctx: Context<Passthrough>, args: Strict<native_ix::RotateRootCertArgs>) -> Result<()> {
        replay(&native_ix::ROTATE_ROOT_CERT_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::REVOKE_VCEK_DISCRIMINATOR)]
    pub fn revoke_vcek(ctx: Context<Passthrough>, args: Strict<native_ix::RevokeVcekArgs>) -> Result<()> {
        replay(&native_ix::REVOKE_VCEK_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::SET_BACKEND_POLICY_DISCRIMINATOR)]
    pub fn set_backend_policy(ctx: Context<Passthrough>, args: Strict<native_ix::SetBackendPolicyArgs>) -> Result<()> {
        replay(&native_ix::SET_BACKEND_POLICY_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::SET_GCP_TENANT_POLICY_DISCRIMINATOR)]
    pub fn set_gcp_tenant_policy(
        ctx: Context<Passthrough>,
        args: Strict<native_ix::SetGcpTenantPolicyArgs>,
    ) -> Result<()> {
        replay(&native_ix::SET_GCP_TENANT_POLICY_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::REVOKE_ATTESTED_SIGNER_DISCRIMINATOR)]
    pub fn revoke_attested_signer(
        ctx: Context<Passthrough>,
        args: Strict<native_ix::RevokeAttestedSignerArgs>,
    ) -> Result<()> {
        replay(&native_ix::REVOKE_ATTESTED_SIGNER_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::REGISTER_JWKS_KEY_DISCRIMINATOR)]
    pub fn register_jwks_key(ctx: Context<Passthrough>, args: Strict<native_ix::RegisterJwksKeyArgs>) -> Result<()> {
        replay(&native_ix::REGISTER_JWKS_KEY_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    #[instruction(discriminator = &native_ix::REVOKE_JWKS_KEY_DISCRIMINATOR)]
    pub fn revoke_jwks_key(ctx: Context<Passthrough>, args: Strict<native_ix::RevokeJwksKeyArgs>) -> Result<()> {
        replay(&native_ix::REVOKE_JWKS_KEY_DISCRIMINATOR, ctx.program_id, ctx.remaining_accounts, &args.0)
    }

    /// Serves every instruction that is not declared above: the attestation
    /// verification paths, the TDX sequence, and the two no-argument account
    /// closures. The payload is forwarded verbatim, so their zero-copy parsing
    /// and compute-budget behaviour are unchanged.
    pub fn fallback<'info>(program_id: &Pubkey, accounts: &'info [AccountInfo<'info>], data: &[u8]) -> Result<()> {
        to_anchor_result(Processor::process(program_id, accounts, data))
    }
}

#[cfg(test)]
mod tests {
    use anchor_lang::Discriminator;

    use super::*;

    /// The Anchor front end must address the instructions the deployed program
    /// already answers to. Pinning is only safe if it is enforced, so compare
    /// every generated discriminator against the native constant.
    #[test]
    fn anchor_discriminators_match_native_constants() {
        let expected: [(&str, &[u8], [u8; 8]); 9] = [
            (
                "init_policy_registry",
                instruction::InitPolicyRegistry::DISCRIMINATOR,
                native_ix::INIT_POLICY_REGISTRY_DISCRIMINATOR,
            ),
            ("update_policy", instruction::UpdatePolicy::DISCRIMINATOR, native_ix::UPDATE_POLICY_DISCRIMINATOR),
            ("rotate_root_cert", instruction::RotateRootCert::DISCRIMINATOR, native_ix::ROTATE_ROOT_CERT_DISCRIMINATOR),
            ("revoke_vcek", instruction::RevokeVcek::DISCRIMINATOR, native_ix::REVOKE_VCEK_DISCRIMINATOR),
            (
                "set_backend_policy",
                instruction::SetBackendPolicy::DISCRIMINATOR,
                native_ix::SET_BACKEND_POLICY_DISCRIMINATOR,
            ),
            (
                "set_gcp_tenant_policy",
                instruction::SetGcpTenantPolicy::DISCRIMINATOR,
                native_ix::SET_GCP_TENANT_POLICY_DISCRIMINATOR,
            ),
            (
                "revoke_attested_signer",
                instruction::RevokeAttestedSigner::DISCRIMINATOR,
                native_ix::REVOKE_ATTESTED_SIGNER_DISCRIMINATOR,
            ),
            (
                "register_jwks_key",
                instruction::RegisterJwksKey::DISCRIMINATOR,
                native_ix::REGISTER_JWKS_KEY_DISCRIMINATOR,
            ),
            ("revoke_jwks_key", instruction::RevokeJwksKey::DISCRIMINATOR, native_ix::REVOKE_JWKS_KEY_DISCRIMINATOR),
        ];

        for (name, generated, native) in expected {
            assert_eq!(generated, &native[..], "{name}: Anchor discriminator drifted from the deployed constant");
        }
    }

    /// `solana_program::declare_id!` generated a `test_id` case; Anchor's macro
    /// does not, and the anchor build swaps to Anchor's so the IDL carries the
    /// program address. Assert the address directly so that swap cannot change
    /// which program the front end claims to be.
    #[test]
    fn program_id_is_unchanged_under_the_anchor_front_end() {
        assert_eq!(crate::ID.to_string(), "EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh");
    }

    /// Anchor's own decode is lenient; the trailing [`NoTrailingBytes`]
    /// argument is what restores the native contract. Assert both halves, so a
    /// future refactor that drops the marker fails here rather than silently
    /// widening the wire specification.
    #[test]
    fn padded_instructions_are_rejected_as_natively() {
        use anchor_lang::AnchorDeserialize;

        let canonical = vec![7u8; 32]; // RevokeJwksKeyArgs is a single [u8; 32]
        let mut padded = canonical.clone();
        padded.extend_from_slice(&[0xAA; 48]);

        assert!(native_ix::RevokeJwksKeyArgs::try_from_slice(&canonical).is_ok());
        assert!(
            native_ix::RevokeJwksKeyArgs::try_from_slice(&padded).is_err(),
            "the native path rejects trailing bytes"
        );
        assert!(
            instruction::RevokeJwksKey::deserialize(&mut &canonical[..]).is_ok(),
            "the canonical payload must still decode"
        );
        assert!(
            instruction::RevokeJwksKey::deserialize(&mut &padded[..]).is_err(),
            "the Anchor entrypoint must reject trailing bytes too"
        );
    }

    /// Four historical constants are not `sha256("global:<snake_case_name>")`.
    /// If a future Anchor upgrade silently re-derived them from the handler name
    /// the program would stop answering those instructions, so assert that the
    /// pinned bytes really do differ from the derived ones.
    #[test]
    fn pinning_is_load_bearing_for_renamed_instructions() {
        use sha2::{Digest, Sha256};

        let derived = |name: &str| {
            let digest = Sha256::digest(format!("global:{name}").as_bytes());
            let mut out = [0u8; 8];
            out.copy_from_slice(&digest[..8]);
            out
        };

        for (name, native) in [
            ("update_policy", native_ix::UPDATE_POLICY_DISCRIMINATOR),
            ("register_jwks_key", native_ix::REGISTER_JWKS_KEY_DISCRIMINATOR),
            ("revoke_jwks_key", native_ix::REVOKE_JWKS_KEY_DISCRIMINATOR),
        ] {
            assert_ne!(derived(name), native, "{name}: expected the deployed constant to need pinning");
        }

        // Control: the majority of instructions do match the derived value, so a
        // blanket mismatch would mean the hashing itself is wrong.
        assert_eq!(derived("verify_atomic"), native_ix::VERIFY_ATOMIC_DISCRIMINATOR);
    }
}
