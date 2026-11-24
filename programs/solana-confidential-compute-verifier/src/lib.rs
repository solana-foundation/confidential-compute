//! # Solana Confidential Compute Verifier
//!
//! Solana smart contract that verifies AMD SEV-SNP and AWS Nitro hardware attestations,
//! cross-checks binary code measurements against an on-chain allowlist, and registers
//! verified Ed25519 signer keys.
#![allow(unexpected_cfgs, deprecated)]

// Mock features must never produce an on-chain artifact, even with no-entrypoint.
#[cfg(all(feature = "mock-crypto", target_os = "solana"))]
compile_error!("mock-crypto is unavailable on Solana SBF under every feature combination");

#[cfg(feature = "anchor")]
pub mod anchor_program;
pub mod entrypoint;
pub mod error;
pub mod groth16;
pub mod introspection;
pub mod payload;
pub mod processor;
pub mod state;
pub mod tdx;

#[cfg(feature = "anchor")]
pub use anchor_program::solana_confidential_compute_verifier;
#[cfg(all(not(feature = "no-entrypoint"), not(feature = "anchor")))]
pub use entrypoint::process_instruction;
// `#[program]` emits `crate::__client_accounts_*` paths for its account structs.
// The front end lives in its own module, so surface them at the crate root.
#[cfg(feature = "anchor")]
pub use anchor_program::{__client_accounts_passthrough, __cpi_client_accounts_passthrough};
// Anchor's IDL generator resolves its instruction structs through
// `crate::instruction`, which assumes `#[program]` sits at the crate root. The
// front end lives in its own module, so surface the generated module here. The
// Borsh payload definitions moved to `payload` to free the name.
#[cfg(feature = "anchor")]
pub use anchor_program::instruction;
pub use groth16::{Groth16SyscallVerifier, Groth16VerifyingKey};
pub use introspection::InstructionIntrospectionVerifier;
pub use processor::{DefaultVerifier, DirectCryptoVerifier};
#[cfg(not(target_os = "solana"))]
pub use solana_confidential_compute_core::MockVerifier;
pub use solana_confidential_compute_core::SignatureVerifier;

#[cfg(not(feature = "anchor"))]
solana_program::declare_id!("EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh");
// Same address, but Anchor's macro also emits the IDL address entry, without
// which a generated client cannot resolve the program from the IDL alone.
#[cfg(feature = "anchor")]
anchor_lang::declare_id!("EKfHCTnsbRQfURsdmzkmuoxUx7DVt8WsQ5X7t49ZZZh");

#[cfg(test)]
mod feature_security_tests {
    use super::{DefaultVerifier, DirectCryptoVerifier, MockVerifier, SignatureVerifier};

    #[test]
    fn native_backend_selection_and_garbage_signature_control() {
        let key = [0; 96];
        let digest = [0; 48];
        let signature = [0; 96];
        assert!(MockVerifier::succeeding()
            .verify_p384(&key, &digest, &signature, None)
            .is_ok());
        assert!(DirectCryptoVerifier
            .verify_p384(&key, &digest, &signature, None)
            .is_err());
        // Only an explicit mock-crypto feature may select the native test double.
        assert_eq!(
            DefaultVerifier::default()
                .verify_p384(&key, &digest, &signature, None)
                .is_ok(),
            cfg!(feature = "mock-crypto")
        );
    }
}
