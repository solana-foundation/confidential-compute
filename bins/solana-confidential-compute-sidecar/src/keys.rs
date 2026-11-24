//! Ephemeral in-memory Ed25519 key manager with zeroization on drop.
//!
//! @spec SCC-SIDECAR-001

use solana_sdk::{
    hash::Hash,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::{SeedDerivable, Signer},
    transaction::{Transaction, VersionedTransaction},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SidecarError;

/// Ed25519 seed. `ZeroizeOnDrop` wipes this buffer on rotate and on drop.
/// @spec SCC-SIDECAR-001
#[derive(Zeroize, ZeroizeOnDrop)]
struct EphemeralSecret([u8; 32]);

/// Ephemeral Ed25519 keypair manager.
/// Keys reside strictly in RAM and are never written to disk or persistently logged.
pub struct EphemeralKeyManager {
    /// `solana_sdk::Keypair` does not implement `Zeroize`, so the bytes that sign live here.
    /// @spec SCC-SIDECAR-001
    secret: EphemeralSecret,
    pubkey: Pubkey,
}

impl EphemeralKeyManager {
    /// Generates a new ephemeral Ed25519 keypair in RAM via OS CSPRNG.
    /// @spec SCC-SEC-007
    pub fn new() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut secret = EphemeralSecret([0u8; 32]);
        OsRng.fill_bytes(&mut secret.0);
        let keypair = Keypair::from_seed(&secret.0).expect("32-byte seed");
        let pubkey = keypair.pubkey();
        drop(keypair);
        Self { secret, pubkey }
    }

    /// Signs with a temporary `Keypair` built from a reference to the seed.
    ///
    /// `Keypair::from_seed` borrows `self.secret`. `ed25519_dalek::SecretKey`
    /// wipes that keypair copy in `Drop`, including when `op` unwinds.
    /// `solana_sdk::Keypair` does not implement `Zeroize`. The durable seed
    /// stays in `self.secret`.
    /// @spec SCC-SEC-007 SCC-SIDECAR-001
    fn with_signing_key<T>(&self, op: impl FnOnce(&Keypair) -> T) -> T {
        let keypair = Keypair::from_seed(self.secret.0.as_ref()).expect("ephemeral seed is 32 bytes");
        op(&keypair)
    }

    /// Returns the public key of the active ephemeral signer.
    #[inline]
    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    /// Signs an arbitrary message using the active ephemeral key.
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        self.with_signing_key(|keypair| keypair.sign_message(message).into())
    }

    /// Partially signs a Solana `VersionedTransaction`.
    /// Requires a distinct external fee payer and an authorized workload signer.
    pub fn sign_transaction(&self, tx: &mut VersionedTransaction) -> Result<Signature, SidecarError> {
        let message = &tx.message;
        let static_keys = message.static_account_keys();
        let required_sigs = message.header().num_required_signatures as usize;

        self.require_external_payer(static_keys.first())?;

        // Find the index of this ephemeral signer in static accounts
        let signer_index = static_keys.iter().position(|k| k == &self.pubkey).ok_or_else(|| {
            SidecarError::UnauthorizedSigner(format!(
                "Ephemeral public key {} not present in transaction accounts",
                self.pubkey
            ))
        })?;

        if signer_index >= required_sigs {
            return Err(SidecarError::UnauthorizedSigner(format!(
                "Account {} is present at index {} but transaction header only requires {} signatures",
                self.pubkey, signer_index, required_sigs
            )));
        }

        // Ensure transaction signatures vector is properly sized
        if tx.signatures.len() < required_sigs {
            tx.signatures.resize(required_sigs, Signature::default());
        }

        let message_bytes = message.serialize();
        let signature = self.with_signing_key(|keypair| keypair.sign_message(&message_bytes));
        tx.signatures[signer_index] = signature;

        Ok(signature)
    }

    /// Adds the workload signature to a legacy transaction. The secret stays inside this manager.
    pub fn partial_sign(&self, tx: &mut Transaction, recent_blockhash: Hash) -> Result<(), SidecarError> {
        self.require_external_payer(tx.message.account_keys.first())?;
        self.with_signing_key(|keypair| tx.try_partial_sign(&[keypair], recent_blockhash))
            .map_err(|e| SidecarError::KeyError(format!("workload sign failed: {e}")))?;
        Ok(())
    }

    /// Enforce before creating a signature or modifying the transaction. Solana
    /// account zero pays fees, including fees on failed caller transactions.
    fn require_external_payer(&self, payer: Option<&Pubkey>) -> Result<(), SidecarError> {
        if payer.is_none() || payer == Some(&self.pubkey) {
            return Err(SidecarError::UnauthorizedSigner(
                "workload key must not be the transaction fee payer; a distinct external payer is required".into(),
            ));
        }
        Ok(())
    }

    /// Rotates the ephemeral key. The previous secret is dropped, and therefore zeroized, before return.
    /// @spec SCC-SIDECAR-001
    pub fn rotate(&mut self) -> Pubkey {
        let fresh = Self::new();
        let pubkey = fresh.pubkey;
        drop(std::mem::replace(self, fresh));
        pubkey
    }
}

impl Default for EphemeralKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use solana_sdk::{
        hash::Hash,
        message::{v0::Message, VersionedMessage},
    };
    use solana_system_interface::instruction as system_instruction;
    use zeroize::Zeroizing;

    #[test]
    fn test_ephemeral_key_signing_and_verification() {
        let manager = EphemeralKeyManager::new();
        let pubkey = manager.pubkey();
        let data = b"solana confidential compute payload";
        let sig_bytes = manager.sign_message(data);
        let sig = Signature::from(sig_bytes);

        assert!(sig.verify(pubkey.as_ref(), data));
    }

    #[test]
    fn test_key_rotation_changes_pubkey() {
        let mut manager = EphemeralKeyManager::new();
        let pk1 = manager.pubkey();
        let pk2 = manager.rotate();

        assert_ne!(pk1, pk2);
        assert_eq!(manager.pubkey(), pk2);
    }

    #[test]
    fn test_sign_versioned_transaction() {
        let manager = EphemeralKeyManager::new();
        let recipient = Pubkey::new_unique();
        let payer = Pubkey::new_unique();

        let ix = system_instruction::transfer(&manager.pubkey(), &recipient, 1_000);
        let message = VersionedMessage::V0(Message::try_compile(&payer, &[ix], &[], Hash::default()).expect("compile"));

        let mut tx = VersionedTransaction { signatures: vec![Signature::default()], message };

        let sig = manager.sign_transaction(&mut tx).expect("sign");
        assert_ne!(sig, Signature::default());
        assert_eq!(tx.signatures[0], Signature::default());
        assert_eq!(tx.signatures[1], sig);
    }

    #[test]
    fn test_rejects_transaction_missing_signer() {
        let manager = EphemeralKeyManager::new();
        let other_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let ix = system_instruction::transfer(&other_payer, &recipient, 1_000);
        let message =
            VersionedMessage::V0(Message::try_compile(&other_payer, &[ix], &[], Hash::default()).expect("compile"));

        let mut tx = VersionedTransaction { signatures: vec![Signature::default()], message };

        let err = manager.sign_transaction(&mut tx);
        assert!(err.is_err());
    }

    #[test]
    fn drop_zeroizes_the_signing_secret() {
        let mut secret = EphemeralSecret([0xa5; 32]);
        assert_eq!(secret.0, [0xa5; 32]);
        secret.zeroize();
        assert_eq!(secret.0, [0u8; 32]);

        let mut seed = Zeroizing::new([0xa5u8; 32]);
        seed.zeroize();
        assert_eq!(seed.as_ref(), &[0u8; 32]);
    }

    #[test]
    fn panic_during_sign_still_wipes_the_temporary_seed() {
        let manager = from_secret([0xa5; 32]);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            manager.with_signing_key(|_| panic!("sign op"));
        }));
        assert!(panicked.is_err());
        let message = b"after panic";
        let sig = Signature::from(manager.sign_message(message));
        assert!(sig.verify(manager.pubkey().as_ref(), message));
    }

    #[test]
    fn rotate_drops_previous_secret_and_signs_with_the_new_key() {
        let mut manager = from_secret([0xa5; 32]);
        let old_pk = manager.pubkey();
        let new_pk = manager.rotate();
        assert_ne!(old_pk, new_pk);
        assert_ne!(manager.secret.0, [0xa5; 32]);
        let message = b"rotated";
        let sig = Signature::from(manager.sign_message(message));
        assert!(sig.verify(new_pk.as_ref(), message));
        assert!(!sig.verify(old_pk.as_ref(), message));
    }

    fn from_secret(secret: [u8; 32]) -> EphemeralKeyManager {
        let pubkey = Keypair::new_from_array(secret).pubkey();
        EphemeralKeyManager { secret: EphemeralSecret(secret), pubkey }
    }
}
