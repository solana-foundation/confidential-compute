//! On-chain state representations for Solana Confidential Compute Verifier.
//! Prepend standard 8-byte Anchor discriminators for 100% CPI interoperability.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_confidential_compute_core::types::AttestedSigner;
use solana_program::program_error::ProgramError;

/// 8-byte Anchor discriminator for AttestedSignerAccount:
/// sha256("account:AttestedSignerAccountV2")[..8]
pub const ATTESTED_SIGNER_DISCRIMINATOR: [u8; 8] = [43, 255, 114, 40, 233, 28, 127, 238];

/// 8-byte Anchor discriminator for VcekAccount:
/// sha256("account:VcekAccountV2")[..8]
pub const VCEK_ACCOUNT_DISCRIMINATOR: [u8; 8] = [180, 227, 118, 227, 197, 175, 220, 193];

/// 8-byte Anchor discriminator for PolicyRegistry:
/// sha256("account:PolicyRegistry")[..8]
pub const POLICY_REGISTRY_DISCRIMINATOR: [u8; 8] = [175, 179, 180, 44, 5, 161, 62, 240];

/// 8-byte Anchor discriminator for UsedNonceAccount:
/// sha256("account:UsedNonceAccount")[..8]
pub const LEGACY_USED_NONCE_DISCRIMINATOR: [u8; 8] = [157, 75, 223, 206, 73, 132, 216, 154];
pub const USED_NONCE_DISCRIMINATOR: [u8; 8] = [138, 99, 69, 17, 9, 177, 205, 94];

/// On-chain PDA account holding verified enclave attestation state.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestedSignerAccount {
    /// 8-byte Anchor discriminator.
    pub discriminator: [u8; 8],
    /// The attested signer domain record.
    pub record: AttestedSigner,
    /// Bump seed for PDA derivation.
    pub bump: u8,
    /// Exclusive trusted Unix deadline; consumers must enforce alongside slot expiry.
    pub expires_unix_timestamp: i64,
}

impl AttestedSignerAccount {
    /// Permanent governance tombstone. Normal admission adds a positive TTL,
    /// even at slot zero; old governance revocations already use this sentinel.
    pub fn is_revoked(&self) -> bool {
        self.record.expires_slot == 0
    }

    pub const SIZE: usize = 8 + (32 + 1 + 48 + 32 + 8 + 8 + 8) + 1 + 8; // 154 bytes

    pub fn new(record: AttestedSigner, bump: u8) -> Self {
        Self { discriminator: ATTESTED_SIGNER_DISCRIMINATOR, record, bump, expires_unix_timestamp: 0 }
    }
}

/// On-chain PDA holding cached physical AMD chip endorsement key.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VcekAccount {
    /// 8-byte Anchor discriminator.
    pub discriminator: [u8; 8],
    /// SHA-256 hash of the 64-byte AMD chip ID.
    pub chip_id_hash: [u8; 32],
    /// TCB version vector.
    pub tcb_version: u64,
    /// P-384 uncompressed public key (x || y) = 96 bytes.
    pub public_key_xy: [u8; 96],
    /// Registration slot.
    pub registered_slot: u64,
    /// Bump seed.
    pub bump: u8,
    /// SHA256 of the pinned Milan RSA4096 ARK modulus, never mutable P384 state.
    pub trust_profile: [u8; 32],
    /// Exclusive min(ASK.notAfter, leaf.notAfter), authenticated at registration.
    pub valid_until_unix: u64,
    pub is_revoked: bool,
}

impl VcekAccount {
    pub const SEED: &'static [u8] = b"vcek_v2";
    pub const MILAN_TRUST_PROFILE: [u8; 32] = [
        133, 117, 150, 230, 106, 13, 196, 134, 214, 159, 68, 89, 85, 76, 86, 249, 108, 63, 131, 243, 54, 89, 132, 101,
        13, 26, 171, 95, 123, 33, 91, 42,
    ];
    pub const TRUST_PROFILE_OFFSET: usize = 153;
    pub const VALID_UNTIL_OFFSET: usize = 185;
    pub const REVOKED_OFFSET: usize = 193;
    pub fn with_validity(mut self, valid_until_unix: u64) -> Self {
        self.valid_until_unix = valid_until_unix;
        self
    }

    pub const SIZE: usize = 8 + 32 + 8 + 96 + 8 + 1 + 32 + 8 + 1; // 194 bytes
    pub const PUBLIC_KEY_OFFSET: usize = 0x30;
    pub const BUMP_OFFSET: usize = 0x98;

    pub fn new(
        chip_id_hash: [u8; 32],
        tcb_version: u64,
        public_key_xy: [u8; 96],
        registered_slot: u64,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: VCEK_ACCOUNT_DISCRIMINATOR,
            chip_id_hash,
            tcb_version,
            public_key_xy,
            registered_slot,
            bump,
            trust_profile: Self::MILAN_TRUST_PROFILE,
            valid_until_unix: 0,
            is_revoked: false,
        }
    }
}

/// Borrows `N` bytes of account data at `offset`. Short data is `InvalidAccountData`.
fn array_at<const N: usize>(data: &[u8], offset: usize) -> Result<&[u8; N], ProgramError> {
    data.get(offset..).and_then(<[u8]>::first_chunk).ok_or(ProgramError::InvalidAccountData)
}

/// Zero-copy view over a serialized `VcekAccount`.
/// @spec SCC-ARCH-002
pub struct VcekAccountView<'a> {
    data: &'a [u8],
}

impl<'a> VcekAccountView<'a> {
    pub fn try_from_slice(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < VcekAccount::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0..8] != VCEK_ACCOUNT_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self { data })
    }

    pub fn is_trusted_at_unix(&self, now: i64) -> bool {
        let Ok(now) = u64::try_from(now) else {
            return false;
        };
        let Ok(valid_until) = self.valid_until_unix() else {
            return false;
        };
        self.data[VcekAccount::TRUST_PROFILE_OFFSET..VcekAccount::TRUST_PROFILE_OFFSET + 32]
            == VcekAccount::MILAN_TRUST_PROFILE
            && self.data[VcekAccount::REVOKED_OFFSET] == 0
            && now < valid_until
    }

    /// Authenticated exclusive certificate-chain deadline stored at registration.
    pub fn valid_until_unix(&self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(*array_at(self.data, VcekAccount::VALID_UNTIL_OFFSET)?))
    }

    #[inline]
    pub fn public_key_xy(&self) -> Result<&'a [u8; 96], ProgramError> {
        array_at(self.data, VcekAccount::PUBLIC_KEY_OFFSET)
    }

    #[inline]
    pub fn bump(&self) -> u8 {
        self.data[VcekAccount::BUMP_OFFSET]
    }
}

/// On-chain governance authority, AMD TCB floors and legacy root/measurement storage.
///
/// The global measurement list is deprecated as a runtime control. AMD, Nitro and
/// GCP admission use `BackendPolicy` exclusively for measurements. Clearing this
/// list does not halt admission; clear each relevant backend policy instead.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PolicyRegistry {
    /// 8-byte Anchor discriminator.
    pub discriminator: [u8; 8],
    /// Authorized governance multisig.
    pub authority: [u8; 32],
    /// Trusted AMD Root Key (ARK) uncompressed P-384 public key.
    pub ark_pubkey_xy: [u8; 96],
    /// Minimum TCB components: [bootloader, tee, snp, microcode].
    pub min_tcb_boot_loader: u8,
    pub min_tcb_tee: u8,
    pub min_tcb_snp: u8,
    pub min_tcb_microcode: u8,
    /// Legacy measurement count (max 8), retained for account ABI compatibility.
    pub measurement_count: u32,
    /// Legacy measurements; ignored by runtime admission.
    pub measurements: [[u8; 48]; 8],
    /// Bump seed.
    pub bump: u8,
}

impl PolicyRegistry {
    pub const SIZE: usize = 8 + 32 + 96 + 4 + 4 + (48 * 8) + 1; // 529 bytes
    pub const MIN_TCB_OFFSET: usize = 0x88;
    pub const MEASUREMENT_COUNT_OFFSET: usize = 0x8C;
    pub const MEASUREMENTS_OFFSET: usize = 0x90;
    pub const BUMP_OFFSET: usize = 0x210;

    /// Queries legacy storage only; does not express runtime admission policy.
    /// Use `BackendPolicy::is_measurement_allowed` for authoritative measurements.
    pub fn is_measurement_allowed(&self, measurement: &[u8; 48]) -> bool {
        if measurement.iter().all(|&b| b == 0) {
            return false;
        }
        let count = self.measurement_count.min(8) as usize;
        for i in 0..count {
            if &self.measurements[i] == measurement {
                return true;
            }
        }
        false
    }
}

/// Zero-copy view over a serialized `PolicyRegistry`.
/// @spec SCC-ARCH-002
pub struct PolicyRegistryView<'a> {
    data: &'a [u8],
}

impl<'a> PolicyRegistryView<'a> {
    pub fn try_from_slice(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < PolicyRegistry::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0..8] != POLICY_REGISTRY_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self { data })
    }

    #[inline]
    pub fn min_tcb_boot_loader(&self) -> u8 {
        self.data[PolicyRegistry::MIN_TCB_OFFSET]
    }

    #[inline]
    pub fn min_tcb_tee(&self) -> u8 {
        self.data[PolicyRegistry::MIN_TCB_OFFSET + 1]
    }

    #[inline]
    pub fn min_tcb_snp(&self) -> u8 {
        self.data[PolicyRegistry::MIN_TCB_OFFSET + 2]
    }

    #[inline]
    pub fn min_tcb_microcode(&self) -> u8 {
        self.data[PolicyRegistry::MIN_TCB_OFFSET + 3]
    }

    #[inline]
    pub fn bump(&self) -> u8 {
        self.data[PolicyRegistry::BUMP_OFFSET]
    }

    /// Queries legacy storage only; does not express runtime admission policy.
    /// Use `BackendPolicy::is_measurement_allowed` for authoritative measurements.
    pub fn is_measurement_allowed(&self, measurement: &[u8; 48]) -> bool {
        if measurement.iter().all(|&b| b == 0) {
            return false;
        }
        let Ok(count_bytes) = array_at::<4>(self.data, PolicyRegistry::MEASUREMENT_COUNT_OFFSET) else {
            return false;
        };
        let count = u32::from_le_bytes(*count_bytes).min(8) as usize;
        let Some(stored) = self.data.get(PolicyRegistry::MEASUREMENTS_OFFSET..) else {
            return false;
        };
        stored.as_chunks::<48>().0.iter().take(count).any(|stored| stored == measurement)
    }
}

/// On-chain tombstone PDA preventing in-window replay attacks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UsedNonceAccount {
    /// 8-byte Anchor discriminator.
    pub discriminator: [u8; 8],
    /// Slot at which the nonce was consumed.
    pub slot: u64,
    /// Bump seed.
    pub bump: u8,
    /// Actual signing payer; only this account receives reclaimed rent.
    pub refund_pubkey: [u8; 32],
}

impl UsedNonceAccount {
    pub fn with_refund(mut self, refund_pubkey: [u8; 32]) -> Self {
        self.refund_pubkey = refund_pubkey;
        self
    }

    /// All attestation paths pin a slot hash no older than 150 slots.
    /// Consumption cannot precede that hash, so age>150 is conservative.
    pub fn is_reclaimable_at_slot(&self, slot: u64) -> bool {
        slot.checked_sub(self.slot).is_some_and(|age| age > 150)
    }

    pub const SIZE: usize = 8 + 8 + 1 + 32; // 49 bytes

    pub fn new(slot: u64, bump: u8) -> Self {
        Self { discriminator: USED_NONCE_DISCRIMINATOR, slot, bump, refund_pubkey: [0; 32] }
    }
}

/// 8-byte Anchor discriminator for JwksAccount:
/// sha256("account:JwksAccount")[..8]
/// @spec SCC-JWT-006
pub const JWKS_ACCOUNT_DISCRIMINATOR: [u8; 8] = [114, 88, 154, 233, 110, 192, 177, 24];

/// On-chain PDA holding a registered Google JWKS RSA-2048 public key.
/// Derived from `[b"jwks", sha256(kid)]`.
/// @spec SCC-JWT-006
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct JwksAccount {
    /// 8-byte Anchor discriminator.
    pub discriminator: [u8; 8],
    /// SHA-256 of the JWT `kid` string.
    pub kid_hash: [u8; 32],
    /// RSA-2048 modulus (big-endian).
    pub modulus: [u8; 256],
    /// RSA public exponent (must be 65537).
    pub exponent: u32,
    /// Montgomery `$n_0 = -n^{-1} \bmod 2^{64}$`.
    pub n0: u64,
    /// Montgomery `$R^2 \bmod n$` (big-endian, 256 bytes).
    pub r2: [u8; 256],
    /// Slot at which this key was registered.
    pub registered_slot: u64,
    /// Governance revocation flag.
    pub is_revoked: bool,
    /// Bump seed.
    pub bump: u8,
}

impl JwksAccount {
    /// Protocol freshness bound in slots, not a wall-clock or Google rotation guarantee.
    /// Governance must explicitly reauthorize a nonrevoked expired key.
    pub const MAX_AGE_SLOTS: u64 = 216_000;

    pub fn is_fresh_at_slot(&self, slot: u64) -> bool {
        !self.is_revoked && slot.checked_sub(self.registered_slot).is_some_and(|age| age <= Self::MAX_AGE_SLOTS)
    }

    pub const SIZE: usize = 8 + 32 + 256 + 4 + 8 + 256 + 8 + 1 + 1; // 574 bytes

    pub fn new(
        kid_hash: [u8; 32],
        modulus: [u8; 256],
        exponent: u32,
        n0: u64,
        r2: [u8; 256],
        registered_slot: u64,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: JWKS_ACCOUNT_DISCRIMINATOR,
            kid_hash,
            modulus,
            exponent,
            n0,
            r2,
            registered_slot,
            is_revoked: false,
            bump,
        }
    }
}

/// Governance-selected exact GCP tenant. Fixed-width encoding permits bounded
/// updates without reallocating or accepting Borsh trailing padding.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GcpTenantPolicy {
    pub discriminator: [u8; 8],
    pub audience_len: u8,
    pub audience: [u8; 128],
    pub subject_len: u8,
    pub subject: [u8; 160],
    pub bump: u8,
}
impl GcpTenantPolicy {
    pub const SIZE: usize = 8 + 1 + 128 + 1 + 160 + 1;
    pub const DISCRIMINATOR: [u8; 8] = [113, 78, 217, 33, 13, 63, 114, 151];
    pub const SEED: &'static [u8] = b"gcp_tenant_policy";
    pub fn new(audience: &[u8], subject: &[u8], bump: u8) -> Result<Self, ProgramError> {
        if audience.is_empty()
            || audience.len() > 128
            || subject.is_empty()
            || subject.len() > 160
            || audience.contains(&0)
            || subject.contains(&0)
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut value = Self {
            discriminator: Self::DISCRIMINATOR,
            audience_len: audience.len() as u8,
            audience: [0; 128],
            subject_len: subject.len() as u8,
            subject: [0; 160],
            bump,
        };
        value.audience[..audience.len()].copy_from_slice(audience);
        value.subject[..subject.len()].copy_from_slice(subject);
        Ok(value)
    }
    pub fn expected(&self) -> Result<(&[u8], &[u8]), ProgramError> {
        let aud = self.audience.get(..usize::from(self.audience_len)).filter(|s| !s.is_empty());
        let sub = self.subject.get(..usize::from(self.subject_len)).filter(|s| !s.is_empty());
        match (aud, sub) {
            (Some(a), Some(s)) if self.discriminator == Self::DISCRIMINATOR => Ok((a, s)),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[cfg(test)]
mod view_reads {
    use super::*;

    /// The view getters used to slice and unwrap. They now read through
    /// `array_at`, which fails closed on short data.
    #[test]
    fn array_at_rejects_short_data_rather_than_panicking() {
        let data = [1u8, 2, 3, 4, 5];
        assert_eq!(array_at::<4>(&data, 1), Ok(&[2, 3, 4, 5]));
        assert_eq!(array_at::<4>(&data, 2), Err(ProgramError::InvalidAccountData));
        assert_eq!(array_at::<1>(&data, usize::MAX), Err(ProgramError::InvalidAccountData));
    }

    #[test]
    fn vcek_view_reads_the_serialized_key_and_deadline() {
        let mut xy = [0u8; 96];
        xy.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let account = VcekAccount::new([9; 32], 7, xy, 11, 254).with_validity(1_700_000_000);
        let bytes = borsh::to_vec(&account).unwrap();
        let view = VcekAccountView::try_from_slice(&bytes).unwrap();
        assert_eq!(view.public_key_xy(), Ok(&xy));
        assert_eq!(view.valid_until_unix(), Ok(1_700_000_000));
        assert_eq!(view.bump(), 254);
        assert!(view.is_trusted_at_unix(1_699_999_999));
        assert!(!view.is_trusted_at_unix(1_700_000_000));
        assert!(!view.is_trusted_at_unix(-1));
    }

    #[test]
    fn legacy_measurement_lookup_reads_only_the_counted_entries() {
        let mut data = vec![0u8; PolicyRegistry::SIZE];
        data[..8].copy_from_slice(&POLICY_REGISTRY_DISCRIMINATOR);
        let stored = &mut data[PolicyRegistry::MEASUREMENTS_OFFSET..PolicyRegistry::MEASUREMENTS_OFFSET + 8 * 48];
        for (i, entry) in stored.as_chunks_mut::<48>().0.iter_mut().enumerate() {
            entry.fill(i as u8 + 1);
        }
        let count_at = PolicyRegistry::MEASUREMENT_COUNT_OFFSET;
        data[count_at..count_at + 4].copy_from_slice(&3u32.to_le_bytes());
        let view = PolicyRegistryView::try_from_slice(&data).unwrap();
        assert!(view.is_measurement_allowed(&[1; 48]));
        assert!(view.is_measurement_allowed(&[3; 48]));
        assert!(!view.is_measurement_allowed(&[4; 48]), "entry 4 is past the count");
        assert!(!view.is_measurement_allowed(&[0; 48]));

        // A count above eight reads at most the eight stored entries.
        data[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let view = PolicyRegistryView::try_from_slice(&data).unwrap();
        assert!(view.is_measurement_allowed(&[8; 48]));
        assert!(!view.is_measurement_allowed(&[9; 48]));
    }
}

#[cfg(test)]
mod issue_185 {
    use super::*;
    #[test]
    fn nonce_cleanup_boundaries_do_not_wrap_or_reopen_live_windows() {
        let n = UsedNonceAccount::new(500, 1);
        assert!(!n.is_reclaimable_at_slot(499));
        assert!(!n.is_reclaimable_at_slot(650));
        assert!(n.is_reclaimable_at_slot(651));
        assert!(!UsedNonceAccount::new(u64::MAX, 1).is_reclaimable_at_slot(u64::MAX));
        assert!(!UsedNonceAccount::new(u64::MAX - 149, 1).is_reclaimable_at_slot(u64::MAX));
    }
}

/// Authoritative measurement allowlist for one backend.
/// Sources: AMD=1, Nitro=2, GCP=3, NVIDIA=4, Intel TDX=5.
/// An empty list rejects new admission for that backend, independently of the
/// legacy global list. Existing Mode A signer records require separate revocation.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BackendPolicy {
    pub discriminator: [u8; 8],
    pub source: u8,
    pub measurement_count: u32,
    pub measurements: [[u8; 48]; 8],
    pub bump: u8,
}
impl BackendPolicy {
    pub const SIZE: usize = 8 + 1 + 4 + 48 * 8 + 1;
    pub const SEED: &'static [u8] = b"backend_policy";
    pub const DISCRIMINATOR: [u8; 8] = [99, 240, 210, 185, 15, 133, 69, 24];
    /// Source 5 compares the 48-byte measurement with the stored allowlist.
    /// @spec SCC-TDX-001
    pub fn is_measurement_allowed(&self, source: u8, measurement: &[u8; 48]) -> bool {
        self.discriminator == Self::DISCRIMINATOR
            && (1..=5).contains(&source)
            && self.source == source
            && self.measurement_count <= 8
            && *measurement != [0; 48]
            && self.measurements[..self.measurement_count.min(8) as usize].contains(measurement)
    }
}

/// Freshness record for an Intel TDX quote.
///
/// PDA seeds are `[b"challenge", &[5], nonce]`.
/// The record stays live while `slot <= expires_slot`.
/// @spec SCC-TDX-005
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChallengeAccount {
    pub discriminator: [u8; 8],
    pub source: u8,
    pub challenge_slot: u64,
    pub slot_hash: [u8; 32],
    pub nonce: [u8; 32],
    pub expires_slot: u64,
    pub bump: u8,
}

impl ChallengeAccount {
    pub const SEED: &'static [u8] = b"challenge";
    /// sha256("account:ChallengeAccount")[..8]
    pub const DISCRIMINATOR: [u8; 8] = [96, 128, 44, 165, 71, 172, 60, 12];
    pub const SIZE: usize = 8 + 1 + 8 + 32 + 32 + 8 + 1;
    /// Lifetime of a challenge, in slots. `expires_slot = clock.slot + TTL_SLOTS`.
    pub const TTL_SLOTS: u64 = 1_500;

    /// Return true while `slot` is still inside the inclusive expiry bound.
    ///
    /// A consumed challenge is never live, whatever the slot.
    pub fn is_live_at(&self, slot: u64) -> bool {
        !self.is_consumed() && slot <= self.expires_slot
    }

    /// Permanent tombstone, written when a quote is accepted against it.
    ///
    /// The nonce tombstone alone is not enough. `UsedNonceAccount` may be
    /// reclaimed 150 slots after consumption, while a challenge lives for
    /// 1,500. In that gap the same signed quote could be submitted again:
    /// replaying the public QE report refreshes the session, the nonce PDA is
    /// empty once more, and the challenge is still inside its window. Marking
    /// the challenge itself closes the window at its source, so the cleanup
    /// rule for nonces does not have to know about TDX.
    ///
    /// `expires_slot == 0` is the sentinel, matching
    /// [`AttestedSignerAccount::is_revoked`]. A live challenge always has a
    /// positive expiry because it is `clock.slot + TTL_SLOTS`.
    pub fn is_consumed(&self) -> bool {
        self.expires_slot == 0
    }
}

/// Permanent denylist for the authenticated AMD credential identity, across TCBs.
/// For VCEK this is hash(chip ID); for VLEK it is hash(endorsement XY), not a chip.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AmdIdentityRevocation {
    pub discriminator: [u8; 8],
    pub identity: [u8; 32],
    pub bump: u8,
}
impl AmdIdentityRevocation {
    pub const SEED: &'static [u8] = b"amd_revocation";
    pub const DISCRIMINATOR: [u8; 8] = [141, 22, 195, 50, 29, 169, 176, 109];
    pub const SIZE: usize = 41;
}

/// Result of the first half of Intel TDX verification.
///
/// Checking a TDX quote needs two signatures -- the QE report, signed by the
/// platform's PCK key, and the quote body, signed by the attestation key the
/// QE certified. Each must be verified by the secp256r1 precompile, which
/// requires its message inline, and 497 + 745 bytes exceeds a 1,232-byte
/// transaction. So the work is split, and this account is what carries the
/// first half's conclusion to the second.
///
/// It records exactly one fact: *this attestation key was certified by a QE
/// whose report an allowlisted PCK key signed.* The second instruction may
/// then trust a quote body signed by that key, and nothing else.
///
/// @spec SCC-TDX-001 SCC-TDX-002
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TdxSessionAccount {
    pub discriminator: [u8; 8],
    /// The attestation key the QE certified, SEC1-compressed.
    pub attestation_pubkey: [u8; 33],
    /// SHA-256 of the QE report this conclusion came from. Pinning it means a
    /// session cannot be silently reused against a different report.
    pub qe_report_digest: [u8; 32],
    /// GPU RIM digest the enclave bound into REPORTDATA.
    ///
    /// Carried here rather than in the second instruction because that
    /// transaction has no room: with the 745-byte precompile instruction it
    /// is already at the packet limit. The QE step has 190 bytes spare, and
    /// the RIM is part of what this step certifies anyway.
    pub gpu_rim_digest: [u8; 32],
    /// Model digest the enclave bound into REPORTDATA.
    pub model_digest: [u8; 32],
    /// Slot the first half ran in.
    pub slot: u64,
    pub bump: u8,
}

impl TdxSessionAccount {
    pub const SEED: &'static [u8] = b"tdx_session";
    /// sha256("account:TdxSessionAccount")[..8]
    pub const DISCRIMINATOR: [u8; 8] = [230, 103, 152, 156, 163, 23, 153, 174];
    pub const SIZE: usize = 8 + 33 + 32 + 32 + 32 + 8 + 1;

    /// Slots a session stays usable.
    ///
    /// The two halves are meant to be submitted back to back, so this is
    /// deliberately short. It matches the 150-slot window every other
    /// freshness check in this program uses, and bounds how long a
    /// half-finished verification can sit around waiting to be completed
    /// against a quote body chosen later.
    pub const TTL_SLOTS: u64 = 150;

    pub fn is_live_at(&self, slot: u64) -> bool {
        slot.checked_sub(self.slot).is_some_and(|age| age <= Self::TTL_SLOTS)
    }
}

impl TdxSessionAccount {
    /// PDA seed for a compressed attestation key.
    ///
    /// A seed is capped at 32 bytes and a compressed P-256 point is 33, so
    /// the key is hashed rather than used directly. Hashing the whole point
    /// rather than dropping the parity byte keeps the two possible points
    /// sharing an X coordinate in separate sessions.
    pub fn seed_for(attestation_pubkey: &[u8; 33]) -> [u8; 32] {
        solana_program::hash::hashv(&[attestation_pubkey]).to_bytes()
    }
}
