//! Zero-copy AMD SEV-SNP attestation report parser and view.
//! Conforms strictly to AMD Publication #56860 (Rev 3.00).

use crate::error::ConfidentialComputeError;

/// Exact size in bytes of a canonical AMD SEV-SNP attestation report.
pub const SNP_REPORT_SIZE: usize = 1184;

/// Size in bytes of the report body covered by the ECDSA P-384 signature.
pub const SNP_SIGNED_BODY_SIZE: usize = 672;

/// Guest policy bit 16: SMT is allowed (not required).
/// @spec SCC-SEC-001
pub const GUEST_POLICY_SMT: u64 = 1 << 16;

/// Guest policy bit 17: AMD reserved bit that must be 1.
/// @spec SCC-SEC-001
pub const GUEST_POLICY_RESERVED_MUST_BE_ONE: u64 = 1 << 17;

/// Guest policy bit 18: migration agent. Prohibited (must be 0).
/// @spec SCC-SEC-001
pub const GUEST_POLICY_MIGRATE_MA: u64 = 1 << 18;

/// Guest policy bit 19: debug. Prohibited (must be 0).
/// @spec SCC-SEC-001
pub const GUEST_POLICY_DEBUG: u64 = 1 << 19;

/// Borrows the `N`-byte field at `OFFSET` of a report.
///
/// The `const` block stops the build when a field is not inside the report, so
/// the lookup always finds the field.
#[inline]
// Cannot fail: the `const` block proves that `OFFSET + N <= SNP_REPORT_SIZE`.
#[allow(clippy::expect_used)]
fn field<const OFFSET: usize, const N: usize>(raw: &[u8; SNP_REPORT_SIZE]) -> &[u8; N] {
    const { assert!(matches!(OFFSET.checked_add(N), Some(end) if end <= SNP_REPORT_SIZE)) };
    raw.get(OFFSET..).and_then(<[u8]>::first_chunk).expect("field is inside the report")
}

/// Zero-copy, zero-heap view over a raw 1,184-byte AMD SEV-SNP attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnpReportView<'a> {
    raw: &'a [u8; SNP_REPORT_SIZE],
}

impl<'a> SnpReportView<'a> {
    /// Attempts to create an `SnpReportView` from a byte slice, asserting exact 1,184-byte size.
    pub fn try_from_slice(bytes: &'a [u8]) -> Result<Self, ConfidentialComputeError> {
        let raw: &[u8; SNP_REPORT_SIZE] = bytes.try_into().map_err(|_| ConfidentialComputeError::ReportSizeInvalid)?;
        Ok(Self { raw })
    }

    /// Creates an `SnpReportView` directly from a fixed-size array reference.
    pub const fn from_array(raw: &'a [u8; SNP_REPORT_SIZE]) -> Self {
        Self { raw }
    }

    /// Report format version (0x000..0x004).
    #[inline]
    pub fn version(&self) -> u32 {
        u32::from_le_bytes(*field::<0, 4>(self.raw))
    }

    /// Guest Security Version Number (0x004..0x008).
    #[inline]
    pub fn guest_svn(&self) -> u32 {
        u32::from_le_bytes(*field::<4, 4>(self.raw))
    }

    /// Guest policy bitmask (0x008..0x010).
    #[inline]
    pub fn policy(&self) -> u64 {
        u64::from_le_bytes(*field::<8, 8>(self.raw))
    }

    /// Returns true if SMT is allowed (policy bit 16).
    #[inline]
    pub fn is_smt_allowed(&self) -> bool {
        (self.policy() & GUEST_POLICY_SMT) != 0
    }

    /// Returns true if the AMD reserved bit (policy bit 17) is set.
    #[inline]
    pub fn reserved_must_be_one(&self) -> bool {
        (self.policy() & GUEST_POLICY_RESERVED_MUST_BE_ONE) != 0
    }

    /// Returns true if migration agent is enabled (policy bit 18).
    #[inline]
    pub fn is_migrate_ma_enabled(&self) -> bool {
        (self.policy() & GUEST_POLICY_MIGRATE_MA) != 0
    }

    /// Returns true if enclave debug mode (policy bit 19) is enabled.
    #[inline]
    pub fn is_debug_enabled(&self) -> bool {
        (self.policy() & GUEST_POLICY_DEBUG) != 0
    }

    /// Virtual Machine Privilege Level (0x030..0x034).
    #[inline]
    pub fn vmpl(&self) -> u32 {
        u32::from_le_bytes(*field::<0x30, 4>(self.raw))
    }

    /// Signature algorithm identifier (0x034..0x038). Must be 1 (ECDSA P-384 with SHA-384).
    #[inline]
    pub fn signature_algo(&self) -> u32 {
        u32::from_le_bytes(*field::<0x34, 4>(self.raw))
    }

    /// FLAGS word at offset `0x048` (AMD Table 141).
    ///
    /// Bit 0 is `AUTHOR_KEY_EN`, bit 1 is `MASK_CHIP_KEY`, and bits 4:2 are
    /// `SIGNING_KEY` (`0` = VCEK, `1` = VLEK, `7` = none).
    /// @spec SCC-CORE-001 SCC-VERIFY-009
    #[inline]
    pub fn flags(&self) -> u32 {
        u32::from_le_bytes(*field::<0x48, 4>(self.raw))
    }

    /// `SIGNING_KEY` from FLAGS bits 4:2. `0` = VCEK, `1` = VLEK, `7` = none.
    /// @spec SCC-CORE-001 SCC-VERIFY-009
    #[inline]
    pub fn key_sel(&self) -> u32 {
        let flags = self.flags();
        (flags >> 2) & 0b111
    }

    /// Current platform TCB version vector (0x038..0x040).
    #[inline]
    pub fn current_tcb(&self) -> u64 {
        u64::from_le_bytes(*field::<0x38, 8>(self.raw))
    }

    /// Full 64-byte user report data scratchpad (0x050..0x090).
    #[inline]
    pub fn report_data(&self) -> &'a [u8; 64] {
        field::<0x50, 64>(self.raw)
    }

    /// Workload Ed25519 public key bound in report data (0x050..0x070).
    #[inline]
    pub fn pubkey(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.raw[0x50..0x70]);
        key
    }

    /// Solana slot blockhash nonce bound in report data (0x070..0x090).
    #[inline]
    pub fn nonce(&self) -> [u8; 32] {
        *field::<0x70, 32>(self.raw)
    }

    /// 48-byte SHA-384 launch digest / binary measurement (0x090..0x0C0).
    #[inline]
    pub fn measurement(&self) -> [u8; 48] {
        let mut m = [0u8; 48];
        m.copy_from_slice(&self.raw[0x90..0x0C0]);
        m
    }

    /// Host-provided data (0x0C0..0x0E0).
    #[inline]
    pub fn host_data(&self) -> &'a [u8; 32] {
        field::<0x0C0, 32>(self.raw)
    }

    /// Unique 32-byte report identifier (0x140..0x160).
    #[inline]
    pub fn report_id(&self) -> &'a [u8; 32] {
        field::<0x140, 32>(self.raw)
    }

    /// Reported TCB version integer (0x180..0x188).
    #[inline]
    pub fn reported_tcb(&self) -> u64 {
        u64::from_le_bytes(*field::<0x180, 8>(self.raw))
    }

    /// Reported TCB component bytes (0x180..0x188):
    /// [0: boot_loader, 1: tee, 2..5: reserved, 6: snp, 7: microcode].
    #[inline]
    pub fn reported_tcb_components(&self) -> [u8; 8] {
        let mut tcb = [0u8; 8];
        tcb.copy_from_slice(&self.raw[0x180..0x188]);
        tcb
    }

    /// 64-byte physical AMD silicon chip ID (0x1A0..0x1E0).
    #[inline]
    pub fn chip_id(&self) -> &'a [u8; 64] {
        field::<0x1A0, 64>(self.raw)
    }

    /// Returns true if `chip_id` is all zeros (hyperscaler VLEK mode).
    #[inline]
    pub fn is_vlek_zero_chip(&self) -> bool {
        self.chip_id().iter().all(|&b| b == 0)
    }

    /// Returns true when VLEK derivation must be used.
    ///
    /// AMD Table 141 stores the signing key in FLAGS bits 4:2, so a VCEK report
    /// with only `AUTHOR_KEY_EN` set has FLAGS word `1` and is not a VLEK.
    /// A VLEK report has `SIGNING_KEY == 1` (FLAGS word `4` when no other flag
    /// is set). A zero chip id remains a VLEK fallback.
    /// @spec SCC-VERIFY-009 SCC-CORE-001
    #[inline]
    pub fn is_vlek(&self) -> bool {
        let flags = self.flags();
        let signing_key = (flags >> 2) & 0b111;
        signing_key == 1 || *self.chip_id() == [0u8; 64]
    }

    /// The 672-byte body covered by the signature (0x000..0x2A0).
    #[inline]
    pub fn signed_body(&self) -> &'a [u8; SNP_SIGNED_BODY_SIZE] {
        field::<0x000, SNP_SIGNED_BODY_SIZE>(self.raw)
    }

    /// Full 512-byte raw signature block (0x2A0..0x4A0).
    #[inline]
    pub fn signature_raw(&self) -> &'a [u8; 512] {
        field::<0x2A0, 512>(self.raw)
    }

    /// Parses and verifies the 72-byte LE `r` field (0x2A0..0x2E8),
    /// asserting bytes 48..72 are strictly zero and returning the 48-byte Big-Endian scalar.
    ///
    /// @spec SCC-SEC-009
    pub fn signature_r_be(&self) -> Result<[u8; 48], ConfidentialComputeError> {
        let le_field = field::<0x2A0, 72>(self.raw);
        // Assert upper 24 bytes are strictly zero
        if le_field[48..72].iter().any(|&b| b != 0) {
            return Err(ConfidentialComputeError::InvalidSignaturePadding);
        }
        let mut scalar_be = [0u8; 48];
        for (be, le) in scalar_be.iter_mut().zip(le_field[..48].iter().rev()) {
            *be = *le;
        }
        Ok(scalar_be)
    }

    /// Parses and verifies the 72-byte LE `s` field (0x2E8..0x330),
    /// asserting bytes 48..72 are strictly zero and returning the 48-byte Big-Endian scalar.
    ///
    /// @spec SCC-SEC-009
    pub fn signature_s_be(&self) -> Result<[u8; 48], ConfidentialComputeError> {
        let le_field = field::<0x2E8, 72>(self.raw);
        // Assert upper 24 bytes are strictly zero
        if le_field[48..72].iter().any(|&b| b != 0) {
            return Err(ConfidentialComputeError::InvalidSignaturePadding);
        }
        let mut scalar_be = [0u8; 48];
        for (be, le) in scalar_be.iter_mut().zip(le_field[..48].iter().rev()) {
            *be = *le;
        }
        Ok(scalar_be)
    }

    /// Validates core silicon and protocol security invariants:
    /// 1. Report version must be within `1..=5` (@spec SCC-SEC-001).
    /// 2. Signature algorithm must be 1 (P-384 / SHA-384).
    /// 3. Policy bit 19 (DEBUG) must be 0 (@spec SCC-SEC-001).
    /// 4. Policy bit 18 (MIGRATE_MA) must be 0 (@spec SCC-SEC-001).
    /// 5. Policy bit 17 (RESERVED_MUST_BE_ONE) must be 1 (@spec SCC-SEC-001).
    /// 6. VMPL must be 0 (@spec SCC-SEC-001).
    /// 7. Measurement must not be all zeros (@spec SCC-VERIFY-002).
    /// 8. Signature r and s padding must be valid (@spec SCC-SEC-009).
    pub fn validate_security_invariants(&self) -> Result<(), ConfidentialComputeError> {
        if !(1..=5).contains(&self.version()) {
            return Err(ConfidentialComputeError::UnauthorizedPolicy);
        }
        if self.signature_algo() != 1 {
            return Err(ConfidentialComputeError::InvalidSignatureAlgorithm);
        }
        if self.is_debug_enabled() {
            return Err(ConfidentialComputeError::DebugModeProhibited);
        }
        let policy = self.policy();
        if (policy & GUEST_POLICY_MIGRATE_MA) != 0 {
            return Err(ConfidentialComputeError::UnauthorizedPolicy);
        }
        if (policy & GUEST_POLICY_RESERVED_MUST_BE_ONE) == 0 {
            return Err(ConfidentialComputeError::UnauthorizedPolicy);
        }
        if self.vmpl() != 0 {
            return Err(ConfidentialComputeError::UnauthorizedPolicy);
        }
        if self.measurement().iter().all(|&b| b == 0) {
            return Err(ConfidentialComputeError::InvalidMeasurement);
        }
        self.signature_r_be()?;
        self.signature_s_be()?;
        Ok(())
    }
}

/// 64-byte user-controlled report data helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportData {
    pub raw: [u8; 64],
}

impl ReportData {
    pub fn new(pubkey: &[u8; 32], blockhash: &[u8; 32]) -> Self {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(pubkey);
        raw[32..].copy_from_slice(blockhash);
        Self { raw }
    }

    pub fn signer_pubkey(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.raw[..32]);
        key
    }

    pub fn blockhash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&self.raw[32..]);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_guest_policy() -> u64 {
        GUEST_POLICY_RESERVED_MUST_BE_ONE
    }

    fn valid_report() -> [u8; SNP_REPORT_SIZE] {
        let mut dummy = [0u8; SNP_REPORT_SIZE];
        dummy[0..4].copy_from_slice(&1u32.to_le_bytes());
        dummy[8..16].copy_from_slice(&valid_guest_policy().to_le_bytes());
        dummy[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        dummy[0x50..0x70].copy_from_slice(&[7u8; 32]);
        dummy[0x70..0x90].copy_from_slice(&[42u8; 32]);
        dummy[0x90..0xC0].copy_from_slice(&[99u8; 48]);
        dummy[0x1A0..0x1E0].copy_from_slice(&[0xAA; 64]);
        dummy[0x2A0..0x2D0].copy_from_slice(&[1u8; 48]);
        dummy[0x2E8..0x318].copy_from_slice(&[2u8; 48]);
        dummy
    }

    #[test]
    fn test_snp_report_view_offsets_and_padding() {
        let dummy = valid_report();

        let view = SnpReportView::try_from_slice(&dummy).expect("valid slice");
        assert!(SnpReportView::try_from_slice(&dummy[..10]).is_err());
        assert_eq!(view.version(), 1);
        assert!(!view.is_debug_enabled());
        assert!(!view.is_migrate_ma_enabled());
        assert!(view.reserved_must_be_one());
        assert!(!view.is_smt_allowed());
        assert_eq!(view.vmpl(), 0);
        assert_eq!(view.signature_algo(), 1);
        assert_eq!(view.flags(), 0);
        assert_eq!(view.key_sel(), 0);
        assert!(!view.is_vlek());
        assert_eq!(view.pubkey(), [7u8; 32]);
        assert_eq!(view.nonce(), [42u8; 32]);
        assert_eq!(view.measurement(), [99u8; 48]);

        let r_be = view.signature_r_be().expect("valid r padding");
        assert_eq!(r_be, [1u8; 48]);

        assert!(view.validate_security_invariants().is_ok());
    }

    #[test]
    fn test_smt_bit_is_allowed() {
        let mut dummy = valid_report();
        dummy[8..16].copy_from_slice(&(GUEST_POLICY_SMT | GUEST_POLICY_RESERVED_MUST_BE_ONE).to_le_bytes());
        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert!(view.is_smt_allowed());
        assert!(view.validate_security_invariants().is_ok());
    }

    #[test]
    fn test_rejects_debug_mode() {
        let mut dummy = valid_report();
        dummy[8..16].copy_from_slice(&(GUEST_POLICY_RESERVED_MUST_BE_ONE | GUEST_POLICY_DEBUG).to_le_bytes());

        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert!(view.is_debug_enabled());
        assert_eq!(view.validate_security_invariants(), Err(ConfidentialComputeError::DebugModeProhibited));
    }

    #[test]
    fn test_rejects_migrate_ma() {
        let mut dummy = valid_report();
        dummy[8..16].copy_from_slice(&(GUEST_POLICY_RESERVED_MUST_BE_ONE | GUEST_POLICY_MIGRATE_MA).to_le_bytes());
        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert!(view.is_migrate_ma_enabled());
        assert_eq!(view.validate_security_invariants(), Err(ConfidentialComputeError::UnauthorizedPolicy));
    }

    #[test]
    fn test_rejects_missing_reserved_bit() {
        let mut dummy = valid_report();
        dummy[8..16].copy_from_slice(&0u64.to_le_bytes());
        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert!(!view.reserved_must_be_one());
        assert_eq!(view.validate_security_invariants(), Err(ConfidentialComputeError::UnauthorizedPolicy));
    }

    #[test]
    fn test_rejects_nonzero_vmpl() {
        let mut dummy = valid_report();
        dummy[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert_eq!(view.vmpl(), 1);
        assert_eq!(view.validate_security_invariants(), Err(ConfidentialComputeError::UnauthorizedPolicy));
    }

    /// FLAGS word `1` is VCEK with `AUTHOR_KEY_EN`, not VLEK.
    /// @spec SCC-VERIFY-009 SCC-CORE-001
    #[test]
    fn flags_author_key_is_vcek_not_vlek() {
        let mut dummy = valid_report();
        dummy[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert_eq!(view.flags(), 1);
        assert_eq!(view.key_sel(), 0);
        assert!(!view.is_vlek());
    }

    /// FLAGS word `4` is `SIGNING_KEY = 1` (VLEK).
    /// @spec SCC-VERIFY-009 SCC-CORE-001
    #[test]
    fn flags_signing_key_one_is_vlek() {
        let mut dummy = valid_report();
        dummy[0x48..0x4C].copy_from_slice(&4u32.to_le_bytes());
        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert_eq!(view.flags(), 4);
        assert_eq!(view.key_sel(), 1);
        assert!(view.is_vlek());
    }

    #[test]
    fn test_rejects_dirty_signature_padding() {
        let mut dummy = [0u8; SNP_REPORT_SIZE];
        dummy[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        dummy[0x90..0xC0].copy_from_slice(&[1u8; 48]);
        // Put non-zero byte in upper 24 bytes of r
        dummy[0x2D5] = 0xFF;

        let view = SnpReportView::try_from_slice(&dummy).unwrap();
        assert_eq!(view.signature_r_be(), Err(ConfidentialComputeError::InvalidSignaturePadding));
    }
}
