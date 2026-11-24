//! AMD SEV-SNP hardware attestation provider using `/dev/sev-guest` ioctl.
//!
//! @spec SCC-SIDECAR-002

use solana_confidential_compute_core::types::EnclaveType;
#[cfg(any(test, target_os = "linux"))]
use solana_confidential_compute_core::SNP_REPORT_SIZE;
use solana_sdk::pubkey::Pubkey;
use std::future::Future;
use std::pin::Pin;

/// Upstream `struct snp_report_resp` payload. The AMD report is `data[0..1184]`.
#[cfg(any(test, target_os = "linux"))]
const SNP_GUEST_RESP_DATA_LEN: usize = 4_000;
/// Trailing bytes so the response object is 4,032. The kernel writes 4,000 bytes.
#[cfg(any(test, target_os = "linux"))]
const SNP_GUEST_RESP_TAIL_LEN: usize = 32;

/// Guest response. `data` is at offset 0 so the kernel copy is the report prefix.
/// @spec SCC-SIDECAR-002
#[cfg(any(test, target_os = "linux"))]
#[repr(C)]
struct SnpReportResp {
    data: [u8; SNP_GUEST_RESP_DATA_LEN],
    reserved: [u8; SNP_GUEST_RESP_TAIL_LEN],
}

/// PSP `MSG_REPORT_RSP` header firmware may write at the front of `data`.
///
/// Status `u32` = 0, report size `u32` = 1184, then 24 reserved bytes.
/// This is not the 32-byte tail on `snp_report_resp`.
/// @spec SCC-SIDECAR-002
#[cfg(any(test, target_os = "linux"))]
const SNP_PSP_REPORT_PREFIX_LEN: usize = 32;

/// `_IOWR('S', 0, 32)` argument. The pad keeps `req_data` 8-byte aligned.
/// @spec SCC-SIDECAR-002
#[cfg(any(test, target_os = "linux"))]
#[repr(C)]
struct SnpGuestRequest {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// Copies the 1,184-byte AMD report out of the 4,000-byte guest response.
///
/// When `data[0..4]` is zero and `data[4..8]` is little-endian 1184, firmware
/// prepended a PSP header and the report is `data[32..32+1184]`. Every other
/// buffer, including AMD report versions `1..=5`, is copied from offset 0.
/// Same rule as `solana_confidential_compute_cli::copy_guest_report_prefix`.
/// @spec SCC-SIDECAR-002
#[cfg(any(test, target_os = "linux"))]
fn attestation_report_prefix(resp: &SnpReportResp) -> [u8; SNP_REPORT_SIZE] {
    let mut report = [0u8; SNP_REPORT_SIZE];
    let offset = if has_psp_report_prefix(&resp.data) { SNP_PSP_REPORT_PREFIX_LEN } else { 0 };
    let Some(end) = offset.checked_add(SNP_REPORT_SIZE) else {
        return report;
    };
    let Some(src) = resp.data.get(offset..end) else {
        return report;
    };
    report.copy_from_slice(src);
    report
}

/// PSP success header: status `0` and report size [`SNP_REPORT_SIZE`] at bytes 4..8.
#[cfg(any(test, target_os = "linux"))]
fn has_psp_report_prefix(data: &[u8; SNP_GUEST_RESP_DATA_LEN]) -> bool {
    let status_ok = data.get(..4).is_some_and(|status| status == [0, 0, 0, 0]);
    let size_ok = data
        .get(4..8)
        .is_some_and(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == SNP_REPORT_SIZE as u32);
    let prefixed_end = SNP_PSP_REPORT_PREFIX_LEN.checked_add(SNP_REPORT_SIZE);
    status_ok && size_ok && prefixed_end.is_some_and(|end| end <= data.len())
}

use super::{AttestationProvider, AttestationReport};
use crate::error::SidecarError;

pub struct SevSnpProvider {
    device_path: String,
}

impl SevSnpProvider {
    pub fn new(device_path: Option<&str>) -> Self {
        Self { device_path: device_path.unwrap_or("/dev/sev-guest").to_string() }
    }
}

impl Default for SevSnpProvider {
    fn default() -> Self {
        Self::new(None)
    }
}

impl AttestationProvider for SevSnpProvider {
    fn enclave_type(&self) -> EnclaveType {
        EnclaveType::AmdSevSnp
    }

    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        Box::pin(async move {
            let mut user_data = [0u8; 64];
            user_data[0..32].copy_from_slice(workload_signer.as_ref());
            user_data[32..64].copy_from_slice(slot_hash);

            #[cfg(target_os = "linux")]
            {
                use std::fs::OpenOptions;
                use std::os::unix::io::AsRawFd;

                let file = OpenOptions::new().read(true).write(true).open(&self.device_path).map_err(|e| {
                    SidecarError::IoctlError(format!("Failed to open SEV guest device {}: {}", self.device_path, e))
                })?;

                #[repr(C)]
                struct SnpReportReq {
                    user_data: [u8; 64],
                    vmpl: u32,
                    rsvd: [u8; 28],
                }

                let req = SnpReportReq { user_data, vmpl: 0, rsvd: [0u8; 28] };
                let mut resp =
                    SnpReportResp { data: [0u8; SNP_GUEST_RESP_DATA_LEN], reserved: [0u8; SNP_GUEST_RESP_TAIL_LEN] };

                let mut guest_req = SnpGuestRequest {
                    msg_version: 1,
                    _pad: [0; 7],
                    req_data: std::ptr::from_ref(&req) as u64,
                    resp_data: std::ptr::from_mut(&mut resp) as u64,
                    exitinfo2: 0,
                };

                const SNP_GET_REPORT_MAGIC: u8 = b'S';
                const SNP_GET_REPORT_NR: u8 = 0x00;
                let ioctl_num =
                    nix_like_iowr(SNP_GET_REPORT_MAGIC, SNP_GET_REPORT_NR, std::mem::size_of::<SnpGuestRequest>());

                // SAFETY: `req`, `resp`, and `guest_req` live on this stack frame
                // for the syscall. The kernel writes 4,000 bytes at `resp_data`,
                // which is `resp.data` at offset 0. The 32-byte tail is not written.
                let ret = unsafe { libc::ioctl(file.as_raw_fd(), ioctl_num, &mut guest_req) };
                if ret != 0 {
                    return Err(SidecarError::IoctlError(format!(
                        "SNP_GET_REPORT ioctl failed (ret={}, exitinfo2={:#x})",
                        ret, guest_req.exitinfo2
                    )));
                }

                let report_bytes = attestation_report_prefix(&resp).to_vec();
                let mut version_bytes = [0u8; 4];
                version_bytes.copy_from_slice(&report_bytes[..4]);
                if u32::from_le_bytes(version_bytes) == 0 {
                    return Err(SidecarError::IoctlError("SEV-SNP report header version is zero".to_string()));
                }
                if report_bytes[0x50..0x90] != user_data {
                    return Err(SidecarError::IoctlError(
                        "SEV-SNP report did not echo the requested user_data".to_string(),
                    ));
                }
                let view = solana_confidential_compute_core::SnpReportView::try_from_slice(&report_bytes)
                    .map_err(|e| SidecarError::IoctlError(format!("Malformed SNP report: {e}")))?;
                view.validate_security_invariants()
                    .map_err(|e| SidecarError::IoctlError(format!("SNP report failed security invariants: {e}")))?;
                Ok(AttestationReport::SevSnp { report: report_bytes, vcek_cert: None })
            }

            #[cfg(not(target_os = "linux"))]
            {
                let _ = user_data;
                Err(SidecarError::IoctlError(format!(
                    "/dev/sev-guest ioctl is only available on Linux (configured path: {})",
                    self.device_path
                )))
            }
        })
    }
}

#[cfg(target_os = "linux")]
#[inline]
fn nix_like_iowr(magic: u8, nr: u8, size: usize) -> libc::c_ulong {
    const IOC_READ: libc::c_ulong = 2;
    const IOC_WRITE: libc::c_ulong = 1;
    let dir = IOC_READ | IOC_WRITE;
    (dir << 30) | ((size as libc::c_ulong & 0x3fff) << 16) | ((magic as libc::c_ulong) << 8) | (nr as libc::c_ulong)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snp_guest_request_is_32_bytes_and_report_starts_at_zero() {
        assert_eq!(std::mem::size_of::<SnpGuestRequest>(), 32);
        assert_eq!(std::mem::size_of::<SnpReportResp>(), SNP_GUEST_RESP_DATA_LEN + SNP_GUEST_RESP_TAIL_LEN);
        assert_eq!(std::mem::size_of::<SnpReportResp>(), 4_032);
        let size = std::mem::size_of::<SnpGuestRequest>() as u64;
        let ioctl = (3u64 << 30) | ((size & 0x3fff) << 16) | ((b'S' as u64) << 8);
        assert_eq!(ioctl, 0xC020_5300);

        let mut resp =
            SnpReportResp { data: [0u8; SNP_GUEST_RESP_DATA_LEN], reserved: [0xA5; SNP_GUEST_RESP_TAIL_LEN] };
        resp.data[..4].copy_from_slice(&2u32.to_le_bytes());
        resp.data[SNP_REPORT_SIZE] = 0xFF;
        let base = std::ptr::from_ref(&resp) as usize;
        assert_eq!(resp.data.as_ptr() as usize, base);
        let report = attestation_report_prefix(&resp);
        assert_eq!(report.len(), SNP_REPORT_SIZE);
        assert_eq!(report[SNP_REPORT_SIZE - 1], 0);
        assert_eq!(&report[..4], &2u32.to_le_bytes());
    }

    #[test]
    fn psp_prefix_report_starts_at_offset_32() {
        let mut resp = SnpReportResp { data: [0u8; SNP_GUEST_RESP_DATA_LEN], reserved: [0u8; SNP_GUEST_RESP_TAIL_LEN] };
        resp.data[4..8].copy_from_slice(&(SNP_REPORT_SIZE as u32).to_le_bytes());
        resp.data[20] = 0xA5;
        let start = SNP_PSP_REPORT_PREFIX_LEN;
        resp.data[start..start + 4].copy_from_slice(&2u32.to_le_bytes());
        resp.data[start + 0x50] = 0x77;
        resp.data[start + SNP_REPORT_SIZE - 1] = 0x3C;

        let report = attestation_report_prefix(&resp);
        assert_eq!(&report[..4], &2u32.to_le_bytes());
        assert_eq!(report[0x50], 0x77);
        assert_eq!(report[SNP_REPORT_SIZE - 1], 0x3C);
        assert_ne!(report[20], 0xA5);
    }

    #[test]
    fn raw_report_versions_are_not_treated_as_psp_prefix() {
        for version in 1u8..=5 {
            let mut resp =
                SnpReportResp { data: [0u8; SNP_GUEST_RESP_DATA_LEN], reserved: [0u8; SNP_GUEST_RESP_TAIL_LEN] };
            resp.data[0] = version;
            resp.data[4..8].copy_from_slice(&1184u32.to_le_bytes());
            resp.data[10] = 0x42;
            let report = attestation_report_prefix(&resp);
            assert_eq!(report[0], version, "version {version} stays at offset 0");
            assert_eq!(report[10], 0x42);
        }
    }

    #[test]
    fn zero_status_with_other_size_stays_a_raw_buffer() {
        let mut resp = SnpReportResp { data: [0u8; SNP_GUEST_RESP_DATA_LEN], reserved: [0u8; SNP_GUEST_RESP_TAIL_LEN] };
        resp.data[4..8].copy_from_slice(&32u32.to_le_bytes());
        resp.data[10] = 0x42;
        let report = attestation_report_prefix(&resp);
        assert_eq!(report[0], 0);
        assert_eq!(report[10], 0x42);
    }
}
