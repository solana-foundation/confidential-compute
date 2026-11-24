//! Linux AMD SEV-SNP `/dev/sev-guest` ioctl interface.
//!
//! @spec SCC-CLI-001

use crate::mock;
use crate::CliError;
use solana_confidential_compute_core::SNP_REPORT_SIZE;

/// `SNP_GET_REPORT` ioctl: `_IOWR('S', 0x00, 32-byte snp_guest_request_ioctl)`.
///
/// Upstream value is `0xC020_5300` (`include/uapi/linux/sev-guest.h`).
/// @spec SCC-CLI-001
pub const SNP_GET_REPORT: u64 = 0xC020_5300;

/// Default SEV-SNP guest device path.
pub const DEFAULT_SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

/// Guest request payload injected into `REPORT_DATA`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpReportReq {
    pub user_data: [u8; 64],
    pub vmpl: u32,
    pub key_sel: u8,
    pub reserved: [u8; 27],
}

/// Guest response object for `SNP_GET_REPORT`.
///
/// Upstream `struct snp_report_resp` is `data[4000]`. The guest driver copies
/// 4,000 bytes into `data` and does not write the 32-byte `reserved` tail.
/// That tail makes this object 4,032 bytes, which is the size required by
/// @spec SCC-CLI-001. The copied payload is either a raw AMD report or a
/// 32-byte PSP header (`status`, `report_size`, reserved) followed by the report.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpReportResp {
    pub data: [u8; solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN],
    pub reserved: [u8; solana_confidential_compute_cli::SNP_GUEST_RESP_TAIL_LEN],
}

/// Kernel ioctl argument for `SNP_GET_REPORT` (`_IOWR('S', 0x00, 32)`).
///
/// Layout matches upstream `struct snp_guest_request_ioctl`.
/// @spec SCC-CLI-001
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnpGuestRequestIoctl {
    pub msg_version: u8,
    pub _pad: [u8; 7],
    pub req_data: u64,
    pub resp_data: u64,
    pub exitinfo2: u64,
}

/// Rejects a guest response whose `report_size` is not exactly [`SNP_REPORT_SIZE`]
/// or whose `data[0x50..0x90]` does not echo `user_data`.
///
/// @spec SCC-CLI-001
pub fn accept_hardware_report(
    report_size: u32,
    data: &[u8; SNP_REPORT_SIZE],
    user_data: &[u8; 64],
    device: &str,
) -> Result<[u8; SNP_REPORT_SIZE], CliError> {
    solana_confidential_compute_cli::validate_hardware_report(report_size, data, user_data)
        .map_err(|err| CliError::HardwareUnavailable(format!("{err} on {device}")))
}

/// Copies the 1,184-byte report from `resp.data` and accepts it when `REPORT_DATA` echoes.
///
/// A PSP success prefix (`status == 0`, `report_size == 1184`) shifts the report
/// to offset 32. A raw report is taken from offset 0.
///
/// @spec SCC-CLI-001
pub fn report_from_guest_response(
    resp: &SnpReportResp,
    user_data: &[u8; 64],
    device: &str,
) -> Result<[u8; SNP_REPORT_SIZE], CliError> {
    let report = solana_confidential_compute_cli::copy_guest_report_prefix(&resp.data);
    accept_hardware_report(SNP_REPORT_SIZE as u32, &report, user_data, device)
}

/// Fetches a 1,184-byte AMD SEV-SNP report from hardware or the mock generator.
///
/// @spec SCC-CLI-001
pub fn fetch_snp_report(
    user_data: &[u8; 64],
    mock: bool,
    device: Option<&str>,
) -> Result<[u8; SNP_REPORT_SIZE], CliError> {
    if mock {
        return Ok(mock::generate_mock_report(user_data));
    }
    fetch_hardware_report(user_data, device.unwrap_or(DEFAULT_SEV_GUEST_DEVICE))
}

#[cfg(target_os = "linux")]
fn fetch_hardware_report(
    user_data: &[u8; 64],
    device: &str,
) -> Result<[u8; SNP_REPORT_SIZE], CliError> {
    use std::fs::OpenOptions;
    use std::io;
    use std::os::unix::io::AsRawFd;

    extern "C" {
        fn ioctl(fd: i32, request: u64, argp: *mut SnpGuestRequestIoctl) -> i32;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .map_err(|err| CliError::HardwareUnavailable(format!("failed to open {device}: {err}")))?;

    let mut req = SnpReportReq {
        user_data: *user_data,
        vmpl: 0,
        key_sel: 0,
        reserved: [0; 27],
    };
    let mut resp = SnpReportResp {
        data: [0u8; solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN],
        reserved: [0u8; solana_confidential_compute_cli::SNP_GUEST_RESP_TAIL_LEN],
    };
    let mut ioctl_arg = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0; 7],
        req_data: std::ptr::from_mut(&mut req) as u64,
        resp_data: std::ptr::from_mut(&mut resp) as u64,
        exitinfo2: 0,
    };

    // SAFETY: `file` is an open SEV-guest fd. `req` and `resp` live on this stack
    // frame for the whole syscall. Pointers stored in `ioctl_arg` remain valid.
    // `resp` is 4,032 bytes. The driver copies 4,000 bytes into `resp.data`.
    // Those bytes may start with a 32-byte PSP report header.
    let rc = unsafe { ioctl(file.as_raw_fd(), SNP_GET_REPORT, &mut ioctl_arg) };
    if rc < 0 {
        return Err(CliError::HardwareUnavailable(format!(
            "SNP_GET_REPORT ioctl failed on {device}: {} (exitinfo2={:#x})",
            io::Error::last_os_error(),
            ioctl_arg.exitinfo2
        )));
    }
    report_from_guest_response(&resp, user_data, device)
}

#[cfg(not(target_os = "linux"))]
fn fetch_hardware_report(
    _user_data: &[u8; 64],
    device: &str,
) -> Result<[u8; SNP_REPORT_SIZE], CliError> {
    Err(CliError::HardwareUnavailable(format!(
        "SEV-SNP device {device} is not available on this platform; pass --mock"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_struct_sizes() {
        assert_eq!(std::mem::size_of::<SnpReportReq>(), 96);
        assert_eq!(std::mem::size_of::<SnpGuestRequestIoctl>(), 32);
        assert_eq!(
            std::mem::size_of::<SnpReportResp>(),
            solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN
                + solana_confidential_compute_cli::SNP_GUEST_RESP_TAIL_LEN
        );
        assert_eq!(std::mem::size_of::<SnpReportResp>(), 4_032);
        assert_eq!(SNP_GET_REPORT, 0xC020_5300);

        let resp = SnpReportResp {
            data: [0u8; solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN],
            reserved: [0u8; solana_confidential_compute_cli::SNP_GUEST_RESP_TAIL_LEN],
        };
        let base = std::ptr::from_ref(&resp) as usize;
        let data = resp.data.as_ptr() as usize;
        assert_eq!(
            data, base,
            "snp_report_resp.data must start at byte 0; a PSP prefix sits inside that buffer"
        );
    }

    #[test]
    fn test_guest_response_slices_1184_and_checks_echo() {
        let user_data = [0x11u8; 64];
        let mut resp = SnpReportResp {
            data: [0u8; solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN],
            reserved: [0xA5u8; solana_confidential_compute_cli::SNP_GUEST_RESP_TAIL_LEN],
        };
        resp.data[0x50..0x90].copy_from_slice(&user_data);
        resp.data[SNP_REPORT_SIZE] = 0xFF;
        resp.data[solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN - 1] = 0xFF;

        let report =
            report_from_guest_response(&resp, &user_data, "/dev/sev-guest").expect("prefix echo");
        assert_eq!(report.len(), SNP_REPORT_SIZE);
        assert_eq!(&report[0x50..0x90], &user_data);
        assert_eq!(report[SNP_REPORT_SIZE - 1], 0);

        resp.data[0x70] ^= 0xFF;
        let echo = report_from_guest_response(&resp, &user_data, "/dev/sev-guest")
            .expect_err("REPORT_DATA mismatch");
        match echo {
            CliError::HardwareUnavailable(msg) => assert!(msg.contains("REPORT_DATA"), "{msg}"),
            other => panic!("expected HardwareUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn test_milan_fixture_psp_prefix_round_trip() {
        let raw: [u8; SNP_REPORT_SIZE] =
            *include_bytes!("../../../fixtures/snp_hardware_report_milan.bin");
        let mut user_data = [0u8; 64];
        user_data.copy_from_slice(&raw[0x50..0x90]);

        let mut resp = SnpReportResp {
            data: [0u8; solana_confidential_compute_cli::SNP_GUEST_RESP_DATA_LEN],
            reserved: [0xA5u8; solana_confidential_compute_cli::SNP_GUEST_RESP_TAIL_LEN],
        };
        resp.data[4..8].copy_from_slice(&(SNP_REPORT_SIZE as u32).to_le_bytes());
        resp.data[20] = 0x5A;
        let start = solana_confidential_compute_cli::SNP_PSP_REPORT_PREFIX_LEN;
        resp.data[start..start + SNP_REPORT_SIZE].copy_from_slice(&raw);

        let report = report_from_guest_response(&resp, &user_data, "/dev/sev-guest")
            .expect("psp-prefixed Milan report");
        assert_eq!(report, raw);
        assert_ne!(report[0], 0, "version byte must survive the prefix skip");
    }

    #[test]
    fn test_fetch_snp_report_mock_path() {
        let user_data = [0x11u8; 64];
        let report = fetch_snp_report(&user_data, true, None).expect("mock report");
        assert_eq!(report.len(), SNP_REPORT_SIZE);
        assert_eq!(&report[0x50..0x90], &user_data);
    }

    #[test]
    fn test_accept_hardware_report_rejects_zero_size_and_bad_echo() {
        let user_data = [0x11u8; 64];
        let mut data = [0u8; SNP_REPORT_SIZE];
        data[0x50..0x90].copy_from_slice(&user_data);

        let zero = accept_hardware_report(0, &data, &user_data, "/dev/sev-guest")
            .expect_err("zero report_size");
        match zero {
            CliError::HardwareUnavailable(msg) => {
                assert!(msg.contains("size 0"), "{msg}");
                assert!(msg.contains("/dev/sev-guest"), "{msg}");
            }
            other => panic!("expected HardwareUnavailable, got {other:?}"),
        }

        data[0x70] ^= 0xFF;
        let echo =
            accept_hardware_report(SNP_REPORT_SIZE as u32, &data, &user_data, "/dev/sev-guest")
                .expect_err("REPORT_DATA mismatch");
        match echo {
            CliError::HardwareUnavailable(msg) => assert!(msg.contains("REPORT_DATA"), "{msg}"),
            other => panic!("expected HardwareUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn test_hardware_path_errors_without_device() {
        let err = fetch_snp_report(&[0u8; 64], false, Some("/dev/sev-guest-missing"))
            .expect_err("hardware path must fail without a device");
        match err {
            CliError::HardwareUnavailable(msg) => assert!(!msg.is_empty()),
            other => panic!("expected HardwareUnavailable, got {other:?}"),
        }
    }
}
