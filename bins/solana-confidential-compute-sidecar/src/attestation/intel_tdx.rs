//! Intel TDX guest attestation provider.
//!
//! Live mode probes three quote sources, in order:
//! 1. Unix socket `/var/run/dstack.sock` (`POST /GetQuote`, then JSON-RPC `tdx_quote`)
//! 2. `/dev/tdx-guest` with `TDX_CMD_GET_REPORT0`
//! 3. `/dev/tdx_guest` with `TDX_CMD_GET_REPORT0`
//!
//! The socket comes first because only it returns a DCAP quote. The ioctl
//! returns a local TDREPORT, which no remote party can verify; each candidate
//! is checked for the v4 quote header before it is accepted.
//!
//! Dry-run returns a synthetic quote and does not open those sources.
//! A simulated provider fails closed when `dry_run` is false.
//! Live mode does not substitute the synthetic quote when every probe misses.
//!
//! The 64-byte `REPORTDATA` is `SHA-512` of the Borsh report-data preimage.
//! That digest is 64 bytes. The preimage commits
//! `SHA-256(signer || slot_challenge || gpu_rim_digest || model_digest)`
//! and the issued challenge nonce, which distinguishes challenges sharing a slot hash.
//!
//! @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 SCC-SIDECAR-002 SCC-SIDECAR-004

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256, Sha512};
use solana_confidential_compute_core::types::EnclaveType;
use solana_sdk::pubkey::Pubkey;

use super::{AttestationProvider, AttestationReport};
use crate::error::SidecarError;

/// Primary guest device. Newer kernels use the hyphenated name.
pub const TDX_GUEST_DEVICE: &str = "/dev/tdx-guest";

/// Secondary guest device. Older kernels use the underscored name.
pub const TDX_GUEST_DEVICE_ALT: &str = "/dev/tdx_guest";

/// dstack guest agent socket.
pub const DSTACK_SOCKET: &str = "/var/run/dstack.sock";

/// `_IOWR('T', 1, struct tdx_report_req)` with a 1,088-byte argument.
pub const TDX_CMD_GET_REPORT0: u32 = 0xC440_5401;

/// Guest `REPORTDATA` length.
pub const TDX_REPORTDATA_LEN: usize = 64;

/// `TDG.MR.REPORT` output length.
pub const TDX_REPORT_LEN: usize = 1024;

/// Borsh domain for the report-data preimage.
/// @spec SCC-TDX-002
pub const REPORT_DATA_DOMAIN: &str = "solana-confidential-compute/v1/report-data";

/// Prefix on a dry-run quote. Live submission rejects this prefix.
pub const SYNTHETIC_TDX_PREFIX: &[u8] = b"INTEL-TDX-SYNTHETIC-v1";

/// Dry-run GPU RIM placeholder. It is not a measured VBIOS or driver digest.
pub const DEFAULT_TDX_GPU_RIM: [u8; 32] = *b"INTEL_TDX_CC_GPU_RIM_PLACEHOLDER";

/// Dry-run model digest placeholder.
pub const DEFAULT_TDX_MODEL_DIGEST: [u8; 32] = *b"INTEL_TDX_MODEL_DIGEST_DRY_RUN!!";

/// Dry-run guest image id placeholder.
///
/// A live guest image id is the identifier of the zkVM program that produced
/// the Groth16 proof, and must be allowlisted on the source-5 backend policy.
/// The dry-run path broadcasts a zero proof, so it carries a placeholder that
/// no policy should ever allow.
pub const DRY_RUN_TDX_GUEST_IMAGE_ID: [u8; 32] = *b"INTEL_TDX_GUEST_IMAGE_DRY_RUN!!!";

const SYNTHETIC_MR_TD: [u8; 48] = [0x11; 48];
const SYNTHETIC_MR_CONFIG_ID: [u8; 48] = [0x22; 48];
const SYNTHETIC_RTMRS: [[u8; 48]; 4] = [[0x31; 48], [0x32; 48], [0x33; 48], [0x34; 48]];

const TDREPORT_REPORTDATA: usize = 128;
const TDREPORT_MR_TD: usize = 528;
const TDREPORT_MR_CONFIG_ID: usize = 576;
const TDREPORT_RTMR0: usize = 720;

const QUOTE_V4_VERSION: u16 = 4;
const QUOTE_TDX_TEE_TYPE: u32 = 0x81;
const QUOTE_MR_TD: usize = 184;
const QUOTE_MR_CONFIG_ID: usize = 232;
const QUOTE_RTMR0: usize = 376;
const QUOTE_REPORTDATA: usize = 568;
const QUOTE_MIN_LEN: usize = 632;

const MAX_DSTACK_RESPONSE: usize = 262_144;

/// `true` when `quote` was built by the dry-run provider.
pub fn synthetic_tdx_evidence(quote: &[u8]) -> bool {
    quote.starts_with(SYNTHETIC_TDX_PREFIX)
}

/// `SHA-256(workload_signer || slot_challenge || gpu_rim_digest || model_digest)`.
///
/// `workload_signer` is the first input so the composite names the key the
/// quote speaks for. Without it the quote attests only to a measurement and a
/// slot, and any party holding a valid quote for that slot can present it
/// alongside a `subject` of their choosing. The sibling NVIDIA provider binds
/// the signer the same way.
///
/// @spec SCC-TDX-002
pub fn composite_challenge(
    workload_signer: &Pubkey,
    slot_challenge: &[u8; 32],
    gpu_rim_digest: &[u8; 32],
    model_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(workload_signer.to_bytes());
    hasher.update(slot_challenge);
    hasher.update(gpu_rim_digest);
    hasher.update(model_digest);
    finalize_32(hasher)
}

/// Borsh image `E("solana-confidential-compute/v1/report-data", signer, composite, slot, gpu, model, nonce)`.
///
/// The signer is named directly as well as through `composite` so that a
/// reader of the hardware-signed bytes does not have to recompute the
/// composite to see which key is bound.
/// The nonce must match the issued on-chain challenge, even when another
/// challenge pins the same slot hash.
///
/// @spec SCC-TDX-002
pub fn report_data_preimage(
    workload_signer: &Pubkey,
    composite: &[u8; 32],
    slot_challenge: &[u8; 32],
    gpu_rim_digest: &[u8; 32],
    model_digest: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> Vec<u8> {
    const _: () = assert!(REPORT_DATA_DOMAIN.len() == 42);
    let mut out = Vec::with_capacity(46 + 192);
    out.extend_from_slice(&42u32.to_le_bytes());
    out.extend_from_slice(REPORT_DATA_DOMAIN.as_bytes());
    out.extend_from_slice(&workload_signer.to_bytes());
    out.extend_from_slice(composite);
    out.extend_from_slice(slot_challenge);
    out.extend_from_slice(gpu_rim_digest);
    out.extend_from_slice(model_digest);
    out.extend_from_slice(challenge_nonce);
    out
}

/// 64-byte TDX `REPORTDATA`.
///
/// The value is `SHA-512` of [`report_data_preimage`]. SHA-512 is 64 bytes.
/// @spec SCC-TDX-002
pub fn report_data_commitment(
    workload_signer: &Pubkey,
    composite: &[u8; 32],
    slot_challenge: &[u8; 32],
    gpu_rim_digest: &[u8; 32],
    model_digest: &[u8; 32],
    challenge_nonce: &[u8; 32],
) -> [u8; 64] {
    let preimage =
        report_data_preimage(workload_signer, composite, slot_challenge, gpu_rim_digest, model_digest, challenge_nonce);
    let digest = Sha512::digest(&preimage);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

struct ParsedQuote {
    mr_td: [u8; 48],
    mr_config_id: [u8; 48],
    rtmrs_hash: [u8; 32],
}

/// Quote source used by [`IntelTdxProvider`]. Tests supply a scripted backend.
trait TdxQuoteBackend: Send + Sync {
    fn read_guest_report(&self, path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError>;

    fn read_dstack_quote(&self, socket_path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError>;
}

struct SystemQuoteBackend;

impl TdxQuoteBackend for SystemQuoteBackend {
    fn read_guest_report(&self, path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
        read_tdx_report0(path, report_data)
    }

    fn read_dstack_quote(&self, socket_path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
        read_dstack_quote(socket_path, report_data)
    }
}

/// Intel TDX attestation provider.
pub struct IntelTdxProvider {
    primary_device: String,
    secondary_device: String,
    dstack_socket: String,
    simulated: bool,
    gpu_rim_digest: Option<[u8; 32]>,
    model_digest: Option<[u8; 32]>,
    backend: Arc<dyn TdxQuoteBackend>,
}

impl IntelTdxProvider {
    /// `simulated` selects the dry-run quote. Live mode keeps the hardware probe.
    pub fn new(gpu_rim_digest: Option<[u8; 32]>, model_digest: Option<[u8; 32]>, simulated: bool) -> Self {
        Self {
            primary_device: TDX_GUEST_DEVICE.to_string(),
            secondary_device: TDX_GUEST_DEVICE_ALT.to_string(),
            dstack_socket: DSTACK_SOCKET.to_string(),
            simulated,
            gpu_rim_digest,
            model_digest,
            backend: Arc::new(SystemQuoteBackend),
        }
    }

    /// Daemon constructor. `dry_run` selects the synthetic quote.
    /// @spec SCC-TDX-001 SCC-SIDECAR-004
    pub fn for_daemon(dry_run: bool) -> Result<Self, SidecarError> {
        let provider = Self::new(None, None, dry_run);
        provider.reject_simulated_live(dry_run)?;
        Ok(provider)
    }

    /// Replace the probe paths. The probe order stays primary, secondary, socket.
    pub fn with_paths(
        mut self,
        primary_device: impl Into<String>,
        secondary_device: impl Into<String>,
        dstack_socket: impl Into<String>,
    ) -> Self {
        self.primary_device = primary_device.into();
        self.secondary_device = secondary_device.into();
        self.dstack_socket = dstack_socket.into();
        self
    }

    #[cfg(test)]
    fn with_backend(mut self, backend: Arc<dyn TdxQuoteBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// Synthetic evidence is a dry-run construction aid.
    /// @spec SCC-SIDECAR-004
    pub fn reject_simulated_live(&self, dry_run: bool) -> Result<(), SidecarError> {
        if self.simulated && !dry_run {
            return Err(SidecarError::InvalidConfig(
                "simulated Intel TDX evidence cannot be used when dry_run is false".to_string(),
            ));
        }
        Ok(())
    }

    /// `true` when this provider fabricates its evidence.
    pub fn is_simulated(&self) -> bool {
        self.simulated
    }

    /// The `(gpu_rim_digest, model_digest)` pair this provider binds into
    /// `REPORTDATA`.
    ///
    /// The enrolment transaction has to name the same two digests in
    /// `verify_tdx_qe_report`, because the program recomputes the report-data
    /// commitment from the session record it writes there. Neither value
    /// survives in `AttestationReport::IntelTdx` -- the composite hash is
    /// one-way -- so the submitter reads them from the provider that produced
    /// the quote rather than trying to recover them.
    ///
    /// @spec SCC-TDX-001 SCC-TDX-002
    pub fn binding_digests(&self) -> Result<([u8; 32], [u8; 32]), SidecarError> {
        if self.simulated {
            return Ok((
                self.gpu_rim_digest.unwrap_or(DEFAULT_TDX_GPU_RIM),
                self.model_digest.unwrap_or(DEFAULT_TDX_MODEL_DIGEST),
            ));
        }
        match (self.gpu_rim_digest, self.model_digest) {
            (Some(gpu), Some(model)) => Ok((gpu, model)),
            _ => Err(SidecarError::TdxAttestationFailed),
        }
    }

    /// Obtain a DCAP quote.
    ///
    /// The quoting socket is tried first, and the `/dev/tdx-guest` ioctl last,
    /// because the two do not return the same thing. `TDX_CMD_GET_REPORT0`
    /// yields a local TDREPORT: the hardware's own structure, signed by
    /// nothing a remote party can check. A DCAP quote is that report after the
    /// Quoting Enclave has signed it with a PCK-certified key, and the signed
    /// form is the only one the on-chain verifier can do anything with.
    ///
    /// Probing the device first therefore failed on exactly the machines the
    /// path was written for: a host with `/dev/tdx-guest` present returned a
    /// TDREPORT and never reached the socket that would have produced a quote.
    ///
    /// Order alone is not the fix. Each candidate is checked for the v4 DCAP
    /// header before it is accepted, so this returns a quote or nothing
    /// regardless of which source answered.
    fn first_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
        match self.backend.read_dstack_quote(&self.dstack_socket, report_data) {
            Ok(quote) if looks_like_quote_v4(&quote) => return Ok(quote),
            Ok(_) => {
                tracing::debug!(path = %self.dstack_socket, "dstack returned a non-quote payload");
            }
            Err(error) => {
                tracing::debug!(%error, path = %self.dstack_socket, "dstack quote probe missed");
            }
        }
        for path in [&self.primary_device, &self.secondary_device] {
            match self.backend.read_guest_report(path, report_data) {
                Ok(quote) if looks_like_quote_v4(&quote) => return Ok(quote),
                Ok(raw) => {
                    tracing::debug!(
                        %path,
                        len = raw.len(),
                        "guest device returned a TDREPORT, not a DCAP quote; \
                         it cannot be verified remotely"
                    );
                }
                Err(error) => {
                    tracing::debug!(%error, %path, "Intel TDX guest probe missed");
                }
            }
        }
        Err(SidecarError::TdxAttestationFailed)
    }

    /// Request evidence for an issued TDX challenge using its exact nonce and
    /// authenticated slot hash. Distinct nonces require distinct hardware evidence.
    pub async fn request_attestation_for_challenge(
        &self,
        workload_signer: &Pubkey,
        slot_hash: &[u8; 32],
        challenge_nonce: &[u8; 32],
    ) -> Result<AttestationReport, SidecarError> {
        let (gpu_rim, model) = self.binding_digests()?;
        let composite = composite_challenge(workload_signer, slot_hash, &gpu_rim, &model);
        let report_data =
            report_data_commitment(workload_signer, &composite, slot_hash, &gpu_rim, &model, challenge_nonce);
        let quote = if self.simulated {
            synthetic_quote(&report_data)
        } else {
            let quote = self.first_quote(&report_data)?;
            if synthetic_tdx_evidence(&quote) {
                return Err(SidecarError::TdxAttestationFailed);
            }
            quote
        };
        let parsed = parse_measurements(&quote, &report_data)?;
        Ok(AttestationReport::IntelTdx {
            quote,
            report_data,
            composite_challenge: composite,
            mr_td: parsed.mr_td,
            mr_config_id: parsed.mr_config_id,
            rtmrs_hash: parsed.rtmrs_hash,
        })
    }
}

impl Default for IntelTdxProvider {
    fn default() -> Self {
        Self::new(None, None, false)
    }
}

impl AttestationProvider for IntelTdxProvider {
    fn enclave_type(&self) -> EnclaveType {
        EnclaveType::IntelTdx
    }

    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        // The shared provider interface supplies only a slot hash, so this
        // path has nothing else to use as a nonce. That makes it a quote
        // collector, not an enrolment path: `OnchainAttestor::enrol_intel_tdx`
        // ignores whatever this returns and asks again with the nonce the
        // on-chain challenge actually recorded.
        //
        // Do not issue a challenge with `nonce = slot_hash` to make this
        // report submittable. The nonce alone selects the challenge PDA, so
        // deriving it from the slot hash gives every workload that picks the
        // same recent slot the same PDA -- and `issue_tdx_challenge` refuses
        // to reissue over a live or consumed record, so the second enroller is
        // locked out for the 1,500-slot challenge lifetime, permanently once a
        // quote has tombstoned it. It also erases the nonce's only stated job,
        // which is to tell apart challenges that pin the same slot hash.
        Box::pin(self.request_attestation_for_challenge(workload_signer, slot_hash, slot_hash))
    }
}

fn synthetic_quote(report_data: &[u8; 64]) -> Vec<u8> {
    let mut quote = Vec::with_capacity(SYNTHETIC_TDX_PREFIX.len() + (48 * 6) + 64);
    quote.extend_from_slice(SYNTHETIC_TDX_PREFIX);
    quote.extend_from_slice(&SYNTHETIC_MR_TD);
    quote.extend_from_slice(&SYNTHETIC_MR_CONFIG_ID);
    for rtmr in SYNTHETIC_RTMRS {
        quote.extend_from_slice(&rtmr);
    }
    quote.extend_from_slice(report_data);
    quote
}

fn parse_measurements(quote: &[u8], expected_report_data: &[u8; 64]) -> Result<ParsedQuote, SidecarError> {
    if synthetic_tdx_evidence(quote) {
        return parse_synthetic(quote, expected_report_data);
    }
    if looks_like_quote_v4(quote) {
        return parse_at(quote, QUOTE_MR_TD, QUOTE_MR_CONFIG_ID, QUOTE_RTMR0, QUOTE_REPORTDATA, expected_report_data);
    }
    if quote.len() >= TDX_REPORT_LEN {
        return parse_at(
            quote,
            TDREPORT_MR_TD,
            TDREPORT_MR_CONFIG_ID,
            TDREPORT_RTMR0,
            TDREPORT_REPORTDATA,
            expected_report_data,
        );
    }
    Err(SidecarError::AttestationError("TDX quote layout is not recognized".to_string()))
}

fn looks_like_quote_v4(quote: &[u8]) -> bool {
    quote.len() >= QUOTE_MIN_LEN
        && quote.get(..2).is_some_and(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) == QUOTE_V4_VERSION)
        && quote
            .get(4..8)
            .is_some_and(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == QUOTE_TDX_TEE_TYPE)
}

fn parse_synthetic(quote: &[u8], expected_report_data: &[u8; 64]) -> Result<ParsedQuote, SidecarError> {
    let mut offset = SYNTHETIC_TDX_PREFIX.len();
    let mr_td = take_array(quote, &mut offset)?;
    let mr_config_id = take_array(quote, &mut offset)?;
    let mut rtmrs = [[0u8; 48]; 4];
    for rtmr in &mut rtmrs {
        *rtmr = take_array(quote, &mut offset)?;
    }
    let report_data: [u8; 64] = take_array(quote, &mut offset)?;
    if offset != quote.len() || report_data != *expected_report_data {
        return Err(SidecarError::AttestationError("synthetic TDX quote does not bind REPORTDATA".to_string()));
    }
    Ok(ParsedQuote { mr_td, mr_config_id, rtmrs_hash: hash_rtmrs(&rtmrs) })
}

fn parse_at(
    quote: &[u8],
    mr_td_at: usize,
    mr_config_at: usize,
    rtmr_at: usize,
    report_data_at: usize,
    expected_report_data: &[u8; 64],
) -> Result<ParsedQuote, SidecarError> {
    let mr_td = copy_at(quote, mr_td_at)?;
    let mr_config_id = copy_at(quote, mr_config_at)?;
    let mut rtmrs = [[0u8; 48]; 4];
    for (index, rtmr) in rtmrs.iter_mut().enumerate() {
        let at = rtmr_at.checked_add(index.checked_mul(48).ok_or_else(truncated)?).ok_or_else(truncated)?;
        *rtmr = copy_at(quote, at)?;
    }
    let report_data: [u8; 64] = copy_at(quote, report_data_at)?;
    if report_data != *expected_report_data {
        return Err(SidecarError::AttestationError(
            "TDX REPORTDATA does not match the composite challenge".to_string(),
        ));
    }
    Ok(ParsedQuote { mr_td, mr_config_id, rtmrs_hash: hash_rtmrs(&rtmrs) })
}

fn truncated() -> SidecarError {
    SidecarError::AttestationError("TDX quote is truncated".to_string())
}

fn take_array<const N: usize>(buf: &[u8], offset: &mut usize) -> Result<[u8; N], SidecarError> {
    let start = *offset;
    let end = start.checked_add(N).ok_or_else(truncated)?;
    let slice = buf.get(start..end).ok_or_else(truncated)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *offset = end;
    Ok(out)
}

fn copy_at<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N], SidecarError> {
    let mut cursor = offset;
    take_array(buf, &mut cursor)
}

fn hash_rtmrs(rtmrs: &[[u8; 48]; 4]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for rtmr in rtmrs {
        hasher.update(rtmr);
    }
    finalize_32(hasher)
}

fn finalize_32(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn read_tdx_report0(path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
    #[cfg(target_os = "linux")]
    {
        linux_get_report0(path, report_data)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, report_data);
        Err(SidecarError::IoctlError("TDX_CMD_GET_REPORT0 requires a Linux TDX guest".to_string()))
    }
}

#[cfg(target_os = "linux")]
fn linux_get_report0(path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
    use std::ffi::CString;
    use std::io::ErrorKind;

    #[repr(C)]
    struct TdxReportReq {
        reportdata: [u8; TDX_REPORTDATA_LEN],
        tdreport: [u8; TDX_REPORT_LEN],
    }

    struct OwnedFd(libc::c_int);
    impl Drop for OwnedFd {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe { libc::close(self.0) };
            }
        }
    }

    let c_path =
        CString::new(path).map_err(|_| SidecarError::IoctlError(format!("{path} is not a valid device path")))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(SidecarError::IoctlError(format!("open {path}: {}", std::io::Error::last_os_error())));
    }
    let _owned = OwnedFd(fd);
    let mut req = Box::new(TdxReportReq { reportdata: *report_data, tdreport: [0; TDX_REPORT_LEN] });
    loop {
        let rc = unsafe { libc::ioctl(fd, TDX_CMD_GET_REPORT0 as libc::Ioctl, req.as_mut()) };
        if rc == 0 {
            return Ok(req.tdreport.to_vec());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(SidecarError::IoctlError(format!("TDX_CMD_GET_REPORT0 on {path}: {error}")));
    }
}

fn read_dstack_quote(socket_path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
    let hex_report = encode_hex(report_data);
    let http_body = serde_json::json!({ "report_data": hex_report }).to_string();
    if let Ok(body) = unix_http(socket_path, "/GetQuote", &http_body) {
        if let Ok(quote) = quote_from_json(&body) {
            return Ok(quote);
        }
    }
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tdx_quote",
        "params": { "report_data": hex_report }
    })
    .to_string();
    let body = unix_http(socket_path, "/", &rpc_body)?;
    quote_from_json(&body)
}

fn quote_from_json(bytes: &[u8]) -> Result<Vec<u8>, SidecarError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| SidecarError::AttestationError("dstack quote response is not JSON".to_string()))?;
    let text = value
        .get("quote")
        .or_else(|| value.pointer("/result/quote"))
        .or_else(|| value.pointer("/data/quote"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SidecarError::AttestationError("dstack response has no quote".to_string()))?;
    let quote = decode_quote_text(text)?;
    if quote.is_empty() {
        return Err(SidecarError::AttestationError("dstack quote is empty".to_string()));
    }
    Ok(quote)
}

fn decode_quote_text(text: &str) -> Result<Vec<u8>, SidecarError> {
    let trimmed = text.trim();
    let hex_text = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex_text.len() >= 2 && hex_text.len().is_multiple_of(2) && hex_text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return decode_hex(hex_text);
    }
    let engine = base64::engine::general_purpose::STANDARD;
    if let Ok(bytes) = base64::Engine::decode(&engine, trimmed) {
        return Ok(bytes);
    }
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    base64::Engine::decode(&url, trimmed)
        .map_err(|_| SidecarError::AttestationError("dstack quote is not hex or base64".to_string()))
}

fn unix_http(socket_path: &str, path: &str, json_body: &str) -> Result<Vec<u8>, SidecarError> {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;

    if path.contains(['\r', '\n', ' ']) {
        return Err(SidecarError::AttestationError("dstack HTTP path is not accepted".to_string()));
    }
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| SidecarError::AttestationError(format!("dstack socket {socket_path}: {error}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(750)))
        .map_err(|error| SidecarError::AttestationError(format!("dstack timeout: {error}")))?;
    stream
        .set_write_timeout(Some(Duration::from_millis(750)))
        .map_err(|error| SidecarError::AttestationError(format!("dstack timeout: {error}")))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
        json_body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| SidecarError::AttestationError(format!("dstack write failed: {error}")))?;
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if raw.len() >= MAX_DSTACK_RESPONSE {
            return Err(SidecarError::AttestationError("dstack response exceeds 256 KiB".to_string()));
        }
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(count) => raw.extend_from_slice(&tmp[..count]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::TimedOut || error.kind() == ErrorKind::WouldBlock => {
                if raw.is_empty() {
                    return Err(SidecarError::AttestationError("dstack response timed out".to_string()));
                }
                break;
            }
            Err(error) => {
                return Err(SidecarError::AttestationError(format!("dstack read failed: {error}")));
            }
        }
        if http_body_complete(&raw) {
            break;
        }
    }
    let (_status, body) = split_http(&raw)?;
    Ok(body)
}

fn http_body_complete(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let header = String::from_utf8_lossy(&raw[..split]);
    let Some(length) = content_length(&header) else {
        return false;
    };
    raw.len().saturating_sub(split + 4) >= length
}

fn split_http(raw: &[u8]) -> Result<(u16, Vec<u8>), SidecarError> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| SidecarError::AttestationError("dstack HTTP response has no header end".to_string()))?;
    let header = String::from_utf8_lossy(&raw[..split]);
    let mut body = raw[split + 4..].to_vec();
    let status = header
        .lines()
        .next()
        .and_then(parse_status)
        .ok_or_else(|| SidecarError::AttestationError("dstack HTTP status is missing".to_string()))?;
    if let Some(length) = content_length(&header) {
        if body.len() < length {
            return Err(SidecarError::AttestationError("dstack HTTP body is short".to_string()));
        }
        body.truncate(length);
    }
    if status != 200 {
        return Err(SidecarError::AttestationError(format!("dstack HTTP status {status}")));
    }
    Ok((status, body))
}

fn parse_status(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1)?.parse().ok()
}

fn content_length(header: &str) -> Option<usize> {
    for line in header.lines() {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.trim().parse().ok()?;
            if length > MAX_DSTACK_RESPONSE {
                return None;
            }
            return Some(length);
        }
    }
    None
}

fn encode_hex(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(ALPHA[(byte >> 4) as usize] as char);
        out.push(ALPHA[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(text: &str) -> Result<Vec<u8>, SidecarError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        let hi = hex_val(bytes[index])?;
        let lo = hex_val(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8, SidecarError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SidecarError::AttestationError("dstack quote hex is malformed".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct ScriptedBackend {
        calls: Mutex<Vec<String>>,
        succeed: Option<String>,
        quote_for: fn(&[u8; 64]) -> Vec<u8>,
    }

    impl TdxQuoteBackend for ScriptedBackend {
        fn read_guest_report(&self, path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
            self.calls.lock().expect("probe log").push(path.to_string());
            if self.succeed.as_deref() == Some(path) {
                return Ok((self.quote_for)(report_data));
            }
            Err(SidecarError::IoctlError(format!("{path} missed")))
        }

        fn read_dstack_quote(&self, socket_path: &str, report_data: &[u8; 64]) -> Result<Vec<u8>, SidecarError> {
            self.calls.lock().expect("probe log").push(socket_path.to_string());
            if self.succeed.as_deref() == Some(socket_path) {
                return Ok((self.quote_for)(report_data));
            }
            Err(SidecarError::AttestationError(format!("{socket_path} missed")))
        }
    }

    fn provider(
        simulated: bool,
        succeed: Option<&str>,
        quote_for: fn(&[u8; 64]) -> Vec<u8>,
    ) -> (IntelTdxProvider, Arc<ScriptedBackend>) {
        let backend = Arc::new(ScriptedBackend {
            calls: Mutex::new(Vec::new()),
            succeed: succeed.map(str::to_string),
            quote_for,
        });
        let provider = IntelTdxProvider::new(Some([0x41; 32]), Some([0x42; 32]), simulated)
            .with_paths("/dev/tdx-guest", "/dev/tdx_guest", "/var/run/dstack.sock")
            .with_backend(backend.clone());
        (provider, backend)
    }

    fn blank_tdreport(report_data: &[u8; 64]) -> Vec<u8> {
        let mut quote = vec![0u8; TDX_REPORT_LEN];
        quote[0] = 0x81;
        quote[TDREPORT_REPORTDATA..TDREPORT_REPORTDATA + 64].copy_from_slice(report_data);
        quote[TDREPORT_MR_TD..TDREPORT_MR_TD + 48].fill(0x11);
        quote[TDREPORT_MR_CONFIG_ID..TDREPORT_MR_CONFIG_ID + 48].fill(0x22);
        quote
    }

    /// A minimal but structurally valid DCAP v4 quote binding `report_data`.
    ///
    /// The distinction this encodes is the whole point of the probe change:
    /// `blank_tdreport` is what the ioctl returns and can never be verified
    /// remotely, this is what the quoting socket returns and can.
    fn quote_v4(report_data: &[u8; 64]) -> Vec<u8> {
        let mut quote = vec![0u8; QUOTE_MIN_LEN];
        quote[0..2].copy_from_slice(&QUOTE_V4_VERSION.to_le_bytes());
        quote[2..4].copy_from_slice(&2u16.to_le_bytes());
        quote[4..8].copy_from_slice(&QUOTE_TDX_TEE_TYPE.to_le_bytes());
        quote[QUOTE_MR_TD..QUOTE_MR_TD + 48].fill(0x11);
        quote[QUOTE_MR_CONFIG_ID..QUOTE_MR_CONFIG_ID + 48].fill(0x22);
        quote[QUOTE_REPORTDATA..QUOTE_REPORTDATA + 64].copy_from_slice(report_data);
        quote
    }

    #[test]
    fn ioctl_number_matches_iowr_encoding() {
        let size = (TDX_REPORTDATA_LEN + TDX_REPORT_LEN) as u32;
        let value = (3u32 << 30) | (size << 16) | (u32::from(b'T') << 8) | 1;
        assert_eq!(value, TDX_CMD_GET_REPORT0);
        assert_eq!(DEFAULT_TDX_GPU_RIM.len(), 32);
        assert_eq!(DEFAULT_TDX_MODEL_DIGEST.len(), 32);
    }

    #[test]
    fn composite_challenge_and_report_data_bind_each_input() {
        let slot = [0x10; 32];
        let gpu = [0x20; 32];
        let model = [0x30; 32];
        let signer = Pubkey::new_from_array([0x40; 32]);
        let composite = composite_challenge(&signer, &slot, &gpu, &model);
        assert_eq!(composite, composite_challenge(&signer, &slot, &gpu, &model));
        assert_ne!(composite, composite_challenge(&signer, &[0x11; 32], &gpu, &model));
        assert_ne!(composite, composite_challenge(&signer, &slot, &[0x21; 32], &model));
        assert_ne!(composite, composite_challenge(&signer, &slot, &gpu, &[0x31; 32]));
        let report = report_data_commitment(&signer, &composite, &slot, &gpu, &model, &slot);
        assert_eq!(report.len(), 64);
        let other = report_data_commitment(&signer, &composite, &slot, &gpu, &[0x31; 32], &slot);
        assert_ne!(report, other);
        let preimage = report_data_preimage(&signer, &composite, &slot, &gpu, &model, &slot);
        assert_eq!(&preimage[..4], &42u32.to_le_bytes());
        assert_eq!(&preimage[4..46], REPORT_DATA_DOMAIN.as_bytes());
        assert_eq!(&preimage[46..78], signer.to_bytes());
    }

    /// Two workloads on the same host share the measurement, the slot, the GPU
    /// RIM and the model digest. Only the signer differs. If the quote does not
    /// commit to the signer, both produce identical `REPORTDATA` and either one
    /// can present the other's evidence as its own.
    #[test]
    fn report_data_separates_two_signers_on_one_host() {
        let slot = [0x10; 32];
        let gpu = DEFAULT_TDX_GPU_RIM;
        let model = DEFAULT_TDX_MODEL_DIGEST;
        let honest = Pubkey::new_from_array([0x41; 32]);
        let attacker = Pubkey::new_from_array([0x42; 32]);

        let honest_composite = composite_challenge(&honest, &slot, &gpu, &model);
        let attacker_composite = composite_challenge(&attacker, &slot, &gpu, &model);
        assert_ne!(honest_composite, attacker_composite);

        let honest_report = report_data_commitment(&honest, &honest_composite, &slot, &gpu, &model, &slot);
        let attacker_report = report_data_commitment(&attacker, &attacker_composite, &slot, &gpu, &model, &slot);
        assert_ne!(honest_report, attacker_report, "a quote issued for one signer must not validate for another");
    }

    #[tokio::test]
    async fn requested_quote_commits_to_the_requesting_signer() {
        let signer = Pubkey::new_from_array([0x43; 32]);
        let slot = [0x44; 32];
        let (provider, _backend) = provider(true, Some("/dev/tdx-guest"), blank_tdreport);

        let report = provider.request_attestation(&signer, &slot).await.expect("dry-run attestation");
        let AttestationReport::IntelTdx { report_data, composite_challenge: composite, .. } = report else {
            panic!("expected an Intel TDX report");
        };

        let (gpu, model) = provider.binding_digests().expect("binding digests");
        assert_eq!(composite, composite_challenge(&signer, &slot, &gpu, &model));
        assert_eq!(report_data, report_data_commitment(&signer, &composite, &slot, &gpu, &model, &slot));

        let other = Pubkey::new_from_array([0x45; 32]);
        let other_composite = composite_challenge(&other, &slot, &gpu, &model);
        assert_ne!(report_data, report_data_commitment(&other, &other_composite, &slot, &gpu, &model, &slot));
    }

    #[tokio::test]
    async fn requested_quotes_distinguish_challenges_with_the_same_slot_hash() {
        let signer = Pubkey::new_unique();
        let slot = [0x44; 32];
        let (provider, backend) = provider(false, Some("/var/run/dstack.sock"), quote_v4);
        let mut commitments = Vec::new();
        for nonce in [[0x55; 32], [0x56; 32]] {
            let report =
                provider.request_attestation_for_challenge(&signer, &slot, &nonce).await.expect("scripted attestation");
            let AttestationReport::IntelTdx { report_data, .. } = report else {
                panic!("expected an Intel TDX report");
            };
            let (gpu, model) = provider.binding_digests().unwrap();
            let composite = composite_challenge(&signer, &slot, &gpu, &model);
            assert_eq!(report_data, report_data_commitment(&signer, &composite, &slot, &gpu, &model, &nonce),);
            commitments.push(report_data);
        }
        assert_eq!(backend.calls.lock().unwrap().len(), 2);
        assert_ne!(commitments[0], commitments[1]);
    }

    #[test]
    fn simulated_provider_is_rejected_for_live_use() {
        let simulated = IntelTdxProvider::new(None, None, true);
        let error = simulated.reject_simulated_live(false).expect_err("simulated evidence");
        assert!(matches!(error, SidecarError::InvalidConfig(_)));
        assert!(simulated.reject_simulated_live(true).is_ok());
        let live = IntelTdxProvider::for_daemon(false).expect("live");
        assert!(live.reject_simulated_live(false).is_ok());
        let dry = IntelTdxProvider::for_daemon(true).expect("dry-run");
        assert!(dry.reject_simulated_live(true).is_ok());
    }

    #[tokio::test]
    async fn dry_run_returns_synthetic_quote_without_probing() {
        let (provider, backend) = provider(true, Some("/dev/tdx-guest"), blank_tdreport);
        let signer = Pubkey::new_unique();
        let report = provider.request_attestation(&signer, &[0x5a; 32]).await.expect("dry-run");
        assert!(backend.calls.lock().expect("log").is_empty());
        match report {
            AttestationReport::IntelTdx {
                quote,
                report_data,
                composite_challenge: composite,
                mr_td,
                mr_config_id,
                rtmrs_hash,
            } => {
                assert!(synthetic_tdx_evidence(&quote));
                assert_eq!(mr_td, SYNTHETIC_MR_TD);
                assert_eq!(mr_config_id, SYNTHETIC_MR_CONFIG_ID);
                let gpu = [0x41; 32];
                let model = [0x42; 32];
                let expected = composite_challenge(&signer, &[0x5a; 32], &gpu, &model);
                assert_eq!(composite, expected);
                let committed = report_data_commitment(&signer, &expected, &[0x5a; 32], &gpu, &model, &[0x5a; 32]);
                assert_eq!(report_data, committed);
                assert_eq!(rtmrs_hash, hash_rtmrs(&SYNTHETIC_RTMRS));
            }
            _ => panic!("expected Intel TDX report"),
        }
    }

    #[tokio::test]
    async fn daemon_dry_run_uses_placeholder_bindings() {
        let provider = IntelTdxProvider::for_daemon(true).expect("dry-run");
        let signer = Pubkey::new_unique();
        let report = provider.request_attestation(&signer, &[0x5a; 32]).await.expect("synthetic");
        match report {
            AttestationReport::IntelTdx { composite_challenge: composite, .. } => {
                let expected =
                    composite_challenge(&signer, &[0x5a; 32], &DEFAULT_TDX_GPU_RIM, &DEFAULT_TDX_MODEL_DIGEST);
                assert_eq!(composite, expected);
            }
            _ => panic!("expected Intel TDX report"),
        }
    }

    #[tokio::test]
    async fn live_synthetic_prefix_from_a_probe_fails_closed() {
        let (provider, _) = provider(false, Some("/dev/tdx-guest"), synthetic_quote);
        let error =
            provider.request_attestation(&Pubkey::new_unique(), &[0x5a; 32]).await.expect_err("synthetic prefix");
        assert!(matches!(error, SidecarError::TdxAttestationFailed));
    }

    #[tokio::test]
    async fn the_quoting_socket_is_probed_before_the_ioctl() {
        // Only the socket returns a DCAP quote, so it is asked first and the
        // devices are never touched. Probing them first was the bug: on a
        // host where `/dev/tdx-guest` exists, the ioctl answered with a
        // TDREPORT and the socket that would have produced a real quote was
        // never reached.
        let (provider, backend) = provider(false, Some("/var/run/dstack.sock"), quote_v4);
        let report =
            provider.request_attestation(&Pubkey::new_unique(), &[0x5a; 32]).await.expect("the socket returns a quote");
        let calls = backend.calls.lock().expect("log").clone();
        assert_eq!(
            calls,
            vec!["/var/run/dstack.sock".to_string()],
            "the devices must not be probed once the socket has answered"
        );
        match report {
            AttestationReport::IntelTdx { quote, mr_td, .. } => {
                assert!(looks_like_quote_v4(&quote));
                assert_eq!(mr_td, [0x11; 48]);
            }
            _ => panic!("expected Intel TDX report"),
        }
    }

    #[tokio::test]
    async fn a_tdreport_from_the_ioctl_is_never_accepted_as_a_quote() {
        // Every source returns a TDREPORT, which is what a host without a
        // quoting service looks like. There is no quote to be had, so this
        // must fail rather than hand a locally signed structure to a verifier
        // that cannot check it.
        let (provider, backend) = provider(false, Some("/dev/tdx-guest"), blank_tdreport);
        let error = provider
            .request_attestation(&Pubkey::new_unique(), &[0x5a; 32])
            .await
            .expect_err("a TDREPORT is not a quote");
        assert!(matches!(error, SidecarError::TdxAttestationFailed));
        let calls = backend.calls.lock().expect("log").clone();
        assert_eq!(
            calls,
            vec!["/var/run/dstack.sock".to_string(), "/dev/tdx-guest".to_string(), "/dev/tdx_guest".to_string(),],
            "all three sources are tried before giving up"
        );
    }

    #[tokio::test]
    async fn live_probe_fail_closed_does_not_emit_synthetic_quote() {
        let (provider, backend) = provider(false, None, blank_tdreport);
        let error = provider.request_attestation(&Pubkey::new_unique(), &[0x5a; 32]).await.expect_err("miss");
        assert!(matches!(error, SidecarError::TdxAttestationFailed));
        assert_eq!(backend.calls.lock().expect("log").len(), 3);

        let (unpinned, backend) = {
            let backend = Arc::new(ScriptedBackend {
                calls: Mutex::new(Vec::new()),
                succeed: Some("/dev/tdx-guest".to_string()),
                quote_for: blank_tdreport,
            });
            let provider = IntelTdxProvider::new(None, None, false).with_backend(backend.clone());
            (provider, backend)
        };
        let error =
            unpinned.request_attestation(&Pubkey::new_unique(), &[0x5a; 32]).await.expect_err("unpinned live binding");
        assert!(matches!(error, SidecarError::TdxAttestationFailed));
        assert!(backend.calls.lock().expect("log").is_empty());
    }

    #[tokio::test]
    async fn mismatched_report_data_fails_closed() {
        // A structurally valid quote that commits to someone else's
        // REPORTDATA. It parses, and must still be refused.
        let (provider, _) = provider(false, Some("/var/run/dstack.sock"), |_| quote_v4(&[0x11; 64]));
        let error = provider.request_attestation(&Pubkey::new_unique(), &[0x5a; 32]).await.expect_err("unbound report");
        assert!(matches!(error, SidecarError::AttestationError(_)));
    }

    #[test]
    fn quote_v4_parser_reads_body_offsets() {
        let report_data = [0x7a; 64];
        let mut quote = vec![0u8; QUOTE_MIN_LEN];
        quote[..2].copy_from_slice(&QUOTE_V4_VERSION.to_le_bytes());
        quote[4..8].copy_from_slice(&QUOTE_TDX_TEE_TYPE.to_le_bytes());
        quote[QUOTE_MR_TD..QUOTE_MR_TD + 48].fill(0x44);
        quote[QUOTE_MR_CONFIG_ID..QUOTE_MR_CONFIG_ID + 48].fill(0x55);
        quote[QUOTE_REPORTDATA..QUOTE_REPORTDATA + 64].copy_from_slice(&report_data);
        let parsed = parse_measurements(&quote, &report_data).expect("quote");
        assert_eq!(parsed.mr_td, [0x44; 48]);
        assert_eq!(parsed.mr_config_id, [0x55; 48]);
    }
}
