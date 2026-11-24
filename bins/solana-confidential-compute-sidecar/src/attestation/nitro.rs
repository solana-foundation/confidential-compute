//! AWS Nitro Enclaves hardware attestation provider using `/dev/nsm` ioctl.
//!
//! @spec SCC-SIDECAR-002 SCC-NITRO-003 SCC-NITRO-007

#[cfg(test)]
use solana_confidential_compute_core::NITRO_PCR_LEN;
use solana_confidential_compute_core::{types::EnclaveType, MAX_NITRO_DOCUMENT_LEN, NITRO_USER_DATA_LEN};
#[cfg(any(test, target_os = "linux"))]
use solana_confidential_compute_crypto::cbor::CborCursor;
use solana_confidential_compute_crypto::parse_nitro_attestation;
use solana_sdk::pubkey::Pubkey;
use std::future::Future;
use std::pin::Pin;

use super::{AttestationProvider, AttestationReport};
use crate::error::SidecarError;

/// NSM ioctl magic (`include/uapi/linux/nsm.h` / aws-nitro-enclaves-nsm-api).
pub const NSM_IOCTL_MAGIC: u8 = 0x0A;
/// NSM ioctl number for a CBOR request/response pair.
pub const NSM_IOCTL_NR: u8 = 0;
/// `struct nsm_message` is two 16-byte iovecs (`__u64 addr` + `__u64 len`).
pub const NSM_MESSAGE_SIZE: usize = 32;
/// `_IOWR(0x0A, 0, 32)` = `NSM_REQUEST_ATTESTATION`.
pub const NSM_REQUEST_ATTESTATION: u64 = 0xC020_0A00;
/// Maximum CBOR request size accepted by the NSM driver.
#[cfg(target_os = "linux")]
const NSM_REQUEST_MAX_SIZE: usize = 0x1000;
/// Maximum CBOR response size accepted by the NSM driver.
#[cfg(target_os = "linux")]
const NSM_RESPONSE_MAX_SIZE: usize = 0x3000;

#[cfg(test)]
const COSE_SIGN1_TAG: u8 = 0xd2;
#[cfg(test)]
const COSE_PROTECTED_ES384: [u8; 4] = [0xa1, 0x01, 0x38, 0x22];
#[cfg(test)]
const MOCK_MODULE_ID: &str = "i-teton-nitro-mock";
#[cfg(test)]
const MOCK_TIMESTAMP_MS: u64 = 1_700_000_000_000;
#[cfg(test)]
const MOCK_LEAF_CERT: [u8; 16] = *b"MOCK-NITRO-LEAF!";
#[cfg(test)]
const MOCK_ROOT_CERT: [u8; 16] = *b"MOCK-NITRO-ROOT!";

pub struct AwsNitroProvider {
    device_path: String,
}

impl AwsNitroProvider {
    pub fn new(device_path: Option<&str>) -> Self {
        Self { device_path: device_path.unwrap_or("/dev/nsm").to_string() }
    }
}

impl Default for AwsNitroProvider {
    fn default() -> Self {
        Self::new(None)
    }
}

impl AttestationProvider for AwsNitroProvider {
    fn enclave_type(&self) -> EnclaveType {
        EnclaveType::AwsNitro
    }

    fn request_attestation<'a>(
        &'a self,
        workload_signer: &'a Pubkey,
        slot_hash: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<AttestationReport, SidecarError>> + Send + 'a>> {
        Box::pin(async move {
            let user_data = workload_signer.to_bytes();
            let document = self.request_document(&user_data, slot_hash)?;
            accept_nitro_document(document, workload_signer, slot_hash)
        })
    }
}

impl AwsNitroProvider {
    /// Requests a COSE Sign1 document from `/dev/nsm`. Missing device, open
    /// failure, ioctl failure, or a non-Linux host fail closed.
    /// @spec SCC-NITRO-003 SCC-NITRO-007
    fn request_document(
        &self,
        user_data: &[u8; NITRO_USER_DATA_LEN],
        nonce: &[u8; 32],
    ) -> Result<Vec<u8>, SidecarError> {
        #[cfg(target_os = "linux")]
        {
            if !std::path::Path::new(&self.device_path).exists() {
                return Err(SidecarError::IoctlError(format!("NSM device is missing: {}", self.device_path)));
            }
            request_from_nsm(&self.device_path, user_data, nonce)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (user_data, nonce);
            Err(SidecarError::IoctlError(format!(
                "/dev/nsm ioctl is only available on Linux (configured path: {})",
                self.device_path
            )))
        }
    }
}

/// Accepts a COSE Sign1 document only when it binds `user_data` and `nonce`
/// and PCR0 is not the all-zero measurement.
/// @spec SCC-NITRO-003 SCC-NITRO-007 SCC-SEC-002
fn accept_nitro_document(
    document: Vec<u8>,
    workload_signer: &Pubkey,
    slot_hash: &[u8; 32],
) -> Result<AttestationReport, SidecarError> {
    if document.is_empty() || document.len() > MAX_NITRO_DOCUMENT_LEN {
        return Err(SidecarError::AttestationError(format!(
            "Nitro document length {} is outside 1..={MAX_NITRO_DOCUMENT_LEN}",
            document.len()
        )));
    }
    let (_cose, view) = parse_nitro_attestation(&document)
        .map_err(|e| SidecarError::AttestationError(format!("Nitro COSE Sign1 parse failed: {e:?}")))?;
    if view.pcrs.pcr0_is_zero() {
        return Err(SidecarError::AttestationError("Nitro document PCR0 measurement is all zeros".to_string()));
    }
    if view.user_data != workload_signer.to_bytes() {
        return Err(SidecarError::AttestationError(
            "Nitro document user_data does not bind the workload pubkey".to_string(),
        ));
    }
    if &view.nonce != slot_hash {
        return Err(SidecarError::AttestationError("Nitro document nonce does not bind the slot hash".to_string()));
    }
    Ok(AttestationReport::AwsNitro { document })
}

/// CBOR `{"Attestation":{"user_data":h'..',"nonce":h'..'}}`.
#[cfg(any(test, target_os = "linux"))]
fn encode_nsm_attestation_request(user_data: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    push_cbor_len(&mut out, 5, 1);
    push_cbor_tstr(&mut out, "Attestation");
    push_cbor_len(&mut out, 5, 2);
    push_cbor_tstr(&mut out, "user_data");
    push_cbor_bstr(&mut out, user_data);
    push_cbor_tstr(&mut out, "nonce");
    push_cbor_bstr(&mut out, nonce);
    out
}

/// Extracts `document` from a CBOR NSM attestation response.
#[cfg(any(test, target_os = "linux"))]
fn decode_nsm_attestation_response(buf: &[u8]) -> Result<Vec<u8>, SidecarError> {
    let mut cur = CborCursor::new(buf);
    let n =
        cur.read_map_len().map_err(|e| SidecarError::IoctlError(format!("NSM response is not a CBOR map: {e:?}")))?;
    if n != 1 {
        return Err(SidecarError::IoctlError("NSM response map must contain exactly one key".to_string()));
    }
    let key = cur.read_tstr().map_err(|e| SidecarError::IoctlError(format!("NSM response key is not text: {e:?}")))?;
    match key {
        "Error" => {
            let msg = cur
                .read_tstr()
                .map_err(|e| SidecarError::IoctlError(format!("NSM error payload is not text: {e:?}")))?;
            Err(SidecarError::IoctlError(format!("NSM returned error: {msg}")))
        }
        "Attestation" => {
            let inner_n = cur
                .read_map_len()
                .map_err(|e| SidecarError::IoctlError(format!("NSM Attestation value is not a map: {e:?}")))?;
            if inner_n != 1 {
                return Err(SidecarError::IoctlError("NSM Attestation map must contain exactly one key".to_string()));
            }
            let inner_key = cur
                .read_tstr()
                .map_err(|e| SidecarError::IoctlError(format!("NSM Attestation key is not text: {e:?}")))?;
            if inner_key != "document" {
                return Err(SidecarError::IoctlError(format!(
                    "NSM Attestation map is missing document (got {inner_key})"
                )));
            }
            let document = cur
                .read_bstr()
                .map_err(|e| SidecarError::IoctlError(format!("NSM document is not a byte string: {e:?}")))?;
            if document.is_empty() {
                return Err(SidecarError::IoctlError("NSM attestation document is empty".to_string()));
            }
            if cur.remaining().iter().any(|&b| b != 0) {
                return Err(SidecarError::IoctlError("NSM response has trailing non-zero bytes".to_string()));
            }
            Ok(document.to_vec())
        }
        other => Err(SidecarError::IoctlError(format!("NSM response has unknown key {other}"))),
    }
}

/// Synthetic tagged COSE Sign1 used by unit tests. Production
/// `request_document` never calls this helper.
/// @spec SCC-NITRO-003
#[cfg(test)]
pub(crate) fn synthetic_cose_sign1(user_data: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    synthetic_cose_sign1_with_pcr0(user_data, nonce, &[0xabu8; NITRO_PCR_LEN])
}

#[cfg(test)]
fn synthetic_cose_sign1_with_pcr0(user_data: &[u8; 32], nonce: &[u8; 32], pcr0: &[u8; NITRO_PCR_LEN]) -> Vec<u8> {
    let payload = synthetic_attestation_payload(user_data, nonce, pcr0);
    let mut doc = Vec::new();
    doc.push(COSE_SIGN1_TAG);
    push_cbor_len(&mut doc, 4, 4);
    push_cbor_bstr(&mut doc, &COSE_PROTECTED_ES384);
    push_cbor_len(&mut doc, 5, 0);
    push_cbor_bstr(&mut doc, &payload);
    push_cbor_bstr(&mut doc, &[0u8; 96]);
    doc
}

#[cfg(test)]
fn synthetic_attestation_payload(user_data: &[u8; 32], nonce: &[u8; 32], pcr0: &[u8; NITRO_PCR_LEN]) -> Vec<u8> {
    let pcr1 = [0x01u8; NITRO_PCR_LEN];
    let pcr2 = [0x02u8; NITRO_PCR_LEN];
    let pcr8 = [0x08u8; NITRO_PCR_LEN];

    let mut pcrs = Vec::new();
    push_cbor_len(&mut pcrs, 5, 4);
    push_cbor_uint(&mut pcrs, 0);
    push_cbor_bstr(&mut pcrs, pcr0);
    push_cbor_uint(&mut pcrs, 1);
    push_cbor_bstr(&mut pcrs, &pcr1);
    push_cbor_uint(&mut pcrs, 2);
    push_cbor_bstr(&mut pcrs, &pcr2);
    push_cbor_uint(&mut pcrs, 8);
    push_cbor_bstr(&mut pcrs, &pcr8);

    let mut cabundle = Vec::new();
    push_cbor_len(&mut cabundle, 4, 1);
    push_cbor_bstr(&mut cabundle, &MOCK_ROOT_CERT);

    let mut payload = Vec::new();
    push_cbor_len(&mut payload, 5, 8);
    push_cbor_tstr(&mut payload, "module_id");
    push_cbor_tstr(&mut payload, MOCK_MODULE_ID);
    push_cbor_tstr(&mut payload, "timestamp");
    push_cbor_uint(&mut payload, MOCK_TIMESTAMP_MS);
    push_cbor_tstr(&mut payload, "digest");
    push_cbor_tstr(&mut payload, "SHA384");
    push_cbor_tstr(&mut payload, "pcrs");
    payload.extend_from_slice(&pcrs);
    push_cbor_tstr(&mut payload, "certificate");
    push_cbor_bstr(&mut payload, &MOCK_LEAF_CERT);
    push_cbor_tstr(&mut payload, "cabundle");
    payload.extend_from_slice(&cabundle);
    push_cbor_tstr(&mut payload, "user_data");
    push_cbor_bstr(&mut payload, user_data);
    push_cbor_tstr(&mut payload, "nonce");
    push_cbor_bstr(&mut payload, nonce);
    payload
}

#[cfg(any(test, target_os = "linux"))]
fn push_cbor_len(out: &mut Vec<u8>, major: u8, len: usize) {
    push_cbor_arg(out, major, len as u64);
}

#[cfg(test)]
fn push_cbor_uint(out: &mut Vec<u8>, n: u64) {
    push_cbor_arg(out, 0, n);
}

#[cfg(any(test, target_os = "linux"))]
fn push_cbor_arg(out: &mut Vec<u8>, major: u8, n: u64) {
    let hi = major << 5;
    if n <= 23 {
        out.push(hi | n as u8);
    } else if n <= 0xff {
        out.push(hi | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(hi | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(hi | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(hi | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

#[cfg(any(test, target_os = "linux"))]
fn push_cbor_tstr(out: &mut Vec<u8>, s: &str) {
    push_cbor_len(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

#[cfg(any(test, target_os = "linux"))]
fn push_cbor_bstr(out: &mut Vec<u8>, b: &[u8]) {
    push_cbor_len(out, 2, b.len());
    out.extend_from_slice(b);
}

#[cfg(target_os = "linux")]
fn request_from_nsm(device_path: &str, user_data: &[u8; 32], nonce: &[u8; 32]) -> Result<Vec<u8>, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device_path)
        .map_err(|e| SidecarError::IoctlError(format!("Failed to open NSM device {device_path}: {e}")))?;

    let request = encode_nsm_attestation_request(user_data, nonce);
    if request.len() > NSM_REQUEST_MAX_SIZE {
        return Err(SidecarError::IoctlError("NSM attestation request exceeds NSM_REQUEST_MAX_SIZE".to_string()));
    }

    let mut request_buf = [0u8; NSM_REQUEST_MAX_SIZE];
    request_buf[..request.len()].copy_from_slice(&request);
    let mut response_buf = [0u8; NSM_RESPONSE_MAX_SIZE];

    #[repr(C)]
    struct NsmIovec {
        iov_base: u64,
        iov_len: u64,
    }

    #[repr(C)]
    struct NsmMessage {
        request: NsmIovec,
        response: NsmIovec,
    }

    let mut message = NsmMessage {
        request: NsmIovec { iov_base: request_buf.as_ptr() as usize as u64, iov_len: request.len() as u64 },
        response: NsmIovec { iov_base: response_buf.as_mut_ptr() as usize as u64, iov_len: response_buf.len() as u64 },
    };

    let ret = unsafe { libc::ioctl(file.as_raw_fd(), NSM_REQUEST_ATTESTATION as libc::c_ulong, &mut message) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SidecarError::IoctlError(format!("NSM_REQUEST_ATTESTATION ioctl failed (ret={ret}): {err}")));
    }

    let resp_len = usize::try_from(message.response.iov_len)
        .map_err(|_| SidecarError::IoctlError("NSM response length does not fit usize".to_string()))?;
    if resp_len == 0 || resp_len > NSM_RESPONSE_MAX_SIZE {
        return Err(SidecarError::IoctlError(format!("NSM response length {resp_len} is invalid")));
    }
    decode_nsm_attestation_response(&response_buf[..resp_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsm_ioctl_number_is_iowr_0a_0_32() {
        assert_eq!(NSM_REQUEST_ATTESTATION, 0xC020_0A00);
        assert_eq!(NSM_MESSAGE_SIZE, 32);
        let dir: u64 = 3;
        let computed = (dir << 30)
            | ((NSM_MESSAGE_SIZE as u64 & 0x3fff) << 16)
            | ((NSM_IOCTL_MAGIC as u64) << 8)
            | (NSM_IOCTL_NR as u64);
        assert_eq!(computed, NSM_REQUEST_ATTESTATION);
    }

    #[test]
    fn nsm_request_cbor_binds_user_data_and_nonce() {
        let user = [0x80u8; 32];
        let nonce = [0x11u8; 32];
        let encoded = encode_nsm_attestation_request(&user, &nonce);
        let mut cur = CborCursor::new(&encoded);
        assert_eq!(cur.read_map_len().unwrap(), 1);
        assert_eq!(cur.read_tstr().unwrap(), "Attestation");
        assert_eq!(cur.read_map_len().unwrap(), 2);
        assert_eq!(cur.read_tstr().unwrap(), "user_data");
        assert_eq!(cur.read_bstr().unwrap(), user.as_slice());
        assert_eq!(cur.read_tstr().unwrap(), "nonce");
        assert_eq!(cur.read_bstr().unwrap(), nonce.as_slice());
        assert!(cur.is_empty());
    }

    #[test]
    fn nsm_response_extracts_document_and_ignores_trailing_zeros() {
        let doc = b"cose-sign1-bytes";
        let mut buf = encode_nsm_attestation_response(doc);
        buf.extend_from_slice(&[0u8; 8]);
        let decoded = decode_nsm_attestation_response(&buf).expect("decode");
        assert_eq!(decoded, doc);
    }

    #[test]
    fn nsm_response_error_is_fail_closed() {
        let mut buf = Vec::new();
        push_cbor_len(&mut buf, 5, 1);
        push_cbor_tstr(&mut buf, "Error");
        push_cbor_tstr(&mut buf, "InvalidArgument");
        let err = decode_nsm_attestation_response(&buf).unwrap_err();
        match err {
            SidecarError::IoctlError(msg) => {
                assert!(msg.contains("InvalidArgument"));
            }
            other => panic!("expected IoctlError, got {other:?}"),
        }
    }

    #[test]
    fn synthetic_document_parses_and_binds_challenge() {
        let signer = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x5au8; 32];
        let document = synthetic_cose_sign1(&signer.to_bytes(), &slot_hash);
        assert!(document.len() <= MAX_NITRO_DOCUMENT_LEN);
        let report = accept_nitro_document(document, &signer, &slot_hash).expect("accept");
        match report {
            AttestationReport::AwsNitro { document } => {
                let (_cose, view) = parse_nitro_attestation(&document).expect("parse");
                assert_eq!(view.module_id, MOCK_MODULE_ID);
                assert_eq!(view.digest, "SHA384");
                assert_eq!(view.user_data, signer.to_bytes());
                assert_eq!(view.nonce, slot_hash);
                assert!(!view.pcrs.pcr0_is_zero());
            }
            other => panic!("expected AwsNitro, got {other:?}"),
        }
    }

    #[test]
    fn reject_zero_pcr0() {
        let signer = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x5au8; 32];
        let document = synthetic_cose_sign1_with_pcr0(&signer.to_bytes(), &slot_hash, &[0u8; NITRO_PCR_LEN]);
        let err = accept_nitro_document(document, &signer, &slot_hash).unwrap_err();
        match err {
            SidecarError::AttestationError(msg) => {
                assert!(msg.contains("PCR0 measurement is all zeros"));
            }
            other => panic!("expected AttestationError, got {other:?}"),
        }
    }

    #[test]
    fn reject_document_that_does_not_bind_signer() {
        let signer = Pubkey::new_from_array([0x01; 32]);
        let other = Pubkey::new_from_array([0x02; 32]);
        let slot_hash = [0x11u8; 32];
        let document = synthetic_cose_sign1(&other.to_bytes(), &slot_hash);
        let err = accept_nitro_document(document, &signer, &slot_hash).unwrap_err();
        match err {
            SidecarError::AttestationError(msg) => {
                assert!(msg.contains("user_data"));
            }
            other => panic!("expected AttestationError, got {other:?}"),
        }
    }

    #[test]
    fn reject_oversized_document() {
        let signer = Pubkey::new_unique();
        let slot_hash = [0u8; 32];
        let err = accept_nitro_document(vec![0u8; MAX_NITRO_DOCUMENT_LEN + 1], &signer, &slot_hash).unwrap_err();
        match err {
            SidecarError::AttestationError(msg) => {
                assert!(msg.contains("outside"));
            }
            other => panic!("expected AttestationError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn provider_fails_closed_without_nsm() {
        let provider = AwsNitroProvider::new(Some("/dev/nsm-missing-confidential-compute-issue-50"));
        assert_eq!(provider.enclave_type(), EnclaveType::AwsNitro);
        let signer = Pubkey::new_from_array([0x80; 32]);
        let slot_hash = [0x11u8; 32];
        let err = provider.request_attestation(&signer, &slot_hash).await.unwrap_err();
        match err {
            SidecarError::IoctlError(_) => {}
            other => panic!("expected IoctlError, got {other:?}"),
        }
    }

    fn encode_nsm_attestation_response(document: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_cbor_len(&mut out, 5, 1);
        push_cbor_tstr(&mut out, "Attestation");
        push_cbor_len(&mut out, 5, 1);
        push_cbor_tstr(&mut out, "document");
        push_cbor_bstr(&mut out, document);
        out
    }
}
