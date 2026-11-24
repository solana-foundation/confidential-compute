//! NVIDIA H100 Confidential GPU Provider and Nonce Tests
//!
//! @spec SCC-NVIDIA-001 SCC-NVIDIA-002 SCC-NVIDIA-005

use clap::Parser;
use solana_confidential_compute_core::types::EnclaveType;
use solana_confidential_compute_sidecar::attestation::nvidia_h100::{
    compute_composite_nonce, NvidiaH100Provider, DEFAULT_H100_GOLDEN_RIM,
};
use solana_confidential_compute_sidecar::attestation::{AttestationProvider, AttestationReport};
use solana_confidential_compute_sidecar::{EnclaveMode, SidecarConfig, SidecarError};
use solana_sdk::pubkey::Pubkey;

#[tokio::test]
async fn test_nvidia_h100_simulated_attestation() {
    let provider = NvidiaH100Provider::new(None, true);
    assert_eq!(provider.enclave_type(), EnclaveType::NvidiaGpu);

    let workload_signer = Pubkey::new_unique();
    let slot_hash = [0x5au8; 32];

    let report = provider
        .request_attestation(&workload_signer, &slot_hash)
        .await
        .expect("Attestation request should succeed in simulation mode");

    match report {
        AttestationReport::NvidiaH100 {
            composite_report,
            gpu_measurement,
            spdm_report,
        } => {
            assert_eq!(gpu_measurement, DEFAULT_H100_GOLDEN_RIM);
            let expected_nonce =
                compute_composite_nonce(&workload_signer, &DEFAULT_H100_GOLDEN_RIM, &slot_hash);
            assert_eq!(composite_report, expected_nonce.to_vec());
            assert!(spdm_report.starts_with(b"NVIDIA-SPDM-v1.2"));
        }
        _ => panic!("Expected NvidiaH100 report variant"),
    }
}

#[tokio::test]
async fn test_nvidia_h100_live_path_fails_closed() {
    let provider = NvidiaH100Provider::default();
    let workload_signer = Pubkey::new_unique();
    let slot_hash = [0x5au8; 32];
    let err = provider
        .request_attestation(&workload_signer, &slot_hash)
        .await
        .expect_err("non-simulated appraisal must fail closed");
    assert!(matches!(
        err,
        solana_confidential_compute_sidecar::SidecarError::GpuAttestationFailed
    ));
}

#[test]
fn test_composite_nonce_binding_properties() {
    let signer_a = Pubkey::new_unique();
    let signer_b = Pubkey::new_unique();
    let gpu_rim_a = [0x11u8; 32];
    let gpu_rim_b = [0x22u8; 32];
    let slot_hash_1 = [0xa1u8; 32];
    let slot_hash_2 = [0xb2u8; 32];

    let nonce_base = compute_composite_nonce(&signer_a, &gpu_rim_a, &slot_hash_1);

    // Nonce must be deterministic
    assert_eq!(
        nonce_base,
        compute_composite_nonce(&signer_a, &gpu_rim_a, &slot_hash_1)
    );

    // Any change to signer, GPU measurement, or slot hash must yield a distinct nonce
    assert_ne!(
        nonce_base,
        compute_composite_nonce(&signer_b, &gpu_rim_a, &slot_hash_1)
    );
    assert_ne!(
        nonce_base,
        compute_composite_nonce(&signer_a, &gpu_rim_b, &slot_hash_1)
    );
    assert_ne!(
        nonce_base,
        compute_composite_nonce(&signer_a, &gpu_rim_a, &slot_hash_2)
    );
}

#[test]
fn nvidia_gpu_mode_is_selectable_and_simulated_live_is_rejected() {
    let by_name = SidecarConfig::try_parse_from([
        "solana-confidential-compute-sidecar",
        "--enclave-mode",
        "nvidia-gpu",
    ])
    .expect("nvidia-gpu");
    assert_eq!(by_name.enclave_mode, EnclaveMode::NvidiaGpu);
    assert!(by_name.dry_run);
    assert!(by_name.fail_closed_live_mock().is_ok());

    let by_alias = SidecarConfig::try_parse_from([
        "solana-confidential-compute-sidecar",
        "--enclave-mode",
        "nvidia",
        "--dry-run",
        "false",
    ])
    .expect("nvidia alias");
    assert_eq!(by_alias.enclave_mode, EnclaveMode::NvidiaGpu);
    assert!(!by_alias.dry_run);
    assert!(by_alias.fail_closed_live_mock().is_ok());

    let simulated = NvidiaH100Provider::new(None, true);
    let err = simulated
        .reject_simulated_live(false)
        .expect_err("simulated evidence is not a live provider");
    assert!(matches!(err, SidecarError::InvalidConfig(_)));
    assert!(simulated.reject_simulated_live(true).is_ok());

    let live = NvidiaH100Provider::for_daemon(false).expect("live appraiser");
    assert!(live.reject_simulated_live(false).is_ok());
    let dry = NvidiaH100Provider::for_daemon(true).expect("dry-run provider");
    assert!(dry.reject_simulated_live(true).is_ok());
}

#[tokio::test]
async fn daemon_provider_follows_dry_run() {
    let live = NvidiaH100Provider::for_daemon(false).expect("live");
    let err = live
        .request_attestation(&Pubkey::new_unique(), &[0x5a; 32])
        .await
        .expect_err("live appraisal fails closed");
    assert!(matches!(err, SidecarError::GpuAttestationFailed));

    let dry = NvidiaH100Provider::for_daemon(true).expect("dry-run");
    let report = dry
        .request_attestation(&Pubkey::new_unique(), &[0x5a; 32])
        .await
        .expect("dry-run construction");
    match report {
        AttestationReport::NvidiaH100 {
            gpu_measurement, ..
        } => assert_eq!(gpu_measurement, DEFAULT_H100_GOLDEN_RIM),
        _ => panic!("Expected NvidiaH100 report variant"),
    }
}
