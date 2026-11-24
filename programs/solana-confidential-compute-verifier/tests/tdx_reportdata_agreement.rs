//! The enclave and the verifier must compute the same `REPORTDATA`.
//!
//! The sidecar asks the hardware to sign a 64-byte commitment; the program
//! recomputes what an honest enclave would have asked for and refuses
//! anything else. If the two preimages drift by a single byte, every genuine
//! quote is rejected -- and the failure looks like bad hardware, not like a
//! code change. Nothing else in either codebase would catch that, because
//! each side is self-consistent.
//!
//! This test is the only place the two implementations meet.
//!
//! @spec SCC-TDX-002

use solana_confidential_compute_sidecar::attestation::intel_tdx::{
    composite_challenge, report_data_commitment,
};
use solana_confidential_compute_verifier::tdx::{expected_report_data, REPORT_DATA_DOMAIN};
use solana_program::pubkey::Pubkey;

/// One set of inputs to the `REPORTDATA` preimage.
struct Vector {
    signer: [u8; 32],
    slot_hash: [u8; 32],
    gpu_rim: [u8; 32],
    model: [u8; 32],
    nonce: [u8; 32],
}

fn vectors() -> Vec<Vector> {
    let make = |signer, slot_hash, gpu_rim, model, nonce| Vector {
        signer,
        slot_hash,
        gpu_rim,
        model,
        nonce,
    };
    vec![
        make([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]),
        make([0x00; 32], [0x00; 32], [0x00; 32], [0x00; 32], [0x00; 32]),
        make([0xff; 32], [0xff; 32], [0xff; 32], [0xff; 32], [0xff; 32]),
        make(
            *b"a-workload-signer-pubkey-32bytes",
            *b"....a-recent-solana-slot-hash...",
            *b"...an-nvidia-h100-gpu-rim-digest",
            *b".....a-model-weights-digest.....",
            [0xa5; 32],
        ),
    ]
}

#[test]
fn the_sidecar_and_the_verifier_agree_on_report_data() {
    for vector in vectors() {
        let Vector {
            signer: signer_bytes,
            slot_hash,
            gpu_rim,
            model,
            nonce,
        } = vector;
        let signer = Pubkey::new_from_array(signer_bytes);

        // What the enclave asks the hardware to sign.
        let composite = composite_challenge(&signer, &slot_hash, &gpu_rim, &model);
        let produced =
            report_data_commitment(&signer, &composite, &slot_hash, &gpu_rim, &model, &nonce);

        // What the on-chain verifier insists it must have been.
        let expected = expected_report_data(&signer_bytes, &slot_hash, &gpu_rim, &model, &nonce);

        assert_eq!(
            produced, expected,
            "sidecar and verifier disagree for signer {}",
            signer
        );
    }
}

/// Every input must change the result, or a field is not really bound.
#[test]
fn each_input_changes_the_commitment() {
    let signer = [0x11u8; 32];
    let slot_hash = [0x22u8; 32];
    let gpu_rim = [0x33u8; 32];
    let model = [0x44u8; 32];
    let nonce = [0x55u8; 32];
    let base = expected_report_data(&signer, &slot_hash, &gpu_rim, &model, &nonce);

    let mut other_signer = signer;
    other_signer[0] ^= 1;
    assert_ne!(
        base,
        expected_report_data(&other_signer, &slot_hash, &gpu_rim, &model, &nonce),
        "a different workload signer must produce different REPORTDATA -- \
         this is the binding the whole design rests on"
    );

    let mut other_slot = slot_hash;
    other_slot[31] ^= 1;
    assert_ne!(
        base,
        expected_report_data(&signer, &other_slot, &gpu_rim, &model, &nonce),
        "freshness must be bound"
    );

    let mut other_gpu = gpu_rim;
    other_gpu[5] ^= 1;
    assert_ne!(
        base,
        expected_report_data(&signer, &slot_hash, &other_gpu, &model, &nonce),
        "the GPU RIM must be bound"
    );

    let mut other_model = model;
    other_model[9] ^= 1;
    assert_ne!(
        base,
        expected_report_data(&signer, &slot_hash, &gpu_rim, &other_model, &nonce),
        "the model digest must be bound"
    );

    let mut other_nonce = nonce;
    other_nonce[0] ^= 1;
    assert_ne!(
        base,
        expected_report_data(&signer, &slot_hash, &gpu_rim, &model, &other_nonce),
        "different challenges sharing a slot hash must require different hardware evidence"
    );
}

/// The domain length is asserted at compile time on both sides against the
/// literal 42. If someone renames the domain, that assertion fires here too.
#[test]
fn the_domain_string_matches_the_sidecars() {
    assert_eq!(
        REPORT_DATA_DOMAIN,
        "solana-confidential-compute/v1/report-data"
    );
    assert_eq!(REPORT_DATA_DOMAIN.len(), 42);
    assert_eq!(
        REPORT_DATA_DOMAIN,
        solana_confidential_compute_sidecar::attestation::intel_tdx::REPORT_DATA_DOMAIN,
        "the two domain constants have drifted"
    );
}

/// A quote is 64 bytes of REPORTDATA; anything shorter is not a commitment.
#[test]
fn the_commitment_is_sha512_wide() {
    let out = expected_report_data(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32]);
    assert_eq!(out.len(), 64);
    assert_ne!(
        out[..32],
        out[32..],
        "a doubled SHA-256 would look like this"
    );
}
