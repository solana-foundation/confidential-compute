//! Intel TDX enrolment pipeline: challenge, read-back, quote, one v1 packet.
//!
//! The submitter used to refuse Intel TDX outright. These tests pin what
//! replaced that refusal: the ordering (challenge is its own, earlier
//! transaction), the shape of the enrolment packet, the fail-closed rules
//! around simulated evidence and a challenge that does not read back as
//! issued, and the quote splitting the SDK's `TdxEnrolment` depends on.
//!
//! @spec SCC-TDX-001 SCC-TDX-002 SCC-TDX-005 SCC-SIDECAR-004

use base64::Engine;
use solana_sdk::message::VersionedMessage;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};

use solana_confidential_compute_sidecar::attestation::intel_tdx::IntelTdxProvider;
use solana_confidential_compute_sidecar::keys::EphemeralKeyManager;
use solana_confidential_compute_sidecar::onchain::{MockCluster, OnchainAttestor};
use solana_confidential_compute_sidecar::tdx_enrolment::{
    decode_challenge_account, dry_run_quote_parts, split_tdx_quote, validate_challenge_readback, ChallengeRecord,
    CHALLENGE_ACCOUNT_LEN, CHALLENGE_DISCRIMINATOR, ISV_SIGNED_LEN, QE_REPORT_LEN,
};
use solana_confidential_compute_sidecar::{AttestationReport, SidecarError};

const CURRENT_SLOT: u64 = 1_000;
/// `get_recent_slot_challenge` targets `current - 5`.
const TARGET_SLOT: u64 = CURRENT_SLOT - 5;
const TARGET_SLOT_HASH: [u8; 32] = [0x5a; 32];
const TDX_SOURCE: u8 = 5;

fn cluster() -> MockCluster {
    MockCluster::new(CURRENT_SLOT, vec![(TARGET_SLOT, TARGET_SLOT_HASH), (TARGET_SLOT - 1, [0x11; 32])])
}

fn attestor(cluster: MockCluster, program_id: Pubkey) -> OnchainAttestor {
    OnchainAttestor::mock(cluster, Some(program_id), Some(Keypair::new()))
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// The whole dry-run pipeline: a challenge packet, then a four-instruction v1
/// enrolment packet, neither of them broadcast.
#[tokio::test]
async fn dry_run_builds_a_challenge_packet_then_a_v1_enrolment_packet() {
    let program_id = Pubkey::new_unique();
    let mock = cluster();
    let onchain = attestor(mock.clone(), program_id);
    let workload = EphemeralKeyManager::new();
    let provider = IntelTdxProvider::new(None, None, true);

    let outcome = onchain.enrol_intel_tdx(&workload, &provider).await.expect("dry-run enrolment");

    // The challenge is a separate, earlier transaction. Merging it would ask
    // the enclave to read an account the same transaction is still writing.
    let legacy = mock.submitted();
    assert_eq!(legacy.len(), 1, "the challenge is its own transaction");
    let challenge_ix = &legacy[0].message.instructions[0];
    assert_eq!(
        &challenge_ix.data[..8],
        &*solana_confidential_compute_sdk::tdx::ISSUE_TDX_CHALLENGE_DISCRIMINATOR,
        "the first transaction is issue_tdx_challenge",
    );
    assert_eq!(
        &challenge_ix.data[8..40],
        &outcome.challenge_nonce,
        "the challenge carries the nonce the pipeline reported",
    );
    assert_eq!(&challenge_ix.data[40..48], &TARGET_SLOT.to_le_bytes());
    assert_eq!(outcome.nonce_slot, TARGET_SLOT);

    // The enrolment is one v1 transaction. No lookup table is involved.
    let versioned = mock.submitted_versioned();
    assert_eq!(versioned.len(), 1, "enrolment is a single transaction");
    let tx = &versioned[0];
    let VersionedMessage::V1(message) = &tx.message else {
        panic!("enrolment must be a v1 message");
    };
    assert_eq!(
        message.instructions.len(),
        4,
        "secp256r1(QE), verify_tdx_qe_report, secp256r1(quote), verify_tdx_quote",
    );
    assert!(
        solana_confidential_compute_sdk::tdx::v1_transaction_size(message)
            <= solana_confidential_compute_sdk::tdx::V1_MAX_TRANSACTION_SIZE,
        "enrolment must fit the v1 packet",
    );
    assert_eq!(
        outcome.enrolment_tx_len,
        solana_confidential_compute_sdk::tdx::v1_transaction_size(message),
        "the reported size is the one that was checked",
    );
    // Recorded so a regression shows up as a number rather than a cluster
    // rejection. The dry-run QE auth data is 32 bytes, matching Intel's.
    //
    // 2,056 rather than the 2,052 this measured before the SDK began filling
    // in the loaded accounts budget. That field is four bytes and leaving it
    // unset is what a cluster rejects, so the four bytes are the point.
    assert_eq!(outcome.enrolment_tx_len, 2056, "enrolment transaction size changed",);

    // Both required keys signed, and the payer is not the workload key.
    assert_eq!(tx.signatures.len(), 2);
    assert!(tx.signatures.iter().all(|s| s != &Signature::default()));

    assert_eq!(
        outcome.attested_signer,
        solana_confidential_compute_sdk::tdx::derive_attested_signer_pda(&program_id, &workload.pubkey()).0,
        "the outcome names the AttestedSigner PDA a Solscan link would point at",
    );
}

/// The nonce selects the challenge PDA on its own, so it must not be derived
/// from the slot hash: two workloads picking the same recent slot would then
/// collide on one PDA, and `issue_tdx_challenge` refuses to reissue over a
/// live or consumed record.
#[tokio::test]
async fn the_challenge_nonce_is_fresh_and_is_not_the_slot_hash() {
    let program_id = Pubkey::new_unique();
    let provider = IntelTdxProvider::new(None, None, true);

    let first = attestor(cluster(), program_id)
        .enrol_intel_tdx(&EphemeralKeyManager::new(), &provider)
        .await
        .expect("first enrolment");
    let second = attestor(cluster(), program_id)
        .enrol_intel_tdx(&EphemeralKeyManager::new(), &provider)
        .await
        .expect("second enrolment");

    assert_ne!(first.challenge_nonce, TARGET_SLOT_HASH);
    assert_ne!(
        first.challenge_nonce, second.challenge_nonce,
        "two enrolments against the same slot must not collide on one PDA",
    );
    assert_ne!(
        solana_confidential_compute_sdk::tdx::derive_tdx_challenge_pda(&program_id, &first.challenge_nonce).0,
        solana_confidential_compute_sdk::tdx::derive_tdx_challenge_pda(&program_id, &second.challenge_nonce).0,
    );
}

/// The arm that used to return "this submitter does not implement yet".
#[tokio::test]
async fn submit_attestation_no_longer_refuses_intel_tdx() {
    let onchain = attestor(cluster(), Pubkey::new_unique());
    let workload = EphemeralKeyManager::new();
    let report = IntelTdxProvider::new(None, None, true)
        .request_attestation_for_challenge(&workload.pubkey(), &TARGET_SLOT_HASH, &[0x42; 32])
        .await
        .expect("synthetic report");

    let expires_slot = onchain
        .submit_attestation(&workload, TARGET_SLOT, &report)
        .await
        .expect("Intel TDX submission must no longer be refused");
    assert!(expires_slot > CURRENT_SLOT);
}

/// Simulated evidence must never reach a live cluster. The refusal happens
/// before the challenge transaction, so no nonce is burned and no socket is
/// opened -- the RPC URL below is deliberately unreachable.
#[tokio::test]
async fn live_mode_refuses_a_simulated_provider_before_broadcasting() {
    let onchain = OnchainAttestor::new("http://127.0.0.1:1", Some(Pubkey::new_unique()), Some(Keypair::new()), false);
    let error = onchain
        .enrol_intel_tdx(&EphemeralKeyManager::new(), &IntelTdxProvider::new(None, None, true))
        .await
        .expect_err("a simulated provider must not enrol live");
    assert!(matches!(error, SidecarError::InvalidConfig(_)), "expected a fail-closed config refusal, got {error:?}",);
}

/// A dry run with no payer still refuses rather than building half a pipeline.
#[tokio::test]
async fn enrolment_without_a_payer_is_refused() {
    let onchain = OnchainAttestor::mock(cluster(), Some(Pubkey::new_unique()), None);
    let error = onchain
        .enrol_intel_tdx(&EphemeralKeyManager::new(), &IntelTdxProvider::new(None, None, true))
        .await
        .expect_err("no payer");
    assert!(matches!(error, SidecarError::OnchainError(_)));
}

/// A live provider with no measured GPU RIM or model digest cannot name the
/// two digests the QE instruction binds, so it fails closed.
#[tokio::test]
async fn a_live_provider_without_binding_digests_fails_closed() {
    let report = IntelTdxProvider::new(None, None, false)
        .request_attestation_for_challenge(&Pubkey::new_unique(), &TARGET_SLOT_HASH, &[1; 32])
        .await;
    assert!(matches!(report, Err(SidecarError::TdxAttestationFailed)));
}

// ---------------------------------------------------------------------------
// Challenge read-back
// ---------------------------------------------------------------------------

fn encoded_challenge(record: &ChallengeRecord) -> Vec<u8> {
    let mut data = Vec::with_capacity(CHALLENGE_ACCOUNT_LEN);
    data.extend_from_slice(&CHALLENGE_DISCRIMINATOR);
    data.push(record.source);
    data.extend_from_slice(&record.challenge_slot.to_le_bytes());
    data.extend_from_slice(&record.slot_hash);
    data.extend_from_slice(&record.nonce);
    data.extend_from_slice(&record.expires_slot.to_le_bytes());
    data.push(record.bump);
    data
}

fn issued_record() -> ChallengeRecord {
    ChallengeRecord {
        source: TDX_SOURCE,
        challenge_slot: TARGET_SLOT,
        slot_hash: TARGET_SLOT_HASH,
        nonce: [0xab; 32],
        expires_slot: CURRENT_SLOT + 1_500,
        bump: 254,
    }
}

#[test]
fn challenge_account_decodes_at_the_programs_offsets() {
    let record = issued_record();
    let decoded = decode_challenge_account(&encoded_challenge(&record)).expect("decode");
    assert_eq!(decoded, record);
    assert!(!decoded.is_consumed());

    let mut wrong_discriminator = encoded_challenge(&record);
    wrong_discriminator[0] ^= 0xff;
    assert!(decode_challenge_account(&wrong_discriminator).is_err());
    assert!(decode_challenge_account(&encoded_challenge(&record)[..40]).is_err());
}

#[test]
fn a_challenge_that_does_not_read_back_as_issued_is_refused() {
    let issued = issued_record();
    let ok = |record: &ChallengeRecord| {
        validate_challenge_readback(record, TDX_SOURCE, &issued.nonce, issued.challenge_slot, &issued.slot_hash)
    };
    ok(&issued).expect("the record as issued is accepted");

    let cases = [
        ChallengeRecord { nonce: [0xcd; 32], ..issued },
        ChallengeRecord { challenge_slot: issued.challenge_slot + 1, ..issued },
        ChallengeRecord { slot_hash: [0x77; 32], ..issued },
        ChallengeRecord { source: 4, ..issued },
        // Tombstoned by a quote that was already accepted against it.
        ChallengeRecord { expires_slot: 0, ..issued },
    ];
    for (index, case) in cases.iter().enumerate() {
        assert!(ok(case).is_err(), "case {index} should have been refused before a quote was requested",);
    }
}

// ---------------------------------------------------------------------------
// Quote splitting
// ---------------------------------------------------------------------------

const INTEL_QE_VENDOR_ID: [u8; 16] =
    [0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07];
/// `SubjectPublicKeyInfo` for `id-ecPublicKey` over `prime256v1`, through the
/// `0x04` uncompressed-point tag.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

struct QuoteFixture {
    raw: Vec<u8>,
    attestation_pubkey_xy: [u8; 64],
    qe_report: Vec<u8>,
    qe_report_signature: [u8; 64],
    qe_auth_data: Vec<u8>,
    isv_signature: [u8; 64],
    pck_xy: [u8; 64],
}

/// A byte-exact v4 quote. The cryptography is nonsense -- nothing here
/// verifies a signature -- but every offset the splitter reads is real.
fn quote_fixture(cert_data_type: u16) -> QuoteFixture {
    let attestation_pubkey_xy = [0x21u8; 64];
    let qe_report: Vec<u8> = (0..QE_REPORT_LEN).map(|i| (i % 251) as u8).collect();
    let qe_report_signature = [0x33u8; 64];
    let qe_auth_data = vec![0x44u8; 32];
    let isv_signature = [0x55u8; 64];
    let mut pck_xy = [0x66u8; 64];
    pck_xy[63] = 0x01; // odd Y, so the compressed prefix must be 0x03

    // A certificate body that carries the leaf key. The splitter scans for the
    // SPKI prefix rather than parsing X.509, so leading bytes must not fool it.
    let mut der = vec![0x30, 0x82, 0x01, 0x00, 0xA0, 0x03, 0x02, 0x01, 0x02];
    der.extend_from_slice(&P256_SPKI_PREFIX);
    der.extend_from_slice(&pck_xy);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&der)
    );

    let cert_start = 1220 + qe_auth_data.len();
    let total = cert_start + 6 + pem.len();
    let mut raw = vec![0u8; total];

    raw[0..2].copy_from_slice(&4u16.to_le_bytes()); // version
    raw[2..4].copy_from_slice(&2u16.to_le_bytes()); // ECDSA P-256
    raw[4..8].copy_from_slice(&0x0000_0081u32.to_le_bytes()); // TDX
    raw[12..28].copy_from_slice(&INTEL_QE_VENDOR_ID);
    // Mark the signed region so the test can tell it apart from padding.
    raw[600..632].copy_from_slice(&[0x99u8; 32]);
    raw[632..636].copy_from_slice(&((total - 636) as u32).to_le_bytes());
    raw[636..700].copy_from_slice(&isv_signature);
    raw[700..764].copy_from_slice(&attestation_pubkey_xy);
    raw[770..770 + QE_REPORT_LEN].copy_from_slice(&qe_report);
    raw[1154..1218].copy_from_slice(&qe_report_signature);
    raw[1218..1220].copy_from_slice(&(qe_auth_data.len() as u16).to_le_bytes());
    raw[1220..cert_start].copy_from_slice(&qe_auth_data);
    raw[cert_start..cert_start + 2].copy_from_slice(&cert_data_type.to_le_bytes());
    raw[cert_start + 2..cert_start + 6].copy_from_slice(&(pem.len() as u32).to_le_bytes());
    raw[cert_start + 6..].copy_from_slice(pem.as_bytes());

    QuoteFixture { raw, attestation_pubkey_xy, qe_report, qe_report_signature, qe_auth_data, isv_signature, pck_xy }
}

#[test]
fn a_v4_quote_splits_into_the_pieces_the_enrolment_needs() {
    let fixture = quote_fixture(5);
    let parts = split_tdx_quote(&fixture.raw).expect("split");

    assert_eq!(parts.isv_signed.len(), ISV_SIGNED_LEN);
    assert_eq!(&parts.isv_signed[..], &fixture.raw[..ISV_SIGNED_LEN]);
    assert_eq!(parts.isv_signature, fixture.isv_signature);
    assert_eq!(parts.attestation_pubkey_xy, fixture.attestation_pubkey_xy);
    assert_eq!(parts.qe_report.len(), QE_REPORT_LEN);
    assert_eq!(parts.qe_report, fixture.qe_report);
    assert_eq!(parts.qe_report_signature, fixture.qe_report_signature);
    assert_eq!(parts.qe_auth_data, fixture.qe_auth_data);

    // The PCK leaf key is SEC1-compressed, and the parity bit comes from Y.
    assert_eq!(parts.pck_pubkey[0], 0x03);
    assert_eq!(&parts.pck_pubkey[1..], &fixture.pck_xy[..32]);
}

#[test]
fn split_rejects_quotes_the_program_would_also_reject() {
    let good = quote_fixture(5);

    let mut wrong_version = good.raw.clone();
    wrong_version[0..2].copy_from_slice(&3u16.to_le_bytes());
    assert!(split_tdx_quote(&wrong_version).is_err());

    let mut wrong_tee = good.raw.clone();
    wrong_tee[4..8].copy_from_slice(&0u32.to_le_bytes());
    assert!(split_tdx_quote(&wrong_tee).is_err());

    let mut wrong_key_type = good.raw.clone();
    wrong_key_type[2..4].copy_from_slice(&3u16.to_le_bytes());
    assert!(split_tdx_quote(&wrong_key_type).is_err());

    let mut wrong_vendor = good.raw.clone();
    wrong_vendor[12] ^= 0xff;
    assert!(split_tdx_quote(&wrong_vendor).is_err());

    assert!(split_tdx_quote(&good.raw[..1000]).is_err());

    // Without a PCK certificate chain there is no leaf key to name on chain.
    assert!(split_tdx_quote(&quote_fixture(1).raw).is_err());

    // Synthetic dry-run evidence is not a quote and must not parse as one.
    let synthetic = IntelTdxProvider::new(None, None, true);
    let report = futures_block_on(synthetic.request_attestation_for_challenge(
        &Pubkey::new_unique(),
        &TARGET_SLOT_HASH,
        &[7; 32],
    ))
    .expect("synthetic report");
    let AttestationReport::IntelTdx { quote, .. } = report else {
        panic!("expected a TDX report");
    };
    assert!(split_tdx_quote(&quote).is_err());
}

/// Dry-run placeholders exist to make the packet buildable and measurable.
/// They must be the right shape, and they must name the key the dry run was
/// about rather than being uniformly zero.
#[test]
fn dry_run_parts_are_correctly_shaped_and_carry_the_report_data() {
    let report_data: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let parts = dry_run_quote_parts(&report_data);

    assert_eq!(parts.isv_signed.len(), ISV_SIGNED_LEN);
    assert_eq!(parts.qe_report.len(), QE_REPORT_LEN);
    assert!(parts.pck_pubkey[0] == 0x02 || parts.pck_pubkey[0] == 0x03);
    // `header (48) || Td10ReportBody`, with `report_data` at body offset 520.
    assert_eq!(&parts.isv_signed[48 + 520..48 + 520 + 64], &report_data);
}

/// `tokio::test` is not available to the plain `#[test]` above.
fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(future)
}
