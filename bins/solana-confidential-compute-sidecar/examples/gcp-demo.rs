//! Manual Milan SEV-SNP demo. Hardware/RPC/KDS access happens only on explicit CLI use.
//! Offline verification authenticates the report and certificate, not capture-time metadata
//! or the continued possession of a sidecar key. No private keys are written to artifacts.
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_confidential_compute_core::SnpReportView;
use solana_confidential_compute_sidecar::{
    attestation::sev_snp::SevSnpProvider, AttestationProvider, AttestationReport, EphemeralKeyManager, OnchainAttestor,
};
use solana_sdk::{
    hash::{hash, Hash},
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
};
use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ASK: &[u8] = include_bytes!("../../../crates/solana-confidential-compute-crypto/tests/data/milan_ask.der");
const ACTION_DISCRIMINATOR: &[u8] = b"gcp-demo";
const ACTION_DATA: &[u8] = b"manual packet-limit demonstration";

#[derive(Parser)]
#[command(
    about = "Manual GCP Milan SNP demo; requires openssl and real SNP hardware",
    long_about = "Manual GCP Milan SNP demo. Capture/enrollment use real /dev/sev-guest, RPC and AMD KDS. Verify is offline. Enrollment defaults to a local dry-run, never an active session. Live submission requires an explicit funded payer, configured verifier policy and pre-registered VCEK. The #265 P384 runtime blocker is not bypassed. Mode A only enrolls and checks the confirmed record; it does not execute a consumer action. Mode B exits blocked on the public SDK packet limit without broadcasting."
)]
struct Cli {
    #[arg(long, global = true, default_value = "https://api.devnet.solana.com")]
    rpc_url: String,
    #[arg(long, global = true, default_value = "http://127.0.0.1:8080")]
    sidecar_url: String,
    #[command(subcommand)]
    command: DemoCommand,
}

#[derive(Subcommand)]
enum DemoCommand {
    /// Capture and locally verify a real report bound to the sidecar's current public key.
    Capture {
        #[arg(long, default_value = "/var/lib/confidential-compute/demo")]
        out_dir: PathBuf,
    },
    /// Verify report.bin, vcek.der and manifest.json offline using the current certificate clock.
    Verify {
        #[arg(long)]
        artifacts: PathBuf,
    },
    /// Enroll a separate ephemeral RAM key; dry-run unless --submit is explicit.
    Enroll(Enrollment),
    /// Enroll and read confirmed deadlines; no consumer spending or end-to-end claim.
    ModeA(Enrollment),
    /// Collect an action-bound real report; demonstrate PacketTooLarge without broadcasting.
    ModeB {
        #[arg(long)]
        program_id: Pubkey,
        #[arg(long)]
        consumer_program_id: Pubkey,
        #[arg(long)]
        payer: Option<PathBuf>,
    },
}

#[derive(Args)]
struct Enrollment {
    #[arg(long)]
    program_id: Pubkey,
    #[arg(long, required_if_eq("submit", "true"))]
    payer: Option<PathBuf>,
    /// Explicit opt-in to funded on-chain submission. No runtime/security bypass.
    #[arg(long)]
    submit: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    report_file: String,
    vcek_file: String,
    public_key: String,
    nonce: [u8; 32],
    nonce_slot: u64,
    /// Informational local capture time; not signed by AMD and not freshness proof.
    captured_unix: u64,
    measurement_hex: String,
    chip_id_hex: String,
    reported_tcb: u64,
    report_sha256: String,
    vcek_sha256: String,
    certificate_valid_until_unix: u64,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// OpenSSL performs certificate/SPKI parsing. The result is only a candidate key;
/// solana_confidential_compute_crypto authenticates the complete leaf and compares the actual SPKI key.
fn vcek_key(der: &[u8]) -> Result<[u8; 96]> {
    let pem = openssl(&["x509", "-inform", "DER", "-pubkey", "-noout"], der)?;
    let spki = openssl(&["pkey", "-pubin", "-outform", "DER"], &pem)?;
    // Canonical DER: id-ecPublicKey + secp384r1 + BIT STRING uncompressed point.
    const PREFIX: &[u8] = &[
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
        0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
    ];
    if spki.len() != PREFIX.len() + 96 || !spki.starts_with(PREFIX) {
        return Err("OpenSSL VCEK output is not a canonical uncompressed P-384 SPKI".into());
    }
    Ok(spki[PREFIX.len()..].try_into()?)
}

fn openssl(args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut child = ProcessCommand::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("openssl is required for public certificate parsing: {e}"))?;
    child.stdin.take().ok_or("openssl stdin unavailable")?.write_all(input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(
            format!("openssl public certificate parsing failed: {}", String::from_utf8_lossy(&output.stderr)).into()
        );
    }
    Ok(output.stdout)
}

fn verify_report(report: &[u8], vcek: &[u8], pubkey: &Pubkey, nonce: &[u8; 32], at: u64) -> Result<u64> {
    let view = SnpReportView::try_from_slice(report)?;
    view.validate_security_invariants()?;
    if view.key_sel() != 0 || view.is_vlek() {
        return Err("only Milan VCEK reports are supported; VLEK/masked-chip reports are unsupported".into());
    }
    let xy = vcek_key(vcek)?;
    let deadline = solana_confidential_compute_crypto::validate_vcek_chain_at(&[0; 96], ASK, vcek, &xy, at)?;
    let identity = solana_confidential_compute_crypto::parse_vcek_identity(vcek)?;
    if identity.subject_is_vlek || identity.chip_id != *view.chip_id() || identity.tcb_version != view.reported_tcb() {
        return Err("VCEK chip/TCB identity does not match report".into());
    }
    if view.pubkey() != pubkey.to_bytes() || view.nonce() != *nonce {
        return Err("report workload public key or nonce binding mismatch".into());
    }
    let mut rs = [0; 96];
    rs[..48].copy_from_slice(&view.signature_r_be()?);
    rs[48..].copy_from_slice(&view.signature_s_be()?);
    if !solana_confidential_compute_crypto::verify_snp_report_signature(&xy, view.signed_body(), &rs)? {
        return Err("SNP report signature verification failed".into());
    }
    Ok(deadline)
}

fn kds_url(view: &SnpReportView<'_>) -> Result<String> {
    if view.key_sel() != 0 || view.is_vlek() {
        return Err("AMD Milan KDS requires a nonzero VCEK chip identity; VLEK is unsupported".into());
    }
    let t = view.reported_tcb_components();
    Ok(format!(
        "https://kdsintf.amd.com/vcek/v1/Milan/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        hex(view.chip_id()),
        t[0],
        t[1],
        t[6],
        t[7]
    ))
}

async fn genuine_report(pubkey: &Pubkey, nonce: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    let AttestationReport::SevSnp { report, .. } = SevSnpProvider::default().request_attestation(pubkey, nonce).await?
    else {
        return Err("SNP provider returned a non-SNP report".into());
    };
    let url = kds_url(&SnpReportView::try_from_slice(&report)?)?;
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    // Endorsement certificates are small; never accept an unbounded KDS body.
    let mut response = response;
    let mut vcek = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if vcek.len() + chunk.len() > 16_384 {
            return Err("AMD KDS certificate exceeds 16 KiB".into());
        }
        vcek.extend_from_slice(&chunk);
    }
    let deadline = verify_report(&report, &vcek, pubkey, nonce, now()?)?;
    Ok((report, vcek, deadline))
}

fn make_manifest(report: &[u8], vcek: &[u8], nonce_slot: u64, deadline: u64) -> Result<Manifest> {
    let view = SnpReportView::try_from_slice(report)?;
    Ok(Manifest {
        schema_version: 1,
        report_file: "report.bin".into(),
        vcek_file: "vcek.der".into(),
        public_key: Pubkey::new_from_array(view.pubkey()).to_string(),
        nonce: view.nonce(),
        nonce_slot,
        captured_unix: now()?,
        measurement_hex: hex(&view.measurement()),
        chip_id_hex: hex(view.chip_id()),
        reported_tcb: view.reported_tcb(),
        report_sha256: hash(report).to_string(),
        vcek_sha256: hash(vcek).to_string(),
        certificate_valid_until_unix: deadline,
    })
}

fn verify_artifacts(path: &Path) -> Result<()> {
    verify_artifacts_at(path, now()?)
}

fn verify_artifacts_at(path: &Path, at: u64) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(&fs::read(path.join("manifest.json"))?)?;
    if manifest.schema_version != 1 || manifest.report_file != "report.bin" || manifest.vcek_file != "vcek.der" {
        return Err("unsupported artifact manifest schema/filenames".into());
    }
    let report = fs::read(path.join("report.bin"))?;
    let vcek = fs::read(path.join("vcek.der"))?;
    let view = SnpReportView::try_from_slice(&report)?;
    if manifest.report_sha256 != hash(&report).to_string()
        || manifest.vcek_sha256 != hash(&vcek).to_string()
        || manifest.measurement_hex != hex(&view.measurement())
        || manifest.chip_id_hex != hex(view.chip_id())
        || manifest.reported_tcb != view.reported_tcb()
    {
        return Err("artifact manifest does not match report/certificate bytes".into());
    }
    let deadline = verify_report(&report, &vcek, &manifest.public_key.parse()?, &manifest.nonce, at)?;
    if manifest.certificate_valid_until_unix != deadline {
        return Err("manifest certificate deadline mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({"result":"verified_offline", "public_key":manifest.public_key, "nonce":manifest.nonce, "measurement_hex":manifest.measurement_hex, "certificate_valid_until_unix":deadline, "note":"Authenticated Milan report and certificate; manifest capture time/slot are informational, offline verification does not establish chain freshness or an active session."})
    );
    Ok(())
}

fn payer(path: Option<&Path>, submit: bool) -> Result<Keypair> {
    match path {
        Some(path) => {
            read_keypair_file(path).map_err(|e| format!("failed to read payer {}: {e}", path.display()).into())
        }
        None if submit => Err("--submit requires --payer PATH to an explicitly funded payer".into()),
        None => Ok(Keypair::new()),
    }
}

async fn live_prerequisites(rpc_url: &str, program: &Pubkey, payer: &Pubkey, report: &[u8]) -> Result<()> {
    let rpc = RpcClient::new_with_commitment(rpc_url.into(), CommitmentConfig::confirmed());
    if !rpc.get_account(program).await.map_err(|e| format!("verifier program missing: {e}"))?.executable {
        return Err("--program-id is not an executable verifier".into());
    }
    if rpc.get_balance(payer).await? == 0 {
        return Err("live submission requires a funded --payer; no automatic funding is performed".into());
    }
    let client = solana_confidential_compute_sdk::ConfidentialComputeClient::new(*program);
    let view = SnpReportView::try_from_slice(report)?;
    let registry = client.derive_policy_registry_pda().0;
    let vcek = client.derive_vcek_pda(&hash(view.chip_id()).to_bytes(), view.reported_tcb()).0;
    for (label, key) in [("configured verifier policy", registry), ("pre-registered VCEK", vcek)] {
        let account =
            rpc.get_account(&key).await.map_err(|e| format!("live prerequisite absent: {label} at {key}: {e}"))?;
        if account.owner != *program || account.data.is_empty() {
            return Err(format!("live prerequisite invalid: {label} at {key}; configure it before --submit").into());
        }
    }
    // Full policy, cache expiry/revocation and measurement checks remain the verifier's job.
    Ok(())
}

async fn enroll(rpc_url: &str, args: Enrollment) -> Result<()> {
    let payer = payer(args.payer.as_deref(), args.submit)?;
    let payer_pubkey = payer.pubkey();
    let keys = EphemeralKeyManager::new();
    let onchain = OnchainAttestor::new(rpc_url, Some(args.program_id), Some(payer), !args.submit);
    let (slot, nonce) = onchain.get_recent_slot_challenge().await?;
    let (report, vcek, _) = genuine_report(&keys.pubkey(), &nonce).await?;
    if args.submit {
        live_prerequisites(rpc_url, &args.program_id, &payer_pubkey, &report).await?;
    }
    onchain.submit_attestation(&keys, slot, &AttestationReport::SevSnp { report, vcek_cert: Some(vcek) })
        .await.map_err(|e| format!("enrollment failed: {e}. No P384 runtime bypass is attempted; stock validator #265 support remains a prerequisite. Mode A does not prove consumer execution."))?;
    if args.submit {
        let s = onchain.confirmed_session(&keys.pubkey()).await?;
        if !s.is_valid() {
            return Err("confirmed session is expired".into());
        }
        println!(
            "{}",
            serde_json::json!({"result":"registered", "public_key":keys.pubkey().to_string(), "registered_slot":s.registered_slot,"expires_slot":s.expires_slot,"expires_unix_timestamp":s.expires_unix_timestamp, "current_slot":s.current_slot,"current_unix_timestamp":s.current_unix_timestamp,"note":"Enrollment and confirmed record only; no consumer action. Ephemeral key is discarded when this command exits."})
        );
    } else {
        println!(
            "{}",
            serde_json::json!({"result":"simulated", "active":false, "public_key":keys.pubkey().to_string(),"nonce_slot":slot,"note":"Locally verified hardware report and signed dry-run registration; no broadcast, no chain session. Ephemeral workload key and throwaway payer are not saved."})
        );
    }
    Ok(())
}

fn mode_b_packet(program: &Pubkey, consumer: &Pubkey, payer: &Pubkey, report: &[u8], slot: u64) -> Result<()> {
    let view = SnpReportView::try_from_slice(report)?;
    let action_hash = solana_confidential_compute_sdk::hash_action(ACTION_DISCRIMINATOR, &[], ACTION_DATA);
    let consumer_ix =
        Instruction { program_id: *consumer, accounts: vec![], data: [ACTION_DISCRIMINATOR, ACTION_DATA].concat() };
    match solana_confidential_compute_sdk::build_atomic_attestation_tx_for_program(program, payer, consumer, action_hash, view.measurement(), report, consumer_ix, Hash::default(), slot) {
        Err(solana_confidential_compute_sdk::SdkError::PacketTooLarge { len }) => Err(format!("BLOCKED: PacketTooLarge: serialized Mode B transaction is {len} bytes (limit 1232). Public SDK refused it; nothing broadcast. This is not a positive end-to-end consumer demonstration.").into()),
        Err(e) => Err(e.into()),
        Ok(_) => Err("unexpected Mode B packet fit; demo intentionally never broadcasts".into()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        DemoCommand::Verify { artifacts } => verify_artifacts(&artifacts),
        DemoCommand::Capture { out_dir } => {
            let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
            let status: serde_json::Value = client
                .get(format!("{}/v1/status", cli.sidecar_url.trim_end_matches('/')))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let public_key: Pubkey =
                status.get("public_key").and_then(|v| v.as_str()).ok_or("sidecar status has no public_key")?.parse()?;
            let onchain = OnchainAttestor::new(&cli.rpc_url, None, None, true);
            let (slot, nonce) = onchain.get_recent_slot_challenge().await?;
            let (report, vcek, deadline) = genuine_report(&public_key, &nonce).await?;
            let manifest = make_manifest(&report, &vcek, slot, deadline)?;
            fs::create_dir_all(&out_dir)?;
            fs::write(out_dir.join("report.bin"), report)?;
            fs::write(out_dir.join("vcek.der"), vcek)?;
            fs::write(out_dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
            println!("Captured and locally verified public artifacts in {}", out_dir.display());
            Ok(())
        }
        DemoCommand::Enroll(args) | DemoCommand::ModeA(args) => enroll(&cli.rpc_url, args).await,
        DemoCommand::ModeB { program_id, consumer_program_id, payer: payer_path } => {
            let payer = payer(payer_path.as_deref(), false)?;
            let keys = EphemeralKeyManager::new();
            let onchain = OnchainAttestor::new(&cli.rpc_url, Some(program_id), None, true);
            let (slot, slot_hash) = onchain.get_recent_slot_challenge().await?;
            let action = solana_confidential_compute_sdk::hash_action(ACTION_DISCRIMINATOR, &[], ACTION_DATA);
            let nonce = solana_confidential_compute_sdk::compute_commitment(&slot_hash, &action, &consumer_program_id);
            let (report, _, _) = genuine_report(&keys.pubkey(), &nonce).await?;
            mode_b_packet(&program_id, &consumer_program_id, &payer.pubkey(), &report, slot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const REPORT: &[u8] = include_bytes!("../../../fixtures/snp_hardware_report_milan.bin");
    const VCEK: &[u8] = include_bytes!("../../../fixtures/vcek_milan.der");
    // Fixed clock is fixture verification only. CLI verify always uses SystemTime.
    const FIXTURE_TIME: u64 = 1_800_000_000;

    #[test]
    fn authentic_milan_and_tampering() {
        let view = SnpReportView::try_from_slice(REPORT).unwrap();
        let key = Pubkey::new_from_array(view.pubkey());
        assert!(verify_report(REPORT, VCEK, &key, &view.nonce(), FIXTURE_TIME).is_ok());
        let mut tampered = REPORT.to_vec();
        tampered[0x90] ^= 1;
        assert!(verify_report(&tampered, VCEK, &key, &view.nonce(), FIXTURE_TIME).is_err());
        assert!(verify_report(REPORT, VCEK, &Pubkey::new_unique(), &view.nonce(), FIXTURE_TIME).is_err());
        let mut nonce = view.nonce();
        nonce[0] ^= 1;
        assert!(verify_report(REPORT, VCEK, &key, &nonce, FIXTURE_TIME).is_err());
        let mut tcb = REPORT.to_vec();
        tcb[0x180] ^= 1;
        let err = verify_report(&tcb, VCEK, &key, &view.nonce(), FIXTURE_TIME).unwrap_err();
        assert!(err.to_string().contains("chip/TCB"));
        assert!(verify_report(REPORT, VCEK, &key, &view.nonce(), 0).is_err());
    }

    #[test]
    fn offline_artifacts_accept_fixture_and_reject_modified_files() {
        let path = std::env::temp_dir().join(format!("solana-cc-gcp-demo-{}", Pubkey::new_unique()));
        fs::create_dir(&path).unwrap();
        let view = SnpReportView::try_from_slice(REPORT).unwrap();
        let deadline =
            verify_report(REPORT, VCEK, &Pubkey::new_from_array(view.pubkey()), &view.nonce(), FIXTURE_TIME).unwrap();
        let manifest = make_manifest(REPORT, VCEK, 1, deadline).unwrap();
        fs::write(path.join("report.bin"), REPORT).unwrap();
        fs::write(path.join("vcek.der"), VCEK).unwrap();
        fs::write(path.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(verify_artifacts_at(&path, FIXTURE_TIME).is_ok());
        let mut tampered = REPORT.to_vec();
        tampered[0x90] ^= 1;
        fs::write(path.join("report.bin"), tampered).unwrap();
        assert!(verify_artifacts_at(&path, FIXTURE_TIME).is_err());
        fs::write(path.join("report.bin"), REPORT).unwrap();
        let mut bad_manifest = manifest;
        bad_manifest.public_key = Pubkey::new_unique().to_string();
        fs::write(path.join("manifest.json"), serde_json::to_vec(&bad_manifest).unwrap()).unwrap();
        assert!(verify_artifacts_at(&path, FIXTURE_TIME).is_err());
        for filename in ["report.bin", "vcek.der", "manifest.json"] {
            fs::remove_file(path.join(filename)).unwrap();
        }
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn milan_kds_uses_reported_tcb_component_offsets() {
        let mut report = REPORT.to_vec();
        report[0x180..0x188].copy_from_slice(&[1, 2, 0, 0, 0, 0, 6, 7]);
        let url = kds_url(&SnpReportView::try_from_slice(&report).unwrap()).unwrap();
        assert!(url.ends_with("?blSPL=1&teeSPL=2&snpSPL=6&ucodeSPL=7"));
    }

    #[test]
    fn public_mode_b_builder_blocks_packet() {
        let err =
            mode_b_packet(&Pubkey::new_unique(), &Pubkey::new_unique(), &Pubkey::new_unique(), REPORT, 1).unwrap_err();
        assert!(err.to_string().contains("PacketTooLarge"), "{err}");
    }

    #[test]
    fn submit_requires_explicit_payer_and_cli_contract() {
        assert!(Cli::try_parse_from(["demo", "enroll", "--program-id", &Pubkey::new_unique().to_string(), "--submit"])
            .is_err());
        assert!(payer(None, true).is_err());
        assert!(
            Cli::try_parse_from(["demo", "capture", "--rpc-url", "http://localhost", "--out-dir", "/tmp/demo"]).is_ok()
        );
        assert!(Cli::try_parse_from(["demo", "verify", "--artifacts", "/tmp/demo"]).is_ok());
    }
}
