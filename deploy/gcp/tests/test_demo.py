"""Hermetic command-boundary checks. Never invokes Terraform or gcloud."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


DEMO = Path(__file__).resolve().parents[1] / "demo.sh"


class DemoCommands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "calls.jsonl"
        stub = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["CALL_LOG"], "a") as f:
    f.write(json.dumps([name, *args]) + "\\n")
if name == "terraform" and "output" in args:
    print({"project_id":"demo-project", "zone":"us-central1-c",
           "instance_name":"confidential-compute-demo", "solana_rpc_url":"https://api.devnet.solana.com",
           "verifier_program_id":"Verifier111", "consumer_program_id":"Consumer111",
           "deployment_mode":os.environ.get("DEMO_MODE", "native_snp")}[args[-1]], end="")
if name == "gcloud":
    print("RUNNING" if args[:3] == ["compute", "instances", "describe"] else "public-evidence", end="")
'''
        for tool in ("terraform", "gcloud", "cargo", "confidential-compute-gcp-demo"):
            path = self.root / tool
            path.write_text(stub)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                        CALL_LOG=str(self.log), SOLANA_CC_DEMO_ARTIFACTS=str(self.root / "artifacts"))

    def run_demo(self, *args, success=True):
        result = subprocess.run(["bash", str(DEMO), *args], env=self.env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_help_and_unknown_command_do_not_access_cloud(self):
        self.run_demo("help")
        self.run_demo("typo", success=False)
        self.assertEqual(self.calls(), [])

    def test_provision_and_teardown_preserve_interactive_confirmation(self):
        self.run_demo("provision")
        self.run_demo("teardown")
        calls = self.calls()
        self.assertEqual([c[2] for c in calls], ["init", "apply", "destroy"])
        self.assertFalse(any("-auto-approve" in c for c in calls))

    def test_enrollment_is_dry_run_until_submit_explicitly_forwarded(self):
        self.run_demo("enroll")
        remote = self.calls()[-1]
        self.assertEqual(remote[0:3], ["gcloud", "compute", "ssh"])
        self.assertIn("--tunnel-through-iap", remote)
        command = next(a for a in remote if a.startswith("--command="))
        self.assertIn("confidential-compute-gcp-demo enroll", command)
        self.assertNotIn("--submit", command)
        self.run_demo("mode-a", "--submit", "--payer", "/tmp/payer path; echo injected")
        command = next(a for a in self.calls()[-1] if a.startswith("--command="))
        self.assertIn("--submit", command)
        self.assertIn(r"/tmp/payer\ path\;\ echo\ injected", command)

    def test_verify_has_no_terraform_or_gcloud_dependency(self):
        self.env["SOLANA_CC_GCP_DEMO_BIN"] = str(self.root / "confidential-compute-gcp-demo")
        self.run_demo("verify")
        self.assertEqual(self.calls(), [["confidential-compute-gcp-demo", "verify", "--artifacts",
                                        str(self.root / "artifacts")]])

    def test_fetch_reads_only_the_three_public_artifacts(self):
        self.run_demo("fetch")
        remotes = [c for c in self.calls() if c[0] == "gcloud"]
        self.assertEqual(len(remotes), 3)
        for name, call in zip(("report.bin", "vcek.der", "manifest.json"), remotes):
            self.assertIn(f"--command=sudo -u confidential-compute cat /var/lib/confidential-compute/demo/{name} ", call)
            self.assertEqual((self.root / "artifacts" / name).read_text(), "public-evidence")
        self.assertEqual(len(list((self.root / "artifacts").iterdir())), 3)

    def test_wait_rejects_invalid_timeout_before_accessing_state(self):
        self.env["BOOT_TIMEOUT_SECONDS"] = "forever"
        self.run_demo("wait", success=False)
        self.assertEqual(self.calls(), [])

    def test_confidential_space_status_uses_api_and_refuses_snp_ssh_helpers(self):
        self.env["DEMO_MODE"] = "confidential_space"
        self.assertEqual(self.run_demo("status").stdout.strip(), "RUNNING")
        self.run_demo("attest", success=False)
        self.run_demo("ssh", success=False)
        remotes = [c for c in self.calls() if c[0] == "gcloud"]
        self.assertEqual(len(remotes), 1)
        self.assertEqual(remotes[0][1:4], ["compute", "instances", "describe"])

    def test_confidential_space_wait_does_not_claim_sidecar_readiness(self):
        self.env["DEMO_MODE"] = "confidential_space"
        result = self.run_demo("wait")
        self.assertIn("attestation are unverified", result.stdout)
        self.assertNotIn("Sidecar API is ready", result.stdout)


if __name__ == "__main__":
    unittest.main()
