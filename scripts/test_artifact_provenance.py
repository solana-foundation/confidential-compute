"""#190: exercise the archive boundary with corruption/substitution controls."""

import copy
from pathlib import Path
import tempfile
import unittest

from artifact_provenance import record, verify, verify_release
from unittest.mock import patch
import subprocess


class ArtifactIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.artifact = Path(self.tmp.name) / "solana_confidential_compute_verifier.so"
        self.lockfile = Path(self.tmp.name) / "Cargo.lock"
        # These bytes test integrity only; ELF validation is a separate CI gate.
        self.artifact.write_bytes(b"release artifact fixture")
        self.lockfile.write_text("locked dependencies fixture\n")
        self.build_inputs = Path(self.tmp.name) / "build-inputs.txt"
        self.build_inputs.write_text("controlled build inputs fixture\n")
        self.source = "a" * 40
        self.manifest = record(self.artifact, self.lockfile, self.source, self.build_inputs)

    def check(self, manifest=None, source=None):
        verify(
            self.manifest if manifest is None else manifest,
            self.artifact,
            self.lockfile,
            self.source if source is None else source,
            self.build_inputs,
        )

    def test_unchanged_download_is_accepted(self):
        self.check()

    def test_artifact_changed_without_updating_record_is_rejected(self):
        self.artifact.write_bytes(b"different or mock build")
        with self.assertRaises(ValueError):
            self.check()

    def test_other_source_commit_is_rejected(self):
        with self.assertRaises(ValueError):
            self.check(source="b" * 40)

    def test_changed_lockfile_is_rejected(self):
        self.lockfile.write_text("different dependencies\n")
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_or_extended_record_is_rejected(self):
        for mutation in ("missing", "extra", "version", "boolean_version"):
            manifest = copy.deepcopy(self.manifest)
            if mutation == "missing":
                del manifest["source_sha"]
            elif mutation == "extra":
                manifest["artifact_path"] = "../../untrusted"
            elif mutation == "version":
                manifest["schema"] = 3
            else:
                manifest["schema"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(manifest=manifest)

    def test_regenerated_record_cannot_prove_authenticity(self):
        self.artifact.write_bytes(b"substituted release")
        forged = record(self.artifact, self.lockfile, self.source, self.build_inputs)
        # Honest boundary: an unsigned regenerated record passes integrity.
        self.check(manifest=forged)
        manifest_path = Path(self.tmp.name) / "manifest.json"
        import json
        manifest_path.write_text(json.dumps(forged))
        # Controlled verifier failure, not a real signature fixture.
        with patch("artifact_provenance.subprocess.run",
                   side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                verify_release(manifest_path, self.artifact, self.lockfile,
                               self.source, self.build_inputs)

    def test_authentication_covers_both_subjects_and_exact_identity(self):
        import json
        manifest_path = Path(self.tmp.name) / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest))
        with patch("artifact_provenance.subprocess.run") as verifier:
            verify_release(manifest_path, self.artifact, self.lockfile,
                           self.source, self.build_inputs)
        self.assertEqual(verifier.call_count, 2)
        for call, subject in zip(verifier.call_args_list, (self.artifact, manifest_path)):
            self.assertEqual(call.args[0], [
                "gh", "attestation", "verify", str(subject.resolve()),
                "--hostname", "github.com", "--repo", "solana-foundation/confidential-compute",
                "--signer-workflow", "solana-foundation/confidential-compute/.github/workflows/ci.yml",
                "--source-ref", "refs/heads/main", "--source-digest", self.source,
                "--deny-self-hosted-runners"])
            self.assertTrue(call.kwargs["check"])

    def test_changed_build_inputs_are_rejected(self):
        self.build_inputs.write_text("different build settings\n")
        with self.assertRaises(ValueError):
            self.check()

    def test_empty_artifact_is_rejected(self):
        self.artifact.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_artifact_is_rejected(self):
        self.artifact.unlink()
        with self.assertRaises(OSError):
            self.check()

    def test_branch_name_cannot_replace_exact_source_sha(self):
        with self.assertRaises(ValueError):
            record(self.artifact, self.lockfile, "main", self.build_inputs)


if __name__ == "__main__":
    unittest.main()
