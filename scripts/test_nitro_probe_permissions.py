"""#299: the probe must never provision privileges or terminate peer enclaves."""
from pathlib import Path
import re
import os
import subprocess
import tempfile
import unittest


class ProbeHostIsolationTests(unittest.TestCase):
    def test_no_host_permission_or_service_mutations(self):
        script = Path(__file__).with_name("run_nitro_hardware_probe.sh").read_text()
        commands = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
        self.assertIsNone(re.search(r"\b(?:chmod|chown|usermod|systemctl|sudo)\b", commands))

    def test_unavailable_docker_fails_before_probe_work(self):
        # Controlled command doubles; never invoke Docker/Nitro or host setup.
        with tempfile.TemporaryDirectory() as directory:
            for name in ("docker", "nitro-cli", "python3"):
                command = Path(directory) / name
                command.write_text("#!/bin/sh\nexit 1\n")
                command.chmod(0o700)
            result = subprocess.run(
                ["/bin/bash", str(Path(__file__).with_name("run_nitro_hardware_probe.sh"))],
                env={**os.environ, "PATH": directory}, capture_output=True, text=True,
                timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Docker is unavailable", result.stderr)

    def test_no_enumeration_and_termination_of_peer_enclaves(self):
        script = Path(__file__).with_name("run_nitro_hardware_probe.sh").read_text()
        self.assertNotIn("describe-enclaves", script)
        self.assertNotIn('for eid in', script)


if __name__ == "__main__":
    unittest.main()
