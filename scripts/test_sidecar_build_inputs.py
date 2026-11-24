"""#298: keep the sidecar build recipe pinned to the tested compiler and lock."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SidecarBuildInputTests(unittest.TestCase):
    def test_base_images_are_pinned(self):
        recipe = (ROOT / "bins/solana-confidential-compute-sidecar/Dockerfile").read_text()
        images = re.findall(r"^FROM (\S+)", recipe, re.M)
        self.assertEqual(len(images), 2)
        for image in images:
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")

    def test_compiler_and_lock_match_repository_contract(self):
        recipe = (ROOT / "bins/solana-confidential-compute-sidecar/Dockerfile").read_text()
        channel = re.search(r'^channel = "([^"]+)"$',
                            (ROOT / "rust-toolchain.toml").read_text(), re.M).group(1)
        self.assertIn(f"FROM rust:{channel}-slim-bookworm@sha256:", recipe)
        self.assertIn("COPY rust-toolchain.toml", recipe)
        self.assertIn(f"RUSTUP_TOOLCHAIN={channel}", recipe)
        self.assertRegex(recipe, r"cargo build --locked --release --package solana-confidential-compute-sidecar -j4")

    def test_apt_and_timestamps_are_fixed(self):
        recipe = (ROOT / "bins/solana-confidential-compute-sidecar/Dockerfile").read_text()
        self.assertIn("ARG SOURCE_DATE_EPOCH=0", recipe)
        self.assertIn("SOURCE_DATE_EPOCH=0", recipe)
        self.assertIn("snapshot.debian.org/archive/debian/20261124T000000Z", recipe)
        self.assertIn("snapshot.debian.org/archive/debian-security/20261124T000000Z", recipe)
        self.assertNotIn("trusted=yes", recipe)


if __name__ == "__main__":
    unittest.main()
