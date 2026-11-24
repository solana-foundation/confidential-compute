#!/usr/bin/env python3
"""Check a release record's integrity and GitHub build provenance (#297).

The record alone is an unsigned checksum list, not a source or authenticity proof.
`verify` requires official GitHub attestations for both artifact and record from
this repository's main CI workflow at the caller's independently approved commit.
`verify-integrity` is explicitly suitable only for corruption checks and PR CI.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record(artifact, lockfile, source_sha, build_inputs):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("source must be an exact Git commit SHA")
    if not Path(artifact).stat().st_size:
        raise ValueError("artifact is empty")
    return {
        "schema": 2,
        "source_sha": source_sha,
        "artifact_sha256": digest(artifact),
        "cargo_lock_sha256": digest(lockfile),
        "build_inputs_sha256": digest(build_inputs),
        "cargo_features": [],
        "default_features": True,
        "rust_toolchain": "1.98.1",
        "sbf_builder": "cargo-build-sbf 4.2.0",
        "platform_tools": "v1.56",
        "sbf_arch": "v3",
    }


def verify(manifest, artifact, lockfile, expected_source_sha, build_inputs):
    expected = record(artifact, lockfile, expected_source_sha, build_inputs)
    # Reject unknown/missing fields; never interpret manifest-supplied paths.
    if type(manifest) is not dict or type(manifest.get("schema")) is not int:
        raise ValueError("invalid release build record schema")
    if manifest != expected:
        raise ValueError("artifact/source/Cargo.lock differs from the release build record")


def verify_release(manifest_path, artifact, lockfile, expected_source_sha, build_inputs):
    # Validate the independent source input before calling an external verifier.
    if not re.fullmatch(r"[0-9a-f]{40}", expected_source_sha):
        raise ValueError("source must be an exact Git commit SHA")
    for subject in (artifact, manifest_path):
        subprocess.run(
            ["gh", "attestation", "verify", str(Path(subject).resolve()),
             "--hostname", "github.com", "--repo", "solana-foundation/confidential-compute",
             "--signer-workflow", "solana-foundation/confidential-compute/.github/workflows/ci.yml",
             "--source-ref", "refs/heads/main", "--source-digest", expected_source_sha,
             "--deny-self-hosted-runners"],
            check=True,
        )
    verify(json.loads(Path(manifest_path).read_text()), artifact, lockfile,
           expected_source_sha, build_inputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("record", "verify", "verify-integrity"))
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--lockfile", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--build-inputs", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "record":
            args.manifest.write_text(
                json.dumps(record(args.artifact, args.lockfile, args.source_sha, args.build_inputs), indent=2) + "\n"
            )
        elif args.mode == "verify":
            verify_release(args.manifest, args.artifact, args.lockfile, args.source_sha,
                           args.build_inputs)
            print("GitHub provenance and release record verified for approved main commit")
        else:
            verify(
                json.loads(args.manifest.read_text()), args.artifact, args.lockfile, args.source_sha, args.build_inputs
            )
            print("integrity only: unsigned release record matches supplied files; authenticity unverified")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
