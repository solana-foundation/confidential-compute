# Sidecar build inputs (#298)

The previous recipe selected Rust 1.82 while the repository/CI selected 1.99.1.
The cached locked time-core 0.1.9 manifest declares edition 2024 and Rust 1.88.0;
Rust documents that edition 2024 first requires 1.85.0. Thus 1.82 cannot consume
this lock graph. Rust 1.82 was not installed or executed during this change, and
this does not establish that any previous deployment used a modified recipe.

The recipe now fixes:

- Rust 1.99.1-slim-bookworm image index digest
  `sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd`.
- Distroless cc-debian12:nonroot image index digest
  `sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`.
- Debian and Debian security signed snapshot repositories at
  `20261124T000000Z`, fixing the apt package closure. Only snapshot expiry
  checking is disabled; package signatures/hashes remain required.
- The copied repository toolchain pin, checked against the preinstalled image
  compiler; Rustup is explicitly directed to that compiler to avoid component
  downloads. The Cargo release build enforces Cargo.lock and caps jobs at four.
- `SOURCE_DATE_EPOCH=0` for build inputs and the BuildKit image timestamp argument.
  The Dockerfile uses no floating external syntax frontend.

The Rust index digest was read from the official registry metadata on 2026-11-24
and the Distroless index digest on 2026-10-17:
[Docker Hub Rust tag metadata](https://hub.docker.com/v2/repositories/library/rust/tags/1.99.1-slim-bookworm)
and [Distroless registry index](https://gcr.io/v2/distroless/cc-debian12/manifests/nonroot).
Both indexes include Linux amd64 and arm64. No image layers were pulled.
[Debian snapshots](https://snapshot.debian.org/) returned signed InRelease metadata
for both selected repository dates. This is metadata/pin validation, not an image
build or verification of the resulting filesystem. Compiler requirements follow
[the Rust edition guide](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)
and the cached locked crate manifest.

## Measurement approval remains a separate gate

Pinned inputs are necessary but do not demonstrate byte-identical image or EIF
reproduction. Builds must also fix the selected platform, Docker/BuildKit version
and export settings, source timestamps, Nitro CLI/kernel/init image inputs, and
packaging timestamps. BuildKit's timestamp argument does not by itself normalize
all copied file timestamps; use its timestamp-rewriting exporter where supported.
Keep the source checkout, Cargo.lock, Dockerfile, platform, builder versions and
resulting image digest/EIF measurements together for independent reconstruction.

No expected image digest, EIF hash, PCR0, or allowlist value is invented here.
The existing deterministic timestamp requirement in
[the Nitro research contract](research/aws-nitro-enclaves.md) remains binding.
Before governance approves measurements, independently rebuild twice with the
same recorded platform/export/EIF inputs and compare the actual bytes and
measurements. A failed or missing reproduction remains an approval gap.

Local source regression tests cover the recipe invariants. The native compiler
check exercises the cached 1.99.1 compiler and locked dependency graph in an
isolated target directory; its result is reported separately in the PR. Neither
that check nor source tests exercise Docker, Distroless runtime linkage, EIF
packaging or genuine Nitro hardware admission.
