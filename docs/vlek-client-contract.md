# VLEK client identity contract

AMD reports with `SIGNING_KEY == 1` or a zero chip ID use
`sha256(endorsement_public_key_XY)` for the existing `vcek_v2` cache PDA. VCEK
reports use `sha256(chip_id)`. `AUTHOR_KEY_EN` alone does not select VLEK.
The XY input is exactly 96 bytes, without an uncompressed-point prefix. It is
an address-selection input; the verifier still authenticates the cached key.

Rust callers use the `*_with_endorsement` variants of
`build_register_signer_ix_for_program`, `build_verify_atomic_with_nonce_ix`, or
`build_atomic_attestation_tx_for_program`. The TypeScript equivalents accept
an optional final `endorsementXy` argument after `programId`. Omitting it for a
VLEK report fails explicitly rather than selecting the wrong cache. Existing
raw-report packet guards remain binding; raw SNP transactions are oversized.
Test-only oversized packers expose the corresponding explicit-key input.

[AMD publication 58369, revision 0.10, tables 5–9](https://docs.amd.com/api/khub/documents/xQu~JcgP~f6ls6rVySZs3w/content)
describes a product-specific RSA-4096 ARK → ASVK → P-384 VLEK chain and a
`SEV-VLEK` leaf common name. Its VLEK extensions omit `hwID`. The identity parser
accepts an absent `hwID` only for that exact subject common name, using the
zero-chip sentinel in the registration arguments. Missing TCB, malformed or
duplicate identity extensions, and ambiguous common names fail closed. A VCEK still
requires its hardware ID.

This change fixes SDK address selection and certificate identity parsing. It
adds no trusted root, product profile, or certificate-signature exception.
Registration continues to require signatures under the pinned Milan root,
matching endorsement key and TCB, and trusted Clock validity checks. Other
root/product chains remain unsupported and must fail closed. No genuine VLEK
leaf/ASVK fixture is available in this repository to establish compatibility
with that pin, so genuine VLEK registration remains unverified. Controlled
parser certificates deliberately use an untrusted synthetic issuer and test
that chain verification rejects them. These tests establish no hardware,
SBF compute, or production admission proof.

Compose with the separate identity-revocation fix (#289): the canonical AMD
revocation address uses this same identity hash; VLEK identity denotes the
endorsement key and does not prove a physical chip identity across keys. The
Nitro CA authorization fix (#269, PR #283) changes a separate Nitro parser and
is not required for these AMD client/parser changes. The earlier P-384
feasibility candidate (PR #285) is not a dependency.
