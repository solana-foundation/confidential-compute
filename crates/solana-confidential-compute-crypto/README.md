# solana-confidential-compute-crypto

`solana-confidential-compute-crypto` verifies hardware signatures. The crate can build with `no_std`. It does not allocate a Solana account and it does not read a sysvar.

Three verifiers live here:

1. NIST P-384 ECDSA and the AMD VCEK certificate chain.
2. An X.509 DER walker for those certificates.
3. A CBOR decoder, a COSE Sign1 parser, and the pinned AWS Nitro Root CA G1 key.

Google JWT (RS256) lives in `src/jwt/`. It is a separate path from the SNP report and the Nitro document. Exact governed audience/subject checks through a mandatory policy PDA are being integrated under #199; parsing/signature verification alone does not establish tenant authorization. Require that integration before relying on it.

`@spec SCC-SEC-001` is enforced on the report view in `solana-confidential-compute-core` before this crate sees the signature. This crate checks the signature and the certificate chain.

---

## 1. Call map

```
                 +----------------------+
  1184-byte      | verify_snp_report_   |
  report    ---> | signature            |
                 |  SHA-384(body)       |
                 |  P-384(r, s, X||Y)   |
                 +----------------------+

  ARK key        +----------------------+
  ASK DER   ---> | validate_vcek_chain  |
  VCEK DER       | parse_vcek_identity  |
                 +----------------------+

  COSE bytes     +----------------------+
            ---> | verify_nitro_document|
                 |  CBOR -> COSE Sign1  |
                 |  cabundle[0] == root |
                 |  ES384 (alg -35)     |
                 +----------------------+
```

```bash
cargo test -p solana-confidential-compute-crypto
cargo test -p solana-confidential-compute-crypto --test milan_kds
cargo test -p solana-confidential-compute-crypto --lib verify_hardware_nitro_attestation_document
```

`milan_kds` loads `fixtures/snp_hardware_report_milan.bin` (1,184 bytes) and `fixtures/vcek_milan.der`. The Nitro test loads the 4,552-byte NSM response and verifies the 4,526-byte COSE document at offset 26.

---

## 2. P-384

`verify_p384_signature` takes three arrays:

| Argument | Length | Layout |
| :--- | ---: | :--- |
| `public_key_xy` | 96 | Big-endian X (48) then Y (48). |
| `hash_sha384` | 48 | SHA-384 digest of the signed bytes. |
| `signature_rs` | 96 | Big-endian r (48) then s (48). |

The function builds a SEC1 point (`0x04 || X || Y`). It rejects an all-zero key, an all-zero hash, and an all-zero signature before the curve parse. Scalar `s` may be high. AMD firmware emits both ranges (`@spec SCC-SEC-010` in the verifier catalog). This function does not force low-S form. Paired valid high-S/low-S signatures with wrong-message/key negative controls did not reproduce a forgery (#207); accepting vendor ECDSA high-S is not itself a signature bypass.

`verify_snp_report_signature` hashes the 672-byte signed body with SHA-384, then calls `verify_p384_signature`.

```
 signed body (672) --SHA-384--> digest (48)
                                    |
 public key X||Y (96) --------------+--> P-384 verify
 signature r||s (96) ---------------+
```

---

## 3. X.509 DER walker

`vcek.rs` walks DER with a cursor. It does not build an ASN.1 tree on the heap. `MAX_CERT_DER_LEN` is **4096**.

Recognized tags include BOOLEAN `0x01`, INTEGER `0x02`, BIT STRING `0x03`, OCTET STRING `0x04`, OID `0x06`, SEQUENCE `0x30`, context `0xA0`, and extensions `0xA3`.

The coordinated upstream #173 fix / PR #226 restricts production AMD certificate validation to the pinned Milan RSA-4096 ARK → RSA ASK → P-384 VCEK chain. The legacy `ark_pubkey_xy` argument remains ABI-compatible but has no supported production vendor-root meaning. Require that fix in the selected implementation; the captured baseline also accepted synthetic P-384 roots.

The upstream issue #175 at-time API `validate_vcek_chain_at(..., now_unix)` checks authentic ASK/leaf certificate time boundaries and returns their exclusive minimum `notAfter` deadline. Its no-time API fails closed; `validate_vcek_signatures_only` is explicitly for offline signature inspection. The processor must supply trusted chain time. Cache reuse deadline enforcement is a separate #176 integration requirement; neither successful registration nor an offline signature check establishes later cache validity.

`parse_vcek_identity` reads the extensions that bind the chip:

| OID | Name in this crate | Use |
| :--- | :--- | :--- |
| `1.3.6.1.4.1.3704.1.4` | `hwID` | 64-byte chip id. |
| `1.3.6.1.4.1.3704.1.3` | SPL arc | Boot loader, TEE, reserved, SNP, microcode. |
| `1.3.6.1.4.1.3704.1.1` | full TCB word | Used only when no SPL component is present. |

`process_register_vcek` requires `identity.chip_id` and `identity.tcb_version` to match the instruction arguments before it creates the PDA.

Nitro certificates use the same DER cursor through `parse_nitro_cert`. `validate_nitro_cert_chain` checks each link after `cabundle[0]`. Entry 0 must carry the caller-supplied root public key. The walker does not check the self-signature of entry 0. The generic explicit trust-anchor API is intentional; production entrypoints pin the AWS root. It does check validity (`not_before` and `not_after`) against the caller clock. `not_before >= not_after` is rejected.

---

## 4. CBOR cursor

`CborCursor` implements RFC 8949 major types 0 through 7 for the items this crate needs. The cursor stores a borrow and an index. It does not allocate.

```
 one byte
 +--------+---------------------------+
 |  major | additional info           |
 |  3 bit |  5 bit                    |
 +--------+---------------------------+
   0 unsigned    4 array
   1 negative    5 map
   2 bytes       6 tag
   3 text        7 simple / break
```

An indefinite map is major type 5 with additional info 31. The first byte is `0xbf`. The stop byte is `0xff`.

```
 0xbf  key1 value1  key2 value2  ...  0xff
 |<------------- indefinite map ----------->|
```

`parse_attestation_payload` is the parser that accepts `IndefiniteMap`. Nested `pcrs` maps, the `cabundle` array, and the COSE headers use definite lengths. A missing break makes the next read return `CryptoError::MalformedCbor`.

### 4.1 Skip depth

Unknown fields are skipped. `MAX_CBOR_SKIP_DEPTH` is **8**.

```
 depth 8   array
   depth 7   array
     ...
       depth 0   --> CryptoError::MalformedCbor
```

The test `skip_cbor_value_depth_bound` allows eight nested arrays and rejects nine. A definite map skip uses `n.saturating_mul(2)` so a hostile pair count cannot spin to `usize::MAX`. An indefinite map or array inside the skipper stops on `0xff`. A break where a map value is required is `CryptoError::MalformedCbor`, and the bytes after that break stay unread.

Simple value `0xf6` is CBOR `null`. The hardware document uses that byte for `public_key`. Major type 7 additional info 31 is the break stop (`0xff`), not simple value 31. Additional info 24 through 30 on major type 7 is not fully decoded. A float in an unknown field can desynchronize the cursor. The signature check still covers the extracted payload bytes. A shifted payload fails ES384 unless the caller holds the leaf key.

The consumer parser in `solana-confidential-compute-cpi` is a second cursor. `parse_nitro_payload` accepts a definite map and an indefinite map (`0xbf` … break `0xff`). `skip_cbor_value_depth` accepts major type 7 simple values whose additional info is 0 through 23. That includes `null` (`0xf6`). Additional info 24 through 30 returns `InvalidInstructionData`. See the [`solana-confidential-compute-cpi` README](../solana-confidential-compute-cpi/README.md).

### 4.2 Hardware document shape

`fixtures/nitro_hardware_attestation.bin` is 4,552 bytes. Bytes `0..26` are the NSM map. The COSE document is bytes `[26..]` and matches `fixtures/nitro_hardware_document.cose` (4,526 bytes).

| Item | Encoding in the fixture |
| :--- | :--- |
| COSE array | Definite array of 4, untagged (`0x84`). |
| Protected header | `{1: -35}` (`a1013822`). |
| Unprotected header | Empty definite map (`0xa0`). |
| Payload | Indefinite map, closed by `0xff`. |
| `pcrs` | Definite map. Indices 0, 1, 2, and 8 are required. |
| `cabundle` | Definite array of 4 certificates. Lengths 533, 707, 794, 705. |
| Leaf certificate | 638 bytes. |
| `public_key` | `0xf6` (`null`). |
| `user_data` | 32 bytes of `0x55`. |
| `nonce` | 32 bytes of `0x77`. |

`MAX_NITRO_DOCUMENT_LEN` is **8192**. `NSM_RESPONSE_MAX_SIZE` in the sidecar is `0x3000` (12,288). Both limits cover 4,552 bytes.

---

## 5. COSE Sign1

`COSE_ALG_ES384` is **-35**. Tag 18 is accepted and is optional. The array has four elements: protected header, unprotected header, payload, signature.

```
 Sig_structure = [
   "Signature1",
   protected bstr,
   h'' ,            # external AAD is empty
   payload bstr
 ]
```

`hash_cose_sig_structure` hashes that structure without a heap copy of the whole document. `verify_cose_sign1` checks ES384 under the leaf key taken from the same payload. Trailing bytes after the COSE array are rejected. `assert_protected_es384` requires algorithm `-35`.

`verify_nitro_document` runs the parse, the chain, and the signature. It does not apply PCR policy. The on-chain program rejects an all-zero PCR0 and a PCR0 that is absent from `PolicyRegistry`.

---

## 6. AWS Nitro Root CA G1

`AWS_NITRO_ROOT_CA_PUBKEY_XY` is the 96-byte uncompressed P-384 point of AWS Nitro Enclaves Root CA G1.

Certificate SHA-256 fingerprint recorded in the source:

```
64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:
7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
```

The on-chain walker accepts `cabundle[0]` only when the key equals this constant. `PolicyRegistry.ark_pubkey_xy` is not a Nitro trust anchor.

Both the library and processor call `validate_nitro_path_constraints` before
signature dispatch or state writes. The supported AWS profile requires X.509 v3,
nonempty issuer/subject names, identical DER name encodings at each issuer hop,
critical CA BasicConstraints and KeyUsage keyCertSign on every CA. Path length
counts non-self-issued subordinate CAs; a leaf does not consume it. A leaf must
not be a CA or assert keyCertSign; when KeyUsage is present it must allow
digitalSignature. Unknown critical extensions, duplicate extension OIDs, and
unsupported name/policy/EKU constraints fail closed. Informational noncritical
extensions remain allowed. This bounded profile does not implement general name
normalization, CRL fetching, revocation, or arbitrary PKIX policy processing.
Root key pinning, child signatures, COSE signatures, and trusted-time validity
remain required separately. The generic offline library accepts a caller-selected
root; the production processor always uses the pinned AWS key.

The committed authentic fixture has four CAs with critical BasicConstraints and
keyCertSign; path limits are absent, 2, 1, and 0. Its leaf has CA=false and
noncritical digitalSignature/nonRepudiation KeyUsage. No name/policy/EKU
constraints occur in that fixture. Signed synthetic processor tests explicitly
substitute only the AWS root signature edge; they do not establish SBF feasibility
or authentic AWS signing authority.

References: [AWS root-of-trust verification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html),
[AWS attestation process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md),
and [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) §§4.2, 4.2.1.3,
4.2.1.9 and 6.1.


Fixture chain order:

| Slot | Subject CN |
| :--- | :--- |
| `cabundle[0]` (533 bytes) | `aws.nitro-enclaves` |
| `cabundle[1]` (707 bytes) | `577c22caffc0b23f.us-east-2.aws.nitro-enclaves` |
| `cabundle[2]` (794 bytes) | `f81d16b798bdf31e.zonal.us-east-2.aws.nitro-enclaves` |
| `cabundle[3]` (705 bytes) | `i-0c801b445eeba3a9e.us-east-2.aws.nitro-enclaves` |
| leaf (638 bytes) | `i-0c801b445eeba3a9e-enc01a0daae7e35adef.us-east-2.aws` |

---

## 7. Google JWT

`src/jwt/` parses a compact JWS and verifies RS256. `verify_jwt_rs256_with_montgomery` uses the Montgomery constants stored on `JwksAccount` (`n0` and `R^2`). The public exponent on that account must be 65537. ES256 is named in future protocol releases. The implemented verifier in this module is RS256.

---

## 8. Errors

Parsers return `Result<_, CryptoError>`. Production functions in `cbor.rs`, `nitro.rs`, and `vcek.rs` do not call `unwrap` or `expect`. A malformed length, a depth past 8, a bad signature, or a missing VCEK extension returns an error. The transaction aborts. The parser does not panic.
