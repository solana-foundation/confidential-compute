//! Error types for cryptographic verification.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("P-384 signature verification failed")]
    InvalidP384Signature,

    #[error("Invalid or malformed P-384 public key")]
    InvalidP384PublicKey,

    #[error("Malformed ASN.1 / X.509 certificate")]
    MalformedCertificate,

    /// Leaf VCEK is missing `hwID` (1.3.6.1.4.1.3704.1.4) or a TCB binding
    /// (`tcbVersion` 1.3.6.1.4.1.3704.1.1, or the AMD SPL components).
    /// @spec SCC-VERIFY-003
    #[error("VCEK certificate is missing hwID or tcbVersion extensions")]
    VcekExtensionMissing,

    #[error("Certificate authority not trusted")]
    UntrustedRoot,

    #[error("Certificate expired or not yet valid")]
    CertificateExpired,

    /// Compact JWS encoding, Base64URL, or JSON claims are malformed.
    /// @spec SCC-JWT-001
    #[error("malformed JWT encoding, header, or claims")]
    MalformedJwt,

    /// Duplicate claim key in JWT header or payload JSON.
    /// @spec SCC-JWT-001
    #[error("duplicate JWT claim")]
    DuplicateJwtClaim,

    /// RS256 / ES256 signature did not verify.
    /// @spec SCC-JWT-003 SCC-JWT-004
    #[error("JWT signature verification failed")]
    InvalidJwtSignature,

    /// PKCS#1 v1.5 encoded message did not match the SHA-256 DigestInfo template.
    /// @spec SCC-JWT-003
    #[error("JWT PKCS#1 v1.5 padding is invalid")]
    InvalidPadding,

    /// Google Cloud Confidential Space policy (secboot, dbgstat, clock) failed.
    /// @spec SCC-JWT-002 SCC-JWT-005
    #[error("JWT Google Cloud security policy violation")]
    PolicyViolation,

    /// JWT `alg` or RSA public exponent is not supported for this path.
    /// @spec SCC-JWT-001 SCC-JWT-003
    #[error("unsupported JWT algorithm or RSA exponent")]
    UnsupportedJwtAlgorithm,

    /// CBOR major type, length, or UTF-8 encoding is invalid.
    /// @spec SCC-NITRO-001
    #[error("malformed CBOR data item")]
    MalformedCbor,

    /// COSE Sign1 array, protected header, or ES384 algorithm is invalid.
    /// @spec SCC-NITRO-002
    #[error("invalid COSE Sign1 structure")]
    InvalidCoseStructure,

    /// Nitro attestation payload map is missing or malformed required fields.
    /// @spec SCC-NITRO-003
    #[error("invalid Nitro attestation payload")]
    InvalidAttestationPayload,

    /// AWS Nitro X.509 chain, validity window, or root pin failed.
    /// @spec SCC-NITRO-004
    #[error("Nitro certificate chain is invalid")]
    CertificateChainInvalid,

    /// COSE Sign1 P-384 signature over Sig_structure failed.
    /// @spec SCC-NITRO-005
    #[error("invalid COSE Sign1 signature")]
    InvalidSignature,
}
