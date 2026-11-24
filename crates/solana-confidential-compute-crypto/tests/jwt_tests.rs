//! Integration tests for the Google Cloud OIDC / JWT verifier.
//!
//! @spec SCC-JWT-001 SCC-JWT-002 SCC-JWT-003 SCC-JWT-004 SCC-JWT-005 SCC-JWT-006

use solana_confidential_compute_crypto::jwt::{
    compute_n0_and_r2, decode_b64url, eat_nonce_tombstone_seed, enforce_google_policy,
    es256_is_low_s, kid_hash, parse_es256_signature, parse_google_claims, parse_header_kid_b64,
    verify_jwt_rs256, verify_jwt_rs256_at, verify_jwt_rs256_with_montgomery, JwtView,
    P256_HALF_ORDER, RSA_EXPONENT,
};
use solana_confidential_compute_crypto::CryptoError;

const MODULUS_HEX: &str = "ba191fcd94096f1c39060a7f7c60606b0f82517068c1a609ec29c0237a62634a62640aaea8b86f7aca35e0fbebde97968ae07f6c91d5950c243a24e4c03a1cf6d8389be8ff0c3373ef37d7171735a1c8c6eae0773c55a133049bd36586957784108c6ac7d3f1ca9a156ccfb3b828f0a6fb9641f07b8cef11f46717fff43766b5ac2b4dce4bae176eb87624c76abf3be0862c79ea29d13a6f8fe6ecd035c45449520c67f34937be57e884a6aef26b7dff3ace96a9b9b3e45ca34ef9ac70e0bdc8e287583738b0688916b4bf2fc8adbfc14f07dc61c603a344ecb198363212446aa66ae2814fa20d1b133697642a1b8b6265c7fcd8f4d428232d58cb4b4a8202f3";

const VALID_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjoibm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.HL3uxjiO3q-Q3-KGoaJfiiHJauq4FwaSZRsyxdxWIrSgRIv5COncTDxcJ2LStvzTJYhQvL85xQ7yJRmwfGTw-7dOnMy74oV6_lRUSxvHl8h3oUsR2CTAwQCRvFzSC0mHYI-TMwldZc1UlzcYfnUSPlfKGfhguejnAjVNxwVaHPEwbGsJFvNNfKkBx5MWlsA8pXYnBCiwaa4LSk420DaHbr-xOtsqOt4IwuywECIp1rpRkK2IA0YwtYXZC9bBbn1Bc8guPcBeOKF0ujTJVFW_4vxIQLV3K1wRe8C5PiuPxQFPKRdkTB8froOoIBuxNMTkhZ1qhumSe8MIcVIc003RKg";

const EXPIRED_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjoibm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubiIsImV4cCI6MTAwMCwiaWF0Ijo1MDAsImlzcyI6Imh0dHBzOi8vY29uZmlkZW50aWFsY29tcHV0aW5nLmdvb2dsZWFwaXMuY29tIiwic2VjYm9vdCI6dHJ1ZSwic3ViIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vY29tcHV0ZS92MS9wcm9qZWN0cy90ZXRvbi96b25lcy91cy9pbnN0YW5jZXMvdm0iLCJzdWJtb2RzIjp7ImNvbnRhaW5lciI6eyJpbWFnZV9kaWdlc3QiOiJzaGEyNTY6YWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYiJ9fX0.T8nObCWKpmyOe2VVZXXhUYLW6XdsKPJkvHmkly2EsA5IGgSn4ns9KeYwaxy5OcU8IU2pUxbT5siqqo3kuC6e0714YDGCtkKjPwNH3ItDMkY5EUWk6pUX2hfmsX3PCCLoRMKg4N8_emDFFCAHChebh9Ee6C8VSazAdowvICN1T9_evPufeRm2UeFJfFRXa6Kla8wUy3pjOSvBiz-DPG9rbLyQO8h1nqClCi0FX_wmW_uwU8k1QFHAvWXHdqmsdJHCmLLf5qdzvCd_WLQzU8u4M6fw5WH3ZFTixNhJ8jVieQIVkv9DPqqblfXGMfm8XTTEOZPyXL9vUm_LmkaINZeNJQ";

const DEBUG_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJlbmFibGVkLWF0LWJvb3QiLCJlYXRfbm9uY2UiOiJubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5uIiwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6Imh0dHBzOi8vY29uZmlkZW50aWFsY29tcHV0aW5nLmdvb2dsZWFwaXMuY29tIiwic2VjYm9vdCI6dHJ1ZSwic3ViIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vY29tcHV0ZS92MS9wcm9qZWN0cy90ZXRvbi96b25lcy91cy9pbnN0YW5jZXMvdm0iLCJzdWJtb2RzIjp7ImNvbnRhaW5lciI6eyJpbWFnZV9kaWdlc3QiOiJzaGEyNTY6YWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYiJ9fX0.kPkUZqaHOxyO2OhUxrzflF1zvec7qiE5zct2GNTIxJ-OrL8heEH7zshPBC4fHZWsedA1AVxvELMr7nhu9YwYVoTGY3UNyZbi4b3Ew4XQMSKEXSkxg_IW9JOd898V6iAaZz__tzlHHpYgBigwsvDcvEXMasv0HSb6iG0vbZeAZi7B_LWsqag3woHAQi8O68-wJhbSUg3oX01khuMSZj-u9x8HQxltSoLmUJ2_zrU88tAANNqp9w2oyIXbmEzfGt0PLhsPXux7FGpYl-427Dd1eOK10O3HcCchiRbzEFVKI0bMKvT0dUjPOY5WC2CsAsaLzFKsqgGw4q4OIMY_r1-0Gg";

const NOSEC_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjoibm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOmZhbHNlLCJzdWIiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9jb21wdXRlL3YxL3Byb2plY3RzL3RldG9uL3pvbmVzL3VzL2luc3RhbmNlcy92bSIsInN1Ym1vZHMiOnsiY29udGFpbmVyIjp7ImltYWdlX2RpZ2VzdCI6InNoYTI1NjphYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIn19fQ.OKYM-nxZU-P5kgvJZ_GQqEEo09FNtNHgWskTj8utsUdjK91nG_Fe9_a0LjuSl5fzASLPGOVK5Tt14BMOxwjh0-_HbB60fTBDmTFOS3RPsFo3UhQcH0uhjhfS5b2uNMWNgm2PReRuywUUsm2u7TSIQdfPW-Jt-knPQZWx0xqKFKjJys4mmTftxemMI8_wPRyh7E1wtvwozzcg4aaN834CruOB-nbEMmBB7WejaZZxbtm53SLOqcL4JkzwZ7LlIpI7Boo3HSHZjLOQqzyngQ-6w91UzJk3VAR92uwdPaCKq-DSQ7W1W6mshVfqnBzHfPm53rZxnhRSBpowDJTYF-9DQQ";

const EXP_LE_IAT_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRldG9uLXRlc3QiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0ZXRvbi12ZXJpZmllciIsImRiZ3N0YXQiOiJkaXNhYmxlZC1zaW5jZS1ib290IiwiZWF0X25vbmNlIjoibm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubiIsImV4cCI6MTAwMCwiaWF0IjoyMDAwLCJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSIsInNlY2Jvb3QiOnRydWUsInN1YiI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2NvbXB1dGUvdjEvcHJvamVjdHMvdGV0b24vem9uZXMvdXMvaW5zdGFuY2VzL3ZtIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifX19.lmL81umW9g73dES9U93TGPrWCgPcdzFQ-2U-6OXJA31dajmp0dUrbuhW0Km72nePPXEF3BPLddEcD1qFYRWpzcNWsPLFIsPm2rIjHgD0WncyEU95dIhfvt_DyX290HkOh-7u4dwGImXNc07y9SlLw1A30LIKSm3QckKdPwMD6YV2e8yo1V9-CKSIUMm9_-EPwOSZ28k7BeIyizmGN9zXLVLLPrejgubDNLzCrwa8wEtOkp_JTmGR20839WCh-nkuTw-olBx5JaKpFLB7dkXCqG8Q5_CxK3aSWTXyCxclv92yFFV2euvLC29V2GXcsdN16AICs_sEQNAX8YMoXPBzNw";

const PAYLOAD_JSON: &[u8] = br#"{"aud":"teton-verifier","dbgstat":"disabled-since-boot","eat_nonce":"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn","exp":4102444800,"iat":1700000000,"iss":"https://confidentialcomputing.googleapis.com","secboot":true,"sub":"https://www.googleapis.com/compute/v1/projects/teton/zones/us/instances/vm","submods":{"container":{"image_digest":"sha256:abababababababababababababababababababababababababababababababab"}}}"#;

const EAT_NONCE: &[u8] = b"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
const KID_HASH_HEX: &str = "644987042bb9fad13921d9d9a7601c73e353688683d62f2a10e525f3a66c4cc5";
const NONCE_SEED_HEX: &str = "ce068a195ab380a813c713035ed74921acee4d3bd1c4ede24c11cba02c3ca985";

fn modulus() -> [u8; 256] {
    let raw = hex::decode(MODULUS_HEX).expect("modulus hex");
    let mut out = [0u8; 256];
    out.copy_from_slice(&raw);
    out
}

fn b64url_encode(data: &[u8]) -> String {
    const TAB: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TAB[((n >> 18) & 63) as usize] as char);
        out.push(TAB[((n >> 12) & 63) as usize] as char);
        out.push(TAB[((n >> 6) & 63) as usize] as char);
        out.push(TAB[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TAB[((n >> 18) & 63) as usize] as char);
        out.push(TAB[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TAB[((n >> 18) & 63) as usize] as char);
        out.push(TAB[((n >> 12) & 63) as usize] as char);
        out.push(TAB[((n >> 6) & 63) as usize] as char);
    }
    out
}

fn compact_jwt(header_json: &str, payload_json: &str) -> String {
    format!(
        "{}.{}.{}",
        b64url_encode(header_json.as_bytes()),
        b64url_encode(payload_json.as_bytes()),
        b64url_encode(&[0u8; 256])
    )
}

fn hex32(s: &str) -> [u8; 32] {
    let raw = hex::decode(s).expect("sha256 hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

#[test]
fn test_verify_jwt_rs256_happy_path() {
    let n = modulus();
    let claims = verify_jwt_rs256(VALID_JWT, &n, RSA_EXPONENT).expect("valid RS256 jwt");
    assert_eq!(
        claims.iss(),
        b"https://confidentialcomputing.googleapis.com"
    );
    assert_eq!(
        claims.sub(),
        b"https://www.googleapis.com/compute/v1/projects/teton/zones/us/instances/vm"
    );
    assert_eq!(claims.aud(), b"teton-verifier");
    assert_eq!(claims.exp, 4_102_444_800);
    assert_eq!(claims.iat, 1_700_000_000);
    assert!(claims.secboot);
    assert_eq!(claims.dbgstat(), b"disabled-since-boot");
    assert_eq!(claims.image_digest, [0xab; 32]);
    assert_eq!(claims.eat_nonce(), EAT_NONCE);
    assert_eq!(claims.kid(), b"teton-test");

    let at = verify_jwt_rs256_at(VALID_JWT, &n, RSA_EXPONENT, Some(1_700_000_100))
        .expect("freshness window");
    assert_eq!(at.exp, claims.exp);
    assert_eq!(at.iat, claims.iat);

    let (n0, r2) = compute_n0_and_r2(&n).expect("montgomery constants");
    let mont =
        verify_jwt_rs256_with_montgomery(VALID_JWT, &n, RSA_EXPONENT, n0, &r2, Some(1_700_000_100))
            .expect("precomputed montgomery");
    assert_eq!(mont.kid(), claims.kid());
    assert_eq!(mont.eat_nonce(), claims.eat_nonce());
}

#[test]
fn test_rejects_tampered_signature_and_payload() {
    let n = modulus();
    let view = JwtView::parse(VALID_JWT).expect("split");
    let mut sig_tampered = VALID_JWT.as_bytes().to_vec();
    let sig_off = view.signing_input.len() + 1;
    sig_tampered[sig_off] ^= 0x01;
    let sig_jwt = std::str::from_utf8(&sig_tampered).expect("ascii");
    assert_eq!(
        verify_jwt_rs256(sig_jwt, &n, RSA_EXPONENT),
        Err(CryptoError::InvalidJwtSignature)
    );

    let mut payload_tampered = VALID_JWT.as_bytes().to_vec();
    payload_tampered[view.header_b64.len() + 2] ^= 0x01;
    let payload_jwt = std::str::from_utf8(&payload_tampered).expect("ascii");
    assert_eq!(
        verify_jwt_rs256(payload_jwt, &n, RSA_EXPONENT),
        Err(CryptoError::InvalidJwtSignature)
    );
}

#[test]
fn test_rejects_security_policy_violations() {
    let n = modulus();
    assert_eq!(
        verify_jwt_rs256(NOSEC_JWT, &n, RSA_EXPONENT),
        Err(CryptoError::PolicyViolation)
    );
    assert_eq!(
        verify_jwt_rs256(DEBUG_JWT, &n, RSA_EXPONENT),
        Err(CryptoError::PolicyViolation)
    );
    assert_eq!(
        verify_jwt_rs256(EXP_LE_IAT_JWT, &n, RSA_EXPONENT),
        Err(CryptoError::PolicyViolation)
    );
    assert_eq!(
        verify_jwt_rs256_at(EXPIRED_JWT, &n, RSA_EXPONENT, Some(2_000)),
        Err(CryptoError::PolicyViolation)
    );
    // iat = 1_700_000_000; now + 120 must be < iat.
    assert_eq!(
        verify_jwt_rs256_at(VALID_JWT, &n, RSA_EXPONENT, Some(1_699_999_879)),
        Err(CryptoError::PolicyViolation)
    );
}

#[test]
fn test_rejects_duplicate_claim_keys() {
    let n = modulus();
    let header_dup = compact_jwt(r#"{"alg":"RS256","alg":"RS256"}"#, r#"{"aud":"x"}"#);
    assert_eq!(
        verify_jwt_rs256(&header_dup, &n, RSA_EXPONENT),
        Err(CryptoError::DuplicateJwtClaim)
    );

    let payload = br#"{"exp":1,"exp":2,"iss":"https://confidentialcomputing.googleapis.com","sub":"s","aud":"a","iat":1,"secboot":true,"dbgstat":"disabled-since-boot","eat_nonce":"n","image_digest":"sha256:abababababababababababababababababababababababababababababababab"}"#;
    assert_eq!(
        parse_google_claims(payload).err(),
        Some(CryptoError::DuplicateJwtClaim)
    );
}

#[test]
fn test_rejects_unsupported_alg() {
    let n = modulus();
    let hs256 = compact_jwt(
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"aud":"teton-verifier"}"#,
    );
    assert_eq!(
        verify_jwt_rs256(&hs256, &n, RSA_EXPONENT),
        Err(CryptoError::UnsupportedJwtAlgorithm)
    );
    assert_eq!(
        verify_jwt_rs256(VALID_JWT, &n, 3),
        Err(CryptoError::UnsupportedJwtAlgorithm)
    );
}

#[test]
fn test_es256_signature_parser_and_low_s() {
    let mut low = [0u8; 64];
    low[31] = 0x01;
    low[63] = 0x01;
    let parsed = parse_es256_signature(b64url_encode(&low).as_bytes()).expect("low-s");
    assert_eq!(parsed, low);
    let mut s_low = [0u8; 32];
    s_low.copy_from_slice(&low[32..]);
    assert!(es256_is_low_s(&s_low));
    assert!(es256_is_low_s(&P256_HALF_ORDER));

    let mut high = low;
    high[32..].copy_from_slice(&P256_HALF_ORDER);
    high[63] = high[63].wrapping_add(1);
    assert!(!es256_is_low_s(high[32..].try_into().expect("s")));
    assert_eq!(
        parse_es256_signature(b64url_encode(&high).as_bytes()),
        Err(CryptoError::InvalidJwtSignature)
    );

    assert_eq!(
        parse_es256_signature(b64url_encode(&[0u8; 64]).as_bytes()),
        Err(CryptoError::InvalidJwtSignature)
    );
}

#[test]
fn test_kid_hash_and_nonce_seed() {
    assert_eq!(kid_hash(b"teton-test"), hex32(KID_HASH_HEX));
    assert_eq!(eat_nonce_tombstone_seed(EAT_NONCE), hex32(NONCE_SEED_HEX));

    let view = JwtView::parse(VALID_JWT).expect("split");
    let kid = parse_header_kid_b64(view.header_b64).expect("kid");
    let kid_len = kid.iter().position(|&b| b == 0).unwrap_or(kid.len());
    assert_eq!(&kid[..kid_len], b"teton-test");
    assert_eq!(kid_hash(&kid[..kid_len]), hex32(KID_HASH_HEX));
}

#[test]
fn test_rejects_wrong_issuer() {
    let payload = br#"{"aud":"teton-verifier","dbgstat":"disabled-since-boot","eat_nonce":"nnnnnnnnnn","exp":4102444800,"iat":1700000000,"iss":"https://evil.example","secboot":true,"sub":"s","image_digest":"sha256:abababababababababababababababababababababababababababababababab"}"#;
    let claims = parse_google_claims(payload).expect("json claims");
    assert_eq!(
        enforce_google_policy(&claims, None),
        Err(CryptoError::PolicyViolation)
    );
}

#[test]
fn test_streaming_base64url_and_json_claims() {
    let mut out = [0u8; 8];
    let n = decode_b64url(b"AQID", &mut out).expect("b64");
    assert_eq!(&out[..n], &[1, 2, 3]);
    let n = decode_b64url(b"aGVsbG8", &mut out).expect("hello");
    assert_eq!(&out[..n], b"hello");
    assert!(decode_b64url(b"+/+/", &mut out).is_err());

    let claims = parse_google_claims(PAYLOAD_JSON).expect("json claims");
    assert_eq!(claims.aud(), b"teton-verifier");
    assert!(claims.secboot);
    assert_eq!(claims.image_digest, [0xab; 32]);
    assert_eq!(claims.eat_nonce(), EAT_NONCE);
}

fn google_shell(eat_nonce_json: &str, image_digest_json: &str) -> Vec<u8> {
    format!(
        r#"{{"aud":"teton-verifier","dbgstat":"disabled-since-boot","eat_nonce":{eat_nonce_json},"exp":4102444800,"iat":1700000000,"iss":"https://confidentialcomputing.googleapis.com","secboot":true,"sub":"s","submods":{{"container":{{"image_digest":{image_digest_json}}}}}}}"#
    )
    .into_bytes()
}

#[test]
fn test_eat_nonce_array_decodes_mode_a_binding() {
    let pk = [0x80u8; 32];
    let slot = [0x5au8; 32];
    let n0 = b64url_encode(&pk);
    let n1 = b64url_encode(&slot);
    assert_eq!(n0.len(), 43);
    assert_eq!(n1.len(), 43);
    let digest = r#""sha256:abababababababababababababababababababababababababababababababab""#;
    let payload = google_shell(&format!(r#"["{n0}","{n1}"]"#), digest);
    let claims = parse_google_claims(&payload).expect("two nonces");
    assert_eq!(claims.eat_nonce_count(), 2);
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&pk);
    raw[32..].copy_from_slice(&slot);
    let binding = claims.decode_mode_a_binding().expect("binding");
    assert_eq!(binding, raw);
    assert_eq!(
        eat_nonce_tombstone_seed(&raw),
        eat_nonce_tombstone_seed(&binding)
    );
}

#[test]
fn test_eat_nonce_and_image_digest_fail_closed() {
    let digest = r#""sha256:abababababababababababababababababababababababababababababababab""#;
    let short = google_shell(r#""nnnnnnnnn""#, digest);
    assert_eq!(
        parse_google_claims(&short).err(),
        Some(CryptoError::MalformedJwt)
    );
    let one = google_shell(r#"["nnnnnnnnnn"]"#, digest);
    assert_eq!(
        parse_google_claims(&one).err(),
        Some(CryptoError::MalformedJwt)
    );
    let three = google_shell(r#"["nnnnnnnnnn","nnnnnnnnnn","nnnnnnnnnn"]"#, digest);
    assert_eq!(
        parse_google_claims(&three).err(),
        Some(CryptoError::MalformedJwt)
    );
    let single = google_shell(
        r#""nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn""#,
        digest,
    );
    let claims = parse_google_claims(&single).expect("single string");
    assert_eq!(claims.eat_nonce_count(), 1);
    assert!(claims.decode_mode_a_binding().is_err());

    let nonce = r#""nnnnnnnnnn""#;
    let array_digest = google_shell(
        nonce,
        r#"["sha256:abababababababababababababababababababababababababababababababab"]"#,
    );
    let claims = parse_google_claims(&array_digest).expect("one-element digest");
    assert_eq!(claims.image_digest, [0xab; 32]);
    let two_digests = google_shell(
        nonce,
        r#"["sha256:abababababababababababababababababababababababababababababababab","sha256:abababababababababababababababababababababababababababababababab"]"#,
    );
    assert_eq!(
        parse_google_claims(&two_digests).err(),
        Some(CryptoError::MalformedJwt)
    );
    let empty_digest = google_shell(nonce, "[]");
    assert_eq!(
        parse_google_claims(&empty_digest).err(),
        Some(CryptoError::MalformedJwt)
    );
}

#[test]
fn test_mode_b_high_bit_commitment_decodes_before_tombstone() {
    let mut commitment = [0x5au8; 32];
    commitment[0] = 0x80;
    commitment[1] = 0xff;
    assert_ne!(commitment[0] & 0x80, 0);
    let encoded = b64url_encode(&commitment);
    assert_eq!(encoded.len(), 43);
    assert!(!encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'));
    assert_ne!(encoded.as_bytes()[..32], commitment[..]);
    let digest = r#""sha256:abababababababababababababababababababababababababababababababab""#;
    let payload = google_shell(&format!(r#""{encoded}""#), digest);
    let claims = parse_google_claims(&payload).expect("mode b nonce");
    assert_eq!(claims.eat_nonce_count(), 1);
    let raw = claims.decode_mode_b_commitment().expect("decode");
    assert_eq!(raw, commitment);
    assert_eq!(
        eat_nonce_tombstone_seed(&raw),
        eat_nonce_tombstone_seed(&commitment)
    );
    assert_ne!(
        eat_nonce_tombstone_seed(&raw),
        eat_nonce_tombstone_seed(encoded.as_bytes())
    );
    assert!(claims.decode_mode_a_binding().is_err());

    let long = google_shell(
        r#""nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn""#,
        digest,
    );
    let long_claims = parse_google_claims(&long).expect("long single nonce still parses");
    assert!(long_claims.decode_mode_b_commitment().is_err());
}

#[test]
fn explicit_tenant_policy_rejects_cross_tenant_and_empty_configuration() {
    use solana_confidential_compute_crypto::jwt::enforce_google_tenant;
    let claims = parse_google_claims(PAYLOAD_JSON).unwrap();
    assert_eq!(
        enforce_google_tenant(&claims, claims.aud(), claims.sub()),
        Ok(())
    );
    for (aud, sub) in [
        (b"other-audience".as_slice(), claims.sub()),
        (claims.aud(), b"other-subject".as_slice()),
        (b"".as_slice(), claims.sub()),
        (claims.aud(), b"".as_slice()),
    ] {
        assert_eq!(
            enforce_google_tenant(&claims, aud, sub),
            Err(CryptoError::PolicyViolation)
        );
    }
    let wrong = std::str::from_utf8(PAYLOAD_JSON)
        .unwrap()
        .replace("teton-verifier", "other-tenant");
    let wrong_claims = parse_google_claims(wrong.as_bytes()).unwrap();
    // The generic Google authenticity policy cannot determine the deployment tenant.
    assert_eq!(
        enforce_google_policy(&wrong_claims, Some(1_700_000_100)),
        Ok(())
    );
    assert_eq!(
        enforce_google_tenant(&wrong_claims, claims.aud(), claims.sub()),
        Err(CryptoError::PolicyViolation)
    );
}

#[test]
fn runtime_verifier_does_not_trust_legacy_montgomery_parameters() {
    let n = modulus();
    assert!(verify_jwt_rs256_with_montgomery(
        VALID_JWT,
        &n,
        RSA_EXPONENT,
        0,
        &[0; 256],
        Some(1_700_000_100)
    )
    .is_ok());
    let mut bad = VALID_JWT.as_bytes().to_vec();
    let i = VALID_JWT.rfind('.').unwrap() + 1;
    bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        verify_jwt_rs256_with_montgomery(
            std::str::from_utf8(&bad).unwrap(),
            &n,
            RSA_EXPONENT,
            0,
            &[0; 256],
            Some(1_700_000_100)
        ),
        Err(CryptoError::InvalidJwtSignature)
    );
}

#[test]
fn nested_security_claims_cannot_supply_root_claims() {
    let original = std::str::from_utf8(PAYLOAD_JSON).unwrap();
    for (key, value) in [
        (
            "eat_nonce",
            format!("\"{}\"", std::str::from_utf8(EAT_NONCE).unwrap()),
        ),
        ("aud", "\"teton-verifier\"".into()),
        ("exp", "4102444800".into()),
        ("secboot", "true".into()),
    ] {
        let member = format!("\"{key}\":{value},");
        let without = original.replace(&member, "");
        let nested = without.replace(
            "\"container\":{",
            &format!("\"container\":{{\"env\":{{{member}\"other\":0}},"),
        );
        assert!(
            parse_google_claims(nested.as_bytes()).is_err(),
            "nested {key} supplied root claim"
        );
        let encoded = b64url_encode(nested.as_bytes());
        assert!(
            solana_confidential_compute_crypto::jwt::parse_google_claims_b64(encoded.as_bytes())
                .is_err()
        );
    }
    let shadow = original.replace("\"container\":{", "\"container\":{\"env\":{\"eat_nonce\":\"host-value-long-enough\",\"aud\":\"host-audience\"},");
    let claims = parse_google_claims(shadow.as_bytes()).unwrap();
    assert_eq!(claims.eat_nonce(), EAT_NONCE);
    assert_eq!(claims.aud(), b"teton-verifier");
    assert_eq!(claims.image_digest, [0xab; 32]);
}

#[test]
fn image_digest_requires_an_explicit_supported_path() {
    let original = std::str::from_utf8(PAYLOAD_JSON).unwrap();
    let wrong = original
        .replace("\"container\":{", "\"container\":{\"env\":{")
        .replace("}}}", "}}}}");
    assert!(parse_google_claims(wrong.as_bytes()).is_err());
    assert!(parse_google_claims(PAYLOAD_JSON).is_ok());
}

#[test]
fn header_identifiers_reject_decoded_nul() {
    use solana_confidential_compute_crypto::jwt::claims::parse_header_alg_b64;
    for kid in [
        r#"teton-test\u0000suffix"#,
        r#"\u0000teton-test"#,
        r#"teton-test\u0000"#,
    ] {
        let header = format!(r#"{{"alg":"RS256","kid":"{kid}"}}"#);
        assert_eq!(
            parse_header_kid_b64(b64url_encode(header.as_bytes()).as_bytes()),
            Err(CryptoError::MalformedJwt)
        );
    }
    let header = b64url_encode(br#"{"alg":"RS256\u0000ES256","kid":"teton-test"}"#);
    assert_eq!(
        parse_header_alg_b64(header.as_bytes()),
        Err(CryptoError::MalformedJwt)
    );
    let header = b64url_encode(br#"{"alg":"RS256","kid":"teton-test"}"#);
    assert!(parse_header_alg_b64(header.as_bytes()).is_ok());
    assert_eq!(
        &parse_header_kid_b64(header.as_bytes()).unwrap()[..10],
        b"teton-test"
    );
}
