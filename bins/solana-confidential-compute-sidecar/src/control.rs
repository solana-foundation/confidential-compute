//! Operator-only HTTP enrollment controls. The heartbeat uses the same operation
//! lock, but retains its configured autonomous renewal schedule.

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use crate::error::SidecarError;

pub struct EnrollmentControl {
    token: Option<Zeroizing<String>>,
    min_interval: Duration,
    attempts: Mutex<Option<Instant>>,
}

/// Default minimum interval between enrollment attempts. `new` accepts 60 to 86400.
const DEFAULT_MIN_INTERVAL_SECS: u64 = 300;

impl Default for EnrollmentControl {
    /// Enrollment over HTTP is off (no token) and the interval is the default.
    fn default() -> Self {
        Self { token: None, min_interval: Duration::from_secs(DEFAULT_MIN_INTERVAL_SECS), attempts: Mutex::new(None) }
    }
}

impl EnrollmentControl {
    /// Token material must be random, URL-safe ASCII, and held only by operators.
    pub fn new(token: Option<Zeroizing<String>>, min_interval_secs: u64) -> Result<Self, SidecarError> {
        if !(60..=86400).contains(&min_interval_secs) {
            return Err(SidecarError::InvalidConfig(
                "enrollment minimum interval must be between 60 and 86400 seconds".into(),
            ));
        }
        if token.as_ref().is_some_and(|token| {
            !(32..=128).contains(&token.len())
                || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }) {
            return Err(SidecarError::InvalidConfig(
                "enrollment token must contain 32-128 URL-safe ASCII characters".into(),
            ));
        }
        Ok(Self { token, min_interval: Duration::from_secs(min_interval_secs), attempts: Mutex::new(None) })
    }

    pub(crate) async fn lock(&self) -> MutexGuard<'_, Option<Instant>> {
        self.attempts.lock().await
    }

    pub(crate) fn begin_http(
        &self,
        headers: &HeaderMap,
    ) -> Result<MutexGuard<'_, Option<Instant>>, EnrollmentRejection> {
        let Some(expected) = &self.token else {
            return Err(EnrollmentRejection::Disabled);
        };
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let provided =
            values.next().and_then(|value| value.to_str().ok()).and_then(|value| value.strip_prefix("Bearer "));
        if values.next().is_some()
            || !provided.is_some_and(|value| bool::from(expected.as_bytes().ct_eq(value.as_bytes())))
        {
            return Err(EnrollmentRejection::Unauthorized);
        }
        let mut attempt = self.attempts.try_lock().map_err(|_| EnrollmentRejection::RateLimited(1))?;
        if let Some(last) = *attempt {
            if let Some(remaining) = self.min_interval.checked_sub(last.elapsed()) {
                return Err(EnrollmentRejection::RateLimited(remaining.as_secs().saturating_add(1)));
            }
        }
        // Charge failed and cancelled attempts too. Retain the lock across all
        // provider/RPC work so concurrent calls cannot queue paid enrollments.
        *attempt = Some(Instant::now());
        Ok(attempt)
    }
}

#[derive(Debug)]
pub(crate) enum EnrollmentRejection {
    Disabled,
    Unauthorized,
    RateLimited(u64),
}

impl IntoResponse for EnrollmentRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Disabled => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "HTTP enrollment is disabled; configure an operator token file"})),
            )
                .into_response(),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                Json(serde_json::json!({"error": "operator bearer token required"})),
            )
                .into_response(),
            Self::RateLimited(seconds) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, seconds.to_string())],
                Json(serde_json::json!({"error": "enrollment busy or cooling down"})),
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Default` builds the same control as `new(None, DEFAULT_MIN_INTERVAL_SECS)`:
    /// no token and the default interval.
    #[test]
    fn default_matches_new_with_no_token() {
        let default = EnrollmentControl::default();
        let built = EnrollmentControl::new(None, DEFAULT_MIN_INTERVAL_SECS).unwrap();
        assert!(default.token.is_none() && built.token.is_none());
        assert_eq!(default.min_interval, built.min_interval);
        assert_eq!(default.min_interval, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn cooldown_expires_and_rejected_auth_does_not_consume_it() {
        let token = "0123456789abcdef0123456789abcdef";
        let control = EnrollmentControl::new(Some(Zeroizing::new(token.into())), 60).unwrap();
        assert!(control.begin_http(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        drop(control.begin_http(&headers).unwrap());
        assert!(control.begin_http(&headers).is_err());
        *control.lock().await = Some(Instant::now() - Duration::from_secs(61));
        assert!(control.begin_http(&headers).is_ok());
    }

    #[test]
    fn malformed_token_and_unsafe_interval_fail_closed() {
        for token in ["", "short", "0123456789abcdef0123456789abcdef\n", "0123456789abcdef0123456789abcdef "] {
            assert!(EnrollmentControl::new(Some(Zeroizing::new(token.into())), 300).is_err());
        }
        for seconds in [0, 1, 59, 86401, u64::MAX] {
            assert!(EnrollmentControl::new(None, seconds).is_err());
        }
    }
}
