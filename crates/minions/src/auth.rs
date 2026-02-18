//! API authentication via bearer tokens.

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct AuthConfig {
    /// API key for bearer token authentication.
    /// If None, authentication is disabled (INSECURE - development only).
    pub api_key: Option<Arc<String>>,
}

impl AuthConfig {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key: api_key.map(Arc::new),
        }
    }

    pub fn enabled(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Compare two strings in constant time to prevent timing side-channel attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Middleware that checks for a valid bearer token.
pub async fn require_auth(
    State(auth): State<AuthConfig>,
    request: Request,
    next: Next,
) -> Response {
    // If auth is disabled, pass through
    if !auth.enabled() {
        return next.run(request).await;
    }

    let expected_key = auth.api_key.as_ref().unwrap();

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..]; // Skip "Bearer "
            // Use constant-time comparison to prevent timing attacks
            if constant_time_eq(token, expected_key.as_str()) {
                // Valid token - proceed
                next.run(request).await
            } else {
                // Invalid token
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "invalid API key".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        _ => {
            // Missing or malformed Authorization header
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing or invalid Authorization header (expected: Bearer <api_key>)"
                        .to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_matches() {
        assert!(constant_time_eq("secret-key-abc", "secret-key-abc"));
    }

    #[test]
    fn test_constant_time_eq_differs() {
        assert!(!constant_time_eq("secret-key-abc", "secret-key-xyz"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("short", "much-longer-key"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq("", ""));
        assert!(!constant_time_eq("", "nonempty"));
    }
}
