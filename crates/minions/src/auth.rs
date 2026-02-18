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
            if token == expected_key.as_str() {
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
