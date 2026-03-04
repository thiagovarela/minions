//! API authentication via bearer tokens.

use axum::{
    Json,
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Clone, Debug)]
pub enum AuthContext {
    /// Admin API key — full access, can specify owner_id.
    Admin,
    /// Per-user API token — scoped to user's resources.
    User { user_id: String, email: String },
}

#[derive(Clone)]
pub struct AuthConfig {
    /// API key for admin bearer token authentication.
    /// If None, authentication is disabled (INSECURE - development only).
    pub api_key: Option<Arc<String>>,
    /// Path to the SQLite database for user token lookups.
    pub db_path: String,
}

impl AuthConfig {
    pub fn new(api_key: Option<String>, db_path: String) -> Self {
        Self {
            api_key: api_key.map(Arc::new),
            db_path,
        }
    }

    pub fn enabled(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Compare two strings in constant time to prevent timing side-channel attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Hash a raw token using SHA-256 for database lookup.
fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Middleware that checks for a valid bearer token.
/// Supports both admin API key and per-user API tokens (mnt_... format).
pub async fn require_auth(
    State(auth): State<AuthConfig>,
    mut request: Request,
    next: Next,
) -> Response {
    // If auth is disabled (no api_key configured), treat as admin
    if !auth.enabled() {
        request.extensions_mut().insert(AuthContext::Admin);
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

            // Check if it's the admin key
            if constant_time_eq(token, expected_key.as_str()) {
                request.extensions_mut().insert(AuthContext::Admin);
                return next.run(request).await;
            }

            // Check if it's a user token (mnt_... format)
            if token.starts_with("mnt_") {
                let token_hash = hash_token(token);
                match minions_db::open(&auth.db_path) {
                    Ok(conn) => {
                        match minions_db::validate_api_token(&conn, &token_hash) {
                            Ok(Some((user_id, email))) => {
                                request.extensions_mut().insert(AuthContext::User {
                                    user_id,
                                    email,
                                });
                                return next.run(request).await;
                            }
                            Ok(None) => {
                                // Token not found or revoked
                            }
                            Err(e) => {
                                tracing::error!("token validation error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to open db for auth: {}", e);
                    }
                }
            }

            // Invalid token
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid API key or token".to_string(),
                }),
            )
                .into_response()
        }
        _ => {
            // Missing or malformed Authorization header
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing or invalid Authorization header (expected: Bearer <token>)"
                        .to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Extractor for AuthContext from request extensions.
#[derive(Clone)]
pub struct Auth(pub AuthContext);

impl std::ops::Deref for Auth {
    type Target = AuthContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<S> axum::extract::FromRequestParts<S> for Auth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .map(Auth)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "authentication required".to_string(),
                    }),
                )
            })
    }
}

/// Extract the AuthContext from a request (for use in middleware).
/// Panics if the auth middleware hasn't run.
pub fn auth_context(request: &Request) -> &AuthContext {
    request
        .extensions()
        .get::<AuthContext>()
        .expect("auth middleware must run before extracting auth context")
}

/// Get the effective owner_id from auth context.
/// - Admin: uses the provided owner_id (from query/body) if given
/// - User: always returns the user's own id (ignores provided value)
pub fn effective_owner(auth: &AuthContext, provided: Option<&str>) -> Option<String> {
    match auth {
        AuthContext::Admin => provided.map(|s| s.to_string()),
        AuthContext::User { user_id, .. } => Some(user_id.clone()),
    }
}

/// Check if the auth context can access a VM.
pub fn can_access_vm(auth: &AuthContext, vm: &minions_db::Vm) -> bool {
    match auth {
        AuthContext::Admin => true,
        AuthContext::User { user_id, .. } => vm.owner_id.as_deref() == Some(user_id.as_str()),
    }
}

/// Middleware that allows public access (no auth required).
/// Used for registration and OAuth endpoints.
pub async fn public_access(request: Request, next: Next) -> Response {
    next.run(request).await
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

    #[test]
    fn test_effective_owner() {
        let admin = AuthContext::Admin;
        assert_eq!(effective_owner(&admin, None), None);
        assert_eq!(effective_owner(&admin, Some("user-123")), Some("user-123".to_string()));

        let user = AuthContext::User {
            user_id: "user-456".to_string(),
            email: "test@example.com".to_string(),
        };
        assert_eq!(effective_owner(&user, None), Some("user-456".to_string()));
        assert_eq!(effective_owner(&user, Some("user-123")), Some("user-456".to_string()));
    }

    #[test]
    fn test_can_access_vm() {
        let admin = AuthContext::Admin;
        let vm = minions_db::Vm {
            name: "test".to_string(),
            status: "running".to_string(),
            ip: "10.0.0.1".to_string(),
            vsock_cid: 3,
            ch_pid: None,
            ch_api_socket: "/tmp/test.sock".to_string(),
            ch_vsock_socket: "/tmp/vsock.sock".to_string(),
            tap_device: "tap0".to_string(),
            mac_address: "02:00:00:00:00:01".to_string(),
            vcpus: 2,
            memory_mb: 1024,
            rootfs_path: "/tmp/rootfs.ext4".to_string(),
            created_at: "2025-01-01".to_string(),
            stopped_at: None,
            proxy_port: 80,
            proxy_public: false,
            owner_id: Some("user-123".to_string()),
            host_id: None,
            os_type: "ubuntu".to_string(),
        };
        assert!(can_access_vm(&admin, &vm));

        let owner = AuthContext::User {
            user_id: "user-123".to_string(),
            email: "owner@example.com".to_string(),
        };
        assert!(can_access_vm(&owner, &vm));

        let other = AuthContext::User {
            user_id: "user-456".to_string(),
            email: "other@example.com".to_string(),
        };
        assert!(!can_access_vm(&other, &vm));

        let mut vm_no_owner = vm.clone();
        vm_no_owner.owner_id = None;
        assert!(!can_access_vm(&other, &vm_no_owner));
    }
}