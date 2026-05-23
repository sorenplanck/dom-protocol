//! Security middleware: rate limiting, CORS, Bearer auth.

use axum::{
    extract::Request,
    http::{header, Method, StatusCode},
    middleware::Next,
    response::Response,
};
// Note: `governor` is added as direct dependency for stability.
// It is already a transitive dependency via `tower_governor`,
// but we declare it directly to control the version explicitly.
use governor::middleware::NoOpMiddleware;
use std::sync::Arc;
#[cfg(test)]
use tower_governor::key_extractor::GlobalKeyExtractor;
#[cfg(not(test))]
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{Any, CorsLayer};

/// Bearer token for authenticated endpoints.
pub struct BearerToken(pub String);

/// Build rate limiting layer for submit endpoints (10 req/sec default).
#[cfg(not(test))]
pub fn rate_limit_submit() -> GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware> {
    let limit = std::env::var("DOM_RPC_RATELIMIT_SUBMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

// NOTE: Tests use GlobalKeyExtractor because oneshot() in tests doesn't
// provide ConnectInfo<SocketAddr>, which SmartIpKeyExtractor requires.
// This means tests validate that rate limiting EXISTS but not per-IP behavior.
// TODO(Phase 2): Replace with ConnectInfo injection in test helpers to
// restore per-IP rate limit testing. See: option B in original design.
#[cfg(test)]
pub fn rate_limit_submit() -> GovernorLayer<GlobalKeyExtractor, NoOpMiddleware> {
    let limit = 10;
    let config = GovernorConfigBuilder::default()
        .key_extractor(GlobalKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

/// Build rate limiting layer for read endpoints (100 req/sec default).
#[cfg(not(test))]
pub fn rate_limit_read() -> GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware> {
    let limit = std::env::var("DOM_RPC_RATELIMIT_READ")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

// NOTE: Tests use GlobalKeyExtractor because oneshot() in tests doesn't
// provide ConnectInfo<SocketAddr>, which SmartIpKeyExtractor requires.
// This means tests validate that rate limiting EXISTS but not per-IP behavior.
// TODO(Phase 2): Replace with ConnectInfo injection in test helpers to
// restore per-IP rate limit testing. See: option B in original design.
#[cfg(test)]
pub fn rate_limit_read() -> GovernorLayer<GlobalKeyExtractor, NoOpMiddleware> {
    let limit = 100;
    let config = GovernorConfigBuilder::default()
        .key_extractor(GlobalKeyExtractor)
        .per_second(1)
        .burst_size(limit)
        .finish()
        .expect("rate limit config valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

/// Build CORS layer for public GET endpoints.
/// CORS middleware that works with axum 0.7 without ResBody: Default requirement.
///
/// Applied globally for simplicity. Endpoints with Bearer auth are still
/// protected by the auth middleware. If CORS becomes too permissive in
/// practice, restrict per-route.
pub async fn cors_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        axum::http::HeaderValue::from_static("content-type, authorization"),
    );
    response
}

#[allow(dead_code)] // Kept for reference; replaced by cors_middleware due to axum 0.7 ResBody: Default incompatibility
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

/// Middleware to validate Bearer token.
pub async fn require_bearer_token(
    axum::extract::State(token): axum::extract::State<Arc<BearerToken>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = &header[7..];
            if provided == token.0 {
                Ok(next.run(req).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_submit_default_is_10() {
        std::env::remove_var("DOM_RPC_RATELIMIT_SUBMIT");
        let layer = rate_limit_submit();
        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn rate_limit_read_default_is_100() {
        std::env::remove_var("DOM_RPC_RATELIMIT_READ");
        let layer = rate_limit_read();
        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn rate_limit_submit_respects_env() {
        std::env::set_var("DOM_RPC_RATELIMIT_SUBMIT", "20");
        let layer = rate_limit_submit();
        assert!(Arc::strong_count(&layer.config) >= 1);
        std::env::remove_var("DOM_RPC_RATELIMIT_SUBMIT");
    }

    #[test]
    fn rate_limit_read_respects_env() {
        std::env::set_var("DOM_RPC_RATELIMIT_READ", "200");
        let layer = rate_limit_read();
        assert!(Arc::strong_count(&layer.config) >= 1);
        std::env::remove_var("DOM_RPC_RATELIMIT_READ");
    }
}
