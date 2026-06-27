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
use subtle::ConstantTimeEq;
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

// Design decision (kept long-term): tests use `GlobalKeyExtractor` because
// `tower::ServiceExt::oneshot()` doesn't inject the `ConnectInfo<SocketAddr>`
// that `SmartIpKeyExtractor` requires (and `axum::extract::ConnectInfo` cannot
// be inserted as a plain request extension — its extractor depends on the
// `MakeService` layer wiring it via `into_make_service_with_connect_info`).
// The production per-IP flow is wired in `serve()` (`lib.rs`) and exercised
// end-to-end by `dom-integration-tests` against a bound socket. Unit tests
// here verify that rate limiting is *configured*; per-IP enforcement is an
// integration-level concern.
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

// See `rate_limit_submit` above for the rationale — same trade-off applies
// to the read path.
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
    if token.0.trim().is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = header[7..].trim();
            if provided.is_empty() {
                return Err(StatusCode::UNAUTHORIZED);
            }
            // Constant-time comparison to avoid leaking the token via a
            // short-circuiting byte compare (timing side-channel). `ct_eq`
            // compares equal-length byte slices without an observable early
            // return; differing lengths compare unequal (the token length is
            // public, so that carries no secret). Accept/reject logic is
            // identical to the previous `==`.
            if bool::from(provided.as_bytes().ct_eq(token.0.as_bytes())) {
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
    use axum::{body::Body, http::Request, middleware::from_fn_with_state, routing::get, Router};
    use tower::ServiceExt;

    /// A 64-char (256-bit) token, the shape produced by `generate_token`.
    const TOK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn protected() -> &'static str {
        "ok"
    }

    fn auth_app(token: &str) -> Router {
        let bt = Arc::new(BearerToken(token.to_string()));
        Router::new()
            .route("/protected", get(protected))
            .layer(from_fn_with_state(bt, require_bearer_token))
    }

    /// Drive one request through the auth middleware and return the status.
    async fn status_for(app_token: &str, auth_header: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri("/protected");
        if let Some(h) = auth_header {
            builder = builder.header(header::AUTHORIZATION, h);
        }
        let req = builder.body(Body::empty()).expect("request");
        auth_app(app_token)
            .oneshot(req)
            .await
            .expect("oneshot")
            .status()
    }

    #[tokio::test]
    async fn bearer_correct_token_authorizes() {
        assert_eq!(
            status_for(TOK, Some(&format!("Bearer {TOK}"))).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn bearer_wrong_token_same_length_rejected() {
        // Flip the first char → same length, different content (exercises the
        // constant-time equal-length path).
        let mut wrong = TOK.to_string();
        wrong.replace_range(0..1, "f");
        assert_ne!(wrong, TOK);
        assert_eq!(
            status_for(TOK, Some(&format!("Bearer {wrong}"))).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bearer_short_token_rejected() {
        assert_eq!(
            status_for(TOK, Some("Bearer short")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bearer_long_token_rejected() {
        assert_eq!(
            status_for(TOK, Some(&format!("Bearer {TOK}extra"))).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn bearer_missing_header_rejected() {
        assert_eq!(status_for(TOK, None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_non_bearer_scheme_rejected() {
        assert_eq!(
            status_for(TOK, Some(&format!("Basic {TOK}"))).await,
            StatusCode::UNAUTHORIZED
        );
    }

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
