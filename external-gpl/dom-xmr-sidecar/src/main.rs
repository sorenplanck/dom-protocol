//! GPL live Monero sweep sidecar built inside the pinned Eigenwallet workspace.

mod auth;
mod cache;
mod http;
mod wire;

use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use auth::AuthKey;
use cache::{CacheError, SweepCache};
use http::{read_request, write_error, write_json};
use monero_daemon_rpc::MoneroDaemon;
use monero_oxide_wallet::ed25519::{CompressedPoint, Point, Scalar};
use monero_simple_request_rpc::SimpleRequestTransport;
use tokio::net::{TcpListener, TcpStream};
use wire::*;
use zeroize::Zeroizing;

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    uds_path: PathBuf,
    monerod_url: String,
    cache: SweepCache,
    auth: Arc<AuthKey>,
}

#[tokio::main]
async fn main() -> Result<()> {
    initialize_tracing();
    let config = Arc::new(load_config()?);
    if !config.listen.ip().is_loopback() {
        anyhow::bail!("sidecar must bind to a loopback address");
    }
    let listener = TcpListener::bind(config.listen).await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    let uds_config = Arc::clone(&config);
    tokio::spawn(async move {
        if let Err(error) = run_uds(uds_config).await {
            tracing::error!(error = %error, "sidecar UDS listener failed");
        }
    });
    tracing::info!(listen = %config.listen, "dom-xmr-sidecar TCP listening");
    tracing::info!(uds = %config.uds_path.display(), "dom-xmr-sidecar UDS listening");
    loop {
        let (stream, peer) = listener.accept().await.context("accept failed")?;
        if !peer.ip().is_loopback() { continue; }
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, config).await {
                tracing::error!(error = %error, "sidecar request failed");
            }
        });
    }
}


fn initialize_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn load_config() -> Result<Config> {
    let listen = env::var("DOM_XMR_SIDECAR_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:19081".to_owned())
        .parse::<SocketAddr>().context("invalid DOM_XMR_SIDECAR_LISTEN")?;
    let monerod_url = env::var("DOM_XMR_MONEROD_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18081".to_owned());
    if !(monerod_url.starts_with("http://127.0.0.1:")
        || monerod_url.starts_with("http://localhost:")
        || monerod_url.starts_with("http://[::1]:"))
    {
        anyhow::bail!("DOM_XMR_MONEROD_URL must be loopback HTTP");
    }
    let key_hex = env::var("DOM_XMR_SIDECAR_AUTH_HEX")
        .context("DOM_XMR_SIDECAR_AUTH_HEX is required")?;
    let key_vec = hex::decode(key_hex).context("sidecar auth key is not hex")?;
    let key: [u8; 32] = key_vec.try_into().map_err(|_| anyhow::anyhow!("sidecar auth key must be 32 bytes"))?;
    let cache_dir = PathBuf::from(env::var("DOM_XMR_SIDECAR_CACHE_DIR")
        .unwrap_or_else(|_| "./dom-xmr-sidecar-cache".to_owned()));
    let uds_path = PathBuf::from(env::var("DOM_XMR_SIDECAR_UDS")
        .unwrap_or_else(|_| "/tmp/dom-xmr-sidecar.sock".to_owned()));
    Ok(Config {
        listen,
        uds_path,
        monerod_url,
        cache: SweepCache::open(cache_dir).context("failed to open sidecar cache")?,
        auth: Arc::new(AuthKey::new(key).context("invalid sidecar auth key")?),
    })
}

async fn handle_connection(mut stream: TcpStream, config: Arc<Config>) -> Result<()> {
    let request = match read_request(&mut stream).await {
        Ok(value) => value,
        Err(http::HttpError::TooLarge) => {
            return write_error(&mut stream, 413, "request_too_large", "request exceeds bound", false)
                .await.map_err(Into::into);
        }
        Err(_) => {
            return write_error(&mut stream, 400, "malformed_http", "malformed request", false)
                .await.map_err(Into::into);
        }
    };
    if request.method != "POST" {
        return write_error(&mut stream, 404, "not_found", "endpoint not found", false)
            .await.map_err(Into::into);
    }
    match request.path.as_str() {
        "/v2/verify-funding" => verify_funding_endpoint(&mut stream, &config, &request.body).await,
        "/v2/build-sweep" => build_sweep_endpoint(&mut stream, &config, &request.body).await,
        _ => write_error(&mut stream, 404, "not_found", "endpoint not found", false)
            .await.map_err(Into::into),
    }
}

async fn verify_funding_endpoint(
    stream: &mut TcpStream,
    config: &Config,
    body: &[u8],
) -> Result<()> {
    let request: VerifyFundingRequestV2 = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return write_error(stream, 400, "invalid_json", "invalid request", false).await.map_err(Into::into),
    };
    if request.validate_public_fields().is_err() {
        return write_error(stream, 422, "invalid_request", "invalid funding request", false).await.map_err(Into::into);
    }
    if config.auth.verify_funding(&request).is_err() {
        return write_error(stream, 401, "auth_failed", "authentication failed", false).await.map_err(Into::into);
    }
    let result = verify_funding(config, &request).await;
    match result {
        Ok(response) => write_json(stream, 200, &response).await.map_err(Into::into),
        Err(SidecarOperationError::Retryable) => write_error(stream, 503, "monerod_unavailable", "Monero backend unavailable", true).await.map_err(Into::into),
        Err(SidecarOperationError::Rejected(message)) => write_error(stream, 422, "funding_rejected", &message, false).await.map_err(Into::into),
    }
}

async fn build_sweep_endpoint(
    stream: &mut TcpStream,
    config: &Config,
    body: &[u8],
) -> Result<()> {
    let request: BuildSweepRequestV2 = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return write_error(stream, 400, "invalid_json", "invalid request", false).await.map_err(Into::into),
    };
    if request.validate_public_fields().is_err() {
        return write_error(stream, 422, "invalid_request", "invalid sweep request", false).await.map_err(Into::into);
    }
    if config.auth.verify_build(&request).is_err() {
        return write_error(stream, 401, "auth_failed", "authentication failed", false).await.map_err(Into::into);
    }
    let canonical = request.canonical_auth_bytes().context("canonical request")?;
    let request_hash = SweepCache::request_hash(&canonical);
    match config.cache.load(&request.request_nonce, &request_hash) {
        Ok(Some(response)) => return write_json(stream, 200, &response).await.map_err(Into::into),
        Ok(None) => {}
        Err(CacheError::Conflict) => return write_error(stream, 409, "nonce_conflict", "request nonce reused with different bytes", false).await.map_err(Into::into),
        Err(_) => return write_error(stream, 503, "cache_unavailable", "idempotency cache unavailable", true).await.map_err(Into::into),
    }
    let result = build_sweep(config, &request).await;
    match result {
        Ok(response) => {
            if let Err(error) = config.cache.store(&request.request_nonce, request_hash, &response) {
                let (status, code, retryable) = match error {
                    CacheError::Conflict => (409, "nonce_conflict", false),
                    _ => (503, "cache_unavailable", true),
                };
                return write_error(stream, status, code, "failed to persist exact signed transaction", retryable).await.map_err(Into::into);
            }
            write_json(stream, 200, &response).await.map_err(Into::into)
        }
        Err(SidecarOperationError::Retryable) => write_error(stream, 503, "monerod_unavailable", "Monero backend unavailable", true).await.map_err(Into::into),
        Err(SidecarOperationError::Rejected(message)) => write_error(stream, 422, "sweep_rejected", &message, false).await.map_err(Into::into),
    }
}

#[derive(Debug)]
enum SidecarOperationError { Retryable, Rejected(String) }

async fn monerod(config: &Config) -> Result<MoneroDaemon<SimpleRequestTransport>, SidecarOperationError> {
    SimpleRequestTransport::new(config.monerod_url.clone()).await
        .map_err(|_| SidecarOperationError::Retryable)
}

async fn verify_funding(
    config: &Config,
    request: &VerifyFundingRequestV2,
) -> Result<VerifyFundingResponseV2, SidecarOperationError> {
    let public_spend = parse_point(request.expected_spend_public_key)?;
    let view = request.view_scalar.expose(|bytes| parse_scalar(*bytes))?;
    let rpc = monerod(config).await?;
    let amount = monero_wallet_ng::verify::largest_received_utxo(
        &rpc,
        request.funding_tx_hash,
        public_spend,
        Zeroizing::new(view),
    ).await.map_err(|_| SidecarOperationError::Retryable)?;
    if amount != Some(request.expected_amount_piconero) {
        return Err(SidecarOperationError::Rejected("funding output amount/view pair mismatch".to_owned()));
    }
    Ok(VerifyFundingResponseV2 {
        api_version: API_VERSION_V2,
        request_nonce: request.request_nonce,
        funding_tx_hash: request.funding_tx_hash,
        event_index: 0,
        received_amount_piconero: request.expected_amount_piconero,
        spendable: true,
    })
}

async fn build_sweep(
    config: &Config,
    request: &BuildSweepRequestV2,
) -> Result<BuildSweepResponseV2, SidecarOperationError> {
    let spend = request.spend_scalar.expose(|bytes| parse_scalar(*bytes))?;
    let view = request.view_scalar.expose(|bytes| parse_scalar(*bytes))?;
    let public = monero_wallet_ng::util::public_key(&spend).compress().to_bytes();
    if public != request.expected_spend_public_key {
        return Err(SidecarOperationError::Rejected("private/public spend key mismatch".to_owned()));
    }
    let destination = request.destination.parse::<monero_address::MoneroAddress>()
        .map_err(|_| SidecarOperationError::Rejected("invalid Monero destination".to_owned()))?;
    let rpc = monerod(config).await?;
    let amount = monero_wallet_ng::verify::largest_received_utxo(
        &rpc,
        request.funding_tx_hash,
        parse_point(request.expected_spend_public_key)?,
        Zeroizing::new(view),
    ).await.map_err(|_| SidecarOperationError::Retryable)?;
    if amount != Some(request.expected_amount_piconero) {
        return Err(SidecarOperationError::Rejected("funding output changed or is not spendable".to_owned()));
    }
    let rpc = monerod(config).await?;
    let transaction = monero_wallet_ng::sweep::construct_sweep_tx_to_single(
        rpc,
        Zeroizing::new(spend),
        Zeroizing::new(view),
        request.funding_tx_hash,
        destination,
        None,
    ).await.map_err(|error| classify_sweep_error(&error))?;
    let raw_tx = transaction.serialize();
    if raw_tx.is_empty() || raw_tx.len() > MAX_RAW_TX_BYTES {
        return Err(SidecarOperationError::Rejected("signed transaction exceeds bound".to_owned()));
    }
    Ok(BuildSweepResponseV2 {
        api_version: API_VERSION_V2,
        request_nonce: request.request_nonce,
        tx_hash: transaction.hash(),
        raw_tx,
    })
}

fn parse_scalar(bytes: [u8; 32]) -> Result<Scalar, SidecarOperationError> {
    let mut input = bytes.as_slice();
    let scalar = Scalar::read(&mut input)
        .map_err(|_| SidecarOperationError::Rejected("non-canonical scalar".to_owned()))?;
    if !input.is_empty() || scalar == Scalar::zero() {
        return Err(SidecarOperationError::Rejected("zero or trailing scalar bytes".to_owned()));
    }
    Ok(scalar)
}

fn parse_point(bytes: [u8; 32]) -> Result<Point, SidecarOperationError> {
    let mut input = bytes.as_slice();
    let compressed = CompressedPoint::read(&mut input)
        .map_err(|_| SidecarOperationError::Rejected("invalid public spend key".to_owned()))?;
    if !input.is_empty() {
        return Err(SidecarOperationError::Rejected("trailing public key bytes".to_owned()));
    }
    compressed.decompress()
        .filter(|point| point.is_torsion_free())
        .ok_or_else(|| SidecarOperationError::Rejected("non-prime-order public spend key".to_owned()))
}

fn classify_sweep_error(error: &monero_wallet_ng::sweep::SweepError) -> SidecarOperationError {
    use monero_wallet_ng::sweep::SweepError;
    match error {
        SweepError::TransactionNotFound { .. }
        | SweepError::TransactionInMempool { .. }
        | SweepError::BlockNotFound { .. }
        | SweepError::StatusLookup(_)
        | SweepError::Fee(_)
        | SweepError::Decoys(_)
        | SweepError::Interface(_) => SidecarOperationError::Retryable,
        _ => SidecarOperationError::Rejected(error.to_string()),
    }
}


#[cfg(unix)]
async fn run_uds(config: Arc<Config>) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::net::UnixListener;

    if let Ok(metadata) = std::fs::symlink_metadata(&config.uds_path) {
        if !metadata.file_type().is_socket() {
            anyhow::bail!("refusing to replace non-socket UDS path");
        }
        std::fs::remove_file(&config.uds_path).context("remove stale UDS")?;
    }
    if let Some(parent) = config.uds_path.parent() {
        std::fs::create_dir_all(parent).context("create UDS parent")?;
    }
    let listener = UnixListener::bind(&config.uds_path).context("bind UDS")?;
    std::fs::set_permissions(&config.uds_path, std::fs::Permissions::from_mode(0o600))
        .context("set UDS permissions")?;
    loop {
        let (stream, _) = listener.accept().await.context("accept UDS")?;
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(error) = handle_uds(stream, config).await {
                tracing::error!(error = %error, "sidecar UDS request failed");
            }
        });
    }
}

#[cfg(not(unix))]
async fn run_uds(_config: Arc<Config>) -> Result<()> {
    anyhow::bail!("Unix-domain sidecar requires Unix")
}

#[cfg(unix)]
async fn handle_uds(
    mut stream: tokio::net::UnixStream,
    config: Arc<Config>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).await.context("read UDS frame length")?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return write_uds_response(&mut stream, SidecarResponseV2::Error(SidecarErrorBody {
            code: "frame_too_large".to_owned(),
            message: "frame exceeds bound".to_owned(),
            retryable: false,
        })).await;
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await.context("read UDS frame")?;
    let request = match serde_json::from_slice::<SidecarRequestV2>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return write_uds_response(&mut stream, SidecarResponseV2::Error(SidecarErrorBody {
                code: "invalid_json".to_owned(),
                message: "malformed sidecar request".to_owned(),
                retryable: false,
            })).await;
        }
    };
    let response = match request {
        SidecarRequestV2::VerifyFunding(request) => {
            if request.validate_public_fields().is_err() || config.auth.verify_funding(&request).is_err() {
                SidecarResponseV2::Error(SidecarErrorBody {
                    code: "auth_or_request_failed".to_owned(),
                    message: "request rejected".to_owned(),
                    retryable: false,
                })
            } else {
                match verify_funding(&config, &request).await {
                    Ok(value) => SidecarResponseV2::Funding(value),
                    Err(SidecarOperationError::Retryable) => SidecarResponseV2::Error(SidecarErrorBody {
                        code: "monerod_unavailable".to_owned(),
                        message: "Monero backend unavailable".to_owned(),
                        retryable: true,
                    }),
                    Err(SidecarOperationError::Rejected(message)) => SidecarResponseV2::Error(SidecarErrorBody {
                        code: "funding_rejected".to_owned(), message, retryable: false,
                    }),
                }
            }
        }
        SidecarRequestV2::BuildSweep(request) => {
            if request.validate_public_fields().is_err() || config.auth.verify_build(&request).is_err() {
                SidecarResponseV2::Error(SidecarErrorBody {
                    code: "auth_or_request_failed".to_owned(),
                    message: "request rejected".to_owned(),
                    retryable: false,
                })
            } else {
                let canonical = match request.canonical_auth_bytes() {
                    Ok(value) => value,
                    Err(_) => {
                        return write_uds_response(&mut stream, SidecarResponseV2::Error(SidecarErrorBody {
                            code: "invalid_request".to_owned(),
                            message: "request canonicalization failed".to_owned(),
                            retryable: false,
                        })).await;
                    }
                };
                let request_hash = SweepCache::request_hash(&canonical);
                match config.cache.load(&request.request_nonce, &request_hash) {
                    Ok(Some(value)) => SidecarResponseV2::Sweep(value),
                    Err(CacheError::Conflict) => SidecarResponseV2::Error(SidecarErrorBody {
                        code: "nonce_conflict".to_owned(),
                        message: "nonce reused with different request".to_owned(),
                        retryable: false,
                    }),
                    Err(_) => SidecarResponseV2::Error(SidecarErrorBody {
                        code: "cache_unavailable".to_owned(),
                        message: "idempotency cache unavailable".to_owned(),
                        retryable: true,
                    }),
                    Ok(None) => match build_sweep(&config, &request).await {
                        Ok(value) => match config.cache.store(&request.request_nonce, request_hash, &value) {
                            Ok(()) => SidecarResponseV2::Sweep(value),
                            Err(CacheError::Conflict) => SidecarResponseV2::Error(SidecarErrorBody {
                                code: "nonce_conflict".to_owned(),
                                message: "nonce reused with different request".to_owned(),
                                retryable: false,
                            }),
                            Err(_) => SidecarResponseV2::Error(SidecarErrorBody {
                                code: "cache_unavailable".to_owned(),
                                message: "exact transaction not durably cached".to_owned(),
                                retryable: true,
                            }),
                        },
                        Err(SidecarOperationError::Retryable) => SidecarResponseV2::Error(SidecarErrorBody {
                            code: "monerod_unavailable".to_owned(),
                            message: "Monero backend unavailable".to_owned(),
                            retryable: true,
                        }),
                        Err(SidecarOperationError::Rejected(message)) => SidecarResponseV2::Error(SidecarErrorBody {
                            code: "sweep_rejected".to_owned(), message, retryable: false,
                        }),
                    },
                }
            }
        }
    };
    write_uds_response(&mut stream, response).await
}

#[cfg(unix)]
async fn write_uds_response(
    stream: &mut tokio::net::UnixStream,
    response: SidecarResponseV2,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(&response).context("serialize UDS response")?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        anyhow::bail!("UDS response exceeds bound");
    }
    let length = u32::try_from(bytes.len()).context("UDS response length")?;
    stream.write_all(&length.to_be_bytes()).await.context("write UDS length")?;
    stream.write_all(&bytes).await.context("write UDS response")?;
    stream.shutdown().await.context("shutdown UDS")?;
    Ok(())
}
