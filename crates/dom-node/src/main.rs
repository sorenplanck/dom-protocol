//! DOM node entry point.

use dom_config::{parse_dom_network, Network, NodeConfig};
use dom_node::node::DomNode;
use dom_node::secret_file::load_owner_only_utf8_secret_file;
use std::{ffi::OsStr, net::SocketAddr, path::Path, sync::Arc};
use tracing::info;

/// Maximum bearer-token payload before an optional trailing newline.
const MAX_RPC_BEARER_TOKEN_BYTES: u64 = 512;

fn load_rpc_bearer_token_file(path: &Path) -> anyhow::Result<String> {
    let token =
        load_owner_only_utf8_secret_file(path, "RPC bearer-token", 32, MAX_RPC_BEARER_TOKEN_BYTES)?;
    if !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        anyhow::bail!("RPC bearer token must contain only visible ASCII without whitespace");
    }
    Ok(token)
}

const MAX_WALLET_PASSWORD_BYTES: u64 = 1024;

fn load_wallet_password_file(path: &Path) -> anyhow::Result<String> {
    let password =
        load_owner_only_utf8_secret_file(path, "wallet password", 1, MAX_WALLET_PASSWORD_BYTES)?;
    if password
        .chars()
        .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        anyhow::bail!("wallet password file contains a forbidden control character");
    }
    Ok(password)
}

fn configure_standalone_rpc(
    config: &mut NodeConfig,
    requested: &str,
    token_file: Option<&OsStr>,
) -> anyhow::Result<()> {
    let addr = if requested == "default" {
        config.network.default_rpc_listen_addr()
    } else {
        requested.to_owned()
    };
    let socket: SocketAddr = addr
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid DOM_RPC_LISTEN_ADDR {addr:?}: {error}"))?;
    if !socket.ip().is_loopback() {
        anyhow::bail!("standalone RPC must bind to a loopback address");
    }
    let token_file = token_file
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "DOM_RPC_BEARER_TOKEN_FILE is required when DOM_RPC_LISTEN_ADDR enables RPC"
            )
        })?;
    let token = load_rpc_bearer_token_file(Path::new(token_file))?;
    config.rpc_listen_addr = Some(addr);
    config.rpc_bearer_token = Some(token);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupAction {
    Run,
    Version,
    Help,
}

fn parse_startup_action<I>(args: I) -> anyhow::Result<StartupAction>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(argument) = args.next() else {
        return Ok(StartupAction::Run);
    };
    if args.next().is_some() {
        anyhow::bail!("only --help or --version are accepted as command-line arguments");
    }
    match argument.as_str() {
        "--version" | "-V" => Ok(StartupAction::Version),
        "--help" | "-h" => Ok(StartupAction::Help),
        _ => anyhow::bail!("unknown argument {argument:?}; use --help"),
    }
}

fn print_help() {
    println!(
        "DOM node {}\n\nUsage:\n  DOM_NETWORK=<mainnet|testnet|regtest> dom-node\n\nThe network must be selected explicitly before the node initializes storage, listeners, mining, or peer discovery. Standalone RPC additionally requires a loopback DOM_RPC_LISTEN_ADDR and an owner-only DOM_RPC_BEARER_TOKEN_FILE. An existing WalletDir should be opened with DOM_WALLET_PATH plus owner-only DOM_WALLET_PASSWORD_FILE.\n\nOptions:\n  -h, --help       Print help\n  -V, --version    Print version",
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_startup_action(std::env::args())? {
        StartupAction::Run => {}
        StartupAction::Version => {
            println!("dom-node {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        StartupAction::Help => {
            print_help();
            return Ok(());
        }
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("DOM_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    info!("DOM Node v{}", env!("CARGO_PKG_VERSION"));
    info!("Author: Soren Planck");
    info!("License: MIT");

    // Select the network before any storage, listener, RPC, metrics, mining, or
    // peer task is initialized. The value must exactly match a canonical
    // lowercase network name; a missing value fails closed.
    let network_value = std::env::var("DOM_NETWORK").ok();
    let network = parse_dom_network(network_value.as_deref())?;
    let mut config = match network {
        Network::Regtest => {
            info!("Network: REGTEST (local dev, trivial PoW)");
            NodeConfig::regtest()
        }
        Network::Mainnet => {
            info!("Network: MAINNET");
            NodeConfig::mainnet()
        }
        Network::Testnet => {
            info!("Network: TESTNET");
            NodeConfig::testnet()
        }
    };

    // Allow override of seed peers via DOM_SEED_PEERS env var (CSV of host:port).
    // Useful for private Testnet deployments where DNS seeds do not exist.
    if let Ok(seeds_csv) = std::env::var("DOM_SEED_PEERS") {
        let seeds: Vec<String> = seeds_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !seeds.is_empty() {
            info!("Using seed peers from DOM_SEED_PEERS: {seeds:?}");
            config.seed_peers = seeds;
        }
    }

    // Allow override of P2P listen address via DOM_P2P_LISTEN_ADDR.
    // Useful when running multiple nodes on the same host.
    if let Ok(addr) = std::env::var("DOM_P2P_LISTEN_ADDR") {
        info!("Overriding P2P listen address: {addr}");
        config.p2p_listen_addr = addr;
    }

    // Allow internal Prometheus metrics endpoint via DOM_METRICS_LISTEN_ADDR.
    // Metrics remain disabled unless explicitly enabled. The value `default`
    // selects the authoritative loopback-only service port.
    if let Ok(requested) = std::env::var("DOM_METRICS_LISTEN_ADDR") {
        let addr = if requested == "default" {
            format!("127.0.0.1:{}", dom_core::METRICS_PORT)
        } else {
            requested
        };
        info!("Enabling metrics listen address: {addr}");
        config.metrics_listen_addr = Some(addr);
    }

    // Standalone RPC is deliberately file-secret-only and loopback-only. The
    // token never appears in argv, environment contents, Debug output, or logs.
    // A missing/insecure token file fails before storage or listeners start.
    if let Some(requested) = std::env::var_os("DOM_RPC_LISTEN_ADDR") {
        let requested = requested
            .into_string()
            .map_err(|_| anyhow::anyhow!("DOM_RPC_LISTEN_ADDR is not valid UTF-8"))?;
        configure_standalone_rpc(
            &mut config,
            &requested,
            std::env::var_os("DOM_RPC_BEARER_TOKEN_FILE").as_deref(),
        )?;
        info!(
            "Enabling authenticated RPC listen address: {}",
            config.rpc_listen_addr.as_deref().unwrap_or("<disabled>")
        );
    }

    // Allow disabling mining via DOM_MINE=false (validator/relay-only node).
    // Accepts "false"/"0"/"no" (case-insensitive) to disable; anything else leaves the default.
    if let Ok(v) = std::env::var("DOM_MINE") {
        let on = !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        );
        info!("Mining set via DOM_MINE={v} -> mine={on}");
        config.mine = on;
    }

    // Allow override of miner worker count via DOM_MINER_THREADS (resource
    // control only, never consensus data). Clamped to 1..=256; invalid values
    // keep the default.
    if let Ok(v) = std::env::var("DOM_MINER_THREADS") {
        match v.trim().parse::<usize>() {
            Ok(n) if n >= 1 => {
                let n = n.min(256);
                info!("Miner threads set via DOM_MINER_THREADS={v} -> {n}");
                config.miner_threads = n;
            }
            _ => {
                info!(
                    "Invalid DOM_MINER_THREADS={v}, keeping {}",
                    config.miner_threads
                );
            }
        }
    }

    // Allow override of data dir via DOM_DATA_DIR.
    if let Ok(dir) = std::env::var("DOM_DATA_DIR") {
        info!("Overriding data dir: {dir}");
        config.data_dir = dir;
    }

    // Allow override of wallet path via DOM_WALLET_PATH.
    if let Ok(path) = std::env::var("DOM_WALLET_PATH") {
        info!("Overriding wallet path: {path}");
        config.wallet_path = Some(path);
    }

    // Standalone deployments should load the wallet password from the same
    // owner-only, bounded file boundary as the RPC token. The legacy direct
    // environment value remains source-compatible but is mutually exclusive
    // so a stale environment cannot silently override the file authority.
    let wallet_password_file = std::env::var_os("DOM_WALLET_PASSWORD_FILE");
    let legacy_wallet_password = std::env::var("DOM_WALLET_PASSWORD").ok();
    if wallet_password_file.is_some() && legacy_wallet_password.is_some() {
        anyhow::bail!(
            "DOM_WALLET_PASSWORD_FILE and legacy DOM_WALLET_PASSWORD are mutually exclusive"
        );
    }
    if let Some(path) = wallet_password_file {
        config.wallet_password = Some(load_wallet_password_file(Path::new(&path))?);
        info!("Loaded wallet password from owner-only file: [REDACTED]");
    } else if let Some(password) = legacy_wallet_password {
        info!("Overriding wallet password from legacy environment: [REDACTED]");
        config.wallet_password = Some(password);
    }

    // Initialize node
    let node = Arc::new(DomNode::init(config)?);

    // Verify H generator on startup — FAIL FAST if placeholder
    // A placeholder H may have known discrete log → Pedersen commitment backdoor.
    // Nodes with placeholder H MUST NOT process any transactions.
    let _h_bytes = dom_crypto::h_compressed()
        .map_err(|e| anyhow::anyhow!(
            "H generator not finalized — node refuses to start.\n             Run: cargo test -p dom-crypto print_h_generator -- --nocapture\n             Then update H_COMPRESSED_FINAL in crates/dom-crypto/src/h_generator.rs\n             Error: {e}"
        ))?;
    info!("H generator verified OK: {}", hex::encode(_h_bytes));

    // Run node
    node.run().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        configure_standalone_rpc, load_rpc_bearer_token_file, load_wallet_password_file,
        parse_startup_action, StartupAction,
    };
    use dom_config::NodeConfig;

    #[test]
    fn inspection_arguments_exit_before_node_startup() {
        assert_eq!(
            parse_startup_action(["dom-node".into(), "--version".into()]).unwrap(),
            StartupAction::Version
        );
        assert_eq!(
            parse_startup_action(["dom-node".into(), "--help".into()]).unwrap(),
            StartupAction::Help
        );
    }

    #[test]
    fn unknown_startup_argument_fails_closed() {
        assert!(parse_startup_action(["dom-node".into(), "--unknown".into()]).is_err());
    }

    #[cfg(unix)]
    fn secure_token_file(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temporary token directory");
        let path = dir.path().join("rpc.token");
        std::fs::write(&path, contents).expect("write token fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure token fixture mode");
        (dir, path)
    }

    #[cfg(unix)]
    #[test]
    fn standalone_rpc_loads_bounded_owner_only_file_and_trims_one_newline() {
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (_dir, path) = secure_token_file(format!("{expected}\n").as_bytes());
        assert_eq!(load_rpc_bearer_token_file(&path).unwrap(), expected);

        let mut config = NodeConfig::regtest();
        configure_standalone_rpc(&mut config, "127.0.0.1:0", Some(path.as_os_str())).unwrap();
        assert_eq!(config.rpc_listen_addr.as_deref(), Some("127.0.0.1:0"));
        assert_eq!(config.rpc_bearer_token.as_deref(), Some(expected));
        assert!(!format!("{config:?}").contains(expected));
    }

    #[cfg(unix)]
    #[test]
    fn standalone_rpc_fails_closed_without_token_or_loopback() {
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (_dir, path) = secure_token_file(expected.as_bytes());
        let mut config = NodeConfig::regtest();
        assert!(configure_standalone_rpc(&mut config, "127.0.0.1:0", None).is_err());
        assert!(
            configure_standalone_rpc(&mut config, "0.0.0.0:3370", Some(path.as_os_str())).is_err()
        );
        assert!(config.rpc_listen_addr.is_none());
        assert!(config.rpc_bearer_token.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn standalone_rpc_rejects_insecure_symlink_or_oversized_token_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_dir, path) = secure_token_file(&[b'a'; 64]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make token fixture insecure");
        assert!(load_rpc_bearer_token_file(&path).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore token fixture mode");
        let link = path.with_extension("link");
        symlink(&path, &link).expect("create symlink fixture");
        assert!(load_rpc_bearer_token_file(&link).is_err());

        std::fs::write(&path, vec![b'a'; 515]).expect("write oversized token fixture");
        assert!(load_rpc_bearer_token_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn standalone_wallet_password_loads_only_owner_only_bounded_utf8_file() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = secure_token_file(b"wallet-only-secret\n");
        assert_eq!(
            load_wallet_password_file(&path).unwrap(),
            "wallet-only-secret"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make wallet password fixture insecure");
        assert!(load_wallet_password_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore wallet password fixture mode");
        std::fs::write(&path, b"embedded\nnewline\n").expect("write invalid password fixture");
        assert!(load_wallet_password_file(&path).is_err());
    }

    #[cfg(unix)]
    struct AuthProbeNode;

    #[cfg(unix)]
    impl dom_rpc::NodeHandle for AuthProbeNode {
        fn chain_height(&self) -> u64 {
            0
        }

        fn mempool_size(&self) -> usize {
            0
        }

        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }

        fn get_mempool_tx(&self, _hash: &[u8; 32]) -> Option<dom_rpc::MempoolTxInfo> {
            None
        }

        fn submit_tx(&self, _tx_bytes: Vec<u8>) -> Result<dom_rpc::TxAdmission, dom_rpc::RpcError> {
            Err(dom_rpc::RpcError::Rejected("unused auth probe".to_string()))
        }

        fn network(&self) -> &'static str {
            "regtest"
        }

        fn get_block_header(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }

        fn get_block_hash_at_height(&self, _height: u64) -> Option<[u8; 32]> {
            None
        }

        fn get_utxo(&self, _commitment: &[u8; 33]) -> Option<dom_rpc::UtxoInfo> {
            None
        }
    }

    #[cfg(unix)]
    async fn auth_probe_status(addr: std::net::SocketAddr, token: Option<&str>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect auth probe");
        let authorization = token
            .map(|value| format!("Authorization: Bearer {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET /build-info HTTP/1.1\r\nHost: {addr}\r\n{authorization}Connection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write auth probe");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read auth probe");
        let status_line = String::from_utf8(response)
            .expect("HTTP response UTF-8")
            .lines()
            .next()
            .expect("HTTP status line")
            .to_owned();
        status_line
            .split_whitespace()
            .nth(1)
            .expect("HTTP status code")
            .parse()
            .expect("numeric HTTP status")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn standalone_rpc_file_token_enforces_401_and_authorizes_200() {
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (_dir, path) = secure_token_file(format!("{expected}\n").as_bytes());
        let mut config = NodeConfig::regtest();
        configure_standalone_rpc(&mut config, "127.0.0.1:0", Some(path.as_os_str())).unwrap();

        let listener = dom_rpc::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind auth probe");
        let addr = listener.local_addr().expect("auth probe address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(dom_rpc::serve_with_token_until_shutdown(
            std::sync::Arc::new(AuthProbeNode),
            listener,
            config.rpc_bearer_token.take(),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        assert_eq!(auth_probe_status(addr, None).await, 401);
        assert_eq!(auth_probe_status(addr, Some(expected)).await, 200);

        shutdown_tx.send(()).expect("request auth probe shutdown");
        server.await.expect("join auth probe server").unwrap();
    }
}
