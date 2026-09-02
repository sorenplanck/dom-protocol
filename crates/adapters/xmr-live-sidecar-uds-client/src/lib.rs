//! Authenticated bounded blocking Unix-domain sidecar client.
//!
//! The socket path carries the route's spend and view scalars, so the peer
//! must prove itself before any request leaves this process. Three fences,
//! all fail-closed, guard the channel:
//!
//! 1. the socket path must be absolute and outside every world-writable
//!    standard directory, so an unprivileged squatter cannot pre-bind it;
//! 2. the connected peer must run under this process's own effective uid,
//!    checked through `SO_PEERCRED` before a single byte is written;
//! 3. the sidecar must answer a fresh challenge nonce with an HMAC proof of
//!    the shared key, in its own domain, before the request — and with it
//!    the scalars — is transmitted.

#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use rand::RngCore as _;
use xmr_live_sidecar_api::{
    BuildSweepRequestV2, BuildSweepResponseV2, SidecarHelloProofV1, SidecarHelloV1,
    SidecarRequestV2, SidecarResponseV2, VerifyFundingRequestV2, VerifyFundingResponseV2,
    API_VERSION_V2, MAX_FRAME_BYTES,
};
use xmr_sidecar_auth::SidecarAuthKey;
use xmr_spend_port::{FundingVerifyPort, SpendPortError, SweepBuildPort};

/// Standard world-writable roots a secret-carrying socket must never live in.
const WORLD_WRITABLE_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
/// The hello proof is one small JSON object; anything larger is an impostor.
const MAX_HELLO_PROOF_BYTES: usize = 1024;

/// Preferred Linux sidecar transport.
pub struct BlockingUdsSidecarPort {
    socket_path: PathBuf,
    timeout: Duration,
    auth_key: SidecarAuthKey,
}

impl core::fmt::Debug for BlockingUdsSidecarPort {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BlockingUdsSidecarPort")
            .field("socket_path", &self.socket_path)
            .field("timeout", &self.timeout)
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

impl BlockingUdsSidecarPort {
    /// Constructs a finite-timeout client over a permissioned socket path.
    ///
    /// The path must be absolute and outside `/tmp`, `/var/tmp` and
    /// `/dev/shm`: a socket in a world-writable directory can be pre-bound
    /// by any local process, and this client's first application frame
    /// carries key material.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        auth_key: SidecarAuthKey,
    ) -> Result<Self, SpendPortError> {
        let socket_path = socket_path.into();
        if socket_path.as_os_str().is_empty()
            || !socket_path.is_absolute()
            || path_in_world_writable_root(&socket_path)
        {
            return Err(SpendPortError::Rejected);
        }
        Ok(Self {
            socket_path,
            timeout: Duration::from_secs(180),
            auth_key,
        })
    }

    /// Socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[cfg(unix)]
    fn call(&self, request: &SidecarRequestV2) -> Result<SidecarResponseV2, SpendPortError> {
        use std::os::unix::net::UnixStream;
        let bytes = serde_json::to_vec(request).map_err(|_| SpendPortError::Rejected)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(SpendPortError::Rejected);
        }
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|_| SpendPortError::Retryable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| SpendPortError::Retryable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| SpendPortError::Retryable)?;
        require_same_uid_peer(&stream)?;
        self.handshake(&mut stream)?;
        write_frame(&mut stream, &bytes)?;
        let response = read_frame(&mut stream, MAX_FRAME_BYTES)?;
        serde_json::from_slice(&response).map_err(|_| SpendPortError::Rejected)
    }

    /// Refuses to transmit anything but a fresh nonce until the peer proves
    /// possession of the shared HMAC key over exactly that nonce.
    #[cfg(unix)]
    fn handshake(&self, stream: &mut std::os::unix::net::UnixStream) -> Result<(), SpendPortError> {
        let mut challenge_nonce = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut challenge_nonce)
            .map_err(|_| SpendPortError::Retryable)?;
        let hello = SidecarHelloV1 {
            api_version: API_VERSION_V2,
            challenge_nonce,
        };
        hello.validate().map_err(|_| SpendPortError::Retryable)?;
        let hello_bytes = serde_json::to_vec(&hello).map_err(|_| SpendPortError::Rejected)?;
        write_frame(stream, &hello_bytes)?;
        let proof_bytes = read_frame(stream, MAX_HELLO_PROOF_BYTES)?;
        let proof: SidecarHelloProofV1 =
            serde_json::from_slice(&proof_bytes).map_err(|_| SpendPortError::Rejected)?;
        proof.validate().map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .verify_challenge_proof(&challenge_nonce, &proof.proof)
            .map_err(|_| SpendPortError::Rejected)
    }

    #[cfg(not(unix))]
    fn call(&self, _request: &SidecarRequestV2) -> Result<SidecarResponseV2, SpendPortError> {
        Err(SpendPortError::Rejected)
    }

    fn classify_error(error: xmr_live_sidecar_api::SidecarErrorBody) -> SpendPortError {
        if error.retryable {
            SpendPortError::Retryable
        } else {
            SpendPortError::Rejected
        }
    }
}

fn path_in_world_writable_root(path: &Path) -> bool {
    WORLD_WRITABLE_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
}

/// Requires the connected peer to run as this process's own effective uid.
///
/// Kernel-attested through `SO_PEERCRED`, so a proxying impostor cannot
/// forward its way around it: the credential is of the process actually
/// holding the other end of this exact socket.
#[cfg(unix)]
fn require_same_uid_peer(stream: &std::os::unix::net::UnixStream) -> Result<(), SpendPortError> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(|_| SpendPortError::Rejected)?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() {
        return Err(SpendPortError::Rejected);
    }
    Ok(())
}

#[cfg(unix)]
fn write_frame(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
) -> Result<(), SpendPortError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(SpendPortError::Rejected);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| SpendPortError::Rejected)?;
    stream
        .write_all(&length.to_be_bytes())
        .map_err(|_| SpendPortError::Retryable)?;
    stream
        .write_all(bytes)
        .map_err(|_| SpendPortError::Retryable)?;
    stream.flush().map_err(|_| SpendPortError::Retryable)?;
    Ok(())
}

#[cfg(unix)]
fn read_frame(
    stream: &mut std::os::unix::net::UnixStream,
    max_bytes: usize,
) -> Result<Vec<u8>, SpendPortError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| SpendPortError::Retryable)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > max_bytes {
        return Err(SpendPortError::Rejected);
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .map_err(|_| SpendPortError::Retryable)?;
    Ok(frame)
}

impl FundingVerifyPort for BlockingUdsSidecarPort {
    fn verify_funding(
        &mut self,
        mut request: VerifyFundingRequestV2,
    ) -> Result<VerifyFundingResponseV2, SpendPortError> {
        request
            .validate_public_fields()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_funding(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        match self.call(&SidecarRequestV2::VerifyFunding(request))? {
            SidecarResponseV2::Funding(response) => Ok(response),
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            SidecarResponseV2::Sweep(_) => Err(SpendPortError::Rejected),
        }
    }
}

impl SweepBuildPort for BlockingUdsSidecarPort {
    fn build_sweep(
        &mut self,
        mut request: BuildSweepRequestV2,
    ) -> Result<BuildSweepResponseV2, SpendPortError> {
        request
            .validate_public_fields()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_build(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let nonce = request.request_nonce;
        match self.call(&SidecarRequestV2::BuildSweep(request))? {
            SidecarResponseV2::Sweep(response) => {
                response
                    .validate_for(&nonce)
                    .map_err(|_| SpendPortError::Rejected)?;
                Ok(response)
            }
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            SidecarResponseV2::Funding(_) => Err(SpendPortError::Rejected),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};

    use xmr_live_sidecar_api::SecretScalarBytes;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The client refuses sockets under `/tmp`, where `tempdir()` would put
    /// them, and `connect(2)` bounds the whole path by `SUN_LEN` (~108
    /// bytes), so the scratch directory is the first short-enough private
    /// base: the runtime dir, the crate dir, or the home directory.
    fn socket_scratch_dir() -> tempfile::TempDir {
        let candidates = [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
            std::env::var_os("HOME").map(PathBuf::from),
        ];
        let base = candidates
            .into_iter()
            .flatten()
            .find(|base| {
                base.is_absolute()
                    && !path_in_world_writable_root(base)
                    && base.exists()
                    && base.as_os_str().len() < 70
            })
            .expect("no short private base directory for a test Unix socket");
        tempfile::tempdir_in(base).expect("scratch dir")
    }

    const KEY: [u8; 32] = [7; 32];
    const WRONG_KEY: [u8; 32] = [9; 32];

    fn funding_request() -> VerifyFundingRequestV2 {
        VerifyFundingRequestV2 {
            api_version: API_VERSION_V2,
            request_nonce: [1; 32],
            settlement_id: [2; 32],
            funding_tx_hash: [3; 32],
            expected_amount_piconero: 1_000,
            expected_spend_public_key: [4; 32],
            view_scalar: SecretScalarBytes::new([5; 32]),
            auth_tag: [0; 32],
        }
    }

    fn read_test_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut frame)?;
        Ok(frame)
    }

    fn write_test_frame(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
        let length = u32::try_from(bytes.len()).expect("frame length");
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(bytes)?;
        stream.flush()
    }

    /// Serves one connection: answers the hello with a proof under
    /// `proof_key`, then reports whether any request bytes followed.
    fn one_shot_sidecar(
        listener: UnixListener,
        proof_key: [u8; 32],
    ) -> std::thread::JoinHandle<(bool, Option<SidecarRequestV2>)> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let hello_bytes = read_test_frame(&mut stream).expect("read hello");
            let hello: SidecarHelloV1 = serde_json::from_slice(&hello_bytes).expect("decode hello");
            hello.validate().expect("valid hello");
            let proof_source = SidecarAuthKey::new(proof_key).expect("key");
            let proof = SidecarHelloProofV1 {
                api_version: API_VERSION_V2,
                proof: proof_source
                    .challenge_proof(&hello.challenge_nonce)
                    .expect("proof"),
            };
            write_test_frame(
                &mut stream,
                &serde_json::to_vec(&proof).expect("encode proof"),
            )
            .expect("write proof");
            match read_test_frame(&mut stream) {
                Ok(frame) => {
                    let request =
                        serde_json::from_slice::<SidecarRequestV2>(&frame).expect("request");
                    let response = SidecarResponseV2::Funding(VerifyFundingResponseV2 {
                        api_version: API_VERSION_V2,
                        request_nonce: [1; 32],
                        funding_tx_hash: [3; 32],
                        event_index: 0,
                        received_amount_piconero: 1_000,
                        spendable: true,
                    });
                    let _ = write_test_frame(
                        &mut stream,
                        &serde_json::to_vec(&response).expect("encode response"),
                    );
                    (true, Some(request))
                }
                Err(_) => (false, None),
            }
        })
    }

    #[test]
    fn honest_sidecar_completes_handshake_then_serves_the_request() -> TestResult {
        let directory = socket_scratch_dir();
        let socket_path = directory.path().join("sidecar.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let served = one_shot_sidecar(listener, KEY);
        let mut port =
            BlockingUdsSidecarPort::new(&socket_path, SidecarAuthKey::new(KEY).unwrap())?;
        let response = port.verify_funding(funding_request());
        assert!(response.is_ok(), "honest sidecar must serve: {response:?}");
        let (request_seen, request) = served.join().expect("sidecar thread");
        assert!(request_seen);
        assert!(matches!(request, Some(SidecarRequestV2::VerifyFunding(_))));
        Ok(())
    }

    #[test]
    fn impostor_with_wrong_key_never_receives_the_request() -> TestResult {
        let directory = socket_scratch_dir();
        let socket_path = directory.path().join("impostor.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let served = one_shot_sidecar(listener, WRONG_KEY);
        let mut port =
            BlockingUdsSidecarPort::new(&socket_path, SidecarAuthKey::new(KEY).unwrap())?;
        let response = port.verify_funding(funding_request());
        assert!(matches!(response, Err(SpendPortError::Rejected)));
        // The class being closed: the impostor answered the hello but must
        // observe the connection die with no request — and no scalar — ever
        // transmitted.
        let (request_seen, request) = served.join().expect("sidecar thread");
        assert!(!request_seen, "no request frame may reach an unproven peer");
        assert!(request.is_none());
        Ok(())
    }

    #[test]
    fn world_writable_and_relative_socket_paths_are_refused() {
        let auth = || SidecarAuthKey::new(KEY).unwrap();
        for path in [
            "/tmp/dom-xmr-sidecar.sock",
            "/tmp/nested/dom-xmr-sidecar.sock",
            "/var/tmp/dom-xmr-sidecar.sock",
            "/dev/shm/dom-xmr-sidecar.sock",
            "relative/sidecar.sock",
        ] {
            assert!(
                BlockingUdsSidecarPort::new(path, auth()).is_err(),
                "path must be refused: {path}"
            );
        }
        assert!(BlockingUdsSidecarPort::new("/run/dom/sidecar.sock", auth()).is_ok());
    }
}
