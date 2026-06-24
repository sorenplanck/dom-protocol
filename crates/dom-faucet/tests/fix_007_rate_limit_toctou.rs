//! dom-shield — FIX-007 reproducer: faucet rate-limit TOCTOU / drain.
//!
//! Production flow (`src/lib.rs::request_coins`, lines ~102-151):
//!   1. lock `last_requests`, read the per-commitment timestamp, decide.
//!   2. `drop(last_requests)`  <-- LOCK RELEASED HERE
//!   3. blocking `send_payment(...)`  (the expensive dispense)
//!   4. re-lock and `insert(commitment, now())` ONLY on success.
//!
//! Four distinct attack vectors are exercised below; all four are properties of
//! the same gate. Each test ASSERTS the vulnerable behaviour (so it stays RED-as-
//! confirmation: a passing test here = the vulnerability is present and the fix
//! is still pending). NOTHING is fixed.
//!
//!   (a) gate is not atomic with the record  -> concurrent multi-dispense.
//!   (b) per-commitment key bypass            -> fresh blinding = fresh key = unlimited.
//!   (c) record-only-on-success (fail-open)   -> a failed send leaves no record.
//!   (d) unbounded `last_requests` growth     -> no eviction/cap (memory DoS).
//!
//! The server is driven over a real loopback TCP socket via the public
//! `FaucetServer`/`FaucetBackend` API. The mock backend can be made slow (to
//! widen the TOCTOU window) and/or failing (to show fail-open).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use dom_core::Address;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_faucet::{FaucetBackend, FaucetServer};

const FAUCET_AMOUNT: u64 = 10_000;
const FEE: u64 = 10;

/// Mock backend: counts every dispense; optionally sleeps to widen the window;
/// optionally fails every call to demonstrate fail-open.
struct CountingBackend {
    dispenses: AtomicU64,
    delay: Duration,
    fail: bool,
}

impl CountingBackend {
    fn new(delay: Duration, fail: bool) -> Self {
        Self {
            dispenses: AtomicU64::new(0),
            delay,
            fail,
        }
    }
}

impl FaucetBackend for CountingBackend {
    fn send_payment(
        &self,
        _commitment_hex: &str,
        _blinding_hex: &str,
        _amount: u64,
        _fee: u64,
    ) -> Result<[u8; 32], String> {
        // Count the moment money actually leaves the faucet.
        self.dispenses.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        if self.fail {
            return Err("simulated downstream node error".to_string());
        }
        Ok([0xABu8; 32])
    }
}

/// Build a well-formed request for a given blinding (=> a given commitment/key).
fn request_for(blinding: &BlindingFactor) -> String {
    let commitment = Commitment::commit(FAUCET_AMOUNT, blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode();
    format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = address,
        c = hex::encode(commitment.as_bytes()),
        b = hex::encode(blinding.as_bytes()),
    )
}

/// Start the real faucet server on an ephemeral loopback port; return its addr.
async fn spawn_server(backend: Arc<CountingBackend>) -> (String, Arc<CountingBackend>) {
    // Bind 127.0.0.1:0 to grab a free port, then hand the addr to the server.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let addr = format!("127.0.0.1:{port}");
    let server = FaucetServer::new(addr.clone(), backend.clone(), FAUCET_AMOUNT, FEE);
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    // Give the listener a moment to come up.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (addr, backend)
}

/// Minimal blocking HTTP POST of a JSON body to /api/request. Returns status code.
fn http_post_request(addr: &str, payment_request: &str) -> u16 {
    let body = serde_json::json!({ "payment_request": payment_request }).to_string();
    let req = format!(
        "POST /api/request HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(req.as_bytes()).expect("write");
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    // Parse "HTTP/1.1 NNN ..."
    resp.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

// ----------------------------------------------------------------------------
// (a) Gate not atomic with record  ->  concurrent multi-dispense (DRAIN).
// ----------------------------------------------------------------------------
#[test]
fn fix_007a_concurrent_same_commitment_multidispenses() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Slow backend => the lock is dropped, all concurrent requests pass the gate
    // BEFORE any of them records a timestamp.
    let backend = Arc::new(CountingBackend::new(Duration::from_millis(400), false));
    let (addr, backend) = rt.block_on(spawn_server(backend));

    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("blinding");
    let request = request_for(&blinding);

    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();
    for _ in 0..N {
        let addr = addr.clone();
        let request = request.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait(); // fire all at once
            http_post_request(&addr, &request)
        }));
    }
    let statuses: Vec<u16> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let ok = statuses.iter().filter(|&&s| s == 200).count();
    let dispenses = backend.dispenses.load(Ordering::SeqCst);

    // A correctly-locked faucet would dispense EXACTLY ONCE for N identical
    // concurrent requests on the same commitment. FIX-007: it dispenses many.
    assert!(
        dispenses > 1,
        "FIX-007(a) NOT reproduced: {dispenses} dispense(s) for {N} concurrent identical requests (expected >1 due to TOCTOU drain). HTTP 200s={ok}"
    );
    eprintln!(
        "FIX-007(a) CONFIRMED: {dispenses} dispenses / {N} concurrent identical requests (HTTP 200s={ok}); a sound faucet dispenses exactly 1."
    );
}

// ----------------------------------------------------------------------------
// (b) Per-commitment key bypass: fresh blinding => fresh commitment => fresh
//     rate-limit key => unlimited serial claims. (Analysis + executable KAV.)
// ----------------------------------------------------------------------------
#[test]
fn fix_007b_fresh_commitment_bypasses_rate_limit_serially() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let backend = Arc::new(CountingBackend::new(Duration::ZERO, false));
    let (addr, backend) = rt.block_on(spawn_server(backend));

    // Same attacker, same wallet — they simply pick a NEW blinding each time.
    // The rate-limit key is hex(commitment) and commitment = commit(amount, b),
    // so every fresh b yields a brand-new key the map has never seen.
    const ROUNDS: usize = 5;
    for i in 0..ROUNDS {
        // Distinct, valid, non-zero blinding per round.
        let mut bytes = [1u8; 32];
        bytes[0] = (i as u8) + 1;
        let blinding = BlindingFactor::from_bytes(bytes).expect("blinding");
        let status = http_post_request(&addr, &request_for(&blinding));
        assert_eq!(
            status, 200,
            "round {i}: a fresh-commitment claim should pass the gate (got HTTP {status})"
        );
    }
    let dispenses = backend.dispenses.load(Ordering::SeqCst);
    assert_eq!(
        dispenses as usize, ROUNDS,
        "FIX-007(b) NOT reproduced: expected {ROUNDS} unlimited claims via fresh commitments, got {dispenses}"
    );
    eprintln!(
        "FIX-007(b) CONFIRMED: {dispenses} consecutive dispenses to the SAME actor via fresh blindings (rate-limit key = commitment, trivially rotated)."
    );
}

// ----------------------------------------------------------------------------
// (c) Record-only-on-success (fail-open): a failing send leaves NO timestamp,
//     so the attacker is never rate-limited even after consuming faucet effort.
// ----------------------------------------------------------------------------
#[test]
fn fix_007c_failed_send_leaves_no_rate_limit_record() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // fail=true => send_payment always errors; insert() is never reached.
    let backend = Arc::new(CountingBackend::new(Duration::ZERO, true));
    let (addr, backend) = rt.block_on(spawn_server(backend));

    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("blinding");
    let request = request_for(&blinding);

    // Hit the SAME commitment serially many times. Because each send fails,
    // no record is written, so each subsequent call still passes the gate and
    // re-attempts the (costly) dispense path — fail-open amplification.
    const ATTEMPTS: usize = 4;
    let mut server_errors = 0;
    for _ in 0..ATTEMPTS {
        let status = http_post_request(&addr, &request);
        if status == 500 {
            server_errors += 1;
        }
    }
    let attempts_reaching_backend = backend.dispenses.load(Ordering::SeqCst);

    // Sound behaviour would record the attempt (or fail closed), capping the
    // backend hits to 1 within the window. FIX-007 lets every attempt through.
    assert!(
        attempts_reaching_backend > 1,
        "FIX-007(c) NOT reproduced: backend reached {attempts_reaching_backend} time(s) over {ATTEMPTS} same-key attempts (expected >1 fail-open)"
    );
    eprintln!(
        "FIX-007(c) CONFIRMED: {attempts_reaching_backend}/{ATTEMPTS} same-key attempts reached the backend ({server_errors} HTTP 500s); failed sends write no rate-limit record (fail-open)."
    );
}

// ----------------------------------------------------------------------------
// (d) Unbounded last_requests growth: the map is never evicted/capped. Each new
//     commitment is a permanent entry. Combined with (b) this is a slow OOM.
//     (Analysis-backed executable demonstration via successful unique claims.)
// ----------------------------------------------------------------------------
#[test]
fn fix_007d_last_requests_grows_unbounded() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let backend = Arc::new(CountingBackend::new(Duration::ZERO, false));
    let (addr, backend) = rt.block_on(spawn_server(backend));

    // Every distinct commitment becomes a permanent HashMap entry: there is no
    // RATE_LIMIT_SECS-based expiry sweep, no LRU, no max-size. We demonstrate
    // that K distinct keys all succeed (=> K permanent entries accrue) and that
    // nothing bounds the map. K is small here to keep the test fast; the unbound
    // is structural (no eviction code path exists in lib.rs).
    const K: usize = 32;
    let mut ok = 0;
    for i in 0..K {
        let mut bytes = [1u8; 32];
        // vary first two bytes for 32 distinct, valid, non-zero blindings
        bytes[0] = (i as u8).wrapping_add(1);
        bytes[1] = 0xA5 ^ (i as u8);
        let blinding = BlindingFactor::from_bytes(bytes).expect("blinding");
        if http_post_request(&addr, &request_for(&blinding)) == 200 {
            ok += 1;
        }
    }
    let dispenses = backend.dispenses.load(Ordering::SeqCst);
    assert_eq!(
        dispenses as usize, K,
        "FIX-007(d): expected {K} distinct successful claims (=> {K} permanent map entries), got {dispenses} (ok responses {ok})"
    );
    eprintln!(
        "FIX-007(d) CONFIRMED (structural): {dispenses} distinct commitments => {dispenses} permanent last_requests entries; lib.rs has no eviction/expiry/cap path (HashMap grows with attacker-chosen distinct commitments)."
    );
}
