use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn request(addr: &str, token: &str, method: &str, path: &str) -> String {
    let mut last_error = None;
    for _ in 0..30 {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                write!(
                    stream,
                    "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                return response;
            }
            Err(error) => last_error = Some(error),
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("probe RPC did not start: {last_error:?}");
}

#[test]
fn probe_mode_isolated_from_production_data_p2p_and_mining() {
    let temp = tempfile::tempdir().unwrap();
    let production_data = temp.path().join("production-data");
    let p2p_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let p2p_addr = p2p_listener.local_addr().unwrap();
    drop(p2p_listener);

    let mut child = Command::new(env!("CARGO_BIN_EXE_dom-node"))
        .arg("--probe")
        .env("DOM_DATA_DIR", &production_data)
        .env("DOM_P2P_LISTEN_ADDR", p2p_addr.to_string())
        .env("DOM_MINE", "true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let probe: serde_json::Value = serde_json::from_str(&line).unwrap();
    let rpc_addr = probe["rpc_addr"].as_str().unwrap();
    let token = probe["token"].as_str().unwrap();

    let build_info = request(rpc_addr, token, "GET", "/build-info");
    assert!(build_info.starts_with("HTTP/1.1 200"), "{build_info}");
    let shutdown = request(rpc_addr, token, "POST", "/shutdown");
    assert!(shutdown.starts_with("HTTP/1.1 202"), "{shutdown}");
    assert!(child.wait().unwrap().success());

    assert!(
        !production_data.exists(),
        "probe mode must not create or open the production data directory"
    );
    TcpListener::bind(p2p_addr).expect("probe mode must not bind the configured P2P address");
}
