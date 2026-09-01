//! Small bounded HTTP/1.1 loopback server codec.

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

use crate::wire::{SidecarErrorBody, MAX_HTTP_BODY_BYTES};

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("transport error")]
    Transport,
    #[error("malformed HTTP request")]
    Malformed,
    #[error("request exceeds bound")]
    TooLarge,
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub async fn read_request(stream: &mut TcpStream) -> Result<Request, HttpError> {
    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if buffer.len() > MAX_HEADER_BYTES { return Err(HttpError::TooLarge); }
        if let Some(index) = find_header_end(&buffer) { break index; }
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await.map_err(|_| HttpError::Transport)?;
        if count == 0 { return Err(HttpError::Malformed); }
        buffer.extend_from_slice(&chunk[..count]);
    };
    let header_bytes = &buffer[..header_end];
    let header = std::str::from_utf8(header_bytes).map_err(|_| HttpError::Malformed)?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next().ok_or(HttpError::Malformed)?;
    let mut fields = request_line.split_whitespace();
    let method = fields.next().ok_or(HttpError::Malformed)?.to_owned();
    let path = fields.next().ok_or(HttpError::Malformed)?.to_owned();
    if fields.next() != Some("HTTP/1.1") || fields.next().is_some() { return Err(HttpError::Malformed); }

    let mut content_length = None;
    for line in lines {
        if line.is_empty() { continue; }
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        if name.eq_ignore_ascii_case("transfer-encoding") { return Err(HttpError::Malformed); }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() { return Err(HttpError::Malformed); }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| HttpError::Malformed)?);
        }
    }
    let content_length = content_length.ok_or(HttpError::Malformed)?;
    if content_length > MAX_HTTP_BODY_BYTES { return Err(HttpError::TooLarge); }
    let body_start = header_end + 4;
    if buffer.len() > body_start + content_length { return Err(HttpError::Malformed); }
    while buffer.len() < body_start + content_length {
        let remaining = body_start + content_length - buffer.len();
        let mut chunk = vec![0_u8; remaining.min(4096)];
        let count = stream.read(&mut chunk).await.map_err(|_| HttpError::Transport)?;
        if count == 0 { return Err(HttpError::Malformed); }
        buffer.extend_from_slice(&chunk[..count]);
    }
    Ok(Request { method, path, body: buffer[body_start..].to_vec() })
}

pub async fn write_json<T: serde::Serialize>(
    stream: &mut TcpStream,
    status: u16,
    value: &T,
) -> Result<(), HttpError> {
    let body = serde_json::to_vec(value).map_err(|_| HttpError::Malformed)?;
    let reason = match status {
        200 => "OK", 400 => "Bad Request", 401 => "Unauthorized",
        404 => "Not Found", 409 => "Conflict", 413 => "Payload Too Large",
        422 => "Unprocessable Entity", 500 => "Internal Server Error",
        503 => "Service Unavailable", _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len(),
    );
    stream.write_all(headers.as_bytes()).await.map_err(|_| HttpError::Transport)?;
    stream.write_all(&body).await.map_err(|_| HttpError::Transport)?;
    stream.shutdown().await.map_err(|_| HttpError::Transport)
}

pub async fn write_error(
    stream: &mut TcpStream,
    status: u16,
    code: &str,
    message: &str,
    retryable: bool,
) -> Result<(), HttpError> {
    write_json(stream, status, &SidecarErrorBody {
        code: code.to_owned(), message: message.to_owned(), retryable,
    }).await
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}
