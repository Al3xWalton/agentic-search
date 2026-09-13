// SPDX-License-Identifier: AGPL-3.0-only
//! A bounded literal-loopback HTTP/1 fixture that records each accepted connection and body.
//! It serves only synthetic responses and closes every request; no URL is fetched.
//! Timeouts terminate the fixture rather than leaving detached test servers alive.

use std::time::Duration;
use stract::eval::endpoint::Endpoint;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

/// Recorded one-connection request, including exact method/path and decoded JSON body.
#[derive(Debug)]
pub struct Request {
    /// Raw request line, without terminal line endings.
    pub line: String,
    /// Raw HTTP headers for identity/connection assertions.
    pub headers: String,
    /// Parsed request JSON, retaining original query string.
    pub body: serde_json::Value,
}

/// Serve a finite response sequence, recording a separate accepted socket per response.
/// A 300 ms post-sequence accept window detects accidental retries or redirect requests.
pub async fn serve(
    responses: Vec<(u16, Vec<u8>, Duration)>,
) -> (Endpoint, JoinHandle<Vec<Request>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body, delay) in responses {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            let end = loop {
                let mut bytes = [0; 1024];
                let n = socket.read(&mut bytes).await.unwrap();
                assert!(n > 0 && request.len() + n < 128 * 1024);
                request.extend_from_slice(&bytes[..n]);
                if let Some(end) = request.windows(4).position(|p| p == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8(request[..end].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse().unwrap())
                })
                .unwrap();
            while request.len() - end < length {
                let mut bytes = [0; 1024];
                let n = socket.read(&mut bytes).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&bytes[..n]);
            }
            requests.push(Request {
                line: headers.lines().next().unwrap().into(),
                headers,
                body: serde_json::from_slice(&request[end..end + length]).unwrap(),
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(5), listener.accept())
                    .await
                    .is_err(),
                "another request began before this response completed"
            );
            tokio::time::sleep(delay).await;
            let head = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", body.len());
            if socket.write_all(head.as_bytes()).await.is_ok() {
                let _ = socket.write_all(&body).await;
            }
            let _ = socket.shutdown().await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_err(),
            "unexpected extra connection"
        );
        requests
    });
    (endpoint, handle)
}

/// Close a response before its declared body length, preserving a known seven-byte prefix.
/// Accept/read deadlines are five seconds; fixture setup or I/O failure panics.
pub async fn truncated_body() -> (Endpoint, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut buffer = [0; 1024];
            let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert!(read > 0 && request.len() + read <= 4096);
            request.extend_from_slice(&buffer[..read]);
            if let Some(end) = request.windows(4).position(|p| p == b"\r\n\r\n") {
                let headers = String::from_utf8(request[..end].to_vec()).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse().unwrap())
                    })
                    .unwrap();
                if request.len() - (end + 4) >= length {
                    break;
                }
            }
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
            )
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });
    (endpoint, handle)
}

/// Stream three chunks whose individual waits fit the deadline but whose total does not.
/// A caller that restarts its deadline for each chunk incorrectly accepts the complete body.
pub async fn slow_stream() -> (Endpoint, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut request = vec![0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(70)).await;
            if socket.write_all(b"1\r\nx\r\n").await.is_err() {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
        let _ = socket.shutdown().await;
    });
    (endpoint, handle)
}
