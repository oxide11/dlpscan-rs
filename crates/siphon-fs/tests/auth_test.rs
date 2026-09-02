//! Authentication enforcement for siphon-fs.
//!
//! Until 2026-09-02 this service had no authentication at all: `POST /scan`
//! accepted uploads, `GET /v1/findings` returned previously scanned findings,
//! and `POST /v1/overrides/reload` mutated detection config — none of them
//! requiring a credential. Both `CLAUDE.md` and the nginx config asserted the
//! opposite, and nginx omits its Authelia gate for `/fs/` on the strength of
//! that assertion, so the claim being false made the whole path open.
//!
//! These tests exist so the claim stays true.
//!
//! Requests are written straight onto a TCP socket rather than through an HTTP
//! client: the assertions only need a status line, and siphon-fs has no HTTP
//! client dependency worth adding one for.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const KEY: &str = "test-key-0123456789abcdef";

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(port: u16) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_siphon-fs"))
        .env("SIPHON_API_KEY", KEY)
        .env("SIPHON_FS_BIND", format!("127.0.0.1:{port}"))
        .env_remove("SIPHON_DATABASE_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn siphon-fs");

    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Server(child);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("siphon-fs did not begin listening on port {port}");
}

/// Issue a request and return the numeric status from the response line.
fn status(port: u16, method: &str, path: &str, auth: Option<&str>) -> u16 {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    if method == "POST" {
        req.push_str("Content-Length: 0\r\n");
    }
    req.push_str("\r\n");

    sock.write_all(req.as_bytes()).expect("write request");
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next().unwrap_or_default();
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status in response line: {line:?}"))
}

#[test]
fn probes_open_everything_else_gated() {
    let port = 18211;
    let _s = start(port);

    // Kubelet probes stay unauthenticated: a kubelet cannot present a token,
    // and gating them crash-loops the pod on every rollout.
    assert_eq!(
        status(port, "GET", "/health", None),
        200,
        "/health must be open"
    );
    assert_eq!(
        status(port, "GET", "/ready", None),
        200,
        "/ready must be open"
    );

    // Findings are other people's sensitive data. No credential, no read.
    assert_eq!(
        status(port, "GET", "/v1/findings", None),
        401,
        "findings readable without a credential"
    );
    assert_eq!(
        status(port, "GET", "/v1/findings", Some("Bearer wrong-key")),
        401,
        "a wrong key was accepted"
    );
    assert_eq!(
        status(port, "GET", "/v1/findings", Some("Bearer ")),
        401,
        "an empty bearer token was accepted"
    );
    assert_eq!(
        status(port, "GET", "/v1/findings", Some(&format!("Bearer {KEY}"))),
        200,
        "the configured key was rejected"
    );

    // Upload and config mutation are gated too, not just reads.
    assert_eq!(
        status(port, "POST", "/scan", None),
        401,
        "uploads accepted without a credential"
    );
    assert_eq!(
        status(port, "POST", "/v1/overrides/reload", None),
        401,
        "detection config mutable without a credential"
    );
}

#[test]
fn refuses_to_start_without_a_key() {
    // Fail closed. An operator who forgets the key gets a dead pod, which is
    // noticed, rather than an open upload endpoint, which is not.
    for (label, key) in [("unset", None), ("empty", Some(""))] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_siphon-fs"));
        cmd.env_remove("SIPHON_API_KEY")
            .env_remove("SIPHON_ALLOW_UNAUTHENTICATED")
            .env("SIPHON_FS_BIND", "127.0.0.1:18212")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(k) = key {
            cmd.env("SIPHON_API_KEY", k);
        }
        let out = cmd.output().expect("run siphon-fs");
        assert!(
            !out.status.success(),
            "siphon-fs started with a {label} API key instead of refusing"
        );
    }
}
