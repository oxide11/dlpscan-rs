//! The property the crate exists for, exercised with a real handshake: a
//! listener with a client CA admits a peer holding a certificate from that CA
//! and refuses one with none, or with one from elsewhere.
//!
//! Certificates come from `scripts/dev/mkcerts.sh`, so this also proves the
//! generator produces material rustls accepts — a script that emits a CA
//! without `keyCertSign` or a leaf without the right EKU fails here rather
//! than at deploy time.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rustls_pki_types::ServerName;
use siphon_auth::db::{self, DbTls};
use siphon_auth::pem;
use siphon_auth::server::{ServerTls, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn mkcerts(out: &Path) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dev/mkcerts.sh");
    let status = Command::new("bash")
        .arg(&script)
        .arg("--out")
        .arg(out)
        .arg("--quiet")
        .status()
        .expect("run scripts/dev/mkcerts.sh (needs bash and openssl)");
    assert!(status.success(), "mkcerts.sh failed");
}

struct Certs {
    dir: PathBuf,
}

impl Certs {
    fn generate() -> (tempfile::TempDir, Self) {
        let tmp = tempfile::tempdir().unwrap();
        mkcerts(tmp.path());
        let dir = tmp.path().to_path_buf();
        (tmp, Self { dir })
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
}

fn client_config(ca: &Path, identity: Option<(&Path, &Path)>) -> Arc<rustls::ClientConfig> {
    let roots = pem::load_roots(ca, "ca").unwrap();
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    Arc::new(match identity {
        Some((cert, key)) => b
            .with_client_auth_cert(
                pem::load_certs(cert, "cert").unwrap(),
                pem::load_key(key, "key").unwrap(),
            )
            .unwrap(),
        None => b.with_no_client_auth(),
    })
}

/// One server accept + one client connect; returns whether the *server* saw
/// an authenticated stream and echoed. Judged from the server side because
/// under TLS 1.3 the client's handshake can complete before the server has
/// evaluated the client certificate, so the client only learns of rejection
/// on its first read.
async fn exchange(server: rustls::ServerConfig, client: Arc<rustls::ClientConfig>) -> bool {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return false;
        };
        let mut buf = [0u8; 4];
        if tls.read_exact(&mut buf).await.is_err() {
            return false;
        }
        tls.write_all(&buf).await.is_ok()
    });

    let connector = tokio_rustls::TlsConnector::from(client);
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("siphon-api").unwrap();
    let client_result = async {
        let mut tls = connector.connect(name, tcp).await.ok()?;
        tls.write_all(b"ping").await.ok()?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.ok()?;
        Some(buf)
    }
    .await;

    let server_ok = server_task.await.unwrap();
    if server_ok {
        assert_eq!(client_result, Some(*b"ping"));
    }
    server_ok
}

fn server_config(c: &Certs, client_ca: bool) -> rustls::ServerConfig {
    let s = Settings {
        cert: c.p("siphon-api/tls.crt"),
        key: c.p("siphon-api/tls.key"),
        client_ca: client_ca.then(|| c.p("ca/ca.crt")),
    };
    let tls = ServerTls::load(&s).unwrap();
    assert_eq!(tls.requires_client_cert(), client_ca);
    tls.into_config().unwrap()
}

#[tokio::test]
async fn a_peer_with_the_right_certificate_is_admitted() {
    let (_tmp, c) = Certs::generate();
    let client = client_config(
        &c.p("ca/ca.crt"),
        Some((&c.p("nginx/client.crt"), &c.p("nginx/client.key"))),
    );
    assert!(exchange(server_config(&c, true), client).await);
}

#[tokio::test]
async fn a_peer_with_no_certificate_never_reaches_the_application() {
    let (_tmp, c) = Certs::generate();
    let client = client_config(&c.p("ca/ca.crt"), None);
    assert!(
        !exchange(server_config(&c, true), client).await,
        "anonymous peer was admitted by a listener with a client CA"
    );
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused() {
    let (_tmp, ours) = Certs::generate();
    let (_tmp2, theirs) = Certs::generate();
    // Their CA is not ours, so a client certificate it issued proves nothing
    // to us — even though it is otherwise well-formed.
    let client = client_config(
        &ours.p("ca/ca.crt"),
        Some((&theirs.p("nginx/client.crt"), &theirs.p("nginx/client.key"))),
    );
    assert!(!exchange(server_config(&ours, true), client).await);
}

#[tokio::test]
async fn without_a_client_ca_anyone_is_admitted() {
    // The pre-existing behaviour, kept reachable on purpose for a listener
    // behind a mesh — and pinned so nobody thinks TLS alone authenticates.
    let (_tmp, c) = Certs::generate();
    let client = client_config(&c.p("ca/ca.crt"), None);
    assert!(exchange(server_config(&c, false), client).await);
}

#[test]
fn the_generated_db_client_identity_loads_in_mtls_mode() {
    let (_tmp, c) = Certs::generate();
    let s = db::Settings {
        mode: db::Mode::Mtls,
        ca_file: Some(c.p("ca/ca.crt")),
        client_cert: Some(c.p("siphon-api/db-client.crt")),
        client_key: Some(c.p("siphon-api/db-client.key")),
    };
    let tls = DbTls::from_settings(&s).unwrap();
    assert!(tls.is_client_authenticated());
}

#[test]
fn the_db_client_cn_is_the_database_role() {
    // Postgres `clientcert=verify-full` matches the CN against the role name.
    // A generator that puts the service name there instead would produce
    // certificates that chain correctly and are refused by every hostssl
    // line — and the failure would look like a password problem.
    let (_tmp, c) = Certs::generate();
    let out = Command::new("openssl")
        .args(["x509", "-noout", "-subject", "-in"])
        .arg(c.p("siphon-smtp/db-client.crt"))
        .output()
        .unwrap();
    let subject = String::from_utf8_lossy(&out.stdout);
    assert!(
        subject.contains("CN = siphon") || subject.contains("CN=siphon"),
        "{subject}"
    );
}
