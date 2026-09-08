//! The listener side: a service certificate, and optionally a CA that every
//! client must chain to.
//!
//! siphon-api served TLS from `SIPHON_TLS_CERT`/`SIPHON_TLS_KEY` and accepted
//! any peer; siphon-fs served no TLS at all. Both now build their listener
//! config here, and when `<PREFIX>_CLIENT_CA` is set a connection without a
//! certificate that CA signed fails in the handshake — the request never
//! reaches the router, the auth middleware, or a log line that could be
//! mistaken for an authenticated attempt.
//!
//! The prefix is a parameter because siphon-launcher runs both services from
//! one environment: `SIPHON_TLS_*` is siphon-api's, `SIPHON_FS_TLS_*` is
//! siphon-fs's, and each presents its own identity.

use std::path::PathBuf;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::pem;

/// Paths, resolved from the environment before any file is opened.
#[derive(Debug, Clone)]
pub struct Settings {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// When set, clients must present a certificate chaining to this bundle.
    pub client_ca: Option<PathBuf>,
}

impl Settings {
    /// `<prefix>_CERT`, `<prefix>_KEY`, `<prefix>_CLIENT_CA`.
    ///
    /// `Ok(None)` when TLS is not configured at all. An error when it is half
    /// configured — a certificate with no key, or a client CA with no
    /// certificate to serve — because each of those is an operator who meant
    /// to turn something on.
    pub fn from_env(prefix: &str) -> Result<Option<Self>, String> {
        let var = |suffix: &str| {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from)
        };
        let (cert, key, client_ca) = (var("CERT"), var("KEY"), var("CLIENT_CA"));
        match (cert, key) {
            (Some(cert), Some(key)) => Ok(Some(Self {
                cert,
                key,
                client_ca,
            })),
            (None, None) => {
                if client_ca.is_some() {
                    return Err(format!(
                        "{prefix}_CLIENT_CA is set but {prefix}_CERT/{prefix}_KEY are not — \
                         a client CA is meaningless on a plaintext listener"
                    ));
                }
                Ok(None)
            }
            (Some(_), None) => Err(format!("{prefix}_CERT is set but {prefix}_KEY is not")),
            (None, Some(_)) => Err(format!("{prefix}_KEY is set but {prefix}_CERT is not")),
        }
    }
}

/// Loaded material, ready to become a `rustls::ServerConfig`.
pub struct ServerTls {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca: Option<RootCertStore>,
}

impl ServerTls {
    pub fn load(s: &Settings) -> Result<Self, String> {
        let certs = pem::load_certs(&s.cert, "TLS certificate")?;
        let key = pem::load_key(&s.key, "TLS private key")?;
        let client_ca = match &s.client_ca {
            Some(path) => Some(pem::load_roots(path, "TLS client CA")?),
            None => None,
        };
        Ok(Self {
            certs,
            key,
            client_ca,
        })
    }

    /// Whether a peer must present a certificate. Logged at startup so the
    /// difference between "TLS" and "mutual TLS" is visible in the record.
    pub fn requires_client_cert(&self) -> bool {
        self.client_ca.is_some()
    }

    pub fn into_config(self) -> Result<rustls::ServerConfig, String> {
        let provider = crate::provider();
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("configuring TLS listener: {e}"))?;
        let builder = match self.client_ca {
            Some(roots) => {
                // No `allow_unauthenticated()`: a client CA that is set is a
                // requirement, not a preference. The verifier rejects a
                // handshake with no client certificate outright.
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                        .build()
                        .map_err(|e| format!("building client certificate verifier: {e}"))?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        builder
            .with_single_cert(self.certs, self.key)
            .map_err(|e| format!("TLS certificate/key: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialised because they set process-wide environment. The prefix is
    // unique to this test module so a parallel test elsewhere cannot collide.
    fn with_env<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
        let out = f();
        for (k, _) in vars {
            std::env::remove_var(k);
        }
        out
    }

    #[test]
    fn unset_is_plaintext_not_an_error() {
        let s = with_env(&[], || Settings::from_env("SIPHON_AUTH_TEST_TLS")).unwrap();
        assert!(s.is_none());
    }

    #[test]
    fn a_certificate_without_a_key_is_an_error() {
        let r = with_env(&[("SIPHON_AUTH_TEST_TLS_CERT", "/x.crt")], || {
            Settings::from_env("SIPHON_AUTH_TEST_TLS")
        });
        assert!(r.unwrap_err().contains("_KEY is not"));
    }

    #[test]
    fn a_client_ca_on_a_plaintext_listener_is_an_error() {
        // The operator meant to require client certificates; silently
        // serving plaintext instead is the opposite of what they asked.
        let r = with_env(&[("SIPHON_AUTH_TEST_TLS_CLIENT_CA", "/ca.crt")], || {
            Settings::from_env("SIPHON_AUTH_TEST_TLS")
        });
        assert!(r
            .unwrap_err()
            .contains("meaningless on a plaintext listener"));
    }
}
