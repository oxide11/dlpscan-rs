//! The Postgres connector, in one place.
//!
//! Findings rows carry the sensitive data this product exists to detect —
//! matched card numbers, national IDs, credentials — and the mail path
//! carries whole messages. The link that moves them is worth authenticating
//! in both directions, not only encrypting.
//!
//! Controlled by `SIPHON_DATABASE_TLS`:
//!
//! | Mode | Server verified | Client presents a certificate |
//! |---|---|---|
//! | `disable` | — | — |
//! | `require` *(default)* | yes, against platform roots plus `SIPHON_DATABASE_CA_FILE` | if `SIPHON_DATABASE_CLIENT_CERT` and `_KEY` are both set |
//! | `mtls` | yes | **always** — startup is refused without both |
//!
//! `require` presents a certificate when one is configured so that setting
//! the two variables is never a downgrade; `mtls` exists so an operator can
//! say "and refuse to run without it", which is the difference between a
//! deployment that is mutual today and one that is guaranteed to stay so.
//!
//! Postgres enforces the other half with `clientcert=verify-full` in
//! `pg_hba.conf` (`deploy/postgres/pg_hba.conf`): the certificate must chain
//! to its CA *and* carry the connecting role's name as its CN.

use std::path::PathBuf;

use deadpool_postgres::{CreatePoolError, Pool, Runtime, SslMode};
use tokio_postgres::NoTls;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::pem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Disable,
    Require,
    Mtls,
}

impl Mode {
    /// Parse the wire value. Unknown values are an error, never a fallback —
    /// a typo in a TLS mode must not quietly select a weaker one.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disable" | "off" | "false" => Ok(Self::Disable),
            "require" | "on" | "true" => Ok(Self::Require),
            "mtls" | "verify-client" => Ok(Self::Mtls),
            other => Err(format!(
                "SIPHON_DATABASE_TLS={other:?} is not recognised (expected 'disable', 'require' or 'mtls')"
            )),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Require => "require",
            Self::Mtls => "mtls",
        }
    }
}

/// Everything the connector needs, gathered before any file is opened so a
/// test can build it without touching the environment.
#[derive(Debug, Clone)]
pub struct Settings {
    pub mode: Mode,
    /// Extra CA bundle for a self-signed or in-cluster Postgres.
    pub ca_file: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

impl Settings {
    /// `SIPHON_DATABASE_TLS`, `SIPHON_DATABASE_CA_FILE`,
    /// `SIPHON_DATABASE_CLIENT_CERT`, `SIPHON_DATABASE_CLIENT_KEY`.
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let mode = match var("SIPHON_DATABASE_TLS") {
            Some(raw) => Mode::parse(&raw)?,
            None => Mode::Require,
        };
        Ok(Self {
            mode,
            ca_file: var("SIPHON_DATABASE_CA_FILE").map(PathBuf::from),
            client_cert: var("SIPHON_DATABASE_CLIENT_CERT").map(PathBuf::from),
            client_key: var("SIPHON_DATABASE_CLIENT_KEY").map(PathBuf::from),
        })
    }
}

/// Either connector, resolved at startup. Boxed because the rustls variant is
/// substantially larger than the unit-sized `NoTls`.
pub enum DbTls {
    Plain,
    Tls {
        connect: Box<MakeRustlsConnect>,
        /// True when a client certificate is presented. Reported at startup
        /// so "encrypted" and "mutually authenticated" are not confused in
        /// the log.
        client_authenticated: bool,
    },
}

impl DbTls {
    pub fn from_env() -> Result<Self, String> {
        Self::from_settings(&Settings::from_env()?)
    }

    pub fn from_settings(s: &Settings) -> Result<Self, String> {
        match s.mode {
            Mode::Disable => {
                tracing::warn!(
                    "SIPHON_DATABASE_TLS=disable — the Postgres link is unencrypted and \
                     unauthenticated. The rows it carries are the sensitive values this \
                     scanner detects; only do this for a loopback Postgres in local \
                     development or when a service mesh secures the hop"
                );
                Ok(Self::Plain)
            }
            Mode::Require | Mode::Mtls => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                if let Some(path) = &s.ca_file {
                    let extra = pem::load_roots(path, "SIPHON_DATABASE_CA_FILE")?;
                    let n = extra.len();
                    roots.roots.extend(extra.roots);
                    tracing::info!(path = %path.display(), added = n, "loaded extra Postgres CA certificates");
                }

                let client = match (&s.client_cert, &s.client_key) {
                    (Some(cert), Some(key)) => Some((
                        pem::load_certs(cert, "SIPHON_DATABASE_CLIENT_CERT")?,
                        pem::load_key(key, "SIPHON_DATABASE_CLIENT_KEY")?,
                    )),
                    (None, None) => None,
                    // Half a client identity is a misconfiguration, whatever
                    // the mode: the operator meant to present one.
                    (Some(_), None) => return Err(
                        "SIPHON_DATABASE_CLIENT_CERT is set but SIPHON_DATABASE_CLIENT_KEY is not"
                            .into(),
                    ),
                    (None, Some(_)) => return Err(
                        "SIPHON_DATABASE_CLIENT_KEY is set but SIPHON_DATABASE_CLIENT_CERT is not"
                            .into(),
                    ),
                };

                if s.mode == Mode::Mtls && client.is_none() {
                    return Err(
                        "SIPHON_DATABASE_TLS=mtls requires SIPHON_DATABASE_CLIENT_CERT and \
                         SIPHON_DATABASE_CLIENT_KEY — refusing to connect to Postgres without \
                         presenting a client certificate"
                            .into(),
                    );
                }

                let builder = rustls::ClientConfig::builder_with_provider(crate::provider())
                    .with_safe_default_protocol_versions()
                    .map_err(|e| format!("configuring Postgres TLS: {e}"))?
                    .with_root_certificates(roots);
                let (config, client_authenticated) = match client {
                    Some((certs, key)) => (
                        builder
                            .with_client_auth_cert(certs, key)
                            .map_err(|e| format!("Postgres client certificate: {e}"))?,
                        true,
                    ),
                    None => (builder.with_no_client_auth(), false),
                };

                if client_authenticated {
                    tracing::info!(
                        mode = s.mode.label(),
                        "Postgres TLS enabled, client certificate presented"
                    );
                } else {
                    tracing::info!(
                        mode = s.mode.label(),
                        "Postgres TLS enabled; no client certificate configured, so this hop \
                         is encrypted but the service is anonymous to the database"
                    );
                }
                Ok(Self::Tls {
                    connect: Box::new(MakeRustlsConnect::new(config)),
                    client_authenticated,
                })
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Tls { .. })
    }

    pub fn is_client_authenticated(&self) -> bool {
        matches!(
            self,
            Self::Tls {
                client_authenticated: true,
                ..
            }
        )
    }

    /// Build the pool with this connector.
    ///
    /// Supplying a TLS connector is not by itself enough to get an encrypted
    /// link. tokio-postgres defaults to `SslMode::Prefer`, which negotiates
    /// TLS and then *silently continues in clear text* if the server
    /// declines — so a stripped or misconfigured server downgrades the
    /// connection without a word, which is precisely the exposure `require`
    /// exists to close. deadpool applies `ssl_mode` after parsing the URL, so
    /// this also overrides an `sslmode=` the connection string may carry.
    pub fn create_pool(self, mut cfg: deadpool_postgres::Config) -> Result<Pool, CreatePoolError> {
        match self {
            Self::Plain => cfg.create_pool(Some(Runtime::Tokio1), NoTls),
            Self::Tls { connect, .. } => {
                cfg.ssl_mode = Some(SslMode::Require);
                cfg.create_pool(Some(Runtime::Tokio1), *connect)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: Mode) -> Settings {
        Settings {
            mode,
            ca_file: None,
            client_cert: None,
            client_key: None,
        }
    }

    #[test]
    fn unknown_mode_is_an_error_not_a_fallback() {
        assert!(Mode::parse("prefer").is_err());
        assert!(Mode::parse("").is_err());
        assert_eq!(Mode::parse(" MTLS ").unwrap(), Mode::Mtls);
    }

    #[test]
    fn mtls_without_a_client_certificate_refuses_to_start() {
        let err = DbTls::from_settings(&settings(Mode::Mtls))
            .err()
            .expect("must refuse");
        assert!(err.contains("SIPHON_DATABASE_CLIENT_CERT"), "{err}");
    }

    #[test]
    fn require_without_a_client_certificate_is_encrypted_but_anonymous() {
        let tls = DbTls::from_settings(&settings(Mode::Require)).unwrap();
        assert!(tls.is_encrypted());
        assert!(!tls.is_client_authenticated());
    }

    #[test]
    fn half_a_client_identity_is_a_misconfiguration() {
        let mut s = settings(Mode::Require);
        s.client_cert = Some("/nonexistent/client.crt".into());
        let err = DbTls::from_settings(&s).err().expect("must refuse");
        assert!(err.contains("SIPHON_DATABASE_CLIENT_KEY is not"), "{err}");
    }

    #[test]
    fn disable_is_plain() {
        assert!(!DbTls::from_settings(&settings(Mode::Disable))
            .unwrap()
            .is_encrypted());
    }
}
