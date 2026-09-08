//! PEM loading with errors that name the file and the variable.
//!
//! A TLS misconfiguration is found at 3 a.m. by someone reading a log line;
//! "invalid PEM" is not enough, and neither is a path with no hint of which
//! setting produced it.

use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;

/// Every certificate in a PEM file. Errors on an unreadable file or one
/// holding no certificates — an empty chain would build a config that fails
/// only on first use.
pub fn load_certs(path: &Path, what: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = read(path, what)?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{what} {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{what} {}: no certificates found", path.display()));
    }
    Ok(certs)
}

/// The first private key in a PEM file (PKCS#8, PKCS#1 or SEC1).
pub fn load_key(path: &Path, what: &str) -> Result<PrivateKeyDer<'static>, String> {
    let pem = read(path, what)?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|e| format!("{what} {}: {e}", path.display()))
}

/// A root store holding every certificate in a PEM bundle, and nothing else.
///
/// Used for the client CA on a listener and for the Postgres CA when the
/// platform roots are not wanted. Deliberately does not fall back to the
/// platform store: a listener that trusts "the deployment's CA, or any
/// public CA" accepts a client certificate from anyone with a domain name.
pub fn load_roots(path: &Path, what: &str) -> Result<RootCertStore, String> {
    let certs = load_certs(path, what)?;
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(format!(
            "{what} {}: no usable CA certificates ({ignored} ignored)",
            path.display()
        ));
    }
    if ignored > 0 {
        tracing::warn!(
            path = %path.display(),
            added,
            ignored,
            "{what}: some certificates in the bundle could not be parsed as CAs"
        );
    }
    Ok(roots)
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("reading {what} {}: {e}", path.display()))
}
