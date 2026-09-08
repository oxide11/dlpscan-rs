//! Service identity for the Siphon stack: mutual TLS on every hop between a
//! detector and the C2/IR surface or the database.
//!
//! # Mutual, not merely encrypted
//!
//! `SIPHON_DATABASE_TLS=require` verified the server's certificate and left
//! the client anonymous; siphon-api's listener served a certificate and
//! accepted any peer that could reach the port. Both hops were encrypted and
//! neither was *authenticated* — a pod that could open a socket to siphon-api
//! was, as far as TLS was concerned, nginx.
//!
//! This crate is the one implementation of both directions:
//!
//! * [`db::DbTls`] — the Postgres connector. Mode `mtls` presents a client
//!   certificate and refuses to start without one.
//! * [`server::ServerTls`] — the listener side for siphon-api and siphon-fs.
//!   When a client CA is configured, a peer without a certificate chaining
//!   to it never reaches the HTTP layer; the handshake fails.
//!
//! # Failure direction
//!
//! Everything here fails closed and fails at startup. A certificate is
//! deployment configuration, not a runtime credential that can lag, so there
//! is no grace path: a service configured for `mtls` with no client
//! certificate does not come up, and a peer with the wrong CA gets a TLS
//! alert, not a 401.
//!
//! The one thing that is *not* here is a switch that silently downgrades.
//! Every mode is named in an environment variable an operator set on
//! purpose, and the startup log line says which one is in effect.

pub mod db;
pub mod pem;
pub mod server;

/// The crypto provider every config in this crate is built with.
///
/// Named explicitly rather than installed process-wide: siphon-api drives
/// rustls for its own listener as well as for Postgres, and a global default
/// couples two unrelated call sites through hidden state. Without an explicit
/// provider rustls 0.23 panics at first use — "Could not automatically
/// determine the process-level CryptoProvider".
pub(crate) fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}
