//! Path sanitization helpers for user-supplied input.
//!
//! Addresses CodeQL `rust/path-injection` — when HTTP/user-facing code
//! builds a filesystem path from untrusted input, route it through
//! [`safe_path`] so a `..` or absolute path can't escape the intended
//! directory. Canonicalizes the joined path and verifies the result is
//! still rooted at `base`, with a pre-canonicalize syntactic reject of
//! absolute inputs and `ParentDir` components so failures are
//! deterministic even when the target does not yet exist.

use crate::errors::{DlpError, Result};
use std::path::{Component, Path, PathBuf};

/// Resolve `user_input` against `base`, rejecting traversal attempts.
///
/// Returns `DlpError::InvalidPath` if `user_input` is absolute, empty,
/// contains a `..` component, or canonicalization fails; returns
/// `DlpError::PathTraversal` if the canonicalized result escapes
/// `base`. `base` itself is canonicalized first so symlinked mount
/// points (common in k8s ConfigMap mounts) don't trigger false
/// positives.
pub fn safe_path(base: &Path, user_input: &str) -> Result<PathBuf> {
    if user_input.is_empty() {
        return Err(DlpError::InvalidPath);
    }

    let candidate = Path::new(user_input);
    if candidate.is_absolute() {
        return Err(DlpError::InvalidPath);
    }
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(DlpError::PathTraversal);
    }

    let canonical_base = base.canonicalize().map_err(|_| DlpError::InvalidPath)?;
    let joined = canonical_base.join(candidate);
    let canonical = joined.canonicalize().map_err(|_| DlpError::InvalidPath)?;
    if !canonical.starts_with(&canonical_base) {
        return Err(DlpError::PathTraversal);
    }
    Ok(canonical)
}

/// True if `token` is a safe version label of the form `v<digits>`
/// (the shape `overrides_apply` emits for backup filenames). Used by
/// `overrides_revert` to reject attempts to smuggle path separators
/// through the `version` field.
pub fn is_safe_version_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('v') else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn safe_path_accepts_child() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("ok.txt"), b"hi").unwrap();
        let r = safe_path(tmp.path(), "ok.txt").unwrap();
        assert!(r.ends_with("ok.txt"));
    }

    #[test]
    fn safe_path_rejects_parent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            safe_path(tmp.path(), "../etc/passwd"),
            Err(DlpError::PathTraversal)
        ));
    }

    #[test]
    fn safe_path_rejects_absolute() {
        let tmp = tempfile::tempdir().unwrap();
        let abs = if cfg!(windows) {
            "C:\\windows\\system32\\notepad.exe"
        } else {
            "/etc/passwd"
        };
        assert!(matches!(
            safe_path(tmp.path(), abs),
            Err(DlpError::InvalidPath)
        ));
    }

    #[test]
    fn safe_path_rejects_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            safe_path(tmp.path(), ""),
            Err(DlpError::InvalidPath)
        ));
    }

    #[test]
    fn safe_path_rejects_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            safe_path(tmp.path(), "nope.txt"),
            Err(DlpError::InvalidPath)
        ));
    }

    #[test]
    fn version_token_accepts_v_digits() {
        assert!(is_safe_version_token("v12345"));
        assert!(is_safe_version_token("v0"));
    }

    #[test]
    fn version_token_rejects_traversal() {
        assert!(!is_safe_version_token("v1/../etc"));
        assert!(!is_safe_version_token("../etc"));
        assert!(!is_safe_version_token("v"));
        assert!(!is_safe_version_token(""));
        assert!(!is_safe_version_token("vabc"));
        assert!(!is_safe_version_token("v1.2"));
    }
}
