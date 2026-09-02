//! Archive-extraction security regressions.
//!
//! `sevenz-rust 0.6` does not sanitise entry names: its
//! `default_entry_extract_fn` builds the output path as
//! `dest.join(entry.name())` and calls `File::create` on the result. An entry
//! named `../../x` therefore escapes the destination, and an absolute name
//! discards the destination entirely, since `Path::join` on an absolute path
//! returns that path. This is Zip Slip, and the crate offers no guard.
//!
//! `extract_7z` consequently drives extraction itself rather than calling
//! `decompress_file`, routing every entry name through `sanitize_archive_path`.
//! These tests craft hostile archives and assert nothing lands outside the
//! destination.

use sevenz_rust::{SevenZArchiveEntry, SevenZWriter};
use std::io::Write;

/// Build a 7z whose single entry carries `entry_name` verbatim.
fn craft_7z(archive: &std::path::Path, entry_name: &str, body: &[u8]) {
    let mut w = SevenZWriter::create(archive).expect("create 7z");
    let mut entry = SevenZArchiveEntry::default();
    entry.name = entry_name.to_string();
    entry.has_stream = true;
    w.push_archive_entry(entry, Some(body)).expect("push entry");
    w.finish().expect("finish 7z");
}

#[test]
fn seven_z_relative_traversal_is_contained() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("evil.7z");
    // The canary sits beside the extraction root, where `../` would land.
    let canary = tmp.path().join("PWNED.txt");
    craft_7z(&archive, "../../PWNED.txt", b"traversal succeeded");

    // Extraction may succeed or error; what matters is where bytes landed.
    let _ = siphon::extractors::extract_text(archive.to_str().unwrap());

    assert!(
        !canary.exists(),
        "7z entry '../../PWNED.txt' escaped the extraction directory"
    );
}

#[test]
fn seven_z_absolute_path_entry_is_contained() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("evil-abs.7z");
    let canary = tmp.path().join("ABS_PWNED.txt");
    // `Path::join` with an absolute path discards the base entirely, so an
    // absolute entry name is the sharper version of the same bug.
    let abs = canary.to_string_lossy().to_string();
    craft_7z(&archive, &abs, b"absolute traversal succeeded");

    let _ = siphon::extractors::extract_text(archive.to_str().unwrap());

    assert!(
        !canary.exists(),
        "absolute 7z entry name escaped the extraction directory"
    );
}

#[test]
fn seven_z_benign_entry_still_extracts() {
    // The guard must not reject ordinary archives — a traversal check that
    // blocks everything is as broken as one that blocks nothing.
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("benign.7z");
    craft_7z(&archive, "notes.txt", b"card 4532015112830366 inside");

    let out = siphon::extractors::extract_text(archive.to_str().unwrap())
        .expect("benign 7z should extract");
    assert!(
        out.text.contains("4532015112830366"),
        "benign entry was not extracted: {:?}",
        out.text
    );
}
