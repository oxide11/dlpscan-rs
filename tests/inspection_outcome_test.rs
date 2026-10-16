//! Step 2 of `docs/architecture/inspection-outcome.md`: the CLI says what its
//! verdict covers.
//!
//! A `PipelineResult` with zero matches used to be the same object for a file
//! read end to end and for an archive whose only entry nobody opened. These
//! tests pin the difference: `inspection` is `Incomplete` with a typed reason
//! whenever content went unread, `describe()` is its one-line form, and
//! `--on-incomplete fail` turns that into exit code 3 — for `scan` and for
//! `scan-dir`, which never set a non-zero exit code before.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use siphon::{Inspection, Pipeline, Unread};

/// outer.zip holding inner.zip holding secret.txt: the inner archive is never
/// descended into, so the card inside is unread content.
fn nested_zip(dir: &Path) -> std::path::PathBuf {
    let mut inner = Vec::new();
    {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut inner));
        z.start_file::<_, ()>("secret.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(b"card 4532015112830366").unwrap();
        z.finish().unwrap();
    }
    let outer = dir.join("outer.zip");
    let f = std::fs::File::create(&outer).unwrap();
    let mut z = zip::ZipWriter::new(f);
    z.start_file::<_, ()>("inner.zip", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(&inner).unwrap();
    z.finish().unwrap();
    outer
}

/// A zip with one text entry, read in full.
fn honest_zip(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("honest.zip");
    let f = std::fs::File::create(&path).unwrap();
    let mut z = zip::ZipWriter::new(f);
    z.start_file::<_, ()>("notes.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(b"credit card 4532015112830366 on file")
        .unwrap();
    z.finish().unwrap();
    path
}

fn siphon() -> Command {
    Command::new(env!("CARGO_BIN_EXE_siphon"))
}

// ── the library ────────────────────────────────────────────────────────────────

#[test]
fn a_nested_archive_makes_the_verdict_incomplete_with_a_typed_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let result = Pipeline::new().process_file(&nested_zip(tmp.path()));

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.match_count(), 0);
    assert!(!result.inspection.is_complete());
    assert!(
        matches!(
            result.inspection.unread_reasons(),
            [Unread::NestedArchive { unit }] if unit == "entry inner.zip"
        ),
        "{:?}",
        result.inspection
    );
    // The one-line form is the type's own, nothing else.
    assert!(result.inspection.describe()[0].contains("nested archive"));
}

#[test]
fn a_file_read_end_to_end_is_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let result = Pipeline::new().process_file(&honest_zip(tmp.path()));
    assert!(result.error.is_none());
    assert_eq!(result.inspection, Inspection::Complete);
    assert!(result.inspection.describe().is_empty());
    assert!(
        result.match_count() >= 1,
        "the card is readable: {result:?}"
    );
}

/// The extractor returning `Err` used to fall through to `read_to_string` and
/// report the result as a faithful read. It is still scanned — a value that
/// survives in the bytes is still worth reporting — but the verdict says it
/// covers only what that pass could see.
#[test]
fn an_extractor_failure_is_a_read_error_not_a_clean_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    // A .msg that is not an OLE compound file: `extract_msg` fails to open it.
    let path = tmp.path().join("broken.msg");
    std::fs::write(&path, b"not a compound file at all").unwrap();

    let result = Pipeline::new().process_file(&path);
    assert!(
        result.error.is_none(),
        "an unreadable format is a coverage gap, not a crash: {:?}",
        result.error
    );
    assert!(!result.inspection.is_complete());
    assert!(
        matches!(
            result.inspection.unread_reasons(),
            [Unread::ReadError { unit, .. }] if unit == "file"
        ),
        "{:?}",
        result.inspection
    );
}

/// A zip renamed `.txt` is read as the zip it is (flag policy, the default),
/// and the verdict records that the name lied — a typed reason the caller can
/// act on, where before it was a metadata key nothing serialised.
#[test]
fn a_renamed_file_carries_a_format_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let zip_path = honest_zip(tmp.path());
    let renamed = tmp.path().join("notes.txt");
    std::fs::rename(&zip_path, &renamed).unwrap();

    let result = Pipeline::new().process_file(&renamed);
    assert!(result.error.is_none());
    assert!(
        result.inspection.unread_reasons().iter().any(|r| matches!(
            r,
            Unread::FormatMismatch { declared, detected } if declared == "txt" && detected == "zip"
        )),
        "{:?}",
        result.inspection
    );
    assert!(
        result.match_count() >= 1,
        "the content was still read: {result:?}"
    );
}

#[test]
fn the_json_output_carries_the_inspection() {
    let tmp = tempfile::tempdir().unwrap();
    let result = Pipeline::new().process_file(&nested_zip(tmp.path()));
    let json: serde_json::Value =
        serde_json::from_str(&siphon::pipeline::results_to_json(&[result], false).unwrap())
            .unwrap();
    let inspection = &json[0]["inspection"];
    assert_eq!(inspection["status"], "incomplete");
    assert_eq!(inspection["unread"][0]["kind"], "nested_archive");
    assert_eq!(inspection["unread"][0]["unit"], "entry inner.zip");
    // Step 6 of the ADR: the string form is no longer on the wire.
    assert!(
        json[0].get("warnings").is_none(),
        "`warnings` was removed from the JSON output: {}",
        json[0]
    );
}

// ── the binary ─────────────────────────────────────────────────────────────────

#[test]
fn scan_reports_unread_content_and_exits_zero_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let out = siphon()
        .arg("scan")
        .arg(nested_zip(tmp.path()))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Matches: 0"), "{stdout}");
    assert!(stdout.contains("Unscanned content: 1"), "{stdout}");
    assert!(stdout.contains("nested archive"), "{stdout}");
}

#[test]
fn scan_with_on_incomplete_fail_exits_three() {
    let tmp = tempfile::tempdir().unwrap();
    let out = siphon()
        .args(["scan", "--on-incomplete", "fail"])
        .arg(nested_zip(tmp.path()))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");

    // A complete read is unaffected by the flag.
    let out = siphon()
        .args(["scan", "--on-incomplete", "fail"])
        .arg(honest_zip(tmp.path()))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn scan_dir_honours_the_exit_codes_and_names_the_gap() {
    let tmp = tempfile::tempdir().unwrap();
    nested_zip(tmp.path());
    honest_zip(tmp.path());

    // Default: exit 0, as always, but the summary and the per-file lines say
    // what was not read.
    let out = siphon().arg("scan-dir").arg(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("not fully scanned"), "{stdout}");
    assert!(stdout.contains("1 not fully scanned)"), "{stdout}");

    // `fail`: 3, because one file was not fully read.
    let out = siphon()
        .args(["scan-dir", "--on-incomplete", "fail"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");

    // `fail` with every file read in full: 0.
    std::fs::remove_file(tmp.path().join("outer.zip")).unwrap();
    let out = siphon()
        .args(["scan-dir", "--on-incomplete", "fail"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn scan_dir_json_carries_the_inspection_per_file() {
    let tmp = tempfile::tempdir().unwrap();
    nested_zip(tmp.path());
    let out = siphon()
        .args(["scan-dir", "--format", "json"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json[0]["inspection"]["status"], "incomplete");
}
