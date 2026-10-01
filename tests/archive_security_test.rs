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
//! destination directory.

#[cfg(feature = "archives")]
mod archives {
    use sevenz_rust::{SevenZArchiveEntry, SevenZWriter};

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
        let _ = siphon::extract_text(archive.to_str().unwrap());

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

        let _ = siphon::extract_text(archive.to_str().unwrap());

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

        let out =
            siphon::extract_text(archive.to_str().unwrap()).expect("benign 7z should extract");
        assert!(
            out.text.contains("4532015112830366"),
            "benign entry was not extracted: {:?}",
            out.text
        );
    }

    /// A sensitive text file inside a *plain* ZIP must be scanned, exactly as
    /// it would be inside a 7z or RAR. Regression for a silent DLP bypass: the
    /// generic-zip path used to collect only Office XML entries, so `zip
    /// out.zip secrets.txt` sailed through with zero findings (and a confusing
    /// 500 from the empty extraction). Found during pen-testing of siphon-fs.
    #[test]
    fn plain_zip_text_entry_is_scanned() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("secrets.zip");
        let f = std::fs::File::create(&archive).unwrap();
        let mut z = zip::ZipWriter::new(f);
        z.start_file::<_, ()>("secrets.txt", zip::write::FileOptions::default())
            .unwrap();
        z.write_all(b"card 4532015112830366 and SSN 457-55-5462\n")
            .unwrap();
        z.finish().unwrap();

        let out = siphon::extract_text(archive.to_str().unwrap())
            .expect("plain zip with a text entry should extract");
        assert!(
            out.text.contains("4532015112830366"),
            "sensitive .txt inside a plain .zip was not extracted: {:?}",
            out.text
        );
    }

    /// The Office path must keep working after the generic-zip branch was
    /// added — a .docx is a ZIP too, and its content still comes from the
    /// Office XML pass, not the generic text walk.
    #[test]
    fn docx_like_zip_still_extracts_xml_body() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("doc.docx");
        let f = std::fs::File::create(&archive).unwrap();
        let mut z = zip::ZipWriter::new(f);
        z.start_file::<_, ()>("word/document.xml", zip::write::FileOptions::default())
            .unwrap();
        z.write_all(b"<w:document><w:t>SSN 457-55-5462</w:t></w:document>")
            .unwrap();
        z.finish().unwrap();

        let out = siphon::extract_text(archive.to_str().unwrap()).expect("docx should extract");
        assert!(
            out.text.contains("457-55-5462"),
            "docx XML body was not extracted: {:?}",
            out.text
        );
    }

    /// A nested archive (`.zip` inside a `.zip`) is not recursed, but it must
    /// not vanish silently — the extractor surfaces a warning so an analyst
    /// knows unscanned content is present. Otherwise a sensitive file one layer
    /// deep scans to zero findings with no signal at all.
    #[test]
    fn nested_zip_surfaces_a_warning() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();

        // inner.zip holds the sensitive file
        let mut inner = Vec::new();
        {
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut inner));
            z.start_file::<_, ()>("secret.txt", zip::write::FileOptions::default())
                .unwrap();
            z.write_all(b"card 4532015112830366").unwrap();
            z.finish().unwrap();
        }

        // outer.zip wraps inner.zip
        let outer_path = tmp.path().join("outer.zip");
        {
            let f = std::fs::File::create(&outer_path).unwrap();
            let mut z = zip::ZipWriter::new(f);
            z.start_file::<_, ()>("inner.zip", zip::write::FileOptions::default())
                .unwrap();
            z.write_all(&inner).unwrap();
            z.finish().unwrap();
        }

        let out = siphon::extract_text(outer_path.to_str().unwrap()).expect("outer zip extracts");
        assert!(
            out.warnings.iter().any(|w| w.contains("nested archive")),
            "nested archive should produce a warning, got: {:?}",
            out.warnings
        );
    }

    /// Build a ZIP whose central directory and local header both *understate*
    /// the entry's uncompressed size, while the deflate stream actually holds
    /// `body` in full.
    ///
    /// Deflated, not stored, on purpose: for a stored entry the reader bounds
    /// itself by the declared size, so a lie truncates and proves nothing. A
    /// deflate stream's length is independent of the number the headers claim,
    /// which is exactly the gap being tested.
    fn craft_zip_with_understated_size(
        path: &std::path::Path,
        entry_name: &str,
        body: &[u8],
        declared: u32,
    ) {
        use std::io::Write;
        let mut raw = Vec::new();
        {
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut raw));
            z.start_file::<_, ()>(
                entry_name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            z.write_all(body).unwrap();
            z.finish().unwrap();
        }

        // Local file header: uncompressed size is 4 LE bytes at offset 22.
        assert_eq!(
            &raw[0..4],
            b"PK\x03\x04",
            "expected a local file header at 0"
        );
        raw[22..26].copy_from_slice(&declared.to_le_bytes());

        // Central directory: located through the End Of Central Directory
        // record rather than by scanning for a signature, which the body could
        // otherwise contain. EOCD holds the CD offset at its own offset 16.
        let eocd = raw
            .windows(4)
            .rposition(|w| w == b"PK\x05\x06")
            .expect("EOCD record");
        let cd_off = u32::from_le_bytes(raw[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        assert_eq!(
            &raw[cd_off..cd_off + 4],
            b"PK\x01\x02",
            "EOCD pointed somewhere other than the central directory"
        );
        raw[cd_off + 24..cd_off + 28].copy_from_slice(&declared.to_le_bytes());

        std::fs::write(path, &raw).unwrap();
    }

    /// Every size guard on the Office XML path reads `file.size()` — a number
    /// the archive asserts about itself. A `.docx` declaring 8 bytes for a
    /// `word/document.xml` that inflates to several KB used to pass all of
    /// them and then be read in full by `read_to_string`, so the per-entry cap
    /// was bypassed by exactly the lie it exists to catch. Measured at the
    /// scale that matters: a 427 KB file reached 339 MB resident.
    #[test]
    fn docx_entry_understating_its_size_is_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("liar.docx");
        // The marker sits well past the declared length, so it can only appear
        // in the output if the read ignored that length.
        let mut body = b"<w:document><w:t>".to_vec();
        body.extend(std::iter::repeat_n(b'A', 4096));
        body.extend_from_slice(b"SSN 457-55-5462</w:t></w:document>");
        craft_zip_with_understated_size(&archive, "word/document.xml", &body, 8);

        let out = siphon::extract_text(archive.to_str().unwrap()).expect("docx should extract");
        assert!(
            !out.text.contains("457-55-5462"),
            "entry was read past its declared size: {:?}",
            out.text
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("inflated past its declared size")),
            "an entry refused for lying about its size must say so, got: {:?}",
            out.warnings
        );
    }

    /// The OpenDocument path carried the same defect and had no cumulative
    /// budget across content.xml/meta.xml/styles.xml either.
    #[test]
    fn odf_entry_understating_its_size_is_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("liar.odt");
        let mut body = b"<office:document><text:p>".to_vec();
        body.extend(std::iter::repeat_n(b'A', 4096));
        body.extend_from_slice(b"SSN 457-55-5462</text:p></office:document>");
        craft_zip_with_understated_size(&archive, "content.xml", &body, 8);

        let out = siphon::extract_text(archive.to_str().unwrap()).expect("odt should extract");
        assert!(
            !out.text.contains("457-55-5462"),
            "ODF entry was read past its declared size: {:?}",
            out.text
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("inflated past its declared size")),
            "an ODF entry refused for lying about its size must say so, got: {:?}",
            out.warnings
        );
    }

    /// An honest archive must still extract — the guard keys on the lie, not on
    /// compression. Without this the fix above could pass by refusing
    /// everything.
    #[test]
    fn deflated_docx_declaring_the_truth_still_extracts() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("honest.docx");
        let f = std::fs::File::create(&archive).unwrap();
        let mut z = zip::ZipWriter::new(f);
        z.start_file::<_, ()>(
            "word/document.xml",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        z.write_all(b"<w:document><w:t>SSN 457-55-5462</w:t></w:document>")
            .unwrap();
        z.finish().unwrap();

        let out = siphon::extract_text(archive.to_str().unwrap()).expect("docx should extract");
        assert!(
            out.text.contains("457-55-5462"),
            "an honestly-declared deflated docx must still be read: {:?}",
            out.text
        );
        assert!(
            out.warnings.is_empty(),
            "an honest archive should raise no warnings, got: {:?}",
            out.warnings
        );
    }

    /// `extract_text` has always reported unreadable content through
    /// `warnings`, and siphon-fs has always returned them, but `PipelineResult`
    /// had nowhere to put them — so `process_file` dropped them and
    /// `siphon scan` printed a bare `Matches: 0` for an archive whose payload
    /// nobody had opened. The CLI and the HTTP service have to agree about
    /// what was not read.
    #[test]
    fn pipeline_result_carries_extraction_warnings() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();

        let mut inner = Vec::new();
        {
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut inner));
            z.start_file::<_, ()>("secret.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(b"card 4532015112830366").unwrap();
            z.finish().unwrap();
        }
        let outer = tmp.path().join("outer.zip");
        {
            let f = std::fs::File::create(&outer).unwrap();
            let mut z = zip::ZipWriter::new(f);
            z.start_file::<_, ()>("inner.zip", zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(&inner).unwrap();
            z.finish().unwrap();
        }

        let result = siphon::Pipeline::new().process_file(&outer);
        assert_eq!(
            result.match_count(),
            0,
            "nested entry is deliberately not recursed"
        );
        assert!(
            result.warnings.iter().any(|w| w.contains("nested archive")),
            "PipelineResult must carry the extractor's warnings, got: {:?}",
            result.warnings
        );
    }
}
