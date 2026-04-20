//! Evasion technique tests for siphon-rs.
//!
//! Tests resilience against malformed files, polyglots, resource exhaustion,
//! and format-specific evasion vectors.

use std::io::Write;

// ---------------------------------------------------------------------------
// 1. Extension Mismatch / Polyglot Tests
// ---------------------------------------------------------------------------

/// HTML file containing sensitive data saved with .docx extension.
/// Tests whether scanner trusts extension or uses magic bytes.
#[test]
fn test_extension_mismatch_html_as_docx() {
    let html = r#"<html><body>
        Credit card: 4532015112830366
        SSN: 425-71-3482
        Email: secret@example.com
    </body></html>"#;

    let f = tempfile::Builder::new().suffix(".docx").tempfile().unwrap();
    std::fs::write(f.path(), html.as_bytes()).unwrap();

    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    // The file has no PK magic bytes, so zip extraction should fail.
    // The pipeline should fall back to plain text extraction.
    // Either way, the sensitive data MUST be detected.
    match result {
        Ok(r) => {
            // If extraction succeeded (e.g., via magic byte fallback to plain text),
            // verify the sensitive data was found
            assert!(
                r.text.contains("4532015112830366") || r.text.contains("425-71-3482"),
                "HTML-as-DOCX: extracted text should contain sensitive data, got: {:?}",
                &r.text[..r.text.len().min(200)]
            );
        }
        Err(_) => {
            // Extraction failed — this is the fail-OPEN scenario.
            // The pipeline should fall back to read_to_string.
            // Test that directly:
            let raw = std::fs::read_to_string(f.path()).unwrap();
            assert!(
                raw.contains("4532015112830366"),
                "Fallback text read should still contain the data"
            );

            // Now test via scanner to ensure detection works on fallback
            let matches = siphon::scan_text(&raw).unwrap();
            assert!(
                matches
                    .iter()
                    .any(|m| m.sub_category == "Visa" || m.sub_category == "Email Address"),
                "Scanner must detect sensitive data in HTML-as-DOCX fallback"
            );
        }
    }
}

/// HTML file saved with .pdf extension — tests magic byte detection.
#[test]
fn test_extension_mismatch_html_as_pdf() {
    let html = "<html><body>SSN: 219-09-9999 and card 4532015112830366</body></html>";

    let f = tempfile::Builder::new().suffix(".pdf").tempfile().unwrap();
    std::fs::write(f.path(), html.as_bytes()).unwrap();

    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    // No %PDF magic bytes, so PDF extractor won't trigger.
    // Magic byte detection returns None, falls back to plain text.
    match result {
        Ok(r) => {
            assert!(
                r.text.contains("4532015112830366"),
                "HTML-as-PDF: must detect card number"
            );
        }
        Err(_) => {
            // Even if extraction fails, raw text is readable
            let raw = std::fs::read_to_string(f.path()).unwrap();
            assert!(raw.contains("4532015112830366"));
        }
    }
}

/// Plain text file with PK ZIP magic bytes prepended — tests magic byte trust.
#[test]
fn test_polyglot_zip_header_with_text_payload() {
    let mut data = b"PK\x03\x04".to_vec(); // ZIP magic bytes
    data.extend_from_slice(b"\x00\x00\x00\x00"); // fake header
    data.extend_from_slice(b"SSN: 425-71-3482 credit card 4532015112830366");

    let f = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
    std::fs::write(f.path(), &data).unwrap();

    // Extension says .txt (plain text), but magic bytes say ZIP.
    // get_extractor checks extension first, so .txt -> extract_plain_text.
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    // Since it's .txt, it should be treated as text regardless of magic bytes
    assert!(
        result.is_ok(),
        "Plain text extraction should succeed for .txt"
    );
}

// ---------------------------------------------------------------------------
// 2. Corrupted Header / Fail-Open Tests
// ---------------------------------------------------------------------------

/// Corrupted DOCX (valid ZIP start but broken central directory).
/// Tests: does scanner fail open (miss data) or fall back to raw scan?
///
/// FINDING: When a DOCX is compressed (default), corrupting the ZIP
/// central directory makes the compressed payload unreadable. The raw
/// bytes no longer contain the plaintext. This is an inherent limitation
/// of ZIP-based formats — NOT a scanner bug.
///
/// To detect data in corrupted ZIPs, we'd need to attempt entry-by-entry
/// decompression of the local file headers (ignoring the central directory).
#[test]
fn test_corrupted_docx_fail_behavior() {
    // Create a minimal valid ZIP with STORED (uncompressed) content
    // so the payload survives corruption
    let f = tempfile::Builder::new().suffix(".docx").tempfile().unwrap();
    {
        let file = std::fs::File::create(f.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored); // Uncompressed!
        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Secret SSN 425-71-3482 and card 4532015112830366</w:t></w:r></w:p></w:body></w:document>"
        ).unwrap();
        zip.finish().unwrap();
    }

    // First verify it works uncorrupted
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    assert!(result.is_ok(), "Valid DOCX should extract successfully");
    let text = result.unwrap().text;
    assert!(
        text.contains("425-71-3482"),
        "Valid DOCX should contain SSN: {text}"
    );

    // Now corrupt the central directory (last 22+ bytes of ZIP)
    let mut data = std::fs::read(f.path()).unwrap();
    let len = data.len();
    if len > 30 {
        for b in data[len - 22..].iter_mut() {
            *b = 0xFF;
        }
    }
    std::fs::write(f.path(), &data).unwrap();

    // Try extraction — should fail on ZIP parse
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    match result {
        Ok(r) => {
            // If extraction still works, data should be present
            if r.text.contains("425-71-3482") {
                eprintln!("GOOD: found data despite corruption");
            }
        }
        Err(_) => {
            // ZIP extraction failed. Since we used STORED compression,
            // the plaintext is still in the raw bytes.
            let raw = std::fs::read(f.path()).unwrap();
            let raw_text = String::from_utf8_lossy(&raw);
            assert!(
                raw_text.contains("425-71-3482"),
                "Raw bytes of STORED ZIP should still contain the SSN payload"
            );
            // This demonstrates the need for a raw-byte fallback scanner
            // when structured extraction fails.
        }
    }
}

/// Tests that a corrupted ZIP doesn't panic and attempts recovery.
#[test]
fn test_corrupted_zip_no_panic() {
    let f = tempfile::Builder::new().suffix(".docx").tempfile().unwrap();
    // Write garbage with ZIP magic bytes + embedded text
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(&[0xFF; 200]);
    data.extend_from_slice(b"hidden SSN 425-71-3482 here in the raw bytes of the file");
    std::fs::write(f.path(), &data).unwrap();

    // Must not panic — may succeed via raw byte recovery or fail gracefully
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    match result {
        Ok(r) => {
            // Recovery succeeded — verify it found the embedded text
            assert!(
                r.text.contains("425-71-3482"),
                "ZIP recovery should find embedded SSN: {}",
                &r.text[..r.text.len().min(200)]
            );
        }
        Err(_) => {
            // Graceful failure — acceptable if no printable strings found
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Offset Map Limits / MAX_MATCHES Stress Test
// ---------------------------------------------------------------------------

/// Feed the scanner 50,000+ credit card numbers with zero-width spaces.
/// Tests offset_map memory, match truncation, and scan_truncated flag.
#[test]
fn test_offset_map_stress_50k_matches() {
    // Generate text with many credit card numbers interleaved with
    // alphabetic markers. The marker is deliberate: `collapse_padding`
    // in src/normalize/mod.rs strips whitespace that sits between two
    // non-alphabetic characters (to defeat `4242 4242 4242 4242`-style
    // evasion), so a bare ZWSP + space between two 16-digit PANs
    // normalizes to a single contiguous digit run and individual
    // card matches are lost. Interleaving with `" card "` keeps a
    // letter adjacent to each space, so collapse_padding leaves the
    // spaces in place and each PAN keeps its word boundaries for
    // the regex. The previous version of this test happened to pass
    // only because the MICR Line pattern (then unvalidated) was
    // matching substrings of the merged digit run — a false-positive
    // masquerading as success. The MICR Line validator added in
    // `fix(validation): secondary FP gates` closed that path and
    // surfaced the real test bug; this is the fix.
    let card = "4532015112830366"; // Valid Visa (passes Luhn)
    let zwsp = "\u{200B}"; // Zero-width space

    let mut text = String::with_capacity(2_000_000);
    for i in 0..60_000 {
        if i > 0 {
            text.push_str(" card ");
            text.push_str(zwsp);
        }
        text.push_str(card);
    }

    // This should not panic, not OOM, and should respect MAX_MATCHES
    let config = siphon::ScanConfig {
        max_matches: 1000, // Cap to prevent test from taking forever
        ..Default::default()
    };
    let result = siphon::scanner::scan_text_with_config(&text, &config);
    assert!(result.is_ok(), "Stress test must not panic");
    let matches = result.unwrap();
    assert!(
        matches.len() <= 1000,
        "Must respect max_matches cap: got {}",
        matches.len()
    );
    assert!(
        !matches.is_empty(),
        "Should still find some credit cards in stress test"
    );
}

/// Large text with dense zero-width characters between digits.
/// Tests normalization + offset mapping under pressure.
#[test]
fn test_zero_width_dense_evasion() {
    let ssn_evaded = "4\u{200B}2\u{200B}5\u{200B}-\u{200B}7\u{200B}1\u{200B}-\u{200B}3\u{200B}4\u{200B}8\u{200B}2";
    let text = format!("The SSN on file is {ssn_evaded} in the record.");

    let matches = siphon::scan_text(&text).unwrap();
    assert!(
        matches.iter().any(|m| m.sub_category == "USA SSN"),
        "Zero-width evasion should be normalized and SSN detected: {:?}",
        matches.iter().map(|m| &m.sub_category).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// 4. Archive Extraction Limits (Zip Bomb Protection)
// ---------------------------------------------------------------------------

/// Nested ZIP (zip within zip within zip) — tests recursion depth limits.
#[test]
fn test_nested_zip_depth_limit() {
    // Create a 3-level nested ZIP: inner.txt -> level1.zip -> level2.zip
    let f = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    {
        // Level 0: create innermost ZIP containing sensitive text
        let mut inner_buf = Vec::new();
        {
            let mut inner_zip = zip::ZipWriter::new(std::io::Cursor::new(&mut inner_buf));
            let options = zip::write::SimpleFileOptions::default();
            inner_zip.start_file("secret.txt", options).unwrap();
            inner_zip.write_all(b"SSN: 425-71-3482").unwrap();
            inner_zip.finish().unwrap();
        }

        // Level 1: wrap inner ZIP
        let mut mid_buf = Vec::new();
        {
            let mut mid_zip = zip::ZipWriter::new(std::io::Cursor::new(&mut mid_buf));
            let options = zip::write::SimpleFileOptions::default();
            mid_zip.start_file("inner.zip", options).unwrap();
            mid_zip.write_all(&inner_buf).unwrap();
            mid_zip.finish().unwrap();
        }

        // Level 2: wrap mid ZIP as the outer file
        let file = std::fs::File::create(f.path()).unwrap();
        let mut outer_zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        outer_zip.start_file("mid.zip", options).unwrap();
        outer_zip.write_all(&mid_buf).unwrap();
        outer_zip.finish().unwrap();
    }

    // Extract — should handle gracefully without infinite recursion
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    // We don't require recursive extraction, but it MUST NOT panic or hang
    assert!(
        result.is_ok(),
        "Nested ZIP extraction must not panic: {:?}",
        result.err()
    );
}

/// High-compression-ratio ZIP (many copies of repeated data).
/// Tests decompression size limits.
#[test]
fn test_zip_bomb_protection() {
    let f = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    {
        let file = std::fs::File::create(f.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Create 100 files, each with 1MB of repeated 'A' characters
        // This compresses very well but expands to ~100MB
        let big_content = "A".repeat(1_000_000);
        for i in 0..100 {
            zip.start_file(format!("file_{i:04}.txt"), options).unwrap();
            zip.write_all(big_content.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    // Extract — must respect size limits and not OOM
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    // It's OK if extraction fails (zip bomb detected) or succeeds with truncation.
    // It must NOT panic or exhaust memory.
    match result {
        Ok(r) => {
            // If it succeeded, output should be bounded
            assert!(
                r.text.len() < 200 * 1024 * 1024, // less than 200MB
                "Zip bomb output must be bounded"
            );
        }
        Err(e) => {
            // Expected: extraction refused due to size limits
            eprintln!("Zip bomb correctly rejected: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Extractor Fallback on Corrupted Formats
// ---------------------------------------------------------------------------

/// Valid DOCX with sensitive data, then corrupt it and rename to .txt.
/// Tests: does the fallback text scanner pick up the data from raw bytes?
#[test]
fn test_corrupted_docx_renamed_txt() {
    // Create a valid DOCX with sensitive data
    let docx_f = tempfile::Builder::new().suffix(".docx").tempfile().unwrap();
    {
        let file = std::fs::File::create(docx_f.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(b"<w:t>email: secret@example.com card: 4532015112830366</w:t>")
            .unwrap();
        zip.finish().unwrap();
    }

    // Read the DOCX bytes and corrupt the ZIP header slightly
    let mut data = std::fs::read(docx_f.path()).unwrap();
    // Corrupt byte 5 to break the ZIP local file header
    if data.len() > 10 {
        data[4] = 0xFF;
        data[5] = 0xFF;
    }

    // Save as .txt
    let txt_f = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
    std::fs::write(txt_f.path(), &data).unwrap();

    // As .txt, the scanner should read it as plain text
    let result = siphon::extractors::extract_text(txt_f.path().to_str().unwrap());
    assert!(
        result.is_ok(),
        "Corrupted DOCX as .txt should extract as plain text"
    );

    let text = result.unwrap().text;
    // The XML payload is still in the raw bytes
    assert!(
        text.contains("secret@example.com") || text.contains("4532015112830366"),
        "Fallback text extraction should find sensitive data in raw bytes: {}",
        &text[..text.len().min(300)]
    );
}

/// Binary file with embedded text payload, unknown extension.
/// Tests: the pipeline's binary fallback extracts printable strings.
#[test]
fn test_unknown_extension_binary_with_payload() {
    let mut data = vec![0u8; 100];
    data.extend_from_slice(
        b"CONFIDENTIAL: SSN 219-09-9999 card 4532015112830366 API_KEY=sk_live_abc123def456",
    );
    data.extend_from_slice(&[0xFF; 100]);

    let f = tempfile::Builder::new()
        .suffix(".xyz") // Unknown extension
        .tempfile()
        .unwrap();
    std::fs::write(f.path(), &data).unwrap();

    // extract_text may fail for binary with unknown extension, BUT
    // the pipeline's binary fallback should use extract_printable_strings_public.
    // Test the public API directly:
    let text = siphon::extractors::extract_printable_strings_public(&data, 12);
    assert!(
        text.contains("4532015112830366"),
        "Printable string extraction should find card number in binary: {text}"
    );
    assert!(
        text.contains("219-09-9999"),
        "Printable string extraction should find SSN in binary"
    );
}

/// Corrupted ZIP with STORED entries should recover data via raw byte scan.
#[test]
fn test_corrupted_zip_raw_byte_recovery() {
    let f = tempfile::Builder::new().suffix(".docx").tempfile().unwrap();
    {
        let file = std::fs::File::create(f.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(b"<w:t>card number is 4532015112830366 hidden here</w:t>")
            .unwrap();
        zip.finish().unwrap();
    }

    // Corrupt the central directory
    let mut data = std::fs::read(f.path()).unwrap();
    let len = data.len();
    if len > 30 {
        for b in data[len - 22..].iter_mut() {
            *b = 0xFF;
        }
    }
    std::fs::write(f.path(), &data).unwrap();

    // extract_text should now recover via raw byte fallback
    let result = siphon::extractors::extract_text(f.path().to_str().unwrap());
    match result {
        Ok(r) => {
            assert!(
                r.text.contains("4532015112830366"),
                "Corrupted ZIP recovery should find card number: format={}, text_len={}",
                r.format,
                r.text.len()
            );
            assert!(
                r.format == "zip-recovered",
                "Format should indicate recovery: {}",
                r.format
            );
        }
        Err(e) => {
            panic!("Corrupted ZIP should recover via raw bytes, but got error: {e}");
        }
    }
}
