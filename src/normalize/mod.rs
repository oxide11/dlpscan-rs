//! Unicode normalization to defeat evasion attacks.
//!
//! Handles zero-width character stripping, whitespace normalization,
//! homoglyph substitution, and leet-speak decoding.

use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use unicode_normalization::UnicodeNormalization;

/// Zero-width and invisible Unicode characters.
pub static ZERO_WIDTH_CHARS: Lazy<HashSet<char>> = Lazy::new(|| {
    [
        '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}',
        '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}',
        '\u{2064}', '\u{FEFF}', '\u{00AD}', '\u{034F}', '\u{061C}', '\u{180E}', '\u{2066}',
        '\u{2067}', '\u{2068}', '\u{2069}', '\u{FE00}', '\u{FE01}', '\u{FE02}', '\u{FE03}',
        '\u{FE04}', '\u{FE05}', '\u{FE06}', '\u{FE07}', '\u{FE08}', '\u{FE09}', '\u{FE0A}',
        '\u{FE0B}', '\u{FE0C}', '\u{FE0D}', '\u{FE0E}', '\u{FE0F}',
    ]
    .into_iter()
    .collect()
});

/// Exotic Unicode whitespace characters.
pub static UNICODE_SPACES: Lazy<HashSet<char>> = Lazy::new(|| {
    [
        '\u{00A0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200A}', '\u{202F}',
        '\u{205F}', '\u{3000}',
    ]
    .into_iter()
    .collect()
});

/// Leet-speak substitution map.
static LEET_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let pairs = [
        ('@', 'a'),
        ('4', 'a'),
        ('8', 'b'),
        ('(', 'c'),
        ('3', 'e'),
        ('6', 'g'),
        ('#', 'h'),
        ('!', 'i'),
        ('1', 'l'),
        ('0', 'o'),
        ('5', 's'),
        ('7', 't'),
        ('+', 't'),
        ('2', 'z'),
    ];
    pairs.iter().copied().collect()
});

/// Homoglyph substitution map (Cyrillic, Greek, mathematical, etc. → ASCII).
/// Applied AFTER NFKC, so this catches anything NFKC doesn't normalize.
static HOMOGLYPH_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let pairs = [
        // Cyrillic uppercase
        ('\u{0410}', 'A'),
        ('\u{0412}', 'B'),
        ('\u{0421}', 'C'),
        ('\u{0415}', 'E'),
        ('\u{041D}', 'H'),
        ('\u{0406}', 'I'),
        ('\u{0408}', 'J'),
        ('\u{041A}', 'K'),
        ('\u{041C}', 'M'),
        ('\u{041E}', 'O'),
        ('\u{0420}', 'P'),
        ('\u{0405}', 'S'),
        ('\u{0422}', 'T'),
        ('\u{0425}', 'X'),
        ('\u{0417}', 'Z'),
        ('\u{0423}', 'Y'), // Cyrillic У → Y
        ('\u{0401}', 'E'), // Cyrillic Ё → E
        ('\u{040D}', 'I'), // Cyrillic Ѝ → I
        // Cyrillic lowercase
        ('\u{0430}', 'a'),
        ('\u{0435}', 'e'),
        ('\u{0451}', 'e'), // Cyrillic ё → e
        ('\u{0456}', 'i'),
        ('\u{0458}', 'j'),
        ('\u{043E}', 'o'),
        ('\u{0440}', 'p'),
        ('\u{0441}', 'c'),
        ('\u{0443}', 'y'),
        ('\u{0445}', 'x'),
        ('\u{0455}', 's'),
        ('\u{0432}', 'b'), // Cyrillic в → b (visual lookalike in some fonts)
        // Greek uppercase
        ('\u{0391}', 'A'),
        ('\u{0392}', 'B'),
        ('\u{0393}', 'G'),
        ('\u{0395}', 'E'),
        ('\u{0397}', 'H'),
        ('\u{0399}', 'I'),
        ('\u{039A}', 'K'),
        ('\u{039C}', 'M'),
        ('\u{039D}', 'N'),
        ('\u{039F}', 'O'),
        ('\u{03A1}', 'P'),
        ('\u{03A4}', 'T'),
        ('\u{03A5}', 'Y'),
        ('\u{03A7}', 'X'),
        ('\u{0396}', 'Z'),
        // Greek lowercase
        ('\u{03B1}', 'a'),
        ('\u{03B5}', 'e'), // Greek ε (epsilon) → e
        ('\u{03B7}', 'n'), // Greek η (eta) → n (visual lookalike)
        ('\u{03BF}', 'o'),
        ('\u{03B9}', 'i'),
        ('\u{03BA}', 'k'),
        ('\u{03BD}', 'v'),
        ('\u{03C1}', 'p'),
        ('\u{03C3}', 's'), // Greek σ (sigma) → s (visual in some fonts)
        ('\u{03C4}', 't'), // Greek τ (tau) → t (visual lookalike)
        ('\u{03C5}', 'u'),
        ('\u{03C7}', 'x'),
        ('\u{03C9}', 'w'), // Greek ω (omega) → w (visual lookalike)
        // Fullwidth digits (backup — NFKC should handle these)
        ('\u{FF10}', '0'),
        ('\u{FF11}', '1'),
        ('\u{FF12}', '2'),
        ('\u{FF13}', '3'),
        ('\u{FF14}', '4'),
        ('\u{FF15}', '5'),
        ('\u{FF16}', '6'),
        ('\u{FF17}', '7'),
        ('\u{FF18}', '8'),
        ('\u{FF19}', '9'),
        // Fullwidth ASCII letters (backup — NFKC should handle these)
        ('\u{FF21}', 'A'),
        ('\u{FF22}', 'B'),
        ('\u{FF23}', 'C'),
        ('\u{FF24}', 'D'),
        ('\u{FF25}', 'E'),
        ('\u{FF26}', 'F'),
        ('\u{FF27}', 'G'),
        ('\u{FF28}', 'H'),
        ('\u{FF29}', 'I'),
        ('\u{FF2A}', 'J'),
        ('\u{FF2B}', 'K'),
        ('\u{FF2C}', 'L'),
        ('\u{FF2D}', 'M'),
        ('\u{FF2E}', 'N'),
        ('\u{FF2F}', 'O'),
        ('\u{FF30}', 'P'),
        ('\u{FF31}', 'Q'),
        ('\u{FF32}', 'R'),
        ('\u{FF33}', 'S'),
        ('\u{FF34}', 'T'),
        ('\u{FF35}', 'U'),
        ('\u{FF36}', 'V'),
        ('\u{FF37}', 'W'),
        ('\u{FF38}', 'X'),
        ('\u{FF39}', 'Y'),
        ('\u{FF3A}', 'Z'),
        ('\u{FF41}', 'a'),
        ('\u{FF42}', 'b'),
        ('\u{FF43}', 'c'),
        ('\u{FF44}', 'd'),
        ('\u{FF45}', 'e'),
        ('\u{FF46}', 'f'),
        ('\u{FF47}', 'g'),
        ('\u{FF48}', 'h'),
        ('\u{FF49}', 'i'),
        ('\u{FF4A}', 'j'),
        ('\u{FF4B}', 'k'),
        ('\u{FF4C}', 'l'),
        ('\u{FF4D}', 'm'),
        ('\u{FF4E}', 'n'),
        ('\u{FF4F}', 'o'),
        ('\u{FF50}', 'p'),
        ('\u{FF51}', 'q'),
        ('\u{FF52}', 'r'),
        ('\u{FF53}', 's'),
        ('\u{FF54}', 't'),
        ('\u{FF55}', 'u'),
        ('\u{FF56}', 'v'),
        ('\u{FF57}', 'w'),
        ('\u{FF58}', 'x'),
        ('\u{FF59}', 'y'),
        ('\u{FF5A}', 'z'),
        // Fullwidth punctuation commonly used in evasion
        ('\u{FF0D}', '-'),
        ('\u{FF0E}', '.'),
        ('\u{FF20}', '@'),
        ('\u{FF3F}', '_'),
        ('\u{FF0A}', '*'),
        // Mathematical/script homoglyphs (commonly used for evasion)
        ('\u{2070}', '0'),
        ('\u{00B9}', '1'),
        ('\u{00B2}', '2'),
        ('\u{00B3}', '3'),
        // Subscript digits
        ('\u{2080}', '0'),
        ('\u{2081}', '1'),
        ('\u{2082}', '2'),
        ('\u{2083}', '3'),
        ('\u{2084}', '4'),
        ('\u{2085}', '5'),
        ('\u{2086}', '6'),
        ('\u{2087}', '7'),
        ('\u{2088}', '8'),
        ('\u{2089}', '9'),
        // Other common lookalikes
        ('\u{0131}', 'i'), // dotless i
        ('\u{0237}', 'j'), // dotless j
        ('\u{1D00}', 'A'), // small cap A
        ('\u{0299}', 'B'), // small cap B
        ('\u{1D04}', 'C'), // small cap C
        ('\u{1D05}', 'D'), // small cap D
        ('\u{1D07}', 'E'), // small cap E
    ];
    pairs.iter().copied().collect()
});

/// Strip zero-width characters from text.
/// Returns (cleaned_text, offset_map) where offset_map[i] = original position of char i.
pub fn strip_zero_width(text: &str) -> (String, Vec<usize>) {
    // Fast path: check if any zero-width chars exist
    let has_zw = text.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c));
    if !has_zw {
        // Return empty offset_map to signal "no mapping needed" (identity)
        return (text.to_string(), Vec::new());
    }

    let mut result = String::with_capacity(text.len());
    let mut offset_map = Vec::with_capacity(text.len());

    for (byte_idx, ch) in text.char_indices() {
        if !ZERO_WIDTH_CHARS.contains(&ch) {
            result.push(ch);
            // Map each byte of the output char to the original byte index
            for i in 0..ch.len_utf8() {
                offset_map.push(byte_idx + i);
            }
        }
    }

    (result, offset_map)
}

/// Replace exotic Unicode whitespace with ASCII space.
pub fn normalize_whitespace(text: &str) -> String {
    text.chars()
        .map(|c| if UNICODE_SPACES.contains(&c) { ' ' } else { c })
        .collect()
}

/// Replace homoglyph characters with ASCII equivalents (NFKC + explicit map).
pub fn normalize_homoglyphs(text: &str) -> String {
    let nfkc: String = text.nfkc().collect();
    nfkc.chars()
        .map(|c| *HOMOGLYPH_MAP.get(&c).unwrap_or(&c))
        .collect()
}

/// Convert leet-speak back to letters.
pub fn normalize_leet(text: &str) -> String {
    text.chars()
        .map(|c| *LEET_MAP.get(&c).unwrap_or(&c))
        .collect()
}

/// Check if text is pure ASCII (fast path to skip expensive Unicode normalization).
fn is_ascii_only(text: &str) -> bool {
    text.as_bytes().iter().all(|&b| b < 128)
}

// ---------------------------------------------------------------------------
// Evasion-defeating normalization helpers
// ---------------------------------------------------------------------------

/// Get the original byte offset, handling identity mapping (empty offsets = identity).
#[inline]
fn orig_offset(offsets: &[usize], byte_idx: usize) -> usize {
    if offsets.is_empty() || byte_idx >= offsets.len() {
        byte_idx
    } else {
        offsets[byte_idx]
    }
}

/// Convert a hex digit byte to its numeric value.
#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Check if text contains percent-encoding sequences (%XX with hex digits).
fn has_percent_encoding(bytes: &[u8]) -> bool {
    if bytes.len() < 3 {
        return false;
    }
    for i in 0..bytes.len() - 2 {
        if bytes[i] == b'%' && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit()
        {
            return true;
        }
    }
    false
}

/// Single pass of URL percent-decoding (%XX → byte, printable ASCII only).
fn decode_percent_single(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    if !has_percent_encoding(bytes) {
        return (input.to_string(), in_offsets.to_vec());
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                let decoded = (h << 4) | l;
                // Only decode printable ASCII (space through tilde)
                if (0x20..=0x7E).contains(&decoded) {
                    out.push(decoded);
                    offsets.push(orig_offset(in_offsets, i));
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    if out.len() == bytes.len() {
        return (input.to_string(), in_offsets.to_vec());
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Decode URL percent-encoding with double-decode support (%25XX → %XX → char).
fn decode_percent_encoding(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let (first, first_off) = decode_percent_single(input, in_offsets);
    // Second pass catches double-encoding (%2541 → %41 → A)
    decode_percent_single(&first, &first_off)
}

/// Decode HTML numeric character references: decimal `&#NNN;` and hex `&#xHH;`.
fn decode_html_entities(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    if !input.contains("&#") {
        return (input.to_string(), in_offsets.to_vec());
    }

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut offsets = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'&' && i + 2 < bytes.len() && bytes[i + 1] == b'#' {
            let entity_start = i;

            // Try hex: &#xHH; or &#XHH;
            if i + 3 < bytes.len() && (bytes[i + 2] == b'x' || bytes[i + 2] == b'X') {
                let mut j = i + 3;
                while j < bytes.len() && j < i + 12 && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > i + 3 && j < bytes.len() && bytes[j] == b';' {
                    if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 3..j]) {
                        if let Ok(code) = u32::from_str_radix(hex_str, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                let base_offset = orig_offset(in_offsets, entity_start);
                                out.push(ch);
                                for _ in 0..ch.len_utf8() {
                                    offsets.push(base_offset);
                                }
                                i = j + 1;
                                continue;
                            }
                        }
                    }
                }
            }

            // Try decimal: &#NNN;
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 2 && j < bytes.len() && bytes[j] == b';' {
                if let Ok(code) = std::str::from_utf8(&bytes[i + 2..j])
                    .unwrap_or("")
                    .parse::<u32>()
                {
                    if let Some(ch) = char::from_u32(code) {
                        let base_offset = orig_offset(in_offsets, entity_start);
                        out.push(ch);
                        for _ in 0..ch.len_utf8() {
                            offsets.push(base_offset);
                        }
                        i = j + 1;
                        continue;
                    }
                }
            }
        }
        // Not an entity — copy the character preserving UTF-8
        if bytes[i] < 0x80 {
            out.push(bytes[i] as char);
            offsets.push(orig_offset(in_offsets, i));
            i += 1;
        } else {
            let ch = match input[i..].chars().next() {
                Some(c) => c,
                None => break,
            };
            let ch_len = ch.len_utf8();
            out.push(ch);
            for k in 0..ch_len {
                offsets.push(orig_offset(in_offsets, i + k));
            }
            i += ch_len;
        }
    }

    if out.len() == input.len() && out == input {
        return (input.to_string(), in_offsets.to_vec());
    }

    (out, offsets)
}

/// Strip empty CSS comments (`/**/`) and empty HTML comments (`<!---->`) from text.
fn strip_comments(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    if !input.contains("/**/") && !input.contains("<!---->") {
        return (input.to_string(), in_offsets.to_vec());
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        // Check for /**/  (4 bytes)
        if i + 3 < bytes.len() && &bytes[i..i + 4] == b"/**/" {
            i += 4;
            continue;
        }
        // Check for <!---->  (7 bytes)
        if i + 6 < bytes.len() && &bytes[i..i + 7] == b"<!---->" {
            i += 7;
            continue;
        }
        out.push(bytes[i]);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    if out.len() == bytes.len() {
        return (input.to_string(), in_offsets.to_vec());
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Collapse whitespace padding between non-alphabetic characters.
///
/// Removes ASCII whitespace (space, tab, newline, CR) that appears between
/// two non-alphabetic characters (digits, punctuation, symbols). This defeats
/// evasion techniques like `1 2 3 - 4 5 - 6 7 8 9` while preserving natural
/// language spacing like `social security number`.
fn collapse_padding(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    if !bytes
        .iter()
        .any(|&b| b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
    {
        return (input.to_string(), in_offsets.to_vec());
    }

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
            // Find previous non-whitespace byte in output
            let prev_non_ws = out
                .iter()
                .rev()
                .find(|&&c| c != b' ' && c != b'\n' && c != b'\r' && c != b'\t')
                .copied();
            // Find next non-whitespace byte in input
            let next_non_ws = bytes[i + 1..]
                .iter()
                .find(|&&c| c != b' ' && c != b'\n' && c != b'\r' && c != b'\t')
                .copied();

            if let (Some(p), Some(n)) = (prev_non_ws, next_non_ws) {
                if !p.is_ascii_alphabetic() && !n.is_ascii_alphabetic() {
                    i += 1;
                    continue;
                }
            }
        }
        out.push(b);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    if out.len() == bytes.len() {
        return (input.to_string(), in_offsets.to_vec());
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Normalize excessive delimiters between alphanumeric characters.
///
/// Collapses runs of repeated hyphens or dots (e.g. `123--45` → `123-45`)
/// only when surrounded by alphanumeric characters on both sides.
fn normalize_delimiters(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] == b'-' || bytes[i] == b'.' {
            let delim = bytes[i];
            let start = i;
            // Count the delimiter run
            while i + 1 < bytes.len() && bytes[i + 1] == delim {
                i += 1;
            }
            let run_len = (i - start) + 1;

            if run_len > 1 {
                let prev_alnum = !out.is_empty()
                    && out
                        .last()
                        .map(|&b: &u8| b.is_ascii_alphanumeric())
                        .unwrap_or(false);
                let next_alnum = i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphanumeric();

                if prev_alnum && next_alnum {
                    // Collapse to single delimiter
                    out.push(delim);
                    offsets.push(orig_offset(in_offsets, start));
                    changed = true;
                    i += 1;
                    continue;
                }
            }

            // Keep the full delimiter run
            for (j, &b) in bytes.iter().enumerate().take(i + 1).skip(start) {
                out.push(b);
                offsets.push(orig_offset(in_offsets, j));
            }
        } else {
            out.push(bytes[i]);
            offsets.push(orig_offset(in_offsets, i));
        }
        i += 1;
    }

    if !changed {
        return (input.to_string(), in_offsets.to_vec());
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Strip zero-width characters with offset composition.
fn remap_strip_zero_width(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let has_zw = input.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c));
    if !has_zw {
        return (input.to_string(), in_offsets.to_vec());
    }

    let mut result = String::with_capacity(input.len());
    let mut offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        if !ZERO_WIDTH_CHARS.contains(&ch) {
            result.push(ch);
            for i in 0..ch.len_utf8() {
                offsets.push(orig_offset(in_offsets, byte_idx + i));
            }
        }
    }

    (result, offsets)
}

/// Decode hex-spaced byte sequences: `34 35 33 32` → `4532`.
///
/// Heuristic: if the text looks like space-separated pairs of hex digits
/// (at least 3 pairs), decode them to ASCII.
fn decode_hex_spaced(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    // Quick check: need at least "XX XX XX" = 8 chars
    if bytes.len() < 8 {
        return (input.to_string(), in_offsets.to_vec());
    }

    // Scan for runs of hex-space-hex patterns
    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        // Try to match a hex-spaced run: XX SP XX SP XX ...
        if i + 4 < bytes.len()
            && bytes[i].is_ascii_hexdigit()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2] == b' '
            && bytes[i + 3].is_ascii_hexdigit()
            && bytes[i + 4].is_ascii_hexdigit()
        {
            // Count how many hex pairs follow
            let run_start = i;
            let mut pairs = Vec::new();
            loop {
                if i + 1 < bytes.len()
                    && bytes[i].is_ascii_hexdigit()
                    && bytes[i + 1].is_ascii_hexdigit()
                {
                    if let (Some(h), Some(l)) = (hex_val(bytes[i]), hex_val(bytes[i + 1])) {
                        pairs.push((i, (h << 4) | l));
                    }
                    i += 2;
                    // Require a mandatory space between consecutive pairs.
                    // The whole point of hex-spaced encoding is that pairs
                    // are separated by whitespace; without this guard the
                    // loop greedily consumes a display-formatted number
                    // like "4242 4242 4242 4242" as 8 back-to-back pairs
                    // (treating each group of 4 digits as two 2-char
                    // pairs), producing "BBBBBBBB" and destroying the
                    // card number before the credit-card regex ever sees
                    // it. End of input is also a valid run terminator.
                    if i < bytes.len() && bytes[i] == b' ' {
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            // Only decode if we got at least 3 pairs and all produce printable ASCII
            if pairs.len() >= 3 && pairs.iter().all(|(_, v)| *v >= 0x20 && *v <= 0x7E) {
                for &(pair_pos, val) in &pairs {
                    out.push(val);
                    offsets.push(orig_offset(in_offsets, pair_pos));
                }
                changed = true;
                continue;
            }
            // Not a valid hex run, rewind and copy literally
            i = run_start;
        }
        out.push(bytes[i]);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    if !changed {
        return (input.to_string(), in_offsets.to_vec());
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Decode `\xHH` hex-escape sequences (e.g. `\x31\x32\x33` → `123`).
///
/// Only replaces sequences where both digits are valid hex and the decoded byte
/// is printable ASCII (0x20–0x7E). Other sequences are passed through unchanged.
fn decode_hex_escapes(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    if !bytes.windows(2).any(|w| w[0] == b'\\' && w[1] == b'x') {
        return (input.to_string(), in_offsets.to_vec());
    }

    let mut out = String::with_capacity(input.len());
    let mut offsets: Vec<usize> = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                let decoded = (hi << 4) | lo;
                if (0x20..=0x7E).contains(&decoded) {
                    out.push(decoded as char);
                    offsets.push(orig_offset(in_offsets, i));
                    i += 4;
                    continue;
                }
            }
        }
        // Emit one byte (preserving multi-byte UTF-8 chars where possible).
        out.push(bytes[i] as char);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    (out, offsets)
}

// ---------------------------------------------------------------------------
// Stage 4c: Token-level base64 decode
// ---------------------------------------------------------------------------

/// Check if a byte is in the standard base64 alphabet (A-Z, a-z, 0-9, +, /).
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Try to decode a base64 token to bytes, handling both padded and unpadded
/// forms. Returns `None` if the token isn't valid base64.
fn try_base64_decode_bytes(token: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};
    // Try standard decode (requires valid padding).
    if let Ok(bytes) = general_purpose::STANDARD.decode(token) {
        return Some(bytes);
    }
    // If the token lacks padding, add it and retry.
    let padded = match token.len() % 4 {
        2 => format!("{token}=="),
        3 => format!("{token}="),
        _ => return None, // len % 4 == 1 is structurally invalid base64
    };
    general_purpose::STANDARD.decode(&padded).ok()
}

/// Try to decode a base64 token to a printable UTF-8 string. Returns `None`
/// if the token isn't valid base64, or if the decoded bytes aren't valid
/// UTF-8, or if fewer than 50% of the decoded bytes are printable ASCII.
///
/// The 50% printable gate is the main defense against false decoding:
/// English words that happen to be valid base64 alphabet
/// (`INTERNATIONALIZATION`, `DOCUMENTATION`) decode to binary garbage,
/// and the gate rejects them.
fn try_base64_decode(token: &str) -> Option<String> {
    let decoded_bytes = try_base64_decode_bytes(token)?;
    let decoded_str = std::str::from_utf8(&decoded_bytes).ok()?;
    // Gate: at least 50% of decoded bytes must be printable ASCII
    // (0x20..=0x7E) or common whitespace.
    let printable = decoded_str
        .bytes()
        .filter(|&b| (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    if decoded_str.is_empty() || printable * 2 < decoded_str.len() {
        return None;
    }
    // Gate: decoded result must be non-trivial (not just whitespace).
    if decoded_str.trim().len() < 4 {
        return None;
    }
    Some(decoded_str.to_string())
}

/// Scan the text for tokens that look like base64-encoded data, decode each
/// one, and if the decoded result is valid printable UTF-8, replace the
/// token inline. Maintains the offset map so match spans in the output
/// point back to the start of the original base64 token.
///
/// Token detection: a maximal run of base64-alphabet characters (A-Za-z0-9+/)
/// followed by optional `=` padding. The run must be at least 12 characters
/// — shorter tokens have too little entropy for the UTF-8/printable gate to
/// distinguish real encoded data from English words that happen to be
/// base64-alphabet. 12 chars is the sweet spot: an encoded 9-byte value
/// (like a short SSN `123-45-6789` without separators) is exactly 12 chars
/// of base64, so we catch the smallest realistic evasion payload.
fn decode_base64_tokens(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets: Vec<usize> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if is_base64_char(bytes[i]) {
            // Find the end of the base64-alphabet run.
            let start = i;
            while i < bytes.len() && is_base64_char(bytes[i]) {
                i += 1;
            }
            // Include trailing `=` padding.
            while i < bytes.len() && bytes[i] == b'=' {
                i += 1;
            }
            let token = &input[start..i];

            // Skip tokens that are part of a dot-delimited structure
            // (JWTs, OAuth tokens, X.509 certs). These use base64 as
            // their canonical wire format — decoding would corrupt the
            // pattern match (e.g., JWT header `eyJhbGci...` → `{"alg":...}`
            // which breaks the JWT regex). The heuristic: if the byte
            // immediately before or after the token is `.`, it's likely
            // a segment in a dot-delimited protocol element.
            let prev_is_dot = start > 0 && bytes[start - 1] == b'.';
            let next_is_dot = i < bytes.len() && bytes[i] == b'.';
            if prev_is_dot || next_is_dot {
                for j in start..i {
                    out.push(bytes[j]);
                    offsets.push(orig_offset(in_offsets, j));
                }
                continue;
            }

            // Only attempt decode on sufficiently long tokens.
            if token.len() >= 12 {
                if let Some(decoded) = try_base64_decode(token) {
                    // Replace the token with the decoded text. All decoded
                    // bytes inherit the offset of the first byte of the
                    // source token — this means the match span in the
                    // scanner's output will point to the START of the
                    // base64 token in the original input, which is the
                    // right behaviour for redaction (you'd redact the
                    // whole encoded token).
                    let token_orig = orig_offset(in_offsets, start);
                    for b in decoded.bytes() {
                        out.push(b);
                        offsets.push(token_orig);
                    }
                    changed = true;
                    continue;
                }
            }

            // Token wasn't decoded — emit the original bytes unchanged.
            for j in start..i {
                out.push(bytes[j]);
                offsets.push(orig_offset(in_offsets, j));
            }
        } else {
            out.push(bytes[i]);
            offsets.push(orig_offset(in_offsets, i));
            i += 1;
        }
    }

    if !changed {
        return (input.to_string(), in_offsets.to_vec());
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Standard base32 alphabet (RFC 4648).
const BASE32_ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode a base32 string to bytes. Returns None if invalid.
fn base32_decode_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let mut val_map = [255u8; 256];
    for (i, &c) in BASE32_ALPHA.iter().enumerate() {
        val_map[c as usize] = i as u8;
        val_map[c.to_ascii_lowercase() as usize] = i as u8;
    }

    // Strip padding
    let trimmed: Vec<u8> = input.iter().copied().filter(|&b| b != b'=').collect();
    if trimmed.is_empty() {
        return None;
    }
    // All chars must be valid base32
    if trimmed.iter().any(|&b| val_map[b as usize] == 255) {
        return None;
    }

    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut result = Vec::new();

    for &b in &trimmed {
        bits = (bits << 5) | val_map[b as usize] as u64;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Some(result)
}

/// Try to detect and decode base32/base64 encoded content.
///
/// Heuristic: if the entire input (after trimming whitespace) looks like
/// base32 or base64, try decoding and check if the result is printable ASCII.
fn try_decode_base_encoding(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let trimmed = input.trim();
    let tbytes = trimmed.as_bytes();

    // Must be at least 8 chars and look like an encoded string
    if tbytes.len() < 8 {
        return (input.to_string(), in_offsets.to_vec());
    }

    // Try base64 first (more common)
    let is_b64 = tbytes.iter().all(|&b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    });
    if is_b64 {
        // Standard base64
        if let Some(decoded) = base64_decode_bytes(tbytes) {
            if decoded.len() >= 3 && decoded.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                let decoded_str = String::from_utf8_lossy(&decoded);
                let base_offset = orig_offset(in_offsets, input.find(trimmed).unwrap_or(0));
                let mut new_offsets = Vec::with_capacity(decoded.len());
                for _ in 0..decoded_str.len() {
                    new_offsets.push(base_offset);
                }
                return (decoded_str.into_owned(), new_offsets);
            }
        }
    }

    // Try base32
    let is_b32 = tbytes.iter().all(|&b| {
        (b.is_ascii_alphanumeric() && !(b == b'0' || b == b'1' || b == b'8' || b == b'9'))
            || b == b'='
    });
    if is_b32 && tbytes.len() >= 10 {
        if let Some(decoded) = base32_decode_bytes(tbytes) {
            if decoded.len() >= 3 && decoded.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                let decoded_str = String::from_utf8_lossy(&decoded);
                let base_offset = orig_offset(in_offsets, input.find(trimmed).unwrap_or(0));
                let mut new_offsets = Vec::with_capacity(decoded.len());
                for _ in 0..decoded_str.len() {
                    new_offsets.push(base_offset);
                }
                return (decoded_str.into_owned(), new_offsets);
            }
        }
    }

    (input.to_string(), in_offsets.to_vec())
}

/// Simple base64 decoder (standard + URL-safe alphabets).
fn base64_decode_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let mut val_map = [255u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        val_map[c as usize] = i as u8;
    }
    // URL-safe variants
    val_map[b'-' as usize] = 62;
    val_map[b'_' as usize] = 63;

    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&b| b != b'=' && b != b'\n' && b != b'\r')
        .collect();
    if trimmed.is_empty() || trimmed.iter().any(|&b| val_map[b as usize] == 255) {
        return None;
    }

    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut result = Vec::new();

    for &b in &trimmed {
        bits = (bits << 6) | val_map[b as usize] as u64;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Some(result)
}

/// Morse code lookup table: morse pattern → ASCII character.
static MORSE_TABLE: Lazy<HashMap<&'static str, char>> = Lazy::new(|| {
    [
        // Letters
        (".-", 'A'),
        ("-...", 'B'),
        ("-.-.", 'C'),
        ("-..", 'D'),
        (".", 'E'),
        ("..-.", 'F'),
        ("--.", 'G'),
        ("....", 'H'),
        ("..", 'I'),
        (".---", 'J'),
        ("-.-", 'K'),
        (".-..", 'L'),
        ("--", 'M'),
        ("-.", 'N'),
        ("---", 'O'),
        (".--.", 'P'),
        ("--.-", 'Q'),
        (".-.", 'R'),
        ("...", 'S'),
        ("-", 'T'),
        ("..-", 'U'),
        ("...-", 'V'),
        (".--", 'W'),
        ("-..-", 'X'),
        ("-.--", 'Y'),
        ("--..", 'Z'),
        // Digits
        ("-----", '0'),
        (".----", '1'),
        ("..---", '2'),
        ("...--", '3'),
        ("....-", '4'),
        (".....", '5'),
        ("-....", '6'),
        ("--...", '7'),
        ("---..", '8'),
        ("----.", '9'),
        // Common punctuation
        (".-.-.-", '.'),
        ("--..--", ','),
        ("..--..", '?'),
        ("-....-", '-'),
        (".--.-.", '@'),
        ("---...", ':'),
    ]
    .into_iter()
    .collect()
});

/// Decode morse code text to plaintext.
///
/// Expects characters separated by spaces and words separated by `/`, `|`, or
/// 3+ spaces. Returns None if the input doesn't look like valid morse code.
fn decode_morse(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.len() < 3 {
        return None;
    }

    // Quick check: morse code only contains '.', '-', ' ', '/', '|'
    if !trimmed
        .bytes()
        .all(|b| b == b'.' || b == b'-' || b == b' ' || b == b'/' || b == b'|')
    {
        return None;
    }

    // Must have at least one dot or dash
    if !trimmed.bytes().any(|b| b == b'.' || b == b'-') {
        return None;
    }

    // Split into words (separated by / or |), then chars (separated by space)
    let mut result = String::new();
    let words: Vec<&str> = if trimmed.contains('/') {
        trimmed.split('/').collect()
    } else if trimmed.contains('|') {
        trimmed.split('|').collect()
    } else {
        // Try splitting on 3+ spaces for word boundaries
        trimmed.split("   ").collect()
    };

    let mut decoded_count = 0;
    let mut total_symbols = 0;

    for (wi, word) in words.iter().enumerate() {
        if wi > 0 {
            result.push(' ');
        }
        let chars: Vec<&str> = word.trim().split(' ').filter(|s| !s.is_empty()).collect();
        for symbol in &chars {
            total_symbols += 1;
            if let Some(&ch) = MORSE_TABLE.get(symbol) {
                result.push(ch);
                decoded_count += 1;
            } else {
                return None; // Invalid morse symbol → not morse code
            }
        }
    }

    // Require at least 3 decoded symbols to avoid false positives
    if decoded_count < 3 || total_symbols < 3 {
        return None;
    }

    Some(result)
}

/// Apply ROT13 transformation to alphabetic characters.
fn apply_rot13(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    // Only apply if text has letters (no point on pure digits)
    if !bytes.iter().any(|b| b.is_ascii_alphabetic()) {
        return (input.to_string(), in_offsets.to_vec());
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());

    for (i, &b) in bytes.iter().enumerate() {
        let decoded = match b {
            b'A'..=b'M' | b'a'..=b'm' => b + 13,
            b'N'..=b'Z' | b'n'..=b'z' => b - 13,
            _ => b,
        };
        out.push(decoded);
        offsets.push(orig_offset(in_offsets, i));
    }

    (String::from_utf8_lossy(&out).into_owned(), offsets)
}

/// Full normalization pipeline with accurate byte-level offset tracking.
///
/// Pipeline:
///   1. URL percent-decode (double-decode for %25XX)
///   2. HTML decimal entity decode (&#NNN;)
///   3. Strip empty CSS/HTML comments
///   4. Collapse whitespace padding between non-alpha chars
///   5. Normalize excessive delimiters
///   6. Decode hex-spaced byte sequences
///   7. Strip zero-width Unicode characters
///   8. Normalize exotic Unicode whitespace
///   9. NFKC normalization
///  10. Homoglyph map (Cyrillic/Greek → ASCII)
///
/// The returned offset_map maps each byte index in the normalized output back
/// to the corresponding byte index in the original input. Empty offset_map
/// means identity mapping (nothing changed).
pub fn normalize_text(text: &str) -> (String, Vec<usize>) {
    // Fast path: pure ASCII with no evasion markers
    let ascii = is_ascii_only(text);
    if ascii && !has_evasion_markers(text) {
        return (text.to_string(), Vec::new());
    }

    let mut current = text.to_string();
    let mut offsets: Vec<usize> = Vec::new(); // empty = identity mapping

    // Helper macro: only call a stage if its quick-check would pass,
    // avoiding the allocation of (String, Vec) on the no-change path.
    macro_rules! apply_stage {
        ($fn:ident, $current:expr, $offsets:expr) => {{
            let r = $fn(&$current, &$offsets);
            $current = r.0;
            $offsets = r.1;
        }};
    }

    // Stage 1: URL percent-decode (two passes for double encoding)
    if current.contains('%') {
        apply_stage!(decode_percent_encoding, current, offsets);
    }

    // Stage 2: HTML decimal entity decode
    if current.contains("&#") {
        apply_stage!(decode_html_entities, current, offsets);
    }

    // Stage 3: Strip empty CSS/HTML comments
    if current.contains("/**/") || current.contains("<!---->") {
        apply_stage!(strip_comments, current, offsets);
    }

    // Stage 4: Decode hex-spaced byte sequences
    if current.len() >= 8 {
        apply_stage!(decode_hex_spaced, current, offsets);
    }

    // Stage 4b: Decode \xHH hex-escape sequences
    let r = decode_hex_escapes(&current, &offsets);
    current = r.0;
    offsets = r.1;

    // Stage 4c: Token-level base64 decode
    //
    // Find tokens that look like base64-encoded data (standard alphabet,
    // ≥ 16 chars, optional `=` padding), decode each one, and if the
    // decoded bytes are valid UTF-8 printable text, replace the token
    // inline. This runs BEFORE collapse_padding so the decoded result
    // gets the same whitespace/delimiter normalization as everything else.
    //
    // The primary scan then sees the decoded plaintext — every regex
    // pattern (not just always-run) gets a chance to match the decoded
    // content, and context keywords near the decoded value fire normally.
    //
    // This replaces the "decode entire text as base64" approach that
    // Stage H used, which only ran on small/clean documents and skipped
    // context checking entirely.
    {
        let r = decode_base64_tokens(&current, &offsets);
        current = r.0;
        offsets = r.1;
    }

    // Stage 5: Collapse whitespace padding between non-alpha chars
    if current
        .as_bytes()
        .iter()
        .any(|&b| b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
    {
        apply_stage!(collapse_padding, current, offsets);
    }

    // Stage 6: Normalize excessive delimiters
    apply_stage!(normalize_delimiters, current, offsets);

    // Stages 7-10: Unicode normalization (only if non-ASCII remaining)
    if !is_ascii_only(&current) {
        // Stage 7: Strip zero-width characters
        let r = remap_strip_zero_width(&current, &offsets);
        current = r.0;
        offsets = r.1;

        // Stage 8: Normalize exotic whitespace
        let r = remap_char_transform(&current, &offsets, |c| {
            if UNICODE_SPACES.contains(&c) {
                ' '
            } else {
                c
            }
        });
        current = r.0;
        offsets = r.1;

        // Stage 9: NFKC normalization
        let r = remap_nfkc(&current, &offsets);
        current = r.0;
        offsets = r.1;

        // Stage 10: Homoglyph map
        let r = remap_char_transform(&current, &offsets, |c| *HOMOGLYPH_MAP.get(&c).unwrap_or(&c));
        current = r.0;
        offsets = r.1;
    }

    // If nothing changed, return empty offsets (identity)
    if current == text {
        return (current, Vec::new());
    }

    (current, offsets)
}

/// Maximum input size (bytes) for which alternative decodings are
/// generated. Above this threshold the second-pass evasion defense is
/// skipped entirely — the cost of producing five full copies of the
/// input outweighs the marginal detection benefit on large documents,
/// and it opens a clear memory-amplification vector for adversarial
/// payloads.
pub const MAX_ALTERNATIVE_DECODING_INPUT: usize = 16 * 1024;

/// Hard cap on the total number of bytes across all alternative
/// decodings for a single call. Even with the per-input gate above, a
/// well-formed payload under the limit can still multiply into several
/// full-size copies; this budget stops accumulation once we hit it.
pub const MAX_ALTERNATIVE_DECODING_TOTAL: usize = 64 * 1024;

/// Extended normalization: tries additional decodings (base32/64, ROT13, reversal).
///
/// Called by the scanner as a second pass when standard normalization didn't
/// produce matches. Each variant is returned for separate scanning.
///
/// Hardening: skip entirely for inputs larger than
/// [`MAX_ALTERNATIVE_DECODING_INPUT`] and stop accumulating once the
/// combined size of the produced alternatives exceeds
/// [`MAX_ALTERNATIVE_DECODING_TOTAL`]. Both limits are generous enough
/// to cover the short-document case the second pass is designed for
/// (a few KB) while refusing to multiply an attacker-controlled blob
/// into N full copies in memory.
pub fn generate_alternative_decodings(text: &str) -> Vec<String> {
    if text.len() > MAX_ALTERNATIVE_DECODING_INPUT {
        return Vec::new();
    }

    let mut alternatives = Vec::new();
    let mut total_bytes: usize = 0;

    // Helper: push if distinct from input AND within the output budget.
    let push_if_room = |alt: String, alternatives: &mut Vec<String>, total: &mut usize| {
        if alt.is_empty() || alt == text {
            return;
        }
        if *total + alt.len() > MAX_ALTERNATIVE_DECODING_TOTAL {
            return;
        }
        *total += alt.len();
        alternatives.push(alt);
    };

    // Try base32/base64 decode
    let (decoded, _) = try_decode_base_encoding(text, &[]);
    push_if_room(decoded, &mut alternatives, &mut total_bytes);

    // Try ROT13
    let (rot, _) = apply_rot13(text, &[]);
    push_if_room(rot, &mut alternatives, &mut total_bytes);

    // NOTE: a reverse-text transformation used to live here, based
    // on the assumption that an adversary might write their data
    // backwards to evade detection. In practice that's not a
    // realistic evasion technique — real adversaries use encoding,
    // homoglyphs, zero-width injection, or splitting across
    // boundaries, not string reversal. The reversed transformation
    // was producing concrete false positives against high-specificity
    // patterns whose regexes happened to match natural-text reversed
    // fragments: the detection-quality harness caught two of these
    //
    //   * `Geohash` matched the reversed substring of French
    //     "serveur" ("ruevres"), silently firing as a positive in
    //     an unrelated doc.
    //   * `Bitcoin Cash Address` matched the reversal of a legitimate
    //     bech32 address (`qdm5fwzztg95er9wndyl346l5yvkfx7rrrs0raq1cb`),
    //     and because its specificity was higher than the broken
    //     Bitcoin Bech32 entry in `pattern_specificity`, it won dedup
    //     and dropped the real Bech32 detection on the floor.
    //
    // Both cases were symptoms of the same underlying architectural
    // mismatch: the "signal" from a reversed-text match is zero (no
    // real attacker is writing SSNs backwards) but the "noise" is
    // continuous, because natural text has many substrings whose
    // reversal incidentally matches a detection regex. Removing the
    // reverse transformation closes the whole class of bug.

    // Try leetspeak decode (only useful for alpha-based patterns like email)
    let leet_decoded = normalize_leet(text);
    push_if_room(leet_decoded, &mut alternatives, &mut total_bytes);

    // Try morse code decode
    if let Some(decoded) = decode_morse(text) {
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    alternatives
}

/// Check if ASCII text contains patterns that suggest encoding-based evasion.
fn has_evasion_markers(text: &str) -> bool {
    let bytes = text.as_bytes();
    // Percent-encoding: %XX
    if has_percent_encoding(bytes) {
        return true;
    }
    // HTML entities
    if text.contains("&#") {
        return true;
    }
    // Empty comments (evasion-specific)
    if text.contains("/**/") || text.contains("<!---->") {
        return true;
    }
    // Whitespace run between non-alpha chars (handles padding and multi-byte \r\n)
    {
        let mut prev_non_ws: Option<u8> = None;
        let mut in_ws_run = false;
        for &b in bytes {
            if is_ascii_ws(b) {
                in_ws_run = true;
            } else {
                if in_ws_run {
                    if let Some(p) = prev_non_ws {
                        if !p.is_ascii_alphabetic() && !b.is_ascii_alphabetic() {
                            return true;
                        }
                    }
                }
                in_ws_run = false;
                prev_non_ws = Some(b);
            }
        }
    }
    // Excessive delimiters between alphanumeric chars
    if bytes.len() >= 4 {
        for w in bytes.windows(4) {
            if w[0].is_ascii_alphanumeric()
                && (w[1] == b'-' || w[1] == b'.')
                && w[2] == w[1]
                && w[3].is_ascii_alphanumeric()
            {
                return true;
            }
        }
    }
    // Hex-spaced bytes: "XX XX XX" pattern
    if bytes.len() >= 8 {
        for w in bytes.windows(5) {
            if w[0].is_ascii_hexdigit()
                && w[1].is_ascii_hexdigit()
                && w[2] == b' '
                && w[3].is_ascii_hexdigit()
                && w[4].is_ascii_hexdigit()
            {
                return true;
            }
        }
    }
    // \xHH hex-escape sequences
    if bytes.windows(2).any(|w| w[0] == b'\\' && w[1] == b'x') {
        return true;
    }
    // Base64-encoded tokens: a run of ≥16 base64-alphabet characters
    // (optionally followed by `=` padding). This is a cheap linear
    // scan that gates the more expensive `decode_base64_tokens` stage.
    {
        let mut run_len = 0usize;
        for &b in bytes {
            if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' {
                run_len += 1;
            } else if b == b'=' && run_len >= 12 {
                // Trailing `=` after a 12+ char base64 run — likely
                // padded base64. The actual decode threshold (16 chars
                // including padding) is enforced in decode_base64_tokens;
                // this gate just needs to be permissive enough to enter
                // the normalization pipeline.
                return true;
            } else {
                if run_len >= 12 {
                    return true;
                }
                run_len = 0;
            }
        }
        if run_len >= 12 {
            return true;
        }
    }
    false
}

#[inline]
fn is_ascii_ws(b: u8) -> bool {
    b == b' ' || b == b'\n' || b == b'\r' || b == b'\t'
}

/// Apply a 1-char → 1-char transform while maintaining byte-level offset map.
/// The transform function maps each input char to exactly one output char.
fn remap_char_transform(
    input: &str,
    input_offsets: &[usize],
    transform: impl Fn(char) -> char,
) -> (String, Vec<usize>) {
    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        let replacement = transform(ch);
        output.push(replacement);

        // The original offset for this input char's first byte
        let orig_start = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            byte_idx
        };

        // Map each byte of the output char to the original offset
        for _ in 0..replacement.len_utf8() {
            output_offsets.push(orig_start);
        }
    }

    (output, output_offsets)
}

/// Apply NFKC normalization while maintaining byte-level offset map.
/// NFKC can expand or contract characters (e.g., fullwidth '０' → '0',
/// ligature 'ﬁ' → 'fi'). Each output char inherits the original byte offset
/// of the input char that produced it.
fn remap_nfkc(input: &str, input_offsets: &[usize]) -> (String, Vec<usize>) {
    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        // The original offset for this input char
        let orig_offset = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            byte_idx
        };

        // NFKC decompose this single character
        let nfkc_chars: String = std::iter::once(ch).nfkc().collect();
        for nfkc_ch in nfkc_chars.chars() {
            output.push(nfkc_ch);
            for _ in 0..nfkc_ch.len_utf8() {
                output_offsets.push(orig_offset);
            }
        }
    }

    (output, output_offsets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_zero_width_no_change() {
        let (result, _) = strip_zero_width("hello world");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_strip_zero_width_removes_chars() {
        let input = "he\u{200B}llo";
        let (result, offsets) = strip_zero_width(input);
        assert_eq!(result, "hello");
        assert!(!offsets.is_empty());
    }

    #[test]
    fn test_normalize_whitespace() {
        let input = "hello\u{00A0}world";
        assert_eq!(normalize_whitespace(input), "hello world");
    }

    #[test]
    fn test_normalize_leet() {
        assert_eq!(normalize_leet("h3ll0"), "hello");
    }

    #[test]
    fn test_base64_token_decode_ssn() {
        // "123-45-6789" base64-encoded = "MTIzLTQ1LTY3ODk="
        let input = "config ssn = MTIzLTQ1LTY3ODk= end";
        let (result, _offsets) = normalize_text(input);
        assert!(
            result.contains("123-45-6789"),
            "base64-encoded SSN should be decoded inline. Got: {result:?}"
        );
    }

    #[test]
    fn test_base64_token_decode_credit_card() {
        // "4532015112830366" base64-encoded = "NDUzMjAxNTExMjgzMDM2Ng=="
        let input = "card NDUzMjAxNTExMjgzMDM2Ng== stored";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("4532015112830366"),
            "base64-encoded card should be decoded. Got: {result:?}"
        );
    }

    #[test]
    fn test_base64_token_decode_unpadded() {
        // "123-45-6789" without padding = "MTIzLTQ1LTY3ODk" (no trailing =)
        let input = "data MTIzLTQ1LTY3ODk here";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("123-45-6789"),
            "unpadded base64 should also decode. Got: {result:?}"
        );
    }

    #[test]
    fn test_base64_token_decode_preserves_non_base64() {
        // Short tokens (< 16 chars) should not be decoded.
        let input = "The word HELLO is not base64 decoded";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("HELLO"),
            "short token should be preserved. Got: {result:?}"
        );
    }

    #[test]
    fn test_base64_token_decode_rejects_binary() {
        // A 20-char base64-alphabet string that decodes to binary
        // garbage (not valid UTF-8 or not printable).
        // "AAAAAAAAAAAAAAAAAAAAAA==" decodes to 16 zero bytes → not printable
        let input = "blob AAAAAAAAAAAAAAAAAAAAAA== end";
        let (result, _) = normalize_text(input);
        // The token should NOT be replaced with decoded content
        // (decoded bytes are all-zero, fail the printable gate).
        assert!(
            !result.contains("\0"),
            "binary decode should be rejected. Got: {result:?}"
        );
    }

    #[test]
    fn test_base64_token_decode_offset_map() {
        // Verify the offset map points decoded bytes back to the
        // original token position.
        let input = "prefix MTIzLTQ1LTY3ODk= suffix";
        let (result, offsets) = normalize_text(input);
        assert!(result.contains("123-45-6789"));
        // The decoded SSN starts where "MTIz..." started in the original
        let decoded_start = result.find("123-45-6789").unwrap();
        let original_token_start = input.find("MTIz").unwrap();
        if !offsets.is_empty() {
            assert_eq!(
                offsets[decoded_start], original_token_start,
                "offset map should point decoded bytes to the original token start"
            );
        }
    }

    #[test]
    fn test_normalize_homoglyphs() {
        // Cyrillic 'а' (U+0430) → ASCII 'a'
        let input = "\u{0430}bc";
        let result = normalize_homoglyphs(input);
        assert_eq!(result, "abc");
    }

    #[test]
    fn test_fullwidth_digits_normalized() {
        // Fullwidth digits ０１２３ should normalize to 0123
        let input = "\u{FF10}\u{FF11}\u{FF12}\u{FF13}";
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "0123");
        assert!(!offsets.is_empty());
        // Verify offset map points back to original positions
        assert_eq!(offsets[0], 0); // '0' maps to byte 0 of original ０
    }

    #[test]
    fn test_fullwidth_letters_normalized() {
        // Fullwidth Ａ Ｂ Ｃ should normalize to ABC
        let input = "\u{FF21}\u{FF22}\u{FF23}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "ABC");
    }

    #[test]
    fn test_cyrillic_homoglyphs_normalized() {
        // Cyrillic а е о should normalize to a e o
        let input = "\u{0430}\u{0435}\u{043E}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "aeo");
    }

    #[test]
    fn test_mixed_unicode_evasion() {
        // SSN with fullwidth digits: １２３-４５-６７８９
        let input = "\u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19}";
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "123-45-6789");
        assert!(!offsets.is_empty());
    }

    #[test]
    fn test_offset_map_accuracy_multibyte() {
        // Zero-width char followed by fullwidth digit
        let input = "\u{200B}\u{FF10}"; // ZW + fullwidth 0
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "0");
        // The '0' should map back to byte offset of ０ in original (byte 3, after 3-byte ZW)
        assert_eq!(offsets[0], 3);
    }

    #[test]
    fn test_normalize_text_ascii_fast_path() {
        let (result, offsets) = normalize_text("hello world");
        assert_eq!(result, "hello world");
        assert!(offsets.is_empty()); // Empty = identity mapping
    }

    // === Evasion normalization tests ===

    #[test]
    fn test_percent_decode_ssn() {
        let (result, _) = normalize_text("%31%32%33-%34%35-%36%37%38%39");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_percent_decode_digits_only() {
        // url_percent_encoding_digits: only digits encoded
        let (result, _) = normalize_text("%34532-%30151-%31283");
        assert_eq!(result, "4532-0151-1283");
    }

    #[test]
    fn test_percent_decode_full() {
        // url_percent_encoding_full: everything encoded
        let (result, _) = normalize_text("%34%35%33%32%2D%30%31%35%31");
        assert_eq!(result, "4532-0151");
    }

    #[test]
    fn test_double_percent_decode() {
        // %25 decodes to %, then %31 decodes to 1
        let (result, _) = normalize_text("%2531%2532%2533");
        assert_eq!(result, "123");
    }

    #[test]
    fn test_html_entity_decode_ssn() {
        let (result, _) = normalize_text("&#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_html_entity_decode_mixed() {
        // Some chars encoded, some plain
        let (result, _) = normalize_text("1&#50;3-&#52;5-6&#55;89");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_html_entity_hex() {
        // &#x31;&#x32;&#x33; → 123
        let (result, _) = normalize_text("&#x31;&#x32;&#x33;");
        assert_eq!(result, "123");
    }

    #[test]
    fn test_html_entity_hex_uppercase() {
        let (result, _) = normalize_text("&#X41;&#X42;&#X43;");
        assert_eq!(result, "ABC");
    }

    #[test]
    fn test_css_comment_strip() {
        let (result, _) = normalize_text("1/**/2/**/3/**/-/**/4/**/5/**/-/**/6/**/7/**/8/**/9");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_html_comment_strip() {
        let (result, _) =
            normalize_text("1<!---->2<!---->3<!---->-<!---->4<!---->5<!---->-<!---->6789");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_whitespace_padding_digits() {
        let (result, _) = normalize_text("1 2 3 - 4 5 - 6 7 8 9");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_whitespace_padding_preserves_words() {
        // Spaces between alphabetic chars should be preserved
        let (result, _) = normalize_text("social security number: 1 2 3");
        assert_eq!(result, "social security number:123");
    }

    #[test]
    fn test_mid_line_break() {
        let (result, _) = normalize_text("123-45-\n6789");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_mid_line_break_crlf() {
        let (result, _) = normalize_text("123-45-\r\n6789");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_excessive_delimiter() {
        let (result, _) = normalize_text("123--45--6789");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_excessive_dots() {
        let (result, _) = normalize_text("192..168..1..1");
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_excessive_delimiter_preserves_cli_flags() {
        // --verbose should not be collapsed (no alnum before --)
        let (result, _) = normalize_text("--verbose");
        assert_eq!(result, "--verbose");
    }

    #[test]
    fn test_combined_evasion_percent_and_padding() {
        // Percent-encoded digits with spaces
        let (result, _) = normalize_text("%31 %32 %33 - %34 %35 - %36 %37 %38 %39");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_offset_tracking_percent_decode() {
        let input = "%41%42C";
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "ABC");
        // 'A' from %41 at byte 0, 'B' from %42 at byte 3, 'C' at byte 6
        assert_eq!(offsets[0], 0); // A → %41 starts at 0
        assert_eq!(offsets[1], 3); // B → %42 starts at 3
        assert_eq!(offsets[2], 6); // C at byte 6
    }

    #[test]
    fn test_clean_text_fast_path() {
        // Normal text with no evasion markers should hit fast path
        let (result, offsets) = normalize_text("The quick brown fox jumps over the lazy dog.");
        assert_eq!(result, "The quick brown fox jumps over the lazy dog.");
        assert!(offsets.is_empty());
    }

    // === New evasion technique tests ===

    #[test]
    fn test_hex_spaced_bytes_ssn() {
        // "123-45-6789" encoded as hex-spaced bytes
        let (result, _) = normalize_text("31 32 33 2D 34 35 2D 36 37 38 39");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_hex_spaced_bytes_short_ignored() {
        // Too short to be hex-spaced (only 2 pairs), but whitespace collapse
        // still removes the space between digits
        let (result, _) = normalize_text("31 32");
        assert_eq!(result, "3132");
    }

    #[test]
    fn test_hex_spaced_does_not_eat_display_formatted_card_number() {
        // Regression: decode_hex_spaced used to allow an OPTIONAL space
        // between consecutive hex pairs, which meant it greedily
        // consumed a display-formatted card number like
        // "4242 4242 4242 4242" as back-to-back 2-char pairs and
        // rewrote it as "BBBBBBBB" (8 × 0x42). With the space between
        // pairs now mandatory, the decoder runs out of contiguous
        // pair-space-pair-space runs and falls through. The
        // collapse_padding stage then does what it should — strip the
        // spaces between the digit groups — and the credit-card regex
        // sees an intact 16-digit PAN.
        let (result, _) = normalize_text("4242 4242 4242 4242");
        assert_eq!(result, "4242424242424242");

        // 15-digit Amex display format.
        let (result, _) = normalize_text("3782 822463 10005");
        assert_eq!(result, "378282246310005");
    }

    #[test]
    fn test_hex_spaced_still_defeats_real_evasion() {
        // Counter-test: legitimate hex-spaced evasion (bytes separated
        // by mandatory single spaces, at least 3 pairs, all decoding
        // to printable ASCII) must still be decoded. "Hello" is
        // 48 65 6c 6c 6f in hex.
        let (result, _) = normalize_text("48 65 6c 6c 6f");
        assert_eq!(result, "Hello");

        // And the existing SSN evasion regression should still fire.
        let (result, _) = normalize_text("31 32 33 2D 34 35 2D 36 37 38 39");
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_base64_decode() {
        // "123-45-6789" in base64
        let alts = generate_alternative_decodings("MTIzLTQ1LTY3ODk=");
        assert!(alts.iter().any(|a| a == "123-45-6789"));
    }

    #[test]
    fn test_base32_decode() {
        // "123-45-6789" in base32
        let alts = generate_alternative_decodings("GEZDGNA=");
        // base32("123") = "GEZDG===" — test a simple case
        let alts2 = generate_alternative_decodings("GEZDGNBVGY3TQOJQ");
        assert!(!alts2.is_empty());
    }

    #[test]
    fn test_rot13_decode() {
        let alts = generate_alternative_decodings("QRHGFPURONAX");
        // ROT13 of "DEUTSCHEBANK" is "QRHGFPURONAX"
        assert!(alts.iter().any(|a| a == "DEUTSCHEBANK"));
    }

    #[test]
    fn test_reversed_text_is_not_generated() {
        // Reverse-text alt-decoding was removed because it produced
        // false positives against high-specificity regexes whose
        // patterns happened to match natural-text reversed fragments
        // (Geohash / "ruevres", Bitcoin Cash Address / reversed
        // bech32). The transformation has no real-world evasion
        // value — no adversary is writing their data backwards —
        // so we now assert the alt-decodings pass does NOT produce
        // a reversed copy of its input.
        let alts = generate_alternative_decodings("9876-54-321");
        assert!(
            alts.iter().all(|a| a != "123-45-6789"),
            "reverse-text alt-decoding should have been removed"
        );
    }

    #[test]
    fn test_leet_decode() {
        // Note: '@' → 'a' in leet map, so email @ is destroyed.
        // Leet decode is best for non-email patterns.
        let alts = generate_alternative_decodings("h3ll0 w0rld");
        assert!(alts.iter().any(|a| a == "hello world"));
    }

    #[test]
    fn test_alternative_decodings_empty_for_clean() {
        let alts = generate_alternative_decodings("hello world");
        // Should produce alternatives (ROT13, reversal) but not base32/64
        assert!(alts.iter().all(|a| a != "hello world"));
    }

    // === Morse code tests ===

    #[test]
    fn test_morse_decode_digits() {
        // "123" in morse: .---- ..--- ...--
        let alts = generate_alternative_decodings(".---- ..--- ...--");
        assert!(alts.iter().any(|a| a == "123"));
    }

    #[test]
    fn test_alternative_decodings_rejects_oversize_input() {
        // Regression: the alternative-decodings pass used to allocate N
        // full copies of the input unconditionally. For an oversized
        // adversarial blob that multiplies peak memory by 5x. The
        // hardening cap skips the pass entirely above MAX_ALTERNATIVE_
        // DECODING_INPUT.
        let oversized = "a".repeat(MAX_ALTERNATIVE_DECODING_INPUT + 1);
        let alts = generate_alternative_decodings(&oversized);
        assert!(alts.is_empty());
    }

    #[test]
    fn test_alternative_decodings_total_budget_is_enforced() {
        // Even for inputs under the per-input cap, the combined size of
        // the produced alternatives is bounded. Use an input that is
        // large enough to make 5 copies blow the total budget but small
        // enough to pass the per-input gate.
        let in_size = MAX_ALTERNATIVE_DECODING_INPUT; // right at the gate
        let input = "A".repeat(in_size);
        let alts = generate_alternative_decodings(&input);
        let total: usize = alts.iter().map(|a| a.len()).sum();
        assert!(
            total <= MAX_ALTERNATIVE_DECODING_TOTAL,
            "total bytes {total} exceeded budget"
        );
    }

    #[test]
    fn test_morse_decode_ssn() {
        // "123-45-6789" — digits and hyphen in morse, words separated by /
        let morse = ".---- ..--- ...-- -....- ....- ..... -....- -.... --... ---.. ----.";
        let alts = generate_alternative_decodings(morse);
        assert!(alts.iter().any(|a| a == "123-45-6789"), "got: {:?}", alts);
    }

    #[test]
    fn test_morse_decode_letters() {
        // "HELLO" in morse
        let alts = generate_alternative_decodings(".... . .-.. .-.. ---");
        assert!(alts.iter().any(|a| a == "HELLO"));
    }

    #[test]
    fn test_morse_decode_with_word_separator() {
        // "AB CD" with / as word separator
        let alts = generate_alternative_decodings(".- -...|-.-.  -..");
        assert!(alts.iter().any(|a| a == "AB CD"));
    }

    #[test]
    fn test_morse_rejects_normal_text() {
        // Normal text should NOT be decoded as morse
        assert!(decode_morse("hello world").is_none());
        assert!(decode_morse("123-45-6789").is_none());
        assert!(decode_morse("short").is_none());
    }

    #[test]
    fn test_morse_rejects_too_short() {
        assert!(decode_morse(".-").is_none()); // only 1 symbol
        assert!(decode_morse(". .").is_none()); // only 2 symbols
    }

    #[test]
    fn test_greek_epsilon_homoglyph() {
        // Greek ε (U+03B5) should normalize to 'e'
        let input = "t\u{03B5}st@example.com";
        let (normalized, _) = normalize_text(input);
        assert!(normalized.contains("test@example.com"));
    }

    #[test]
    fn test_cyrillic_yo_homoglyph() {
        // Cyrillic Ё (U+0401) should normalize to 'E'
        let input = "\u{0401}mail";
        let (normalized, _) = normalize_text(input);
        assert!(normalized.contains("Email") || normalized.contains("email"));
    }

    #[test]
    fn test_cyrillic_lowercase_yo_homoglyph() {
        // Cyrillic ё (U+0451) should normalize to 'e'
        let input = "t\u{0451}st";
        let (normalized, _) = normalize_text(input);
        assert!(normalized.contains("test"));
    }

    #[test]
    fn test_greek_sigma_tau_omega() {
        // Greek σ → s, τ → t, ω → w
        let input = "\u{03C3}\u{03C4}\u{03C9}";
        let (normalized, _) = normalize_text(input);
        assert!(normalized.contains("stw"));
    }

    #[test]
    fn test_cyrillic_ve_homoglyph() {
        // Cyrillic в (U+0432) should normalize to 'b'
        let input = "\u{0432}ank";
        let (normalized, _) = normalize_text(input);
        assert!(normalized.contains("bank"));
    }
}
