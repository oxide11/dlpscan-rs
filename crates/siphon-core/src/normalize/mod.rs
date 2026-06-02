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

/// Returns `true` if the dot at `pos` in `bytes` should be stripped.
///
/// Strips when both neighbouring pure-digit runs are 1–6 characters long —
/// covers credit-card groupings (4-4), SSN groupings (3-2-4), ABA/SEPA wider
/// splits (5-4, 3-6, etc.).  A letter on either side means the dot is part of
/// an email address, domain name, ICD-10 code, or similar pattern and must not
/// be removed.  IPv4 dots are protected upstream by `mark_ipv4_dot_positions`.
fn should_strip_dot(bytes: &[u8], pos: usize) -> bool {
    if pos == 0 || pos + 1 >= bytes.len() {
        return false;
    }
    if !bytes[pos - 1].is_ascii_digit() || !bytes[pos + 1].is_ascii_digit() {
        return false;
    }
    let before = bytes[..pos]
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let after = bytes[pos + 1..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    (1..=6).contains(&before) && (1..=6).contains(&after)
}

/// Returns a bitmask of dot positions that belong to a valid IPv4 address.
///
/// Dots inside `d{1,3}.d{1,3}.d{1,3}.d{1,3}` with each octet 0–255 are
/// protected from stripping so that `192.168.1.1` is never collapsed to
/// `192168.1.1`.
fn mark_ipv4_dot_positions(bytes: &[u8]) -> Vec<bool> {
    let mut protected = vec![false; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit()) {
            if let Some(end) = try_match_ipv4(bytes, i) {
                for j in i..end {
                    if bytes[j] == b'.' {
                        protected[j] = true;
                    }
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    protected
}

/// Attempt to match a complete IPv4 address (`d{1,3}.d{1,3}.d{1,3}.d{1,3}`)
/// starting at `start`.  Returns `Some(end)` (exclusive) on success.
fn try_match_ipv4(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for group in 0..4u8 {
        let group_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let group_len = pos - group_start;
        if group_len == 0 || group_len > 3 {
            return None;
        }
        let val: u32 = bytes[group_start..pos]
            .iter()
            .fold(0u32, |acc, &b| acc * 10 + (b - b'0') as u32);
        if val > 255 {
            return None;
        }
        if group < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    if pos < bytes.len() && bytes[pos].is_ascii_digit() {
        return None;
    }
    Some(pos)
}

/// Strip delimiter characters between adjacent alphanumeric characters.
///
/// For `-`, `/`, `\`, `_`: removed when both immediate byte-neighbours are
/// ASCII alphanumeric and at least one is a digit or uppercase letter, defeating
/// delimiter-injection evasion like `D123-4567` → `D1234567` and
/// `BBG0-00BP-HV59` → `BBG000BPHV59` while preserving compound words like
/// `test-case` whose neighbours are both lowercase.
///
/// For `.`: stripped only when both neighbouring pure-digit runs are 2–4
/// digits long (credit-card / identifier grouping such as `4532.0151.1283.0366`
/// or `D123.4567`).  Dots that are part of a valid IPv4 address are never
/// stripped.  Dots adjacent to letters (email addresses, domain names, ICD-10
/// codes, JWT segments) are preserved because the digit guard fires first.
///
/// Runs after `normalize_delimiters` so doubled-delimiter evasion (e.g.
/// `123--456`) has already been collapsed to a single delimiter before this
/// stage strips it entirely.
fn strip_alnum_adjacent_delimiters(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    if !bytes
        .iter()
        .any(|&b| b == b'-' || b == b'.' || b == b'/' || b == b'\\' || b == b'_')
    {
        return (input.to_string(), in_offsets.to_vec());
    }

    let ip_dots = mark_ipv4_dot_positions(bytes);

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets: Vec<usize> = Vec::with_capacity(bytes.len());
    let mut changed = false;

    for i in 0..bytes.len() {
        let b = bytes[i];
        if b == b'.' && !ip_dots[i] && should_strip_dot(bytes, i) {
            changed = true;
            continue;
        }
        if b == b'-' || b == b'/' || b == b'\\' || b == b'_' {
            let prev = out.last().copied();
            let next = if i + 1 < bytes.len() {
                Some(bytes[i + 1])
            } else {
                None
            };
            if let (Some(p), Some(n)) = (prev, next) {
                if p.is_ascii_alphanumeric() && n.is_ascii_alphanumeric() {
                    // Preserve lowercase–word boundaries (`test-case`);
                    // strip identifier separators (`D123-4567`, `BBG0-00BP-HV59`).
                    if p.is_ascii_digit()
                        || n.is_ascii_digit()
                        || p.is_ascii_uppercase()
                        || n.is_ascii_uppercase()
                    {
                        changed = true;
                        continue;
                    }
                }
            }
        }
        out.push(b);
        offsets.push(orig_offset(in_offsets, i));
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
// Stage 4c: Token-level encoded-data decode
//
// Supports base64 (standard), base64url, base32, and hex. Tokens are
// found by scanning for maximal runs of "possibly encoded" characters
// (the union of all supported alphabets) and then trying each codec
// in priority order. First successful decode that passes the
// UTF-8/printable gate wins.
// ---------------------------------------------------------------------------

/// Check if a byte could be part of any supported encoding (the union
/// alphabet): alphanumeric, `+`, `/`, `_`, `-`. This is deliberately
/// wide — the codec-try logic downstream determines which encoding it
/// actually is.
fn is_encoded_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'_' || b == b'-'
}

/// Validate decoded bytes: valid UTF-8, > 50% printable ASCII, ≥ 4
/// non-whitespace chars. Shared by all codecs.
fn validate_decoded(decoded_bytes: &[u8]) -> Option<String> {
    let decoded_str = std::str::from_utf8(decoded_bytes).ok()?;
    let printable = decoded_str
        .bytes()
        .filter(|&b| (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    // Require STRICTLY more than 50% printable. The `<=` (rather than `<`)
    // prevents exactly-50% cases from passing — e.g. "3530111333300000"
    // hex-decodes to 8 bytes with 4 printable + 4 control chars, which was
    // previously accepted and corrupted the JCB credit-card pattern match.
    if decoded_str.is_empty() || printable * 2 <= decoded_str.len() {
        return None;
    }
    if decoded_str.trim().len() < 4 {
        return None;
    }
    // Reject trivial decoded output: all-same character (e.g., hex
    // decode of "4242424242424242" → "BBBBBBBB") or fewer than 3
    // distinct characters. Real encoded sensitive data always has
    // variety.
    let distinct = {
        let mut seen = [false; 256];
        for &b in decoded_str.as_bytes() {
            seen[b as usize] = true;
        }
        seen.iter().filter(|&&s| s).count()
    };
    if distinct < 3 {
        return None;
    }
    Some(decoded_str.to_string())
}

/// Try base64 standard decode (A-Za-z0-9+/, optional = padding).
fn try_decode_base64(token: &str) -> Option<String> {
    use base64::{engine::general_purpose, Engine};
    // Only attempt if the token uses base64-standard alphabet.
    if token.bytes().any(|b| {
        b == b'_'
            || b == b'-'
            || (!b.is_ascii_alphanumeric() && b != b'+' && b != b'/' && b != b'=')
    }) {
        return None;
    }
    let bytes = if let Ok(b) = general_purpose::STANDARD.decode(token) {
        b
    } else {
        // Try adding padding for unpadded base64.
        let padded = match token.trim_end_matches('=').len() % 4 {
            2 => format!("{}==", token.trim_end_matches('=')),
            3 => format!("{}=", token.trim_end_matches('=')),
            0 => token.to_string(),
            _ => return None,
        };
        general_purpose::STANDARD.decode(&padded).ok()?
    };
    validate_decoded(&bytes)
}

/// Try base64url decode (A-Za-z0-9_-, optional = padding).
fn try_decode_base64url(token: &str) -> Option<String> {
    use base64::{engine::general_purpose, Engine};
    // Only attempt if the token uses base64url alphabet (has _ or -,
    // no + or /).
    if token.bytes().any(|b| b == b'+' || b == b'/') {
        return None;
    }
    if !token.bytes().any(|b| b == b'_' || b == b'-') {
        return None; // No URL-safe chars, standard base64 should have caught it
    }
    let bytes = if let Ok(b) = general_purpose::URL_SAFE.decode(token) {
        b
    } else {
        let stripped = token.trim_end_matches('=');
        let padded = match stripped.len() % 4 {
            2 => format!("{stripped}=="),
            3 => format!("{stripped}="),
            0 => stripped.to_string(),
            _ => return None,
        };
        general_purpose::URL_SAFE.decode(&padded).ok()?
    };
    validate_decoded(&bytes)
}

/// Try base32 decode (A-Z2-7 case-insensitive, optional = padding).
///
/// Accepts both uppercase (`GQ2TGMRQ…`) and lowercase (`gq2tgmrq…`) forms.
/// `base32_decode_bytes` already maps both cases, so no pre-uppercasing is
/// required here — just remove the lowercase rejection that used to live here.
fn try_decode_base32(token: &str) -> Option<String> {
    let stripped = token.trim_end_matches('=');
    // Standard base32 alphabet: A-Z (case-insensitive) + digits 2-7.
    // Reject digits 0/1/8/9 and any base64/URL-safe chars not in the alphabet.
    if stripped.bytes().any(|b| {
        b == b'0'
            || b == b'1'
            || b == b'8'
            || b == b'9'
            || b == b'+'
            || b == b'/'
            || b == b'_'
            || b == b'-'
    }) {
        return None;
    }
    let decoded_bytes = super_base32_decode(stripped.as_bytes())?;
    validate_decoded(&decoded_bytes)
}

/// Try base32hex decode (0-9 A-V case-insensitive, RFC 4648 §7).
///
/// Base32hex extends the alphabet from A-Z2-7 to 0-9A-V, preserving sort
/// order. A valid base32hex token must contain at least one digit from
/// {0,1,8,9} — otherwise it overlaps with standard base32 and
/// `try_decode_base32` handles it (the two alphabets assign different values
/// to the same letters).
fn try_decode_base32hex(token: &str) -> Option<String> {
    let stripped = token.trim_end_matches('=');
    if stripped.is_empty() {
        return None;
    }
    // Accept 0-9 and A-V (case-insensitive). Reject W-Z and any special chars.
    if stripped.bytes().any(|b| {
        let bu = b.to_ascii_uppercase();
        !(b.is_ascii_digit() || (b'A'..=b'V').contains(&bu))
    }) {
        return None;
    }
    // Require at least one digit in {0,1,8,9}: these are valid in base32hex
    // but NOT in standard base32. Without this guard a pure A-V token would
    // be tried twice with conflicting decodings.
    if !stripped
        .bytes()
        .any(|b| b == b'0' || b == b'1' || b == b'8' || b == b'9')
    {
        return None;
    }
    let decoded = base32hex_decode_bytes(stripped.as_bytes())?;
    validate_decoded(&decoded)
}

/// Decode RFC 4648 §7 base32hex (alphabet `0-9A-V`, case-insensitive).
fn base32hex_decode_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let mut val_map = [255u8; 256];
    for b in b'0'..=b'9' {
        val_map[b as usize] = b - b'0';
    }
    for b in b'A'..=b'V' {
        val_map[b as usize] = b - b'A' + 10;
        val_map[(b + 32) as usize] = b - b'A' + 10; // lowercase a-v
    }
    let trimmed: Vec<u8> = input.iter().copied().filter(|&b| b != b'=').collect();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.iter().any(|&b| val_map[b as usize] == 255) {
        return None;
    }
    let mut bits: u64 = 0;
    let mut bit_count = 0u8;
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

/// Wrapper around the existing `base32_decode_bytes` in this module.
fn super_base32_decode(input: &[u8]) -> Option<Vec<u8>> {
    base32_decode_bytes(input)
}

/// Try hex decode (0-9a-fA-F, even length, optional 0x prefix).
fn try_decode_hex(token: &str) -> Option<String> {
    let hex_str = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .unwrap_or(token);
    // Must be even length and all hex digits.
    if !hex_str.len().is_multiple_of(2) {
        return None;
    }
    if !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Must be long enough: 12 hex chars = 6 decoded bytes, borderline.
    // Require 16 hex chars (8 decoded bytes) to avoid false decodes
    // on short hex-shaped strings.
    if hex_str.len() < 16 {
        return None;
    }
    let decoded_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect();
    if decoded_bytes.len() != hex_str.len() / 2 {
        return None;
    }
    validate_decoded(&decoded_bytes)
}

/// Try all supported decodings on a token, in priority order.
/// Returns the first successful decode that passes the printable gate.
///
/// Priority logic: base32 alphabet is a strict subset of base64, so
/// a pure-base32 token (A-Z2-7, case-insensitive) would be decoded by
/// base64 first and produce a different (wrong) result. To handle this,
/// tokens that match the base32 alphabet (uppercase OR lowercase + digits
/// 2-7) try base32 FIRST. Everything else: base64 → base64url → base32
/// → hex → base32hex.
fn try_decode_any(token: &str) -> Option<String> {
    let stripped = token.trim_end_matches('=');
    let looks_like_base32 = !stripped.is_empty()
        && stripped
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));

    // Base32-shaped tokens: try base32 first.
    if looks_like_base32 {
        if let Some(d) = try_decode_base32(token) {
            return Some(d);
        }
    }

    // Standard priority.
    if let Some(d) = try_decode_base64(token) {
        return Some(d);
    }
    if let Some(d) = try_decode_base64url(token) {
        return Some(d);
    }
    if !looks_like_base32 {
        if let Some(d) = try_decode_base32(token) {
            return Some(d);
        }
    }
    if let Some(d) = try_decode_hex(token) {
        return Some(d);
    }
    // Base32hex (RFC 4648 §7, alphabet 0-9A-V) as last resort — only tried
    // when the token contains at least one digit from {0,1,8,9} that
    // standard base32 rejects.
    if let Some(d) = try_decode_base32hex(token) {
        return Some(d);
    }
    None
}

/// Scan the text for tokens that look like encoded data, decode each
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
fn decode_encoded_tokens(input: &str, in_offsets: &[usize]) -> (String, Vec<usize>) {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets: Vec<usize> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if is_encoded_char(bytes[i]) {
            // Find the end of the encoded-alphabet run.
            let start = i;
            while i < bytes.len() && is_encoded_char(bytes[i]) {
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
                for (j, b) in bytes[start..i].iter().enumerate() {
                    out.push(*b);
                    offsets.push(orig_offset(in_offsets, start + j));
                }
                continue;
            }

            // Only attempt decode on sufficiently long tokens.
            if token.len() >= 12 {
                if let Some(decoded) = try_decode_any(token) {
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
            for (j, b) in bytes[start..i].iter().enumerate() {
                out.push(*b);
                offsets.push(orig_offset(in_offsets, start + j));
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

/// Digit-only ITU-R M.1677-1 morse codes as byte slices.
/// All digit codes are exactly 5 characters — this property is used to
/// distinguish them from single-char literal passthroughs in evadex-style encoding.
const MORSE_DIGITS: &[(&[u8], u8)] = &[
    (b"-----", b'0'),
    (b".----", b'1'),
    (b"..---", b'2'),
    (b"...--", b'3'),
    (b"....-", b'4'),
    (b".....", b'5'),
    (b"-....", b'6'),
    (b"--...", b'7'),
    (b"---..", b'8'),
    (b"----.", b'9'),
];

/// Decode a single 5-char all-dot-dash token as a morse digit.
#[inline]
fn decode_morse_digit_token(token: &[u8]) -> Option<char> {
    if token.len() == 5 && token.iter().all(|&b| b == b'.' || b == b'-') {
        MORSE_DIGITS
            .iter()
            .find(|(code, _)| *code == token)
            .map(|&(_, d)| d as char)
    } else {
        None
    }
}

/// Decode evadex-style digit-only morse with slash `/` separator.
///
/// Evadex encodes only digit characters as 5-char ITU-R morse sequences;
/// non-digit characters (hyphens, letters, etc.) pass through as literal
/// single ASCII characters.  The key invariant: every digit morse code is
/// exactly 5 chars, so a 1-char token is always a literal passthrough.
///
/// Returns `Some(decoded)` when at least 4 digit tokens are found; `None`
/// otherwise (too short, no slashes, or unrecognised token).
fn try_decode_digit_morse_slash(text: &str) -> Option<String> {
    if !text.is_ascii() || !text.contains('/') {
        return None;
    }
    if !text.bytes().any(|b| b == b'.' || b == b'-') {
        return None;
    }

    let raw = text.as_bytes();
    let tokens: Vec<&[u8]> = raw
        .split(|&b| b == b'/')
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.len() < 4 {
        return None;
    }

    let mut result = String::with_capacity(tokens.len());
    let mut digit_count = 0usize;

    for token in &tokens {
        if let Some(ch) = decode_morse_digit_token(token) {
            // 5-char all-dot-dash: digit morse code
            result.push(ch);
            digit_count += 1;
        } else if token.len() == 1 && token[0].is_ascii() {
            // Single ASCII char: literal passthrough from the evadex encoder
            result.push(token[0] as char);
        } else {
            // Multi-char but not a 5-char digit code: try letter morse table
            // (handles fully-encoded non-digit characters).
            if let Ok(s) = std::str::from_utf8(token) {
                if let Some(&ch) = MORSE_TABLE.get(s) {
                    result.push(ch);
                } else {
                    return None; // Unrecognised token
                }
            } else {
                return None;
            }
        }
    }

    if digit_count < 4 {
        return None;
    }
    Some(result)
}

/// Decode concatenated (no-separator) digit-only morse.
///
/// Greedy left-to-right matching in 5-char chunks.  Succeeds only when the
/// entire input is all dots/dashes, its length is an exact multiple of 5, and
/// every chunk maps to a digit code.  This constraint keeps false-positive risk
/// very low: random text won't form a valid sequence of 5-char digit codes.
///
/// Space-sep and newline-sep morse collapse to this form after `normalize_text`
/// strips whitespace between non-alphabetic neighbours (stage 5).  No-sep morse
/// arrives unchanged.  In all three cases a pure-digit value (credit card,
/// routing number, TFN, etc.) produces a length that is exactly N×5.
fn try_decode_digit_morse_nosep(text: &[u8]) -> Option<String> {
    if text.is_empty() || !text.len().is_multiple_of(5) {
        return None;
    }
    if text.iter().any(|&b| b != b'.' && b != b'-') {
        return None;
    }

    let count = text.len() / 5;
    if !(4..=20).contains(&count) {
        return None;
    }

    let mut result = String::with_capacity(count);
    for chunk in text.chunks_exact(5) {
        match MORSE_DIGITS.iter().find(|(code, _)| *code == chunk) {
            Some(&(_, digit)) => result.push(digit as char),
            None => return None,
        }
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

    // Stage 4c: Token-level encoded-data decode (base64, base32, hex)
    //
    // Runs up to 3 iterations to handle nested encoding (e.g., base64
    // of base64, or base64 of hex). Each iteration finds and decodes
    // tokens; if nothing changed, the loop stops early. The 3-iteration
    // cap prevents infinite loops on pathological input.
    //
    // This runs BEFORE collapse_padding so the decoded result gets the
    // same whitespace/delimiter normalization as everything else.
    for _decode_iteration in 0..3 {
        let r = decode_encoded_tokens(&current, &offsets);
        if r.0 == current {
            break; // No more decoding possible
        }
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

    // Stage 6b: Strip delimiter characters between alphanumeric neighbours.
    // Resolves delimiter-injection evasion (e.g. `D123-4567` → `D1234567`,
    // `BBG0-00BP-HV59` → `BBG000BPHV59`). Runs after stage 6 so any
    // doubled-delimiter evasion has already been collapsed to a single char.
    apply_stage!(strip_alnum_adjacent_delimiters, current, offsets);

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

    // NOTE: base64/base32 decode used to live here but has been moved
    // to the normalization pipeline (stage 4c) where it runs on ALL
    // documents with full context checking. The token-level approach
    // there is strictly better: it handles individual tokens in mixed
    // documents, runs against every regex (not just always-run), and
    // supports nested decode up to 3 iterations.

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

    // Try morse code decode (full alphabet, space/slash/pipe separated)
    if let Some(decoded) = decode_morse(text) {
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    // Evadex-style digit-only morse: slash-separated, non-digits pass through literally.
    // Fixes the "-" → 'T' misidentification in the full-alphabet decoder for values
    // like SSNs ("123-45-6789") where the hyphen separator is not itself morse-encoded.
    if let Some(decoded) = try_decode_digit_morse_slash(text) {
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    // No-separator digit morse. Catches:
    //   1. Original no-sep encoding (.----..---...)
    //   2. Space-sep after normalize_text collapses spaces between non-alpha chars
    //   3. Newline-sep after the same collapse
    // Only succeeds for pure-digit values (length exactly N×5); mixed values with
    // embedded literal hyphens produce lengths that are not a multiple of 5, so they
    // correctly fall through to None rather than producing a garbled decode.
    if let Some(decoded) = try_decode_digit_morse_nosep(text.as_bytes()) {
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
    // Single delimiter between alphanumeric chars where at least one side is a
    // digit or uppercase letter — identifier-delimiter evasion (e.g. `D123-4567`).
    if bytes.len() >= 3 {
        for w in bytes.windows(3) {
            if (w[1] == b'-' || w[1] == b'.' || w[1] == b'/' || w[1] == b'\\' || w[1] == b'_')
                && w[0].is_ascii_alphanumeric()
                && w[2].is_ascii_alphanumeric()
                && (w[0].is_ascii_digit()
                    || w[2].is_ascii_digit()
                    || w[0].is_ascii_uppercase()
                    || w[2].is_ascii_uppercase())
            {
                return true;
            }
        }
    }
    // Base64-encoded tokens: a run of ≥16 base64-alphabet characters
    // (optionally followed by `=` padding). This is a cheap linear
    // scan that gates the more expensive `decode_encoded_tokens` stage.
    {
        let mut run_len = 0usize;
        for &b in bytes {
            if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' {
                run_len += 1;
            } else if b == b'=' && run_len >= 12 {
                // Trailing `=` after a 12+ char base64 run — likely
                // padded base64. The actual decode threshold (16 chars
                // including padding) is enforced in decode_encoded_tokens;
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
        // "123-45-6789" base64-encoded = "MTIzLTQ1LTY3ODk=".
        // Stage 4c decodes the token; stage 6b then strips digit-adjacent hyphens.
        let input = "config ssn = MTIzLTQ1LTY3ODk= end";
        let (result, _offsets) = normalize_text(input);
        assert!(
            result.contains("123456789"),
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
        // "123-45-6789" without padding = "MTIzLTQ1LTY3ODk" (no trailing =).
        // Hyphens are stripped by stage 6b after decoding.
        let input = "data MTIzLTQ1LTY3ODk here";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("123456789"),
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
        // Stage 4c decodes base64; stage 6b strips digit-adjacent hyphens.
        // The offset of the first decoded byte still points to the original token.
        let input = "prefix MTIzLTQ1LTY3ODk= suffix";
        let (result, offsets) = normalize_text(input);
        assert!(result.contains("123456789"));
        let decoded_start = result.find("123456789").unwrap();
        let original_token_start = input.find("MTIz").unwrap();
        if !offsets.is_empty() {
            assert_eq!(
                offsets[decoded_start], original_token_start,
                "offset map should point decoded bytes to the original token start"
            );
        }
    }

    #[test]
    fn test_nested_base64_decode() {
        // "123-45-6789" → base64 → "MTIzLTQ1LTY3ODk=" → base64 →
        // "TVRJekxUUTFMVFkzT0RrPQ=="; nested decode loop unwraps both layers,
        // then stage 6b strips digit-adjacent hyphens.
        let input = "nested TVRJekxUUTFMVFkzT0RrPQ== end";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("123456789"),
            "double-base64 should unwrap to plaintext. Got: {result:?}"
        );
    }

    #[test]
    fn test_nested_decode_no_infinite_loop() {
        // Verify the decode loop terminates cleanly; stage 6b strips hyphens.
        let input = "safe MTIzLTQ1LTY3ODk= done";
        let (result, _) = normalize_text(input);
        assert!(result.contains("123456789"));
    }

    #[test]
    fn test_base64url_token_decode() {
        // Stage 4c decodes standard base64; stage 6b strips digit-adjacent hyphens.
        let input = "key = MTIzLTQ1LTY3ODk= done";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("123456789"),
            "standard base64 should decode first. Got: {result:?}"
        );
    }

    #[test]
    fn test_base32_token_decode() {
        // Use the existing base32 decoder to verify round-trip at
        // runtime rather than trusting hand-computed values.
        // Encode "1234567890" as base32 via a known-correct encoder
        // (or use a pre-verified test vector).
        //
        // RFC 4648 extended test vector:
        // "foobar" → "MZXW6YTBOI======" (too short for our 12-char floor)
        // So use a longer value. "Hello, World!" is 13 bytes.
        // Pre-verified: base32("Hello, World!") = "JBSWY3DPEBLW64TMMQQQ===="
        // (verified via multiple online encoders)
        // "JBSWY3DPEBLW64TMMQQQ" is the base32 encoding of
        // "Hello World!" (verified via direct decode + online tools).
        let input = "data JBSWY3DPEBLW64TMMQQQ here";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("Hello World!"),
            "base32-encoded text should be decoded. Got: {result:?}"
        );
    }

    #[test]
    fn test_hex_token_decode() {
        // "123-45-6789" as hex = "3132332d34352d36373839".
        // Stage 4c decodes the hex; stage 6b strips digit-adjacent hyphens.
        let input = "hex 3132332d34352d36373839 end";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("123456789"),
            "hex-encoded SSN should be decoded. Got: {result:?}"
        );
    }

    #[test]
    fn test_hex_token_decode_with_0x_prefix() {
        // Stage 4c decodes 0x-prefixed hex; stage 6b strips digit-adjacent hyphens.
        let input = "val 0x3132332d34352d36373839 done";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("123456789"),
            "0x-prefixed hex should decode. Got: {result:?}"
        );
    }

    #[test]
    fn test_hex_rejects_short_tokens() {
        // Hex tokens under 16 chars should not be decoded.
        let input = "code ABCDEF123456 end";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("ABCDEF123456"),
            "short hex should be preserved. Got: {result:?}"
        );
    }

    #[test]
    fn test_codec_priority_base64_wins() {
        // A token that's valid in multiple codecs should decode as
        // base64 (highest priority) if that produces valid output.
        // "NDUzMjAxNTExMjgzMDM2Ng==" is base64 for "4532015112830366"
        // and is NOT valid base32 (contains lowercase and digits 0,1,8,9).
        let input = "card NDUzMjAxNTExMjgzMDM2Ng== stored";
        let (result, _) = normalize_text(input);
        assert!(
            result.contains("4532015112830366"),
            "base64 should win. Got: {result:?}"
        );
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
        // Stage 1 decodes percent-encoding; stage 6b then strips the
        // digit-adjacent hyphens, so the final result is all digits.
        let (result, _) = normalize_text("%31%32%33-%34%35-%36%37%38%39");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_percent_decode_digits_only() {
        // url_percent_encoding_digits: only digits encoded; digit-adjacent
        // hyphens stripped by stage 6b.
        let (result, _) = normalize_text("%34532-%30151-%31283");
        assert_eq!(result, "453201511283");
    }

    #[test]
    fn test_percent_decode_full() {
        // url_percent_encoding_full: everything encoded; hyphen stripped by stage 6b.
        let (result, _) = normalize_text("%34%35%33%32%2D%30%31%35%31");
        assert_eq!(result, "45320151");
    }

    #[test]
    fn test_double_percent_decode() {
        // %25 decodes to %, then %31 decodes to 1
        let (result, _) = normalize_text("%2531%2532%2533");
        assert_eq!(result, "123");
    }

    #[test]
    fn test_html_entity_decode_ssn() {
        // Stage 2 decodes entities; stage 6b strips digit-adjacent hyphens.
        let (result, _) = normalize_text("&#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_html_entity_decode_mixed() {
        // Some chars encoded, some plain; hyphens stripped by stage 6b.
        let (result, _) = normalize_text("1&#50;3-&#52;5-6&#55;89");
        assert_eq!(result, "123456789");
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
        // Stage 3 strips CSS comments; stage 6b strips digit-adjacent hyphens.
        let (result, _) = normalize_text("1/**/2/**/3/**/-/**/4/**/5/**/-/**/6/**/7/**/8/**/9");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_html_comment_strip() {
        // Stage 3 strips HTML comments; stage 6b strips digit-adjacent hyphens.
        let (result, _) =
            normalize_text("1<!---->2<!---->3<!---->-<!---->4<!---->5<!---->-<!---->6789");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_whitespace_padding_digits() {
        // Stage 5 strips spaces between non-alpha chars; stage 6b strips
        // the remaining digit-adjacent hyphens.
        let (result, _) = normalize_text("1 2 3 - 4 5 - 6 7 8 9");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_whitespace_padding_preserves_words() {
        // Spaces between alphabetic chars should be preserved
        let (result, _) = normalize_text("social security number: 1 2 3");
        assert_eq!(result, "social security number:123");
    }

    #[test]
    fn test_mid_line_break() {
        // Stage 5 strips the newline between non-alpha chars; stage 6b
        // strips digit-adjacent hyphens.
        let (result, _) = normalize_text("123-45-\n6789");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_mid_line_break_crlf() {
        // Stage 5 strips CR+LF; stage 6b strips digit-adjacent hyphens.
        let (result, _) = normalize_text("123-45-\r\n6789");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_excessive_delimiter() {
        // Stage 6 collapses `--` to `-`; stage 6b then strips digit-adjacent `-`.
        let (result, _) = normalize_text("123--45--6789");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_excessive_dots() {
        // Stage 6 collapses `..` to `.`; stage 6b then recognises `192.168.1.1`
        // as a valid IPv4 address and protects its dots from stripping.
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
        // Percent-encoded digits with spaces; stages 1, 5, and 6b all fire.
        let (result, _) = normalize_text("%31 %32 %33 - %34 %35 - %36 %37 %38 %39");
        assert_eq!(result, "123456789");
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
        // "123-45-6789" encoded as hex-spaced bytes.
        // Stage 4 decodes the hex; stage 6b strips digit-adjacent hyphens.
        let (result, _) = normalize_text("31 32 33 2D 34 35 2D 36 37 38 39");
        assert_eq!(result, "123456789");
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

        // And the existing SSN evasion regression should still fire;
        // stage 6b further strips the digit-adjacent hyphens.
        let (result, _) = normalize_text("31 32 33 2D 34 35 2D 36 37 38 39");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_base64_decode_moved_to_normalization() {
        // Base64/base32 decode used to live in generate_alternative_decodings
        // but has been moved to the normalization pipeline (stage 4c).
        // Verify the alt-decodings path no longer produces base64 output.
        let alts = generate_alternative_decodings("MTIzLTQ1LTY3ODk=");
        assert!(
            !alts.iter().any(|a| a == "123-45-6789"),
            "base64 decode should no longer be in alt-decodings"
        );
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

    // === stage 6b: strip_alnum_adjacent_delimiters tests ===

    #[test]
    fn test_strip_digit_adjacent_hyphen() {
        // California DL evaded: D123-4567 → D1234567
        let (result, _) = normalize_text("D123-4567");
        assert_eq!(result, "D1234567");
    }

    #[test]
    fn test_strip_digit_adjacent_dot() {
        let (result, _) = normalize_text("D123.4567");
        assert_eq!(result, "D123.4567");
    }

    #[test]
    fn test_dot_not_stripped_in_email() {
        // Dots in email addresses must never be removed — letters on each side
        // of the dot mean `should_strip_dot` returns false immediately.
        let (result, _) = normalize_text("test.user@example.com");
        assert_eq!(result, "test.user@example.com");
    }

    #[test]
    fn test_dot_not_stripped_in_ip() {
        // Dots inside a valid IPv4 address are marked by `mark_ipv4_dot_positions`
        // and skipped by the strip loop even though the digit runs would otherwise
        // satisfy the 2–4-digit threshold.
        let (result, _) = normalize_text("192.168.1.1");
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_dot_stripped_in_digit_groups() {
        // Credit-card dot-delimiter evasion: all three dots between 4-digit groups
        // are stripped, yielding the canonical 16-digit PAN.
        let (result, _) = normalize_text("4532.0151.1283.0366");
        assert_eq!(result, "4532015112830366");
    }

    #[test]
    fn test_dot_stripped_ssn_style() {
        // SSN dot-delimiter evasion: 3-2-4 grouping.
        let (result, _) = normalize_text("123.45.6789");
        assert_eq!(result, "123456789");
    }

    #[test]
    fn test_dot_stripped_aba_routing_style() {
        // ABA routing-number dot-delimiter evasion: 3-3-3 grouping (9 digits).
        // `021.000.021` has only 3 groups so it is NOT recognised as IPv4
        // (which needs 4 groups) and the dots are stripped.
        let (result, _) = normalize_text("021.000.021");
        assert_eq!(result, "021000021");
    }

    #[test]
    fn test_dot_stripped_wider_5_4_grouping() {
        // 5-4 grouping: wider than the old 2-4 cap; the 1-6 cap catches it.
        let (result, _) = normalize_text("45320.1512");
        assert_eq!(result, "453201512");
    }

    #[test]
    fn test_dot_stripped_wider_3_6_grouping() {
        // 3-6 grouping: after-run of 6 digits is within the 1-6 cap.
        let (result, _) = normalize_text("453.201511");
        assert_eq!(result, "453201511");
    }

    #[test]
    fn test_strip_digit_adjacent_slash() {
        let (result, _) = normalize_text("1234/5678/9012");
        assert_eq!(result, "123456789012");
    }

    #[test]
    fn test_strip_multiple_groups_fl_dl() {
        // Florida DL: letter + 12 digits; evadex groups as D123-4567-8901-23
        let (result, _) = normalize_text("D123-4567-8901-23");
        assert_eq!(result, "D1234567890123");
    }

    #[test]
    fn test_strip_uppercase_adjacent_figi() {
        // FIGI: BBG000BPHV59 evaded as BBG0-00BP-HV59
        let (result, _) = normalize_text("BBG0-00BP-HV59");
        assert_eq!(result, "BBG000BPHV59");
    }

    #[test]
    fn test_strip_preserves_lowercase_word_boundaries() {
        // Lowercase-letter–only boundaries must NOT be stripped
        let (result, _) = normalize_text("test-case");
        assert_eq!(result, "test-case");

        let (result, _) = normalize_text("pre-existing");
        assert_eq!(result, "pre-existing");
    }

    #[test]
    fn test_strip_idaho_dl() {
        // Idaho DL: AB123456X; evadex groups as AB12-3456-X
        let (result, _) = normalize_text("AB12-3456-X");
        assert_eq!(result, "AB123456X");
    }

    #[test]
    fn test_strip_nh_dl() {
        // New Hampshire DL: 12ABC67890; evadex groups as 12AB-C678-90
        let (result, _) = normalize_text("12AB-C678-90");
        assert_eq!(result, "12ABC67890");
    }

    #[test]
    fn test_morse_rejects_too_short() {
        assert!(decode_morse(".-").is_none()); // only 1 symbol
        assert!(decode_morse(". .").is_none()); // only 2 symbols
    }

    // === Evadex-style digit-only morse tests ===

    #[test]
    fn test_digit_morse_slash_ssn() {
        // "123-45-6789" evadex slash_sep: hyphens are literal passthroughs
        let morse = ".----/..---/...--/-/....-/...../-/-..../--.../---../----.";
        let alts = generate_alternative_decodings(morse);
        assert!(
            alts.iter().any(|a| a == "123-45-6789"),
            "slash_sep SSN should decode correctly; got: {:?}",
            alts
        );
    }

    #[test]
    fn test_digit_morse_slash_pure_digits() {
        // Pure-digit value: ABA routing number "021000021" slash_sep.
        // 0=-----, 2=..---, 1=.----, 0=-----, 0=-----, 0=-----, 0=-----, 2=..---, 1=.----
        let morse = "-----/..---/.----/-----/-----/-----/-----/..---/.----";
        let alts = generate_alternative_decodings(morse);
        assert!(
            alts.iter().any(|a| a == "021000021"),
            "slash_sep pure-digit routing number should decode; got: {:?}",
            alts
        );
    }

    #[test]
    fn test_digit_morse_slash_literal_passthrough_not_t() {
        // A single '-' token is treated as literal '-' (evadex passthrough), not Morse 'T'.
        // .---- = 1, ..--- = 2, ...-- = 3, - = literal '-', ....- = 4, ..... = 5
        let result = try_decode_digit_morse_slash(".----/..---/...--/-/....-/.....");
        assert_eq!(result, Some("123-45".to_string()), "got: {:?}", result);

        // Full SSN 123-45-6789
        let result2 = try_decode_digit_morse_slash(
            ".----/..---/...--/-/....-/...../-/-..../--.../---../----.",
        );
        assert_eq!(
            result2,
            Some("123-45-6789".to_string()),
            "got: {:?}",
            result2
        );
    }

    #[test]
    fn test_digit_morse_nosep_credit_card() {
        // Credit card "1234567890123456" (16 digits) — no separator, after space-collapse
        let digits = "1234567890123456";
        let morse_nosep: String = digits
            .chars()
            .map(|c| {
                let idx = c as usize - b'0' as usize;
                let codes = [
                    "-----", ".----", "..---", "...--", "....-", ".....", "-....", "--...",
                    "---..", "----.",
                ];
                codes[idx]
            })
            .collect();
        let result = try_decode_digit_morse_nosep(morse_nosep.as_bytes());
        assert_eq!(result, Some(digits.to_string()), "got: {:?}", result);
    }

    #[test]
    fn test_digit_morse_nosep_via_space_sep_after_normalize() {
        // Space-sep morse collapses to no-sep during normalize_text because stage 5
        // strips whitespace between non-alphabetic neighbours.
        // Use a 9-digit ABA routing number "021000021".
        // 0=-----, 2=..---, 1=.----, 0=-----, 0=-----, 0=-----, 0=-----, 2=..---, 1=.----
        let space_sep = "----- ..--- .---- ----- ----- ----- ----- ..--- .----";
        let (normalized, _) = normalize_text(space_sep);
        // After collapse: no-sep form, 45 chars = 9 × 5
        assert_eq!(
            normalized.len(),
            45,
            "spaces should be collapsed; got {:?}",
            normalized
        );
        let alts = generate_alternative_decodings(&normalized);
        assert!(
            alts.iter().any(|a| a == "021000021"),
            "space_sep routing number after normalize should decode via nosep; norm={:?}, alts={:?}",
            normalized,
            alts
        );
    }

    #[test]
    fn test_digit_morse_nosep_too_short() {
        // Fewer than 4 digits (15 chars = 3 × 5) — must return None
        assert!(try_decode_digit_morse_nosep(b".----..---...--").is_none());
    }

    #[test]
    fn test_digit_morse_nosep_non_multiple_of_5() {
        // SSN "123-45-6789" no-sep: 9 digits × 5 chars + 2 literal hyphens = 47 chars.
        // 47 % 5 == 2, so the decoder must return None.
        // (Computed: .---- ..--- ...-- - ....- ..... - -.... --... ---.. ----.  concatenated)
        let ssn_nosep = ".----..---...---....-.....--....--...---..----.";
        assert_eq!(
            ssn_nosep.len(),
            47,
            "SSN nosep should be 47 chars; got {}",
            ssn_nosep.len()
        );
        assert!(try_decode_digit_morse_nosep(ssn_nosep.as_bytes()).is_none());
    }

    #[test]
    fn test_digit_morse_slash_too_few_digits() {
        // Only 3 digit tokens: below the 4-digit minimum
        assert!(try_decode_digit_morse_slash(".----/..---/...--").is_none());
    }

    #[test]
    fn test_digit_morse_slash_no_slash() {
        // No slash separator: should return None (handled by nosep decoder instead)
        assert!(try_decode_digit_morse_slash(".----..---...--....-").is_none());
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
