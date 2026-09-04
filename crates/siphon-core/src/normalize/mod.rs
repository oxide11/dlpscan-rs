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
        ('\u{20AC}', 'e'), // € → e
        ('6', 'g'),
        ('#', 'h'),
        ('!', 'i'),
        ('1', 'l'),
        ('|', 'l'), // | → l
        ('0', 'o'),
        ('$', 's'), // $ → s
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
        // Unicode dashes that substitute for ASCII hyphen/minus in morse evasion
        // (em-dash, en-dash, and minus sign used as the '-' symbol in morse code)
        ('\u{2013}', '-'), // en-dash (–)
        ('\u{2014}', '-'), // em-dash (—)
        ('\u{2212}', '-'), // minus sign (−)
        ('\u{2015}', '-'), // horizontal bar (―)
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
        // Arabic-Indic digits: ٠١٢٣٤٥٦٧٨٩ (U+0660–U+0669)
        ('\u{0660}', '0'),
        ('\u{0661}', '1'),
        ('\u{0662}', '2'),
        ('\u{0663}', '3'),
        ('\u{0664}', '4'),
        ('\u{0665}', '5'),
        ('\u{0666}', '6'),
        ('\u{0667}', '7'),
        ('\u{0668}', '8'),
        ('\u{0669}', '9'),
        // Extended Arabic-Indic digits: ۰۱۲۳۴۵۶۷۸۹ (U+06F0–U+06F9)
        ('\u{06F0}', '0'),
        ('\u{06F1}', '1'),
        ('\u{06F2}', '2'),
        ('\u{06F3}', '3'),
        ('\u{06F4}', '4'),
        ('\u{06F5}', '5'),
        ('\u{06F6}', '6'),
        ('\u{06F7}', '7'),
        ('\u{06F8}', '8'),
        ('\u{06F9}', '9'),
        // Thai digits: ๐๑๒๓๔๕๖๗๘๙ (U+0E50–U+0E59)
        ('\u{0E50}', '0'),
        ('\u{0E51}', '1'),
        ('\u{0E52}', '2'),
        ('\u{0E53}', '3'),
        ('\u{0E54}', '4'),
        ('\u{0E55}', '5'),
        ('\u{0E56}', '6'),
        ('\u{0E57}', '7'),
        ('\u{0E58}', '8'),
        ('\u{0E59}', '9'),
        // Superscript digits 4–9 (⁰¹²³ already above; NFKC handles these but kept as backup)
        ('\u{2074}', '4'), // ⁴
        ('\u{2075}', '5'), // ⁵
        ('\u{2076}', '6'), // ⁶
        ('\u{2077}', '7'), // ⁷
        ('\u{2078}', '8'), // ⁸
        ('\u{2079}', '9'), // ⁹
        // Devanagari digits: ०१२३४५६७८९ (U+0966–U+096F)
        ('\u{0966}', '0'),
        ('\u{0967}', '1'),
        ('\u{0968}', '2'),
        ('\u{0969}', '3'),
        ('\u{096A}', '4'),
        ('\u{096B}', '5'),
        ('\u{096C}', '6'),
        ('\u{096D}', '7'),
        ('\u{096E}', '8'),
        ('\u{096F}', '9'),
        // Bengali digits: ০১২৩৪৫৬৭৮৯ (U+09E6–U+09EF)
        ('\u{09E6}', '0'),
        ('\u{09E7}', '1'),
        ('\u{09E8}', '2'),
        ('\u{09E9}', '3'),
        ('\u{09EA}', '4'),
        ('\u{09EB}', '5'),
        ('\u{09EC}', '6'),
        ('\u{09ED}', '7'),
        ('\u{09EE}', '8'),
        ('\u{09EF}', '9'),
        // Gujarati digits: ૦૧૨૩૪૫૬૭૮૯ (U+0AE6–U+0AEF)
        ('\u{0AE6}', '0'),
        ('\u{0AE7}', '1'),
        ('\u{0AE8}', '2'),
        ('\u{0AE9}', '3'),
        ('\u{0AEA}', '4'),
        ('\u{0AEB}', '5'),
        ('\u{0AEC}', '6'),
        ('\u{0AED}', '7'),
        ('\u{0AEE}', '8'),
        ('\u{0AEF}', '9'),
        // Gurmukhi digits: ੦੧੨੩੪੫੬੭੮੯ (U+0A66–U+0A6F)
        ('\u{0A66}', '0'),
        ('\u{0A67}', '1'),
        ('\u{0A68}', '2'),
        ('\u{0A69}', '3'),
        ('\u{0A6A}', '4'),
        ('\u{0A6B}', '5'),
        ('\u{0A6C}', '6'),
        ('\u{0A6D}', '7'),
        ('\u{0A6E}', '8'),
        ('\u{0A6F}', '9'),
        // Khmer digits: ០១២៣៤៥៦៧៨៩ (U+17E0–U+17E9)
        ('\u{17E0}', '0'),
        ('\u{17E1}', '1'),
        ('\u{17E2}', '2'),
        ('\u{17E3}', '3'),
        ('\u{17E4}', '4'),
        ('\u{17E5}', '5'),
        ('\u{17E6}', '6'),
        ('\u{17E7}', '7'),
        ('\u{17E8}', '8'),
        ('\u{17E9}', '9'),
        // Myanmar digits: ၀၁၂၃၄၅၆၇၈၉ (U+1040–U+1049)
        ('\u{1040}', '0'),
        ('\u{1041}', '1'),
        ('\u{1042}', '2'),
        ('\u{1043}', '3'),
        ('\u{1044}', '4'),
        ('\u{1045}', '5'),
        ('\u{1046}', '6'),
        ('\u{1047}', '7'),
        ('\u{1048}', '8'),
        ('\u{1049}', '9'),
        // Mathematical bold digits: 𝟎–𝟗 (U+1D7CE–U+1D7D7) — backup for NFKC
        ('\u{1D7CE}', '0'),
        ('\u{1D7CF}', '1'),
        ('\u{1D7D0}', '2'),
        ('\u{1D7D1}', '3'),
        ('\u{1D7D2}', '4'),
        ('\u{1D7D3}', '5'),
        ('\u{1D7D4}', '6'),
        ('\u{1D7D5}', '7'),
        ('\u{1D7D6}', '8'),
        ('\u{1D7D7}', '9'),
        // Mathematical sans-serif bold digits: 𝟬–𝟵 (U+1D7EC–U+1D7F5) — backup for NFKC
        ('\u{1D7EC}', '0'),
        ('\u{1D7ED}', '1'),
        ('\u{1D7EE}', '2'),
        ('\u{1D7EF}', '3'),
        ('\u{1D7F0}', '4'),
        ('\u{1D7F1}', '5'),
        ('\u{1D7F2}', '6'),
        ('\u{1D7F3}', '7'),
        ('\u{1D7F4}', '8'),
        ('\u{1D7F5}', '9'),
        // Roman numeral lookalikes
        ('\u{2160}', 'I'), // Ⅰ → I
        ('\u{2165}', 'V'), // Ⅵ → V (closest single-char visual match)
        // Script/mathematical letter lookalikes
        ('\u{2113}', 'l'), // ℓ SCRIPT SMALL L → l
        // Mathematical double-struck letters (ℕℚℝℤ) — not normalized by NFKC
        ('\u{2115}', 'N'), // ℕ → N
        ('\u{211A}', 'Q'), // ℚ → Q
        ('\u{211D}', 'R'), // ℝ → R
        ('\u{2124}', 'Z'), // ℤ → Z
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
/// A byte offset into the caller's original, un-normalized input.
///
/// `u32` rather than `usize` deliberately. The offset map holds one entry per
/// byte of normalized output, which makes it the largest allocation in the
/// scan path — larger than the text itself. On 64-bit, halving the element
/// width halves that: at the 10 MB input cap the map goes from ~80 MB to
/// ~40 MB, and every stage holds both an input and an output map at once.
///
/// Safe by construction: `MAX_INPUT_SIZE` is orders of magnitude below
/// `u32::MAX` (4 GiB), and normalization shrinks far more often than it grows.
/// `offset_fits` asserts the invariant rather than trusting it.
pub type Offset = u32;

/// One [`Offset`] per byte of normalized output.
pub type OffsetMap = Vec<Offset>;

/// Narrow a byte index to an [`Offset`].
///
/// Saturates rather than wrapping. A wrap would silently point a finding at
/// the wrong part of the document, which is worse than clamping to the last
/// addressable byte — and the debug assertion catches it in tests long before
/// an input that large could reach production.
#[inline]
fn to_offset(idx: usize) -> Offset {
    debug_assert!(
        idx <= Offset::MAX as usize,
        "offset {idx} exceeds Offset::MAX; input cap should have prevented this"
    );
    idx.min(Offset::MAX as usize) as Offset
}

pub fn strip_zero_width(text: &str) -> (String, OffsetMap) {
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
                offset_map.push(to_offset(byte_idx + i));
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
fn orig_offset(offsets: &[Offset], byte_idx: usize) -> Offset {
    if offsets.is_empty() || byte_idx >= offsets.len() {
        // Empty map means identity: the stage did not move anything.
        to_offset(byte_idx)
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
fn decode_percent_single(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    if !has_percent_encoding(bytes) {
        return None;
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
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
}

/// Decode URL percent-encoding with double-decode support (%25XX → %XX → char).
fn decode_percent_encoding(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    // If the first pass decodes nothing there is nothing for a second pass to
    // find either, so propagate "unchanged" straight out.
    let (first, first_off) = decode_percent_single(input, in_offsets)?;
    // Second pass catches double-encoding (%2541 → %41 → A). When it finds
    // nothing, the first pass's result still stands.
    Some(decode_percent_single(&first, &first_off).unwrap_or((first, first_off)))
}

/// Decode HTML numeric character references: decimal `&#NNN;` and hex `&#xHH;`.
fn decode_html_entities(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    if !input.contains("&#") {
        return None;
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
        return None;
    }

    Some((out, offsets))
}

/// Strip empty CSS comments (`/**/`) and empty HTML comments (`<!---->`) from text.
fn strip_comments(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let has_css = input.contains("/*");
    let has_html = input.contains("<!--");
    if !has_css && !has_html {
        return None;
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        // Strip /* ... */ CSS/C comments (including empty /**/).
        if has_css && i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let start = i;
            let mut j = i + 2;
            let mut found = false;
            while j + 1 < bytes.len() {
                if bytes[j] == b'*' && bytes[j + 1] == b'/' {
                    i = j + 2;
                    found = true;
                    break;
                }
                j += 1;
            }
            if !found {
                out.push(bytes[start]);
                offsets.push(orig_offset(in_offsets, start));
                i = start + 1;
            }
            continue;
        }
        // Strip <!-- ... --> HTML comments (including empty <!---->) .
        if has_html && i + 3 < bytes.len() && &bytes[i..i + 4] == b"<!--" {
            let start = i;
            let mut j = i + 4;
            let mut found = false;
            while j + 2 < bytes.len() {
                if &bytes[j..j + 3] == b"-->" {
                    i = j + 3;
                    found = true;
                    break;
                }
                j += 1;
            }
            if !found {
                out.push(bytes[start]);
                offsets.push(orig_offset(in_offsets, start));
                i = start + 1;
            }
            continue;
        }
        out.push(bytes[i]);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    if out.len() == bytes.len() {
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
}

/// Collapse whitespace padding between non-alphabetic characters.
///
/// Removes ASCII whitespace (space, tab, newline, CR) that appears between
/// two non-alphabetic characters (digits, punctuation, symbols). This defeats
/// evasion techniques like `1 2 3 - 4 5 - 6 7 8 9` while preserving natural
/// language spacing like `social security number`.
fn collapse_padding(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    if !bytes
        .iter()
        .any(|&b| b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
    {
        return None;
    }

    let is_ws = |c: u8| c == b' ' || c == b'\n' || c == b'\r' || c == b'\t';

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    // Last non-whitespace byte already emitted to `out` — i.e. the
    // "previous non-whitespace byte in output". Tracked incrementally
    // rather than rescanned, since dropped/kept whitespace never changes
    // it (the old reverse `find` skipped whitespace anyway).
    let mut prev_non_ws: Option<u8> = None;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if is_ws(b) {
            // Process the whole whitespace run at once. Both the previous
            // non-ws byte (constant during the run) and the next non-ws
            // byte (the first non-ws after the run) are identical for
            // every byte in the run, so the original per-byte drop
            // decision is uniform across the run — we compute it once.
            //
            // Perf: the previous implementation rescanned forward from
            // every whitespace byte to find the next non-ws, which is
            // O(k^2) for a run of length k and a remotely-triggerable DoS
            // on large whitespace-padded inputs (a 512 KiB space run took
            // ~86 s). Handling the run in one step makes this O(n).
            let run_start = i;
            let mut j = i;
            while j < bytes.len() && is_ws(bytes[j]) {
                j += 1;
            }
            let next_non_ws = bytes.get(j).copied();

            let drop_run = matches!(
                (prev_non_ws, next_non_ws),
                (Some(p), Some(n)) if !p.is_ascii_alphabetic() && !n.is_ascii_alphabetic()
            );

            if !drop_run {
                for (off, &byte) in bytes[run_start..j].iter().enumerate() {
                    out.push(byte);
                    offsets.push(orig_offset(in_offsets, run_start + off));
                }
            }
            i = j;
            continue;
        }
        out.push(b);
        offsets.push(orig_offset(in_offsets, i));
        prev_non_ws = Some(b);
        i += 1;
    }

    if out.len() == bytes.len() {
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
}

/// Normalize excessive delimiters between alphanumeric characters.
///
/// Collapses runs of repeated hyphens or dots (e.g. `123--45` → `123-45`)
/// only when surrounded by alphanumeric characters on both sides.
fn normalize_delimiters(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    // Cheap necessary condition, checked before allocating. This stage only
    // rewrites *runs* of two or more identical `-`/`.`, so text without a
    // doubled delimiter cannot change — and previously still paid for two
    // full-length vectors plus a byte-by-byte walk (~9 ms per MB) to find
    // that out.
    if !bytes
        .windows(2)
        .any(|w| (w[0] == b'-' || w[0] == b'.') && w[1] == w[0])
    {
        return None;
    }
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
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
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
    if !((1..=6).contains(&before) && (1..=6).contains(&after)) {
        return false;
    }
    // An ASCII letter bounding either digit run means the dot belongs to an
    // alphanumeric identifier (e.g. `D123.4567`, a driver-licence / part
    // number where the dot is structural), not a purely numeric group
    // separator like `4532.0151` — leave those dots intact. Hyphens in the
    // same identifiers are still stripped by the delimiter branch; only the
    // dot rule is this conservative because dots also delimit emails, hosts,
    // and version/ICD-10 codes.
    let before_run_start = pos - before;
    if before_run_start > 0 && bytes[before_run_start - 1].is_ascii_alphabetic() {
        return false;
    }
    let after_run_end = pos + 1 + after;
    if after_run_end < bytes.len() && bytes[after_run_end].is_ascii_alphabetic() {
        return false;
    }
    true
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

/// Mark dots belonging to a decimal coordinate pair
/// (`-?d{1,3}.d{4,8} , -?d{1,3}.d{4,8}`) so stage 6b leaves them alone.
///
/// Mirrors `mark_ipv4_dot_positions` and exists for the same reason.
/// Without it, `37.7749,-122.4194` normalizes to `377749,-1224194`, and the
/// `GPS Coordinates` pattern — which requires literal dots — can never fire.
/// That was a silent recall hole: the coordinate was destroyed before phase-1
/// ever saw it.
///
/// The shape is deliberately tight — the integer half is capped at 3 digits,
/// a comma between the two halves is mandatory, and both halves need 4-8
/// decimal places — so ordinary delimiter evasion (`4111.1111.1111.1111`,
/// which has four groups, no comma, and 4-digit integer parts) is unaffected.
fn mark_decimal_coord_dot_positions(bytes: &[u8]) -> Vec<bool> {
    let mut protected = vec![false; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        // Anchor only at the start of a candidate: a '-' or digit that isn't
        // continuing a longer numeric run.
        let fresh = i == 0 || (!bytes[i - 1].is_ascii_digit() && bytes[i - 1] != b'.');
        if fresh && (bytes[i] == b'-' || bytes[i].is_ascii_digit()) {
            if let Some(end) = try_match_coord_pair(bytes, i) {
                for (j, &b) in bytes.iter().enumerate().take(end).skip(i) {
                    if b == b'.' {
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

/// Match one `-?d{1,3}.d{4,8}` coordinate component starting at `start`.
/// Returns `Some(end)` (exclusive) on success.
fn try_match_coord_component(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    if pos < bytes.len() && bytes[pos] == b'-' {
        pos += 1;
    }
    let int_start = pos;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    if !(1..=3).contains(&(pos - int_start)) {
        return None;
    }
    if pos >= bytes.len() || bytes[pos] != b'.' {
        return None;
    }
    pos += 1;
    let frac_start = pos;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    if !(4..=8).contains(&(pos - frac_start)) {
        return None;
    }
    Some(pos)
}

/// Match a full `lat,lon` decimal coordinate pair starting at `start`.
fn try_match_coord_pair(bytes: &[u8], start: usize) -> Option<usize> {
    let mid = try_match_coord_component(bytes, start)?;
    if mid >= bytes.len() || bytes[mid] != b',' {
        return None;
    }
    let mut pos = mid + 1;
    // The GPS pattern allows an optional single space after the comma.
    if pos < bytes.len() && bytes[pos] == b' ' {
        pos += 1;
    }
    try_match_coord_component(bytes, pos)
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
fn strip_alnum_adjacent_delimiters(
    input: &str,
    in_offsets: &[Offset],
) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    if !bytes
        .iter()
        .any(|&b| b == b'-' || b == b'.' || b == b'/' || b == b'\\' || b == b'_')
    {
        return None;
    }

    let ip_dots = mark_ipv4_dot_positions(bytes);
    let coord_dots = mark_decimal_coord_dot_positions(bytes);

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets: OffsetMap = Vec::with_capacity(bytes.len());
    let mut changed = false;

    for i in 0..bytes.len() {
        let b = bytes[i];
        if b == b'.' && !ip_dots[i] && !coord_dots[i] && should_strip_dot(bytes, i) {
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
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
}

/// Returns `true` if `c` is a candidate "injected separator" character for
/// [`strip_consistent_digit_separators`]: any non-alphanumeric, non-whitespace
/// character that is NOT already handled by the dedicated delimiter stages
/// (`.`, `-`, `/`, `_`, `\`). Includes ASCII punctuation (`|`, `,`, `:`, `;`,
/// `~`, `+`, `=`, `*`, `#`, `@`, `$`, …) and non-ASCII symbols (e.g. U+00B7
/// MIDDLE DOT).
#[inline]
fn is_consistent_sep(c: char) -> bool {
    !c.is_ascii_alphanumeric() && !c.is_whitespace() && !matches!(c, '.' | '-' | '/' | '_' | '\\')
}

/// Returns `true` if `c` is a non-ASCII separator — i.e. an exotic Unicode
/// character that virtually never appears as a legitimate structured separator
/// (middle dot, bullet, dagger, etc.). A single occurrence of an exotic
/// separator is a reliable evasion signal, so [`strip_consistent_digit_separators`]
/// uses a lower repetition threshold for these than for ASCII punctuation.
#[inline]
fn is_exotic_sep(c: char) -> bool {
    !c.is_ascii() && is_consistent_sep(c)
}

/// Strip a single, *consistent* separator character injected between pure-digit
/// groups — the delimiter-injection and consistent-noise evasion families that
/// the dedicated delimiter stages don't cover.
///
/// Defeats (each with an identical separator repeated ≥ 3×):
///   * `4532|0151|1283|0366`  (pipe / `,` / `:` / `;` / `~` / `+` / `=` …)
///   * `4532*0151*1283*0366`  (asterisk / `#` / `@` / `$` consistent noise)
///   * `4532·0151·1283·0366`  (U+00B7 middle-dot, non-ASCII)
///
/// Deliberately conservative to protect legitimate text:
///   * the separator must be *identical* at every position — mixed noise like
///     `4532#0151@1283$0366` is left intact because inconsistency is not a
///     reliable evasion signal and stripping it would be guesswork;
///   * the separator may not be a digit, ASCII letter, or whitespace, and the
///     `.`/`-`/`/`/`_`/`\` characters are excluded (handled by
///     [`strip_alnum_adjacent_delimiters`], which carefully protects emails,
///     IPs, and ICD-10 codes);
///   * each digit group must be 1–6 digits, the separator must repeat ≥ 3
///     times, the concatenated run must be 12–40 digits, and the whole span
///     must be flanked by non-alphanumeric characters (never strip *inside* an
///     identifier);
///   * downstream checksum/Luhn validation still gates every resulting match.
fn strip_consistent_digit_separators(
    input: &str,
    in_offsets: &[Offset],
) -> Option<(String, OffsetMap)> {
    // Cheap necessary condition, checked *before* the two collects below.
    // Those materialise a `Vec<char>` (4 bytes/char) plus a `Vec<usize>` index
    // (8 bytes/char) — about 12 MB for a 1 MB input — and this stage only ever
    // acts on a `digit / consistent-separator / digit` triple. Scanning for
    // one first is allocation-free and skips ~9 ms per MB on text that has no
    // such triple (which includes most ordinary documents, since `.`, `-`,
    // `/`, `_` and `\` are deliberately excluded from `is_consistent_sep`).
    //
    // Only taken for all-ASCII input: a non-ASCII separator such as U+00B7 is
    // multi-byte, so a 3-byte window cannot see it and the text falls through
    // to the full path unchanged. `is_ascii` is a cheap vectorised check, and
    // the byte scan below is several times faster than walking `chars()` —
    // decoding UTF-8 per character costs more than the work it saves.
    if input.is_ascii()
        && !input.as_bytes().windows(3).any(|w| {
            w[0].is_ascii_digit()
                && w[2].is_ascii_digit()
                && !w[1].is_ascii_alphanumeric()
                && !w[1].is_ascii_whitespace()
                && !matches!(w[1], b'.' | b'-' | b'/' | b'_' | b'\\')
        })
    {
        return None;
    }

    // For all-ASCII input — nearly every real document — a character index is
    // a byte index, so neither of these vectors carries information the byte
    // slice does not already have. Building them anyway cost a `Vec<char>` (4
    // bytes/char) plus a `Vec<usize>` index map (8 bytes/char): ~12 MB for a
    // 1 MB input, allocated before the scan below decides whether there is
    // anything to strip (usually there is not). They are now built only for
    // genuinely non-ASCII input, where char and byte indices diverge.
    let ascii = input.is_ascii();
    let bytes = input.as_bytes();
    let cs: Vec<char> = if ascii {
        Vec::new()
    } else {
        input.chars().collect()
    };
    let starts: Vec<usize> = if ascii {
        Vec::new()
    } else {
        input.char_indices().map(|(b, _)| b).collect()
    };
    let n = if ascii { bytes.len() } else { cs.len() };
    // One scan body serves both paths; the branch is loop-invariant and
    // perfectly predicted, which is far cheaper than the allocation it avoids.
    let ch = |i: usize| -> char {
        if ascii {
            bytes[i] as char
        } else {
            cs[i]
        }
    };
    let start_of = |i: usize| -> usize {
        if ascii {
            i
        } else {
            starts[i]
        }
    };
    if n < 15 {
        // Shortest strippable span is 12 digits + 3 separators.
        return None;
    }
    let mut remove = vec![false; n];
    let mut any = false;

    let mut i = 0;
    while i < n {
        if !ch(i).is_ascii_digit() {
            i += 1;
            continue;
        }
        // Left boundary: never start mid-identifier (alphanumeric to the left).
        if i > 0 && ch(i - 1).is_ascii_alphanumeric() {
            while i < n && ch(i).is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        // First digit group.
        let mut j = i;
        while j < n && ch(j).is_ascii_digit() {
            j += 1;
        }
        let first_len = j - i;
        if !((1..=6).contains(&first_len) && j < n && is_consistent_sep(ch(j))) {
            i = j.max(i + 1);
            continue;
        }
        let sep = ch(j);
        let mut sep_positions: Vec<usize> = Vec::new();
        let mut total_digits = first_len;
        let mut groups_ok = true;
        let mut k = j;
        loop {
            if k < n && ch(k) == sep {
                let g = k + 1;
                let mut m = g;
                while m < n && ch(m).is_ascii_digit() {
                    m += 1;
                }
                let glen = m - g;
                if glen == 0 {
                    break; // trailing separator with no following digit group
                }
                if !(1..=6).contains(&glen) {
                    groups_ok = false;
                    break;
                }
                sep_positions.push(k);
                total_digits += glen;
                k = m;
            } else {
                break;
            }
        }
        // Right boundary must not continue into an identifier.
        let right_ok = k >= n || !ch(k).is_ascii_alphanumeric();
        // Non-ASCII (exotic) separators almost never appear in legitimate data,
        // so a single occurrence is sufficient signal. ASCII punctuation keeps
        // the conservative ≥3 threshold to avoid stripping e.g. 0151:1283:0366.
        let min_seps: usize = if is_exotic_sep(sep) { 2 } else { 3 };
        if groups_ok
            && right_ok
            && sep_positions.len() >= min_seps
            && (12..=40).contains(&total_digits)
        {
            for &p in &sep_positions {
                remove[p] = true;
            }
            any = true;
        }
        i = k.max(i + 1);
    }

    if !any {
        return None;
    }

    let mut out = String::with_capacity(input.len());
    let mut offsets: OffsetMap = Vec::with_capacity(input.len());
    for (idx, &dropped) in remove.iter().enumerate() {
        if dropped {
            continue;
        }
        let c = ch(idx);
        let byte_idx = start_of(idx);
        out.push(c);
        for b in 0..c.len_utf8() {
            offsets.push(orig_offset(in_offsets, byte_idx + b));
        }
    }
    Some((out, offsets))
}

/// Strip zero-width characters with offset composition.
fn remap_strip_zero_width(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let has_zw = input.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c));
    if !has_zw {
        return None;
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

    Some((result, offsets))
}

/// Decode hex-spaced byte sequences: `34 35 33 32` → `4532`.
///
/// Heuristic: if the text looks like space-separated pairs of hex digits
/// (at least 3 pairs), decode them to ASCII.
fn decode_hex_spaced(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    // Quick check: need at least "XX XX XX" = 8 chars
    if bytes.len() < 8 {
        return None;
    }

    // Cheap necessary condition, checked before allocating: a hex-spaced run
    // needs at least `XX SP XX`. Mirrors the same window test
    // `has_evasion_markers` uses to route text here in the first place, so a
    // document that reached this stage for some *other* marker no longer pays
    // a full allocate-and-walk (~9 ms per MB) to discover there is no hex.
    if !bytes.windows(5).any(|w| {
        w[0].is_ascii_hexdigit()
            && w[1].is_ascii_hexdigit()
            && w[2] == b' '
            && w[3].is_ascii_hexdigit()
            && w[4].is_ascii_hexdigit()
    }) {
        return None;
    }

    // Scan for runs of hex-space-hex patterns
    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;
    // Reused across candidate runs rather than allocated per candidate.
    //
    // Most candidates are rejected below by the `pairs.len() >= 3` test, and
    // ordinary English trips this matcher constantly: any word ending in two
    // hex letters followed by a space and a number opens a candidate, so
    // "dated 2024" scans as `ed 20`. A fresh `Vec` per candidate meant 1 MB of
    // such prose performed ~21,000 heap allocations that were populated with
    // two entries and immediately discarded — against ~24 allocations for the
    // whole rest of the pipeline.
    let mut pairs: Vec<(usize, u8)> = Vec::new();

    while i < bytes.len() {
        // Try to match a hex-spaced run: XX SP XX SP XX ...
        // A run may only begin at a token boundary (start of input or just
        // after a space). Without this, a run could start in the middle of a
        // longer digit group: `457 55 5462` starting at offset 1 reads
        // `57 55 54` as three pairs and decodes an SSN to `WUT`. See the
        // per-pair token check below for the other half of this guard.
        let at_left_boundary = i == 0 || bytes[i - 1] == b' ';
        if at_left_boundary
            && i + 4 < bytes.len()
            && bytes[i].is_ascii_hexdigit()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2] == b' '
            && bytes[i + 3].is_ascii_hexdigit()
            && bytes[i + 4].is_ascii_hexdigit()
        {
            // Count how many hex pairs follow
            let run_start = i;
            pairs.clear();
            loop {
                // Each pair must be a *complete* space-delimited token: exactly
                // two hex digits bounded by a space (or string end) on the
                // right. The left side is already a boundary — the run starts at
                // one and every subsequent pair begins right after the mandatory
                // space. Requiring the right boundary too is what separates a
                // real hex dump (`34 35 33 32`, every token two chars) from
                // formatted decimal data (`457 55 5462`, groups of 3/2/4): a
                // 3-char group like `457` or `567` offers two hex digits but is
                // not a 2-char token, so it never contributes a pair.
                let has_pair = i + 1 < bytes.len()
                    && bytes[i].is_ascii_hexdigit()
                    && bytes[i + 1].is_ascii_hexdigit();
                let right_boundary = i + 2 >= bytes.len() || bytes[i + 2] == b' ';
                if has_pair && right_boundary {
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
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
}

/// Decode `\xHH` hex-escape sequences (e.g. `\x31\x32\x33` → `123`).
///
/// Only replaces sequences where both digits are valid hex and the decoded byte
/// is printable ASCII (0x20–0x7E). Other sequences are passed through unchanged.
fn decode_hex_escapes(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    if !bytes.windows(2).any(|w| w[0] == b'\\' && w[1] == b'x') {
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut offsets: OffsetMap = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                let decoded = (hi << 4) | lo;
                if (0x20..=0x7E).contains(&decoded) {
                    out.push(decoded);
                    offsets.push(orig_offset(in_offsets, i));
                    i += 4;
                    continue;
                }
            }
        }
        // Copy the raw byte through unchanged. Buffering into a Vec<u8>
        // and finishing with from_utf8_lossy (as every other byte-level
        // stage does) preserves multibyte UTF-8 sequences verbatim. The
        // previous `String::push(bytes[i] as char)` reinterpreted any
        // byte >= 0x80 as a Latin-1 code point that re-encodes to two
        // UTF-8 bytes, which both mojibake-corrupted non-ASCII input and
        // desynced the offset map (two output bytes for one offset entry).
        // One offset entry per input byte keeps the map byte-aligned.
        out.push(bytes[i]);
        offsets.push(orig_offset(in_offsets, i));
        i += 1;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
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
    // Reject immediately if decoded bytes contain any C0 control character
    // other than tab (0x09), line-feed (0x0A), or carriage-return (0x0D).
    // These (especially NUL/0x00 and ENQ/0x05) are never present in
    // meaningful encoded text, but DO appear when a digit-only string (like
    // a credit-card number) is incorrectly decoded as hex bytes.
    if decoded_bytes
        .iter()
        .any(|&b| b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F)
    {
        return None;
    }
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
fn decode_encoded_tokens(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut offsets: OffsetMap = Vec::with_capacity(bytes.len());
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
        return None;
    }

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
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

    // Quick check: morse code only contains '.', '-', ' ', '/', '|', ',', ':'
    if !trimmed.bytes().all(|b| {
        b == b'.' || b == b'-' || b == b' ' || b == b'/' || b == b'|' || b == b',' || b == b':'
    }) {
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
    } else if trimmed.contains(':') {
        trimmed.split(':').collect()
    } else if trimmed.contains(',') {
        // Comma-separated: chars within each word split by comma
        // (evadex comma_sep variant)
        let parts: Vec<&str> = trimmed.split(',').collect();
        // If comma-separated, we treat each token as a char (no nested word separator)
        // Single-pass: just split on commas and treat each as a char code
        return {
            let mut r = String::new();
            let mut decoded = 0usize;
            for symbol in parts.iter().filter(|s| !s.trim().is_empty()) {
                let sym = symbol.trim();
                if let Some(&ch) = MORSE_TABLE.get(sym) {
                    r.push(ch);
                    decoded += 1;
                } else {
                    return None;
                }
            }
            if decoded < 3 {
                None
            } else {
                Some(r)
            }
        };
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
        } else if token.iter().all(|&b| b.is_ascii_alphabetic()) {
            // All-alpha token: literal passthrough.  Stage 6b
            // (strip_alnum_adjacent_delimiters) merges adjacent alpha chars
            // separated by slashes (e.g. G/B → GB, W/E/S/T → WEST) before
            // alt-decodings run, so a multi-char all-alpha token is a valid
            // pass-through in IBAN country-code / bank-code position.
            for &b in *token {
                result.push(b as char);
            }
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

/// Decode evadex-style digit-only morse with comma `','` separator.
///
/// Same semantics as `try_decode_digit_morse_slash` but uses comma as
/// the field separator.  The comma is the evadex `comma_sep` encoding.
fn try_decode_digit_morse_comma(text: &str) -> Option<String> {
    if !text.is_ascii() || !text.contains(',') {
        return None;
    }
    if !text.bytes().any(|b| b == b'.' || b == b'-') {
        return None;
    }

    let raw = text.as_bytes();
    let tokens: Vec<&[u8]> = raw
        .split(|&b| b == b',')
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.len() < 4 {
        return None;
    }

    let mut result = String::with_capacity(tokens.len());
    let mut digit_count = 0usize;

    for token in &tokens {
        if let Some(ch) = decode_morse_digit_token(token) {
            result.push(ch);
            digit_count += 1;
        } else if token.len() == 1 && token[0].is_ascii() {
            result.push(token[0] as char);
        } else if token.iter().all(|&b| b.is_ascii_alphabetic()) {
            for &b in *token {
                result.push(b as char);
            }
        } else {
            if let Ok(s) = std::str::from_utf8(token) {
                if let Some(&ch) = MORSE_TABLE.get(s) {
                    result.push(ch);
                } else {
                    return None;
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
    // Trim ASCII whitespace: a trailing \n from piped input survives
    // collapse_padding (no next non-WS neighbour) and must not invalidate
    // an otherwise-valid no-separator morse sequence.
    let start = text
        .iter()
        .position(|&b| !is_ascii_ws(b))
        .unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|&b| !is_ascii_ws(b))
        .map(|i| i + 1)
        .unwrap_or(0);
    let text = if end > start { &text[start..end] } else { &[] };
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

/// Scan text for an embedded no-separator digit-only morse segment.
///
/// Unlike `try_decode_digit_morse_nosep` which requires the ENTIRE input to be
/// morse, this function finds maximal runs of '.' and '-' embedded within a
/// larger text (e.g., text with a prepended filename context line) and tries to
/// decode each candidate segment.  Used in the alt-decodings pass so that
/// file-scan paths that prepend filename preamble don't break morse detection.
///
/// Decoding constraints are identical to `try_decode_digit_morse_nosep`:
/// length must be an exact multiple of 5, every 5-char chunk must be a valid
/// digit morse code, and the digit count must be in 4..=20.
fn find_embedded_digit_morse_nosep(text: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'.' || text[i] == b'-' {
            let seg_start = i;
            while i < text.len() && (text[i] == b'.' || text[i] == b'-') {
                i += 1;
            }
            let segment = &text[seg_start..i];
            if segment.len().is_multiple_of(5) {
                let count = segment.len() / 5;
                if (4..=20).contains(&count) {
                    let mut result = String::with_capacity(count);
                    let mut valid = true;
                    for chunk in segment.chunks_exact(5) {
                        match MORSE_DIGITS.iter().find(|(code, _)| *code == chunk) {
                            Some(&(_, digit)) => result.push(digit as char),
                            None => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if valid {
                        return Some(result);
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Scan `text` for an embedded run of digit-only morse tokens joined by a single
/// consistent delimiter `delim` (one of `/`, `,`, `|`) and decode it.
///
/// This is the delimited analogue of [`find_embedded_digit_morse_nosep`]. The
/// whole-input decoders [`try_decode_digit_morse_slash`] /
/// [`try_decode_digit_morse_comma`] bail as soon as any non-morse text pollutes
/// a token, so a filename preamble or surrounding prose (e.g. the file-scan path
/// that prepends `invoice.txt\n` before the payload, or a `card ` prefix)
/// defeats them — even though the nosep path already tolerates exactly that.
/// This closes that asymmetry for the delimited variants.
///
/// A candidate run is a maximal sequence `TOKEN (DELIM TOKEN)*` where every
/// `TOKEN` is a run of `.`/`-` and `DELIM` is `delim` throughout. The run is
/// accepted only when it holds 4..=20 tokens and **every** token is a valid
/// 5-char digit morse code — the same low-false-positive constraints as the
/// nosep embedded scan (Luhn/checksum still gates the decoded digits downstream).
fn find_embedded_digit_morse_delimited(text: &str, delim: u8) -> Option<String> {
    if !text.is_ascii() {
        return None;
    }
    let raw = text.as_bytes();
    let is_morse = |b: u8| b == b'.' || b == b'-';
    let mut i = 0;
    while i < raw.len() {
        if !is_morse(raw[i]) {
            i += 1;
            continue;
        }
        // Walk a maximal `TOKEN (DELIM TOKEN)*` run starting at `i`.
        let run_start = i;
        let mut tokens: Vec<&[u8]> = Vec::new();
        let mut j = i;
        loop {
            let tok_start = j;
            while j < raw.len() && is_morse(raw[j]) {
                j += 1;
            }
            tokens.push(&raw[tok_start..j]);
            // Continue only across a single `delim` that is followed by another
            // morse token; anything else terminates the run.
            if j + 1 < raw.len() && raw[j] == delim && is_morse(raw[j + 1]) {
                j += 1;
            } else {
                break;
            }
        }
        if (4..=20).contains(&tokens.len()) {
            let mut result = String::with_capacity(tokens.len());
            let mut ok = true;
            for token in &tokens {
                match decode_morse_digit_token(token) {
                    Some(ch) => result.push(ch),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Some(result);
            }
        }
        // Advance past this run (guaranteed progress: j > run_start).
        i = j.max(run_start + 1);
    }
    None
}

/// Apply ROT13 transformation to alphabetic characters.
/// `apply_rot13` reports `None` when the input holds no letters to rotate.
/// The alt-decoding callers below want the rotated text either way, so this
/// collapses "unchanged" back to an owned copy of the original for them.
fn rot13_or_same(text: &str) -> String {
    apply_rot13(text, &[])
        .map(|(s, _)| s)
        .unwrap_or_else(|| text.to_string())
}

fn apply_rot13(input: &str, in_offsets: &[Offset]) -> Option<(String, OffsetMap)> {
    let bytes = input.as_bytes();
    // Only apply if text has letters (no point on pure digits)
    if !bytes.iter().any(|b| b.is_ascii_alphabetic()) {
        return None;
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

    Some((String::from_utf8_lossy(&out).into_owned(), offsets))
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
pub fn normalize_text(text: &str) -> (String, OffsetMap) {
    // Fast path: pure ASCII with no evasion markers
    let ascii = is_ascii_only(text);
    if ascii && !has_evasion_markers(text) {
        return (text.to_string(), Vec::new());
    }

    let mut current = text.to_string();
    let mut offsets: OffsetMap = Vec::new(); // empty = identity mapping

    // Helper macro: adopt a stage's output only when the stage actually
    // changed something.
    //
    // Stages return `None` for "unchanged". That matters far more than it
    // looks: the offset map is one `usize` per input byte, so it is 8x the
    // size of the text itself, and a stage that cloned it just to report no
    // change cost ~9 MB of memcpy per megabyte scanned. With 13 stages and 19
    // such bail-out points, normalising 1 MB of ordinary text (anything
    // holding a date or a parenthesised number takes this path) allocated
    // ~130 MB — and a max-size 10 MB input extrapolated to ~1.3 GB of
    // transient allocation for a single scan, which is an OOM surface under
    // concurrent load rather than merely slow.
    macro_rules! apply_stage {
        ($fn:ident, $current:expr, $offsets:expr) => {{
            if let Some((s, o)) = $fn(&$current, &$offsets) {
                $current = s;
                $offsets = o;
            }
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
    apply_stage!(decode_hex_escapes, current, offsets);

    // Stage 4c: Token-level encoded-data decode (base64, base32, hex)
    //
    // Runs up to 3 iterations to handle nested encoding (e.g., base64
    // of base64, or base64 of hex). Each iteration finds and decodes
    // tokens; if nothing changed, the loop stops early. The 3-iteration
    // cap prevents infinite loops on pathological input.
    //
    // This runs BEFORE collapse_padding so the decoded result gets the
    // same whitespace/delimiter normalization as everything else.
    // `None` now reports "nothing decoded" directly, which also retires the
    // full `r.0 == current` string comparison this loop used to run on every
    // iteration to discover the same fact.
    for _decode_iteration in 0..3 {
        match decode_encoded_tokens(&current, &offsets) {
            Some((s, o)) => {
                current = s;
                offsets = o;
            }
            None => break, // No more decoding possible
        }
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

    // Stage 6c: Strip a consistent separator injected between digit groups.
    // Covers the delimiter families the previous stages don't (`|`, `,`, `:`,
    // `;`, `~`, `+`, `=`) and consistent-noise evasion (`4532*0151*1283*0366`,
    // including non-ASCII separators like U+00B7). Conservative: identical
    // separator repeated ≥3× between 12–40 digits only.
    apply_stage!(strip_consistent_digit_separators, current, offsets);

    // Stages 7-10: Unicode normalization (only if non-ASCII remaining)
    if !is_ascii_only(&current) {
        // Stage 7: Strip zero-width characters
        apply_stage!(remap_strip_zero_width, current, offsets);

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

        // Stage 10: Homoglyph map, with a Unicode decimal-digit (Nd) fallback
        // so *every* digit script folds to ASCII (Devanagari, Bengali, Tamil,
        // …), not just the handful hard-coded in HOMOGLYPH_MAP.
        let r = remap_char_transform(&current, &offsets, |c| {
            if let Some(&mapped) = HOMOGLYPH_MAP.get(&c) {
                mapped
            } else if let Some(d) = fold_unicode_digit(c) {
                d
            } else {
                c
            }
        });
        current = r.0;
        offsets = r.1;
    }

    // Stage 11: Fold digit-confusable letters (Latin/Greek/Cyrillic O→0, l→1,
    // …) that sit inside a long, digit-dense run — homoglyph/leet substitution
    // inside a candidate card/account number (e.g. `4532O151l283O366`). This
    // runs OUTSIDE the `!is_ascii_only` block above because the substituted
    // letters are themselves ASCII, so Stage 10 would never see them.
    apply_stage!(fold_confusable_digit_runs, current, offsets);

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
/// Decode evadex-style morse where digit chars are nosep-encoded and non-digit
/// ASCII chars (letters, hyphens, etc.) pass through literally, with both
/// types directly adjacent or separated by spaces.
///
/// Handles IBAN-style values (e.g. "GB82WEST12345698765432") after evadex
/// space-sep or no-sep encoding and normalize_text's collapse_padding:
///   "G B---....---W E S T.----..---...--..."  → "GB82WEST12345698765432"
///
/// Constraints:
/// - Input must contain at least one morse symbol (`.` or `-`) AND one alpha letter.
/// - Contiguous runs of `.`/`-` must have length divisible by 5; each 5-char
///   chunk must be a valid ITU-R digit code.
/// - At least 4 digits must be decoded to avoid false positives on short noise.
/// - Any character that is not a space, ASCII alpha, or `.`/`-` causes failure.
fn try_decode_mixed_alpha_nosep(text: &str) -> Option<String> {
    let bytes = text.as_bytes();

    // Require at least one morse symbol AND at least one alpha letter.
    // Without alpha: use try_decode_digit_morse_nosep instead.
    // Without morse: this isn't morse at all.
    if !bytes.iter().any(|&b| b == b'.' || b == b'-') {
        return None;
    }
    if !bytes.iter().any(|b| b.is_ascii_alphabetic()) {
        return None;
    }

    let mut result = String::with_capacity(text.len());
    let mut digit_count = 0usize;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' {
            i += 1;
            continue;
        }
        if b.is_ascii_alphabetic() {
            result.push(b as char);
            i += 1;
            continue;
        }
        if b == b'.' || b == b'-' {
            let seg_start = i;
            while i < bytes.len() && (bytes[i] == b'.' || bytes[i] == b'-') {
                i += 1;
            }
            let segment = &bytes[seg_start..i];
            if segment.is_empty() || !segment.len().is_multiple_of(5) {
                return None;
            }
            for chunk in segment.chunks_exact(5) {
                match MORSE_DIGITS.iter().find(|(code, _)| *code == chunk) {
                    Some(&(_, digit)) => {
                        result.push(digit as char);
                        digit_count += 1;
                    }
                    None => return None,
                }
            }
            continue;
        }
        // Unknown character — not a valid mixed-alpha-nosep morse input
        return None;
    }

    if digit_count < 4 {
        return None;
    }
    Some(result)
}

/// Recover a case-folded base64 token that encodes a purely numeric secret
/// (credit-card / SSN / bank-account numbers).
///
/// Base64 is case-sensitive, so upper-, lower-, or mixed-casing an encoded blob
/// corrupts a standard decode — this is the `base64_mixed_case` (and
/// `base64_uppercase` / `base64_lowercase`) evasion family. But base64 decodes
/// in independent 4-symbol → 3-byte blocks, and when the *plaintext* is all
/// ASCII digits there is (almost always) exactly one assignment of upper/lower
/// case to each letter in a block that yields three digit bytes. We enumerate
/// the ≤2⁴ case combinations per block, keep those whose bytes are all digits,
/// and return the cartesian product as candidate digit strings for the caller
/// to re-scan (Luhn / checksum validation still gates every match).
///
/// Returns an empty vec unless the token could plausibly be a case-folded
/// numeric payload. Bounded: token ≤ 64 chars, ≤ `MAX_CANDIDATES` results.
fn recover_case_folded_base64_digits(token: &str) -> Vec<String> {
    const MAX_LEN: usize = 64;
    const MAX_CANDIDATES: usize = 16;

    if token.len() > MAX_LEN {
        return Vec::new();
    }
    let stripped = token.trim_end_matches('=');
    // Need at least 16 base64 symbols (≈12 decoded digits) to be worth it, and
    // a valid base64 body length is never ≡1 (mod 4).
    if stripped.len() < 16 || stripped.len() % 4 == 1 {
        return Vec::new();
    }
    let sym = stripped.as_bytes();
    if sym
        .iter()
        .any(|&b| !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/'))
    {
        return Vec::new();
    }

    // Candidate 6-bit value(s) per symbol. Letters carry two candidates (their
    // upper-case value 0–25 and lower-case value 26–51); everything else one.
    let opts: Vec<[Option<u8>; 2]> = sym
        .iter()
        .map(|&b| {
            if b.is_ascii_alphabetic() {
                let up = b.to_ascii_uppercase() - b'A';
                let lo = (b.to_ascii_lowercase() - b'a') + 26;
                [Some(up), Some(lo)]
            } else if b.is_ascii_digit() {
                [Some(52 + (b - b'0')), None]
            } else if b == b'+' {
                [Some(62), None]
            } else {
                [Some(63), None] // '/'
            }
        })
        .collect();

    // Solve block-by-block (base64 blocks are independent).
    let mut per_block: Vec<Vec<String>> = Vec::new();
    let mut idx = 0;
    while idx < opts.len() {
        let end = (idx + 4).min(opts.len());
        let block = &opts[idx..end];
        let bn = block.len();
        let choice_positions: Vec<usize> = (0..bn).filter(|&p| block[p][1].is_some()).collect();
        let combos = 1usize << choice_positions.len();
        let mut block_strs: Vec<String> = Vec::new();
        for mask in 0..combos {
            let mut vals = [0u8; 4];
            for (p, slot) in vals.iter_mut().enumerate().take(bn) {
                let sel = choice_positions
                    .iter()
                    .position(|&c| c == p)
                    .map(|bit| (mask >> bit) & 1)
                    .unwrap_or(0);
                *slot = block[p][sel].unwrap();
            }
            let out_bytes: Vec<u8> = match bn {
                4 => vec![
                    (vals[0] << 2) | (vals[1] >> 4),
                    ((vals[1] & 0x0f) << 4) | (vals[2] >> 2),
                    ((vals[2] & 0x03) << 6) | vals[3],
                ],
                3 => vec![
                    (vals[0] << 2) | (vals[1] >> 4),
                    ((vals[1] & 0x0f) << 4) | (vals[2] >> 2),
                ],
                2 => vec![(vals[0] << 2) | (vals[1] >> 4)],
                _ => Vec::new(),
            };
            if !out_bytes.is_empty() && out_bytes.iter().all(|b| b.is_ascii_digit()) {
                let s: String = out_bytes.iter().map(|&b| b as char).collect();
                if !block_strs.contains(&s) {
                    block_strs.push(s);
                }
            }
        }
        if block_strs.is_empty() {
            return Vec::new(); // this block can't be all-digits → token isn't numeric
        }
        per_block.push(block_strs);
        idx = end;
    }

    // Bounded cartesian product of the per-block digit strings.
    let mut results: Vec<String> = vec![String::new()];
    for block_strs in &per_block {
        let mut next: Vec<String> = Vec::new();
        'outer: for prefix in &results {
            for bs in block_strs {
                next.push(format!("{prefix}{bs}"));
                if next.len() >= MAX_CANDIDATES {
                    break 'outer;
                }
            }
        }
        results = next;
    }
    results.retain(|s| s.len() >= 12);
    results.sort();
    results.dedup();
    results
}

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
    let rot = rot13_or_same(text);
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
    } else if let Some(decoded) = find_embedded_digit_morse_delimited(text, b'/') {
        // Fallback: slash-morse embedded in surrounding text (filename preamble,
        // prose prefix) — the whole-input decoder above bails on the first
        // polluted token, mirroring the nosep embedded fallback below.
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    // Evadex-style digit-only morse: comma-separated (evadex comma_sep variant).
    if let Some(decoded) = try_decode_digit_morse_comma(text) {
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    } else if let Some(decoded) = find_embedded_digit_morse_delimited(text, b',') {
        // Fallback: comma-morse embedded in surrounding text.
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    // Pipe-separated digit morse embedded in surrounding text. The full-alphabet
    // decode_morse() handles bare pipe-morse, but bails on any non-morse prefix;
    // no whole-input digit decoder covers pipe, so this is the only digit path
    // that tolerates a preamble for the pipe variant.
    if let Some(decoded) = find_embedded_digit_morse_delimited(text, b'|') {
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    // Evadex-style digit-only morse: comma-separated (evadex comma_sep variant).
    if let Some(decoded) = try_decode_digit_morse_comma(text) {
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
    } else {
        // Fallback: scan for embedded morse segments within a larger text.
        // Handles the file-scan path where a filename preamble is prepended to
        // the text before scanning (pipeline.process_file prepends filename
        // context words followed by \n, which breaks the pure-bytes check above).
        if let Some(decoded) = find_embedded_digit_morse_nosep(text.as_bytes()) {
            push_if_room(decoded, &mut alternatives, &mut total_bytes);
        }
    }

    // Mixed alpha + nosep digit-morse decoder. Handles IBAN-style values where
    // non-digit characters (country code letters, bank code) pass through
    // literally and digit characters are nosep-encoded. After collapse_padding
    // the space-sep and newline-sep variants collapse to this mixed form:
    //   "G B---....---W E S T.----..---..." → "GB82WEST12345698765432"
    if let Some(decoded) = try_decode_mixed_alpha_nosep(text) {
        push_if_room(decoded, &mut alternatives, &mut total_bytes);
    }

    // Two-stage encoding chain: base64 → ROT13.
    // Covers the evasion pattern base64(rot13(secret)) where the primary
    // normalization pipeline decodes the base64 wrapper and the alt pass
    // then needs to strip the inner ROT13.  The existing ROT13 alt above
    // handles rot13(data) that survived to the normalized text; this
    // explicitly generates rot13(b64decode(text)) for the case where the
    // *normalised* text is still base64-encoded (e.g. the token-splitter
    // didn't fire because it was embedded mid-sentence with no whitespace).
    if let Some(b64_decoded) = try_decode_base64(text) {
        let rot_of_b64 = rot13_or_same(&b64_decoded);
        // Only emit the chain result when ROT13 actually transformed the
        // decoded bytes. If the payload has no letters (e.g. a pure-digit
        // SSN/PAN), ROT13 is a no-op and `rot_of_b64` collapses to a plain
        // single-layer base64 decode — which belongs to the normalization
        // pipeline (stage 4c), not the alt-decodings pass. Emitting it here
        // would re-introduce raw base64 output that stage 4c already covers.
        if rot_of_b64 != b64_decoded {
            push_if_room(rot_of_b64, &mut alternatives, &mut total_bytes);
        }
    }

    // Two-stage encoding chain: ROT13 → base64.
    // Covers rot13(base64(secret)): ROT13 the outer shell to recover
    // base64, then the scanner's per-alt normalize_text call decodes
    // the base64.  The first-pass ROT13 alt already produces rot13(text)
    // and the alt-norm step runs normalize_text on it, but that only
    // works when the full text is a clean base64 blob.  This explicit
    // step handles the mixed-content case where rot13(base64(token)) is
    // embedded among other text and the token-splitter can isolate it.
    {
        let rot_text = rot13_or_same(text);
        if let Some(b64_decoded) = try_decode_base64(&rot_text) {
            push_if_room(b64_decoded, &mut alternatives, &mut total_bytes);
        }
        // Also push rot_text itself if not already added (ROT13 alt above
        // already did this, push_if_room de-dups via != text check).
        push_if_room(rot_text, &mut alternatives, &mut total_bytes);
    }

    // Two-stage encoding chain: hex → base64.
    // Covers hex(base64(secret)) where the outer hex is already stripped
    // by stage 4c but the intermediate base64 layer may not have been
    // reached in a single normalize pass when the hex content is short
    // enough to be treated as a literal token.
    if let Some(hex_decoded) = try_decode_hex(text) {
        if let Some(b64_decoded) = try_decode_base64(&hex_decoded) {
            push_if_room(b64_decoded, &mut alternatives, &mut total_bytes);
        }
        push_if_room(hex_decoded, &mut alternatives, &mut total_bytes);
    }

    // Case-folded base64 of a numeric secret (`base64_mixed_case` /
    // `_uppercase` / `_lowercase`). Recover the original digits per 4-symbol
    // block. Also try the ROT13 shell so `base64_then_rot13` mixed-case is
    // covered: rot13(rot13(base64)) restores the base64 letters (with folded
    // case) which then recovers the same way.
    let rot_text = rot13_or_same(text);
    for src in [text.trim(), rot_text.trim()] {
        for recovered in recover_case_folded_base64_digits(src) {
            push_if_room(recovered, &mut alternatives, &mut total_bytes);
        }
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
    // Consistent separator injected between digit groups (e.g.
    // `4532|0151|1283|0366`, `4532*0151*1283*0366`). Cheap ASCII byte scan:
    // the same non-alphanumeric, non-whitespace separator flanked by ASCII
    // digits appearing ≥3× enters the pipeline for
    // `strip_consistent_digit_separators`. Non-ASCII separators (U+00B7 …)
    // fail `is_ascii_only` and enter the pipeline anyway. `.`/`-`/`/`/`_`/`\`
    // are excluded here (handled by the dedicated delimiter stages/markers).
    if bytes.len() >= 15 {
        let mut counts = [0u8; 128];
        for w in bytes.windows(3) {
            let s = w[1];
            if w[0].is_ascii_digit()
                && w[2].is_ascii_digit()
                && s < 128
                && !s.is_ascii_alphanumeric()
                && s != b' '
                && s != b'\t'
                && s != b'\n'
                && s != b'\r'
                && !matches!(s, b'.' | b'-' | b'/' | b'_' | b'\\')
            {
                counts[s as usize] = counts[s as usize].saturating_add(1);
                if counts[s as usize] >= 3 {
                    return true;
                }
            }
        }
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
    input_offsets: &[Offset],
    transform: impl Fn(char) -> char,
) -> (String, OffsetMap) {
    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        let replacement = transform(ch);
        output.push(replacement);

        // The original offset for this input char's first byte
        let orig_start = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            to_offset(byte_idx)
        };

        // Map each byte of the output char to the original offset
        for _ in 0..replacement.len_utf8() {
            output_offsets.push(orig_start);
        }
    }

    (output, output_offsets)
}

/// Fold any Unicode decimal digit (general category Nd) to its ASCII
/// equivalent. Rather than hand-maintaining a 10-entry table per script (the
/// old approach in `HOMOGLYPH_MAP`, which covered only Arabic/Thai and let
/// Devanagari, Bengali, Tamil, … through), this walks the fixed set of Nd
/// block starts — the "zero" code point of each contiguous 0–9 run — so a new
/// digit script never needs a code change. `char::to_digit` is not usable
/// here: it only understands ASCII digits and a–z.
fn fold_unicode_digit(c: char) -> Option<char> {
    // ASCII digits are already canonical; skip the scan.
    if c.is_ascii() {
        return None;
    }
    // Start code point ("digit zero") of every Unicode Nd block, ascending.
    const ZERO_BASES: &[u32] = &[
        0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
        0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0,
        0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0,
        0xAA50, 0xABF0, 0xFF10, // Supplementary planes
        0x1_04A0, 0x1_0D30, 0x1_1066, 0x1_10F0, 0x1_1136, 0x1_11D0, 0x1_12F0, 0x1_1450, 0x1_14D0,
        0x1_1650, 0x1_16C0, 0x1_1730, 0x1_18E0, 0x1_1950, 0x1_1C50, 0x1_1D50, 0x1_1DA0, 0x1_1F50,
        0x1_6A60, 0x1_6AC0, 0x1_6B50, 0x1_D7CE, 0x1_D7D8, 0x1_D7E2, 0x1_D7EC, 0x1_D7F6, 0x1_E140,
        0x1_E2F0, 0x1_E4F0, 0x1_E950, 0x1_FBF0,
    ];
    let cp = c as u32;
    for &base in ZERO_BASES {
        if base > cp {
            break; // list is sorted ascending; no later block can match
        }
        if cp <= base + 9 {
            return Some((b'0' + (cp - base) as u8) as char);
        }
    }
    None
}

/// Letters/symbols that visually stand in for a digit. These fold to a digit
/// ONLY inside a long, digit-dense run (see `fold_confusable_digit_runs`) —
/// folding every 'O' → '0' unconditionally would wreck ordinary prose, so the
/// caller gates on run length and digit density.
#[inline]
fn confusable_to_digit(c: char) -> Option<char> {
    match c {
        // zero look-alikes: Latin O/o, Greek omicron Ο/ο, Cyrillic O/о
        'O' | 'o' | '\u{039F}' | '\u{03BF}' | '\u{041E}' | '\u{043E}' => Some('0'),
        // one look-alikes: Latin l/I/i, bar, Greek Iota Ι, Cyrillic Byelo-Ukr І
        'l' | 'I' | 'i' | '|' | '\u{0399}' | '\u{0406}' => Some('1'),
        _ => None,
    }
}

#[inline]
fn is_digit_run_member(c: char) -> bool {
    c.is_ascii_digit() || confusable_to_digit(c).is_some()
}

/// Fold digit-confusable letters to ASCII digits, but only inside a maximal
/// run of ≥12 chars that is ≥60% real ASCII digits (and has ≥8 of them). This
/// defeats homoglyph/leet substitution inside a candidate card/account number
/// (e.g. `4532O151l283O366` → `4532015112830366`) while leaving ordinary text
/// untouched. Each char maps to exactly one char, so byte offsets are
/// preserved the same way `remap_char_transform` does it.
fn fold_confusable_digit_runs(
    input: &str,
    input_offsets: &[Offset],
) -> Option<(String, OffsetMap)> {
    // A run qualifies when it is ≥ 12 chars with ≥ 8 real digits, is more than
    // 60% real digits, and contains at least one confusable to actually fold
    // (otherwise the run is already plain digits).
    fn qualifies(len: usize, ascii_digits: usize) -> bool {
        len > ascii_digits && len >= 12 && ascii_digits >= 8 && ascii_digits * 10 > len * 6
    }

    // Detection streams over the input instead of collecting `char_indices()`
    // into a `Vec<(usize, char)>`. That vector is 16 bytes per character — 16 MB
    // for a 1 MB input — and was built before knowing whether anything folds,
    // which for ordinary text it never does. Qualifying runs are recorded as
    // character ranges, so this vector stays empty on the common path.
    //
    // This stage runs unconditionally (confusables like `l`/`O` are themselves
    // ASCII, so the non-ASCII guard upstream cannot skip it), which is why it
    // was the single largest allocator in the pipeline at ~38 MB per 1 MB
    // scanned.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_len = 0usize;
    let mut ascii_digits = 0usize;

    for (idx, ch) in input.chars().enumerate() {
        if is_digit_run_member(ch) {
            if run_start.is_none() {
                run_start = Some(idx);
                run_len = 0;
                ascii_digits = 0;
            }
            run_len += 1;
            if ch.is_ascii_digit() {
                ascii_digits += 1;
            }
        } else if let Some(s) = run_start.take() {
            if qualifies(run_len, ascii_digits) {
                runs.push((s, s + run_len));
            }
        }
    }
    // A run ending at end-of-input is closed here rather than by a separator.
    if let Some(s) = run_start {
        if qualifies(run_len, ascii_digits) {
            runs.push((s, s + run_len));
        }
    }

    if runs.is_empty() {
        return None;
    }

    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());
    // `runs` is sorted and non-overlapping by construction, so a single cursor
    // walks it alongside the characters.
    let mut r = 0usize;
    for (idx, (byte_idx, ch)) in input.char_indices().enumerate() {
        while r < runs.len() && idx >= runs[r].1 {
            r += 1;
        }
        let in_run = r < runs.len() && idx >= runs[r].0;
        let replacement = if in_run {
            confusable_to_digit(ch).unwrap_or(ch)
        } else {
            ch
        };
        output.push(replacement);
        let orig_start = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            to_offset(byte_idx)
        };
        for _ in 0..replacement.len_utf8() {
            output_offsets.push(orig_start);
        }
    }
    Some((output, output_offsets))
}

/// Apply NFKC normalization while maintaining byte-level offset map.
/// NFKC can expand or contract characters (e.g., fullwidth '０' → '0',
/// ligature 'ﬁ' → 'fi'). Each output char inherits the original byte offset
/// of the input char that produced it.
fn remap_nfkc(input: &str, input_offsets: &[Offset]) -> (String, OffsetMap) {
    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        // The original offset for this input char
        let orig_offset = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            to_offset(byte_idx)
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
mod offset_width_tests {
    use super::*;

    /// The whole point of the change: the offset map is the largest
    /// allocation in the scan path, and its element width sets that cost.
    /// If someone widens `Offset` back to `usize` this fails on 64-bit.
    #[test]
    fn offset_is_four_bytes() {
        assert_eq!(
            std::mem::size_of::<Offset>(),
            4,
            "Offset sets the size of the largest allocation in a scan; \
             widening it doubles peak memory per concurrent scan"
        );
    }

    /// At the input cap the map must stay well inside what an Offset can
    /// address, with room for normalization stages that grow the text
    /// (NFKC can expand a character into several).
    #[test]
    fn input_cap_fits_the_offset_width_with_headroom() {
        let cap = crate::validation::MAX_INPUT_SIZE;
        assert!(
            cap < Offset::MAX as usize / 16,
            "input cap {cap} leaves too little headroom below Offset::MAX \
             ({}) for stages that expand the text",
            Offset::MAX
        );
    }

    #[test]
    fn to_offset_is_identity_within_range() {
        assert_eq!(to_offset(0), 0);
        assert_eq!(to_offset(12_345), 12_345);
        assert_eq!(
            to_offset(crate::validation::MAX_INPUT_SIZE),
            crate::validation::MAX_INPUT_SIZE as Offset
        );
    }

    /// Two-layer contract, and the layers differ by build profile.
    ///
    /// In debug the assertion fires, because an offset that large means the
    /// input cap has been bypassed and we want that loud, in a test, not
    /// discovered in production. In release it saturates: a wrapped offset
    /// would point a finding at an unrelated part of the document — a
    /// silently wrong answer — where a clamped one is merely imprecise at a
    /// boundary no real input reaches.
    #[test]
    #[should_panic(expected = "exceeds Offset::MAX")]
    fn to_offset_asserts_in_debug_when_the_cap_is_bypassed() {
        let _ = to_offset(Offset::MAX as usize + 1_000);
    }

    /// The saturating half of that contract, exercised at the boundary the
    /// assertion still permits.
    #[test]
    fn to_offset_handles_the_maximum_addressable_value() {
        assert_eq!(to_offset(Offset::MAX as usize), Offset::MAX);
    }

    /// Spans must still resolve to the caller's original bytes after the
    /// width change — the map is only useful if it round-trips.
    #[test]
    fn offsets_still_resolve_to_original_bytes() {
        // Zero-width joiner inside a card number: normalization removes it,
        // so normalized indices no longer match original ones.
        let original = "card 4111\u{200b}1111 1111 1111 here";
        let (normalized, offsets) = normalize_text(original);
        assert!(
            normalized.contains("4111"),
            "normalization should strip the ZWSP"
        );
        assert_eq!(
            offsets.len(),
            normalized.len(),
            "one offset per byte of normalized output"
        );
        for (norm_idx, &orig) in offsets.iter().enumerate() {
            assert!(
                (orig as usize) <= original.len(),
                "offset {orig} at normalized byte {norm_idx} points past the \
                 original input ({} bytes)",
                original.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Consistent digit-separator stripping (stage 6c) ----

    fn norm(s: &str) -> String {
        normalize_text(s).0
    }

    // ---- collapse_padding: linear-time run handling (regression) ----

    #[test]
    fn test_collapse_padding_between_digits() {
        // Whitespace between two non-alphabetic chars is stripped; the
        // digit-adjacent dashes are then removed by stage 6b, so the
        // spaced-out evasion form collapses to the bare digit run.
        assert_eq!(norm("1 2 3 - 4 5 - 6 7 8 9"), "123456789");
    }

    #[test]
    fn test_collapse_padding_preserves_word_spacing() {
        // Whitespace bordered by an alphabetic char on either side stays.
        let s = "social security number";
        assert_eq!(norm(s), s);
    }

    #[test]
    fn test_collapse_padding_large_run_is_linear() {
        // Regression for the O(n^2) forward-rescan in collapse_padding
        // (a remotely-triggerable DoS). A 256 KiB whitespace run between
        // two digits must normalize in well under a second; the old
        // implementation took ~22 s on this input.
        let text = format!("4{}2", " ".repeat(256 * 1024));
        let start = std::time::Instant::now();
        let out = norm(&text);
        let elapsed = start.elapsed();
        assert_eq!(out, "42", "padding between digits should collapse");
        assert!(
            elapsed.as_secs() < 2,
            "collapse_padding took {elapsed:?} — likely quadratic again"
        );
    }

    // ---- decimal coordinate dot protection (regression) ----

    #[test]
    fn test_gps_coordinate_dots_survive_normalization() {
        // Regression: stage 6b stripped the decimal points, turning
        // `37.7749,-122.4194` into `377749,-1224194` so the GPS Coordinates
        // pattern (which needs literal dots) could never match. The labelled
        // corpus recorded this as a permanent recall miss.
        let line = "[2024-11-02 14:22:12] geo tag 37.7749,-122.4194 attached";
        assert!(
            norm(line).contains("37.7749,-122.4194"),
            "coordinates were mangled: {}",
            norm(line)
        );
    }

    #[test]
    fn test_gps_coordinate_space_variant() {
        // A space after the comma is legitimately collapsed by
        // `collapse_padding` (it sits between two non-alphabetic bytes), so
        // the pair arrives as `51.5074,-0.1278`. What matters is that the
        // decimal points survive — the GPS regex accepts `,\s?` either way.
        assert!(norm("at 51.5074, -0.1278 today").contains("51.5074,-0.1278"));
    }

    #[test]
    fn test_coordinate_protection_does_not_shield_card_evasion() {
        // The protection must stay tight enough that dot-delimited card
        // evasion is still collapsed: four groups, no comma, 4-digit
        // integer parts — none of which match the coordinate shape.
        assert_eq!(norm("4532.0151.1283.0366"), "4532015112830366");
    }

    // ---- decode_hex_escapes: multibyte-safe passthrough (regression) ----

    #[test]
    fn test_hex_escape_decodes_printable() {
        // \x41 -> 'A'; presence of \x triggers the stage.
        assert_eq!(norm(r"\x41\x42\x43"), "ABC");
    }

    #[test]
    fn test_hex_escape_preserves_nonascii() {
        // Regression: a literal \x escape alongside non-ASCII text used to
        // mojibake the multibyte chars (u8 as char -> Latin-1) and desync
        // the offset map. The decoded escape should resolve and the
        // non-ASCII text must survive byte-for-byte.
        let (out, offsets) = normalize_text(r"café \x41 münchen");
        assert_eq!(out, "café A münchen");
        // Offset map stays byte-aligned with the output.
        assert_eq!(offsets.len(), out.len());
    }

    #[test]
    fn test_consistent_sep_pipe() {
        assert_eq!(norm("4532|0151|1283|0366"), "4532015112830366");
    }

    #[test]
    fn test_consistent_sep_variants() {
        for sep in [',', ':', ';', '~', '+', '=', '*', '#', '@', '$'] {
            let input = format!("4532{sep}0151{sep}1283{sep}0366");
            assert_eq!(
                norm(&input),
                "4532015112830366",
                "separator {sep:?} not stripped"
            );
        }
    }

    #[test]
    fn test_consistent_sep_unicode_middot() {
        assert_eq!(
            norm("4532\u{00B7}0151\u{00B7}1283\u{00B7}0366"),
            "4532015112830366"
        );
    }

    #[test]
    fn test_inconsistent_noise_left_intact() {
        // Mixed separators are NOT a reliable evasion signal — leave them.
        let input = "4532#0151@1283$0366";
        assert_eq!(norm(input), input);
    }

    #[test]
    fn test_letter_noise_left_intact() {
        // Letters are never treated as separators (would corrupt identifiers).
        let input = "4532x0151y1283z0366";
        assert_eq!(norm(input), input);
    }

    #[test]
    fn test_consistent_sep_too_few_seps() {
        // Only two separators — below the ≥3 threshold, left intact.
        let input = "45320151:1283:0366";
        assert_eq!(norm(input), input);
    }

    #[test]
    fn test_consistent_sep_preserves_ipv4() {
        // Dots are excluded, and even so IPv4 must survive untouched.
        let input = "10.0.0.1 and 192.168.1.1";
        assert_eq!(norm(input), input);
    }

    #[test]
    fn test_consistent_sep_not_inside_identifier() {
        // Alphanumeric boundary on the left → don't strip (part number, etc.).
        let input = "AB4532:0151:1283:0366";
        assert_eq!(norm(input), input);
    }

    #[test]
    fn test_strip_consistent_offsets_are_valid() {
        let input = "4532*0151*1283*0366";
        // The stage reports `None` for "unchanged"; this input must change.
        let (out, offsets) =
            strip_consistent_digit_separators(input, &[]).expect("separators should be stripped");
        assert_eq!(out, "4532015112830366");
        assert_eq!(offsets.len(), out.len());
        // Every offset must point back inside the original string.
        assert!(offsets.iter().all(|&o| (o as usize) < input.len()));
    }

    // ---- Stage prescan boundaries ----
    //
    // Three stages gained a cheap "can this possibly do anything?" check in
    // front of their allocation. Each check must be a *necessary* condition —
    // if it can ever reject input the stage would have transformed, the
    // scanner silently loses an evasion defence. These pin the boundaries.

    #[test]
    fn test_prescan_keeps_non_ascii_separator_stripping() {
        // The `strip_consistent_digit_separators` prescan is a byte-window
        // scan, so it only runs for all-ASCII input; a multi-byte separator
        // like U+00B7 cannot be seen in a 3-byte window and must fall through
        // to the full path instead of being rejected.
        assert!(norm("4532·0151·1283·0366").contains("4532015112830366"));
    }

    #[test]
    fn test_separator_stripping_ascii_and_char_paths_agree() {
        // `strip_consistent_digit_separators` now indexes bytes directly for
        // all-ASCII input and only builds char/index vectors when the text is
        // genuinely non-ASCII. The two paths must produce identical results
        // for the same logical input, so this pins an ASCII separator against
        // its non-ASCII counterpart.
        assert!(norm("4532*0151*1283*0366").contains("4532015112830366"));
        assert!(norm("4532·0151·1283·0366").contains("4532015112830366"));
        // Mixed: a non-ASCII character elsewhere in the text forces the char
        // path even though the separator itself is ASCII.
        assert!(norm("café 4532*0151*1283*0366").contains("4532015112830366"));
    }

    #[test]
    fn test_confusable_fold_survives_streaming_detection() {
        // `fold_confusable_digit_runs` detects qualifying runs by streaming
        // rather than collecting every char up front, then re-walks the input
        // to emit. Runs closed by a separator and runs closed by end-of-input
        // take different branches, so both are pinned here.
        // Only O→0 and l/I→1 are confusables; letters like S are not folded.
        let mid = norm("card 4532Ol5112830366 here");
        let end = norm("card 4532Ol5112830366");
        assert!(
            mid.contains("4532015112830366"),
            "run closed by separator: {mid}"
        );
        assert!(
            end.contains("4532015112830366"),
            "run closed by end-of-input: {end}"
        );
    }

    #[test]
    fn test_prescan_keeps_ascii_separator_stripping() {
        // The ASCII side of the same prescan must still admit real evasion.
        assert!(norm("4532*0151*1283*0366").contains("4532015112830366"));
        assert!(norm("4532|0151|1283|0366").contains("4532015112830366"));
    }

    #[test]
    fn test_prescan_keeps_doubled_delimiter_collapse() {
        // `normalize_delimiters` is skipped unless two identical `-`/`.` sit
        // adjacent, which is precisely what it collapses.
        assert!(norm("4532--0151--1283--0366").contains("4532015112830366"));
        assert!(norm("4532..0151..1283..0366").contains("4532015112830366"));
    }

    #[test]
    fn test_prescan_keeps_hex_spaced_decoding() {
        // `decode_hex_spaced` is skipped without an `XX SP XX` window.
        // "48 65 6c 6c 6f" is "Hello".
        assert!(norm("48 65 6c 6c 6f").contains("Hello"));
    }

    #[test]
    fn test_hex_spaced_buffer_is_cleared_between_candidates() {
        // `decode_hex_spaced` reuses one `pairs` buffer across candidate runs
        // instead of allocating per candidate. That is only correct while the
        // buffer is cleared each time: "ab 12" is a two-pair run and gets
        // rejected by the `>= 3` test, so if its entries survived into the
        // following real run they would prepend two junk bytes to the decode.
        let out = norm("ab 12 then 48 65 6c 6c 6f end");
        assert!(out.contains("Hello"), "real run should still decode: {out}");
        assert!(
            !out.contains("\u{ab}") && !out.contains('\u{12}'),
            "rejected candidate leaked into the next run: {out}"
        );
    }

    // ---- Case-folded base64 numeric recovery ----

    #[test]
    fn test_recover_case_folded_base64_uppercased() {
        use base64::{engine::general_purpose, Engine};
        let b64 = general_purpose::STANDARD.encode("4532015112830366");
        let got = recover_case_folded_base64_digits(&b64.to_uppercase());
        assert!(
            got.contains(&"4532015112830366".to_string()),
            "recovered = {got:?}"
        );
    }

    #[test]
    fn test_recover_case_folded_base64_lowercased() {
        use base64::{engine::general_purpose, Engine};
        let b64 = general_purpose::STANDARD.encode("4532015112830366");
        let got = recover_case_folded_base64_digits(&b64.to_lowercase());
        assert!(got.contains(&"4532015112830366".to_string()));
    }

    #[test]
    fn test_recover_case_folded_base64_rejects_non_numeric() {
        // A base64 blob whose plaintext has letters must not "recover" digits.
        use base64::{engine::general_purpose, Engine};
        let b64 = general_purpose::STANDARD.encode("hello world secret");
        assert!(recover_case_folded_base64_digits(&b64.to_uppercase()).is_empty());
    }

    #[test]
    fn test_recover_case_folded_base64_alt_decoding() {
        use base64::{engine::general_purpose, Engine};
        let b64 = general_purpose::STANDARD.encode("4532015112830366");
        // Mixed-case the encoded blob deterministically.
        let mixed: String = b64
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        let alts = generate_alternative_decodings(&mixed);
        assert!(
            alts.iter().any(|a| a.contains("4532015112830366")),
            "alts = {alts:?}"
        );
    }

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
                offsets[decoded_start] as usize, original_token_start,
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
    fn test_hex_spaced_does_not_eat_space_separated_ssn() {
        // Regression for a silent DLP bypass found during pen-testing: a
        // space-separated SSN `457 55 5462` was mangled to `4WUT62` because the
        // hex-spaced decoder started mid-token at offset 1 and read `57 55 54`
        // (0x57 0x55 0x54) as three pairs -> "WUT". A run must now begin at a
        // token boundary and every pair must be a complete 2-char token, so the
        // 3/2/4 digit grouping no longer forms a hex run. The SSN survives
        // normalization and the context-gated SSN pattern can match it.
        // The digits must survive intact. Downstream digit-group collapse
        // then joins them to a contiguous run (same as the no-space form),
        // which is exactly what the SSN pattern needs — the point is that no
        // hex letters (W/U/T) appear and no digits are lost.
        let (result, _) = normalize_text("457 55 5462");
        assert_eq!(result, "457555462", "space-separated SSN was corrupted");
        let (result, _) = normalize_text("123 45 6789");
        assert_eq!(result, "123456789");
        let (result, _) = normalize_text("555 12 3456");
        assert_eq!(result, "555123456");
    }

    #[test]
    fn test_hex_spaced_rejects_partial_token_run() {
        // A 3-char trailing group must not be partially consumed: `12 34 567`
        // offers pairs 0x12, 0x34, then `56` from `567` — but `567` is not a
        // 2-char token, so the run stops at two pairs (below the threshold) and
        // nothing is decoded.
        let (result, _) = normalize_text("12 34 567");
        assert_eq!(result, "1234567");
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
    fn test_digit_morse_nosep_trailing_newline() {
        // When space-sep morse is piped via `echo "..." | siphon scan-text`, the shell
        // appends \n. collapse_padding strips inner spaces but leaves the terminal \n
        // (no next non-WS neighbour). The decoder must trim it and still decode.
        let codes = [
            "-----", ".----", "..---", "...--", "....-", ".....", "-....", "--...", "---..",
            "----.",
        ];
        let nosep: String = "4532"
            .chars()
            .map(|c| codes[c as usize - b'0' as usize])
            .collect();
        assert_eq!(nosep.len(), 20, "nosep 4532 should be 20 chars");

        let with_lf = format!("{nosep}\n");
        let result = try_decode_digit_morse_nosep(with_lf.as_bytes());
        assert_eq!(
            result.as_deref(),
            Some("4532"),
            "trailing LF should not prevent nosep decode; got {result:?}"
        );

        let with_crlf = format!("{nosep}\r\n");
        let result = try_decode_digit_morse_nosep(with_crlf.as_bytes());
        assert_eq!(
            result.as_deref(),
            Some("4532"),
            "trailing CRLF should not prevent nosep decode; got {result:?}"
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

    // === Embedded delimited digit-morse (preamble-tolerant) tests ===

    // Helper: encode a digit string as delimited morse.
    fn enc_delim_morse(digits: &str, delim: char) -> String {
        let codes: Vec<String> = digits
            .chars()
            .map(|d| {
                let (code, _) = MORSE_DIGITS
                    .iter()
                    .find(|(_, dd)| *dd == d as u8)
                    .expect("digit");
                String::from_utf8(code.to_vec()).unwrap()
            })
            .collect();
        codes.join(&delim.to_string())
    }

    #[test]
    fn test_embedded_comma_morse_with_preamble() {
        // A filename preamble (as prepended on the file-scan path) must not defeat
        // comma-separated digit morse the way the whole-input decoder does.
        let cc = enc_delim_morse("4532015112830366", ',');
        let payload = format!("invoice.txt\n{cc}");
        // Whole-input decoder bails on the polluted first token…
        assert!(try_decode_digit_morse_comma(&payload).is_none());
        // …but the embedded scan recovers the run.
        assert_eq!(
            find_embedded_digit_morse_delimited(&payload, b','),
            Some("4532015112830366".to_string())
        );
    }

    #[test]
    fn test_embedded_slash_morse_with_word_prefix() {
        let cc = enc_delim_morse("4532015112830366", '/');
        let payload = format!("card {cc}");
        assert_eq!(
            find_embedded_digit_morse_delimited(&payload, b'/'),
            Some("4532015112830366".to_string())
        );
    }

    #[test]
    fn test_embedded_pipe_morse_with_preamble() {
        let cc = enc_delim_morse("4532015112830366", '|');
        let payload = format!("leak.log\n{cc}");
        assert_eq!(
            find_embedded_digit_morse_delimited(&payload, b'|'),
            Some("4532015112830366".to_string())
        );
    }

    #[test]
    fn test_embedded_delimited_morse_via_generate_alternatives() {
        // End-to-end through the alt-decoding entry point for all three delimiters.
        for delim in [',', '/', '|'] {
            let cc = enc_delim_morse("4532015112830366", delim);
            let payload = format!("invoice.txt\n{cc}");
            let alts = generate_alternative_decodings(&payload);
            assert!(
                alts.iter().any(|a| a.contains("4532015112830366")),
                "delim {delim:?}: expected recovered CC in alternatives, got {alts:?}"
            );
        }
    }

    #[test]
    fn test_embedded_delimited_morse_rejects_prose() {
        // The lone '.' in "invoice.txt" (and any other short/invalid run) must not
        // be mistaken for a digit-morse run.
        assert!(find_embedded_digit_morse_delimited("invoice.txt is here", b',').is_none());
        assert!(find_embedded_digit_morse_delimited("a.b/c.d/e.f", b'/').is_none());
        // Fewer than 4 tokens → rejected.
        let short = enc_delim_morse("453", ',');
        assert!(find_embedded_digit_morse_delimited(&format!("x {short}"), b',').is_none());
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

    #[test]
    fn test_arabic_indic_digits_normalized() {
        // Arabic-Indic ٠١٢٣ should normalize to 0123
        let input = "\u{0660}\u{0661}\u{0662}\u{0663}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "0123");
    }

    #[test]
    fn test_extended_arabic_indic_digits_normalized() {
        // Extended Arabic-Indic ۰۱۲۳ should normalize to 0123
        let input = "\u{06F0}\u{06F1}\u{06F2}\u{06F3}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "0123");
    }

    #[test]
    fn test_thai_digits_normalized() {
        // Thai ๐๑๒๓ should normalize to 0123
        let input = "\u{0E50}\u{0E51}\u{0E52}\u{0E53}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "0123");
    }

    #[test]
    fn test_devanagari_and_bengali_digits_normalized() {
        // Devanagari १२३ and Bengali ৪৫৬ fold via the Unicode Nd fallback,
        // not a hand-maintained per-script table.
        let (deva, _) = normalize_text("\u{0967}\u{0968}\u{0969}");
        assert_eq!(deva, "123");
        let (beng, _) = normalize_text("\u{09EA}\u{09EB}\u{09EC}");
        assert_eq!(beng, "456");
    }

    #[test]
    fn test_fold_unicode_digit_covers_supplementary_scripts() {
        // Mathematical bold digits (U+1D7CE..) and fullwidth digits fold too.
        assert_eq!(fold_unicode_digit('\u{1D7CE}'), Some('0'));
        assert_eq!(fold_unicode_digit('\u{1D7D7}'), Some('9'));
        assert_eq!(fold_unicode_digit('\u{FF15}'), Some('5'));
        // Non-digits and ASCII return None.
        assert_eq!(fold_unicode_digit('A'), None);
        assert_eq!(fold_unicode_digit('5'), None);
        assert_eq!(fold_unicode_digit('\u{0966}'), Some('0')); // Devanagari zero
    }

    #[test]
    fn test_confusable_digits_fold_in_dense_run() {
        // Latin O→0 and l→1 inside a 16-char, digit-dense run (leet evasion).
        let (result, _) = normalize_text("4532O151l283O366");
        assert_eq!(result, "4532015112830366");
    }

    #[test]
    fn test_confusable_greek_and_cyrillic_o_fold_in_run() {
        // Greek omicron (U+039F) and Cyrillic O (U+041E) standing in for '0'
        // inside a digit run both fold to ASCII '0'.
        let (greek, _) = normalize_text("4532\u{039F}15112830366");
        assert_eq!(greek, "4532015112830366");
        let (cyr, _) = normalize_text("4532\u{041E}15112830366");
        assert_eq!(cyr, "4532015112830366");
    }

    #[test]
    fn test_confusable_fold_does_not_touch_prose() {
        // Ordinary words with O/o/l/I must NOT be rewritten — the run gate
        // (≥12 chars, ≥8 real digits, >60% digits) protects normal text.
        let (r1, _) = normalize_text("Hello world, I lost my wallet OoOo");
        assert_eq!(r1, "Hello world, I lost my wallet OoOo");
        // Short number-ish token below the 12-char threshold is untouched.
        let (r2, _) = normalize_text("Order IOl only 12345");
        assert_eq!(r2, "Order IOl only 12345");
    }

    #[test]
    fn test_confusable_fold_requires_digit_density() {
        // A long run that is mostly letters (≤60% digits) is left alone even
        // if it exceeds the length threshold.
        let sparse = "OIlOIlOIl123456"; // 15 chars, only 6 real digits
        let (result, _) = normalize_text(sparse);
        assert_eq!(result, sparse);
    }

    #[test]
    fn test_em_dash_normalized_to_hyphen() {
        // Em-dash (U+2014) and en-dash (U+2013) should map to ASCII hyphen
        let em = "\u{2014}";
        let (result, _) = normalize_text(em);
        assert_eq!(result, "-", "em-dash should normalize to '-'");

        let en = "\u{2013}";
        let (result, _) = normalize_text(en);
        assert_eq!(result, "-", "en-dash should normalize to '-'");

        let minus = "\u{2212}";
        let (result, _) = normalize_text(minus);
        assert_eq!(result, "-", "minus sign should normalize to '-'");
    }

    #[test]
    fn test_em_dash_morse_via_homoglyph() {
        // Morse where ASCII '-' is replaced with em-dash: after homoglyph normalization
        // the em-dashes become '-' and the nosep decoder can decode the result.
        // "4532" standard nosep: "....-" + "....." + "...--" + "..---"
        let standard = concat!("....-", ".....", "...--", "..---");
        let em = '\u{2014}';
        let nosep_4532_em: String = standard
            .chars()
            .map(|c| if c == '-' { em } else { c })
            .collect();
        let (normalized, _) = normalize_text(&nosep_4532_em);
        let alts = generate_alternative_decodings(&normalized);
        assert!(
            alts.iter().any(|a| a == "4532"),
            "em-dash morse should decode to digits after normalization; norm={:?} alts={:?}",
            normalized,
            alts
        );
    }

    #[test]
    fn test_mixed_alpha_nosep_basic() {
        // "AB1234" with digits nosep-encoded and alpha passing through:
        // A, B pass through; 1=.---- 2=..--- 3=...-- 4=....-
        let input = concat!("AB", ".----", "..---", "...--", "....-");
        let decoded = try_decode_mixed_alpha_nosep(input);
        assert_eq!(
            decoded.as_deref(),
            Some("AB1234"),
            "mixed nosep should decode alpha+digits; got {decoded:?}"
        );
    }

    #[test]
    fn test_mixed_alpha_nosep_with_spaces() {
        // Space-separated letters (post-collapse form): "A B.----..---...--....-"
        let input = "A B.----..---...--....-";
        let decoded = try_decode_mixed_alpha_nosep(input);
        assert_eq!(
            decoded.as_deref(),
            Some("AB1234"),
            "mixed nosep should skip spaces between letters; got {decoded:?}"
        );
    }

    #[test]
    fn test_mixed_alpha_nosep_rejects_pure_nosep() {
        // Pure nosep (no alpha) must return None — use existing nosep decoder instead
        let pure = ".----..---...--....-";
        assert!(
            try_decode_mixed_alpha_nosep(pure).is_none(),
            "pure nosep should not match mixed decoder"
        );
    }

    #[test]
    fn test_mixed_alpha_nosep_rejects_bad_segment_length() {
        // A morse segment whose length is not a multiple of 5 → None
        // "A---" has "---" (3 chars), not a multiple of 5
        assert!(
            try_decode_mixed_alpha_nosep("A---BCDE").is_none(),
            "segment of length 3 should reject"
        );
    }

    #[test]
    fn test_mixed_alpha_nosep_rejects_too_few_digits() {
        // Only 3 digits decoded (< 4 minimum) → None
        // 3 digit nosep = ".----..---...--" (15 chars)
        let input = "A.----..---...--";
        assert!(
            try_decode_mixed_alpha_nosep(input).is_none(),
            "3 decoded digits should reject (< 4 minimum)"
        );
    }

    #[test]
    fn test_slash_decoder_multi_char_alpha_token() {
        // After stage 6b (strip_alnum_adjacent_delimiters), G/B becomes GB and
        // W/E/S/T becomes WEST in the slash-sep IBAN form.  The slash decoder
        // must accept all-alpha multi-char tokens as literal passthrough.
        // digits "82" encoded as "---..'' / "..---"; 4 more digits to meet minimum
        let input = "GB/---../..---/WEST/.----/..---/...--/....-/...../-..../----./---../--.../-..../...../....-/...--/..---";
        let decoded = try_decode_digit_morse_slash(input);
        assert_eq!(
            decoded.as_deref(),
            Some("GB82WEST12345698765432"),
            "multi-char alpha tokens should pass through literally"
        );
    }
}
