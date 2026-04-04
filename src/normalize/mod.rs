//! Unicode normalization to defeat evasion attacks.
//!
//! Handles zero-width character stripping, whitespace normalization,
//! homoglyph substitution, and leet-speak decoding.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

/// Zero-width and invisible Unicode characters.
pub static ZERO_WIDTH_CHARS: Lazy<Vec<char>> = Lazy::new(|| {
    vec![
        '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}',
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
        '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}',
        '\u{FEFF}', '\u{00AD}', '\u{034F}', '\u{061C}',
        '\u{180E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        '\u{FE00}', '\u{FE01}', '\u{FE02}', '\u{FE03}', '\u{FE04}',
        '\u{FE05}', '\u{FE06}', '\u{FE07}', '\u{FE08}', '\u{FE09}',
        '\u{FE0A}', '\u{FE0B}', '\u{FE0C}', '\u{FE0D}', '\u{FE0E}',
        '\u{FE0F}',
    ]
});

/// Exotic Unicode whitespace characters.
pub static UNICODE_SPACES: Lazy<Vec<char>> = Lazy::new(|| {
    vec![
        '\u{00A0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}',
        '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}',
        '\u{2008}', '\u{2009}', '\u{200A}', '\u{202F}', '\u{205F}',
        '\u{3000}',
    ]
});

/// Leet-speak substitution map.
static LEET_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let pairs = [
        ('@', 'a'), ('4', 'a'), ('8', 'b'), ('(', 'c'),
        ('3', 'e'), ('6', 'g'), ('#', 'h'), ('!', 'i'),
        ('1', 'l'), ('0', 'o'), ('5', 's'), ('7', 't'),
        ('+', 't'), ('2', 'z'),
    ];
    pairs.iter().copied().collect()
});

/// Homoglyph substitution map (Cyrillic, Greek, mathematical, etc. → ASCII).
/// Applied AFTER NFKC, so this catches anything NFKC doesn't normalize.
static HOMOGLYPH_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let pairs = [
        // Cyrillic uppercase
        ('\u{0410}', 'A'), ('\u{0412}', 'B'), ('\u{0421}', 'C'),
        ('\u{0415}', 'E'), ('\u{041D}', 'H'), ('\u{0406}', 'I'),
        ('\u{0408}', 'J'), ('\u{041A}', 'K'), ('\u{041C}', 'M'),
        ('\u{041E}', 'O'), ('\u{0420}', 'P'), ('\u{0405}', 'S'),
        ('\u{0422}', 'T'), ('\u{0425}', 'X'), ('\u{0417}', 'Z'),
        // Cyrillic lowercase
        ('\u{0430}', 'a'), ('\u{0435}', 'e'), ('\u{0456}', 'i'),
        ('\u{0458}', 'j'), ('\u{043E}', 'o'), ('\u{0440}', 'p'),
        ('\u{0441}', 'c'), ('\u{0443}', 'y'), ('\u{0445}', 'x'),
        ('\u{0455}', 's'),
        // Greek uppercase
        ('\u{0391}', 'A'), ('\u{0392}', 'B'), ('\u{0393}', 'G'),
        ('\u{0395}', 'E'), ('\u{0397}', 'H'), ('\u{0399}', 'I'),
        ('\u{039A}', 'K'), ('\u{039C}', 'M'), ('\u{039D}', 'N'),
        ('\u{039F}', 'O'), ('\u{03A1}', 'P'), ('\u{03A4}', 'T'),
        ('\u{03A5}', 'Y'), ('\u{03A7}', 'X'), ('\u{0396}', 'Z'),
        // Greek lowercase
        ('\u{03B1}', 'a'), ('\u{03BF}', 'o'), ('\u{03B9}', 'i'),
        ('\u{03BA}', 'k'), ('\u{03BD}', 'v'), ('\u{03C1}', 'p'),
        ('\u{03C5}', 'u'), ('\u{03C7}', 'x'),
        // Fullwidth digits (backup — NFKC should handle these)
        ('\u{FF10}', '0'), ('\u{FF11}', '1'), ('\u{FF12}', '2'),
        ('\u{FF13}', '3'), ('\u{FF14}', '4'), ('\u{FF15}', '5'),
        ('\u{FF16}', '6'), ('\u{FF17}', '7'), ('\u{FF18}', '8'),
        ('\u{FF19}', '9'),
        // Fullwidth ASCII letters (backup — NFKC should handle these)
        ('\u{FF21}', 'A'), ('\u{FF22}', 'B'), ('\u{FF23}', 'C'),
        ('\u{FF24}', 'D'), ('\u{FF25}', 'E'), ('\u{FF26}', 'F'),
        ('\u{FF27}', 'G'), ('\u{FF28}', 'H'), ('\u{FF29}', 'I'),
        ('\u{FF2A}', 'J'), ('\u{FF2B}', 'K'), ('\u{FF2C}', 'L'),
        ('\u{FF2D}', 'M'), ('\u{FF2E}', 'N'), ('\u{FF2F}', 'O'),
        ('\u{FF30}', 'P'), ('\u{FF31}', 'Q'), ('\u{FF32}', 'R'),
        ('\u{FF33}', 'S'), ('\u{FF34}', 'T'), ('\u{FF35}', 'U'),
        ('\u{FF36}', 'V'), ('\u{FF37}', 'W'), ('\u{FF38}', 'X'),
        ('\u{FF39}', 'Y'), ('\u{FF3A}', 'Z'),
        ('\u{FF41}', 'a'), ('\u{FF42}', 'b'), ('\u{FF43}', 'c'),
        ('\u{FF44}', 'd'), ('\u{FF45}', 'e'), ('\u{FF46}', 'f'),
        ('\u{FF47}', 'g'), ('\u{FF48}', 'h'), ('\u{FF49}', 'i'),
        ('\u{FF4A}', 'j'), ('\u{FF4B}', 'k'), ('\u{FF4C}', 'l'),
        ('\u{FF4D}', 'm'), ('\u{FF4E}', 'n'), ('\u{FF4F}', 'o'),
        ('\u{FF50}', 'p'), ('\u{FF51}', 'q'), ('\u{FF52}', 'r'),
        ('\u{FF53}', 's'), ('\u{FF54}', 't'), ('\u{FF55}', 'u'),
        ('\u{FF56}', 'v'), ('\u{FF57}', 'w'), ('\u{FF58}', 'x'),
        ('\u{FF59}', 'y'), ('\u{FF5A}', 'z'),
        // Fullwidth punctuation commonly used in evasion
        ('\u{FF0D}', '-'), ('\u{FF0E}', '.'), ('\u{FF20}', '@'),
        ('\u{FF3F}', '_'), ('\u{FF0A}', '*'),
        // Mathematical/script homoglyphs (commonly used for evasion)
        ('\u{2070}', '0'), ('\u{00B9}', '1'), ('\u{00B2}', '2'),
        ('\u{00B3}', '3'),
        // Subscript digits
        ('\u{2080}', '0'), ('\u{2081}', '1'), ('\u{2082}', '2'),
        ('\u{2083}', '3'), ('\u{2084}', '4'), ('\u{2085}', '5'),
        ('\u{2086}', '6'), ('\u{2087}', '7'), ('\u{2088}', '8'),
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

/// Full normalization pipeline with accurate byte-level offset tracking.
///
/// Pipeline: zero-width strip → whitespace normalize → NFKC → homoglyph map.
/// The returned offset_map maps each byte index in the normalized output back
/// to the corresponding byte index in the original input. Empty offset_map
/// means identity mapping (text was pure ASCII, nothing changed).
pub fn normalize_text(text: &str) -> (String, Vec<usize>) {
    if is_ascii_only(text) {
        return (text.to_string(), Vec::new());
    }

    // Stage 1: Strip zero-width characters, building initial offset map.
    // offset1[output_byte] = original_byte
    let mut current = String::with_capacity(text.len());
    let mut offsets: Vec<usize> = Vec::with_capacity(text.len());

    for (byte_idx, ch) in text.char_indices() {
        if !ZERO_WIDTH_CHARS.contains(&ch) {
            current.push(ch);
            for i in 0..ch.len_utf8() {
                offsets.push(byte_idx + i);
            }
        }
    }

    // Stage 2: Normalize exotic whitespace (char-by-char, may change byte widths).
    let (current, offsets) = remap_char_transform(&current, &offsets, |c| {
        if UNICODE_SPACES.contains(&c) { ' ' } else { c }
    });

    // Stage 3: NFKC normalization (handles fullwidth digits/letters, ligatures, etc.).
    // NFKC can change string length — one input char may produce multiple output chars
    // or vice versa. We track at char granularity: each output char inherits the
    // original byte offset of the input char that produced it.
    let (current, offsets) = remap_nfkc(&current, &offsets);

    // Stage 4: Homoglyph map (Cyrillic/Greek → ASCII). Always 1:1 char replacement,
    // but replacement char may have different UTF-8 byte width.
    let (current, offsets) = remap_char_transform(&current, &offsets, |c| {
        *HOMOGLYPH_MAP.get(&c).unwrap_or(&c)
    });

    // If nothing changed, return empty offsets (identity)
    if current == text {
        return (current, Vec::new());
    }

    (current, offsets)
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
}
