//! The detection matrix: five cases for every pattern Siphon can observe.
//!
//! Siphon advertises 583 patterns. This asks each of them the same five
//! questions the format matrix asks of each reader, with the slots meaning
//! what they have to mean for a pattern rather than a file:
//!
//! | Slot | Question |
//! |---|---|
//! | [`Slot::Clean`]      | Ordinary prose containing none of its values: does it stay quiet? |
//! | [`Slot::Single`]     | The value, labelled: is it found? |
//! | [`Slot::Structural`] | The same value inside a real document rather than alone: still found? |
//! | [`Slot::Damaged`]    | A near miss — the value mutated until it should no longer qualify: does it stay quiet? |
//! | [`Slot::Evasive`]    | The value wearing an encoding the normalizer is meant to undo: still found? |
//!
//! # What this can and cannot catch
//!
//! Worth being precise about, because the answer differs by slot.
//!
//! The **positive** slots (`single`, `structural`, `evasive`) are seeded from
//! the scanner's own behaviour — a candidate is generated from the pattern's
//! regex, and kept only if the scanner reports it. That makes them a
//! regression suite: they pin today's answers and fail when those change.
//! They cannot catch a pattern that is wrong today, because the pattern was
//! the oracle.
//!
//! The **negative** slots (`clean`, `damaged`) are not circular. A near miss
//! is derived by mutating a known-good value — dropping a character, bumping
//! a checksum digit — and asserting the pattern goes quiet. That tests
//! whether a pattern checks substance or merely shape, and it is the half a
//! corpus grown only from positive examples never gets.
//!
//! # Cases are generated, then verified
//!
//! Everything here comes from [`super::detections_data`], produced by
//! sampling each pattern's own regex and keeping only what the scanner
//! confirms. Nothing was asserted into existence: a slot that could not be
//! made to behave is carried as a declared gap with the reason, not quietly
//! dropped or weakened.
//!
//! [`UNSEEDED`] is the other half of that honesty. Some patterns have no
//! observable example at all, and the largest group is not a generator
//! failure — it is patterns carrying a regex identical to a sibling's, where
//! deduplication means only one of them can ever be reported.

use super::detections_data::{DETECTIONS, UNSEEDED};
use super::{gap, text_case, Case, Expect, Slot};

fn slot_of(n: u8) -> Slot {
    match n {
        0 => Slot::Clean,
        1 => Slot::Single,
        2 => Slot::Structural,
        3 => Slot::Damaged,
        _ => Slot::Evasive,
    }
}

fn note_of(n: u8) -> &'static str {
    match n {
        0 => "ordinary prose holding none of this pattern's values must not trip it",
        1 => "the value, labelled with a context keyword: the plainest possible positive",
        2 => {
            "the same value inside a document rather than alone — surrounding text must \
              not lose it, and must not be needed to find it"
        }
        3 => {
            "a near miss: the value mutated until it should no longer qualify. A pattern \
              that still fires here is checking shape, not substance"
        }
        _ => {
            "the value wearing an encoding the normalizer exists to undo. Still the same \
              value, so still a finding"
        }
    }
}

/// Every detection case, in pattern order.
pub fn cases() -> Vec<Case> {
    DETECTIONS
        .iter()
        .map(|(_category, sub, slot, text, fire, gap_reason)| {
            let c = text_case(
                sub,
                slot_of(*slot),
                *text,
                if *fire {
                    Expect::DetectsSubCategory(sub)
                } else {
                    Expect::SubCategoryAbsent(sub)
                },
                note_of(*slot),
            );
            if gap_reason.is_empty() {
                c
            } else {
                gap(c, gap_reason)
            }
        })
        .collect()
}

/// Patterns with no observable example, paired with the diagnosis.
pub fn unseeded() -> Vec<(&'static str, &'static str)> {
    UNSEEDED
        .iter()
        .map(|(_category, sub, why)| (*sub, *why))
        .collect()
}

/// How many patterns the matrix covers, out of how many exist.
pub fn coverage() -> (usize, usize) {
    let covered = DETECTIONS.len() / 5;
    (covered, covered + UNSEEDED.len())
}
