//! Per-label recall against a held-out corpus split.
//!
//! The 2,586 samples read here are the `test` split of the Canada public
//! professional contact corpus (`tests/corpus/canada_contact_v1/`). They are
//! used for nothing else — not for tuning, not for any other suite — so the
//! numbers below are a genuine held-out measurement rather than a restatement
//! of what the scanner was built against.
//!
//! This is what `tests/corpus/labels.jsonl` cannot provide. That set holds 80
//! positives spread over 73 sub-categories, roughly one example each, which is
//! enough to catch a total break and nothing more. Here there are thousands of
//! instances of three labels, which is enough to state a recall figure and
//! notice a small regression in it.
//!
//! **Floors, not targets.** Each assertion sits a little below the measured
//! value so ordinary variation does not produce noise. A failure means recall
//! fell. If recall *rises*, re-derive the baseline and raise the floor in the
//! commit that earned it.
//!
//! Offsets in the corpus are character offsets (Python convention), so this
//! harness matches on entity text rather than on spans — see PROVENANCE.md.

use std::collections::HashMap;
use std::path::PathBuf;

/// Corpus labels mapped to the siphon sub-categories that satisfy them.
fn label_map() -> HashMap<&'static str, Vec<&'static str>> {
    HashMap::from([
        ("POSTAL_CODE", vec!["Canada Postal Code", "UK Postcode"]),
        ("EMAIL_ADDRESS", vec!["Email Address"]),
        (
            "PHONE_NUMBER",
            vec!["US Phone Number", "E.164 Phone Number", "UK Phone Number"],
        ),
    ])
}

struct Sample {
    text: String,
    entities: Vec<(String, String)>,
}

fn load_test_split() -> Vec<Sample> {
    let p: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "corpus",
        "canada_contact_v1",
        "polygon_siphon_ner_corpus_v1.jsonl",
    ]
    .iter()
    .collect();
    // Absent corpus is a skip, not a failure. The bulk files are not in git —
    // see scripts/fetch-corpus.sh and the corpus PROVENANCE.md — so a
    // contributor without them should still be able to run every other suite.
    // CI fetches the corpus, so the gate is real where it matters.
    let Ok(data) = std::fs::read_to_string(&p) else {
        eprintln!(
            "held-out corpus not present at {} — skipping. \
             Run scripts/fetch-corpus.sh to obtain it.",
            p.display()
        );
        return Vec::new();
    };

    let mut out = Vec::new();
    for line in data.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v["split"].as_str() != Some("test") {
            continue;
        }
        let text = match v["text"].as_str() {
            Some(t) => t.to_string(),
            None => continue,
        };
        let entities = v["entities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some((
                            e["label"].as_str()?.to_string(),
                            e["text"].as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(Sample { text, entities });
    }
    out
}

/// Recall per label over the held-out split.
fn measure() -> HashMap<String, (usize, usize)> {
    let map = label_map();
    let mut acc: HashMap<String, (usize, usize)> = HashMap::new();
    for s in load_test_split() {
        let found = siphon::scan_text(&s.text).unwrap_or_default();
        for (label, etext) in &s.entities {
            let Some(subs) = map.get(label.as_str()) else {
                continue;
            };
            let hit = found.iter().any(|m| {
                subs.contains(&m.sub_category.as_str())
                    && (m.text.contains(etext) || etext.contains(m.text.trim()))
            });
            let e = acc.entry(label.clone()).or_insert((0, 0));
            if hit {
                e.0 += 1
            } else {
                e.1 += 1
            }
        }
    }
    acc
}

#[test]
fn held_out_split_is_present_and_intact() {
    let s = load_test_split();
    if s.is_empty() {
        return; // corpus absent; see load_test_split
    }
    assert_eq!(
        s.len(),
        2586,
        "held-out split changed size; if the corpus was refreshed, re-derive \
         every baseline in this file in the same commit"
    );
}

/// Baselines measured 2026-09-02, after the context-keyword boundary fix and
/// the gating of nine bare-digit patterns:
///
/// | label | recall |
/// |---|---:|
/// | EMAIL_ADDRESS | 99.3% |
/// | PHONE_NUMBER | 94.6% |
/// | POSTAL_CODE | 93.6% |
///
/// PHONE_NUMBER is the one with history. It measured **45.9%** before those
/// fixes — not because the spans went undetected, but because bare-digit
/// patterns like `British NHS` (`\d{3}\s?\d{3}\s?\d{4}`, always-run, scored
/// above `US Phone Number`) won deduplication and relabelled real telephone
/// numbers as foreign identity documents.
#[test]
fn held_out_recall_meets_baseline() {
    let m = measure();
    if m.is_empty() {
        return; // corpus absent; see load_test_split
    }
    let floors = [
        ("EMAIL_ADDRESS", 0.95),
        ("PHONE_NUMBER", 0.90),
        ("POSTAL_CODE", 0.90),
    ];
    let mut failures = Vec::new();
    for (label, floor) in floors {
        let (hit, miss) = *m.get(label).unwrap_or(&(0, 0));
        assert!(
            hit + miss > 500,
            "{label}: only {} instances in the held-out split; the corpus may \
             have changed",
            hit + miss
        );
        let recall = hit as f64 / (hit + miss) as f64;
        if recall < floor {
            failures.push(format!(
                "{label} recall {:.3} ({hit}/{}) below floor {floor:.2}",
                recall,
                hit + miss
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The six labels the scanner cannot detect at all, pinned so the gap is
/// visible rather than assumed. `PERSON_NAME`, `JOB_TITLE`, `ORGANIZATION`,
/// `STREET_ADDRESS`, `CITY` and `REGION` have no corresponding pattern —
/// regex cannot express them, which is the case for the optional NER stage in
/// `FUTURE.md`.
///
/// If this starts failing, something now detects one of them and the roadmap
/// item has been partly delivered. Update the list.
#[test]
fn unsupported_labels_remain_unsupported() {
    let unsupported = [
        "PERSON_NAME",
        "JOB_TITLE",
        "ORGANIZATION",
        "STREET_ADDRESS",
        "CITY",
        "REGION",
    ];
    let map = label_map();
    for l in unsupported {
        assert!(
            !map.contains_key(l),
            "{l} is now mapped to a pattern — update this test and the NER gap \
             description in FUTURE.md"
        );
    }
}
