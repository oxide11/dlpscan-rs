//! CI gate for the conformance matrix.
//!
//! The cases themselves live in `siphon::conformance` so that this gate, the
//! `siphon-conformance` binary and `scripts/conformance.sh` all run exactly
//! the same thing. This file is only the `cargo test` face of it.
//!
//! Requires the `conformance` feature; without it the whole file compiles to
//! nothing, and `every_capability_is_accounted_for` below is what stops that
//! from becoming a silent skip — `scripts/conformance.sh` and CI both pass
//! the feature.
//!
//! ```bash
//! cargo test --features conformance --test conformance
//! ```

#![cfg(feature = "conformance")]

use siphon::conformance::{self, Slot};

/// One test per capability, so a failure names the format rather than the
/// matrix. Each reports all five of its slots together instead of stopping
/// at the first — when a reader breaks it usually breaks more than one
/// question, and seeing which ones survived is most of the diagnosis.
macro_rules! capability_test {
    ($name:ident, $capability:literal) => {
        #[test]
        fn $name() {
            let report = conformance::run_all(Some($capability));
            assert!(
                !report.results.is_empty(),
                "no cases for {:?} — the matrix lost a capability, or the \
                 feature that provides its reader is off",
                $capability
            );
            // Documented gaps (cases wrapped in `gap()`) are excluded: they
            // are behaving as their recorded reason says, and failing CI on
            // them would only train people to ignore this suite. They are
            // still reported by `scripts/conformance.sh`, which is where
            // they belong — visible, not enforced.
            let failures: Vec<String> = report
                .results
                .iter()
                .filter(|r| r.is_failure())
                .map(|r| {
                    format!(
                        "[{}] {}",
                        r.slot.name(),
                        r.failure.as_deref().unwrap_or("(no detail)")
                    )
                })
                .collect();
            assert!(
                failures.is_empty(),
                "\n\n{}: {} of {} cases failed\n\n{}\n",
                $capability,
                failures.len(),
                report.results.len(),
                failures.join("\n\n")
            );

            // A gap that has started passing is also a finding: the entry
            // has outlived the bug and should be removed, or it will go on
            // excusing a failure that no longer exists.
            let fixed: Vec<&str> = report
                .results
                .iter()
                .filter(|r| r.fixed_gap())
                .map(|r| r.slot.name())
                .collect();
            assert!(
                fixed.is_empty(),
                "\n\n{}: these cases are marked as documented gaps but now pass: \
                 {:?}\nRemove the gap() wrapper in src/conformance/formats.rs.\n",
                $capability,
                fixed
            );
        }
    };
}

capability_test!(txt, "txt");
capability_test!(csv, "csv");
capability_test!(json, "json");
capability_test!(rtf, "rtf");
capability_test!(eml, "eml");
capability_test!(mbox, "mbox");
capability_test!(mhtml, "mhtml");
capability_test!(vcf, "vcf");
capability_test!(ldif, "ldif");
capability_test!(ics, "ics");
capability_test!(warc, "warc");

#[cfg(feature = "office")]
capability_test!(docx, "docx");
#[cfg(feature = "office")]
capability_test!(xlsx, "xlsx");
#[cfg(feature = "office")]
capability_test!(pptx, "pptx");
#[cfg(feature = "office")]
capability_test!(odt, "odt");
#[cfg(feature = "office")]
capability_test!(ods, "ods");

#[cfg(feature = "pdf")]
capability_test!(pdf, "pdf");

#[cfg(feature = "archives")]
capability_test!(zip_archive, "zip");
#[cfg(feature = "archives")]
capability_test!(sevenz, "7z");

#[cfg(feature = "data-formats")]
capability_test!(sqlite, "sqlite");

#[cfg(feature = "barcode")]
capability_test!(png, "png");

// Not a format — the arbitration between formats. See
// `siphon::conformance::formats::disguise`.
#[cfg(feature = "archives")]
capability_test!(disguise, "disguise");

/// Every capability carries all five slots, exactly once.
///
/// Without this, a capability could quietly shrink to its two easy questions
/// and still look green.
#[test]
fn every_capability_asks_all_five_questions() {
    let cases = conformance::formats::cases();
    let mut capabilities: Vec<&str> = cases.iter().map(|c| c.capability).collect();
    capabilities.dedup();

    let mut problems = Vec::new();
    for capability in capabilities {
        let mut slots: Vec<Slot> = cases
            .iter()
            .filter(|c| c.capability == capability)
            .map(|c| c.slot)
            .collect();
        slots.sort();
        if slots != Slot::ALL.to_vec() {
            problems.push(format!(
                "  {capability}: {:?}",
                slots.iter().map(|s| s.name()).collect::<Vec<_>>()
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "\n\nthese capabilities do not cover all five slots exactly once:\n{}\n",
        problems.join("\n")
    );
}

/// Nothing Siphon advertises may be missing from the matrix without a
/// recorded reason.
#[test]
fn every_capability_is_accounted_for() {
    let report = conformance::run_all(Some("__none__"));
    assert!(
        report.uncovered.is_empty(),
        "\n\nthese formats are advertised by supported_extensions() but have no \
         cases in the matrix:\n  {}\n\nAdd five cases, or record it in \
         conformance::formats::KNOWN_GAPS with the reason.\n",
        report.uncovered.join(", ")
    );
}
