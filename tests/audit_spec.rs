//! Specificity drift audit.
//!
//! Ensures `pattern_specificity()` in models.rs and `PatternDef.specificity`
//! in patterns/mod.rs stay in sync. Any commit that updates one without the
//! other will fail this test.

use siphon_core::models::pattern_specificity;
use siphon_core::patterns::PATTERNS;

#[test]
fn specificity_drift_zero() {
    let mut mismatches = 0;
    for p in PATTERNS {
        let map_spec = pattern_specificity(p.sub_category);
        let def_spec = p.specificity;
        if (map_spec - def_spec).abs() > 0.001 {
            eprintln!(
                "  DRIFT {:40} map={:.2}  def={:.2}",
                p.sub_category, map_spec, def_spec
            );
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "{mismatches} pattern(s) have different specificity in pattern_specificity() vs PatternDef. \
         Update both sources to match."
    );
}
