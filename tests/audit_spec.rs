//! Specificity + context_required drift audits.
//!
//! Ensures `pattern_specificity()` / `is_context_required()` in models.rs
//! and the corresponding PatternDef fields in patterns/mod.rs stay in
//! sync. Any commit that updates one without the other fails a test.

use siphon_core::models::{is_context_required, pattern_specificity};
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

/// Same discipline for `PatternDef.context_required` vs
/// `is_context_required(sub_category)`. The scanner consults BOTH
/// (OR'd) via `effective_context_required`, so a disagreement is a
/// smell rather than a correctness bug today — but it means one
/// source is lying, and the admin-console catalog view reads the
/// PatternDef field. Keeping them in lockstep prevents the UI from
/// misrepresenting scanner behavior.
#[test]
fn context_required_drift_zero() {
    let mut mismatches = 0;
    for p in PATTERNS {
        let map_flag = is_context_required(p.sub_category);
        let def_flag = p.context_required;
        if map_flag != def_flag {
            eprintln!(
                "  DRIFT {:40} map={}  def={}",
                p.sub_category, map_flag, def_flag
            );
            mismatches += 1;
        }
    }
    assert_eq!(
        mismatches, 0,
        "{mismatches} pattern(s) disagree on context_required between \
         models::is_context_required() and PatternDef.context_required. \
         Update both sources to match."
    );
}
