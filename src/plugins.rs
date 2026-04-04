//! Plugin system — custom validators and post-processors.
//!
//! Register per-sub_category validators to accept/reject matches,
//! and post-processors that transform the match list after scanning.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::models::Match;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A validator returns true if the match should be kept.
pub type ValidatorFn = Box<dyn Fn(&Match) -> bool + Send + Sync>;

/// A post-processor transforms a match list.
pub type PostProcessorFn = Box<dyn Fn(Vec<Match>) -> Vec<Match> + Send + Sync>;

// ---------------------------------------------------------------------------
// Global registries
// ---------------------------------------------------------------------------

static VALIDATORS: Mutex<Option<HashMap<String, Vec<ValidatorFn>>>> = Mutex::new(None);
static POST_PROCESSORS: Mutex<Option<Vec<PostProcessorFn>>> = Mutex::new(None);

fn with_validators<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, Vec<ValidatorFn>>) -> R,
{
    let mut guard = VALIDATORS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn with_post_processors<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<PostProcessorFn>) -> R,
{
    let mut guard = POST_PROCESSORS.lock().unwrap_or_else(|e| e.into_inner());
    let list = guard.get_or_insert_with(Vec::new);
    f(list)
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Register a custom validator for a specific sub_category.
pub fn register_validator(sub_category: &str, validator: ValidatorFn) {
    with_validators(|map| {
        map.entry(sub_category.to_string())
            .or_default()
            .push(validator);
    });
}

/// Remove all validators for a sub_category.
pub fn unregister_validators(sub_category: &str) {
    with_validators(|map| {
        map.remove(sub_category);
    });
}

/// Run all registered validators for a match.
/// Returns true if the match passes all validators (or has none).
pub fn run_validators(m: &Match) -> bool {
    // Run under a single lock acquisition to avoid TOCTOU races
    with_validators(|map| {
        if let Some(validators) = map.get(&m.sub_category) {
            for validator in validators {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validator(m))) {
                    Ok(true) => {}
                    Ok(false) => return false,
                    Err(e) => {
                        tracing::error!("Validator panicked: {:?}", e);
                        return false; // fail-closed
                    }
                }
            }
        }
        true
    })
}

// ---------------------------------------------------------------------------
// Post-processors
// ---------------------------------------------------------------------------

/// Register a post-processor that transforms the match list.
pub fn register_post_processor(processor: PostProcessorFn) {
    with_post_processors(|list| {
        list.push(processor);
    });
}

/// Remove all registered post-processors.
pub fn unregister_post_processors() {
    with_post_processors(|list| {
        list.clear();
    });
}

/// Run all post-processors sequentially on the match list.
pub fn run_post_processors(matches: Vec<Match>) -> Vec<Match> {
    with_post_processors(|processors| {
        let mut current = matches;
        for processor in processors.iter() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| processor(current.clone()))) {
                Ok(result) => current = result,
                Err(e) => {
                    tracing::error!("Post-processor panicked: {:?}", e);
                }
            }
        }
        current
    })
}

/// Clear all validators and post-processors.
pub fn clear_all() {
    with_validators(|map| map.clear());
    with_post_processors(|list| list.clear());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(sub_cat: &str) -> Match {
        Match {
            text: "test".to_string(),
            category: "test".to_string(),
            sub_category: sub_cat.to_string(),
            has_context: false,
            confidence: 0.9,
            span: (0, 4),
            context_required: false,
        }
    }

    #[test]
    fn test_no_validators_passes() {
        clear_all();
        let m = make_match("unknown_sub");
        assert!(run_validators(&m));
    }

    #[test]
    fn test_register_and_run_validator() {
        clear_all();
        register_validator("ssn", Box::new(|m: &Match| m.confidence > 0.5));
        let m = make_match("ssn");
        assert!(run_validators(&m));

        let mut low = make_match("ssn");
        low.confidence = 0.2;
        assert!(!run_validators(&low));
        clear_all();
    }

    #[test]
    fn test_unregister_validators() {
        clear_all();
        register_validator("cc", Box::new(|_| false));
        unregister_validators("cc");
        let m = make_match("cc");
        assert!(run_validators(&m));
        clear_all();
    }

    #[test]
    fn test_post_processor() {
        clear_all();
        register_post_processor(Box::new(|matches: Vec<Match>| {
            matches.into_iter().filter(|m| m.confidence > 0.5).collect()
        }));

        let mut low = make_match("a");
        low.confidence = 0.3;
        let high = make_match("b");

        let result = run_post_processors(vec![low, high]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sub_category, "b");
        clear_all();
    }
}
