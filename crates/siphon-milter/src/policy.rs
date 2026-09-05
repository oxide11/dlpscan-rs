//! Verdict policy — what a scan result does to a message.
//!
//! Two decisions live here, both from `docs/architecture/email-dlp.md` §4.4,
//! and both deliberately explicit rather than inherited: what happens on a
//! finding, and what happens when we could not finish looking.

use crate::protocol::Response;
use std::fmt;

/// What the milter does when a message is `indeterminate` — when something
/// was not inspected, so the message has not been cleared.
///
/// Configured by `SIPHON_MILTER_ON_INDETERMINATE`, defaulting to [`Defer`].
///
/// [`Defer`]: OnIndeterminate::Defer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnIndeterminate {
    /// SMTP 451 tempfail. The sender's MTA retries; nothing is lost and
    /// nothing is delivered uninspected.
    ///
    /// The default, because it is the only option that is wrong in a
    /// recoverable direction. A deferred message is retried for days before
    /// it bounces and the sender is told; a delivered-uninspected message is
    /// a silent miss, which is the failure this product exists to prevent.
    ///
    /// The cost is real and is why this is configurable at all: under
    /// fail-closed, **scanner unavailability is mail unavailability**. That
    /// trade is right where an uninspected message is the worse outcome, and
    /// wrong where mail must flow regardless — a judgement that belongs to
    /// the operator, not to us.
    #[default]
    Defer,
    /// Accept, and hold in the MTA's quarantine queue for a human.
    Quarantine,
    /// Fail open: deliver, annotated. Chosen, never inherited.
    Deliver,
}

impl OnIndeterminate {
    pub fn as_str(self) -> &'static str {
        match self {
            OnIndeterminate::Defer => "defer",
            OnIndeterminate::Quarantine => "quarantine",
            OnIndeterminate::Deliver => "deliver",
        }
    }

    /// Parse the env value. Unknown values are an error, never a silent
    /// fallback: a typo in this setting would otherwise flip a deployment's
    /// failure direction without anyone noticing.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "defer" => Ok(OnIndeterminate::Defer),
            "quarantine" => Ok(OnIndeterminate::Quarantine),
            "deliver" => Ok(OnIndeterminate::Deliver),
            other => Err(PolicyError::UnknownIndeterminate(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnknownIndeterminate(String),
    /// `quarantine` was configured but there is nowhere to put messages.
    QuarantineUnavailable,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::UnknownIndeterminate(v) => write!(
                f,
                "SIPHON_MILTER_ON_INDETERMINATE={v:?} is not one of defer|quarantine|deliver"
            ),
            PolicyError::QuarantineUnavailable => write!(
                f,
                "SIPHON_MILTER_ON_INDETERMINATE=quarantine needs a quarantine destination, \
                 which is not built yet — set defer or deliver"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The message-level verdict.
///
/// Re-exported from `siphon-mail` rather than redefined. It was briefly
/// duplicated here, when the model lived inside siphon-api's binary crate and
/// there was nothing to depend on — two enums and two `as_str` tables writing
/// the same strings into the same column, with only a test holding them
/// together. Sharing the crate removes the possibility of drift instead of
/// testing for it.
pub use siphon_mail::Verdict;

/// What the milter should do about a message, once the verdict is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Deliver. Headers are still stamped — §1 is annotate, don't block.
    Accept,
    /// Defer with a 4xx; the sender retries.
    Defer,
    /// Accept but hold in the MTA's quarantine queue.
    Quarantine(String),
    /// Reject with a 5xx.
    Reject,
}

impl Action {
    /// The wire response, for the final reply at end-of-message.
    pub fn response(&self) -> Response {
        match self {
            Action::Accept => Response::Accept,
            // A specific code and enhanced status beats a bare tempfail: the
            // postmaster reading a deferred queue can tell a DLP hold from a
            // greylist or a full disk.
            Action::Defer => Response::ReplyCode {
                code: 451,
                text: "4.7.1 Message could not be fully inspected; try again later".into(),
            },
            Action::Quarantine(reason) => Response::Quarantine {
                reason: reason.clone(),
            },
            Action::Reject => Response::ReplyCode {
                code: 550,
                text: "5.7.1 Message rejected by content policy".into(),
            },
        }
    }
}

/// Map a verdict to an action.
///
/// `block` rejects; `quarantine` holds; `flagged` and `clean` deliver, because
/// §1 is annotate-don't-block and the header carries the finding. Only
/// `indeterminate` consults the configured policy — it is the one case where
/// what to do is a deployment decision rather than a property of the message.
pub fn action_for(verdict: Verdict, on_indeterminate: OnIndeterminate) -> Action {
    match verdict {
        Verdict::Clean | Verdict::Flagged => Action::Accept,
        Verdict::Quarantine => Action::Quarantine("siphon: content policy".into()),
        Verdict::Block => Action::Reject,
        Verdict::Indeterminate => match on_indeterminate {
            OnIndeterminate::Defer => Action::Defer,
            OnIndeterminate::Quarantine => {
                Action::Quarantine("siphon: message could not be fully inspected".into())
            }
            OnIndeterminate::Deliver => Action::Accept,
        },
    }
}

/// Headers stamped into every message, per §1.
///
/// Written even when the verdict is `clean`: a missing header is ambiguous
/// between "scanned and clean" and "never reached the filter", and an
/// investigator needs to tell those apart.
pub fn verdict_headers(
    verdict: Verdict,
    categories: &[String],
    finding_count: usize,
    scan_id: &str,
) -> Vec<(String, String)> {
    vec![
        ("X-Siphon-Result".into(), verdict.as_str().into()),
        ("X-Siphon-Categories".into(), categories.join(",")),
        ("X-Siphon-Findings".into(), finding_count.to_string()),
        ("X-Siphon-Scan-Id".into(), scan_id.into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_fail_closed() {
        assert_eq!(OnIndeterminate::default(), OnIndeterminate::Defer);
        assert_eq!(
            action_for(Verdict::Indeterminate, OnIndeterminate::default()),
            Action::Defer
        );
    }

    /// A typo must not silently flip a deployment from fail-closed to
    /// fail-open, so an unknown value is an error rather than a fallback.
    #[test]
    fn an_unknown_policy_value_is_rejected_not_defaulted() {
        assert!(OnIndeterminate::parse("defer").is_ok());
        assert!(OnIndeterminate::parse("QUARANTINE").is_ok());
        assert!(OnIndeterminate::parse("  deliver  ").is_ok());
        assert_eq!(
            OnIndeterminate::parse("fail-open"),
            Err(PolicyError::UnknownIndeterminate("fail-open".into()))
        );
        assert!(OnIndeterminate::parse("").is_err());
    }

    #[test]
    fn indeterminate_follows_the_configured_policy() {
        for (policy, expected) in [
            (OnIndeterminate::Defer, Action::Defer),
            (
                OnIndeterminate::Quarantine,
                Action::Quarantine("siphon: message could not be fully inspected".into()),
            ),
            (OnIndeterminate::Deliver, Action::Accept),
        ] {
            assert_eq!(action_for(Verdict::Indeterminate, policy), expected);
        }
    }

    /// Only indeterminate consults the policy. A blocked message is blocked
    /// whatever the operator chose for the uninspected case.
    #[test]
    fn other_verdicts_ignore_the_indeterminate_policy() {
        for policy in [
            OnIndeterminate::Defer,
            OnIndeterminate::Quarantine,
            OnIndeterminate::Deliver,
        ] {
            assert_eq!(action_for(Verdict::Clean, policy), Action::Accept);
            assert_eq!(action_for(Verdict::Flagged, policy), Action::Accept);
            assert_eq!(action_for(Verdict::Block, policy), Action::Reject);
        }
    }

    /// §1: annotate, don't block. A finding is stamped and delivered; the
    /// MTA's own rules decide what happens next.
    #[test]
    fn flagged_still_delivers() {
        assert_eq!(
            action_for(Verdict::Flagged, OnIndeterminate::Defer),
            Action::Accept
        );
    }

    #[test]
    fn defer_replies_with_a_4xx_and_an_enhanced_status() {
        match Action::Defer.response() {
            Response::ReplyCode { code, text } => {
                assert_eq!(code, 451);
                assert!(
                    text.starts_with("4.7.1"),
                    "expected enhanced status: {text}"
                );
            }
            other => panic!("expected a reply code, got {other:?}"),
        }
    }

    #[test]
    fn reject_replies_with_a_5xx() {
        match Action::Reject.response() {
            Response::ReplyCode { code, .. } => assert_eq!(code, 550),
            other => panic!("expected a reply code, got {other:?}"),
        }
    }

    /// The severity ladder must match siphon-api's, since both write the same
    /// strings into the same column.
    #[test]
    fn verdict_ladder_orders_indeterminate_between_clean_and_flagged() {
        assert!(Verdict::Clean < Verdict::Indeterminate);
        assert!(Verdict::Indeterminate < Verdict::Flagged);
        assert!(Verdict::Flagged < Verdict::Quarantine);
        assert!(Verdict::Quarantine < Verdict::Block);
    }

    /// The strings, not the enum, are the contract: they reach the
    /// `messages.verdict` column, the `messages_verdict_ck` CHECK constraint
    /// and the `X-Siphon-Result` header. Pinned here so a rename in
    /// siphon-mail cannot silently change what an MTA sees.
    #[test]
    fn verdict_strings_are_the_wire_contract() {
        assert_eq!(Verdict::Clean.as_str(), "clean");
        assert_eq!(Verdict::Indeterminate.as_str(), "indeterminate");
        assert_eq!(Verdict::Flagged.as_str(), "flagged");
        assert_eq!(Verdict::Quarantine.as_str(), "quarantine");
        assert_eq!(Verdict::Block.as_str(), "block");
    }

    /// A clean message is stamped too: a missing header cannot be told apart
    /// from a message that never reached the filter.
    #[test]
    fn headers_are_written_even_when_clean() {
        let h = verdict_headers(Verdict::Clean, &[], 0, "abc-123");
        assert_eq!(h.len(), 4);
        assert_eq!(h[0], ("X-Siphon-Result".into(), "clean".into()));
        assert_eq!(h[2], ("X-Siphon-Findings".into(), "0".into()));
        assert_eq!(h[3], ("X-Siphon-Scan-Id".into(), "abc-123".into()));
    }

    #[test]
    fn categories_are_comma_joined() {
        let h = verdict_headers(
            Verdict::Flagged,
            &["SSN".to_string(), "Credit Card".to_string()],
            3,
            "id",
        );
        assert_eq!(
            h[1],
            ("X-Siphon-Categories".into(), "SSN,Credit Card".into())
        );
    }
}
