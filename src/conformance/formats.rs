//! The format matrix: five cases for every file format Siphon claims.
//!
//! Cases are grouped by format and each group is exactly the five slots from
//! [`super::Slot`]. [`cases`] returns the whole matrix; feature-gated formats
//! contribute nothing when their feature is off, so a minimal build reports
//! honestly on what it actually contains rather than failing on readers it
//! was never compiled with.

use super::build;
use super::{case, gap, Case, Expect, Slot, AWS_KEY, CARD, IBAN, INNOCUOUS, SSN};

/// Every case in the matrix, in a stable order.
pub fn cases() -> Vec<Case> {
    let mut v = Vec::new();
    v.extend(txt());
    v.extend(csv());
    v.extend(json());
    v.extend(rtf());
    v.extend(eml());
    v.extend(mbox());
    v.extend(mhtml());
    v.extend(vcf());
    v.extend(ldif());
    v.extend(ics());
    v.extend(warc());
    #[cfg(feature = "office")]
    {
        v.extend(docx());
        v.extend(xlsx());
        v.extend(pptx());
        v.extend(odt());
        v.extend(ods());
    }
    #[cfg(feature = "pdf")]
    v.extend(pdf());
    #[cfg(feature = "archives")]
    {
        v.extend(zip_archive());
        v.extend(sevenz());
    }
    #[cfg(feature = "data-formats")]
    v.extend(sqlite());
    #[cfg(feature = "barcode")]
    v.extend(png());
    v
}

// ---------------------------------------------------------------------------
// Text and text-shaped formats
// ---------------------------------------------------------------------------

fn txt() -> Vec<Case> {
    vec![
        case(
            "txt",
            Slot::Clean,
            "notes.txt",
            INNOCUOUS,
            Expect::NoFindings,
            "ordinary prose must not trip any pattern",
        ),
        case(
            "txt",
            Slot::Single,
            "notes.txt",
            format!("Customer SSN on file: {SSN}"),
            Expect::Detects(SSN),
            "the simplest possible case: a labelled value in plain text",
        ),
        case(
            "txt",
            Slot::Structural,
            "notes.txt",
            format!("{INNOCUOUS}\n\n{}\n\ncard {CARD}\n", "-".repeat(60)),
            Expect::Detects(CARD),
            "a value past the end of the first block is still in the file",
        ),
        case(
            "txt",
            Slot::Damaged,
            "notes.txt",
            {
                let mut v = b"Customer record\n".to_vec();
                v.extend_from_slice(&[0xff, 0xfe, 0xfd]);
                v.extend_from_slice(format!("\nSSN {SSN}\n").as_bytes());
                v
            },
            Expect::Detects(SSN),
            "lossy decoding must not lose the rest of the file — a bad byte \
             sequence is recoverable, unlike an unparseable container",
        ),
        case(
            "txt",
            Slot::Evasive,
            "notes.txt",
            format!("Employee SSN: {}", SSN.replace('-', " ")),
            Expect::DetectsSubCategory("USA SSN"),
            "space-separated groups are a known bypass shape. The context word \
             stays, so this case varies the separator and nothing else — \
             without it the case would really be testing the context gate",
        ),
    ]
}

fn csv() -> Vec<Case> {
    vec![
        case(
            "csv",
            Slot::Clean,
            "rows.csv",
            "id,region,status\n1,EMEA,active\n2,APAC,active\n3,AMER,closed\n",
            Expect::NoFindings,
            "a schema with no sensitive columns",
        ),
        case(
            "csv",
            Slot::Single,
            "rows.csv",
            format!("id,ssn,status\n1,{SSN},active\n"),
            Expect::Detects(SSN),
            "a value in a labelled column",
        ),
        case(
            "csv",
            Slot::Structural,
            "rows.csv",
            format!(
                "id,region,status\n{}\n99,EMEA,{CARD}\n",
                (1..40)
                    .map(|i| format!("{i},EMEA,active"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            Expect::Detects(CARD),
            "the last row of a long file is as much in scope as the first",
        ),
        case(
            "csv",
            Slot::Damaged,
            "rows.csv",
            format!("id,ssn,status\n1,\"{SSN},active\n"),
            Expect::Detects(SSN),
            "an unterminated quoted field must not swallow the row — CSV is \
             read as text, so a quoting error is not an unreadable file",
        ),
        case(
            "csv",
            Slot::Evasive,
            "rows.csv",
            format!("id,notes\n1,\"card number is {CARD}, do not share\"\n"),
            Expect::Detects(CARD),
            "a value inside a quoted free-text field",
        ),
    ]
}

fn json() -> Vec<Case> {
    vec![
        case(
            "json",
            Slot::Clean,
            "config.json",
            r#"{"service":"siphon","replicas":3,"region":"eu-west-1"}"#,
            Expect::NoFindings,
            "ordinary configuration",
        ),
        case(
            "json",
            Slot::Single,
            "config.json",
            format!(r#"{{"aws_access_key_id":"{AWS_KEY}"}}"#),
            Expect::Detects(AWS_KEY),
            "a credential as a JSON string value",
        ),
        case(
            "json",
            Slot::Structural,
            "config.json",
            format!(r#"{{"a":{{"b":{{"c":{{"d":{{"customer":{{"ssn":"{SSN}"}}}}}}}}}}}}"#),
            Expect::Detects(SSN),
            "nesting depth is not a hiding place",
        ),
        case(
            "json",
            Slot::Damaged,
            "config.json",
            format!(r#"{{"aws_access_key_id":"{AWS_KEY}""#),
            Expect::Detects(AWS_KEY),
            "truncated JSON is still text; the scanner does not need it to parse",
        ),
        gap(
            case(
                "json",
                Slot::Evasive,
                "config.json",
                format!(
                    r#"{{"note":"{}"}}"#,
                    SSN.chars()
                        .map(|c| format!("\\u{:04x}", c as u32))
                        .collect::<String>()
                ),
                Expect::DetectsSubCategory("USA SSN"),
                "\\u escapes are a JSON-native way to spell a value",
            ),
            "the normalizer decodes HTML entities, percent-encoding, base64, \
             base32 and hex, but not JSON \\uXXXX escapes. JSON is a first-class \
             input format, so a value spelled this way passes through unread. \
             Fixing it means one more decode stage in normalize/.",
        ),
    ]
}

fn rtf() -> Vec<Case> {
    vec![
        case(
            "rtf",
            Slot::Clean,
            "doc.rtf",
            format!("{{\\rtf1\\ansi\\deff0 {INNOCUOUS}}}"),
            Expect::NoFindings,
            "RTF control words must not themselves look sensitive",
        ),
        case(
            "rtf",
            Slot::Single,
            "doc.rtf",
            format!("{{\\rtf1\\ansi\\deff0 Customer SSN: {SSN}}}"),
            Expect::Detects(SSN),
            "a value in the document body",
        ),
        case(
            "rtf",
            Slot::Structural,
            "doc.rtf",
            format!(
                "{{\\rtf1\\ansi\\deff0{{\\fonttbl{{\\f0 Arial;}}}}\
                 {{\\info{{\\title Quarterly}}}}\\par {INNOCUOUS}\\par Card: {CARD}}}"
            ),
            Expect::Detects(CARD),
            "a value after font and info groups, where naive strippers lose the tail",
        ),
        case(
            "rtf",
            Slot::Damaged,
            "doc.rtf",
            format!("{{\\rtf1\\ansi\\deff0 Customer SSN: {SSN}"),
            Expect::Detects(SSN),
            "an unclosed group must not discard the text already read",
        ),
        case(
            "rtf",
            Slot::Evasive,
            "doc.rtf",
            format!(
                "{{\\rtf1\\ansi\\deff0 Employee SSN: {}\\b0 {}}}",
                &SSN[..3],
                &SSN[3..]
            ),
            Expect::DetectsSubCategory("USA SSN"),
            "a control word spliced into a value still renders as that value",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Mail formats
// ---------------------------------------------------------------------------

fn eml() -> Vec<Case> {
    vec![
        case(
            "eml",
            Slot::Clean,
            "m.eml",
            build::eml("Planning", INNOCUOUS, &[]),
            Expect::NoFindingsExcept(&["Email Address"]),
            "a plain message with nothing in it. The From and To addresses are \
             detected and that is correct — an envelope address is contact \
             information. \"Clean\" for a message can only mean nothing beyond \
             the addresses that make it a message",
        ),
        case(
            "eml",
            Slot::Single,
            "m.eml",
            build::eml("Record", &format!("SSN {SSN}"), &[]),
            Expect::Detects(SSN),
            "a value in the message body",
        ),
        case(
            "eml",
            Slot::Structural,
            "m.eml",
            build::eml(
                "See attached",
                INNOCUOUS,
                &[(
                    "text/plain",
                    "7bit",
                    &format!("account IBAN {IBAN} for settlement"),
                )],
            ),
            Expect::Detects(IBAN),
            "an attachment is content, not metadata",
        ),
        case(
            "eml",
            Slot::Damaged,
            "m.eml",
            format!(
                "From: a@example.com\r\nSubject: Broken\r\n\
                 Content-Type: multipart/mixed; boundary=\"NOPE\"\r\n\r\n\
                 SSN {SSN}\r\n"
            ),
            Expect::Detects(SSN),
            "a message whose MIME structure is wrong still has readable text",
        ),
        case(
            "eml",
            Slot::Evasive,
            "m.eml",
            build::eml(
                "Invoice",
                INNOCUOUS,
                &[(
                    "application/octet-stream",
                    "base64",
                    &build::b64_wrapped(format!("primary card {CARD}").as_bytes()),
                )],
            ),
            Expect::Detects(CARD),
            "a base64 attachment was a live bypass: the payload reached the \
             scanner still encoded and the message came back clean",
        ),
    ]
}

fn mbox() -> Vec<Case> {
    fn msg(subject: &str, body: &str) -> String {
        format!(
            "From sender@example.com Thu Jan  1 00:00:00 2026\n\
             From: sender@example.com\nSubject: {subject}\n\n{body}\n\n"
        )
    }
    vec![
        case(
            "mbox",
            Slot::Clean,
            "archive.mbox",
            msg("Planning", INNOCUOUS),
            Expect::NoFindingsExcept(&["Email Address"]),
            "a single innocuous message; the sender address is inherent to it",
        ),
        case(
            "mbox",
            Slot::Single,
            "archive.mbox",
            msg("Record", &format!("SSN {SSN}")),
            Expect::Detects(SSN),
            "a value in the only message",
        ),
        case(
            "mbox",
            Slot::Structural,
            "archive.mbox",
            format!(
                "{}{}{}",
                msg("One", INNOCUOUS),
                msg("Two", INNOCUOUS),
                msg("Three", &format!("card {CARD}"))
            ),
            Expect::Detects(CARD),
            "the third message in the box — a reader that stops after one \
             message reports the rest of the archive clean",
        ),
        gap(
            case(
                "mbox",
                Slot::Damaged,
                "archive.mbox",
                format!("From \nFrom: \nSubject:\n\nSSN {SSN}\n"),
                Expect::Detects(SSN),
                "a malformed separator line must not drop the message body",
            ),
            "the mbox reader returns zero characters for this file, with no \
             warning — so the body is dropped AND the result looks like a \
             faithful read of an empty archive. That is a fail-open: a caller \
             cannot tell it from a genuinely empty mbox. Whatever the parse \
             does with a malformed \"From \" line, it has to either keep the \
             body or say it dropped it.",
        ),
        case(
            "mbox",
            Slot::Evasive,
            "archive.mbox",
            format!(
                "From sender@example.com Thu Jan  1 00:00:00 2026\n\
                 From: sender@example.com\nSubject: Invoice\n\
                 Content-Transfer-Encoding: base64\n\n{}\n",
                build::b64_wrapped(format!("card {CARD}").as_bytes())
            ),
            Expect::DetectsSubCategory("Visa"),
            "a base64 message body inside an mbox. Asserted by category, not by \
             the decoded digits: the scanner decodes internally but reports the \
             span as it appeared — the base64 text — which is what a redactor \
             has to overwrite",
        ),
    ]
}

fn mhtml() -> Vec<Case> {
    fn doc(body: &str) -> String {
        format!(
            "From: <Saved by Siphon>\r\nSubject: Page\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/related; boundary=\"----=_B\"\r\n\r\n\
             ------=_B\r\nContent-Type: text/html\r\n\
             Content-Location: http://example.com/\r\n\r\n\
             <html><body>{body}</body></html>\r\n------=_B--\r\n"
        )
    }
    vec![
        case(
            "mhtml",
            Slot::Clean,
            "page.mhtml",
            doc(&format!("<p>{INNOCUOUS}</p>")),
            Expect::NoFindings,
            "a saved page with nothing in it",
        ),
        case(
            "mhtml",
            Slot::Single,
            "page.mhtml",
            doc(&format!("<p>SSN {SSN}</p>")),
            Expect::Detects(SSN),
            "a value in the HTML part",
        ),
        case(
            "mhtml",
            Slot::Structural,
            "page.mhtml",
            format!(
                "From: <Saved by Siphon>\r\nSubject: Page\r\nMIME-Version: 1.0\r\n\
                 Content-Type: multipart/related; boundary=\"----=_B\"\r\n\r\n\
                 ------=_B\r\nContent-Type: text/html\r\n\r\n\
                 <html><body>{INNOCUOUS}</body></html>\r\n\
                 ------=_B\r\nContent-Type: text/plain\r\n\
                 Content-Location: http://example.com/notes.txt\r\n\r\ncard {CARD}\r\n\
                 ------=_B--\r\n"
            ),
            Expect::Detects(CARD),
            "a second related part, which is where a saved page keeps its resources",
        ),
        case(
            "mhtml",
            Slot::Damaged,
            "page.mhtml",
            format!(
                "From: <Saved by Siphon>\r\nContent-Type: multipart/related; \
                 boundary=\"----=_B\"\r\n\r\n------=_B\r\nContent-Type: text/html\r\n\r\n\
                 <html><body>SSN {SSN}"
            ),
            Expect::Detects(SSN),
            "a truncated archive still contains everything up to the cut",
        ),
        case(
            "mhtml",
            Slot::Evasive,
            "page.mhtml",
            doc(&format!(
                "<p>SSN {}</p>",
                SSN.chars()
                    .map(|c| if c == '-' {
                        "-".to_string()
                    } else {
                        format!("&#{};", c as u32)
                    })
                    .collect::<String>()
            )),
            Expect::DetectsSubCategory("USA SSN"),
            "HTML numeric entities render as the value and must be decoded",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Contact and calendar formats
// ---------------------------------------------------------------------------

fn vcf() -> Vec<Case> {
    fn card_doc(extra: &str) -> String {
        format!(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Dana Whitfield\r\n\
             ORG:Example Corp\r\n{extra}END:VCARD\r\n"
        )
    }
    vec![
        case(
            "vcf",
            Slot::Clean,
            "c.vcf",
            card_doc("TITLE:Operations Lead\r\n"),
            Expect::NoFindings,
            "a name and a job title are not, by themselves, a finding",
        ),
        case(
            "vcf",
            Slot::Single,
            "c.vcf",
            card_doc(&format!("NOTE:SSN on file {SSN}\r\n")),
            Expect::Detects(SSN),
            "a value in a NOTE property",
        ),
        case(
            "vcf",
            Slot::Structural,
            "c.vcf",
            format!(
                "{}{}",
                card_doc("TITLE:Lead\r\n"),
                card_doc(&format!("NOTE:card {CARD}\r\n"))
            ),
            Expect::Detects(CARD),
            "a .vcf may hold many cards; the second one counts",
        ),
        case(
            "vcf",
            Slot::Damaged,
            "c.vcf",
            format!("BEGIN:VCARD\r\nVERSION:3.0\r\nNOTE:SSN {SSN}\r\n"),
            Expect::Detects(SSN),
            "a card with no END must not be discarded wholesale",
        ),
        case(
            "vcf",
            Slot::Evasive,
            "c.vcf",
            format!(
                "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Dana\r\nNOTE:card {}\r\n {}\r\nEND:VCARD\r\n",
                &CARD[..8],
                &CARD[8..]
            ),
            Expect::Detects(CARD),
            "RFC 6350 line folding splits a value across lines; unfold before \
             scanning or every long value is a bypass",
        ),
    ]
}

fn ldif() -> Vec<Case> {
    fn entry(dn: &str, attrs: &str) -> String {
        format!("dn: {dn}\nobjectClass: person\n{attrs}\n")
    }
    vec![
        case(
            "ldif",
            Slot::Clean,
            "dir.ldif",
            entry("cn=Dana,dc=example,dc=com", "cn: Dana\nsn: Whitfield\n"),
            Expect::NoFindings,
            "a directory entry with only names",
        ),
        case(
            "ldif",
            Slot::Single,
            "dir.ldif",
            entry(
                "cn=Dana,dc=example,dc=com",
                &format!("cn: Dana\ndescription: SSN {SSN}\n"),
            ),
            Expect::Detects(SSN),
            "a value in an attribute",
        ),
        case(
            "ldif",
            Slot::Structural,
            "dir.ldif",
            format!(
                "{}{}",
                entry("cn=A,dc=example,dc=com", "cn: A\n"),
                entry(
                    "cn=B,dc=example,dc=com",
                    &format!("cn: B\ndescription: card {CARD}\n")
                )
            ),
            Expect::Detects(CARD),
            "the second entry in the file",
        ),
        case(
            "ldif",
            Slot::Damaged,
            "dir.ldif",
            format!("dn: cn=Dana,dc=example\ndescription: SSN {SSN}"),
            Expect::Detects(SSN),
            "no trailing newline and no objectClass is still readable",
        ),
        case(
            "ldif",
            Slot::Evasive,
            "dir.ldif",
            format!(
                "dn: cn=Dana,dc=example,dc=com\ndescription:: {}\n",
                build::b64(format!("card {CARD}").as_bytes())
            ),
            Expect::Detects(CARD),
            "`::` is LDIF's own base64 attribute form — the standard way to \
             put an arbitrary value in a directory, not an exotic one",
        ),
    ]
}

fn ics() -> Vec<Case> {
    fn cal(body: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\n{body}END:VCALENDAR\r\n"
        )
    }
    fn event(summary: &str, desc: &str) -> String {
        format!(
            "BEGIN:VEVENT\r\nUID:{summary}@example.com\r\nDTSTAMP:20260101T000000Z\r\n\
             SUMMARY:{summary}\r\nDESCRIPTION:{desc}\r\nEND:VEVENT\r\n"
        )
    }
    vec![
        case(
            "ics",
            Slot::Clean,
            "cal.ics",
            cal(&event("Retrospective", "Sprint review and planning")),
            Expect::NoFindings,
            "an ordinary calendar entry",
        ),
        case(
            "ics",
            Slot::Single,
            "cal.ics",
            cal(&event("Onboarding", &format!("collect SSN {SSN}"))),
            Expect::Detects(SSN),
            "a value in an event description",
        ),
        case(
            "ics",
            Slot::Structural,
            "cal.ics",
            cal(&format!(
                "{}{}{}",
                event("One", "nothing here"),
                event("Two", "nothing here either"),
                event("Three", &format!("card {CARD}"))
            )),
            Expect::Detects(CARD),
            "the third VEVENT — a reader that takes only the first reports \
             the rest of the calendar clean",
        ),
        case(
            "ics",
            Slot::Damaged,
            "cal.ics",
            format!("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDESCRIPTION:SSN {SSN}\r\n"),
            Expect::Detects(SSN),
            "unterminated VEVENT and VCALENDAR",
        ),
        case(
            "ics",
            Slot::Evasive,
            "cal.ics",
            cal(&format!(
                "BEGIN:VEVENT\r\nUID:x@example.com\r\nDESCRIPTION:card {}\r\n {}\r\nEND:VEVENT\r\n",
                &CARD[..8],
                &CARD[8..]
            )),
            Expect::Detects(CARD),
            "iCalendar folds long lines at 75 octets, so any long value arrives split",
        ),
    ]
}

fn warc() -> Vec<Case> {
    fn record(uri: &str, payload: &str) -> String {
        let block = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{payload}");
        format!(
            "WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: {uri}\r\n\
             WARC-Date: 2026-01-01T00:00:00Z\r\n\
             Content-Type: application/http; msgtype=response\r\n\
             Content-Length: {}\r\n\r\n{block}\r\n\r\n",
            block.len()
        )
    }
    vec![
        case(
            "warc",
            Slot::Clean,
            "crawl.warc",
            record("http://example.com/a", INNOCUOUS),
            Expect::NoFindings,
            "an archived page with nothing in it",
        ),
        case(
            "warc",
            Slot::Single,
            "crawl.warc",
            record("http://example.com/a", &format!("SSN {SSN}")),
            Expect::Detects(SSN),
            "a value in the archived response body",
        ),
        case(
            "warc",
            Slot::Structural,
            "crawl.warc",
            format!(
                "{}{}",
                record("http://example.com/a", INNOCUOUS),
                record("http://example.com/b", &format!("card {CARD}"))
            ),
            Expect::Detects(CARD),
            "the second record — a WARC is a concatenation, and a reader that \
             stops at the first record silently drops the crawl",
        ),
        case(
            "warc",
            Slot::Damaged,
            "crawl.warc",
            format!(
                "WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 99999\r\n\r\n\
                 HTTP/1.1 200 OK\r\n\r\nSSN {SSN}"
            ),
            Expect::Detects(SSN),
            "a Content-Length past the end of the file must not truncate what \
             was actually read",
        ),
        case(
            "warc",
            Slot::Evasive,
            "crawl.warc",
            record(
                "http://example.com/a",
                &format!(
                    "<html><body>card {}</body></html>",
                    CARD.chars()
                        .map(|c| format!("&#{};", c as u32))
                        .collect::<String>()
                ),
            ),
            Expect::DetectsSubCategory("Visa"),
            "HTML entities inside an archived response",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Office and OpenDocument
// ---------------------------------------------------------------------------

#[cfg(feature = "office")]
fn docx() -> Vec<Case> {
    vec![
        case(
            "docx",
            Slot::Clean,
            "d.docx",
            build::docx(&[INNOCUOUS]),
            Expect::NoFindings,
            "OOXML boilerplate must not itself produce findings",
        ),
        case(
            "docx",
            Slot::Single,
            "d.docx",
            build::docx(&[&format!("Customer SSN: {SSN}")]),
            Expect::Detects(SSN),
            "a value in the first paragraph",
        ),
        case(
            "docx",
            Slot::Structural,
            "d.docx",
            build::docx(&[INNOCUOUS, INNOCUOUS, &format!("Card on file {CARD}")]),
            Expect::Detects(CARD),
            "the third paragraph of the body",
        ),
        case(
            "docx",
            Slot::Damaged,
            "d.docx",
            {
                let mut v = build::docx(&[&format!("Customer SSN: {SSN}")]);
                v.truncate(v.len() / 2);
                v
            },
            Expect::NotSilentlyClean,
            "a truncated Office file must not read as an empty clean document \
             — this is the fail-open a scanner cannot afford",
        ),
        case(
            "docx",
            Slot::Evasive,
            "d.docx",
            build::docx(&[&format!(
                "Card </w:t></w:r><w:r><w:t>{}</w:t></w:r><w:r><w:t>{}",
                &CARD[..8],
                &CARD[8..]
            )]),
            Expect::Detects(CARD),
            "a value split across adjacent runs still renders as one value — \
             and Word does this on its own after an edit, so it is not even \
             an attack",
        ),
    ]
}

#[cfg(feature = "office")]
fn xlsx() -> Vec<Case> {
    vec![
        case(
            "xlsx",
            Slot::Clean,
            "b.xlsx",
            build::xlsx(&[("Summary", &["Region", "EMEA", "APAC"])]),
            Expect::NoFindings,
            "a sheet of labels",
        ),
        case(
            "xlsx",
            Slot::Single,
            "b.xlsx",
            build::xlsx(&[("Customers", &["SSN", SSN])]),
            Expect::Detects(SSN),
            "a value in the first sheet",
        ),
        case(
            "xlsx",
            Slot::Structural,
            "b.xlsx",
            build::xlsx(&[
                ("Summary", &["Region", "EMEA"]),
                ("Notes", &["nothing here"]),
                ("Raw", &["card", CARD]),
            ]),
            Expect::Detects(CARD),
            "the third sheet — the classic place a spreadsheet keeps its \
             source data, and the classic thing a reader forgets to walk",
        ),
        case(
            "xlsx",
            Slot::Damaged,
            "b.xlsx",
            {
                let mut v = build::xlsx(&[("Customers", &["SSN", SSN])]);
                v.truncate(v.len() / 2);
                v
            },
            Expect::NotSilentlyClean,
            "a truncated workbook must not read as an empty clean one",
        ),
        gap(
            case(
                "xlsx",
                Slot::Evasive,
                "b.xlsx",
                build::xlsx(&[("Data", &[&CARD[..8], &CARD[8..]])]),
                Expect::NoFindings,
                "a card split across two cells is two numbers, and must not be \
                 reported: reaching across cells makes every spreadsheet of \
                 integers a card number",
            ),
            "the extractor now separates cells with a newline, but the scanner \
             normalizes whitespace before matching — and the card pattern \
             tolerates one separator — so two adjacent 8-digit cells still \
             read as one Luhn-valid card. Measured: \"41111111\\n11111111\" \
             matches Visa, while the same digits either side of other text do \
             not. This is a real precision cost, and it lands on spreadsheets, \
             which are the most common carrier of bulk numeric data. It is \
             recorded rather than fixed because the fix is not local: \
             whitespace normalization is what defeats a whole class of \
             evasion, so making the cell boundary hard needs a separator the \
             normalizer preserves, not a weaker normalizer.",
        ),
    ]
}

#[cfg(feature = "office")]
fn pptx() -> Vec<Case> {
    vec![
        case(
            "pptx",
            Slot::Clean,
            "p.pptx",
            build::pptx(&["Roadmap", "Next quarter"]),
            Expect::NoFindings,
            "slide titles with nothing in them",
        ),
        case(
            "pptx",
            Slot::Single,
            "p.pptx",
            build::pptx(&[&format!("Example record: SSN {SSN}")]),
            Expect::Detects(SSN),
            "a value on the first slide",
        ),
        case(
            "pptx",
            Slot::Structural,
            "p.pptx",
            build::pptx(&["Agenda", "Results", &format!("Appendix: card {CARD}")]),
            Expect::Detects(CARD),
            "the appendix slide, which is where the real data ends up",
        ),
        case(
            "pptx",
            Slot::Damaged,
            "p.pptx",
            {
                let mut v = build::pptx(&[&format!("SSN {SSN}")]);
                v.truncate(v.len() / 2);
                v
            },
            Expect::NotSilentlyClean,
            "a truncated deck must not read as an empty clean one",
        ),
        case(
            "pptx",
            Slot::Evasive,
            "p.pptx",
            build::pptx(&[&format!(
                "Card </a:t></a:r><a:r><a:t>{}</a:t></a:r><a:r><a:t>{}",
                &CARD[..8],
                &CARD[8..]
            )]),
            Expect::Detects(CARD),
            "a value split across DrawingML runs",
        ),
    ]
}

#[cfg(feature = "office")]
const ODT_MIME: &str = "application/vnd.oasis.opendocument.text";
#[cfg(feature = "office")]
const ODS_MIME: &str = "application/vnd.oasis.opendocument.spreadsheet";

#[cfg(feature = "office")]
fn odt() -> Vec<Case> {
    vec![
        case(
            "odt",
            Slot::Clean,
            "d.odt",
            build::odf(ODT_MIME, &[INNOCUOUS]),
            Expect::NoFindings,
            "an OpenDocument text file with nothing in it",
        ),
        case(
            "odt",
            Slot::Single,
            "d.odt",
            build::odf(ODT_MIME, &[&format!("Customer SSN: {SSN}")]),
            Expect::Detects(SSN),
            "a value in the first paragraph",
        ),
        case(
            "odt",
            Slot::Structural,
            "d.odt",
            build::odf(
                ODT_MIME,
                &[INNOCUOUS, INNOCUOUS, &format!("Card on file {CARD}")],
            ),
            Expect::Detects(CARD),
            "the third paragraph",
        ),
        case(
            "odt",
            Slot::Damaged,
            "d.odt",
            {
                let mut v = build::odf(ODT_MIME, &[&format!("SSN {SSN}")]);
                v.truncate(v.len() / 2);
                v
            },
            Expect::NotSilentlyClean,
            "a truncated ODF container must not read as an empty clean document",
        ),
        case(
            "odt",
            Slot::Evasive,
            "d.odt",
            build::odf(
                ODT_MIME,
                &[&format!(
                    "Card <text:span>{}</text:span><text:span>{}</text:span>",
                    &CARD[..8],
                    &CARD[8..]
                )],
            ),
            Expect::Detects(CARD),
            "a value split across <text:span> elements — ODF's equivalent of \
             the OOXML run split, and joined for the same reason. Note this is \
             span, not paragraph: two <text:p> are two lines, and joining those \
             would invent values the same way joining spreadsheet cells does",
        ),
    ]
}

#[cfg(feature = "office")]
fn ods() -> Vec<Case> {
    vec![
        case(
            "ods",
            Slot::Clean,
            "s.ods",
            build::odf(ODS_MIME, &["Region", "EMEA"]),
            Expect::NoFindings,
            "a spreadsheet of labels",
        ),
        case(
            "ods",
            Slot::Single,
            "s.ods",
            build::odf(ODS_MIME, &[&format!("SSN {SSN}")]),
            Expect::Detects(SSN),
            "a value in a cell",
        ),
        case(
            "ods",
            Slot::Structural,
            "s.ods",
            build::odf(
                ODS_MIME,
                &["Region", "EMEA", "APAC", &format!("card {CARD}")],
            ),
            Expect::Detects(CARD),
            "a value in the last row",
        ),
        case(
            "ods",
            Slot::Damaged,
            "s.ods",
            {
                let mut v = build::odf(ODS_MIME, &[&format!("SSN {SSN}")]);
                v.truncate(v.len() / 2);
                v
            },
            Expect::NotSilentlyClean,
            "a truncated spreadsheet must not read as an empty clean one",
        ),
        case(
            "ods",
            Slot::Evasive,
            "s.ods",
            build::odf(ODS_MIME, &[&format!("IBAN {}", IBAN.to_lowercase())]),
            Expect::Detects("de89"),
            "a lowercased IBAN is the same account number",
        ),
    ]
}

#[cfg(feature = "pdf")]
fn pdf() -> Vec<Case> {
    vec![
        case(
            "pdf",
            Slot::Clean,
            "d.pdf",
            build::pdf(&["Quarterly planning notes.", "No customer data here."]),
            Expect::NoFindings,
            "PDF structural keywords must not themselves produce findings",
        ),
        case(
            "pdf",
            Slot::Single,
            "d.pdf",
            build::pdf(&[&format!("Customer SSN: {SSN}")]),
            Expect::Detects(SSN),
            "a value in the page content stream",
        ),
        case(
            "pdf",
            Slot::Structural,
            "d.pdf",
            build::pdf(&[
                "Quarterly planning notes.",
                "No customer data here.",
                &format!("Appendix A: card {CARD}"),
            ]),
            Expect::Detects(CARD),
            "a value on the third text line of the stream",
        ),
        case(
            "pdf",
            Slot::Damaged,
            "d.pdf",
            {
                let mut v = build::pdf(&[&format!("Customer SSN: {SSN}")]);
                v.truncate(40);
                v.extend_from_slice(b"\nstartxref\n999999\n%%EOF\n");
                v
            },
            Expect::NotSilentlyClean,
            "a PDF that does not parse must say so. This was a real fail-open: \
             extraction returned Ok having fallen back to raw bytes, and the \
             caller could not tell that from a parse",
        ),
        case(
            "pdf",
            Slot::Evasive,
            "d.pdf",
            build::pdf(&[&format!("Card {} {}", &CARD[..8], &CARD[8..])]),
            Expect::DetectsSubCategory("Visa"),
            "PDF text positioning splits strings routinely; a space-separated \
             card is still a card. By category, because the reported span is \
             the spaced form as it appears on the page",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Archives
// ---------------------------------------------------------------------------

#[cfg(feature = "archives")]
fn zip_archive() -> Vec<Case> {
    vec![
        case(
            "zip",
            Slot::Clean,
            "a.zip",
            build::zip(&[("notes.txt", INNOCUOUS.as_bytes())]),
            Expect::NoFindings,
            "an archive of innocuous text",
        ),
        case(
            "zip",
            Slot::Single,
            "a.zip",
            build::zip(&[("record.txt", format!("SSN {SSN}").as_bytes())]),
            Expect::Detects(SSN),
            "a value in the only entry",
        ),
        case(
            "zip",
            Slot::Structural,
            "a.zip",
            build::zip(&[
                ("a.txt", INNOCUOUS.as_bytes()),
                ("b.txt", INNOCUOUS.as_bytes()),
                ("c.txt", format!("card {CARD}").as_bytes()),
            ]),
            Expect::Detects(CARD),
            "the third entry — an extractor that reads only the first makes a \
             zip a one-line bypass",
        ),
        case(
            "zip",
            Slot::Damaged,
            "a.zip",
            {
                let mut v = build::zip(&[("record.txt", format!("SSN {SSN}").as_bytes())]);
                let n = v.len();
                v.truncate(n - 8); // destroy the end-of-central-directory record
                v
            },
            Expect::NotSilentlyClean,
            "a zip with no central directory must be reported, not read as empty",
        ),
        case(
            "zip",
            Slot::Evasive,
            "a.zip",
            build::zip(&[(
                "payload.txt",
                build::b64_wrapped(format!("card {CARD}").as_bytes()).as_bytes(),
            )]),
            Expect::DetectsSubCategory("Visa"),
            "base64 inside an archive entry — two layers, each individually \
             handled, which is where layered decoders stop one short",
        ),
    ]
}

#[cfg(feature = "archives")]
fn sevenz() -> Vec<Case> {
    vec![
        case(
            "7z",
            Slot::Clean,
            "a.7z",
            build::sevenz(&[("notes.txt", INNOCUOUS.as_bytes())]),
            Expect::NoFindings,
            "a 7z of innocuous text",
        ),
        case(
            "7z",
            Slot::Single,
            "a.7z",
            build::sevenz(&[("record.txt", format!("SSN {SSN}").as_bytes())]),
            Expect::Detects(SSN),
            "a value in the only entry",
        ),
        case(
            "7z",
            Slot::Structural,
            "a.7z",
            build::sevenz(&[
                ("a.txt", INNOCUOUS.as_bytes()),
                ("b.txt", INNOCUOUS.as_bytes()),
                ("c.txt", format!("card {CARD}").as_bytes()),
            ]),
            Expect::Detects(CARD),
            "the third entry",
        ),
        case(
            "7z",
            Slot::Damaged,
            "a.7z",
            {
                let mut v = build::sevenz(&[("record.txt", format!("SSN {SSN}").as_bytes())]);
                let n = v.len();
                v.truncate(n / 2);
                v
            },
            Expect::NotSilentlyClean,
            "a truncated 7z must be reported, not read as empty",
        ),
        case(
            "7z",
            Slot::Evasive,
            "a.7z",
            build::sevenz(&[(
                "payload.txt",
                build::b64_wrapped(format!("card {CARD}").as_bytes()).as_bytes(),
            )]),
            Expect::DetectsSubCategory("Visa"),
            "base64 inside a 7z entry",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Data formats
// ---------------------------------------------------------------------------

#[cfg(feature = "data-formats")]
fn sqlite() -> Vec<Case> {
    vec![
        case(
            "sqlite",
            Slot::Clean,
            "d.sqlite",
            build::sqlite(&[("region", "EMEA"), ("status", "active")]),
            Expect::NoFindings,
            "a table of ordinary values",
        ),
        case(
            "sqlite",
            Slot::Single,
            "d.sqlite",
            build::sqlite(&[("ssn", SSN)]),
            Expect::Detects(SSN),
            "a value in the only row",
        ),
        case(
            "sqlite",
            Slot::Structural,
            "d.sqlite",
            build::sqlite(&[
                ("region", "EMEA"),
                ("status", "active"),
                ("note", &format!("card {CARD}")),
            ]),
            Expect::Detects(CARD),
            "the third row",
        ),
        case(
            "sqlite",
            Slot::Damaged,
            "d.sqlite",
            {
                // Keep the "SQLite format 3" magic so the real reader is
                // chosen, then corrupt the page structure behind it.
                let mut v = build::sqlite(&[("ssn", SSN)]);
                for b in v.iter_mut().skip(100).take(400) {
                    *b = 0xA5;
                }
                v
            },
            Expect::NotSilentlyClean,
            "a corrupt database must be reported rather than read as empty",
        ),
        case(
            "sqlite",
            Slot::Evasive,
            "d.sqlite",
            build::sqlite(&[(
                "blob",
                &build::b64_wrapped(format!("card {CARD}").as_bytes()),
            )]),
            Expect::DetectsSubCategory("Visa"),
            "base64 stored in a text column",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Images (barcode / QR)
// ---------------------------------------------------------------------------

#[cfg(feature = "barcode")]
fn png() -> Vec<Case> {
    vec![
        case(
            "png",
            Slot::Clean,
            "p.png",
            build::png(32, 32, |x, y| ((x * 8 + y * 4) % 256) as u8),
            Expect::NoFindings,
            "an image that decodes and carries no barcode is INSPECTED and \
             clean. rxing reports that as Err(NotFoundException) rather than \
             an empty result, so the obvious `?` turns every photo into an \
             unreadable attachment — which under a fail-closed policy defers \
             every message carrying one",
        ),
        case(
            "png",
            Slot::Single,
            "p.png",
            build::png(
                64,
                64,
                |x, y| {
                    if (x / 4 + y / 4) % 2 == 0 {
                        0
                    } else {
                        255
                    }
                },
            ),
            Expect::NoFindings,
            "a high-contrast checkerboard is not a valid symbol and must not \
             decode into anything — a reader that hallucinates text from noise \
             is worse than one that reads nothing",
        ),
        case(
            "png",
            Slot::Structural,
            "p.png",
            build::png(200, 40, |x, _| if (x / 3) % 2 == 0 { 0 } else { 255 }),
            Expect::NoFindings,
            "barcode-shaped stripes without valid start/stop guards decode to \
             nothing, and must not be forced into a reading",
        ),
        case(
            "png",
            Slot::Damaged,
            "p.png",
            {
                let mut v = build::png(32, 32, |_, _| 128);
                v.truncate(30); // header only
                v
            },
            Expect::NotSilentlyClean,
            "an image that will not decode is content nobody inspected, and \
             must stay distinguishable from one that decoded and held no barcode",
        ),
        case(
            "png",
            Slot::Evasive,
            "p.png",
            {
                let mut v = build::png(32, 32, |_, _| 200);
                v.extend_from_slice(format!("card {CARD}").as_bytes());
                v
            },
            Expect::NoFindings,
            "bytes appended after IEND are not image content. This documents \
             the boundary: the image reader reports what the image encodes, \
             and a trailing-data carrier is a container problem, not a \
             barcode one",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// Extensions that reach an already-covered reader.
///
/// Kept explicit rather than pattern-matched, so adding one is a decision
/// someone made rather than a regex quietly absorbing a new format.
const ALIASES: &[(&str, &str)] = &[
    ("tsv", "csv"),
    ("log", "txt"),
    ("xml", "txt"),
    ("html", "txt"),
    ("htm", "txt"),
    ("yaml", "txt"),
    ("yml", "txt"),
    ("toml", "txt"),
    ("ini", "txt"),
    ("cfg", "txt"),
    ("conf", "txt"),
    ("md", "txt"),
    ("rst", "txt"),
    ("py", "txt"),
    ("js", "txt"),
    ("ts", "txt"),
    ("java", "txt"),
    ("go", "txt"),
    ("rs", "txt"),
    ("rb", "txt"),
    ("php", "txt"),
    ("sh", "txt"),
    ("bat", "txt"),
    ("ps1", "txt"),
    ("sql", "txt"),
    ("env", "txt"),
    ("c", "txt"),
    ("cpp", "txt"),
    ("h", "txt"),
    ("hpp", "txt"),
    ("css", "txt"),
    ("scss", "txt"),
    ("pem", "txt"),
    ("cer", "txt"),
    ("crt", "txt"),
    ("key", "txt"),
    ("pub", "txt"),
    ("csr", "txt"),
    ("vcard", "vcf"),
    ("contact", "vcf"),
    ("ical", "ics"),
    ("mbx", "mbox"),
    ("mht", "mhtml"),
    ("odp", "odt"),
];

/// Formats Siphon reads that the matrix does not yet cover, each with the
/// reason. A gap with a reason is a decision; a gap without one is a hole,
/// which is why [`uncovered`] fails on anything not listed here.
pub const KNOWN_GAPS: &[(&str, &str)] = &[
    (
        "rar",
        "no RAR writer exists in the workspace (unrar is read-only) and no rar \
         binary is available, so a fixture cannot be built in-process. Covering \
         it needs a committed binary fixture — the one exception the no-blobs \
         rule would have to make.",
    ),
    (
        "cab",
        "same shape as rar: no writer available. The CAB reader is exercised by \
         tests/archive_security_test.rs for its bomb and traversal limits.",
    ),
    (
        "msg",
        "OLE2 fixtures are hand-rolled in tests/forensics_test.rs via the cfb \
         crate; folding those into this matrix is worthwhile and not yet done.",
    ),
    (
        "parquet",
        "arrow can write one; the builder is the only missing piece.",
    ),
    (
        "dat",
        "reached only as a fallback for unknown binary content, so there is no \
         well-formed case to write — its Clean slot has no meaning.",
    ),
];

/// Extensions advertised by [`crate::extractors::supported_extensions`] that
/// are neither covered by a case, an alias of something covered, nor recorded
/// in [`KNOWN_GAPS`].
pub fn uncovered(cases: &[Case]) -> Vec<String> {
    let mut out = Vec::new();
    for ext in crate::extractors::supported_extensions() {
        if cases.iter().any(|c| c.capability == ext) {
            continue;
        }
        if ALIASES.iter().any(|(a, _)| *a == ext) {
            continue;
        }
        if KNOWN_GAPS.iter().any(|(g, _)| *g == ext) {
            continue;
        }
        out.push(ext);
    }
    out
}
