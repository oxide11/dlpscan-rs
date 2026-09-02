# Public records corpus — provenance

Real documents, committed under the **official public records exemption** in
`FUTURE.md` → Data provenance policy. Every file here is a directory of elected
representatives' **institutional** contact details — office telephone, office
address, official email — published by a legislature for public use.

Nothing here is a home address, a personal mobile, or a private email. Nothing
here came from a breach, a broker, or a scrape of a consumer directory. Read
the exemption before adding to this directory: the test it turns on is
*institutional versus personal*, not *public versus private*.

These files exist to answer a question 80 synthetic fixtures could not: **what
does the scanner do on documents people actually write?** The answer, recorded
in `tests/public_records_test.rs`, was uncomfortable and worth knowing.

---

## `us_house_directory.xlsx`

| | |
|---|---|
| Content | US House of Representatives member offices — name, telephone, office |
| Authority | US House of Representatives (via a Kaggle redistribution) |
| Retrieved | 2026-09-02 |
| Rows | 442 (441 with a telephone number) |
| Licence | US Government work — not subject to copyright |

Phone numbers are the House switchboard exchange (`202-225-XXXX`); addresses
are House office buildings (`417 CHOB` = Cannon House Office Building). Sheet 2
is prose explaining House room numbering, which usefully exercises multi-sheet
extraction.

**Why it is here:** the scanner finds **zero** of its 441 phone numbers. See
the `collapse_padding` field-fusing bug in `FUTURE.md`.

## `ca_mp_addresses.txt`

| | |
|---|---|
| Content | Canadian MPs — Hill and constituency office telephone, address, postal code |
| Source | https://www.ourcommons.ca/Members/en/addresses |
| Authority | House of Commons of Canada |
| Retrieved | 2026-09-02 |
| Size | 1,306 telephone numbers across 35 area codes; 408 postal codes |

Text extracted from the published HTML; markup stripped, content unaltered.
The area-code spread is what makes it valuable — the US file is a single
exchange, so it cannot exercise phone validation broadly.

**Why it is here:** 87% phone recall, **0%** postal-code recall, and roughly
250 false positives across fifteen foreign identifier categories.

## `uk_mps.csv`

| | |
|---|---|
| Content | UK MPs — name, party, constituency, official email, address, postcode |
| Authority | UK Parliament |
| Retrieved | 2026-09-02 |
| Rows | 649 (643 with an email address) |

**Why it is here:** it is the control. 100% recall on both postcodes and
emails — and it achieves that *only* because the CSV carries `Postcode` and
`Email` column headers, which supply the context keywords the Aho-Corasick
prefilter demands. The Canadian file holds the same class of data with no such
headers and scores zero. That contrast is the evidence for the
`context_required` gating defect described in `FUTURE.md`.

---

## Refreshing

These are point-in-time snapshots; membership changes with each election, so
counts in `tests/public_records_test.rs` are pinned to the files as committed
rather than to whatever the sources currently serve. Re-fetching means
re-deriving the ground-truth counts and updating that test in the same commit.
