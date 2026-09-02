# Polygon Siphon Public Professional Contact Corpus v1

Built: 2026-09-02  
Jurisdiction: Canada-first  
Purpose: defensive DLP testing and entity-recognition development

## What is included

- 13,551 normalized public-professional entity records
- 27,102 generated text examples with exact character-offset annotations
- 10,909 train, 1,349 validation, and 1,293 test records
- 12,000 sampled federal-directory records
- 338 current Member of Parliament records returned by the official feed
- 1,129 municipal mayor records
- 84 other municipal elected-official records
- 8 synthetic negative-control examples

The person-level split is deterministic: the same normalized person name cannot appear in more than one of train, validation, or test.

## Files

| File | Purpose |
| --- | --- |
| `polygon_siphon_entities_v1.csv` | Primary, single combined CSV with normalized public-professional entity records |
| `polygon_siphon_dlp_eval_v1.csv` | Full DLP evaluation CSV with source text, expected labels, entity counts, and expected masked output |
| `polygon_siphon_ner_corpus_v1.jsonl` | Span-annotated JSONL for model pipelines; each entity includes `start`, `end`, `label`, and exact text |
| `polygon_siphon_negative_controls_v1.csv` | Synthetic near-miss examples expected to produce no contact-data labels |
| `polygon_siphon_source_registry_v1.csv` | Provenance, licence, retrieval date, source hash, and ingestion decision |
| `polygon_siphon_chunk_audit_v1.csv` | Independent validation result and SHA-256 for each 1,000-record working chunk |
| `polygon_siphon_corpus_v1.xlsx` | Audit workbook with summary, QA, data dictionary, sources, 2,000-row balanced entity sample, and 120 annotated samples |
| `manifest.json` | Machine-readable counts, QA results, and output hashes |

## Primary CSV schema

The primary CSV contains identifiers, split and provenance fields; person and role fields; organization and political-office fields; raw and normalized phone, email, address, and postal-code fields; and explicit privacy/licensing controls.

Important normalized fields:

- `person_name`
- `office_phone_raw`
- `office_phone_e164`
- `office_email`
- `street_address`
- `city`
- `province`
- `postal_code_raw`
- `postal_code_normalized`
- `source_url`
- `rights_status`

See the workbook's **Data Dictionary** sheet for all 34 columns.

## Annotation labels

- `PERSON_NAME`
- `PHONE_NUMBER`
- `EMAIL_ADDRESS`
- `STREET_ADDRESS`
- `CITY`
- `REGION`
- `POSTAL_CODE`
- `ORGANIZATION`
- `JOB_TITLE`

Offsets use JavaScript/Python-style zero-based, end-exclusive character positions. Automated validation confirmed that every annotated span exactly equals `text.slice(start, end)`.

## Chunk audit and recombination

The primary CSV was split into 14 working chunks of at most 1,000 records. Each chunk was independently checked for:

- exact column count and required fields
- unique record identifiers
- allowed source and split values
- open-rights status and public-professional policy flag
- email syntax
- E.164 Canadian phone syntax
- normalized Canadian postal-code syntax

All 14 chunks passed. The chunks were recombined with a single header. The recombined CSV's SHA-256 exactly matched the pre-split file:

`b3670e17e6123afea378f9c9329d74436daaac1a210775a466edd3b92f47f62d`

## QA results

- duplicate record IDs: 0
- invalid normalized emails: 0
- invalid normalized Canadian postal codes: 0
- invalid annotation offsets: 0
- samples without entities: 0
- person-level split leakage: 0
- chunk validation failures: 0
- recombined checksum mismatch: false

Thirty-two noncanonical postal values from publishers remain in `postal_code_raw`. Their normalized field is blank, so they are not emitted as `POSTAL_CODE` annotations.

## Data policy

The real-data partition is limited to published professional contact information from sources approved for ingestion. It excludes personal residences and private/mobile numbers. Where the Montreal source displayed a `Cell.` field, that field was omitted and the row was flagged with `mobile_number_excluded=true`.

Use this corpus for defensive detection, validation, and controlled model development. Do not use it for outreach, profiling, identity resolution, or contact enrichment.

## Sources and licensing

Included:

1. [Government of Canada Employee Contact Information (GEDS)](https://open.canada.ca/data/en/dataset/8ec4a9df-b76b-4a67-8f93-cdbc2e040098) — Open Government Licence, Canada 2.0.
2. [House of Commons Open Data](https://www.ourcommons.ca/en/open-data) — current Member of Parliament structured feed, described by the publisher as freely shared and reusable without restrictions.
3. [Directory of municipalities in Quebec](https://open.canada.ca/data/en/dataset/a8a678b0-875f-4607-b347-009a5096ff45) — Creative Commons Attribution 4.0, Quebec.
4. [List of elected officials of the City of Montreal](https://open.canada.ca/data/en/dataset/381d74ca-dadd-459f-95c9-db255b5f4480) — Creative Commons Attribution 4.0, Quebec.

Candidate McGill University faculty directories are documented in the source registry but excluded from v1 because no explicit bulk/model-training licence was verified. Public visibility alone was not treated as reuse permission.

The source registry and manifest are the authoritative release records. Re-check source terms before redistribution or commercial deployment; this package is not legal advice.
