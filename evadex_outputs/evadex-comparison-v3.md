# evadex DLP Scanner Comparison Report

**Python dlpscan-1.6.0 vs Rust dlpscan-rs-2.0.0**
Strategy: `text` | Payloads: all structured | Generated: 2026-04-03

---

## 1. Overall Detection Rates

| Metric | Python | Rust | Delta |
|---|---:|---:|---:|
| Total tests | 1234 | 1234 | +0 |
| Detected (pass) | 1013 | 735 | +278 |
| Evaded (fail) | 221 | 499 | −278 |
| Errors | 0 | 0 | +0 |
| **Detection rate** | **82.1%** | **59.6%** | **+22.5 pp** |

---

## 2. Per-Category Breakdown

| Category | Py Pass | Py Fail | Py% | Ru Pass | Ru Fail | Ru% | Delta |
|---|---:|---:|---:|---:|---:|---:|---:|
| `aba_routing` | 41 | 6 | 87.2% | 28 | 19 | 59.6% | **+27.6 pp** |
| `au_tfn` | 44 | 5 | 89.8% | 4 | 45 | 8.2% | **+81.6 pp** |
| `bitcoin` | 21 | 32 | 39.6% | 14 | 39 | 26.4% | +13.2 pp |
| `credit_card` | 347 | 51 | 87.2% | 281 | 117 | 70.6% | +16.6 pp |
| `de_tax_id` | 41 | 7 | 85.4% | 28 | 20 | 58.3% | **+27.1 pp** |
| `email` | 22 | 18 | 55.0% | 19 | 21 | 47.5% | +7.5 pp |
| `ethereum` | 20 | 32 | 38.5% | 12 | 40 | 23.1% | +15.4 pp |
| `fr_insee` | 41 | 6 | 87.2% | 32 | 15 | 68.1% | +19.1 pp |
| `iban` | 217 | 25 | 89.7% | 168 | 74 | 69.4% | **+20.3 pp** |
| `phone` | 53 | 4 | 93.0% | 37 | 20 | 64.9% | **+28.1 pp** |
| `sin` | 53 | 5 | 91.4% | 35 | 23 | 60.3% | **+31.1 pp** |
| `ssn` | 53 | 5 | 91.4% | 34 | 24 | 58.6% | **+32.8 pp** |
| `swift_bic` | 19 | 19 | 50.0% | 15 | 23 | 39.5% | +10.5 pp |
| `us_passport` | 41 | 6 | 87.2% | 28 | 19 | 59.6% | **+27.6 pp** |

> **Bold** = delta ≥ 20 pp

---

## 3. Per-Technique Breakdown

Techniques where Rust detection rate is lower than Python, sorted by delta descending.

| Generator | Technique | Py% | Ru% | Delta |
|---|---|---:|---:|---:|
| `delimiter` | `excessive_delimiter` | 100.0% | 0.0% | **+100.0 pp** |
| `encoding` | `double_url_encoding` | 100.0% | 0.0% | **+100.0 pp** |
| `encoding` | `double_url_encoding_digits` | 100.0% | 0.0% | **+100.0 pp** |
| `leetspeak` | `leet_aggressive` | 100.0% | 0.0% | **+100.0 pp** |
| `leetspeak` | `leet_moderate` | 100.0% | 0.0% | **+100.0 pp** |
| `unicode_encoding` | `html_entity_decimal` | 100.0% | 0.0% | **+100.0 pp** |
| `unicode_encoding` | `url_percent_encoding_digits` | 100.0% | 0.0% | **+100.0 pp** |
| `unicode_encoding` | `url_percent_encoding_full` | 100.0% | 0.0% | **+100.0 pp** |
| `splitting` | `css_comment_injection` | 91.3% | 0.0% | **+91.3 pp** |
| `splitting` | `html_comment_injection` | 91.3% | 0.0% | **+91.3 pp** |
| `splitting` | `whitespace_padding` | 91.3% | 0.0% | **+91.3 pp** |
| `unicode_encoding` | `url_percent_encoding_mixed` | 91.3% | 0.0% | **+91.3 pp** |
| `structural` | `noise_embedded` | 65.2% | 17.4% | +47.8 pp |
| `structural` | `partial_first_half` | 82.6% | 39.1% | +43.5 pp |
| `splitting` | `json_field_split` | 82.6% | 52.2% | +30.4 pp |
| `splitting` | `mid_line_break` | 82.6% | 52.2% | +30.4 pp |
| `structural` | `partial_last_half` | 82.6% | 52.2% | +30.4 pp |
| `encoding` | `base64_partial` | 21.7% | 0.0% | +21.7 pp |
| `structural` | `partial_minus_one` | 95.7% | 78.3% | +17.4 pp |
| `encoding` | `reversed_full` | 91.3% | 78.3% | +13.0 pp |
| `structural` | `overlapping_prefix` | 39.1% | 26.1% | +13.0 pp |
| `encoding` | `rot13` | 75.0% | 62.5% | +12.5 pp |
| `encoding` | `reversed_group_order` | 87.0% | 78.3% | +8.7 pp |
| `structural` | `left_pad_zeros` | 91.3% | 82.6% | +8.7 pp |
| `regional_digits` | `regional_arabic_indic` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_bengali` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_devanagari` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_extended_arabic_indic` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_khmer` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_mixed_alternating` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_mixed_partial` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_mongolian` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_myanmar` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_nko` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_thai` | 90.5% | 85.7% | +4.8 pp |
| `regional_digits` | `regional_tibetan` | 90.5% | 85.7% | +4.8 pp |
| `encoding` | `reversed_within_groups` | 87.0% | 82.6% | +4.4 pp |
| `structural` | `right_pad_zeros` | 87.0% | 82.6% | +4.4 pp |
| `splitting` | `prefix_noise` | 100.0% | 95.7% | +4.3 pp |
| `splitting` | `suffix_noise` | 100.0% | 95.7% | +4.3 pp |
| `splitting` | `xml_tag_injection` | 100.0% | 95.7% | +4.3 pp |
| `structural` | `left_pad_spaces` | 100.0% | 95.7% | +4.3 pp |
| `structural` | `repeated` | 100.0% | 95.7% | +4.3 pp |
| `structural` | `right_pad_spaces` | 100.0% | 95.7% | +4.3 pp |

> **Bold** = Rust scores 0% (complete blind spot)

---

## 4. Variants Python Catches but Rust Misses

**Total: 286 variants** detected by Python that Rust misses (all Rust status: `fail`).

### `aba_routing` — 13 gaps

| Payload | Generator | Technique |
|---|---|---|
| ABA routing number | `encoding` | `double_url_encoding` |
| ABA routing number | `splitting` | `css_comment_injection` |
| ABA routing number | `splitting` | `html_comment_injection` |
| ABA routing number | `splitting` | `json_field_split` |
| ABA routing number | `splitting` | `mid_line_break` |
| ABA routing number | `splitting` | `whitespace_padding` |
| ABA routing number | `structural` | `noise_embedded` |
| ABA routing number | `structural` | `partial_first_half` |
| ABA routing number | `structural` | `partial_last_half` |
| ABA routing number | `unicode_encoding` | `html_entity_decimal` |
| ABA routing number | `unicode_encoding` | `url_percent_encoding_digits` |
| ABA routing number | `unicode_encoding` | `url_percent_encoding_full` |
| ABA routing number | `unicode_encoding` | `url_percent_encoding_mixed` |

### `au_tfn` — 38 gaps

| Payload | Generator | Technique |
|---|---|---|
| Australia TFN | `encoding` | `base64_partial` |
| Australia TFN | `encoding` | `double_url_encoding` |
| Australia TFN | `encoding` | `double_url_encoding_digits` |
| Australia TFN | `encoding` | `reversed_full` |
| Australia TFN | `regional_digits` | `regional_arabic_indic` |
| Australia TFN | `regional_digits` | `regional_bengali` |
| Australia TFN | `regional_digits` | `regional_devanagari` |
| Australia TFN | `regional_digits` | `regional_extended_arabic_indic` |
| Australia TFN | `regional_digits` | `regional_khmer` |
| Australia TFN | `regional_digits` | `regional_mixed_alternating` |
| Australia TFN | `regional_digits` | `regional_mixed_partial` |
| Australia TFN | `regional_digits` | `regional_mongolian` |
| Australia TFN | `regional_digits` | `regional_myanmar` |
| Australia TFN | `regional_digits` | `regional_nko` |
| Australia TFN | `regional_digits` | `regional_thai` |
| Australia TFN | `regional_digits` | `regional_tibetan` |
| Australia TFN | `splitting` | `css_comment_injection` |
| Australia TFN | `splitting` | `html_comment_injection` |
| Australia TFN | `splitting` | `json_field_split` |
| Australia TFN | `splitting` | `mid_line_break` |
| Australia TFN | `splitting` | `prefix_noise` |
| Australia TFN | `splitting` | `suffix_noise` |
| Australia TFN | `splitting` | `whitespace_padding` |
| Australia TFN | `splitting` | `xml_tag_injection` |
| Australia TFN | `structural` | `left_pad_spaces` |
| Australia TFN | `structural` | `noise_embedded` |
| Australia TFN | `structural` | `overlapping_prefix` |
| Australia TFN | `structural` | `partial_first_half` |
| Australia TFN | `structural` | `partial_last_half` |
| Australia TFN | `structural` | `partial_minus_one` |
| Australia TFN | `structural` | `repeated` |
| Australia TFN | `structural` | `right_pad_spaces` |
| Australia TFN | `unicode_encoding` | `fullwidth_digits` |
| Australia TFN | `unicode_encoding` | `html_entity_decimal` |
| Australia TFN | `unicode_encoding` | `url_percent_encoding_digits` |
| Australia TFN | `unicode_encoding` | `url_percent_encoding_full` |
| Australia TFN | `unicode_encoding` | `url_percent_encoding_mixed` |
| Australia TFN | `unicode_encoding` | `zero_width_injection` |

### `bitcoin` — 8 gaps

| Payload | Generator | Technique |
|---|---|---|
| Bitcoin legacy address | `encoding` | `double_url_encoding` |
| Bitcoin legacy address | `encoding` | `double_url_encoding_digits` |
| Bitcoin legacy address | `splitting` | `css_comment_injection` |
| Bitcoin legacy address | `splitting` | `html_comment_injection` |
| Bitcoin legacy address | `splitting` | `whitespace_padding` |
| Bitcoin legacy address | `unicode_encoding` | `html_entity_decimal` |
| Bitcoin legacy address | `unicode_encoding` | `url_percent_encoding_digits` |
| Bitcoin legacy address | `unicode_encoding` | `url_percent_encoding_full` |

### `credit_card` — 66 gaps

| Payload | Generator | Technique |
|---|---|---|
| Amex 15-digit | `delimiter` | `excessive_delimiter` |
| Visa 16-digit | `delimiter` | `excessive_delimiter` |
| Diners Club 14-digit | `delimiter` | `excessive_delimiter` |
| Mastercard 16-digit | `delimiter` | `excessive_delimiter` |
| Discover 16-digit | `delimiter` | `excessive_delimiter` |
| JCB 16-digit | `delimiter` | `excessive_delimiter` |
| UnionPay 16-digit | `delimiter` | `excessive_delimiter` |
| Amex 15-digit | `encoding` | `double_url_encoding` |
| Diners Club 14-digit | `encoding` | `double_url_encoding` |
| Discover 16-digit | `encoding` | `double_url_encoding` |
| JCB 16-digit | `encoding` | `double_url_encoding` |
| Mastercard 16-digit | `encoding` | `double_url_encoding` |
| UnionPay 16-digit | `encoding` | `double_url_encoding` |
| Visa 16-digit | `encoding` | `double_url_encoding` |
| Amex 15-digit | `splitting` | `css_comment_injection` |
| Diners Club 14-digit | `splitting` | `css_comment_injection` |
| Discover 16-digit | `splitting` | `css_comment_injection` |
| JCB 16-digit | `splitting` | `css_comment_injection` |
| Mastercard 16-digit | `splitting` | `css_comment_injection` |
| UnionPay 16-digit | `splitting` | `css_comment_injection` |
| Visa 16-digit | `splitting` | `css_comment_injection` |
| Amex 15-digit | `splitting` | `html_comment_injection` |
| Diners Club 14-digit | `splitting` | `html_comment_injection` |
| Discover 16-digit | `splitting` | `html_comment_injection` |
| JCB 16-digit | `splitting` | `html_comment_injection` |
| Mastercard 16-digit | `splitting` | `html_comment_injection` |
| UnionPay 16-digit | `splitting` | `html_comment_injection` |
| Visa 16-digit | `splitting` | `html_comment_injection` |
| Amex 15-digit | `splitting` | `whitespace_padding` |
| Diners Club 14-digit | `splitting` | `whitespace_padding` |
| Discover 16-digit | `splitting` | `whitespace_padding` |
| JCB 16-digit | `splitting` | `whitespace_padding` |
| Mastercard 16-digit | `splitting` | `whitespace_padding` |
| UnionPay 16-digit | `splitting` | `whitespace_padding` |
| Visa 16-digit | `splitting` | `whitespace_padding` |
| Amex 15-digit | `structural` | `noise_embedded` |
| Diners Club 14-digit | `structural` | `noise_embedded` |
| Mastercard 16-digit | `structural` | `noise_embedded` |
| Amex 15-digit | `unicode_encoding` | `html_entity_decimal` |
| Diners Club 14-digit | `unicode_encoding` | `html_entity_decimal` |
| Discover 16-digit | `unicode_encoding` | `html_entity_decimal` |
| JCB 16-digit | `unicode_encoding` | `html_entity_decimal` |
| Mastercard 16-digit | `unicode_encoding` | `html_entity_decimal` |
| UnionPay 16-digit | `unicode_encoding` | `html_entity_decimal` |
| Visa 16-digit | `unicode_encoding` | `html_entity_decimal` |
| Amex 15-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| Diners Club 14-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| Discover 16-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| JCB 16-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| Mastercard 16-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| UnionPay 16-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| Visa 16-digit | `unicode_encoding` | `url_percent_encoding_digits` |
| Amex 15-digit | `unicode_encoding` | `url_percent_encoding_full` |
| Diners Club 14-digit | `unicode_encoding` | `url_percent_encoding_full` |
| Discover 16-digit | `unicode_encoding` | `url_percent_encoding_full` |
| JCB 16-digit | `unicode_encoding` | `url_percent_encoding_full` |
| Mastercard 16-digit | `unicode_encoding` | `url_percent_encoding_full` |
| UnionPay 16-digit | `unicode_encoding` | `url_percent_encoding_full` |
| Visa 16-digit | `unicode_encoding` | `url_percent_encoding_full` |
| Amex 15-digit | `unicode_encoding` | `url_percent_encoding_mixed` |
| Diners Club 14-digit | `unicode_encoding` | `url_percent_encoding_mixed` |
| Discover 16-digit | `unicode_encoding` | `url_percent_encoding_mixed` |
| JCB 16-digit | `unicode_encoding` | `url_percent_encoding_mixed` |
| Mastercard 16-digit | `unicode_encoding` | `url_percent_encoding_mixed` |
| UnionPay 16-digit | `unicode_encoding` | `url_percent_encoding_mixed` |
| Visa 16-digit | `unicode_encoding` | `url_percent_encoding_mixed` |

### `de_tax_id` — 13 gaps

| Payload | Generator | Technique |
|---|---|---|
| Germany Steuer-IdNr | `encoding` | `double_url_encoding` |
| Germany Steuer-IdNr | `splitting` | `css_comment_injection` |
| Germany Steuer-IdNr | `splitting` | `html_comment_injection` |
| Germany Steuer-IdNr | `splitting` | `json_field_split` |
| Germany Steuer-IdNr | `splitting` | `mid_line_break` |
| Germany Steuer-IdNr | `splitting` | `whitespace_padding` |
| Germany Steuer-IdNr | `structural` | `noise_embedded` |
| Germany Steuer-IdNr | `structural` | `partial_first_half` |
| Germany Steuer-IdNr | `structural` | `partial_last_half` |
| Germany Steuer-IdNr | `unicode_encoding` | `html_entity_decimal` |
| Germany Steuer-IdNr | `unicode_encoding` | `url_percent_encoding_digits` |
| Germany Steuer-IdNr | `unicode_encoding` | `url_percent_encoding_full` |
| Germany Steuer-IdNr | `unicode_encoding` | `url_percent_encoding_mixed` |

### `email` — 7 gaps

| Payload | Generator | Technique |
|---|---|---|
| Email address | `encoding` | `double_url_encoding` |
| Email address | `encoding` | `double_url_encoding_digits` |
| Email address | `leetspeak` | `leet_aggressive` |
| Email address | `leetspeak` | `leet_moderate` |
| Email address | `unicode_encoding` | `html_entity_decimal` |
| Email address | `unicode_encoding` | `url_percent_encoding_full` |
| Email address | `unicode_encoding` | `url_percent_encoding_mixed` |

### `ethereum` — 9 gaps

| Payload | Generator | Technique |
|---|---|---|
| Ethereum address | `encoding` | `double_url_encoding` |
| Ethereum address | `encoding` | `double_url_encoding_digits` |
| Ethereum address | `splitting` | `css_comment_injection` |
| Ethereum address | `splitting` | `html_comment_injection` |
| Ethereum address | `splitting` | `whitespace_padding` |
| Ethereum address | `unicode_encoding` | `html_entity_decimal` |
| Ethereum address | `unicode_encoding` | `url_percent_encoding_digits` |
| Ethereum address | `unicode_encoding` | `url_percent_encoding_full` |
| Ethereum address | `unicode_encoding` | `url_percent_encoding_mixed` |

### `fr_insee` — 9 gaps

| Payload | Generator | Technique |
|---|---|---|
| France INSEE (NIR) | `encoding` | `double_url_encoding` |
| France INSEE (NIR) | `splitting` | `css_comment_injection` |
| France INSEE (NIR) | `splitting` | `html_comment_injection` |
| France INSEE (NIR) | `splitting` | `whitespace_padding` |
| France INSEE (NIR) | `structural` | `noise_embedded` |
| France INSEE (NIR) | `unicode_encoding` | `html_entity_decimal` |
| France INSEE (NIR) | `unicode_encoding` | `url_percent_encoding_digits` |
| France INSEE (NIR) | `unicode_encoding` | `url_percent_encoding_full` |
| France INSEE (NIR) | `unicode_encoding` | `url_percent_encoding_mixed` |

### `iban` — 49 gaps

| Payload | Generator | Technique |
|---|---|---|
| France IBAN | `delimiter` | `excessive_delimiter` |
| Germany IBAN | `delimiter` | `excessive_delimiter` |
| Spain IBAN | `delimiter` | `excessive_delimiter` |
| UK IBAN | `delimiter` | `excessive_delimiter` |
| France IBAN | `encoding` | `double_url_encoding` |
| Germany IBAN | `encoding` | `double_url_encoding` |
| Spain IBAN | `encoding` | `double_url_encoding` |
| UK IBAN | `encoding` | `double_url_encoding` |
| France IBAN | `encoding` | `double_url_encoding_digits` |
| Germany IBAN | `encoding` | `double_url_encoding_digits` |
| Spain IBAN | `encoding` | `double_url_encoding_digits` |
| UK IBAN | `encoding` | `double_url_encoding_digits` |
| Spain IBAN | `encoding` | `base64_partial` |
| UK IBAN | `encoding` | `reversed_full` |
| Germany IBAN | `encoding` | `reversed_group_order` |
| UK IBAN | `encoding` | `reversed_group_order` |
| UK IBAN | `encoding` | `reversed_within_groups` |
| France IBAN | `splitting` | `css_comment_injection` |
| Germany IBAN | `splitting` | `css_comment_injection` |
| Spain IBAN | `splitting` | `css_comment_injection` |
| UK IBAN | `splitting` | `css_comment_injection` |
| France IBAN | `splitting` | `html_comment_injection` |
| Germany IBAN | `splitting` | `html_comment_injection` |
| Spain IBAN | `splitting` | `html_comment_injection` |
| UK IBAN | `splitting` | `html_comment_injection` |
| France IBAN | `splitting` | `whitespace_padding` |
| Germany IBAN | `splitting` | `whitespace_padding` |
| Spain IBAN | `splitting` | `whitespace_padding` |
| UK IBAN | `splitting` | `whitespace_padding` |
| UK IBAN | `structural` | `left_pad_zeros` |
| France IBAN | `structural` | `partial_first_half` |
| Germany IBAN | `structural` | `partial_first_half` |
| UK IBAN | `structural` | `partial_first_half` |
| France IBAN | `unicode_encoding` | `html_entity_decimal` |
| Germany IBAN | `unicode_encoding` | `html_entity_decimal` |
| Spain IBAN | `unicode_encoding` | `html_entity_decimal` |
| UK IBAN | `unicode_encoding` | `html_entity_decimal` |
| France IBAN | `unicode_encoding` | `url_percent_encoding_digits` |
| Germany IBAN | `unicode_encoding` | `url_percent_encoding_digits` |
| Spain IBAN | `unicode_encoding` | `url_percent_encoding_digits` |
| UK IBAN | `unicode_encoding` | `url_percent_encoding_digits` |
| France IBAN | `unicode_encoding` | `url_percent_encoding_full` |
| Germany IBAN | `unicode_encoding` | `url_percent_encoding_full` |
| Spain IBAN | `unicode_encoding` | `url_percent_encoding_full` |
| UK IBAN | `unicode_encoding` | `url_percent_encoding_full` |
| France IBAN | `unicode_encoding` | `url_percent_encoding_mixed` |
| Germany IBAN | `unicode_encoding` | `url_percent_encoding_mixed` |
| Spain IBAN | `unicode_encoding` | `url_percent_encoding_mixed` |
| UK IBAN | `unicode_encoding` | `url_percent_encoding_mixed` |

### `phone` — 16 gaps

| Payload | Generator | Technique |
|---|---|---|
| US phone number | `delimiter` | `excessive_delimiter` |
| US phone number | `encoding` | `base64_partial` |
| US phone number | `encoding` | `double_url_encoding` |
| US phone number | `encoding` | `double_url_encoding_digits` |
| US phone number | `splitting` | `css_comment_injection` |
| US phone number | `splitting` | `html_comment_injection` |
| US phone number | `splitting` | `json_field_split` |
| US phone number | `splitting` | `mid_line_break` |
| US phone number | `splitting` | `whitespace_padding` |
| US phone number | `structural` | `noise_embedded` |
| US phone number | `structural` | `partial_first_half` |
| US phone number | `structural` | `partial_last_half` |
| US phone number | `unicode_encoding` | `html_entity_decimal` |
| US phone number | `unicode_encoding` | `url_percent_encoding_digits` |
| US phone number | `unicode_encoding` | `url_percent_encoding_full` |
| US phone number | `unicode_encoding` | `url_percent_encoding_mixed` |

### `sin` — 18 gaps

| Payload | Generator | Technique |
|---|---|---|
| Canada SIN | `delimiter` | `excessive_delimiter` |
| Canada SIN | `encoding` | `base64_partial` |
| Canada SIN | `encoding` | `double_url_encoding` |
| Canada SIN | `encoding` | `double_url_encoding_digits` |
| Canada SIN | `splitting` | `css_comment_injection` |
| Canada SIN | `splitting` | `html_comment_injection` |
| Canada SIN | `splitting` | `json_field_split` |
| Canada SIN | `splitting` | `mid_line_break` |
| Canada SIN | `splitting` | `whitespace_padding` |
| Canada SIN | `structural` | `noise_embedded` |
| Canada SIN | `structural` | `overlapping_prefix` |
| Canada SIN | `structural` | `partial_first_half` |
| Canada SIN | `structural` | `partial_last_half` |
| Canada SIN | `structural` | `partial_minus_one` |
| Canada SIN | `unicode_encoding` | `html_entity_decimal` |
| Canada SIN | `unicode_encoding` | `url_percent_encoding_digits` |
| Canada SIN | `unicode_encoding` | `url_percent_encoding_full` |
| Canada SIN | `unicode_encoding` | `url_percent_encoding_mixed` |

### `ssn` — 19 gaps

| Payload | Generator | Technique |
|---|---|---|
| US SSN | `delimiter` | `excessive_delimiter` |
| US SSN | `encoding` | `base64_partial` |
| US SSN | `encoding` | `double_url_encoding` |
| US SSN | `encoding` | `double_url_encoding_digits` |
| US SSN | `encoding` | `reversed_full` |
| US SSN | `splitting` | `css_comment_injection` |
| US SSN | `splitting` | `html_comment_injection` |
| US SSN | `splitting` | `json_field_split` |
| US SSN | `splitting` | `mid_line_break` |
| US SSN | `splitting` | `whitespace_padding` |
| US SSN | `structural` | `noise_embedded` |
| US SSN | `structural` | `overlapping_prefix` |
| US SSN | `structural` | `partial_first_half` |
| US SSN | `structural` | `partial_last_half` |
| US SSN | `structural` | `partial_minus_one` |
| US SSN | `unicode_encoding` | `html_entity_decimal` |
| US SSN | `unicode_encoding` | `url_percent_encoding_digits` |
| US SSN | `unicode_encoding` | `url_percent_encoding_full` |
| US SSN | `unicode_encoding` | `url_percent_encoding_mixed` |

### `swift_bic` — 8 gaps

| Payload | Generator | Technique |
|---|---|---|
| SWIFT/BIC code | `encoding` | `double_url_encoding` |
| SWIFT/BIC code | `encoding` | `double_url_encoding_digits` |
| SWIFT/BIC code | `encoding` | `rot13` |
| SWIFT/BIC code | `structural` | `left_pad_zeros` |
| SWIFT/BIC code | `structural` | `partial_minus_one` |
| SWIFT/BIC code | `structural` | `right_pad_zeros` |
| SWIFT/BIC code | `unicode_encoding` | `html_entity_decimal` |
| SWIFT/BIC code | `unicode_encoding` | `url_percent_encoding_full` |

### `us_passport` — 13 gaps

| Payload | Generator | Technique |
|---|---|---|
| US Passport number | `encoding` | `double_url_encoding` |
| US Passport number | `splitting` | `css_comment_injection` |
| US Passport number | `splitting` | `html_comment_injection` |
| US Passport number | `splitting` | `json_field_split` |
| US Passport number | `splitting` | `mid_line_break` |
| US Passport number | `splitting` | `whitespace_padding` |
| US Passport number | `structural` | `noise_embedded` |
| US Passport number | `structural` | `partial_first_half` |
| US Passport number | `structural` | `partial_last_half` |
| US Passport number | `unicode_encoding` | `html_entity_decimal` |
| US Passport number | `unicode_encoding` | `url_percent_encoding_digits` |
| US Passport number | `unicode_encoding` | `url_percent_encoding_full` |
| US Passport number | `unicode_encoding` | `url_percent_encoding_mixed` |

---

## 5. Errors

| Scanner | Error count |
|---|---:|
| Python 1.6.0 | 0 |
| Rust 2.0.0 | 0 |

No errors in either scanner.

---

## Summary

The Rust scanner misses **286 variants** that Python catches across all 14 categories — a gap of **22.5 percentage points** (82.1% vs 59.6%). Zero errors in either run.

**Rust complete blind spots** (0% detection, Python 100%):

| Technique cluster | What it is |
|---|---|
| `url_percent_encoding_full/digits/mixed` | Standard `%XX` percent-encoding of the value |
| `html_entity_decimal` | All characters encoded as `&#NNN;` HTML entities |
| `double_url_encoding` / `_digits` | `%25XX` double percent-encoding |
| `excessive_delimiter` | Doubled hyphens between digit groups |
| `css_comment_injection` | `/**/` injected between every character |
| `html_comment_injection` | `<!---->` injected between every character |
| `whitespace_padding` | Space inserted between every character |
| `leet_moderate` / `leet_aggressive` | Leetspeak substitution on SSN/SIN/email/phone |

**Worst-hit categories by delta:**

| Category | Python | Rust | Gap |
|---|---:|---:|---:|
| `au_tfn` | 89.8% | 8.2% | −81.6 pp |
| `ssn` | 91.4% | 58.6% | −32.8 pp |
| `sin` | 91.4% | 60.3% | −31.1 pp |
| `phone` | 93.0% | 64.9% | −28.1 pp |
| `us_passport` | 87.2% | 59.6% | −27.6 pp |
| `aba_routing` | 87.2% | 59.6% | −27.6 pp |
| `de_tax_id` | 85.4% | 58.3% | −27.1 pp |

The pattern is consistent across categories: Rust's text-normalisation pipeline does not preprocess percent-encoded, HTML-entity-encoded, or comment-injected input before pattern matching.