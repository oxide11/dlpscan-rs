# PHI — Regex Patterns

Regex patterns for detecting Protected Health Information aligned with
HIPAA, HITECH, and international health privacy regulations.

> Corresponding keywords: [phi-keywords.md](phi-keywords.md)

---

## Medical Identifiers

| Pattern Name | Regex |
|---|---|
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` |
| DEA Number | `\b[A-Z]{2}\d{7}\b` |
| ICD-10 Code | `\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b` |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` |
| Medical Record Number | `\b\d{6,10}\b` |

## Insurance & Health Plan Data

| Pattern Name | Regex |
|---|---|
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` |
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |
| Insurance Group Number | `\b\d{5,10}\b` |

## Biometric Identifiers (HIPAA #16)

| Pattern Name | Regex |
|---|---|
| Biometric Hash (SHA-256) | `\b[0-9a-f]{64}\b` |
| Biometric Template ID (UUID) | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` |

## Personal Identifiers (PHI Context)

| Pattern Name | Regex |
|---|---|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender\|M\|F\|X)\b` |
| Age Value | `\b(?:1[89]\|[2-9]\d\|1[0-4]\d)\b` |

## Contact Information (PHI Context)

| Pattern Name | Regex |
|---|---|
| Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| IPv4 Address | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` |
| IPv6 Address | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b` |

## Device Identifiers (HIPAA #13 — Medical Devices)

| Pattern Name | Regex |
|---|---|
| IMEI | `\b\d{2}[-.\s]?\d{6}[-.\s]?\d{6}[-.\s]?\d\b` |
| ICCID | `\b89\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{3,4}\d?\b` |
| Device Serial Number | `\b[A-Z0-9]{8,20}\b` |

## Date Formats (HIPAA #3)

| Pattern Name | Regex |
|---|---|
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` |
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` |

## Geographic Data (HIPAA #2)

| Pattern Name | Regex |
|---|---|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` |
| US ZIP Code | `\b\d{5}(?:-\d{4})?\b` |

## Privacy Classification Labels

| Pattern Name | Regex |
|---|---|
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` |
| HIPAA | `\bHIPAA\b` |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` |

## Government Health IDs (Regional)

| Region | Pattern Name | Regex |
|--------|---|---|
| US | SSN | `\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| US | MBI (Medicare) | `\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s]?[A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s]?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b` |
| US | NPI (Provider) | `\b[12]\d{9}\b` |
| US | US DEA Number | `\b[A-Z]{2}\d{7}\b` |
| US | US DoD ID | `\b\d{10}\b` |
| UK | NHS Number | `\b\d{3}\s?\d{3}\s?\d{4}\b` |
| Brazil | SUS Card | `\b[1-2]\d{10}00[01]\d\b\|\b[789]\d{14}\b` |
