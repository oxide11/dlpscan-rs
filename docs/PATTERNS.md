# PATTERNS.md

Complete inventory of all patterns in dlpscan.
**557 patterns** across **126 categories**.

Each pattern includes:
- **Regex** -- the detection pattern
- **Specificity** -- base confidence score (0.0-1.0); higher means fewer false positives
- **Context Required** -- if Yes, the pattern is suppressed unless a context keyword appears nearby

> See [KEYWORDS.md](KEYWORDS.md) for the context keywords that boost or gate
> each pattern.

### Specificity scale

| Range | Meaning | Examples |
|---|---|---|
| 0.85 -- 1.0 | High confidence, few false positives | JWT, AWS keys, Track Data, Credit Cards |
| 0.50 -- 0.84 | Moderate confidence, context helps | IBAN, Email, Phone, Crypto addresses |
| 0.20 -- 0.49 | Low confidence, context recommended | Bank accounts, dates, check numbers |
| 0.00 -- 0.19 | Very low, context required | Cardholder name, OFAC SDN |

---

## Africa - Egypt (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Egypt National ID | `\b[23]\d{13}\b` | 0.40 | No |
| Egypt Passport | `\b[A-Z]?\d{7,8}\b` | 0.40 | No |
| Egypt Tax ID | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}\b` | 0.40 | No |

## Africa - Ethiopia (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Ethiopia National ID | `\b\d{12}\b` | 0.40 | No |
| Ethiopia Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Ethiopia TIN | `\b\d{10}\b` | 0.40 | No |

## Africa - Ghana (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Ghana Card | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` | 0.40 | No |
| Ghana NHIS | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` | 0.40 | No |
| Ghana Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |
| Ghana TIN | `\b[CGQV]\d{10}\b` | 0.40 | No |

## Africa - Kenya (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Kenya KRA PIN | `\b[A-Z]\d{9}[A-Z]\b` | 0.40 | No |
| Kenya NHIF | `\b\d{6,9}\b` | 0.40 | No |
| Kenya National ID | `\b\d{7,8}\b` | 0.40 | No |
| Kenya Passport | `\b[A-Z]\d{7,8}\b` | 0.40 | No |

## Africa - Morocco (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Morocco CIN | `\b[A-Z]{1,2}\d{5,6}\b` | 0.40 | No |
| Morocco Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Morocco Tax ID | `\b\d{8}\b` | 0.40 | No |

## Africa - Nigeria (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Nigeria BVN | `\b\d{11}\b` | 0.40 | No |
| Nigeria Driver Licence | `\b[A-Z]{3}\d{5,9}[A-Z]{0,2}\d{0,2}\b` | 0.40 | No |
| Nigeria NIN | `\b\d{11}\b` | 0.40 | No |
| Nigeria Passport | `\b[A-Z]\d{8}\b` | 0.40 | No |
| Nigeria TIN | `\b\d{12,13}\b` | 0.40 | No |
| Nigeria Voter Card | `\b[0-9A-Z]{19}\b` | 0.40 | No |

## Africa - South Africa (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| South Africa DL | `\b\d{10}[A-Z]{2}\b` | 0.40 | No |
| South Africa ID | `\b\d{13}\b` | 0.40 | No |
| South Africa Passport | `\b[A-Z]?\d{8,9}\b` | 0.40 | No |

## Africa - Tanzania (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Tanzania NIDA | `\b\d{20}\b` | 0.40 | No |
| Tanzania Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Tanzania TIN | `\b\d{9}\b` | 0.40 | No |

## Africa - Tunisia (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Tunisia CIN | `\b\d{8}\b` | 0.40 | No |
| Tunisia Passport | `\b[A-Z]\d{6}\b` | 0.40 | No |

## Africa - Uganda (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Uganda NIN | `\bC[MF]\d{8}[A-Z0-9]{4}\b` | 0.40 | No |
| Uganda Passport | `\b[A-Z]\d{7,8}\b` | 0.40 | No |

## Asia-Pacific - Australia (11 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Australia DL ACT | `\b\d{6,10}\b` | 0.40 | No |
| Australia DL NSW | `\b\d{8}\b` | 0.40 | No |
| Australia DL NT | `\b\d{5,7}\b` | 0.40 | No |
| Australia DL QLD | `\b\d{8,9}\b` | 0.40 | No |
| Australia DL SA | `\b[A-Z]?\d{5,6}\b` | 0.40 | No |
| Australia DL TAS | `\b[A-Z]\d{5,6}\b` | 0.40 | No |
| Australia DL VIC | `\b\d{8,10}\b` | 0.40 | No |
| Australia DL WA | `\b\d{7}\b` | 0.40 | No |
| Australia Medicare | `\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s]?\d?\b` | 0.40 | No |
| Australia Passport | `\b[A-Z]{1,2}\d{7}\b` | 0.40 | No |
| Australia TFN | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2,3}\b` | 0.40 | No |

## Asia-Pacific - Bangladesh (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Bangladesh NID | `\b(?:\d{10}\|\d{17})\b` | 0.40 | No |
| Bangladesh Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Bangladesh TIN | `\b\d{12}\b` | 0.40 | No |

## Asia-Pacific - China (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| China Passport | `\b[EGD][A-Z]?\d{7,8}\b` | 0.40 | No |
| China Resident ID | `\b\d{6}(?:18\|19\|20)\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` | 0.40 | No |
| Hong Kong ID | `\b[A-Z]{1,2}\d{6}\s?\(?[0-9A]\)?\b` | 0.40 | No |
| Macau ID | `\b[1578]\d{6}\s?\(?[0-9]\)?\b` | 0.40 | No |
| Taiwan National ID | `\b[A-Z][12489]\d{8}\b` | 0.40 | No |

## Asia-Pacific - India (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| India Aadhaar | `\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b` | 0.40 | No |
| India DL | `\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19\|20)\d{2}[-\s]?\d{7}\b` | 0.40 | No |
| India PAN | `\b[A-Z]{5}\d{4}[A-Z]\b` | 0.40 | No |
| India Passport | `\b[A-Z][1-9]\d{5}[1-9]\b` | 0.40 | No |
| India Ration Card | `\b\d{2}[\s-]?\d{8}\b` | 0.40 | No |
| India Voter ID | `\b[A-Z]{3}\d{7}\b` | 0.40 | No |

## Asia-Pacific - Indonesia (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Indonesia NIK | `\b\d{16}\b` | 0.40 | No |
| Indonesia NPWP | `\b\d{2}\.?\d{3}\.?\d{3}\.?\d[-.]?\d{3}\.?\d{3}\b` | 0.40 | No |
| Indonesia Passport | `\b[A-Z]{1,2}\d{6,7}\b` | 0.40 | No |

## Asia-Pacific - Japan (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Japan DL | `\b\d{12}\b` | 0.40 | No |
| Japan Health Insurance | `\b\d{8}\b` | 0.40 | No |
| Japan Juminhyo Code | `\b\d{11}\b` | 0.40 | No |
| Japan My Number | `\b\d{12}\b` | 0.40 | No |
| Japan Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Japan Residence Card | `\b[A-Z]{2}\d{8}[A-Z]{2}\b` | 0.40 | No |

## Asia-Pacific - Malaysia (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Malaysia MyKad | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?\d{2}[-\s]?\d{4}\b` | 0.40 | No |
| Malaysia Passport | `\b[A-Z]\d{8}\b` | 0.40 | No |

## Asia-Pacific - New Zealand (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| New Zealand DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| New Zealand IRD | `\b\d{8,9}\b` | 0.40 | No |
| New Zealand NHI | `\b[A-HJ-NP-Z]{3}\d{4}\b` | 0.40 | No |
| New Zealand Passport | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |

## Asia-Pacific - Pakistan (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Pakistan CNIC | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` | 0.40 | No |
| Pakistan NICOP | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` | 0.40 | No |
| Pakistan Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |

## Asia-Pacific - Philippines (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Philippines Passport | `\b[A-Z]{1,2}\d{6,7}[A-Z]?\b` | 0.40 | No |
| Philippines PhilHealth | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{9}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |
| Philippines PhilSys | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` | 0.40 | No |
| Philippines SSS | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{7}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |
| Philippines TIN | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}(?:[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3})?\b` | 0.40 | No |
| Philippines UMID | `\b\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{7}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |

## Asia-Pacific - Singapore (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Singapore DL | `\b[STFGM]\d{7}[A-Z]\b` | 0.40 | No |
| Singapore FIN | `\b[FGM]\d{7}[A-Z]\b` | 0.40 | No |
| Singapore NRIC | `\b[ST]\d{7}[A-Z]\b` | 0.40 | No |
| Singapore Passport | `\b[A-Z]\d{7}[A-Z]\b` | 0.40 | No |

## Asia-Pacific - South Korea (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| South Korea DL | `\b\d{2}[-\s]?\d{2}[-\s]?\d{6}[-\s]?\d{2}\b` | 0.40 | No |
| South Korea Passport | `\b[MSROD]\d{8}\b` | 0.40 | No |
| South Korea RRN | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?[1-8]\d{6}\b` | 0.40 | No |

## Asia-Pacific - Sri Lanka (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Sri Lanka NIC New | `\b\d{12}\b` | 0.40 | No |
| Sri Lanka NIC Old | `\b\d{9}[VXvx]\b` | 0.40 | No |
| Sri Lanka Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |

## Asia-Pacific - Thailand (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Thailand DL | `\b\d{13}\b` | 0.40 | No |
| Thailand National ID | `\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b` | 0.40 | No |
| Thailand Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Thailand Tax ID | `\b\d{13}\b` | 0.40 | No |

## Asia-Pacific - Vietnam (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Vietnam CCCD | `\b\d{12}\b` | 0.40 | No |
| Vietnam Passport | `\b[A-Z]\d{8}\b` | 0.40 | No |
| Vietnam Tax Code | `\b\d{10}(?:-\d{3})?\b` | 0.40 | No |

## Authentication Tokens (1 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Session ID | `\b[0-9a-f]{32,64}\b` | 0.55 | No |

## Banking Authentication (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` | 0.50 | No |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` | 0.55 | No |
| PIN Block | `\b[0-9A-F]{16}\b` | 0.65 | No |

## Banking and Financial (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| ABA Routing Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{7}\b` | 0.55 | No |
| Canada Transit Number | `\b\d{5}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}\b` | 0.40 | No |
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` | 0.90 | No |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` | 0.85 | No |
| US Bank Account Number | `\b\d{8,17}\b` | 0.20 | Yes |

## Biometric Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Biometric Hash | `\b[0-9a-f]{64}\b` | 0.70 | No |
| Biometric Template ID | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` | 0.75 | No |

## Card Expiration Dates (1 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Card Expiry | `\b(?:0[1-9]\|1[0-2])\s?/\s?(?:\d{2}\|\d{4})\b` | 0.30 | Yes |

## Card Track Data (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Track 1 Data | `%B\d{13,19}\^[A-Z\s/]+\^\d{4}\d*` | 0.95 | No |
| Track 2 Data | `;\d{13,19}=\d{4}\d*\?` | 0.95 | No |

## Check and MICR Data (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Cashier Check Number | `\b\d{8,15}\b` | 0.20 | Yes |
| Check Number | `\b\d{4,6}\b` | 0.15 | Yes |
| MICR Line | `[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}` | 0.90 | No |

## Cloud Provider Secrets (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| AWS Access Key | `\bAKIA[0-9A-Z]{16}\b` | 0.95 | No |
| AWS Secret Key | `(?:^\|[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?:[^A-Za-z0-9/+=]\|$)` | 0.90 | No |
| Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | 0.90 | No |

## Code Platform Secrets (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| GitHub OAuth Token | `\bgho_[A-Za-z0-9]{36}\b` | 0.95 | No |
| GitHub Token (Classic) | `\bghp_[A-Za-z0-9]{36}\b` | 0.95 | No |
| GitHub Token (Fine-Grained) | `\bgithub_pat_[A-Za-z0-9_]{22,82}\b` | 0.95 | No |
| NPM Token | `\bnpm_[A-Za-z0-9]{36}\b` | 0.95 | No |
| PyPI Token | `\bpypi-[A-Za-z0-9_\-]{16,}\b` | 0.95 | No |

## Contact Information (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| E.164 Phone Number | `\+[1-9]\d{6,14}\b` | 0.40 | No |
| Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` | 0.90 | No |
| IPv4 Address | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` | 0.60 | No |
| IPv6 Address | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b\|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b\|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b` | 0.80 | No |
| MAC Address | `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` | 0.80 | No |

## Corporate Classification (9 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Corporate Confidential | `\b(?:[Cc]ompany\s+[Cc]onfidential\|[Cc]orporate\s+[Cc]onfidential\|[Ss]trictly\s+[Cc]onfidential)\b` | 0.40 | No |
| Do Not Distribute | `\b(?:[Nn]ot\s+[Ff]or\s+[Dd]istribution\|[Dd]o\s+[Nn]ot\s+[Dd]istribute\|[Nn]o\s+[Dd]istribution)\b` | 0.40 | No |
| Embargoed | `\b[Ee]mbargoed?\s+(?:[Ii]nformation\|[Dd]ata\|[Uu]ntil\|[Mm]aterial)\b` | 0.40 | No |
| Eyes Only | `\b[Ee]yes\s+[Oo]nly\b` | 0.40 | No |
| Highly Confidential | `\b[Hh]ighly\s+[Cc]onfidential\b` | 0.40 | No |
| Internal Only | `\b[Ii]nternal\s+(?:[Uu]se\s+)?[Oo]nly\b` | 0.40 | No |
| Need to Know | `\b[Nn]eed\s+[Tt]o\s+[Kk]now(?:\s+[Bb]asis)?\b` | 0.40 | No |
| Proprietary | `\b(?:[Pp]roprietary\s+(?:[Ii]nformation\|[Dd]ata\|[Mm]aterial)\|[Tt]rade\s+[Ss]ecret)\b` | 0.40 | No |
| Restricted | `\b(?:RESTRICTED\|[Rr]estricted\s+[Dd]ata\|[Rr]estricted\s+[Ii]nformation)\b` | 0.40 | No |

## Credit Card Numbers (7 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Amex | `\b3[47]\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{5}\b` | 0.90 | No |
| Diners Club | `\b3(?:0[0-5]\|[68]\d)\d[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.90 | No |
| Discover | `\b6(?:011\|5\d{2}\|4[4-9]\d)[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.90 | No |
| JCB | `\b35(?:2[89]\|[3-8]\d)[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.90 | No |
| MasterCard | `\b(?:5[1-5]\d{2}\|2(?:2[2-9]\d\|2[3-9]\d\|[3-6]\d{2}\|7[01]\d\|720))[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.90 | No |
| UnionPay | `\b62\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}(?:[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{1,3})?\b` | 0.90 | No |
| Visa | `\b4\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.90 | No |

## Cryptocurrency (7 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Bitcoin Address (Bech32) | `\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b` | 0.40 | No |
| Bitcoin Address (Legacy) | `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` | 0.40 | No |
| Bitcoin Cash Address | `\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b` | 0.75 | No |
| Ethereum Address | `\b0x[0-9a-fA-F]{40}\b` | 0.80 | No |
| Litecoin Address | `\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b` | 0.80 | No |
| Monero Address | `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` | 0.85 | No |
| Ripple Address | `\br[1-9A-HJ-NP-Za-km-z]{24,34}\b` | 0.80 | No |

## Customer Financial Data (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Account Balance | `(?:^\|[\s\(\[{,;])[\$\x{20ac}\x{00a3}\x{00a5}]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` | 0.50 | No |
| Balance with Currency Code | `\b(?:USD\|EUR\|GBP\|JPY\|CAD\|AUD\|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` | 0.55 | No |
| DTI Ratio | `\b\d{1,2}\.\d{1,2}%\b` | 0.45 | Yes |
| Income Amount | `(?:^\|[\s\(\[{,;])[\$\x{20ac}\x{00a3}\x{00a5}]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` | 0.40 | No |

## Data Classification Labels (8 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| CUI | `\b(?:CUI\|[Cc]ontrolled\s+[Uu]nclassified\s+[Ii]nformation)\b` | 0.40 | No |
| Confidential Classification | `\bCLASSIFIED\s+CONFIDENTIAL\b` | 0.40 | No |
| FOUO | `\b(?:FOUO\|[Ff]or\s+[Oo]fficial\s+[Uu]se\s+[Oo]nly)\b` | 0.40 | No |
| LES | `\b(?:LES\|[Ll]aw\s+[Ee]nforcement\s+[Ss]ensitive)\b` | 0.40 | No |
| NOFORN | `\bNOFORN\b` | 0.40 | No |
| SBU | `\b(?:SBU\|[Ss]ensitive\s+[Bb]ut\s+[Uu]nclassified)\b` | 0.40 | No |
| Secret Classification | `\b(?:SECRET(?://NOFORN)?\|CLASSIFIED\s+SECRET)\b` | 0.40 | No |
| Top Secret | `\b(?:TOP\s+SECRET\|TS//SCI\|TS//SI)\b` | 0.40 | No |

## Dates (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` | 0.40 | No |
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` | 0.40 | No |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` | 0.40 | No |

## Device Identifiers (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| ICCID | `\b89\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3,4}\d?\b` | 0.85 | No |
| IDFA/IDFV | `\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b` | 0.85 | No |
| IMEI | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.55 | No |
| IMEISV | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.55 | No |
| MEID | `\b[0-9A-F]{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[0-9A-F]{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[0-9A-F]{6}\b` | 0.70 | No |

## Education Identifiers (1 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| EDU Email | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b` | 0.90 | No |

## Employment Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Employee ID | `\b[A-Z]{1,3}\d{4,8}\b` | 0.35 | No |
| Work Permit Number | `\b[A-Z]{2,3}\d{7,10}\b` | 0.50 | No |

## Europe - Austria (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Austria DL | `\b\d{8}\b` | 0.40 | No |
| Austria ID Card | `\b\d{8}\b` | 0.40 | No |
| Austria Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |
| Austria SVN | `\b\d{4}[-\s]?\d{6}\b` | 0.40 | No |
| Austria Tax Number | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.40 | No |

## Europe - Belgium (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Belgium DL | `\b\d{10}\b` | 0.40 | No |
| Belgium NRN | `\b\d{2}[.\s]?\d{2}[.\s]?\d{2}[-.\s]?\d{3}[.\s]?\d{2}\b` | 0.40 | No |
| Belgium Passport | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Belgium VAT | `\bBE\s?0?\d{3}\.?\d{3}\.?\d{3}\b` | 0.40 | No |

## Europe - Bulgaria (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Bulgaria EGN | `\b\d{10}\b` | 0.40 | No |
| Bulgaria ID Card | `\b\d{9}\b` | 0.40 | No |
| Bulgaria LNC | `\b\d{10}\b` | 0.40 | No |
| Bulgaria Passport | `\b\d{9}\b` | 0.40 | No |

## Europe - Croatia (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Croatia DL | `\b\d{8,9}\b` | 0.40 | No |
| Croatia ID Card | `\b\d{9}\b` | 0.40 | No |
| Croatia OIB | `\b\d{11}\b` | 0.40 | No |
| Croatia Passport | `\b\d{9}\b` | 0.40 | No |

## Europe - Cyprus (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Cyprus ID Card | `\b\d{7,8}\b` | 0.40 | No |
| Cyprus Passport | `\b[A-Z]\d{7,8}\b` | 0.40 | No |
| Cyprus TIN | `\b\d{8}[A-Z]\b` | 0.40 | No |

## Europe - Czech Republic (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Czech Birth Number | `\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b` | 0.40 | No |
| Czech DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Czech ICO | `\b\d{8}\b` | 0.40 | No |
| Czech Passport | `\b\d{8}\b` | 0.40 | No |

## Europe - Denmark (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Denmark CPR | `\b[0-3]\d[01]\d{3}[-]?\d{4}\b` | 0.40 | No |
| Denmark DL | `\b\d{8}\b` | 0.40 | No |
| Denmark Passport | `\b\d{9}\b` | 0.40 | No |

## Europe - EU (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| EU ETD | `\b[A-Z]{3}\d{6}\b` | 0.40 | No |
| EU VAT Generic | `\b(?:AT\|BE\|BG\|CY\|CZ\|DE\|DK\|EE\|EL\|ES\|FI\|FR\|HR\|HU\|IE\|IT\|LT\|LU\|LV\|MT\|NL\|PL\|PT\|RO\|SE\|SI\|SK)[A-Z0-9]{8,12}\b` | 0.40 | No |

## Europe - Estonia (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Estonia DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Estonia Isikukood | `\b[1-6]\d{2}[01]\d[0-3]\d{5}\b` | 0.40 | No |
| Estonia Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |

## Europe - Finland (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Finland DL | `\b\d{8,10}\b` | 0.40 | No |
| Finland HETU | `\b[0-3]\d[01]\d{3}[-+A]\d{3}[A-Z0-9]\b` | 0.40 | No |
| Finland Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |

## Europe - France (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| France CNI | `\b[A-Z0-9]{12}\b` | 0.40 | No |
| France DL | `\b\d{2}[A-Z]{2}\d{5}\b` | 0.40 | No |
| France IBAN | `\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b` | 0.40 | No |
| France NIR | `\b[12]\d{2}(?:0[1-9]\|1[0-2])(?:\d{2}\|2[AB])\d{3}\d{3}\d{2}\b` | 0.40 | No |
| France Passport | `\b\d{2}[A-Z]{2}\d{5}\b` | 0.40 | No |

## Europe - Germany (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Germany DL | `\b[A-Z0-9]{11}\b` | 0.40 | No |
| Germany IBAN | `\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` | 0.40 | No |
| Germany ID | `\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b` | 0.40 | No |
| Germany Passport | `\bC[A-Z0-9]{8}\b` | 0.40 | No |
| Germany Social Insurance | `\b\d{2}[0-3]\d[01]\d{2}\d[A-Z]\d{3}\b` | 0.40 | No |
| Germany Tax ID | `\b\d{11}\b` | 0.40 | No |

## Europe - Greece (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Greece AFM | `\b\d{9}\b` | 0.40 | No |
| Greece AMKA | `\b[0-3]\d[01]\d{3}\d{5}\b` | 0.40 | No |
| Greece DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Greece ID Card | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Greece Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |

## Europe - Hungary (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Hungary DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Hungary Passport | `\b[A-Z]{2}\d{6,7}\b` | 0.40 | No |
| Hungary Personal ID | `\b\d[-]?\d{6}[-]?\d{4}\b` | 0.40 | No |
| Hungary TAJ | `\b\d{3}\s?\d{3}\s?\d{3}\b` | 0.40 | No |
| Hungary Tax Number | `\b\d{10}\b` | 0.40 | No |

## Europe - Iceland (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Iceland Kennitala | `\b[0-3]\d[01]\d{3}[-]?\d{4}\b` | 0.40 | No |
| Iceland Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |

## Europe - Ireland (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Ireland DL | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}\b` | 0.40 | No |
| Ireland Eircode | `\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b` | 0.40 | No |
| Ireland PPS | `\b\d{7}[A-Z]{1,2}\b` | 0.40 | No |
| Ireland Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |

## Europe - Italy (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Italy Codice Fiscale | `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b` | 0.40 | No |
| Italy DL | `\b[A-Z]{2}\d{7}[A-Z]\b` | 0.40 | No |
| Italy Partita IVA | `\b\d{11}\b` | 0.40 | No |
| Italy Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Italy SSN | `\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b` | 0.40 | No |

## Europe - Latvia (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Latvia DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Latvia Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Latvia Personas Kods | `\b[0-3]\d[01]\d{3}[-]?\d{5}\b` | 0.40 | No |

## Europe - Liechtenstein (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Liechtenstein PIN | `\b\d{12}\b` | 0.40 | No |
| Liechtenstein Passport | `\b[A-Z]\d{5}\b` | 0.40 | No |

## Europe - Lithuania (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Lithuania Asmens Kodas | `\b[3-6]\d{2}[01]\d[0-3]\d{5}\b` | 0.40 | No |
| Lithuania DL | `\b\d{8}\b` | 0.40 | No |
| Lithuania Passport | `\b\d{8}\b` | 0.40 | No |

## Europe - Luxembourg (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Luxembourg DL | `\b\d{6}\b` | 0.40 | No |
| Luxembourg NIN | `\b\d{4}[01]\d[0-3]\d\d{5}\b` | 0.40 | No |
| Luxembourg Passport | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |

## Europe - Malta (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Malta ID Card | `\b\d{3,7}[A-Z]\b` | 0.40 | No |
| Malta Passport | `\b\d{7}\b` | 0.40 | No |
| Malta TIN | `\b\d{3,9}[A-Z]?\b` | 0.40 | No |

## Europe - Netherlands (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Netherlands BSN | `\b\d{9}\b` | 0.40 | No |
| Netherlands DL | `\b\d{10}\b` | 0.40 | No |
| Netherlands IBAN | `\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` | 0.40 | No |
| Netherlands Passport | `\b[A-Z]{2}[A-Z0-9]{6}\d\b` | 0.40 | No |

## Europe - Norway (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Norway D-Number | `\b[4-7]\d[01]\d{3}\d{5}\b` | 0.40 | No |
| Norway DL | `\b\d{11}\b` | 0.40 | No |
| Norway FNR | `\b[0-3]\d[01]\d{3}\d{5}\b` | 0.40 | No |
| Norway Passport | `\b\d{8}\b` | 0.40 | No |

## Europe - Poland (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Poland DL | `\b\d{5}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.40 | No |
| Poland ID Card | `\b[A-Z]{3}\d{6}\b` | 0.40 | No |
| Poland NIP | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.40 | No |
| Poland PESEL | `\b\d{11}\b` | 0.40 | No |
| Poland Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Poland REGON | `\b\d{9}(?:\d{5})?\b` | 0.40 | No |

## Europe - Portugal (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Portugal CC | `\b\d{8}\s?\d\s?[A-Z]{2}\d\b` | 0.40 | No |
| Portugal NIF | `\b[12356789]\d{8}\b` | 0.40 | No |
| Portugal NISS | `\b\d{11}\b` | 0.40 | No |
| Portugal Passport | `\b[A-Z]{1,2}\d{6}\b` | 0.40 | No |

## Europe - Romania (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Romania CIF | `\b\d{2,10}\b` | 0.40 | No |
| Romania CNP | `\b[1-8]\d{12}\b` | 0.40 | No |
| Romania DL | `\b\d{9}\b` | 0.40 | No |
| Romania Passport | `\b\d{8,9}\b` | 0.40 | No |

## Europe - Slovakia (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Slovakia Birth Number | `\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b` | 0.40 | No |
| Slovakia DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Slovakia Passport | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |

## Europe - Slovenia (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Slovenia DL | `\b\d{8}\b` | 0.40 | No |
| Slovenia EMSO | `\b[0-3]\d[01]\d{3}\d{6}\d\b` | 0.40 | No |
| Slovenia Passport | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| Slovenia Tax Number | `\b\d{8}\b` | 0.40 | No |

## Europe - Spain (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Spain DL | `\b\d{8}[A-Z]\b` | 0.40 | No |
| Spain DNI | `\b\d{8}[A-Z]\b` | 0.40 | No |
| Spain NIE | `\b[XYZ]\d{7}[A-Z]\b` | 0.40 | No |
| Spain NSS | `\b\d{2}[-/]?\d{8}[-/]?\d{2}\b` | 0.40 | No |
| Spain Passport | `\b[A-Z]{3}\d{6}\b` | 0.40 | No |

## Europe - Sweden (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Sweden DL | `\b\d{6}[-]?\d{4}\b` | 0.40 | No |
| Sweden Organisation Number | `\b\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.40 | No |
| Sweden PIN | `\b\d{6}[-+]?\d{4}\b` | 0.40 | No |
| Sweden Passport | `\b\d{8}\b` | 0.40 | No |

## Europe - Switzerland (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Switzerland AHV | `\b756[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.40 | No |
| Switzerland DL | `\b\d{6,7}\b` | 0.40 | No |
| Switzerland Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |
| Switzerland UID | `\bCHE[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}\b` | 0.40 | No |

## Europe - Turkey (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Turkey DL | `\b\d{6}\b` | 0.40 | No |
| Turkey Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |
| Turkey TC Kimlik | `\b[1-9]\d{10}\b` | 0.40 | No |
| Turkey Tax ID | `\b\d{10}\b` | 0.40 | No |

## Europe - United Kingdom (7 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| British NHS | `\b\d{3}\s?\d{3}\s?\d{4}\b` | 0.40 | No |
| UK DL | `\b[A-Z]{5}\d{6}[A-Z0-9]{5}\b` | 0.40 | No |
| UK NIN | `\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b` | 0.40 | No |
| UK Passport | `\b\d{9}\b` | 0.40 | No |
| UK Phone Number | `(?:\+44[-.\s]?\|0)(?:\d[-.\s]?){9,10}\b` | 0.40 | No |
| UK Sort Code | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.40 | No |
| UK UTR | `\b\d{5}\s?\d{5}\b` | 0.40 | No |

## Financial Regulatory Labels (7 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Draft Not for Circulation | `\b[Dd]raft\s*[-–—]\s*[Nn]ot\s+[Ff]or\s+[Cc]irculation\b` | 0.40 | No |
| Information Barrier | `\b(?:[Ii]nformation\s+[Bb]arrier\|[Cc]hinese\s+[Ww]all)\b` | 0.40 | No |
| Inside Information | `\b[Ii]nside(?:r)?\s+[Ii]nformation\b` | 0.40 | No |
| Investment Restricted | `\b[Rr]estricted\s+[Ll]ist\b` | 0.40 | No |
| MNPI | `\b(?:MNPI\|[Mm]aterial\s+[Nn]on-?[Pp]ublic\s+[Ii]nformation)\b` | 0.40 | No |
| Market Sensitive | `\b[Mm]arket\s+[Ss]ensitive\b` | 0.40 | No |
| Pre-Decisional | `\b[Pp]re-?[Dd]ecisional\b` | 0.40 | No |

## Generic Secrets (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Bearer Token | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` | 0.80 | No |
| Database Connection String | `(?:mongodb(?:\+srv)?\|mysql\|postgres(?:ql)?\|redis\|mssql)://[^:\s]+:[^@\s]+@[^\s]+` | 0.90 | No |
| JWT Token | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | 0.95 | No |
| Private Key | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` | 0.95 | No |

## Geolocation (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` | 0.80 | No |
| Geohash | `\b[0-9bcdefghjkmnpqrstuvwxyz]{7,12}\b` | 0.60 | No |

## Insurance Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` | 0.45 | No |
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` | 0.50 | No |

## Internal Banking References (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Internal Account Ref | `\b[A-Z]{2,4}\d{8,14}\b` | 0.50 | No |
| Teller ID | `\b[A-Z]{1,3}\d{4,8}\b` | 0.35 | No |

## Latin America - Argentina (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Argentina CUIL/CUIT | `\b(?:20\|2[3-7]\|30\|33)[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{8}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |
| Argentina DNI | `\b\d{7,8}\b` | 0.40 | No |
| Argentina Passport | `\b[A-Z]{3}\d{6}\b` | 0.40 | No |

## Latin America - Brazil (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Brazil CNH | `\b\d{11}\b` | 0.40 | No |
| Brazil CNPJ | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.40 | No |
| Brazil CPF | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.40 | No |
| Brazil Passport | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Brazil RG | `\b\d{1,2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[\dXx]\b` | 0.40 | No |
| Brazil SUS Card | `\b[1-2]\d{10}00[01]\d\b\|\b[789]\d{14}\b` | 0.40 | No |

## Latin America - Chile (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Chile Passport | `\b[A-Z]?\d{7,8}\b` | 0.40 | No |
| Chile RUN/RUT | `\b\d{1,2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[\dkK]\b` | 0.40 | No |

## Latin America - Colombia (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Colombia Cedula | `\b\d{6,10}\b` | 0.40 | No |
| Colombia NIT | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |
| Colombia NUIP | `\b\d{6,10}\b` | 0.40 | No |
| Colombia Passport | `\b[A-Z]{2}\d{6,7}\b` | 0.40 | No |

## Latin America - Costa Rica (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Costa Rica Cedula | `\b\d{1}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.40 | No |
| Costa Rica DIMEX | `\b\d{11,12}\b` | 0.40 | No |
| Costa Rica Passport | `\b[A-Z]\d{8}\b` | 0.40 | No |

## Latin America - Ecuador (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Ecuador Cedula | `\b\d{10}\b` | 0.40 | No |
| Ecuador Passport | `\b[A-Z]\d{7,8}\b` | 0.40 | No |
| Ecuador RUC | `\b\d{13}\b` | 0.40 | No |

## Latin America - Paraguay (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Paraguay Cedula | `\b\d{5,7}\b` | 0.40 | No |
| Paraguay Passport | `\b[A-Z]\d{6,8}\b` | 0.40 | No |
| Paraguay RUC | `\b\d{6,8}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |

## Latin America - Peru (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Peru Carnet Extranjeria | `\b\d{9,12}\b` | 0.40 | No |
| Peru DNI | `\b\d{8}\b` | 0.40 | No |
| Peru Passport | `\b[A-Z]{2}\d{6,7}\b` | 0.40 | No |
| Peru RUC | `\b(?:10\|15\|17\|20)\d{9}\b` | 0.40 | No |

## Latin America - Uruguay (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Uruguay Cedula | `\b\d{1}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |
| Uruguay Passport | `\b[A-Z]\d{6,8}\b` | 0.40 | No |
| Uruguay RUT | `\b\d{12}\b` | 0.40 | No |

## Latin America - Venezuela (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Venezuela Cedula | `\b[VvEe][-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6,9}\b` | 0.40 | No |
| Venezuela Passport | `\b[A-Z]\d{7,8}\b` | 0.40 | No |
| Venezuela RIF | `\b[VEJGvejg][-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{8}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |

## Legal Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Court Docket Number | `\b\d{2,4}-?[A-Z]{1,4}-?\d{4,8}\b` | 0.45 | No |
| US Federal Case Number | `\b\d:\d{2}-[a-z]{2}-\d{4,5}\b` | 0.80 | No |

## Loan and Mortgage Data (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| LTV Ratio | `\b\d{1,3}\.\d{1,2}%\b` | 0.40 | Yes |
| Loan Number | `\b[A-Z0-9]{8,15}\b` | 0.45 | No |
| MERS MIN | `\b\d{18}\b` | 0.50 | No |
| Universal Loan Identifier | `\b[A-Z0-9]{4}00[A-Z0-9]{17,39}\b` | 0.75 | No |

## Medical Identifiers (4 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| DEA Number | `\b[A-Z]{2}\d{7}\b` | 0.55 | No |
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` | 0.60 | No |
| ICD-10 Code | `\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b` | 0.50 | No |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` | 0.65 | No |

## Messaging Service Secrets (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Mailgun API Key | `\bkey-[0-9a-zA-Z]{32}\b` | 0.90 | No |
| SendGrid API Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | 0.95 | No |
| Slack Bot Token | `\bxoxb-[0-9A-Za-z\-]+\b` | 0.95 | No |
| Slack User Token | `\bxoxp-[0-9A-Za-z\-]+\b` | 0.95 | No |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+` | 0.40 | No |
| Twilio API Key | `\bSK[0-9a-f]{32}\b` | 0.90 | No |

## Middle East - Bahrain (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Bahrain CPR | `\b\d{9}\b` | 0.40 | No |
| Bahrain Passport | `\b\d{7,9}\b` | 0.40 | No |

## Middle East - Iran (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Iran Melli Code | `\b\d{10}\b` | 0.40 | No |
| Iran Passport | `\b[A-Z]\d{8}\b` | 0.40 | No |

## Middle East - Iraq (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Iraq National ID | `\b\d{12}\b` | 0.40 | No |
| Iraq Passport | `\b[A-HJ-NP-Z0-9]{9}\b` | 0.40 | No |

## Middle East - Israel (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Israel Passport | `\b\d{7,8}\b` | 0.40 | No |
| Israel Teudat Zehut | `\b\d{9}\b` | 0.40 | No |

## Middle East - Jordan (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Jordan National ID | `\b\d{10}\b` | 0.40 | No |
| Jordan Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |

## Middle East - Kuwait (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Kuwait Civil ID | `\b[1-3]\d{11}\b` | 0.40 | No |
| Kuwait Passport | `\b[A-Z]?\d{7,9}\b` | 0.40 | No |

## Middle East - Lebanon (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Lebanon ID | `\b\d{7,12}\b` | 0.40 | No |
| Lebanon Passport | `\b(?:RL\|LR)\d{6,7}\b` | 0.40 | No |

## Middle East - Qatar (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Qatar Passport | `\b[A-Z]\d{7}\b` | 0.40 | No |
| Qatar QID | `\b[23]\d{10}\b` | 0.40 | No |

## Middle East - Saudi Arabia (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Saudi Arabia National ID | `\b[12]\d{9}\b` | 0.40 | No |
| Saudi Arabia Passport | `\b[A-Z]\d{7,8}\b` | 0.40 | No |

## Middle East - UAE (3 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| UAE Emirates ID | `\b784[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{7}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d\b` | 0.40 | No |
| UAE Passport | `\b[A-Z]?\d{7,9}\b` | 0.40 | No |
| UAE Visa Number | `\b[1-7]01/?(?:19\|20)\d{2}/?\d{7}\b` | 0.40 | No |

## North America - Canada (29 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Alberta DL | `\b\d{6,9}\b` | 0.40 | No |
| Alberta HC | `\b\d{9}\b` | 0.40 | No |
| BC HC | `\b9\d{9}\b` | 0.40 | No |
| British Columbia DL | `\b\d{7}\b` | 0.40 | No |
| Canada BN | `\b\d{9}[A-Z]{2}\d{4}\b` | 0.40 | No |
| Canada Bank Code | `\b\d{5}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}\b` | 0.40 | No |
| Canada NEXUS | `\b\d{9}\b` | 0.40 | No |
| Canada PR Card | `\b[A-Z]{2}\d{7,10}\b` | 0.40 | No |
| Canada Passport | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Canada SIN | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}\b` | 0.40 | No |
| Manitoba DL | `\b[A-Z]{6}\d{6}\b` | 0.40 | No |
| Manitoba HC | `\b\d{9}\b` | 0.40 | No |
| NWT DL | `\b\d{6}\b` | 0.40 | No |
| New Brunswick DL | `\b\d{5,7}\b` | 0.40 | No |
| New Brunswick HC | `\b\d{9}\b` | 0.40 | No |
| Newfoundland DL | `\b[A-Z]\d{9,10}\b` | 0.40 | No |
| Newfoundland HC | `\b\d{12}\b` | 0.40 | No |
| Nova Scotia DL | `\b[A-Z]{5}\d{9}\b` | 0.40 | No |
| Nova Scotia HC | `\b\d{10}\b` | 0.40 | No |
| Nunavut DL | `\b\d{6}\b` | 0.40 | No |
| Ontario DL | `\b[A-Z]\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{5}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{5}\b` | 0.40 | No |
| Ontario HC | `\b\d{10}(?:\s?[A-Z]{2})?\b` | 0.40 | No |
| PEI DL | `\b\d{1,6}\b` | 0.40 | No |
| PEI HC | `\b\d{8}\b` | 0.40 | No |
| Quebec DL | `\b[A-Z]\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{6}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}\b` | 0.40 | No |
| Quebec HC | `\b[A-Z]{4}\d{8}\b` | 0.40 | No |
| Saskatchewan DL | `\b\d{8}\b` | 0.40 | No |
| Saskatchewan HC | `\b\d{9}\b` | 0.40 | No |
| Yukon DL | `\b\d{6}\b` | 0.40 | No |

## North America - Mexico (7 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Mexico CURP | `\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b` | 0.40 | No |
| Mexico Clave Elector | `\b[A-Z]{6}\d{8}[HM]\d{3}\b` | 0.40 | No |
| Mexico INE CIC | `\b\d{9}\b` | 0.40 | No |
| Mexico INE OCR | `\b\d{13}\b` | 0.40 | No |
| Mexico NSS | `\b\d{11}\b` | 0.40 | No |
| Mexico Passport | `\b[A-Z]\d{8}\b` | 0.40 | No |
| Mexico RFC | `\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b` | 0.40 | No |

## North America - US Generic DL (1 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Generic US DL | `\b[A-Z]{1,2}\d{4,14}\b` | 0.40 | No |

## North America - United States (63 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Alabama DL | `\b\d{7}\b` | 0.40 | No |
| Alaska DL | `\b\d{7}\b` | 0.40 | No |
| Arizona DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` | 0.40 | No |
| Arkansas DL | `\b\d{8,9}\b` | 0.40 | No |
| California DL | `\b[A-Z]\d{7}\b` | 0.40 | No |
| Colorado DL | `\b(?:\d{9}\|[A-Z]\d{3,6})\b` | 0.40 | No |
| Connecticut DL | `\b\d{9}\b` | 0.40 | No |
| DC DL | `\b(?:\d{7}\|\d{9})\b` | 0.40 | No |
| Delaware DL | `\b\d{1,7}\b` | 0.40 | No |
| Florida DL | `\b[A-Z]\d{12}\b` | 0.40 | No |
| Georgia DL | `\b\d{7,9}\b` | 0.40 | No |
| Hawaii DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` | 0.40 | No |
| Idaho DL | `\b[A-Z]{2}\d{6}[A-Z]\b` | 0.40 | No |
| Illinois DL | `\b[A-Z]\d{11}\b` | 0.40 | No |
| Indiana DL | `\b(?:\d{10}\|[A-Z]\d{9})\b` | 0.40 | No |
| Iowa DL | `\b\d{3}[A-Z]{2}\d{4}\b` | 0.40 | No |
| Kansas DL | `\b(?:[A-Z]\d{8}\|[A-Z]{2}\d{7}\|\d{9})\b` | 0.40 | No |
| Kentucky DL | `\b[A-Z]\d{8}\b` | 0.40 | No |
| Louisiana DL | `\b\d{9}\b` | 0.40 | No |
| Maine DL | `\b\d{7}[A-Z]?\b` | 0.40 | No |
| Maryland DL | `\b[A-Z]\d{12}\b` | 0.40 | No |
| Massachusetts DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` | 0.40 | No |
| Michigan DL | `\b[A-Z]\d{12}\b` | 0.40 | No |
| Minnesota DL | `\b[A-Z]\d{12}\b` | 0.40 | No |
| Mississippi DL | `\b\d{9}\b` | 0.40 | No |
| Missouri DL | `\b(?:[A-Z]\d{5,9}\|\d{9})\b` | 0.40 | No |
| Montana DL | `\b(?:\d{13}\|\d{9})\b` | 0.40 | No |
| Nebraska DL | `\b[A-Z]\d{8}\b` | 0.40 | No |
| Nevada DL | `\b(?:\d{10}\|\d{12})\b` | 0.40 | No |
| New Hampshire DL | `\b\d{2}[A-Z]{3}\d{5}\b` | 0.40 | No |
| New Jersey DL | `\b[A-Z]\d{14}\b` | 0.40 | No |
| New Mexico DL | `\b\d{9}\b` | 0.40 | No |
| New York DL | `\b\d{9}\b` | 0.40 | No |
| North Carolina DL | `\b\d{1,12}\b` | 0.40 | No |
| North Dakota DL | `\b(?:[A-Z]{3}\d{6}\|\d{9})\b` | 0.40 | No |
| Ohio DL | `\b[A-Z]{2}\d{6}\b` | 0.40 | No |
| Oklahoma DL | `\b(?:[A-Z]\d{9}\|\d{9})\b` | 0.40 | No |
| Oregon DL | `\b\d{1,9}\b` | 0.40 | No |
| Pennsylvania DL | `\b\d{8}\b` | 0.40 | No |
| Rhode Island DL | `\b(?:\d{7}\|[A-Z]\d{6})\b` | 0.40 | No |
| South Carolina DL | `\b\d{5,11}\b` | 0.40 | No |
| South Dakota DL | `\b(?:\d{8,10}\|\d{12})\b` | 0.40 | No |
| Tennessee DL | `\b\d{7,9}\b` | 0.40 | No |
| Texas DL | `\b\d{8}\b` | 0.40 | No |
| US DEA Number | `\b[A-Z]{2}\d{7}\b` | 0.40 | No |
| US DoD ID | `\b\d{10}\b` | 0.40 | No |
| US Known Traveler Number | `\b\d{9}\b` | 0.40 | No |
| US MBI | `\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b` | 0.40 | No |
| US NPI | `\b[12]\d{9}\b` | 0.40 | No |
| US Phone Number | `(?:^\|[^\d])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b` | 0.40 | No |
| USA EIN | `\b\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{7}\b` | 0.40 | No |
| USA ITIN | `\b9\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.40 | No |
| USA Passport | `\b\d{9}\b` | 0.40 | No |
| USA Passport Card | `\bC\d{8}\b` | 0.40 | No |
| USA Routing Number | `\b\d{9}\b` | 0.40 | No |
| USA SSN | `\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.40 | No |
| Utah DL | `\b\d{4,10}\b` | 0.40 | No |
| Vermont DL | `\b(?:\d{8}\|\d{7}[A-Z])\b` | 0.40 | No |
| Virginia DL | `\b(?:[A-Z]\d{8,11}\|\d{9})\b` | 0.40 | No |
| Washington DL | `\b[A-Z]{1,7}[A-Z0-9*]{5,11}\b` | 0.40 | No |
| West Virginia DL | `\b(?:\d{7}\|[A-Z]\d{6})\b` | 0.40 | No |
| Wisconsin DL | `\b[A-Z]\d{13}\b` | 0.40 | No |
| Wyoming DL | `\b\d{9,10}\b` | 0.40 | No |

## PCI Sensitive Data (1 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Cardholder Name Pattern | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` | 0.10 | Yes |

## Payment Service Secrets (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Stripe Publishable Key | `\bpk_(?:live\|test)_[A-Za-z0-9]{24,}\b` | 0.85 | No |
| Stripe Secret Key | `\bsk_(?:live\|test)_[A-Za-z0-9]{24,}\b` | 0.95 | No |

## Personal Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` | 0.40 | Yes |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender)\b` | 0.25 | Yes |

## Postal Codes (5 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Brazil CEP | `\b\d{5}-\d{3}\b` | 0.45 | No |
| Canada Postal Code | `\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b` | 0.75 | No |
| Japan Postal Code | `\b\d{3}-\d{4}\b` | 0.45 | No |
| UK Postcode | `\b[A-Z]{1,2}\d[A-Z0-9]?\s?\d[A-Z]{2}\b` | 0.70 | No |
| US ZIP+4 Code | `\b\d{5}-\d{4}\b` | 0.55 | No |

## Primary Account Numbers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Masked PAN | `\b\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[Xx*]{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[Xx*]{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}\b` | 0.85 | No |
| PAN | `\b\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{4}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{1,7}\b` | 0.60 | No |

## Privacy Classification (10 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| CCPA/CPRA | `\b(?:CCPA\|CPRA\|[Cc]alifornia\s+[Cc]onsumer\s+[Pp]rivacy)\b` | 0.40 | No |
| FERPA | `\b(?:FERPA\|[Ff]amily\s+[Ee]ducational\s+[Rr]ights)\b` | 0.40 | No |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` | 0.40 | No |
| GLBA | `\b(?:GLBA\|[Gg]ramm[-\s][Ll]each[-\s][Bb]liley)\b` | 0.40 | No |
| HIPAA | `\bHIPAA\b` | 0.40 | No |
| NPI | `\b(?:NPI\|[Nn]on-?[Pp]ublic\s+[Pp]ersonal\s+[Ii]nformation)\b` | 0.40 | No |
| PCI-DSS | `\b(?:PCI[-\s]?DSS\|[Cc]ardholder\s+[Dd]ata\s+[Ee]nvironment\|CDE)\b` | 0.40 | No |
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` | 0.40 | No |
| PII Label | `\b(?:PII\|[Pp]ersonally\s+[Ii]dentifiable\s+[Ii]nformation)\b` | 0.40 | No |
| SOX | `\b(?:SOX\|[Ss]arbanes[-\s][Oo]xley)\b` | 0.40 | No |

## Privileged Information (7 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Attorney-Client Privilege | `\b[Aa]ttorney[-\s][Cc]lient\s+[Pp]rivileged?\b` | 0.40 | No |
| Legal Privilege | `\b[Ll]egal(?:ly)?\s+[Pp]rivileged\b` | 0.40 | No |
| Litigation Hold | `\b(?:[Ll]itigation\|[Ll]egal)\s+[Hh]old\b` | 0.40 | No |
| Privileged Information | `\b[Pp]rivileged\s+[Ii]nformation\b` | 0.40 | No |
| Privileged and Confidential | `\b[Pp]rivileged\s+(?:and\|&)\s+[Cc]onfidential\b` | 0.40 | No |
| Protected by Privilege | `\b[Pp]rotected\s+(?:by\|under)\s+[Pp]rivilege\b` | 0.40 | No |
| Work Product | `\b[Ww]ork\s+[Pp]roduct(?:\s+[Dd]octrine)?\b` | 0.40 | No |

## Property Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Parcel Number | `\b\d{3}-\d{3}-\d{3}(?:-\d{3})?\b` | 0.60 | No |
| Title Deed Number | `\b\d{4,}-\d{4,}\b` | 0.40 | No |

## Regulatory Identifiers (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| AML Case ID | `\b[A-Z]{2,4}[-]?\d{6,12}\b` | 0.60 | No |
| CTR Number | `\b\d{14,20}\b` | 0.30 | No |
| Compliance Case Number | `\b[A-Z]{2,5}[-]?\d{4}[-]?\d{4,8}\b` | 0.55 | No |
| FinCEN Report Number | `\b\d{14}\b` | 0.30 | No |
| OFAC SDN Entry | `\b\d{4,6}\b` | 0.15 | Yes |
| SAR Filing Number | `\b\d{14,20}\b` | 0.30 | No |

## Securities Identifiers (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| CUSIP | `\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b` | 0.70 | No |
| FIGI | `\bBBG[A-Z0-9]{9}\b` | 0.90 | No |
| ISIN | `\b[A-Z]{2}[0-9A-Z]{9}\d\b` | 0.75 | No |
| LEI | `\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b` | 0.80 | No |
| SEDOL | `\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b` | 0.70 | No |
| Ticker Symbol | `(?:^\|[\s\(\[{,;])\$[A-Z]{1,5}\b` | 0.80 | No |

## Social Media Identifiers (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| Hashtag | `(?:^\|[\s\(\[{,;])#[A-Za-z]\w{2,49}\b` | 0.30 | Yes |
| Twitter Handle | `(?:^\|[\s\(\[{,;])@[A-Za-z_]\w{0,14}\b` | 0.60 | No |

## Supervisory Information (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` | 0.40 | No |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` | 0.40 | No |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` | 0.40 | No |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` | 0.40 | No |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` | 0.40 | No |
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` | 0.40 | No |

## URLs with Credentials (2 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| URL with Password | `https?://[^:\s]+:[^@\s]+@[^\s]+` | 0.40 | No |
| URL with Token | `https?://[^\s]*[?&](?:token\|key\|api_key\|apikey\|access_token\|secret\|password\|passwd\|pwd)=[^\s&]+` | 0.40 | No |

## Vehicle Identification (1 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| VIN | `\b[A-HJ-NPR-Z0-9]{17}\b` | 0.70 | No |

## Wire Transfer Data (6 patterns)

| Pattern Name | Regex | Specificity | Context Required |
|---|---|---:|:---:|
| ACH Batch Number | `\b\d{7}\b` | 0.20 | Yes |
| ACH Trace Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{13}\b` | 0.55 | No |
| CHIPS UID | `\b\d{6}[A-Z0-9]{4,10}\b` | 0.50 | No |
| Fedwire IMAD | `\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b` | 0.90 | No |
| SEPA Reference | `\b[A-Z0-9]{12,35}\b` | 0.50 | No |
| Wire Reference Number | `\b[A-Z0-9]{16,35}\b` | 0.50 | No |
