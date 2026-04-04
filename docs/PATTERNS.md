# PATTERNS.md

Complete inventory of all patterns in dlpscan.
**560 patterns** across **126 categories**.


## Africa - Egypt (3 patterns)

| Pattern Name | Regex |
|---|---|
| Egypt National ID | `\b[23]\d{13}\b` |
| Egypt Tax ID | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Egypt Passport | `\b[A-Z]?\d{7,8}\b` |

## Africa - Ethiopia (3 patterns)

| Pattern Name | Regex |
|---|---|
| Ethiopia National ID | `\b\d{12}\b` |
| Ethiopia TIN | `\b\d{10}\b` |
| Ethiopia Passport | `\b[A-Z]{2}\d{7}\b` |

## Africa - Ghana (4 patterns)

| Pattern Name | Regex |
|---|---|
| Ghana Card | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` |
| Ghana TIN | `\b[CGQV]\d{10}\b` |
| Ghana NHIS | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` |
| Ghana Passport | `\b[A-Z]\d{7}\b` |

## Africa - Kenya (4 patterns)

| Pattern Name | Regex |
|---|---|
| Kenya National ID | `\b\d{7,8}\b` |
| Kenya KRA PIN | `\b[A-Z]\d{9}[A-Z]\b` |
| Kenya NHIF | `\b\d{6,9}\b` |
| Kenya Passport | `\b[A-Z]\d{7,8}\b` |

## Africa - Morocco (3 patterns)

| Pattern Name | Regex |
|---|---|
| Morocco CIN | `\b[A-Z]{1,2}\d{5,6}\b` |
| Morocco Tax ID | `\b\d{8}\b` |
| Morocco Passport | `\b[A-Z]{2}\d{7}\b` |

## Africa - Nigeria (6 patterns)

| Pattern Name | Regex |
|---|---|
| Nigeria NIN | `\b\d{11}\b` |
| Nigeria BVN | `\b\d{11}\b` |
| Nigeria TIN | `\b\d{12,13}\b` |
| Nigeria Voter Card | `\b[0-9A-Z]{19}\b` |
| Nigeria Driver Licence | `\b[A-Z]{3}\d{5,9}[A-Z]{0,2}\d{0,2}\b` |
| Nigeria Passport | `\b[A-Z]\d{8}\b` |

## Africa - South Africa (3 patterns)

| Pattern Name | Regex |
|---|---|
| South Africa ID | `\b\d{13}\b` |
| South Africa Passport | `\b[A-Z]?\d{8,9}\b` |
| South Africa DL | `\b\d{10}[A-Z]{2}\b` |

## Africa - Tanzania (3 patterns)

| Pattern Name | Regex |
|---|---|
| Tanzania NIDA | `\b\d{20}\b` |
| Tanzania TIN | `\b\d{9}\b` |
| Tanzania Passport | `\b[A-Z]{2}\d{7}\b` |

## Africa - Tunisia (2 patterns)

| Pattern Name | Regex |
|---|---|
| Tunisia CIN | `\b\d{8}\b` |
| Tunisia Passport | `\b[A-Z]\d{6}\b` |

## Africa - Uganda (2 patterns)

| Pattern Name | Regex |
|---|---|
| Uganda NIN | `\bC[MF]\d{8}[A-Z0-9]{4}\b` |
| Uganda Passport | `\b[A-Z]\d{7,8}\b` |

## Asia-Pacific - Australia (11 patterns)

| Pattern Name | Regex |
|---|---|
| Australia TFN | `\b\d{3}[\s]?\d{3}[\s]?\d{2,3}\b` |
| Australia Medicare | `\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s]?\d?\b` |
| Australia Passport | `\b[A-Z]{1,2}\d{7}\b` |
| Australia DL NSW | `\b\d{8}\b` |
| Australia DL VIC | `\b\d{8,10}\b` |
| Australia DL QLD | `\b\d{8,9}\b` |
| Australia DL WA | `\b\d{7}\b` |
| Australia DL SA | `\b[A-Z]?\d{5,6}\b` |
| Australia DL TAS | `\b[A-Z]\d{5,6}\b` |
| Australia DL ACT | `\b\d{6,10}\b` |
| Australia DL NT | `\b\d{5,7}\b` |

## Asia-Pacific - Bangladesh (3 patterns)

| Pattern Name | Regex |
|---|---|
| Bangladesh NID | `\b(?:\d{10}\|\d{17})\b` |
| Bangladesh Passport | `\b[A-Z]{2}\d{7}\b` |
| Bangladesh TIN | `\b\d{12}\b` |

## Asia-Pacific - China (5 patterns)

| Pattern Name | Regex |
|---|---|
| China Resident ID | `\b\d{6}(?:18\|19\|20)\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` |
| China Passport | `\b[EGD][A-Z]?\d{7,8}\b` |
| Hong Kong ID | `\b[A-Z]{1,2}\d{6}\s?\(?[0-9A]\)?\b` |
| Macau ID | `\b[1578]\d{6}\s?\(?[0-9]\)?\b` |
| Taiwan National ID | `\b[A-Z][12489]\d{8}\b` |

## Asia-Pacific - India (6 patterns)

| Pattern Name | Regex |
|---|---|
| India PAN | `\b[A-Z]{5}\d{4}[A-Z]\b` |
| India Aadhaar | `\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b` |
| India Passport | `\b[A-Z][1-9]\d{5}[1-9]\b` |
| India DL | `\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19\|20)\d{2}[-\s]?\d{7}\b` |
| India Voter ID | `\b[A-Z]{3}\d{7}\b` |
| India Ration Card | `\b\d{2}[\s-]?\d{8}\b` |

## Asia-Pacific - Indonesia (3 patterns)

| Pattern Name | Regex |
|---|---|
| Indonesia NIK | `\b\d{16}\b` |
| Indonesia NPWP | `\b\d{2}\.?\d{3}\.?\d{3}\.?\d[-.]?\d{3}\.?\d{3}\b` |
| Indonesia Passport | `\b[A-Z]{1,2}\d{6,7}\b` |

## Asia-Pacific - Japan (6 patterns)

| Pattern Name | Regex |
|---|---|
| Japan My Number | `\b\d{12}\b` |
| Japan Passport | `\b[A-Z]{2}\d{7}\b` |
| Japan DL | `\b\d{12}\b` |
| Japan Juminhyo Code | `\b\d{11}\b` |
| Japan Health Insurance | `\b\d{8}\b` |
| Japan Residence Card | `\b[A-Z]{2}\d{8}[A-Z]{2}\b` |

## Asia-Pacific - Malaysia (2 patterns)

| Pattern Name | Regex |
|---|---|
| Malaysia MyKad | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?\d{2}[-\s]?\d{4}\b` |
| Malaysia Passport | `\b[A-Z]\d{8}\b` |

## Asia-Pacific - New Zealand (4 patterns)

| Pattern Name | Regex |
|---|---|
| New Zealand IRD | `\b\d{8,9}\b` |
| New Zealand Passport | `\b[A-Z]{2}\d{6}\b` |
| New Zealand NHI | `\b[A-HJ-NP-Z]{3}\d{4}\b` |
| New Zealand DL | `\b[A-Z]{2}\d{6}\b` |

## Asia-Pacific - Pakistan (3 patterns)

| Pattern Name | Regex |
|---|---|
| Pakistan CNIC | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` |
| Pakistan NICOP | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` |
| Pakistan Passport | `\b[A-Z]{2}\d{7}\b` |

## Asia-Pacific - Philippines (6 patterns)

| Pattern Name | Regex |
|---|---|
| Philippines PhilSys | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` |
| Philippines TIN | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}(?:[-.\s/\\_\u2013\u2014\u00a0]?\d{3})?\b` |
| Philippines SSS | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{7}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Philippines PhilHealth | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{9}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Philippines Passport | `\b[A-Z]{1,2}\d{6,7}[A-Z]?\b` |
| Philippines UMID | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{7}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |

## Asia-Pacific - Singapore (4 patterns)

| Pattern Name | Regex |
|---|---|
| Singapore NRIC | `\b[ST]\d{7}[A-Z]\b` |
| Singapore FIN | `\b[FGM]\d{7}[A-Z]\b` |
| Singapore Passport | `\b[A-Z]\d{7}[A-Z]\b` |
| Singapore DL | `\b[STFGM]\d{7}[A-Z]\b` |

## Asia-Pacific - South Korea (3 patterns)

| Pattern Name | Regex |
|---|---|
| South Korea RRN | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?[1-8]\d{6}\b` |
| South Korea Passport | `\b[MSROD]\d{8}\b` |
| South Korea DL | `\b\d{2}[-\s]?\d{2}[-\s]?\d{6}[-\s]?\d{2}\b` |

## Asia-Pacific - Sri Lanka (3 patterns)

| Pattern Name | Regex |
|---|---|
| Sri Lanka NIC Old | `\b\d{9}[VXvx]\b` |
| Sri Lanka NIC New | `\b\d{12}\b` |
| Sri Lanka Passport | `\b[A-Z]\d{7}\b` |

## Asia-Pacific - Thailand (4 patterns)

| Pattern Name | Regex |
|---|---|
| Thailand National ID | `\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b` |
| Thailand Passport | `\b[A-Z]{2}\d{7}\b` |
| Thailand DL | `\b\d{13}\b` |
| Thailand Tax ID | `\b\d{13}\b` |

## Asia-Pacific - Vietnam (3 patterns)

| Pattern Name | Regex |
|---|---|
| Vietnam CCCD | `\b\d{12}\b` |
| Vietnam Passport | `\b[A-Z]\d{8}\b` |
| Vietnam Tax Code | `\b\d{10}(?:-\d{3})?\b` |

## Authentication Tokens (1 patterns)

| Pattern Name | Regex |
|---|---|
| Session ID | `\b[0-9a-f]{32,64}\b` |

## Banking Authentication (3 patterns)

| Pattern Name | Regex |
|---|---|
| PIN Block | `\b[0-9A-F]{16}\b` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` |
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` |

## Banking and Financial (5 patterns)

| Pattern Name | Regex |
|---|---|
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` |
| ABA Routing Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{7}\b` |
| US Bank Account Number | `\b\d{8,17}\b` |
| Canada Transit Number | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |

## Biometric Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| Biometric Hash | `\b[0-9a-f]{64}\b` |
| Biometric Template ID | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` |

## Card Expiration Dates (1 patterns)

| Pattern Name | Regex |
|---|---|
| Card Expiry | `\b(?:0[1-9]\|1[0-2])\s?/\s?(?:\d{2}\|\d{4})\b` |

## Card Track Data (2 patterns)

| Pattern Name | Regex |
|---|---|
| Track 1 Data | `%B\d{13,19}\^[A-Z\s/]+\^\d{4}\d*` |
| Track 2 Data | `;\d{13,19}=\d{4}\d*\?` |

## Check and MICR Data (3 patterns)

| Pattern Name | Regex |
|---|---|
| MICR Line | `[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}` |
| Check Number | `\b\d{4,6}\b` |
| Cashier Check Number | `\b\d{8,15}\b` |

## Cloud Provider Secrets (3 patterns)

| Pattern Name | Regex |
|---|---|
| AWS Access Key | `\bAKIA[0-9A-Z]{16}\b` |
| AWS Secret Key | `(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])` |
| Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` |

## Code Platform Secrets (5 patterns)

| Pattern Name | Regex |
|---|---|
| GitHub Token (Classic) | `\bghp_[A-Za-z0-9]{36}\b` |
| GitHub Token (Fine-Grained) | `\bgithub_pat_[A-Za-z0-9_]{22,82}\b` |
| GitHub OAuth Token | `\bgho_[A-Za-z0-9]{36}\b` |
| NPM Token | `\bnpm_[A-Za-z0-9]{36}\b` |
| PyPI Token | `\bpypi-[A-Za-z0-9_\-]{16,}\b` |

## Contact Information (5 patterns)

| Pattern Name | Regex |
|---|---|
| Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| IPv4 Address | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` |
| IPv6 Address | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b\|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b\|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b` |
| MAC Address | `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` |

## Corporate Classification (9 patterns)

| Pattern Name | Regex |
|---|---|
| Internal Only | `\b[Ii]nternal\s+(?:[Uu]se\s+)?[Oo]nly\b` |
| Restricted | `\b(?:RESTRICTED\|[Rr]estricted\s+[Dd]ata\|[Rr]estricted\s+[Ii]nformation)\b` |
| Corporate Confidential | `\b(?:[Cc]ompany\s+[Cc]onfidential\|[Cc]orporate\s+[Cc]onfidential\|[Ss]trictly\s+[Cc]onfidential)\b` |
| Highly Confidential | `\b[Hh]ighly\s+[Cc]onfidential\b` |
| Do Not Distribute | `\b(?:[Nn]ot\s+[Ff]or\s+[Dd]istribution\|[Dd]o\s+[Nn]ot\s+[Dd]istribute\|[Nn]o\s+[Dd]istribution)\b` |
| Need to Know | `\b[Nn]eed\s+[Tt]o\s+[Kk]now(?:\s+[Bb]asis)?\b` |
| Eyes Only | `\b[Ee]yes\s+[Oo]nly\b` |
| Proprietary | `\b(?:[Pp]roprietary\s+(?:[Ii]nformation\|[Dd]ata\|[Mm]aterial)\|[Tt]rade\s+[Ss]ecret)\b` |
| Embargoed | `\b[Ee]mbargoed?\s+(?:[Ii]nformation\|[Dd]ata\|[Uu]ntil\|[Mm]aterial)\b` |

## Credit Card Numbers (7 patterns)

| Pattern Name | Regex |
|---|---|
| Visa | `\b4\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| MasterCard | `\b(?:5[1-5]\d{2}\|2(?:2[2-9]\d\|2[3-9]\d\|[3-6]\d{2}\|7[01]\d\|720))[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| Amex | `\b3[47]\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{5}\b` |
| Discover | `\b6(?:011\|5\d{2}\|4[4-9]\d)[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| JCB | `\b35(?:2[89]\|[3-8]\d)[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| Diners Club | `\b3(?:0[0-5]\|[68]\d)\d[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| UnionPay | `\b62\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}(?:[-.\s/\\_\u2013\u2014\u00a0]?\d{1,3})?\b` |

## Cryptocurrency (7 patterns)

| Pattern Name | Regex |
|---|---|
| Bitcoin Address (Legacy) | `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` |
| Bitcoin Address (Bech32) | `\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b` |
| Ethereum Address | `\b0x[0-9a-fA-F]{40}\b` |
| Litecoin Address | `\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b` |
| Bitcoin Cash Address | `\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b` |
| Monero Address | `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` |
| Ripple Address | `\br[1-9A-HJ-NP-Za-km-z]{24,34}\b` |

## Customer Financial Data (4 patterns)

| Pattern Name | Regex |
|---|---|
| Account Balance | `(?<!\w)[\$\u20ac\u00a3\u00a5]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Balance with Currency Code | `\b(?:USD\|EUR\|GBP\|JPY\|CAD\|AUD\|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Income Amount | `(?<!\w)[\$\u20ac\u00a3\u00a5]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| DTI Ratio | `\b\d{1,2}\.\d{1,2}%\b` |

## Data Classification Labels (8 patterns)

| Pattern Name | Regex |
|---|---|
| Top Secret | `\b(?:TOP\s+SECRET\|TS//SCI\|TS//SI)\b` |
| Secret Classification | `\b(?:SECRET(?://NOFORN)?\|CLASSIFIED\s+SECRET)\b` |
| Confidential Classification | `\bCLASSIFIED\s+CONFIDENTIAL\b` |
| FOUO | `\b(?:FOUO\|[Ff]or\s+[Oo]fficial\s+[Uu]se\s+[Oo]nly)\b` |
| CUI | `\b(?:CUI\|[Cc]ontrolled\s+[Uu]nclassified\s+[Ii]nformation)\b` |
| SBU | `\b(?:SBU\|[Ss]ensitive\s+[Bb]ut\s+[Uu]nclassified)\b` |
| LES | `\b(?:LES\|[Ll]aw\s+[Ee]nforcement\s+[Ss]ensitive)\b` |
| NOFORN | `\bNOFORN\b` |

## Dates (3 patterns)

| Pattern Name | Regex |
|---|---|
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` |
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` |

## Device Identifiers (5 patterns)

| Pattern Name | Regex |
|---|---|
| IMEI | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| IMEISV | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| MEID | `\b[0-9A-F]{2}[-.\s/\\_\u2013\u2014\u00a0]?[0-9A-F]{6}[-.\s/\\_\u2013\u2014\u00a0]?[0-9A-F]{6}\b` |
| ICCID | `\b89\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{3,4}\d?\b` |
| IDFA/IDFV | `\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b` |

## Education Identifiers (1 patterns)

| Pattern Name | Regex |
|---|---|
| EDU Email | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b` |

## Employment Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| Employee ID | `\b[A-Z]{1,3}\d{4,8}\b` |
| Work Permit Number | `\b[A-Z]{2,3}\d{7,10}\b` |

## Europe - Austria (5 patterns)

| Pattern Name | Regex |
|---|---|
| Austria SVN | `\b\d{4}[-\s]?\d{6}\b` |
| Austria Passport | `\b[A-Z]\d{7}\b` |
| Austria ID Card | `\b\d{8}\b` |
| Austria DL | `\b\d{8}\b` |
| Austria Tax Number | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Europe - Belgium (4 patterns)

| Pattern Name | Regex |
|---|---|
| Belgium NRN | `\b\d{2}[.\s]?\d{2}[.\s]?\d{2}[-.\s]?\d{3}[.\s]?\d{2}\b` |
| Belgium Passport | `\b[A-Z]{2}\d{6}\b` |
| Belgium DL | `\b\d{10}\b` |
| Belgium VAT | `\bBE\s?0?\d{3}\.?\d{3}\.?\d{3}\b` |

## Europe - Bulgaria (4 patterns)

| Pattern Name | Regex |
|---|---|
| Bulgaria EGN | `\b\d{10}\b` |
| Bulgaria LNC | `\b\d{10}\b` |
| Bulgaria ID Card | `\b\d{9}\b` |
| Bulgaria Passport | `\b\d{9}\b` |

## Europe - Croatia (4 patterns)

| Pattern Name | Regex |
|---|---|
| Croatia OIB | `\b\d{11}\b` |
| Croatia Passport | `\b\d{9}\b` |
| Croatia ID Card | `\b\d{9}\b` |
| Croatia DL | `\b\d{8,9}\b` |

## Europe - Cyprus (3 patterns)

| Pattern Name | Regex |
|---|---|
| Cyprus ID Card | `\b\d{7,8}\b` |
| Cyprus Passport | `\b[A-Z]\d{7,8}\b` |
| Cyprus TIN | `\b\d{8}[A-Z]\b` |

## Europe - Czech Republic (4 patterns)

| Pattern Name | Regex |
|---|---|
| Czech Birth Number | `\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b` |
| Czech Passport | `\b\d{8}\b` |
| Czech DL | `\b[A-Z]{2}\d{6}\b` |
| Czech ICO | `\b\d{8}\b` |

## Europe - Denmark (3 patterns)

| Pattern Name | Regex |
|---|---|
| Denmark CPR | `\b[0-3]\d[01]\d{3}[-]?\d{4}\b` |
| Denmark Passport | `\b\d{9}\b` |
| Denmark DL | `\b\d{8}\b` |

## Europe - EU (2 patterns)

| Pattern Name | Regex |
|---|---|
| EU ETD | `\b[A-Z]{3}\d{6}\b` |
| EU VAT Generic | `\b(?:AT\|BE\|BG\|CY\|CZ\|DE\|DK\|EE\|EL\|ES\|FI\|FR\|HR\|HU\|IE\|IT\|LT\|LU\|LV\|MT\|NL\|PL\|PT\|RO\|SE\|SI\|SK)[A-Z0-9]{8,12}\b` |

## Europe - Estonia (3 patterns)

| Pattern Name | Regex |
|---|---|
| Estonia Isikukood | `\b[1-6]\d{2}[01]\d[0-3]\d{5}\b` |
| Estonia Passport | `\b[A-Z]{2}\d{7}\b` |
| Estonia DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Finland (3 patterns)

| Pattern Name | Regex |
|---|---|
| Finland HETU | `\b[0-3]\d[01]\d{3}[-+A]\d{3}[A-Z0-9]\b` |
| Finland Passport | `\b[A-Z]{2}\d{7}\b` |
| Finland DL | `\b\d{8,10}\b` |

## Europe - France (5 patterns)

| Pattern Name | Regex |
|---|---|
| France NIR | `\b[12]\d{2}(?:0[1-9]\|1[0-2])(?:\d{2}\|2[AB])\d{3}\d{3}\d{2}\b` |
| France Passport | `\b\d{2}[A-Z]{2}\d{5}\b` |
| France CNI | `\b[A-Z0-9]{12}\b` |
| France DL | `\b\d{2}[A-Z]{2}\d{5}\b` |
| France IBAN | `\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b` |

## Europe - Germany (6 patterns)

| Pattern Name | Regex |
|---|---|
| Germany ID | `\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b` |
| Germany Passport | `\bC[A-Z0-9]{8}\b` |
| Germany Tax ID | `\b\d{11}\b` |
| Germany Social Insurance | `\b\d{2}[0-3]\d[01]\d{2}\d[A-Z]\d{3}\b` |
| Germany DL | `\b[A-Z0-9]{11}\b` |
| Germany IBAN | `\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` |

## Europe - Greece (5 patterns)

| Pattern Name | Regex |
|---|---|
| Greece AFM | `\b\d{9}\b` |
| Greece AMKA | `\b[0-3]\d[01]\d{3}\d{5}\b` |
| Greece ID Card | `\b[A-Z]{2}\d{6}\b` |
| Greece Passport | `\b[A-Z]{2}\d{7}\b` |
| Greece DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Hungary (5 patterns)

| Pattern Name | Regex |
|---|---|
| Hungary Personal ID | `\b\d[-]?\d{6}[-]?\d{4}\b` |
| Hungary TAJ | `\b\d{3}\s?\d{3}\s?\d{3}\b` |
| Hungary Tax Number | `\b\d{10}\b` |
| Hungary Passport | `\b[A-Z]{2}\d{6,7}\b` |
| Hungary DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Iceland (2 patterns)

| Pattern Name | Regex |
|---|---|
| Iceland Kennitala | `\b[0-3]\d[01]\d{3}[-]?\d{4}\b` |
| Iceland Passport | `\b[A-Z]\d{7}\b` |

## Europe - Ireland (4 patterns)

| Pattern Name | Regex |
|---|---|
| Ireland PPS | `\b\d{7}[A-Z]{1,2}\b` |
| Ireland Passport | `\b[A-Z]{2}\d{7}\b` |
| Ireland DL | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Ireland Eircode | `\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b` |

## Europe - Italy (5 patterns)

| Pattern Name | Regex |
|---|---|
| Italy Codice Fiscale | `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b` |
| Italy Passport | `\b[A-Z]{2}\d{7}\b` |
| Italy DL | `\b[A-Z]{2}\d{7}[A-Z]\b` |
| Italy SSN | `\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b` |
| Italy Partita IVA | `\b\d{11}\b` |

## Europe - Latvia (3 patterns)

| Pattern Name | Regex |
|---|---|
| Latvia Personas Kods | `\b[0-3]\d[01]\d{3}[-]?\d{5}\b` |
| Latvia Passport | `\b[A-Z]{2}\d{7}\b` |
| Latvia DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Liechtenstein (2 patterns)

| Pattern Name | Regex |
|---|---|
| Liechtenstein PIN | `\b\d{12}\b` |
| Liechtenstein Passport | `\b[A-Z]\d{5}\b` |

## Europe - Lithuania (3 patterns)

| Pattern Name | Regex |
|---|---|
| Lithuania Asmens Kodas | `\b[3-6]\d{2}[01]\d[0-3]\d{5}\b` |
| Lithuania Passport | `\b\d{8}\b` |
| Lithuania DL | `\b\d{8}\b` |

## Europe - Luxembourg (3 patterns)

| Pattern Name | Regex |
|---|---|
| Luxembourg NIN | `\b\d{4}[01]\d[0-3]\d\d{5}\b` |
| Luxembourg Passport | `\b[A-Z]{2}\d{6}\b` |
| Luxembourg DL | `\b\d{6}\b` |

## Europe - Malta (3 patterns)

| Pattern Name | Regex |
|---|---|
| Malta ID Card | `\b\d{3,7}[A-Z]\b` |
| Malta Passport | `\b\d{7}\b` |
| Malta TIN | `\b\d{3,9}[A-Z]?\b` |

## Europe - Netherlands (4 patterns)

| Pattern Name | Regex |
|---|---|
| Netherlands BSN | `\b\d{9}\b` |
| Netherlands Passport | `\b[A-Z]{2}[A-Z0-9]{6}\d\b` |
| Netherlands DL | `\b\d{10}\b` |
| Netherlands IBAN | `\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` |

## Europe - Norway (4 patterns)

| Pattern Name | Regex |
|---|---|
| Norway FNR | `\b[0-3]\d[01]\d{3}\d{5}\b` |
| Norway D-Number | `\b[4-7]\d[01]\d{3}\d{5}\b` |
| Norway Passport | `\b\d{8}\b` |
| Norway DL | `\b\d{11}\b` |

## Europe - Poland (6 patterns)

| Pattern Name | Regex |
|---|---|
| Poland PESEL | `\b\d{11}\b` |
| Poland NIP | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Poland REGON | `\b\d{9}(?:\d{5})?\b` |
| Poland ID Card | `\b[A-Z]{3}\d{6}\b` |
| Poland Passport | `\b[A-Z]{2}\d{7}\b` |
| Poland DL | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Europe - Portugal (4 patterns)

| Pattern Name | Regex |
|---|---|
| Portugal NIF | `\b[12356789]\d{8}\b` |
| Portugal CC | `\b\d{8}\s?\d\s?[A-Z]{2}\d\b` |
| Portugal Passport | `\b[A-Z]{1,2}\d{6}\b` |
| Portugal NISS | `\b\d{11}\b` |

## Europe - Romania (4 patterns)

| Pattern Name | Regex |
|---|---|
| Romania CNP | `\b[1-8]\d{12}\b` |
| Romania CIF | `\b\d{2,10}\b` |
| Romania Passport | `\b\d{8,9}\b` |
| Romania DL | `\b\d{9}\b` |

## Europe - Slovakia (3 patterns)

| Pattern Name | Regex |
|---|---|
| Slovakia Birth Number | `\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b` |
| Slovakia Passport | `\b[A-Z]{2}\d{6}\b` |
| Slovakia DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Slovenia (4 patterns)

| Pattern Name | Regex |
|---|---|
| Slovenia EMSO | `\b[0-3]\d[01]\d{3}\d{6}\d\b` |
| Slovenia Tax Number | `\b\d{8}\b` |
| Slovenia Passport | `\b[A-Z]{2}\d{7}\b` |
| Slovenia DL | `\b\d{8}\b` |

## Europe - Spain (5 patterns)

| Pattern Name | Regex |
|---|---|
| Spain DNI | `\b\d{8}[A-Z]\b` |
| Spain NIE | `\b[XYZ]\d{7}[A-Z]\b` |
| Spain Passport | `\b[A-Z]{3}\d{6}\b` |
| Spain NSS | `\b\d{2}[-/]?\d{8}[-/]?\d{2}\b` |
| Spain DL | `\b\d{8}[A-Z]\b` |

## Europe - Sweden (4 patterns)

| Pattern Name | Regex |
|---|---|
| Sweden PIN | `\b\d{6}[-+]?\d{4}\b` |
| Sweden Passport | `\b\d{8}\b` |
| Sweden DL | `\b\d{6}[-]?\d{4}\b` |
| Sweden Organisation Number | `\b\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Europe - Switzerland (4 patterns)

| Pattern Name | Regex |
|---|---|
| Switzerland AHV | `\b756[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Switzerland Passport | `\b[A-Z]\d{7}\b` |
| Switzerland DL | `\b\d{6,7}\b` |
| Switzerland UID | `\bCHE[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |

## Europe - Turkey (4 patterns)

| Pattern Name | Regex |
|---|---|
| Turkey TC Kimlik | `\b[1-9]\d{10}\b` |
| Turkey Passport | `\b[A-Z]\d{7}\b` |
| Turkey DL | `\b\d{6}\b` |
| Turkey Tax ID | `\b\d{10}\b` |

## Europe - United Kingdom (7 patterns)

| Pattern Name | Regex |
|---|---|
| UK NIN | `\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b` |
| UK UTR | `\b\d{5}\s?\d{5}\b` |
| UK Passport | `\b\d{9}\b` |
| UK Sort Code | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| British NHS | `\b\d{3}\s?\d{3}\s?\d{4}\b` |
| UK Phone Number | `(?:\+44[-.\s]?\|0)(?:\d[-.\s]?){9,10}(?!\d)` |
| UK DL | `\b[A-Z]{5}\d{6}[A-Z0-9]{5}\b` |

## Financial Regulatory Labels (7 patterns)

| Pattern Name | Regex |
|---|---|
| MNPI | `\b(?:MNPI\|[Mm]aterial\s+[Nn]on-?[Pp]ublic\s+[Ii]nformation)\b` |
| Inside Information | `\b[Ii]nside(?:r)?\s+[Ii]nformation\b` |
| Pre-Decisional | `\b[Pp]re-?[Dd]ecisional\b` |
| Draft Not for Circulation | `\b[Dd]raft\s*[-–—]\s*[Nn]ot\s+[Ff]or\s+[Cc]irculation\b` |
| Market Sensitive | `\b[Mm]arket\s+[Ss]ensitive\b` |
| Information Barrier | `\b(?:[Ii]nformation\s+[Bb]arrier\|[Cc]hinese\s+[Ww]all)\b` |
| Investment Restricted | `\b[Rr]estricted\s+[Ll]ist\b` |

## Generic Secrets (6 patterns)

| Pattern Name | Regex |
|---|---|
| Bearer Token | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` |
| JWT Token | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` |
| Private Key | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` |
| Generic API Key | `(?:api[_-]?key\|apikey\|api[_-]?secret\|api[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9\-._~+/]{16,}["\']?` |
| Generic Secret Assignment | `(?:password\|passwd\|pwd\|secret\|token\|credential)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?` |
| Database Connection String | `(?:mongodb(?:\+srv)?\|mysql\|postgres(?:ql)?\|redis\|mssql)://[^:\s]+:[^@\s]+@[^\s]+` |

## Geolocation (3 patterns)

| Pattern Name | Regex |
|---|---|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` |
| GPS DMS | `\d{1,3}[°]\d{1,2}[\'′]\d{1,2}(?:\.\d+)?[\"″]?\s?[NSEW]` |
| Geohash | `\b(?=[0-9bcdefghjkmnpqrstuvwxyz]*\d)[0-9bcdefghjkmnpqrstuvwxyz]{7,12}\b` |

## Insurance Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` |
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |

## Internal Banking References (2 patterns)

| Pattern Name | Regex |
|---|---|
| Internal Account Ref | `\b[A-Z]{2,4}\d{8,14}\b` |
| Teller ID | `\b[A-Z]{1,3}\d{4,8}\b` |

## Latin America - Argentina (3 patterns)

| Pattern Name | Regex |
|---|---|
| Argentina DNI | `\b\d{7,8}\b` |
| Argentina CUIL/CUIT | `\b(?:20\|2[3-7]\|30\|33)[-.\s/\\_\u2013\u2014\u00a0]?\d{8}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Argentina Passport | `\b[A-Z]{3}\d{6}\b` |

## Latin America - Brazil (6 patterns)

| Pattern Name | Regex |
|---|---|
| Brazil CPF | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Brazil CNPJ | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Brazil RG | `\b\d{1,2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?[\dXx]\b` |
| Brazil CNH | `\b\d{11}\b` |
| Brazil SUS Card | `\b[1-2]\d{10}00[01]\d\b\|\b[789]\d{14}\b` |
| Brazil Passport | `\b[A-Z]{2}\d{6}\b` |

## Latin America - Chile (2 patterns)

| Pattern Name | Regex |
|---|---|
| Chile RUN/RUT | `\b\d{1,2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?[\dkK]\b` |
| Chile Passport | `\b[A-Z]?\d{7,8}\b` |

## Latin America - Colombia (4 patterns)

| Pattern Name | Regex |
|---|---|
| Colombia Cedula | `\b\d{6,10}\b` |
| Colombia NIT | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Colombia NUIP | `\b\d{6,10}\b` |
| Colombia Passport | `\b[A-Z]{2}\d{6,7}\b` |

## Latin America - Costa Rica (3 patterns)

| Pattern Name | Regex |
|---|---|
| Costa Rica Cedula | `\b\d{1}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| Costa Rica DIMEX | `\b\d{11,12}\b` |
| Costa Rica Passport | `\b[A-Z]\d{8}\b` |

## Latin America - Ecuador (3 patterns)

| Pattern Name | Regex |
|---|---|
| Ecuador Cedula | `\b\d{10}\b` |
| Ecuador RUC | `\b\d{13}\b` |
| Ecuador Passport | `\b[A-Z]\d{7,8}\b` |

## Latin America - Paraguay (3 patterns)

| Pattern Name | Regex |
|---|---|
| Paraguay Cedula | `\b\d{5,7}\b` |
| Paraguay RUC | `\b\d{6,8}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Paraguay Passport | `\b[A-Z]\d{6,8}\b` |

## Latin America - Peru (4 patterns)

| Pattern Name | Regex |
|---|---|
| Peru DNI | `\b\d{8}\b` |
| Peru RUC | `\b(?:10\|15\|17\|20)\d{9}\b` |
| Peru Carnet Extranjeria | `\b\d{9,12}\b` |
| Peru Passport | `\b[A-Z]{2}\d{6,7}\b` |

## Latin America - Uruguay (3 patterns)

| Pattern Name | Regex |
|---|---|
| Uruguay Cedula | `\b\d{1}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Uruguay RUT | `\b\d{12}\b` |
| Uruguay Passport | `\b[A-Z]\d{6,8}\b` |

## Latin America - Venezuela (3 patterns)

| Pattern Name | Regex |
|---|---|
| Venezuela Cedula | `\b[VvEe][-.\s/\\_\u2013\u2014\u00a0]?\d{6,9}\b` |
| Venezuela RIF | `\b[VEJGvejg][-.\s/\\_\u2013\u2014\u00a0]?\d{8}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Venezuela Passport | `\b[A-Z]\d{7,8}\b` |

## Legal Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| US Federal Case Number | `\b\d:\d{2}-[a-z]{2}-\d{4,5}\b` |
| Court Docket Number | `\b\d{2,4}-?[A-Z]{1,4}-?\d{4,8}\b` |

## Loan and Mortgage Data (4 patterns)

| Pattern Name | Regex |
|---|---|
| Loan Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}\b` |
| MERS MIN | `\b\d{18}\b` |
| Universal Loan Identifier | `\b[A-Z0-9]{4}00[A-Z0-9]{17,39}\b` |
| LTV Ratio | `\b\d{1,3}\.\d{1,2}%\b` |

## Medical Identifiers (4 patterns)

| Pattern Name | Regex |
|---|---|
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` |
| DEA Number | `\b[A-Z]{2}\d{7}\b` |
| ICD-10 Code | `\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b` |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` |

## Messaging Service Secrets (6 patterns)

| Pattern Name | Regex |
|---|---|
| Slack Bot Token | `\bxoxb-[0-9A-Za-z\-]+\b` |
| Slack User Token | `\bxoxp-[0-9A-Za-z\-]+\b` |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+` |
| SendGrid API Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` |
| Twilio API Key | `\bSK[0-9a-f]{32}\b` |
| Mailgun API Key | `\bkey-[0-9a-zA-Z]{32}\b` |

## Middle East - Bahrain (2 patterns)

| Pattern Name | Regex |
|---|---|
| Bahrain CPR | `\b\d{9}\b` |
| Bahrain Passport | `\b\d{7,9}\b` |

## Middle East - Iran (2 patterns)

| Pattern Name | Regex |
|---|---|
| Iran Melli Code | `\b\d{10}\b` |
| Iran Passport | `\b[A-Z]\d{8}\b` |

## Middle East - Iraq (2 patterns)

| Pattern Name | Regex |
|---|---|
| Iraq National ID | `\b\d{12}\b` |
| Iraq Passport | `\b[A-HJ-NP-Z0-9]{9}\b` |

## Middle East - Israel (2 patterns)

| Pattern Name | Regex |
|---|---|
| Israel Teudat Zehut | `\b\d{9}\b` |
| Israel Passport | `\b\d{7,8}\b` |

## Middle East - Jordan (2 patterns)

| Pattern Name | Regex |
|---|---|
| Jordan National ID | `\b\d{10}\b` |
| Jordan Passport | `\b[A-Z]\d{7}\b` |

## Middle East - Kuwait (2 patterns)

| Pattern Name | Regex |
|---|---|
| Kuwait Civil ID | `\b[1-3]\d{11}\b` |
| Kuwait Passport | `\b[A-Z]?\d{7,9}\b` |

## Middle East - Lebanon (2 patterns)

| Pattern Name | Regex |
|---|---|
| Lebanon ID | `\b\d{7,12}\b` |
| Lebanon Passport | `\b(?:RL\|LR)\d{6,7}\b` |

## Middle East - Qatar (2 patterns)

| Pattern Name | Regex |
|---|---|
| Qatar QID | `\b[23]\d{10}\b` |
| Qatar Passport | `\b[A-Z]\d{7}\b` |

## Middle East - Saudi Arabia (2 patterns)

| Pattern Name | Regex |
|---|---|
| Saudi Arabia National ID | `\b[12]\d{9}\b` |
| Saudi Arabia Passport | `\b[A-Z]\d{7,8}\b` |

## Middle East - UAE (3 patterns)

| Pattern Name | Regex |
|---|---|
| UAE Emirates ID | `\b784[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{7}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| UAE Visa Number | `\b[1-7]01/?(?:19\|20)\d{2}/?\d{7}\b` |
| UAE Passport | `\b[A-Z]?\d{7,9}\b` |

## North America - Canada (29 patterns)

| Pattern Name | Regex |
|---|---|
| Canada SIN | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Canada BN | `\b\d{9}[A-Z]{2}\d{4}\b` |
| Canada Passport | `\b[A-Z]{2}\d{6}\b` |
| Canada Bank Code | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Canada PR Card | `\b[A-Z]{2}\d{7,10}\b` |
| Canada NEXUS | `\b\d{9}\b` |
| Ontario DL | `\b[A-Z]\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{5}\b` |
| Ontario HC | `\b\d{10}(?:\s?[A-Z]{2})?\b` |
| Quebec DL | `\b[A-Z]\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Quebec HC | `\b[A-Z]{4}\d{8}\b` |
| British Columbia DL | `\b\d{7}\b` |
| BC HC | `\b9\d{9}\b` |
| Alberta DL | `\b\d{6,9}\b` |
| Alberta HC | `\b\d{9}\b` |
| Saskatchewan DL | `\b\d{8}\b` |
| Saskatchewan HC | `\b\d{9}\b` |
| Manitoba DL | `\b[A-Z]{6}\d{6}\b` |
| Manitoba HC | `\b\d{9}\b` |
| New Brunswick DL | `\b\d{5,7}\b` |
| New Brunswick HC | `\b\d{9}\b` |
| Nova Scotia DL | `\b[A-Z]{5}\d{9}\b` |
| Nova Scotia HC | `\b\d{10}\b` |
| PEI DL | `\b\d{1,6}\b` |
| PEI HC | `\b\d{8}\b` |
| Newfoundland DL | `\b[A-Z]\d{9,10}\b` |
| Newfoundland HC | `\b\d{12}\b` |
| Yukon DL | `\b\d{6}\b` |
| NWT DL | `\b\d{6}\b` |
| Nunavut DL | `\b\d{6}\b` |

## North America - Mexico (7 patterns)

| Pattern Name | Regex |
|---|---|
| Mexico CURP | `\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b` |
| Mexico RFC | `\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b` |
| Mexico Clave Elector | `\b[A-Z]{6}\d{8}[HM]\d{3}\b` |
| Mexico INE CIC | `\b\d{9}\b` |
| Mexico INE OCR | `\b\d{13}\b` |
| Mexico Passport | `\b[A-Z]\d{8}\b` |
| Mexico NSS | `\b\d{11}\b` |

## North America - US Generic DL (1 patterns)

| Pattern Name | Regex |
|---|---|
| Generic US DL | `\b[A-Z]{1,2}\d{4,14}\b` |

## North America - United States (63 patterns)

| Pattern Name | Regex |
|---|---|
| USA SSN | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| USA ITIN | `\b9\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| USA EIN | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{7}\b` |
| USA Passport | `\b\d{9}\b` |
| USA Passport Card | `\bC\d{8}\b` |
| USA Routing Number | `\b\d{9}\b` |
| US DEA Number | `\b[A-Z]{2}\d{7}\b` |
| US NPI | `\b[12]\d{9}\b` |
| US MBI | `\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s/\\_\u2013\u2014\u00a0]?[A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s/\\_\u2013\u2014\u00a0]?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b` |
| US DoD ID | `\b\d{10}\b` |
| US Known Traveler Number | `\b\d{9}\b` |
| US Phone Number | `(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)` |
| Alabama DL | `\b\d{7}\b` |
| Alaska DL | `\b\d{7}\b` |
| Arizona DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` |
| Arkansas DL | `\b\d{8,9}\b` |
| California DL | `\b[A-Z]\d{7}\b` |
| Colorado DL | `\b(?:\d{9}\|[A-Z]\d{3,6})\b` |
| Connecticut DL | `\b\d{9}\b` |
| Delaware DL | `\b\d{1,7}\b` |
| DC DL | `\b(?:\d{7}\|\d{9})\b` |
| Florida DL | `\b[A-Z]\d{12}\b` |
| Georgia DL | `\b\d{7,9}\b` |
| Hawaii DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` |
| Idaho DL | `\b[A-Z]{2}\d{6}[A-Z]\b` |
| Illinois DL | `\b[A-Z]\d{11}\b` |
| Indiana DL | `\b(?:\d{10}\|[A-Z]\d{9})\b` |
| Iowa DL | `\b\d{3}[A-Z]{2}\d{4}\b` |
| Kansas DL | `\b(?:[A-Z]\d{8}\|[A-Z]{2}\d{7}\|\d{9})\b` |
| Kentucky DL | `\b[A-Z]\d{8}\b` |
| Louisiana DL | `\b\d{9}\b` |
| Maine DL | `\b\d{7}[A-Z]?\b` |
| Maryland DL | `\b[A-Z]\d{12}\b` |
| Massachusetts DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` |
| Michigan DL | `\b[A-Z]\d{12}\b` |
| Minnesota DL | `\b[A-Z]\d{12}\b` |
| Mississippi DL | `\b\d{9}\b` |
| Missouri DL | `\b(?:[A-Z]\d{5,9}\|\d{9})\b` |
| Montana DL | `\b(?:\d{13}\|\d{9})\b` |
| Nebraska DL | `\b[A-Z]\d{8}\b` |
| Nevada DL | `\b(?:\d{10}\|\d{12})\b` |
| New Hampshire DL | `\b\d{2}[A-Z]{3}\d{5}\b` |
| New Jersey DL | `\b[A-Z]\d{14}\b` |
| New Mexico DL | `\b\d{9}\b` |
| New York DL | `\b\d{9}\b` |
| North Carolina DL | `\b\d{1,12}\b` |
| North Dakota DL | `\b(?:[A-Z]{3}\d{6}\|\d{9})\b` |
| Ohio DL | `\b[A-Z]{2}\d{6}\b` |
| Oklahoma DL | `\b(?:[A-Z]\d{9}\|\d{9})\b` |
| Oregon DL | `\b\d{1,9}\b` |
| Pennsylvania DL | `\b\d{8}\b` |
| Rhode Island DL | `\b(?:\d{7}\|[A-Z]\d{6})\b` |
| South Carolina DL | `\b\d{5,11}\b` |
| South Dakota DL | `\b(?:\d{8,10}\|\d{12})\b` |
| Tennessee DL | `\b\d{7,9}\b` |
| Texas DL | `\b\d{8}\b` |
| Utah DL | `\b\d{4,10}\b` |
| Vermont DL | `\b(?:\d{8}\|\d{7}[A-Z])\b` |
| Virginia DL | `\b(?:[A-Z]\d{8,11}\|\d{9})\b` |
| Washington DL | `\b[A-Z]{1,7}[A-Z0-9*]{5,11}\b` |
| West Virginia DL | `\b(?:\d{7}\|[A-Z]\d{6})\b` |
| Wisconsin DL | `\b[A-Z]\d{13}\b` |
| Wyoming DL | `\b\d{9,10}\b` |

## PCI Sensitive Data (1 patterns)

| Pattern Name | Regex |
|---|---|
| Cardholder Name Pattern | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` |

## Payment Service Secrets (2 patterns)

| Pattern Name | Regex |
|---|---|
| Stripe Secret Key | `\bsk_(?:live\|test)_[A-Za-z0-9]{24,}\b` |
| Stripe Publishable Key | `\bpk_(?:live\|test)_[A-Za-z0-9]{24,}\b` |

## Personal Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender)\b` |

## Postal Codes (5 patterns)

| Pattern Name | Regex |
|---|---|
| US ZIP+4 Code | `\b\d{5}-\d{4}\b` |
| UK Postcode | `\b[A-Z]{1,2}\d[A-Z0-9]?\s?\d[A-Z]{2}\b` |
| Canada Postal Code | `\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b` |
| Japan Postal Code | `\b\d{3}-\d{4}\b` |
| Brazil CEP | `\b\d{5}-\d{3}\b` |

## Primary Account Numbers (2 patterns)

| Pattern Name | Regex |
|---|---|
| PAN | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{1,7}\b` |
| Masked PAN | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?[Xx*]{4}[-.\s/\\_\u2013\u2014\u00a0]?[Xx*]{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Privacy Classification (10 patterns)

| Pattern Name | Regex |
|---|---|
| PII Label | `\b(?:PII\|[Pp]ersonally\s+[Ii]dentifiable\s+[Ii]nformation)\b` |
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` |
| HIPAA | `\bHIPAA\b` |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` |
| PCI-DSS | `\b(?:PCI[-\s]?DSS\|[Cc]ardholder\s+[Dd]ata\s+[Ee]nvironment\|CDE)\b` |
| FERPA | `\b(?:FERPA\|[Ff]amily\s+[Ee]ducational\s+[Rr]ights)\b` |
| GLBA | `\b(?:GLBA\|[Gg]ramm[-\s][Ll]each[-\s][Bb]liley)\b` |
| CCPA/CPRA | `\b(?:CCPA\|CPRA\|[Cc]alifornia\s+[Cc]onsumer\s+[Pp]rivacy)\b` |
| SOX | `\b(?:SOX\|[Ss]arbanes[-\s][Oo]xley)\b` |
| NPI | `\b(?:NPI\|[Nn]on-?[Pp]ublic\s+[Pp]ersonal\s+[Ii]nformation)\b` |

## Privileged Information (7 patterns)

| Pattern Name | Regex |
|---|---|
| Attorney-Client Privilege | `\b[Aa]ttorney[-\s][Cc]lient\s+[Pp]rivileged?\b` |
| Privileged and Confidential | `\b[Pp]rivileged\s+(?:and\|&)\s+[Cc]onfidential\b` |
| Work Product | `\b[Ww]ork\s+[Pp]roduct(?:\s+[Dd]octrine)?\b` |
| Privileged Information | `\b[Pp]rivileged\s+[Ii]nformation\b` |
| Legal Privilege | `\b[Ll]egal(?:ly)?\s+[Pp]rivileged\b` |
| Litigation Hold | `\b(?:[Ll]itigation\|[Ll]egal)\s+[Hh]old\b` |
| Protected by Privilege | `\b[Pp]rotected\s+(?:by\|under)\s+[Pp]rivilege\b` |

## Property Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| Parcel Number | `\b\d{3}-\d{3}-\d{3}(?:-\d{3})?\b` |
| Title Deed Number | `\b\d{4,}-\d{4,}\b` |

## Regulatory Identifiers (6 patterns)

| Pattern Name | Regex |
|---|---|
| SAR Filing Number | `\b\d{14,20}\b` |
| CTR Number | `\b\d{14,20}\b` |
| AML Case ID | `\b[A-Z]{2,4}[-]?\d{6,12}\b` |
| OFAC SDN Entry | `\b\d{4,6}\b` |
| FinCEN Report Number | `\b\d{14}\b` |
| Compliance Case Number | `\b[A-Z]{2,5}[-]?\d{4}[-]?\d{4,8}\b` |

## Securities Identifiers (6 patterns)

| Pattern Name | Regex |
|---|---|
| CUSIP | `\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b` |
| ISIN | `\b[A-Z]{2}[0-9A-Z]{9}\d\b` |
| SEDOL | `\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b` |
| FIGI | `\bBBG[A-Z0-9]{9}\b` |
| LEI | `\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b` |
| Ticker Symbol | `(?<!\w)\$[A-Z]{1,5}\b` |

## Social Media Identifiers (2 patterns)

| Pattern Name | Regex |
|---|---|
| Twitter Handle | `(?<!\w)@[A-Za-z_]\w{0,14}\b` |
| Hashtag | `(?<!\w)#[A-Za-z]\w{2,49}\b` |

## Supervisory Information (6 patterns)

| Pattern Name | Regex |
|---|---|
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` |
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` |

## URLs with Credentials (2 patterns)

| Pattern Name | Regex |
|---|---|
| URL with Password | `https?://[^:\s]+:[^@\s]+@[^\s]+` |
| URL with Token | `https?://[^\s]*[?&](?:token\|key\|api_key\|apikey\|access_token\|secret\|password\|passwd\|pwd)=[^\s&]+` |

## Vehicle Identification (1 patterns)

| Pattern Name | Regex |
|---|---|
| VIN | `\b[A-HJ-NPR-Z0-9]{17}\b` |

## Wire Transfer Data (6 patterns)

| Pattern Name | Regex |
|---|---|
| Fedwire IMAD | `\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b` |
| CHIPS UID | `\b\d{6}[A-Z0-9]{4,10}\b` |
| Wire Reference Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{16,35}\b` |
| ACH Trace Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{13}\b` |
| ACH Batch Number | `\b\d{7}\b` |
| SEPA Reference | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{12,35}\b` |
