# PII — Regex Patterns

Regex patterns for detecting Personally Identifiable Information aligned
with GDPR, CCPA/CPRA, FERPA, GLBA, PIPEDA, LGPD, and POPIA.

> Corresponding keywords: [pii-keywords.md](pii-keywords.md)

---

## Personal Identifiers

| Pattern Name | Regex |
|---|---|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender)\b` |

## Contact Information

| Pattern Name | Regex |
|---|---|
| Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| IPv4 Address | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` |
| IPv6 Address | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b\|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b\|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b` |
| MAC Address | `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` |

## Biometric Identifiers

| Pattern Name | Regex |
|---|---|
| Biometric Hash (SHA-256) | `\b[0-9a-f]{64}\b` |
| Biometric Template ID (UUID) | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` |

## Employment & Education

| Pattern Name | Regex |
|---|---|
| Employee ID | `\b[A-Z]{1,3}\d{4,8}\b` |
| Work Permit Number | `\b[A-Z]{2,3}\d{7,10}\b` |
| EDU Email | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b` |

## Location & Address

| Pattern Name | Regex |
|---|---|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` |
| GPS DMS | `\d{1,3}[°]\d{1,2}['′]\d{1,2}(?:\.\d+)?["″]?\s?[NSEW]` |
| Geohash | `\b(?=[0-9bcdefghjkmnpqrstuvwxyz]*\d)[0-9bcdefghjkmnpqrstuvwxyz]{7,12}\b` |
| US ZIP+4 Code | `\b\d{5}-\d{4}\b` |
| UK Postcode | `\b[A-Z]{1,2}\d[A-Z0-9]?\s?\d[A-Z]{2}\b` |
| Canada Postal Code | `\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b` |
| Japan Postal Code | `\b\d{3}-\d{4}\b` |
| Brazil CEP | `\b\d{5}-\d{3}\b` |

## Digital Identifiers

| Pattern Name | Regex |
|---|---|
| IMEI | `\b\d{2}[-.\s]?\d{6}[-.\s]?\d{6}[-.\s]?\d\b` |
| IMEISV | `\b\d{2}[-.\s]?\d{6}[-.\s]?\d{6}[-.\s]?\d{2}\b` |
| MEID | `\b[0-9A-F]{2}[-.\s]?[0-9A-F]{6}[-.\s]?[0-9A-F]{6}\b` |
| ICCID | `\b89\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{3,4}\d?\b` |
| IDFA/IDFV | `\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b` |
| Twitter Handle | `(?<!\w)@[A-Za-z_]\w{0,14}\b` |
| Hashtag | `(?<!\w)#[A-Za-z]\w{2,49}\b` |

## Authentication Tokens

| Pattern Name | Regex |
|---|---|
| Session ID | `\b[0-9a-f]{32,64}\b` |

## Date Formats

| Pattern Name | Regex |
|---|---|
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` |
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` |

## Vehicle Identification

| Pattern Name | Regex |
|---|---|
| VIN | `\b[A-HJ-NPR-Z0-9]{17}\b` |

## Insurance Identifiers

| Pattern Name | Regex |
|---|---|
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` |
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |

## Property Identifiers

| Pattern Name | Regex |
|---|---|
| Parcel Number | `\b\d{3}-\d{3}-\d{3}(?:-\d{3})?\b` |
| Title Deed Number | `\b\d{4,}-\d{4,}\b` |

## Legal Identifiers

| Pattern Name | Regex |
|---|---|
| US Federal Case Number | `\b\d:\d{2}-[a-z]{2}-\d{4,5}\b` |
| Court Docket Number | `\b\d{2,4}-?[A-Z]{1,4}-?\d{4,8}\b` |

---

## Regional Government-Issued IDs

### North America — United States

| Pattern Name | Regex |
|---|---|
| USA SSN | `\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| USA ITIN | `\b9\d{2}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| USA EIN | `\b\d{2}[-.\s]?\d{7}\b` |
| USA Passport | `\b\d{9}\b` |
| USA Passport Card | `\bC\d{8}\b` |
| US DEA Number | `\b[A-Z]{2}\d{7}\b` |
| US NPI | `\b[12]\d{9}\b` |
| US MBI | `\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s]?[A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s]?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b` |
| US DoD ID | `\b\d{10}\b` |
| US Known Traveler Number | `\b\d{9}\b` |
| US Phone Number | `(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)` |
| Generic US DL | `\b[A-Z]{1,2}\d{4,14}\b` |
| California DL | `\b[A-Z]\d{7}\b` |
| Florida DL | `\b[A-Z]\d{12}\b` |
| Illinois DL | `\b[A-Z]\d{11}\b` |
| New York DL | `\b\d{9}\b` |
| Texas DL | `\b\d{8}\b` |

### North America — Canada

| Pattern Name | Regex |
|---|---|
| Canada SIN | `\b\d{3}[-.\s]?\d{3}[-.\s]?\d{3}\b` |
| Canada BN | `\b\d{9}[A-Z]{2}\d{4}\b` |
| Canada Passport | `\b[A-Z]{2}\d{6}\b` |
| Canada Bank Code | `\b\d{5}[-.\s]?\d{3}\b` |
| Canada PR Card | `\b[A-Z]{2}\d{7,10}\b` |
| Ontario DL | `\b[A-Z]\d{4}[-.\s]?\d{5}[-.\s]?\d{5}\b` |
| Quebec DL | `\b[A-Z]\d{4}[-.\s]?\d{6}[-.\s]?\d{2}\b` |
| Ontario HC (OHIP) | `\b\d{10}(?:\s?[A-Z]{2})?\b` |
| Quebec HC (RAMQ) | `\b[A-Z]{4}\d{8}\b` |
| BC HC (MSP) | `\b9\d{9}\b` |

### North America — Mexico

| Pattern Name | Regex |
|---|---|
| Mexico CURP | `\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b` |
| Mexico RFC | `\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b` |
| Mexico Clave Elector | `\b[A-Z]{6}\d{8}[HM]\d{3}\b` |
| Mexico NSS | `\b\d{11}\b` |
| Mexico Passport | `\b[A-Z]\d{8}\b` |

### Europe — Key Countries

| Pattern Name | Regex |
|---|---|
| UK NIN | `\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b` |
| UK UTR | `\b\d{5}\s?\d{5}\b` |
| UK Passport | `\b\d{9}\b` |
| UK Sort Code | `\b\d{2}[-.\s]?\d{2}[-.\s]?\d{2}\b` |
| British NHS | `\b\d{3}\s?\d{3}\s?\d{4}\b` |
| UK DL | `\b[A-Z]{5}\d{6}[A-Z0-9]{5}\b` |
| Germany ID | `\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b` |
| Germany Passport | `\bC[A-Z0-9]{8}\b` |
| Germany Tax ID | `\b\d{11}\b` |
| Germany IBAN | `\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` |
| France NIR | `\b[12]\d{2}(?:0[1-9]\|1[0-2])(?:\d{2}\|2[AB])\d{3}\d{3}\d{2}\b` |
| France Passport | `\b\d{2}[A-Z]{2}\d{5}\b` |
| Italy Codice Fiscale | `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b` |
| Spain DNI | `\b\d{8}[A-Z]\b` |
| Spain NIE | `\b[XYZ]\d{7}[A-Z]\b` |
| Netherlands BSN | `\b\d{9}\b` |
| Poland PESEL | `\b\d{11}\b` |
| Sweden PIN | `\b\d{6}[-+]?\d{4}\b` |
| Switzerland AHV | `\b756[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{2}\b` |
| Ireland PPS | `\b\d{7}[A-Z]{1,2}\b` |
| EU VAT Generic | `\b(?:AT\|BE\|BG\|CY\|CZ\|DE\|DK\|EE\|EL\|ES\|FI\|FR\|HR\|HU\|IE\|IT\|LT\|LU\|LV\|MT\|NL\|PL\|PT\|RO\|SE\|SI\|SK)[A-Z0-9]{8,12}\b` |

### Asia-Pacific

| Pattern Name | Regex |
|---|---|
| India PAN | `\b[A-Z]{5}\d{4}[A-Z]\b` |
| India Aadhaar | `\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b` |
| India Passport | `\b[A-Z][1-9]\d{5}[1-9]\b` |
| India DL | `\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19\|20)\d{2}[-\s]?\d{7}\b` |
| India Voter ID | `\b[A-Z]{3}\d{7}\b` |
| China Resident ID | `\b\d{6}(?:18\|19\|20)\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` |
| China Passport | `\b[EGD][A-Z]?\d{7,8}\b` |
| Hong Kong ID | `\b[A-Z]{1,2}\d{6}\s?\(?[0-9A]\)?\b` |
| Taiwan National ID | `\b[A-Z][12489]\d{8}\b` |
| Japan My Number | `\b\d{12}\b` |
| Japan Passport | `\b[A-Z]{2}\d{7}\b` |
| South Korea RRN | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?[1-8]\d{6}\b` |
| Singapore NRIC | `\b[ST]\d{7}[A-Z]\b` |
| Singapore FIN | `\b[FGM]\d{7}[A-Z]\b` |
| Australia TFN | `\b\d{3}[\s]?\d{3}[\s]?\d{2,3}\b` |
| Australia Medicare | `\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s]?\d?\b` |
| Malaysia MyKad | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?\d{2}[-\s]?\d{4}\b` |
| Indonesia NIK | `\b\d{16}\b` |
| Thailand National ID | `\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b` |
| Philippines PhilSys | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` |
| Pakistan CNIC | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` |
| Vietnam CCCD | `\b\d{12}\b` |

### Latin America

| Pattern Name | Regex |
|---|---|
| Brazil CPF | `\b\d{3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{2}\b` |
| Brazil CNPJ | `\b\d{2}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}[-.\s]?\d{2}\b` |
| Brazil RG | `\b\d{1,2}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?[\dXx]\b` |
| Brazil CNH | `\b\d{11}\b` |
| Brazil SUS Card | `\b[1-2]\d{10}00[01]\d\b\|\b[789]\d{14}\b` |
| Brazil Passport | `\b[A-Z]{2}\d{6}\b` |
| Argentina DNI | `\b\d{7,8}\b` |
| Argentina CUIL/CUIT | `\b(?:20\|2[3-7]\|30\|33)[-.\s]?\d{8}[-.\s]?\d\b` |
| Colombia Cedula | `\b\d{6,10}\b` |
| Colombia NIT | `\b\d{3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d\b` |
| Chile RUN/RUT | `\b\d{1,2}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?[\dkK]\b` |
| Peru DNI | `\b\d{8}\b` |
| Peru RUC | `\b(?:10\|15\|17\|20)\d{9}\b` |

### Middle East

| Pattern Name | Regex |
|---|---|
| Saudi Arabia National ID | `\b[12]\d{9}\b` |
| Saudi Arabia Passport | `\b[A-Z]\d{7,8}\b` |
| UAE Emirates ID | `\b784[-.\s]?\d{4}[-.\s]?\d{7}[-.\s]?\d\b` |
| UAE Visa Number | `\b[1-7]01/?(?:19\|20)\d{2}/?\d{7}\b` |
| Israel Teudat Zehut | `\b\d{9}\b` |
| Qatar QID | `\b[23]\d{10}\b` |
| Kuwait Civil ID | `\b[1-3]\d{11}\b` |
| Iran Melli Code | `\b\d{10}\b` |

### Africa

| Pattern Name | Regex |
|---|---|
| South Africa ID | `\b\d{13}\b` |
| South Africa Passport | `\b[A-Z]?\d{8,9}\b` |
| South Africa DL | `\b\d{10}[A-Z]{2}\b` |
| Nigeria NIN | `\b\d{11}\b` |
| Nigeria BVN | `\b\d{11}\b` |
| Nigeria TIN | `\b\d{12,13}\b` |
| Nigeria Voter Card | `\b[0-9A-Z]{19}\b` |
| Nigeria Passport | `\b[A-Z]\d{8}\b` |
| Kenya National ID | `\b\d{7,8}\b` |
| Kenya KRA PIN | `\b[A-Z]\d{9}[A-Z]\b` |
| Egypt National ID | `\b[23]\d{13}\b` |
| Ghana Card | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` |
| Uganda NIN | `\bC[MF]\d{8}[A-Z0-9]{4}\b` |
| Tanzania NIDA | `\b\d{20}\b` |
