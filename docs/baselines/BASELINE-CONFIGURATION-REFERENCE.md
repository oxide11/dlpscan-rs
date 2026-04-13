# Baseline Configuration Reference

This is a portable, tool-agnostic reference of every regex pattern and
keyword proximity list used by the dlpscan control baselines. Use it to
configure another DLP, SIEM, or scanning solution so it implements the
same controls and can be benchmarked against dlpscan on an apples-to-
apples basis.

> For the narrative explanation of each baseline (control objective,
> coverage summary, regulatory mapping), see
> [ABOUT-BASELINES.md](ABOUT-BASELINES.md).

## How to Read This Document

Each baseline section is organized by **category**. For every category
you will find:

- **Proximity** — the maximum character distance between a regex match
  and a keyword for the match to be considered confirmed.
- **Patterns table** — one row per pattern with its name and PCRE-
  compatible regex.
- **Keywords table** — one row per pattern with the context keywords
  required within the proximity distance.

### Regex dialect

All patterns are written in PCRE / Rust-regex syntax and use:

- `\b` word boundaries
- Non-capturing groups `(?:...)`
- Lookarounds `(?<!...)` / `(?!...)` where supported
- Standard character classes (`\d`, `\s`, `\w`)

If a candidate engine does not support lookarounds, substitute
equivalent anchors or pre-filter candidates in a second pass.

### Matching semantics

- **Case sensitivity.** Default is case-sensitive. Override only where
  the pattern uses explicit `[Aa]`-style classes.
- **Keyword matching.** Keywords are case-insensitive substring matches.
- **Proximity window.** The window is measured from either end of the
  regex match. Any listed keyword appearing within that window confirms
  the match.
- **Confidence.** Patterns without keyword context are
  lower-confidence. Patterns that match a keyword in proximity should
  have their confidence boosted (dlpscan adds +0.2 by default).

---

## Baseline 1 — PII (Personally Identifiable Information)

### Personal Identifiers (proximity: 30 chars)

| Pattern Name | Regex |
|---|---|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender)\b` |

| Pattern Name | Keywords |
|---|---|
| Date of Birth | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |

### Contact Information (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| IPv4 Address | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` |
| IPv6 Address | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b` |
| MAC Address | `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` |

| Pattern Name | Keywords |
|---|---|
| Email Address | `email`, `e-mail`, `email address`, `mail to`, `contact` |
| E.164 Phone Number | `phone`, `telephone`, `tel`, `mobile`, `contact number` |
| IPv4 Address | `ip address`, `ip`, `server`, `host`, `network` |
| IPv6 Address | `ip address`, `ipv6`, `server`, `host`, `network` |
| MAC Address | `mac address`, `hardware address`, `physical address`, `mac` |

### Biometric Identifiers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Biometric Hash (SHA-256) | `\b[0-9a-f]{64}\b` |
| Biometric Template ID (UUID) | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` |

| Pattern Name | Keywords |
|---|---|
| Biometric Hash | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` |
| Biometric Template ID | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` |

### Employment & Education (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Employee ID | `\b[A-Z]{1,3}\d{4,8}\b` |
| Work Permit Number | `\b[A-Z]{2,3}\d{7,10}\b` |
| EDU Email | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b` |

| Pattern Name | Keywords |
|---|---|
| Employee ID | `employee id`, `employee number`, `emp id`, `staff id`, `personnel number`, `badge number` |
| Work Permit Number | `work permit`, `work visa`, `employment authorization`, `ead`, `work authorization` |
| EDU Email | `student email`, `edu email`, `university email`, `academic email`, `school email` |

### Location & Address (proximity: 50 chars)

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

| Pattern Name | Keywords |
|---|---|
| GPS Coordinates | `latitude`, `longitude`, `lat`, `lng`, `coordinates`, `gps`, `geolocation`, `location` |
| GPS DMS | `latitude`, `longitude`, `coordinates`, `gps`, `dms`, `degrees minutes seconds` |
| Geohash | `geohash`, `geo hash`, `location hash` |
| US ZIP+4 Code | `zip`, `zip code`, `zipcode`, `postal code`, `mailing address`, `zip+4` |
| UK Postcode | `postcode`, `post code`, `postal code`, `uk address` |
| Canada Postal Code | `postal code`, `code postal`, `canadian address` |
| Japan Postal Code | `postal code`, `yubin bangou`, `japanese address` |
| Brazil CEP | `cep`, `codigo postal`, `brazilian address` |

### Digital Identifiers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| IMEI | `\b\d{2}[-.\s]?\d{6}[-.\s]?\d{6}[-.\s]?\d\b` |
| MEID | `\b[0-9A-F]{2}[-.\s]?[0-9A-F]{6}[-.\s]?[0-9A-F]{6}\b` |
| ICCID | `\b89\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{3,4}\d?\b` |
| IDFA/IDFV | `\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b` |
| Twitter Handle | `(?<!\w)@[A-Za-z_]\w{0,14}\b` |
| Hashtag | `(?<!\w)#[A-Za-z]\w{2,49}\b` |

| Pattern Name | Keywords |
|---|---|
| IMEI | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `equipment identity` |
| MEID | `meid`, `mobile equipment identifier`, `cdma device`, `equipment id` |
| ICCID | `iccid`, `sim card number`, `sim number`, `integrated circuit card`, `sim id` |
| IDFA/IDFV | `idfa`, `idfv`, `advertising identifier`, `identifier for advertisers`, `vendor identifier` |
| Twitter Handle | `twitter`, `tweet`, `x.com`, `twitter handle`, `twitter username` |

### Date Formats (proximity: 50 chars, confidence 0.8, require context)

| Pattern Name | Regex |
|---|---|
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` |
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` |

Keywords (all three): `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate`

### Regional Government IDs — North America (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| USA SSN | `\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| USA ITIN | `\b9\d{2}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| USA EIN | `\b\d{2}[-.\s]?\d{7}\b` |
| USA Passport | `\b\d{9}\b` |
| US Phone Number | `(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)` |
| Canada SIN | `\b\d{3}[-.\s]?\d{3}[-.\s]?\d{3}\b` |
| Canada BN | `\b\d{9}[A-Z]{2}\d{4}\b` |
| Mexico CURP | `\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b` |
| Mexico RFC | `\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b` |

| Pattern Name | Keywords |
|---|---|
| USA SSN | `ssn`, `social security`, `social security number`, `ss#`, `tax id` |
| USA ITIN | `itin`, `individual taxpayer`, `tax id`, `taxpayer identification` |
| USA EIN | `ein`, `employer identification`, `tax id`, `federal tax`, `fein` |
| USA Passport | `passport`, `passport number`, `travel document`, `us passport` |
| Canada SIN | `sin`, `social insurance number`, `social insurance` |
| Mexico CURP | `curp`, `clave unica`, `registro de poblacion` |
| Mexico RFC | `rfc`, `registro federal`, `contribuyentes`, `tax id` |

### Regional Government IDs — Europe (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| UK NIN | `\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b` |
| UK UTR | `\b\d{5}\s?\d{5}\b` |
| UK Sort Code | `\b\d{2}[-.\s]?\d{2}[-.\s]?\d{2}\b` |
| Germany ID | `\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b` |
| Germany Tax ID | `\b\d{11}\b` |
| Germany IBAN | `\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` |
| France NIR | `\b[12]\d{2}(?:0[1-9]\|1[0-2])(?:\d{2}\|2[AB])\d{3}\d{3}\d{2}\b` |
| Italy Codice Fiscale | `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b` |
| Spain DNI | `\b\d{8}[A-Z]\b` |
| Spain NIE | `\b[XYZ]\d{7}[A-Z]\b` |
| Netherlands BSN | `\b\d{9}\b` |
| Poland PESEL | `\b\d{11}\b` |
| Sweden PIN | `\b\d{6}[-+]?\d{4}\b` |
| Switzerland AHV | `\b756[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{2}\b` |
| Ireland PPS | `\b\d{7}[A-Z]{1,2}\b` |
| EU VAT Generic | `\b(?:AT\|BE\|BG\|CY\|CZ\|DE\|DK\|EE\|EL\|ES\|FI\|FR\|HR\|HU\|IE\|IT\|LT\|LU\|LV\|MT\|NL\|PL\|PT\|RO\|SE\|SI\|SK)[A-Z0-9]{8,12}\b` |

| Pattern Name | Keywords |
|---|---|
| UK NIN | `national insurance`, `ni number`, `nino`, `nin`, `insurance number` |
| UK UTR | `utr`, `unique taxpayer`, `tax reference`, `self assessment` |
| UK Sort Code | `sort code`, `bank sort`, `sort-code` |
| Germany ID | `personalausweis`, `identity card`, `ausweis`, `german id` |
| Germany Tax ID | `steuer-id`, `steueridentifikationsnummer`, `tin`, `tax id` |
| Germany IBAN | `iban`, `bankverbindung`, `kontonummer`, `bank account` |
| France NIR | `nir`, `numero de securite sociale`, `securite sociale`, `insee` |

### Regional Government IDs — Asia-Pacific (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| India PAN | `\b[A-Z]{5}\d{4}[A-Z]\b` |
| India Aadhaar | `\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b` |
| China Resident ID | `\b\d{6}(?:18\|19\|20)\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` |
| Japan My Number | `\b\d{12}\b` |
| South Korea RRN | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?[1-8]\d{6}\b` |
| Singapore NRIC | `\b[ST]\d{7}[A-Z]\b` |
| Australia TFN | `\b\d{3}[\s]?\d{3}[\s]?\d{2,3}\b` |
| Malaysia MyKad | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?\d{2}[-\s]?\d{4}\b` |
| Pakistan CNIC | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` |

| Pattern Name | Keywords |
|---|---|
| India PAN | `pan`, `permanent account number`, `income tax`, `pan card` |
| India Aadhaar | `aadhaar`, `aadhar`, `uid`, `unique identification`, `uidai` |
| China Resident ID | `resident id`, `身份证`, `identity card`, `id number`, `shenfenzheng` |
| Japan My Number | `my number`, `マイナンバー`, `individual number`, `kojin bango` |
| South Korea RRN | `resident registration`, `주민등록`, `rrn`, `jumin` |
| Singapore NRIC | `nric`, `identity card`, `ic number`, `singapore id` |
| Australia TFN | `tfn`, `tax file number`, `tax file`, `ato` |

### Regional Government IDs — Latin America, Middle East, Africa (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Brazil CPF | `\b\d{3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{2}\b` |
| Brazil CNPJ | `\b\d{2}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}[-.\s]?\d{2}\b` |
| Argentina CUIL/CUIT | `\b(?:20\|2[3-7]\|30\|33)[-.\s]?\d{8}[-.\s]?\d\b` |
| Chile RUN/RUT | `\b\d{1,2}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?[\dkK]\b` |
| UAE Emirates ID | `\b784[-.\s]?\d{4}[-.\s]?\d{7}[-.\s]?\d\b` |
| Israel Teudat Zehut | `\b\d{9}\b` |
| South Africa ID | `\b\d{13}\b` |
| Nigeria BVN | `\b\d{11}\b` |
| Kenya KRA PIN | `\b[A-Z]\d{9}[A-Z]\b` |
| Ghana Card | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` |

| Pattern Name | Keywords |
|---|---|
| Brazil CPF | `cpf`, `cadastro de pessoa fisica`, `cpf number` |
| Brazil CNPJ | `cnpj`, `cadastro nacional`, `pessoa juridica` |
| Argentina CUIL/CUIT | `cuil`, `cuit`, `clave unica`, `labor identification` |
| Chile RUN/RUT | `run`, `rut`, `rol unico`, `tributario` |
| UAE Emirates ID | `emirates id`, `eid`, `uae id` |
| Israel Teudat Zehut | `teudat zehut`, `tz`, `identity number` |
| South Africa ID | `sa id`, `id number`, `south african id`, `rsa id` |
| Nigeria BVN | `bvn`, `bank verification`, `bank verification number` |
| Kenya KRA PIN | `kra pin`, `pin number`, `kra`, `tax pin` |
| Ghana Card | `ghana card`, `national id`, `nia`, `ghana id` |

> **Note.** The full PII regional set (130+ patterns across all
> continents) is maintained in [pii-patterns.md](pii-patterns.md) and
> [pii-keywords.md](pii-keywords.md). The table above lists the most
> commonly tested patterns. Port the remainder when evaluating a tool
> intended for global deployment.

---

## Baseline 2 — PCI (Payment Card Industry)

### Credit Card Numbers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Visa | `\b4\d{3}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` |
| MasterCard | `\b(?:5[1-5]\d{2}\|2(?:2[2-9]\d\|2[3-9]\d\|[3-6]\d{2}\|7[01]\d\|720))[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` |
| Amex | `\b3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5}\b` |
| Discover | `\b6(?:011\|5\d{2}\|4[4-9]\d)[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` |
| JCB | `\b35(?:2[89]\|[3-8]\d)[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` |
| Diners Club | `\b3(?:0[0-5]\|[68]\d)\d[-.\s]?\d{6}[-.\s]?\d{4}\b` |
| UnionPay | `\b62\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}(?:[-.\s]?\d{1,3})?\b` |

| Pattern Name | Keywords |
|---|---|
| Visa | `visa`, `credit card`, `card number`, `card no`, `pan`, `primary account` |
| MasterCard | `mastercard`, `mc`, `credit card`, `card number`, `pan`, `primary account` |
| Amex | `amex`, `american express`, `credit card`, `card number`, `pan` |
| Discover | `discover`, `credit card`, `card number`, `pan`, `primary account` |
| JCB | `jcb`, `credit card`, `card number`, `pan`, `primary account` |
| Diners Club | `diners club`, `diners`, `credit card`, `card number`, `pan` |
| UnionPay | `unionpay`, `union pay`, `credit card`, `card number`, `pan` |

> **Luhn check required.** All candidate solutions must validate PAN
> matches with the Luhn algorithm before reporting them, to keep false
> positives at acceptable levels. A regex match alone is not enough.

### Security Codes (proximity: 30 chars)

| Pattern Name | Regex |
|---|---|
| CVV/CVC/CCV | `\b\d{3}\b` |
| Amex CID | `\b\d{4}\b` |

| Pattern Name | Keywords |
|---|---|
| CVV/CVC/CCV | `cvv`, `cvc`, `ccv`, `cvv2`, `cvc2`, `security code`, `card verification`, `verification value`, `verification code`, `csv` |
| Amex CID | `cid`, `card identification`, `amex security`, `amex cvv`, `four digit`, `4 digit security` |

### Primary Account Numbers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| PAN | `\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{1,7}\b` |
| Masked PAN | `\b\d{4}[-.\s]?[Xx*]{4}[-.\s]?[Xx*]{4}[-.\s]?\d{4}\b` |
| BIN/IIN | `\b\d{6,8}\b` |

| Pattern Name | Keywords |
|---|---|
| PAN | `pan`, `primary account number`, `account number`, `card number`, `cardholder number`, `full card` |
| Masked PAN | `masked pan`, `truncated pan`, `masked card`, `truncated card`, `last four`, `first six` |
| BIN/IIN | `bin`, `iin`, `bank identification number`, `issuer identification`, `card prefix`, `bin number` |

### Cardholder Data (proximity: 30 chars)

| Pattern Name | Regex |
|---|---|
| Cardholder Name Pattern | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` |
| Card Expiry | `\b(?:0[1-9]\|1[0-2])\s?/\s?(?:\d{2}\|\d{4})\b` |

| Pattern Name | Keywords |
|---|---|
| Cardholder Name | `cardholder`, `cardholder name`, `name on card`, `card holder`, `card member` |
| Card Expiry | `expiry`, `expiration`, `exp date`, `exp`, `valid thru`, `valid through`, `good thru`, `card expires`, `mm/yy` |

### PCI Sensitive Data (proximity: 30 chars)

| Pattern Name | Regex |
|---|---|
| Dynamic CVV | `\b\d{3}\b` |
| PVKI | `\b\d{1}\b` |
| PVV | `\b\d{4}\b` |
| Service Code | `\b\d{3}\b` |

| Pattern Name | Keywords |
|---|---|
| Dynamic CVV | `icvv`, `dcvv`, `dynamic cvv`, `chip cvv`, `dynamic verification`, `cavv` |
| PVKI | `pvki`, `pin verification key indicator`, `key indicator` |
| PVV | `pvv`, `pin verification value`, `pin value` |
| Service Code | `service code`, `svc code`, `magstripe service`, `card service code` |

### Sensitive Authentication Data — Track Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Track 1 Data | `%B\d{13,19}\^[A-Z\s/]+\^\d{4}\d*` |
| Track 2 Data | `;\d{13,19}=\d{4}\d*\?` |

| Pattern Name | Keywords |
|---|---|
| Track 1 | `track 1`, `track1`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |
| Track 2 | `track 2`, `track2`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |

### Banking Authentication — Payment Infrastructure (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| PIN Block | `\b[0-9A-F]{16}\b` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` |
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` |
| PIN | `\b\d{4,6}\b` |

| Pattern Name | Keywords |
|---|---|
| PIN Block | `pin block`, `encrypted pin`, `pin encryption`, `iso 9564`, `pin format` |
| HSM Key | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |
| Encryption Key | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |
| PIN | `pin`, `personal identification number`, `atm pin`, `debit pin`, `pin number`, `pin code`, `card pin` |

### Check & MICR Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| MICR Line | `[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}` |
| Check Number | `\b\d{4,6}\b` |
| Cashier Check Number | `\b\d{8,15}\b` |

| Pattern Name | Keywords |
|---|---|
| MICR Line | `micr`, `magnetic ink`, `check bottom`, `cheque line`, `micr line`, `e13b` |
| Check Number | `check number`, `check no`, `cheque number`, `check#`, `ck no`, `check num` |
| Cashier Check | `cashier check`, `cashiers check`, `certified check`, `money order`, `bank check`, `official check` |

### Payment Service Secrets (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| Stripe Secret Key | `\bsk_live_[0-9a-zA-Z]{24,}\b` |
| Stripe Publishable Key | `\bpk_live_[0-9a-zA-Z]{24,}\b` |

| Pattern Name | Keywords |
|---|---|
| Stripe Secret | `stripe`, `stripe key`, `secret key`, `payment`, `api key` |
| Stripe Publishable | `stripe`, `publishable`, `public key`, `payment`, `client key` |

---

## Baseline 3 — PHI (Protected Health Information)

### Medical Identifiers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` |
| DEA Number | `\b[A-Z]{2}\d{7}\b` |
| ICD-10 Code | `\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b` |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` |
| Medical Record Number | `\b\d{6,10}\b` |

| Pattern Name | Keywords |
|---|---|
| Health Plan ID | `health plan`, `insurance id`, `beneficiary`, `member id`, `subscriber id` |
| DEA Number | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| ICD-10 Code | `icd`, `icd-10`, `diagnosis code`, `diagnostic code`, `condition code`, `icd code` |
| NDC Code | `ndc`, `national drug code`, `drug code`, `medication code`, `pharmaceutical` |
| Medical Record Number | `mrn`, `medical record`, `patient id`, `patient number`, `chart number`, `medical id`, `health record` |

### Insurance & Health Plan Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` |
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |
| Insurance Group Number | `\b\d{5,10}\b` |

| Pattern Name | Keywords |
|---|---|
| Policy Number | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#` |
| Claim Number | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number` |
| Group Number | `group number`, `group no`, `group id`, `plan group`, `insurance group`, `grp` |

### Personal Identifiers — PHI Context (proximity: 30 chars)

| Pattern Name | Regex |
|---|---|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender\|M\|F\|X)\b` |
| Age Value | `\b(?:1[89]\|[2-9]\d\|1[0-4]\d)\b` |

| Pattern Name | Keywords |
|---|---|
| Date of Birth | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |
| Age Value | `age`, `years old`, `yr old`, `yrs old`, `aged`, `age group` |

### Government Health IDs (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| US SSN | `\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b` |
| US MBI (Medicare) | `\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s]?[A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s]?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b` |
| US NPI | `\b[12]\d{9}\b` |
| US DEA Number | `\b[A-Z]{2}\d{7}\b` |
| UK NHS Number | `\b\d{3}\s?\d{3}\s?\d{4}\b` |
| Brazil SUS Card | `\b[1-2]\d{10}00[01]\d\b\|\b[789]\d{14}\b` |

| Pattern Name | Keywords |
|---|---|
| US SSN | `ssn`, `social security`, `social security number`, `patient ssn` |
| US MBI | `mbi`, `medicare`, `medicare beneficiary`, `cms`, `medicare id` |
| US NPI | `npi`, `national provider`, `provider id`, `prescriber`, `provider identifier` |
| US DEA | `dea`, `dea number`, `drug enforcement`, `prescriber` |
| UK NHS | `nhs`, `nhs number`, `national health service`, `nhs id` |
| Brazil SUS | `sus`, `sus card`, `cartao nacional de saude`, `cns` |

### Privacy Classification Labels (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` |
| HIPAA | `\bHIPAA\b` |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` |

| Pattern Name | Keywords |
|---|---|
| PHI Label | `phi`, `protected health information`, `health information`, `medical information` |
| HIPAA | `hipaa`, `health insurance portability`, `privacy rule`, `covered entity` |
| GDPR | `gdpr`, `personal data`, `data protection`, `eu regulation` |

---

## Baseline 4 — Internal Financial Data

### Banking & Account Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` |
| ABA Routing Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{7}\b` |
| US Bank Account Number | `\b\d{8,17}\b` |
| Canada Transit Number | `\b\d{5}[-.\s]?\d{3}\b` |

| Pattern Name | Keywords |
|---|---|
| IBAN | `iban`, `international bank account number`, `bank account` |
| SWIFT/BIC | `swift`, `bic`, `bank identifier code`, `swift code`, `routing code` |
| ABA Routing | `routing number`, `routing no`, `aba`, `aba routing`, `transit routing`, `bank routing`, `rtn` |
| US Bank Account | `account number`, `account no`, `bank account`, `checking account`, `savings account`, `acct`, `acct no`, `deposit account` |
| Canada Transit | `transit number`, `institution number`, `canadian bank`, `bank transit` |

### Internal Banking References (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Internal Account Ref | `\b[A-Z]{2,4}\d{8,14}\b` |
| Teller ID | `\b[A-Z]{1,3}\d{4,8}\b` |
| Branch Code | `\b\d{4,6}\b` |
| Customer ID | `\b\d{6,12}\b` |

| Pattern Name | Keywords |
|---|---|
| Internal Account Ref | `internal reference`, `account reference`, `internal id`, `system id`, `core banking id` |
| Teller ID | `teller id`, `teller number`, `officer id`, `banker id`, `employee id`, `user id` |
| Branch Code | `branch code`, `branch number`, `branch id`, `cost center`, `branch no`, `office code` |
| Customer ID | `customer id`, `cif`, `cid`, `customer number`, `client id`, `customer identification`, `client number` |

### Customer Financial Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Account Balance | `(?<!\w)[$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Balance with Currency Code | `\b(?:USD\|EUR\|GBP\|JPY\|CAD\|AUD\|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Income Amount | `(?<!\w)[$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| DTI Ratio | `\b\d{1,2}\.\d{1,2}%\b` |
| Credit Score | `\b[3-8]\d{2}\b` |

| Pattern Name | Keywords |
|---|---|
| Account Balance | `balance`, `account balance`, `available balance`, `current balance`, `ledger balance`, `closing balance` |
| Balance w/ Currency | `balance`, `amount`, `total`, `funds`, `available`, `ledger` |
| Income Amount | `income`, `salary`, `annual income`, `monthly income`, `gross income`, `net income`, `compensation`, `wages`, `earnings` |
| DTI Ratio | `dti`, `debt-to-income`, `debt to income`, `dti ratio`, `debt ratio` |
| Credit Score | `credit score`, `fico`, `fico score`, `credit rating`, `vantagescore`, `credit bureau`, `experian`, `equifax`, `transunion` |

### Wire Transfer & Payment Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Fedwire IMAD | `\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b` |
| CHIPS UID | `\b\d{6}[A-Z0-9]{4,10}\b` |
| Wire Reference Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{16,35}\b` |
| ACH Trace Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{13}\b` |
| ACH Batch Number | `\b\d{7}\b` |
| SEPA Reference | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{12,35}\b` |

| Pattern Name | Keywords |
|---|---|
| Fedwire IMAD | `imad`, `input message accountability`, `fedwire`, `fed reference`, `wire reference` |
| CHIPS UID | `chips`, `chips uid`, `chips transfer`, `clearing house`, `interbank payment` |
| Wire Reference | `wire reference`, `wire transfer`, `wire number`, `remittance reference`, `payment reference`, `transfer reference` |
| ACH Trace | `ach trace`, `trace number`, `trace id`, `ach transaction`, `ach payment`, `nacha` |
| ACH Batch | `ach batch`, `batch number`, `batch id`, `ach file`, `nacha batch` |
| SEPA Reference | `sepa`, `sepa reference`, `end-to-end`, `e2e reference`, `sepa transfer`, `sepa credit` |

### Loan & Mortgage Data (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Loan Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}\b` |
| MERS MIN | `\b\d{18}\b` |
| Universal Loan Identifier | `\b[A-Z0-9]{4}00[A-Z0-9]{17,39}\b` |
| LTV Ratio | `\b\d{1,3}\.\d{1,2}%\b` |

| Pattern Name | Keywords |
|---|---|
| Loan Number | `loan number`, `loan no`, `loan id`, `loan account`, `loan#`, `lending number` |
| MERS MIN | `mers`, `mortgage identification number`, `min number`, `mers min`, `mortgage electronic` |
| Universal Loan ID | `uli`, `universal loan identifier`, `hmda`, `loan identifier` |
| LTV Ratio | `ltv`, `loan-to-value`, `loan to value`, `ltv ratio`, `combined ltv`, `cltv` |

### Securities Identifiers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| CUSIP | `\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b` |
| ISIN | `\b[A-Z]{2}[0-9A-Z]{9}\d\b` |
| SEDOL | `\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b` |
| FIGI | `\bBBG[A-Z0-9]{9}\b` |
| LEI | `\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b` |
| Ticker Symbol | `(?<!\w)\$[A-Z]{1,5}\b` |

| Pattern Name | Keywords |
|---|---|
| CUSIP | `cusip`, `committee on uniform securities`, `security identifier`, `bond cusip`, `cusip number` |
| ISIN | `isin`, `international securities`, `securities identification`, `isin code`, `isin number` |
| SEDOL | `sedol`, `stock exchange daily official list`, `london stock`, `uk securities` |
| FIGI | `figi`, `financial instrument global identifier`, `bloomberg`, `bbg`, `openfigi` |
| LEI | `lei`, `legal entity identifier`, `gleif`, `entity identifier`, `lei code` |
| Ticker Symbol | `ticker`, `stock symbol`, `trading symbol`, `nyse`, `nasdaq`, `equity symbol`, `stock ticker` |

### Cryptocurrency (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Bitcoin Address (Legacy) | `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` |
| Bitcoin Address (Bech32) | `\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b` |
| Ethereum Address | `\b0x[0-9a-fA-F]{40}\b` |
| Litecoin Address | `\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b` |
| Bitcoin Cash Address | `\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b` |
| Monero Address | `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` |
| Ripple Address | `\br[1-9A-HJ-NP-Za-km-z]{24,34}\b` |

| Pattern Name | Keywords |
|---|---|
| Bitcoin Legacy | `bitcoin`, `btc`, `wallet`, `crypto` |
| Bitcoin Bech32 | `bitcoin`, `btc`, `segwit`, `wallet` |
| Ethereum | `ethereum`, `eth`, `ether`, `wallet`, `crypto` |
| Litecoin | `litecoin`, `ltc`, `wallet` |
| Bitcoin Cash | `bitcoin cash`, `bch`, `wallet` |
| Monero | `monero`, `xmr`, `wallet` |
| Ripple | `ripple`, `xrp`, `wallet` |

### Regulatory Identifiers (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| SAR Filing Number | `\b\d{14,20}\b` |
| CTR Number | `\b\d{14,20}\b` |
| AML Case ID | `\b[A-Z]{2,4}[-]?\d{6,12}\b` |
| OFAC SDN Entry | `\b\d{4,6}\b` |
| FinCEN Report Number | `\b\d{14}\b` |
| Compliance Case Number | `\b[A-Z]{2,5}[-]?\d{4}[-]?\d{4,8}\b` |

| Pattern Name | Keywords |
|---|---|
| SAR Filing | `sar`, `suspicious activity report`, `sar filing`, `sar number`, `suspicious activity` |
| CTR Number | `ctr`, `currency transaction report`, `ctr filing`, `ctr number`, `cash transaction` |
| AML Case ID | `aml`, `anti-money laundering`, `money laundering`, `aml case`, `aml investigation`, `bsa` |
| OFAC SDN | `ofac`, `sdn`, `specially designated`, `sanctions`, `ofac list`, `blocked persons` |
| FinCEN Report | `fincen`, `financial crimes`, `fincen report`, `fincen filing`, `bsa filing` |
| Compliance Case | `compliance case`, `investigation number`, `regulatory case`, `compliance id`, `audit case`, `examination number` |

### Financial Regulatory Labels (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| MNPI | `\b(?:MNPI\|[Mm]aterial\s+[Nn]on-?[Pp]ublic\s+[Ii]nformation)\b` |
| Inside Information | `\b[Ii]nside(?:r)?\s+[Ii]nformation\b` |
| Pre-Decisional | `\b[Pp]re-?[Dd]ecisional\b` |
| Draft Not for Circulation | `\b[Dd]raft\s*[-–—]\s*[Nn]ot\s+[Ff]or\s+[Cc]irculation\b` |
| Market Sensitive | `\b[Mm]arket\s+[Ss]ensitive\b` |
| Information Barrier | `\b(?:[Ii]nformation\s+[Bb]arrier\|[Cc]hinese\s+[Ww]all)\b` |
| Investment Restricted | `\b[Rr]estricted\s+[Ll]ist\b` |

| Pattern Name | Keywords |
|---|---|
| MNPI | `mnpi`, `material`, `non-public`, `insider`, `trading`, `securities` |
| Inside Information | `inside information`, `insider`, `material`, `non-public`, `trading restriction` |
| Pre-Decisional | `pre-decisional`, `draft`, `deliberative`, `not final`, `preliminary` |
| Draft Not for Circulation | `draft`, `circulation`, `preliminary`, `not final`, `review only` |
| Market Sensitive | `market sensitive`, `price sensitive`, `stock`, `securities`, `trading` |
| Information Barrier | `information barrier`, `chinese wall`, `wall crossing`, `restricted side`, `public side` |
| Investment Restricted | `restricted list`, `watch list`, `grey list`, `restricted securities`, `trading restriction` |

### Supervisory Information (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` |
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` |

| Pattern Name | Keywords |
|---|---|
| Supervisory Controlled | `supervisory`, `controlled`, `occ`, `fdic`, `federal reserve`, `regulator`, `examination` |
| Supervisory Confidential | `supervisory`, `confidential`, `regulator`, `examination`, `bank examination` |
| CSI | `confidential supervisory`, `csi`, `examination report`, `regulatory report`, `supervisory letter` |
| Non-Public Supervisory | `non-public`, `supervisory`, `regulatory`, `examination`, `not for release` |
| Restricted Supervisory | `restricted`, `supervisory`, `regulatory`, `compliance`, `enforcement` |
| Examination Findings | `examination`, `mra`, `mria`, `findings`, `regulatory`, `corrective action`, `consent order` |

---

## Baseline 5 — Source Code & Secrets

### Generic Secrets (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| Bearer Token | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` |
| JWT Token | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` |
| Private Key | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` |
| Generic API Key | `(?:api[_-]?key\|apikey\|api[_-]?secret\|api[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9\-._~+/]{16,}["']?` |
| Generic Secret Assignment | `(?:password\|passwd\|pwd\|secret\|token\|credential)\s*[=:]\s*["']?[^\s"']{8,}["']?` |
| Database Connection String | `(?:mongodb(?:\+srv)?\|mysql\|postgres(?:ql)?\|redis\|mssql)://[^:\s]+:[^@\s]+@[^\s]+` |

| Pattern Name | Keywords |
|---|---|
| Bearer Token | `authorization`, `bearer`, `auth token` |
| JWT Token | `jwt`, `json web token`, `auth`, `token` |
| Private Key | `private key`, `rsa`, `ssh key`, `pem` |
| Generic API Key | `api key`, `api_key`, `apikey`, `api secret` |
| Generic Secret | `password`, `secret`, `credential`, `passwd` |
| DB Connection String | `database`, `db connection`, `connection string`, `mongodb`, `postgres`, `mysql`, `redis` |

### URLs with Embedded Credentials (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| URL with Password | `https?://[^:\s]+:[^@\s]+@[^\s]+` |
| URL with Token | `https?://[^\s]*[?&](?:token\|key\|api_key\|apikey\|access_token\|secret\|password\|passwd\|pwd)=[^\s&]+` |

| Pattern Name | Keywords |
|---|---|
| URL with Password | `url`, `link`, `endpoint`, `connection`, `connect` |
| URL with Token | `url`, `link`, `endpoint`, `api`, `callback` |

### Cloud Provider Secrets (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| AWS Access Key | `\b(?:A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}\b` |
| AWS Secret Key | `(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])` |
| Google API Key | `\bAIza[0-9A-Za-z\\-_]{35}\b` |

| Pattern Name | Keywords |
|---|---|
| AWS Access Key | `aws`, `amazon`, `access key`, `iam`, `credentials` |
| AWS Secret Key | `aws`, `secret key`, `secret access key`, `aws_secret` |
| Google API Key | `google`, `gcp`, `api key`, `google cloud`, `firebase` |

### Code Platform Secrets (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| GitHub Token (Classic) | `\bghp_[A-Za-z0-9]{36}\b` |
| GitHub Token (Fine-Grained) | `\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b` |
| GitHub OAuth Token | `\bgho_[A-Za-z0-9]{36}\b` |
| NPM Token | `\bnpm_[A-Za-z0-9]{36}\b` |
| PyPI Token | `\bpypi-[A-Za-z0-9-_]{16,}\b` |

| Pattern Name | Keywords |
|---|---|
| GitHub Classic | `github`, `token`, `pat`, `personal access token` |
| GitHub Fine-Grained | `github`, `fine-grained`, `pat`, `personal access token` |
| GitHub OAuth | `github`, `oauth`, `token`, `app token` |
| NPM Token | `npm`, `npmjs`, `registry`, `publish token` |
| PyPI Token | `pypi`, `python`, `package`, `upload token` |

### Messaging Service Secrets (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| Slack Bot Token | `\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b` |
| Slack User Token | `\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b` |
| Slack Webhook | `\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}\b` |
| SendGrid API Key | `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b` |
| Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` |
| Mailgun API Key | `\bkey-[0-9a-zA-Z]{32}\b` |

| Pattern Name | Keywords |
|---|---|
| Slack Bot | `slack`, `bot`, `token`, `workspace` |
| Slack User | `slack`, `user`, `token`, `workspace` |
| Slack Webhook | `slack`, `webhook`, `incoming`, `notification` |
| SendGrid | `sendgrid`, `email`, `api key`, `mail` |
| Twilio | `twilio`, `sms`, `api key`, `messaging` |
| Mailgun | `mailgun`, `email`, `api key`, `mail` |

### Payment Service Secrets (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| Stripe Secret Key | `\bsk_live_[0-9a-zA-Z]{24,}\b` |
| Stripe Publishable Key | `\bpk_live_[0-9a-zA-Z]{24,}\b` |

| Pattern Name | Keywords |
|---|---|
| Stripe Secret | `stripe`, `stripe key`, `secret key`, `payment`, `api key` |
| Stripe Publishable | `stripe`, `publishable`, `public key`, `payment`, `client key` |

### Authentication Tokens (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Session ID | `\b[0-9a-f]{32,64}\b` |
| CSRF Token | `\b[0-9a-zA-Z_-]{32,64}\b` |
| OTP Code | `\b\d{6,8}\b` |
| Refresh Token | `\b[0-9a-zA-Z_-]{40,}\b` |

| Pattern Name | Keywords |
|---|---|
| Session ID | `session id`, `session_id`, `sessionid`, `sess_id`, `session token`, `phpsessid`, `jsessionid`, `asp.net_sessionid` |
| CSRF Token | `csrf`, `csrf_token`, `xsrf`, `anti-forgery`, `request token`, `authenticity_token`, `_token` |
| OTP Code | `otp`, `one-time password`, `one time password`, `verification code`, `two-factor`, `2fa`, `mfa code`, `authenticator code`, `totp` |
| Refresh Token | `refresh_token`, `refresh token`, `rt_token`, `oauth refresh` |

### Banking Authentication — Infrastructure Secrets (proximity: 50 chars)

| Pattern Name | Regex |
|---|---|
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` |

| Pattern Name | Keywords |
|---|---|
| Encryption Key | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |
| HSM Key | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |

---

## Baseline 6 — Confidential Documents

Patterns in this baseline are **exact-label** matches. Keyword proximity
is used to boost confidence but is not strictly required — the labels
themselves are the signal.

### Corporate Classification Labels (proximity: 80 chars)

| Pattern Name | Regex |
|---|---|
| TT_Confidential | `\bTT_Confidential\b` |
| TT_MBI | `\bTT_MBI\b` |
| TT_SPI | `\bTT_SPI\b` |
| CNB_Confidential | `\bCNB_Confidential\b` |
| Sensitive - Business | `\b[Ss]ensitive\s*[-–—]\s*[Bb]usiness\b` |
| Sensitive - Personal | `\b[Ss]ensitive\s*[-–—]\s*[Pp]ersonal\b` |
| CNB_Restricted | `\bCNB_Restricted\b` |
| CNB_Internal | `\bCNB_Internal\b` |
| CNB_Public | `\bCNB_Public\b` |
| Public | `\b[Pp]ublic\b` |

| Pattern Name | Keywords |
|---|---|
| TT_Confidential | `confidential`, `classification`, `label`, `sensitive`, `restricted` |
| TT_MBI | `mbi`, `material business information`, `classification`, `sensitive` |
| TT_SPI | `spi`, `sensitive personal information`, `classification`, `personal` |
| CNB_Confidential | `confidential`, `cnb`, `classification`, `restricted`, `sensitive` |
| Sensitive - Business | `sensitive`, `business`, `classification`, `restricted`, `internal` |
| Sensitive - Personal | `sensitive`, `personal`, `classification`, `pii`, `privacy` |
| CNB_Restricted | `restricted`, `cnb`, `classification`, `limited distribution`, `need to know` |
| CNB_Internal | `internal`, `cnb`, `classification`, `employees only`, `not for external` |
| CNB_Public | `public`, `cnb`, `classification`, `unrestricted` |
| Public | `public`, `unrestricted`, `open`, `classification` |

### Legal Privilege Markings (proximity: 100 chars)

| Pattern Name | Regex |
|---|---|
| Attorney-Client Privilege | `\b[Aa]ttorney[-\s][Cc]lient\s+[Pp]rivilege\b` |
| Privileged and Confidential | `\b[Pp]rivileged\s+and\s+[Cc]onfidential\b` |
| Work Product | `\b(?:[Aa]ttorney\s+)?[Ww]ork\s+[Pp]roduct\b` |
| Privileged Information | `\b[Pp]rivileged\s+[Ii]nformation\b` |
| Legal Privilege | `\b[Ll]egal\s+[Pp]rivilege\b` |
| Litigation Hold | `\b[Ll]itigation\s+[Hh]old\b` |
| Protected by Privilege | `\b[Pp]rotected\s+by\s+[Pp]rivilege\b` |

| Pattern Name | Keywords |
|---|---|
| Attorney-Client Privilege | `attorney-client`, `privilege`, `legal`, `counsel`, `confidential`, `do not disclose` |
| Privileged and Confidential | `privileged`, `confidential`, `legal`, `do not disclose`, `counsel` |
| Work Product | `work product`, `attorney work product`, `litigation`, `legal`, `counsel` |
| Privileged Information | `privileged`, `legal`, `confidential`, `protected` |
| Legal Privilege | `legal privilege`, `attorney`, `counsel`, `legal department` |
| Litigation Hold | `litigation hold`, `legal hold`, `preservation`, `discovery`, `do not delete` |
| Protected by Privilege | `protected`, `privilege`, `legal`, `confidential` |

### Financial Regulatory Labels (proximity: 80 chars)

See [Baseline 4 — Financial Regulatory Labels](#financial-regulatory-labels-proximity-80-chars)
for MNPI, Inside Information, Pre-Decisional, Draft Not for Circulation,
Market Sensitive, Information Barrier, and Investment Restricted. These
patterns are shared between the Internal Financial and Confidential
Documents baselines.

### Supervisory Information (proximity: 80 chars)

See [Baseline 4 — Supervisory Information](#supervisory-information-proximity-80-chars)
for Supervisory Controlled, Supervisory Confidential, CSI, Non-Public
Supervisory, Restricted Supervisory, and Examination Findings (MRA/MRIA).

---

## Appendix A — Category Confidence & Context Defaults

The dlpscan engine applies these defaults unless a ruleset overrides
them. Use them as baseline values when tuning a candidate solution.

| Category | Default Confidence | Require Context |
|---|---|---|
| Credit Card Numbers | 0.8 | Yes |
| PAN | 0.8 | Yes |
| Track Data | 0.9 | No |
| Dates | 0.8 | **Yes** |
| Postal Codes | 0.7 | **Yes** |
| Regional Government IDs | 0.7 | Yes |
| Biometric Identifiers | 0.8 | Yes |
| Cloud Provider Secrets | 0.9 | No |
| Code Platform Secrets | 0.9 | No |
| Generic Secrets | 0.7 | Yes |
| Classification Labels | 0.9 | No |
| Legal Privilege Markings | 0.9 | No |

## Appendix B — Shared Patterns

The following patterns appear in more than one baseline. When porting
to a candidate tool, register each pattern **once** and attach it to
every baseline where it is listed, rather than duplicating the rule.

| Pattern | Baselines |
|---|---|
| Date of Birth | PII, PHI |
| Email Address | PII, PHI |
| E.164 Phone Number | PII, PHI |
| IPv4 / IPv6 | PII, PHI |
| Biometric Hash / Template ID | PII, PHI |
| Insurance Policy / Claim Number | PII, PHI |
| VIN | PII, PHI |
| IMEI / ICCID | PII, PHI |
| SSN (and regional equivalents) | PII, PHI |
| Cardholder Name Pattern | PCI, PHI |
| Stripe Secret / Publishable Key | PCI, Source Code & Secrets |
| PIN Block / HSM Key / Encryption Key | PCI, Internal Financial, Source Code & Secrets |
| MNPI, Inside Info, Market Sensitive, Info Barrier, Restricted List | Internal Financial, Confidential Documents |
| Supervisory Controlled / CSI / MRA-MRIA | Internal Financial, Confidential Documents |

## Appendix C — Minimum Feature Set for a Candidate Solution

To faithfully implement these baselines, a candidate DLP solution must
support:

- [ ] PCRE-compatible regex with `\b`, `\d`, non-capturing groups
- [ ] Lookarounds `(?<!...)` and `(?!...)` (or an equivalent pre-filter)
- [ ] Keyword proximity matching with configurable character windows
      (30, 50, 80, and 100 chars are all used)
- [ ] Luhn validation for credit card / PAN matches
- [ ] Per-category confidence thresholds
- [ ] Per-category `require_context` flag
- [ ] Per-category or per-pattern exclusion
- [ ] Mapping of findings back to a baseline and a regulation
- [ ] Case-insensitive keyword matching
- [ ] Multi-byte character support (CJK and Arabic script keywords
      appear in the PII regional sets)

If any of these is missing, document the gap in your evaluation — it
is likely to translate into either coverage loss or elevated false
positives for this baseline set.

