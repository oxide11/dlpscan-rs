# Personal Identifiable Information (PII)

Detects personally identifiable information that can be used to identify,
contact, or locate an individual. Aligns with GDPR, CCPA/CPRA, FERPA, GLBA,
and general privacy protection requirements.

## Control Objective

Prevent the unauthorized disclosure of personal identifiers, contact details,
biometric data, government-issued IDs, and other information that can be
linked to a specific individual.

---

## Pattern & Keyword Reference

| Resource | Description |
|----------|-------------|
| [pii-patterns.md](pii-patterns.md) | All regex patterns for PII detection |
| [pii-keywords.md](pii-keywords.md) | Keyword proximity lists for each pattern |

---

## Categories Covered

| Category | Pattern Count | Description |
|----------|:---:|-------------|
| Personal Identifiers | 2 | Date of birth, gender markers |
| Contact Information | 5 | Email, phone, IP addresses, MAC |
| Biometric Identifiers | 2 | Fingerprint hashes, facial templates |
| Employment & Education | 3 | Employee IDs, work permits, EDU emails |
| Location & Address | 8 | GPS, geohash, postal codes (US/UK/CA/JP/BR) |
| Digital Identifiers | 6 | IMEI, MEID, ICCID, IDFA, social media handles |
| Authentication Tokens | 1 | Session IDs |
| Date Formats | 3 | ISO, US, EU date formats |
| Vehicle Identification | 1 | VIN (17-character) |
| Insurance Identifiers | 2 | Policy numbers, claim numbers |
| Property Identifiers | 2 | Parcel numbers, title deeds |
| Legal Identifiers | 2 | Federal case numbers, court dockets |
| North America | 30+ | SSN, ITIN, EIN, passports, state DLs, SIN, CURP |
| Europe | 40+ | NIN, PESEL, NIR, Codice Fiscale, IBANs, EU VAT |
| Asia-Pacific | 30+ | Aadhaar, PAN, Resident ID, My Number, NRIC |
| Latin America | 15+ | CPF, CNPJ, DNI, CUIL/CUIT, RUN/RUT |
| Middle East | 10+ | Emirates ID, Teudat Zehut, Melli Code |
| Africa | 10+ | SA ID, NIN, BVN, KRA PIN, Ghana Card |

---

## Applicable Regulations

- **GDPR** (EU) -- Articles 4, 9; personal data and special categories
- **CCPA/CPRA** (California) -- Personal information definition
- **FERPA** (US) -- Student education records
- **GLBA** (US) -- Nonpublic personal financial information
- **PIPEDA** (Canada) -- Personal information
- **LGPD** (Brazil) -- Personal and sensitive personal data
- **POPIA** (South Africa) -- Personal information
