# PHI — Keywords

Keyword proximity lists for PHI pattern matching. Each keyword group lists
the terms that must appear within the specified character distance of a
regex match to confirm a detection.

> Corresponding patterns: [phi-patterns.md](phi-patterns.md)

---

## Medical Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Health Plan ID | `health plan`, `insurance id`, `beneficiary`, `member id`, `subscriber id` |
| DEA Number | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| ICD-10 Code | `icd`, `icd-10`, `diagnosis code`, `diagnostic code`, `condition code`, `icd code` |
| NDC Code | `ndc`, `national drug code`, `drug code`, `medication code`, `pharmaceutical` |
| Medical Record Number | `mrn`, `medical record`, `patient id`, `patient number`, `chart number`, `medical id`, `health record` |

## Insurance & Health Plan Data (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Insurance Policy Number | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#` |
| Insurance Claim Number | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number` |
| Insurance Group Number | `group number`, `group no`, `group id`, `plan group`, `insurance group`, `grp` |

## Biometric Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Biometric Hash | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` |
| Biometric Template ID | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` |

## Personal Identifiers (proximity: 30 chars)

| Pattern Name | Keywords |
|---|---|
| Date of Birth | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |
| Age Value | `age`, `years old`, `yr old`, `yrs old`, `aged`, `age group` |

## Contact Information (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Email Address | `email`, `e-mail`, `email address`, `mail to`, `contact` |
| E.164 Phone Number | `phone`, `telephone`, `tel`, `mobile`, `contact number` |
| IPv4 Address | `ip address`, `ip`, `server`, `host`, `network` |
| IPv6 Address | `ip address`, `ipv6`, `server`, `host`, `network` |

## Device Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| IMEI | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `phone imei`, `equipment identity` |
| ICCID | `iccid`, `sim card number`, `sim number`, `integrated circuit card`, `sim id`, `sim serial` |
| Device Serial Number | `serial number`, `serial no`, `sn`, `device serial`, `hardware serial`, `serial#` |

## Date Formats (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Date ISO | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date US | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date EU | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |

## Geographic Data (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| GPS Coordinates | `latitude`, `longitude`, `lat`, `lng`, `lon`, `coordinates`, `gps`, `geolocation`, `location`, `coord` |
| US ZIP Code | `zip`, `zip code`, `zipcode`, `postal code`, `mailing address`, `zip+4` |

## Privacy Classification Labels (proximity: 80 chars)

| Pattern Name | Keywords |
|---|---|
| PHI Label | `phi`, `protected health`, `health information`, `medical records`, `patient data` |
| HIPAA | `hipaa`, `health insurance portability`, `medical privacy`, `health data` |
| GDPR Personal Data | `gdpr`, `personal data`, `data subject`, `data protection`, `eu regulation` |

## Government Health IDs (proximity: 50 chars)

| Region | Pattern Name | Keywords |
|--------|---|---|
| US | SSN | `ssn`, `social security`, `social security number`, `ss#`, `ss number` |
| US | MBI (Medicare) | `mbi`, `medicare`, `medicare beneficiary`, `cms`, `medicare id` |
| US | NPI (Provider) | `npi`, `national provider`, `provider id`, `prescriber`, `provider identifier` |
| US | US DEA Number | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| US | US DoD ID | `dod`, `edipi`, `military id`, `defense id`, `cac` |
| UK | NHS Number | `nhs`, `nhs number`, `national health service`, `nhs id` |
| Brazil | SUS Card | `sus`, `cartao sus`, `sistema unico de saude`, `sus card` |
