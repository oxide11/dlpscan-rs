# PII — Keywords

Keyword proximity lists for PII pattern matching. Each keyword group lists
the terms that must appear within the specified character distance of a
regex match to confirm a detection.

> Corresponding patterns: [pii-patterns.md](pii-patterns.md)

---

## Personal Identifiers (proximity: 30 chars)

| Pattern Name | Keywords |
|---|---|
| Date of Birth | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |

## Contact Information (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Email Address | `email`, `e-mail`, `email address`, `mail to`, `contact` |
| E.164 Phone Number | `phone`, `telephone`, `tel`, `mobile`, `contact number` |
| IPv4 Address | `ip address`, `ip`, `server`, `host`, `network` |
| IPv6 Address | `ip address`, `ipv6`, `server`, `host`, `network` |
| MAC Address | `mac address`, `hardware address`, `physical address`, `mac` |

## Biometric Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Biometric Hash | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` |
| Biometric Template ID | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` |

## Employment & Education (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Employee ID | `employee id`, `employee number`, `emp id`, `staff id`, `personnel number`, `emp no`, `worker id`, `badge number` |
| Work Permit Number | `work permit`, `work visa`, `employment authorization`, `ead`, `labor permit`, `work authorization` |
| EDU Email | `student email`, `edu email`, `university email`, `academic email`, `school email`, `college email` |

## Location & Address (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| GPS Coordinates | `latitude`, `longitude`, `lat`, `lng`, `lon`, `coordinates`, `gps`, `geolocation`, `location`, `coord` |
| GPS DMS | `latitude`, `longitude`, `coordinates`, `gps`, `dms`, `degrees minutes seconds` |
| Geohash | `geohash`, `geo hash`, `location hash` |
| US ZIP+4 Code | `zip`, `zip code`, `zipcode`, `postal code`, `mailing address`, `zip+4` |
| UK Postcode | `postcode`, `post code`, `postal code`, `uk address` |
| Canada Postal Code | `postal code`, `code postal`, `canadian address` |
| Japan Postal Code | `postal code`, `yubin bangou`, `japanese address` |
| Brazil CEP | `cep`, `codigo postal`, `brazilian address` |

## Digital Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| IMEI | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `phone imei`, `equipment identity` |
| IMEISV | `imeisv`, `imei software version`, `imei sv`, `software version number` |
| MEID | `meid`, `mobile equipment identifier`, `cdma device`, `equipment id` |
| ICCID | `iccid`, `sim card number`, `sim number`, `integrated circuit card`, `sim id`, `sim serial` |
| IDFA/IDFV | `idfa`, `idfv`, `advertising identifier`, `identifier for advertisers`, `vendor identifier`, `apple device id` |
| Twitter Handle | `twitter`, `tweet`, `x.com`, `twitter handle`, `twitter username`, `follow` |

## Authentication Tokens (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Session ID | `session id`, `session_id`, `sessionid`, `sess_id`, `session token`, `phpsessid`, `jsessionid`, `asp.net_sessionid` |

## Date Formats (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Date ISO | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date US | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date EU | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |

## Vehicle Identification (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| VIN | `vin`, `vehicle identification`, `vehicle id`, `chassis number` |

## Insurance Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Insurance Policy Number | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#` |
| Insurance Claim Number | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number` |

## Property Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| Parcel Number | `parcel number`, `apn`, `assessor parcel`, `parcel id`, `lot number`, `property id` |
| Title Deed Number | `title number`, `deed number`, `deed of trust`, `title deed`, `land title`, `property title` |

## Legal Identifiers (proximity: 50 chars)

| Pattern Name | Keywords |
|---|---|
| US Federal Case Number | `case number`, `case no`, `docket`, `civil action`, `case#`, `filing number` |
| Court Docket Number | `docket number`, `docket no`, `court case`, `case file`, `case reference`, `court number` |

---

## Regional Government-Issued IDs (proximity: 50 chars)

### North America — United States

| Pattern Name | Keywords |
|---|---|
| USA SSN | `ssn`, `social security`, `social security number`, `ss#`, `ss number`, `tax id` |
| USA ITIN | `itin`, `individual taxpayer`, `tax id`, `taxpayer identification` |
| USA EIN | `ein`, `employer identification`, `tax id`, `federal tax`, `fein` |
| USA Passport | `passport`, `passport number`, `travel document`, `us passport` |
| USA Passport Card | `passport card`, `us passport card`, `travel document` |
| US DEA Number | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| US NPI | `npi`, `national provider`, `provider id`, `prescriber`, `provider identifier` |
| US MBI | `mbi`, `medicare`, `medicare beneficiary`, `cms`, `medicare id` |
| US DoD ID | `dod`, `edipi`, `military id`, `defense id`, `cac`, `common access card` |
| US Phone Number | `phone`, `telephone`, `tel`, `mobile`, `cell`, `contact number`, `call` |
| Generic US DL | `driver license`, `driver's license`, `dl`, `driving license`, `license number`, `dl#` |

### North America — Canada

| Pattern Name | Keywords |
|---|---|
| Canada SIN | `sin`, `social insurance number`, `social insurance`, `numero d'assurance sociale` |
| Canada BN | `business number`, `bn`, `gst number`, `hst number` |
| Canada Passport | `passport`, `passport number`, `canadian passport` |
| Ontario DL | `driver licence`, `ontario dl`, `ontario driver`, `dl number` |
| Quebec HC (RAMQ) | `ramq`, `health card`, `carte soleil`, `assurance maladie` |
| BC HC (MSP) | `msp`, `bc health`, `medical services plan`, `health card` |

### North America — Mexico

| Pattern Name | Keywords |
|---|---|
| Mexico CURP | `curp`, `clave unica`, `registro de poblacion`, `identificacion` |
| Mexico RFC | `rfc`, `registro federal`, `contribuyentes`, `tax id` |
| Mexico Passport | `pasaporte`, `passport`, `passport number` |
| Mexico NSS | `nss`, `imss`, `seguro social`, `numero de seguridad social` |

### Europe — United Kingdom

| Pattern Name | Keywords |
|---|---|
| UK NIN | `national insurance`, `ni number`, `nino`, `nin`, `insurance number` |
| UK UTR | `utr`, `unique taxpayer`, `tax reference`, `self assessment` |
| UK Passport | `passport`, `passport number`, `hmpo`, `uk passport` |
| UK Sort Code | `sort code`, `bank sort`, `sort-code` |
| British NHS | `nhs`, `nhs number`, `national health service`, `nhs id` |
| UK DL | `driving licence`, `dvla`, `driver number`, `licence number` |

### Europe — Germany

| Pattern Name | Keywords |
|---|---|
| Germany ID | `personalausweis`, `identity card`, `ausweis`, `german id` |
| Germany Passport | `reisepass`, `passport`, `german passport` |
| Germany Tax ID | `steuer-id`, `steueridentifikationsnummer`, `tin`, `tax id` |
| Germany IBAN | `iban`, `bankverbindung`, `kontonummer`, `bank account` |

### Europe — France

| Pattern Name | Keywords |
|---|---|
| France NIR | `nir`, `numero de securite sociale`, `securite sociale`, `insee` |
| France Passport | `passeport`, `passport`, `french passport` |
| France CNI | `cni`, `carte nationale`, `carte d'identite`, `identity card` |
| France IBAN | `iban`, `compte bancaire`, `rib`, `bank account` |

### Asia-Pacific

| Pattern Name | Keywords |
|---|---|
| India PAN | `pan`, `permanent account number`, `income tax`, `pan card` |
| India Aadhaar | `aadhaar`, `aadhar`, `uid`, `unique identification`, `uidai` |
| India Passport | `passport`, `passport number`, `indian passport` |
| India DL | `driving licence`, `dl`, `driver licence`, `rto` |
| India Voter ID | `voter id`, `epic`, `election card`, `voter card` |
| China Resident ID | `resident id`, `身份证`, `identity card`, `id number`, `shenfenzheng` |
| Hong Kong ID | `hkid`, `hong kong id`, `identity card`, `身份證` |
| Japan My Number | `my number`, `マイナンバー`, `individual number`, `kojin bango` |
| South Korea RRN | `resident registration`, `주민등록`, `rrn`, `jumin` |
| Singapore NRIC | `nric`, `identity card`, `ic number`, `singapore id` |
| Australia TFN | `tfn`, `tax file number`, `tax file`, `ato` |
| Malaysia MyKad | `mykad`, `ic number`, `identity card`, `kad pengenalan` |
| Pakistan CNIC | `cnic`, `computerized national`, `nadra`, `national id` |

### Latin America

| Pattern Name | Keywords |
|---|---|
| Brazil CPF | `cpf`, `cadastro de pessoa fisica`, `cadastro pessoa`, `cpf number` |
| Brazil CNPJ | `cnpj`, `cadastro nacional`, `pessoa juridica`, `cnpj number` |
| Argentina DNI | `dni`, `documento nacional`, `identity document`, `documento` |
| Argentina CUIL/CUIT | `cuil`, `cuit`, `clave unica`, `labor identification` |
| Chile RUN/RUT | `run`, `rut`, `rol unico`, `tributario` |

### Middle East

| Pattern Name | Keywords |
|---|---|
| Saudi Arabia National ID | `national id`, `هوية وطنية`, `civil id`, `saudi id` |
| UAE Emirates ID | `emirates id`, `eid`, `هوية إماراتية`, `uae id` |
| Israel Teudat Zehut | `teudat zehut`, `tz`, `תעודת זהות`, `identity number` |
| Qatar QID | `qid`, `qatar id`, `residency permit`, `بطاقة شخصية` |
| Kuwait Civil ID | `civil id`, `بطاقة مدنية`, `kuwait id` |
| Iran Melli Code | `melli code`, `کد ملی`, `national code`, `code melli` |

### Africa

| Pattern Name | Keywords |
|---|---|
| South Africa ID | `sa id`, `id number`, `identity number`, `south african id`, `rsa id` |
| Nigeria NIN | `nin`, `national identification`, `nimc`, `national id` |
| Nigeria BVN | `bvn`, `bank verification`, `bank verification number` |
| Kenya KRA PIN | `kra pin`, `pin number`, `kra`, `tax pin` |
| Egypt National ID | `national id`, `رقم قومي`, `identity card`, `egyptian id` |
| Ghana Card | `ghana card`, `national id`, `nia`, `ghana id` |
| Uganda NIN | `nin`, `national id`, `nira`, `uganda id` |
