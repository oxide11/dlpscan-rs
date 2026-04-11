# KEYWORDS.md

Complete inventory of all context keywords used by dlpscan for
proximity-based detection.

**560 keyword groups** across **126 categories** — **4992 keywords** (English, French, Spanish, German, Italian, Portuguese).

## How context matching works

dlpscan uses an [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
automaton to scan the input text for all keywords in a single O(n) pass.
When a keyword is found within the configured **distance** (in characters)
of a regex match, the match receives a confidence boost of +0.20
(capped at 1.0). Patterns marked as **context-required** are suppressed
entirely unless a keyword is found nearby.

Keywords are provided in 6 languages: English, French/French-Canadian,
Spanish, German, Italian, and Portuguese.

> See [PATTERNS.md](PATTERNS.md) for the corresponding regex patterns.

---

## Africa - Egypt (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Egypt National ID | `national id`, `raqam qawmi`, `egyptian id`, `identity card`, `civil registry`, `carte d'identité`, `carte nationale d'identité`, `identité nationale`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis`, `tarjeta de identidad` | 50 |
| Egypt Passport | `egyptian passport`, `egypt passport`, `passport number`, `jawaz safar`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Egypt Tax ID | `tax id`, `tax registration`, `maslahat al-darayeb`, `tax number`, `eta`, `identifiant fiscal`, `numéro d'impôt`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Africa - Ethiopia (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Ethiopia National ID | `fayda`, `national id`, `ethiopian id`, `identity number`, `fayda id`, `carte nationale d'identité`, `identité nationale`, `numéro d'identité`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |
| Ethiopia Passport | `ethiopian passport`, `ethiopia passport`, `passport number`, `immigration`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Ethiopia TIN | `tin`, `tax identification`, `erca`, `ministry of revenue`, `tax number`, `identification fiscale`, `numéro d'impôt`, `numéro fiscal`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |

## Africa - Ghana (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Ghana Card | `ghana card`, `nia`, `national identification`, `identity card`, `ghana id`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Ghana NHIS | `nhis`, `national health insurance`, `health insurance`, `nhia`, `health card`, `assurance maladie`, `assurance santé`, `carte d'assurance maladie`, `carte santé`, `assicurazione sanitaria`, `krankenversicherung`, `seguro de salud`, `seguro de saúde`, `seguro médico`, `seguro saude` | 50 |
| Ghana Passport | `ghanaian passport`, `ghana passport`, `passport number`, `immigration`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Ghana TIN | `tin`, `tax identification`, `gra`, `taxpayer`, `tax number`, `contribuable`, `identification fiscale`, `numéro d'impôt`, `numéro fiscal`, `contribuente`, `contribuinte`, `contribuyente`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation`, `steuerzahler` | 50 |

## Africa - Kenya (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Kenya KRA PIN | `kra pin`, `kra`, `kenya revenue`, `tax pin`, `itax` | 50 |
| Kenya NHIF | `nhif`, `national hospital insurance`, `health insurance`, `nhif number`, `assurance maladie`, `assurance santé`, `assicurazione sanitaria`, `krankenversicherung`, `seguro de salud`, `seguro de saúde`, `seguro médico`, `seguro saude` | 50 |
| Kenya National ID | `national id`, `kenyan id`, `identity card`, `huduma namba`, `maisha namba`, `carte d'identité`, `carte nationale d'identité`, `identité nationale`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis`, `tarjeta de identidad` | 50 |
| Kenya Passport | `kenyan passport`, `kenya passport`, `passport number`, `immigration`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Africa - Morocco (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Morocco CIN | `cin`, `cnie`, `carte nationale`, `carte identite`, `identite nationale` | 50 |
| Morocco Passport | `moroccan passport`, `morocco passport`, `passeport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Morocco Tax ID | `identifiant fiscal`, `if`, `dgi`, `tax id`, `impots`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Africa - Nigeria (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Nigeria BVN | `bvn`, `bank verification number`, `bank verification`, `nibss`, `cbn` | 50 |
| Nigeria Driver Licence | `driver's licence`, `driving licence`, `frsc`, `licence number`, `ndl`, `no de permis`, `numéro de permis`, `permis de conduire` | 50 |
| Nigeria NIN | `nin`, `national identification number`, `nimc`, `national identity`, `identity number`, `numéro d'identité` | 50 |
| Nigeria Passport | `nigerian passport`, `nigeria passport`, `passport number`, `immigration`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Nigeria TIN | `tin`, `tax identification number`, `firs`, `tax id`, `joint tax board`, `identifiant fiscal`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |
| Nigeria Voter Card | `voter card`, `pvc`, `voter identification`, `inec`, `permanent voter` | 50 |

## Africa - South Africa (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| South Africa DL | `driver's licence`, `driving licence`, `south african dl`, `licence number`, `traffic department`, `no de permis`, `numéro de permis`, `permis de conduire` | 50 |
| South Africa ID | `south african id`, `sa id`, `identity number`, `id number`, `home affairs`, `numéro d'identité` | 50 |
| South Africa Passport | `south african passport`, `sa passport`, `passport number`, `home affairs`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Africa - Tanzania (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Tanzania NIDA | `nida`, `national id`, `tanzanian id`, `nin`, `national identification`, `carte nationale d'identité`, `identité nationale`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |
| Tanzania Passport | `tanzanian passport`, `tanzania passport`, `passport number`, `immigration`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Tanzania TIN | `tin`, `tax identification`, `tra`, `tanzania revenue`, `tax number`, `identification fiscale`, `numéro d'impôt`, `numéro fiscal`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |

## Africa - Tunisia (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Tunisia CIN | `cin`, `carte identite nationale`, `carte identite`, `tunisian id`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Tunisia Passport | `tunisian passport`, `tunisia passport`, `passeport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Africa - Uganda (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Uganda NIN | `nin`, `national identification number`, `nira`, `national id`, `ugandan id`, `carte nationale d'identité`, `identité nationale`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |
| Uganda Passport | `ugandan passport`, `uganda passport`, `passport number`, `immigration`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - Australia (11 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Australia DL ACT | `act licence`, `canberra licence`, `act driver` | 50 |
| Australia DL NSW | `nsw licence`, `new south wales licence`, `nsw driver`, `rms`, `service nsw` | 50 |
| Australia DL NT | `nt licence`, `northern territory licence`, `nt driver` | 50 |
| Australia DL QLD | `qld licence`, `queensland licence`, `tmr`, `queensland driver` | 50 |
| Australia DL SA | `sa licence`, `south australia licence`, `sa driver`, `dpti` | 50 |
| Australia DL TAS | `tas licence`, `tasmania licence`, `tasmanian driver` | 50 |
| Australia DL VIC | `vic licence`, `victoria licence`, `vicroads`, `victorian driver` | 50 |
| Australia DL WA | `wa licence`, `western australia licence`, `wa driver`, `dol wa` | 50 |
| Australia Medicare | `medicare`, `medicare number`, `medicare card`, `health insurance`, `bulk billing`, `assurance maladie`, `assurance santé`, `assicurazione sanitaria`, `krankenversicherung`, `seguro de salud`, `seguro de saúde`, `seguro médico`, `seguro saude` | 50 |
| Australia Passport | `australian passport`, `australia passport`, `passport number`, `travel document`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Australia TFN | `tax file number`, `tfn`, `australian tax`, `ato`, `tax return` | 50 |

## Asia-Pacific - Bangladesh (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Bangladesh NID | `nid`, `national id`, `voter id`, `national identity`, `smart card bangladesh`, `carte nationale d'identité`, `identité nationale`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |
| Bangladesh Passport | `bangladeshi passport`, `bangladesh passport`, `passport number`, `e-passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Bangladesh TIN | `tin`, `tax identification`, `nbr`, `national board of revenue`, `taxpayer`, `contribuable`, `identification fiscale`, `contribuente`, `contribuinte`, `contribuyente`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation`, `steuerzahler` | 50 |

## Asia-Pacific - China (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| China Passport | `chinese passport`, `china passport`, `passport number`, `huzhao`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| China Resident ID | `resident id`, `identity card`, `shenfenzheng`, `id card number`, `citizen id`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Hong Kong ID | `hong kong id`, `hkid`, `identity card`, `hk id card`, `hong kong identity`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Macau ID | `macau id`, `bir`, `macau identity`, `macau resident`, `bilhete de identidade` | 50 |
| Taiwan National ID | `taiwan id`, `national id`, `identity number`, `taiwan national`, `roc id`, `carte nationale d'identité`, `identité nationale`, `numéro d'identité`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |

## Asia-Pacific - India (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| India Aadhaar | `aadhaar`, `aadhar`, `aadhaar number`, `uid number`, `uidai` | 50 |
| India DL | `driving licence`, `driver licence`, `indian dl`, `driving license india`, `rto`, `permis de conduire` | 50 |
| India PAN | `permanent account number`, `pan`, `pan card`, `income tax`, `pan no` | 50 |
| India Passport | `indian passport`, `india passport`, `passport number`, `passport no`, `travel document`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| India Ration Card | `ration card`, `ration number`, `public distribution`, `food supply`, `bpl card` | 50 |
| India Voter ID | `voter id`, `epic`, `election commission`, `voter card`, `electoral` | 50 |

## Asia-Pacific - Indonesia (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Indonesia NIK | `nik`, `nomor induk kependudukan`, `ktp`, `identity card`, `kartu tanda penduduk`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Indonesia NPWP | `npwp`, `nomor pokok wajib pajak`, `tax id`, `taxpayer number`, `pajak`, `identifiant fiscal`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |
| Indonesia Passport | `indonesian passport`, `indonesia passport`, `passport number`, `paspor`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - Japan (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Japan DL | `driving licence`, `driver license`, `unten menkyo`, `japan licence`, `japanese dl`, `permis de conduire`, `carta de condução`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida` | 50 |
| Japan Health Insurance | `health insurance`, `hoken`, `insurer number`, `hokensho`, `medical insurance`, `assurance maladie`, `assurance santé`, `assicurazione sanitaria`, `krankenversicherung`, `seguro de salud`, `seguro de saúde`, `seguro médico`, `seguro saude` | 50 |
| Japan Juminhyo Code | `juminhyo`, `resident record`, `resident registration`, `juki net`, `basic resident registry` | 50 |
| Japan My Number | `my number`, `individual number`, `kojin bango`, `mynumber`, `social security tax` | 50 |
| Japan Passport | `japanese passport`, `japan passport`, `passport number`, `ryoken`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Japan Residence Card | `residence card`, `zairyu card`, `zairyu`, `residence permit`, `foreigner registration` | 50 |

## Asia-Pacific - Malaysia (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Malaysia MyKad | `mykad`, `ic number`, `identity card`, `kad pengenalan`, `nric malaysia`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Malaysia Passport | `malaysian passport`, `malaysia passport`, `passport number`, `pasport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - New Zealand (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| New Zealand DL | `driving licence`, `driver licence`, `nz licence`, `nzta`, `waka kotahi`, `permis de conduire` | 50 |
| New Zealand IRD | `ird`, `inland revenue`, `tax number`, `ird number`, `nz tax`, `numéro d'impôt`, `numéro fiscal` | 50 |
| New Zealand NHI | `nhi`, `national health index`, `health index`, `nhi number`, `health system` | 50 |
| New Zealand Passport | `new zealand passport`, `nz passport`, `passport number`, `aotearoa passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - Pakistan (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Pakistan CNIC | `cnic`, `computerized national identity`, `nadra`, `national identity card`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Pakistan NICOP | `nicop`, `national identity card overseas`, `overseas pakistani`, `nadra nicop` | 50 |
| Pakistan Passport | `pakistani passport`, `pakistan passport`, `passport number`, `travel document`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - Philippines (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Philippines Passport | `philippine passport`, `philippines passport`, `passport number`, `dfa passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Philippines PhilHealth | `philhealth`, `health insurance`, `pin`, `philhealth number`, `medical insurance`, `assurance maladie`, `assurance santé`, `assicurazione sanitaria`, `krankenversicherung`, `seguro de salud`, `seguro de saúde`, `seguro médico`, `seguro saude` | 50 |
| Philippines PhilSys | `philsys`, `national id`, `philid`, `psn`, `philippine identification`, `carte nationale d'identité`, `identité nationale`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |
| Philippines SSS | `sss`, `social security`, `sss number`, `social security system` | 50 |
| Philippines TIN | `tin`, `tax identification`, `bir`, `bureau of internal revenue`, `taxpayer`, `contribuable`, `identification fiscale`, `contribuente`, `contribuinte`, `contribuyente`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation`, `steuerzahler` | 50 |
| Philippines UMID | `umid`, `unified multi-purpose`, `crn`, `common reference number`, `umid card` | 50 |

## Asia-Pacific - Singapore (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Singapore DL | `driving licence`, `driver license`, `singapore dl`, `singapore licence`, `traffic police`, `permis de conduire`, `carta de condução`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida` | 50 |
| Singapore FIN | `fin`, `foreign identification`, `foreign id`, `work permit`, `employment pass`, `permis de travail`, `arbeitserlaubnis`, `arbeitsgenehmigung`, `autorização de trabalho`, `permesso di lavoro`, `permiso de trabajo`, `permissão de trabalho` | 50 |
| Singapore NRIC | `nric`, `national registration`, `identity card`, `singapore id`, `ic number`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Singapore Passport | `singapore passport`, `passport number`, `sg passport`, `travel document`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - South Korea (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| South Korea DL | `driving licence`, `driver license`, `korean dl`, `unjon myonho`, `korea licence`, `permis de conduire`, `carta de condução`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida` | 50 |
| South Korea Passport | `korean passport`, `korea passport`, `passport number`, `yeogwon`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| South Korea RRN | `resident registration`, `rrn`, `jumin deungnok`, `jumin`, `resident number` | 50 |

## Asia-Pacific - Sri Lanka (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Sri Lanka NIC New | `nic`, `national identity card`, `identity card`, `sri lanka id`, `new nic`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Sri Lanka NIC Old | `nic`, `national identity card`, `identity card`, `sri lanka id`, `jatika handunumpat`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Sri Lanka Passport | `sri lankan passport`, `sri lanka passport`, `passport number`, `travel document`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Asia-Pacific - Thailand (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Thailand DL | `driving licence`, `driver license`, `thai dl`, `bai kap khi`, `land transport`, `permis de conduire`, `carta de condução`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida` | 50 |
| Thailand National ID | `thai id`, `national id`, `bat prachakon`, `citizen id`, `identity card`, `carte d'identité`, `carte nationale d'identité`, `identité nationale`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis`, `tarjeta de identidad` | 50 |
| Thailand Passport | `thai passport`, `thailand passport`, `passport number`, `nangsue doen thang`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Thailand Tax ID | `tax id`, `tax number`, `revenue department`, `tin thailand`, `vat number`, `identifiant fiscal`, `numéro d'impôt`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Asia-Pacific - Vietnam (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Vietnam CCCD | `cccd`, `cmnd`, `citizen id`, `can cuoc cong dan`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Vietnam Passport | `vietnamese passport`, `vietnam passport`, `passport number`, `ho chieu`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Vietnam Tax Code | `tax code`, `ma so thue`, `mst`, `tax id`, `tax number`, `identifiant fiscal`, `numéro d'impôt`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Authentication Tokens (1 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Session ID | `session id`, `session_id`, `sessionid`, `sess_id`, `session token`, `phpsessid`, `jsessionid`, `asp.net_sessionid` | 50 |

## Banking Authentication (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Encryption Key | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` | 50 |
| HSM Key | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` | 50 |
| PIN Block | `pin block`, `encrypted pin`, `pin encryption`, `iso 9564`, `pin format` | 50 |

## Banking and Financial (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| ABA Routing Number | `routing number`, `routing no`, `aba`, `aba routing`, `transit routing`, `bank routing`, `rtn`, `numero de transit`, `numéro de transit`, `transit bancaire`, `bankleitzahl`, `blz`, `codice di instradamento`, `número de encaminhamento`, `número de ruta` | 50 |
| Canada Transit Number | `transit number`, `institution number`, `canadian bank`, `bank transit` | 50 |
| IBAN Generic | `iban`, `international bank account number`, `bank account`, `compte bancaire`, `compte de banque`, `numéro de compte bancaire international`, `bankkonto`, `conta bancaria`, `conta bancária`, `conto bancario`, `cuenta bancaria`, `internationale bankkontonummer`, `numero di conto bancario internazionale`, `número de conta bancária internacional`, `número de cuenta bancaria internacional` | 50 |
| SWIFT/BIC | `swift`, `bic`, `bank identifier code`, `swift code`, `routing code`, `code d'identification bancaire` | 50 |
| US Bank Account Number | `account number`, `account no`, `bank account`, `checking account`, `savings account`, `acct`, `acct no`, `deposit account`, `compte bancaire`, `compte chèques`, `compte d'épargne`, `compte de banque`, `compte de dépôt`, `no de compte`, `numero de compte`, `numéro de compte`, `bankkonto`, `conta bancaria`, `conta bancária`, `conta corrente`, `conta poupança`, `conto bancario`, `conto corrente`, `conto di risparmio`, `cuenta bancaria`, `cuenta corriente`, `cuenta de ahorro`, `girokonto`, `kontonummer`, `numero da conta`, `numero de cuenta`, `numero di conto`, `número da conta`, `número de cuenta`, `sparkonto` | 50 |

## Biometric Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Biometric Hash | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` | 50 |
| Biometric Template ID | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` | 50 |

## Card Expiration Dates (1 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Card Expiry | `expiry`, `expiration`, `exp date`, `exp`, `valid thru`, `valid through`, `good thru`, `card expires`, `mm/yy`, `carte expire`, `date d'exp`, `date d'expiration`, `valide jusqu'au`, `échéance`, `ablaufdatum`, `caducidad`, `data de validade`, `data di scadenza`, `fecha de caducidad`, `gültig bis`, `scadenza`, `validade`, `vencimento`, `vencimiento` | 30 |

## Card Track Data (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Track 1 Data | `track 1`, `track1`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` | 50 |
| Track 2 Data | `track 2`, `track2`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` | 50 |

## Check and MICR Data (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Cashier Check Number | `cashier check`, `cashiers check`, `certified check`, `money order`, `bank check`, `official check` | 50 |
| Check Number | `check number`, `check no`, `cheque number`, `check#`, `ck no`, `check num` | 50 |
| MICR Line | `micr`, `magnetic ink`, `check bottom`, `cheque line`, `micr line`, `e13b` | 50 |

## Cloud Provider Secrets (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| AWS Access Key | `aws`, `amazon`, `access key`, `aws key` | 80 |
| AWS Secret Key | `aws secret`, `secret access key`, `aws_secret` | 80 |
| Google API Key | `google`, `gcp`, `google api`, `google cloud` | 80 |

## Code Platform Secrets (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| GitHub OAuth Token | `github oauth`, `oauth token` | 80 |
| GitHub Token (Classic) | `github`, `gh token`, `personal access token` | 80 |
| GitHub Token (Fine-Grained) | `github`, `fine-grained`, `pat` | 80 |
| NPM Token | `npm`, `node package`, `npm token` | 80 |
| PyPI Token | `pypi`, `python package`, `pip` | 80 |

## Contact Information (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| E.164 Phone Number | `phone`, `telephone`, `tel`, `mobile`, `contact number`, `cellulaire`, `numéro de téléphone`, `portable`, `tél`, `téléphone`, `cellulare`, `celular`, `handy`, `kontaktnummer`, `mobiltelefon`, `móvil`, `numero di contatto`, `número de contacto`, `número de contato`, `telefon`, `telefone`, `telefono`, `telemóvel`, `teléfono` | 50 |
| Email Address | `email`, `e-mail`, `email address`, `mail to`, `contact`, `adresse courriel`, `adresse électronique`, `coordonnées`, `courriel`, `courrier électronique`, `destinataire`, `envoyer à`, `correio eletronico`, `correio eletrônico`, `correo`, `correo electrónico`, `direccion de correo`, `dirección de correo`, `e-mail-adresse`, `endereco de email`, `endereço de email`, `indirizzo di posta`, `indirizzo email`, `posta elettronica` | 50 |
| IPv4 Address | `ip address`, `ip`, `server`, `host`, `network`, `adresse ip`, `hôte`, `réseau`, `serveur` | 50 |
| IPv6 Address | `ip address`, `ipv6`, `server`, `host`, `network`, `adresse ip`, `hôte`, `réseau`, `serveur` | 50 |
| MAC Address | `mac address`, `hardware address`, `physical address`, `mac`, `adresse mac` | 50 |

## Corporate Classification (9 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Corporate Confidential | `confidential`, `company`, `corporate`, `business`, `proprietary`, `confidentiel`, `confidentielle`, `exclusif`, `propriétaire`, `confidencial`, `confidenziale`, `eigentum`, `propiedad exclusiva`, `proprietario`, `proprietário`, `riservato`, `vertraulich` | 80 |
| Do Not Distribute | `distribute`, `distribution`, `circulation`, `forward`, `share` | 80 |
| Embargoed | `embargo`, `embargoed`, `hold until`, `not for release`, `publication date`, `sous embargo`, `sperrfrist` | 80 |
| Eyes Only | `eyes only`, `recipient only`, `personal`, `addressee only`, `pour vos yeux seulement` | 80 |
| Highly Confidential | `highly confidential`, `sensitive`, `restricted`, `executive only`, `accès restreint`, `restreint`, `restreinte`, `beschränkt`, `eingeschränkt`, `limitato`, `restringida`, `restringido`, `restrita`, `restrito`, `riservato` | 80 |
| Internal Only | `internal`, `company`, `employees only`, `staff only`, `not for external`, `employés seulement`, `interne`, `ne pas diffuser à l'externe`, `réservé aux employés`, `intern`, `interna`, `interno` | 80 |
| Need to Know | `need to know`, `restricted access`, `limited distribution`, `authorized personnel`, `besoin de savoir`, `diffusion restreinte` | 80 |
| Proprietary | `proprietary`, `trade secret`, `intellectual property`, `confidential business`, `exclusif`, `propriétaire`, `secret commercial`, `secret d'affaires`, `eigentum`, `propiedad exclusiva`, `proprietario`, `proprietário`, `vertraulich` | 80 |
| Restricted | `restricted`, `limited distribution`, `access controlled`, `need to know`, `accès restreint`, `besoin de savoir`, `diffusion restreinte`, `restreint`, `restreinte`, `beschränkt`, `eingeschränkt`, `limitato`, `restringida`, `restringido`, `restrita`, `restrito`, `riservato` | 80 |

## Credit Card Numbers (7 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Amex | `amex`, `american express`, `credit card`, `card number`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `kartennummer`, `kreditkarte`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |
| Diners Club | `diners club`, `diners`, `credit card`, `card number`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `kartennummer`, `kreditkarte`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |
| Discover | `discover`, `credit card`, `card number`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `kartennummer`, `kreditkarte`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |
| JCB | `jcb`, `credit card`, `card number`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `kartennummer`, `kreditkarte`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |
| MasterCard | `mastercard`, `credit card`, `card number`, `card no`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `karten-nr`, `kartennummer`, `kreditkarte`, `n. carta`, `no de tarjeta`, `no do cartão`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |
| UnionPay | `unionpay`, `union pay`, `credit card`, `card number`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `kartennummer`, `kreditkarte`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |
| Visa | `visa`, `credit card`, `card number`, `card no`, `pan`, `primary account`, `carte de credit`, `carte de crédit`, `compte principal`, `no de carte`, `numero de carte`, `numéro de carte`, `carta di credito`, `cartao de credito`, `cartão de crédito`, `conta principal`, `conto principale`, `cuenta principal`, `hauptkonto`, `karten-nr`, `kartennummer`, `kreditkarte`, `n. carta`, `no de tarjeta`, `no do cartão`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero do cartao`, `número de tarjeta`, `número do cartão`, `tarjeta de credito`, `tarjeta de crédito` | 50 |

## Cryptocurrency (7 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Bitcoin Address (Bech32) | `bitcoin`, `btc`, `segwit`, `wallet` | 50 |
| Bitcoin Address (Legacy) | `bitcoin`, `btc`, `wallet`, `crypto` | 50 |
| Bitcoin Cash Address | `bitcoin cash`, `bch`, `wallet` | 50 |
| Ethereum Address | `ethereum`, `eth`, `ether`, `wallet`, `crypto` | 50 |
| Litecoin Address | `litecoin`, `ltc`, `wallet` | 50 |
| Monero Address | `monero`, `xmr`, `wallet` | 50 |
| Ripple Address | `ripple`, `xrp`, `wallet` | 50 |

## Customer Financial Data (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Account Balance | `balance`, `account balance`, `available balance`, `current balance`, `ledger balance`, `closing balance`, `solde`, `solde courant`, `solde disponible`, `solde du compte`, `guthaben`, `kontostand`, `saldo`, `saldo da conta`, `saldo de cuenta`, `saldo del conto` | 50 |
| Balance with Currency Code | `balance`, `amount`, `total`, `funds`, `available`, `ledger`, `solde`, `guthaben`, `kontostand`, `saldo` | 50 |
| DTI Ratio | `dti`, `debt-to-income`, `debt to income`, `dti ratio`, `debt ratio` | 50 |
| Income Amount | `income`, `salary`, `annual income`, `monthly income`, `gross income`, `net income`, `compensation`, `wages`, `earnings`, `revenu`, `revenu annuel`, `revenu brut`, `revenu mensuel`, `revenu net`, `salaire`, `einkommen`, `gehalt`, `ingreso`, `reddito`, `renda`, `rendimento`, `renta`, `salario`, `salário`, `stipendio`, `sueldo` | 50 |

## Data Classification Labels (8 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| CUI | `cui`, `controlled unclassified`, `sensitive information`, `marking` | 100 |
| Confidential Classification | `classified`, `confidential`, `national security`, `government`, `classifié`, `classifiée`, `confidentiel`, `confidentielle`, `als verschlusssache eingestuft`, `clasificada`, `clasificado`, `classificada`, `classificado`, `classificata`, `classificato`, `confidencial`, `confidenziale`, `eingestuft`, `riservato`, `vertraulich` | 100 |
| FOUO | `official use`, `fouo`, `government`, `not for public release` | 100 |
| LES | `law enforcement`, `sensitive`, `les`, `police`, `investigation` | 100 |
| NOFORN | `noforn`, `foreign nationals`, `not releasable`, `classification` | 100 |
| SBU | `sensitive`, `unclassified`, `sbu`, `government` | 100 |
| Secret Classification | `classified`, `secret`, `national security`, `clearance`, `noforn`, `classifié`, `classifiée`, `als verschlusssache eingestuft`, `clasificada`, `clasificado`, `classificada`, `classificado`, `classificata`, `classificato`, `eingestuft`, `geheim`, `secreto`, `segredo`, `segreto` | 100 |
| Top Secret | `classified`, `top secret`, `ts`, `sci`, `national security`, `clearance`, `classifié`, `classifiée`, `très secret`, `ultra secret`, `als verschlusssache eingestuft`, `alto secreto`, `clasificada`, `clasificado`, `classificada`, `classificado`, `classificata`, `classificato`, `eingestuft`, `segretissimo`, `streng geheim`, `ultra secreto`, `ultrasecreto`, `ultrassecreto` | 100 |

## Dates (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Date EU | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate`, `anniversaire`, `date de naissance`, `né le`, `née le`, `aniversario`, `aniversário`, `compleanno`, `cumpleaños`, `data de nascimento`, `data di nascita`, `fecha de nacimiento`, `geboren am`, `geburtsdatum`, `geburtstag`, `nacida el`, `nacido el`, `nascida em`, `nascido em`, `nata il`, `nato il` | 50 |
| Date ISO | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate`, `anniversaire`, `date de naissance`, `né le`, `née le`, `aniversario`, `aniversário`, `compleanno`, `cumpleaños`, `data de nascimento`, `data di nascita`, `fecha de nacimiento`, `geboren am`, `geburtsdatum`, `geburtstag`, `nacida el`, `nacido el`, `nascida em`, `nascido em`, `nata il`, `nato il` | 50 |
| Date US | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate`, `anniversaire`, `date de naissance`, `né le`, `née le`, `aniversario`, `aniversário`, `compleanno`, `cumpleaños`, `data de nascimento`, `data di nascita`, `fecha de nacimiento`, `geboren am`, `geburtsdatum`, `geburtstag`, `nacida el`, `nacido el`, `nascida em`, `nascido em`, `nata il`, `nato il` | 50 |

## Device Identifiers (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| ICCID | `iccid`, `sim card number`, `sim number`, `integrated circuit card`, `sim id`, `sim serial` | 50 |
| IDFA/IDFV | `idfa`, `idfv`, `advertising identifier`, `identifier for advertisers`, `vendor identifier`, `apple device id` | 50 |
| IMEI | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `phone imei`, `equipment identity` | 50 |
| IMEISV | `imeisv`, `imei software version`, `imei sv`, `software version number` | 50 |
| MEID | `meid`, `mobile equipment identifier`, `cdma device`, `equipment id` | 50 |

## Education Identifiers (1 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| EDU Email | `student email`, `edu email`, `university email`, `academic email`, `school email`, `college email` | 50 |

## Employment Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Employee ID | `employee id`, `employee number`, `emp id`, `staff id`, `personnel number`, `emp no`, `worker id`, `badge number`, `matricule`, `numéro d'employé`, `numéro du personnel`, `id de empleado`, `matricola`, `matrícula`, `mitarbeiternummer`, `numero dipendente`, `número de empleado`, `número do funcionário`, `personalnummer` | 50 |
| Work Permit Number | `work permit`, `work visa`, `employment authorization`, `ead`, `labor permit`, `work authorization`, `autorisation de travail`, `permis de travail`, `arbeitserlaubnis`, `arbeitsgenehmigung`, `autorização de trabalho`, `permesso di lavoro`, `permiso de trabajo`, `permissão de trabalho` | 50 |

## Europe - Austria (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Austria DL | `fuhrerschein`, `austrian driving`, `driving licence`, `permis de conduire` | 50 |
| Austria ID Card | `personalausweis`, `austrian id`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `tarjeta de identidad` | 50 |
| Austria Passport | `austrian passport`, `osterreichischer reisepass`, `reisepass` | 50 |
| Austria SVN | `sozialversicherungsnummer`, `svnr`, `sv-nummer`, `austrian social security`, `versicherungsnummer` | 50 |
| Austria Tax Number | `steuernummer`, `austrian tax`, `tax number`, `abgabenkontonummer`, `numéro d'impôt`, `numéro fiscal` | 50 |

## Europe - Belgium (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Belgium DL | `belgisch rijbewijs`, `belgian driving`, `permis de conduire belge` | 50 |
| Belgium NRN | `rijksregisternummer`, `nrn`, `national register number`, `registre national`, `insz` | 50 |
| Belgium Passport | `belgian passport`, `belgisch paspoort`, `passeport belge` | 50 |
| Belgium VAT | `btw`, `tva`, `belgian vat`, `ondernemingsnummer`, `numero entreprise` | 50 |

## Europe - Bulgaria (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Bulgaria EGN | `egn`, `edinen grazhdanski nomer`, `bulgarian personal`, `unified civil number` | 50 |
| Bulgaria ID Card | `lichna karta`, `bulgarian id`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Bulgaria LNC | `lnch`, `lichna karta`, `foreigner number`, `personal number of foreigner` | 50 |
| Bulgaria Passport | `bulgarian passport`, `bulgarski pasport` | 50 |

## Europe - Croatia (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Croatia DL | `vozacka dozvola`, `croatian driving`, `driving licence`, `permis de conduire` | 50 |
| Croatia ID Card | `osobna iskaznica`, `croatian id`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Croatia OIB | `oib`, `osobni identifikacijski broj`, `croatian personal`, `personal identification number` | 50 |
| Croatia Passport | `croatian passport`, `hrvatska putovnica` | 50 |

## Europe - Cyprus (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Cyprus ID Card | `cypriot id`, `identity card`, `taftotita`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Cyprus Passport | `cypriot passport`, `kypriako diavatirio` | 50 |
| Cyprus TIN | `cypriot tax`, `tin`, `tax identification`, `identification fiscale`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |

## Europe - Czech Republic (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Czech Birth Number | `rodne cislo`, `birth number`, `czech personal`, `rc` | 50 |
| Czech DL | `ridicsky prukaz`, `czech driving`, `driving licence`, `permis de conduire` | 50 |
| Czech ICO | `ico`, `identifikacni cislo`, `business id` | 50 |
| Czech Passport | `czech passport`, `cesky pas` | 50 |

## Europe - Denmark (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Denmark CPR | `cpr`, `personnummer`, `cpr-nummer`, `danish personal`, `civil registration` | 50 |
| Denmark DL | `korekort`, `danish driving`, `driving licence`, `permis de conduire` | 50 |
| Denmark Passport | `danish passport`, `dansk pas` | 50 |

## Europe - EU (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| EU ETD | `eu emergency travel document`, `etd`, `emergency travel` | 50 |
| EU VAT Generic | `vat number`, `vat registration`, `eu vat`, `value added tax` | 50 |

## Europe - Estonia (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Estonia DL | `juhiluba`, `estonian driving`, `driving licence`, `permis de conduire` | 50 |
| Estonia Isikukood | `isikukood`, `estonian personal`, `personal identification code`, `id-kood` | 50 |
| Estonia Passport | `estonian passport`, `eesti pass` | 50 |

## Europe - Finland (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Finland DL | `ajokortti`, `finnish driving`, `driving licence`, `permis de conduire` | 50 |
| Finland HETU | `henkilotunnus`, `hetu`, `finnish personal identity`, `personal identity code`, `henkilotunnus` | 50 |
| Finland Passport | `finnish passport`, `suomen passi` | 50 |

## Europe - France (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| France CNI | `carte nationale`, `carte identite`, `cni`, `french id card` | 50 |
| France DL | `permis de conduire`, `french driving`, `permis` | 50 |
| France IBAN | `iban`, `french bank`, `compte bancaire`, `rib` | 50 |
| France NIR | `insee`, `nir`, `securite sociale`, `french social security`, `numero de securite` | 50 |
| France Passport | `french passport`, `france passport`, `passeport` | 50 |

## Europe - Germany (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Germany DL | `fuhrerschein`, `driving licence`, `german driving`, `fahrerlaubnis`, `permis de conduire` | 50 |
| Germany IBAN | `iban`, `german bank`, `bankverbindung`, `kontonummer` | 50 |
| Germany ID | `personalausweis`, `german id`, `identification number`, `ausweisnummer` | 50 |
| Germany Passport | `german passport`, `germany passport`, `reisepass` | 50 |
| Germany Social Insurance | `sozialversicherungsnummer`, `social insurance`, `sv-nummer`, `rentenversicherung` | 50 |
| Germany Tax ID | `steueridentifikationsnummer`, `steuer-id`, `tax identification`, `tin`, `steuernummer`, `identification fiscale`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |

## Europe - Greece (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Greece AFM | `afm`, `arithmos forologikou mitroou`, `greek tax`, `tax number`, `numéro d'impôt`, `numéro fiscal` | 50 |
| Greece AMKA | `amka`, `social security`, `arithmos mitroou koinonikis asfalisis` | 50 |
| Greece DL | `adeia odigisis`, `greek driving`, `driving licence`, `permis de conduire` | 50 |
| Greece ID Card | `taftotita`, `greek id`, `deltio taftotitas`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Greece Passport | `greek passport`, `elliniko diavatirio` | 50 |

## Europe - Hungary (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Hungary DL | `jogositvany`, `hungarian driving`, `veztoi engedely` | 50 |
| Hungary Passport | `hungarian passport`, `magyar utlevel` | 50 |
| Hungary Personal ID | `szemelyazonosito`, `personal id`, `hungarian id`, `szemelyi szam` | 50 |
| Hungary TAJ | `taj szam`, `social security`, `taj`, `egeszsegbiztositasi` | 50 |
| Hungary Tax Number | `adoazonosito`, `tax number`, `hungarian tax`, `ado szam`, `numéro d'impôt`, `numéro fiscal` | 50 |

## Europe - Iceland (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Iceland Kennitala | `kennitala`, `icelandic id`, `personal id number`, `kt` | 50 |
| Iceland Passport | `icelandic passport`, `islenskt vegabref` | 50 |

## Europe - Ireland (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Ireland DL | `irish driving`, `driving licence`, `ceadunas tiomana`, `permis de conduire` | 50 |
| Ireland Eircode | `eircode`, `irish postcode`, `postal code` | 50 |
| Ireland PPS | `pps`, `ppsn`, `personal public service`, `pps number` | 50 |
| Ireland Passport | `irish passport`, `ireland passport` | 50 |

## Europe - Italy (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Italy Codice Fiscale | `codice fiscale`, `fiscal code`, `italian tax`, `cf` | 50 |
| Italy DL | `patente di guida`, `italian driving`, `patente` | 50 |
| Italy Partita IVA | `partita iva`, `vat number`, `p.iva`, `piva` | 50 |
| Italy Passport | `italian passport`, `italy passport`, `passaporto` | 50 |
| Italy SSN | `italian ssn`, `tessera sanitaria`, `health card`, `carte d'assurance maladie`, `carte santé` | 50 |

## Europe - Latvia (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Latvia DL | `vaditaja aplieciba`, `latvian driving`, `driving licence`, `permis de conduire` | 50 |
| Latvia Passport | `latvian passport`, `latvijas pase` | 50 |
| Latvia Personas Kods | `personas kods`, `latvian personal`, `personal code`, `pk` | 50 |

## Europe - Liechtenstein (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Liechtenstein PIN | `liechtenstein personal`, `personal identification`, `pin` | 50 |
| Liechtenstein Passport | `liechtenstein passport` | 50 |

## Europe - Lithuania (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Lithuania Asmens Kodas | `asmens kodas`, `lithuanian personal`, `personal code`, `ak` | 50 |
| Lithuania DL | `vairuotojo pazymejimas`, `lithuanian driving`, `driving licence`, `permis de conduire` | 50 |
| Lithuania Passport | `lithuanian passport`, `lietuvos pasas` | 50 |

## Europe - Luxembourg (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Luxembourg DL | `permis de conduire`, `luxembourg driving`, `driving licence` | 50 |
| Luxembourg NIN | `matricule`, `luxembourg id`, `national identification`, `nin` | 50 |
| Luxembourg Passport | `luxembourg passport`, `passeport` | 50 |

## Europe - Malta (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Malta ID Card | `maltese id`, `identity card`, `karta tal-identita`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Malta Passport | `maltese passport`, `passaport malti` | 50 |
| Malta TIN | `maltese tax`, `tin`, `tax identification`, `identification fiscale`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |

## Europe - Netherlands (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Netherlands BSN | `burgerservicenummer`, `bsn`, `citizen service number`, `sofinummer` | 50 |
| Netherlands DL | `rijbewijs`, `dutch driving`, `netherlands driving licence` | 50 |
| Netherlands IBAN | `iban`, `dutch bank`, `nl bank`, `rekeningnummer` | 50 |
| Netherlands Passport | `dutch passport`, `netherlands passport`, `nl passport` | 50 |

## Europe - Norway (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Norway D-Number | `d-nummer`, `d-number`, `norwegian temporary` | 50 |
| Norway DL | `forerkort`, `norwegian driving`, `driving licence`, `permis de conduire` | 50 |
| Norway FNR | `fodselsnummer`, `fnr`, `norwegian personal`, `birth number`, `personnummer` | 50 |
| Norway Passport | `norwegian passport`, `norsk pass` | 50 |

## Europe - Poland (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Poland DL | `prawo jazdy`, `polish driving`, `driving licence`, `permis de conduire` | 50 |
| Poland ID Card | `dowod osobisty`, `polish id card`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Poland NIP | `nip`, `numer identyfikacji podatkowej`, `tax identification`, `identification fiscale`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |
| Poland PESEL | `pesel`, `polish id`, `personal identification number`, `numer pesel` | 50 |
| Poland Passport | `polish passport`, `paszport` | 50 |
| Poland REGON | `regon`, `statistical number`, `business registration` | 50 |

## Europe - Portugal (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Portugal CC | `cartao cidadao`, `citizen card`, `cartao de cidadao`, `cc number` | 50 |
| Portugal NIF | `nif`, `contribuinte`, `tax identification`, `numero fiscal`, `identification fiscale`, `identificación tributaria`, `identificazione fiscale`, `identificação fiscal`, `steueridentifikation` | 50 |
| Portugal NISS | `niss`, `seguranca social`, `social security`, `numero seguranca` | 50 |
| Portugal Passport | `portuguese passport`, `passaporte` | 50 |

## Europe - Romania (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Romania CIF | `cif`, `cod identificare fiscala`, `romanian tax`, `fiscal code` | 50 |
| Romania CNP | `cnp`, `cod numeric personal`, `romanian personal`, `personal numeric code` | 50 |
| Romania DL | `permis de conducere`, `romanian driving`, `driving licence`, `permis de conduire` | 50 |
| Romania Passport | `romanian passport`, `pasaport` | 50 |

## Europe - Slovakia (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Slovakia Birth Number | `rodne cislo`, `birth number`, `slovak personal`, `rc` | 50 |
| Slovakia DL | `vodicsky preukaz`, `slovak driving`, `driving licence`, `permis de conduire` | 50 |
| Slovakia Passport | `slovak passport`, `slovensky pas` | 50 |

## Europe - Slovenia (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Slovenia DL | `voznisko dovoljenje`, `slovenian driving`, `driving licence`, `permis de conduire` | 50 |
| Slovenia EMSO | `emso`, `enotna maticna stevilka`, `slovenian personal`, `personal number` | 50 |
| Slovenia Passport | `slovenian passport`, `slovenski potni list` | 50 |
| Slovenia Tax Number | `davcna stevilka`, `slovenian tax`, `tax number`, `numéro d'impôt`, `numéro fiscal` | 50 |

## Europe - Spain (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Spain DL | `permiso de conducir`, `carnet de conducir`, `spanish driving` | 50 |
| Spain DNI | `dni`, `documento nacional de identidad`, `spanish id` | 50 |
| Spain NIE | `nie`, `numero de identidad de extranjero`, `foreigner id` | 50 |
| Spain NSS | `numero seguridad social`, `nss`, `spanish social security` | 50 |
| Spain Passport | `spanish passport`, `pasaporte`, `spain passport` | 50 |

## Europe - Sweden (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Sweden DL | `korkort`, `swedish driving`, `driving licence`, `permis de conduire` | 50 |
| Sweden Organisation Number | `organisationsnummer`, `org number`, `swedish company` | 50 |
| Sweden PIN | `personnummer`, `swedish id`, `personal identity number`, `swedish personal number` | 50 |
| Sweden Passport | `swedish passport`, `sverige pass` | 50 |

## Europe - Switzerland (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Switzerland AHV | `ahv`, `avs`, `swiss social security`, `ahv-nummer`, `oasi` | 50 |
| Switzerland DL | `fuhrerschein`, `swiss driving`, `fahrausweis`, `permis de conduire` | 50 |
| Switzerland Passport | `swiss passport`, `schweizer pass` | 50 |
| Switzerland UID | `uid`, `unternehmens-identifikationsnummer`, `swiss company`, `che number` | 50 |

## Europe - Turkey (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Turkey DL | `surucu belgesi`, `ehliyet`, `turkish driving` | 50 |
| Turkey Passport | `turkish passport`, `turk pasaportu` | 50 |
| Turkey TC Kimlik | `tc kimlik`, `turkish id`, `kimlik numarasi`, `tc no` | 50 |
| Turkey Tax ID | `vergi kimlik`, `vergi numarasi`, `turkish tax`, `vkn` | 50 |

## Europe - United Kingdom (7 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| British NHS | `nhs number`, `nhs no`, `national health service`, `nhs` | 50 |
| UK DL | `driving licence`, `driver licence`, `dvla`, `uk driving`, `uk dl`, `permis de conduire` | 50 |
| UK NIN | `national insurance number`, `nin`, `national insurance no`, `ni number` | 50 |
| UK Passport | `uk passport`, `british passport`, `united kingdom passport`, `hmpo` | 50 |
| UK Phone Number | `phone`, `telephone`, `tel`, `mobile`, `uk phone`, `cellulaire`, `portable`, `tél`, `téléphone`, `cellulare`, `celular`, `handy`, `mobiltelefon`, `móvil`, `telefon`, `telefone`, `telefono`, `telemóvel`, `teléfono` | 50 |
| UK Sort Code | `sort code`, `uk sort`, `bank sort`, `bank account`, `compte bancaire`, `compte de banque`, `bankkonto`, `conta bancaria`, `conta bancária`, `conto bancario`, `cuenta bancaria` | 50 |
| UK UTR | `unique taxpayer reference`, `utr`, `tax reference`, `self assessment` | 50 |

## Financial Regulatory Labels (7 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Draft Not for Circulation | `draft`, `circulation`, `preliminary`, `not final`, `review only`, `brouillon`, `provisoire`, `ébauche`, `borrador`, `bozza`, `entwurf`, `rascunho` | 80 |
| Information Barrier | `information barrier`, `chinese wall`, `wall crossing`, `restricted side`, `public side` | 80 |
| Inside Information | `inside information`, `insider`, `material`, `non-public`, `trading restriction` | 80 |
| Investment Restricted | `restricted list`, `watch list`, `grey list`, `restricted securities`, `trading restriction` | 80 |
| MNPI | `mnpi`, `material`, `non-public`, `insider`, `trading`, `securities` | 80 |
| Market Sensitive | `market sensitive`, `price sensitive`, `stock`, `securities`, `trading` | 80 |
| Pre-Decisional | `pre-decisional`, `draft`, `deliberative`, `not final`, `preliminary`, `brouillon`, `provisoire`, `ébauche`, `borrador`, `bozza`, `entwurf`, `rascunho` | 80 |

## Generic Secrets (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Bearer Token | `authorization`, `bearer`, `auth token` | 80 |
| Database Connection String | `database`, `db connection`, `connection string`, `mongodb`, `postgres`, `mysql`, `redis`, `base de données`, `chaîne de connexion`, `banca dati`, `banco de dados`, `base de datos`, `cadena de conexión`, `datenbank`, `string de conexão`, `stringa di connessione`, `verbindungszeichenfolge` | 80 |
| Generic API Key | `api key`, `api_key`, `apikey`, `api secret`, `clé api`, `api-schlüssel`, `chave api`, `chave de api`, `chiave api`, `clave api`, `clave de api` | 80 |
| Generic Secret Assignment | `password`, `secret`, `credential`, `passwd`, `identifiant`, `justificatif`, `mot de passe`, `anmeldedaten`, `contrasena`, `contraseña`, `credencial`, `credenziali`, `geheim`, `kennwort`, `passwort`, `secreto`, `segredo`, `segreto`, `senha`, `zugangsdaten` | 80 |
| JWT Token | `jwt`, `json web token`, `auth`, `token`, `jeton`, `zugriffstoken` | 80 |
| Private Key | `private key`, `rsa`, `ssh key`, `pem`, `clé privée`, `chave privada`, `chiave privata`, `clave privada`, `privater schlüssel` | 80 |

## Geolocation (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| GPS Coordinates | `latitude`, `longitude`, `lat`, `lng`, `lon`, `coordinates`, `gps`, `geolocation`, `location`, `coord` | 50 |
| GPS DMS | `latitude`, `longitude`, `coordinates`, `gps`, `dms`, `degrees minutes seconds` | 50 |
| Geohash | `geohash`, `geo hash`, `location hash` | 50 |

## Insurance Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Insurance Claim Number | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number`, `no de réclamation`, `numéro de réclamation`, `antragsnummer`, `numero de reclamo`, `numero di sinistro`, `número de reclamo`, `número de sinistro`, `schadensnummer` | 50 |
| Insurance Policy Number | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#`, `no de police`, `numéro de police`, `police d'assurance`, `apolice de seguro`, `apólice de seguro`, `numero da apolice`, `numero de poliza`, `numero di polizza`, `número da apólice`, `número de póliza`, `policennummer`, `poliza de seguro`, `polizza assicurativa`, `póliza de seguro`, `versicherungsnummer`, `versicherungspolice` | 50 |

## Internal Banking References (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Internal Account Ref | `internal reference`, `account reference`, `internal id`, `system id`, `core banking id` | 50 |
| Teller ID | `teller id`, `teller number`, `officer id`, `banker id`, `employee id`, `user id`, `matricule`, `numéro d'employé`, `id de empleado`, `matricola`, `matrícula`, `mitarbeiternummer`, `numero dipendente`, `número de empleado`, `número do funcionário`, `personalnummer` | 50 |

## Latin America - Argentina (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Argentina CUIL/CUIT | `cuil`, `cuit`, `clave unica`, `identificacion tributaria`, `afip` | 50 |
| Argentina DNI | `dni`, `documento nacional de identidad`, `documento nacional`, `identidad`, `renaper` | 50 |
| Argentina Passport | `pasaporte`, `argentinian passport`, `argentina passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Latin America - Brazil (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Brazil CNH | `cnh`, `carteira de habilitacao`, `habilitacao`, `driving licence`, `carteira nacional`, `permis de conduire` | 50 |
| Brazil CNPJ | `cnpj`, `cadastro nacional`, `pessoa juridica`, `empresa`, `razao social` | 50 |
| Brazil CPF | `cpf`, `cadastro de pessoas fisicas`, `cadastro pessoa fisica`, `contribuinte`, `receita federal` | 50 |
| Brazil Passport | `passaporte`, `brazilian passport`, `brazil passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Brazil RG | `rg`, `registro geral`, `identidade`, `carteira de identidade`, `documento de identidade` | 50 |
| Brazil SUS Card | `sus`, `cartao nacional de saude`, `cns`, `saude`, `cartao sus` | 50 |

## Latin America - Chile (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Chile Passport | `pasaporte`, `chilean passport`, `chile passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Chile RUN/RUT | `rut`, `run`, `rol unico tributario`, `rol unico nacional`, `cedula identidad` | 50 |

## Latin America - Colombia (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Colombia Cedula | `cedula`, `cedula de ciudadania`, `cc`, `documento identidad`, `registraduria` | 50 |
| Colombia NIT | `nit`, `numero de identificacion tributaria`, `dian`, `contribuyente`, `tax id`, `identifiant fiscal`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |
| Colombia NUIP | `nuip`, `numero unico de identificacion personal`, `identificacion personal`, `tarjeta identidad` | 50 |
| Colombia Passport | `pasaporte`, `colombian passport`, `colombia passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Latin America - Costa Rica (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Costa Rica Cedula | `cedula`, `cedula de identidad`, `tse`, `costarricense`, `tribunal supremo` | 50 |
| Costa Rica DIMEX | `dimex`, `documento migratorio`, `extranjero`, `migracion`, `residencia` | 50 |
| Costa Rica Passport | `pasaporte`, `costa rican passport`, `costa rica passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Latin America - Ecuador (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Ecuador Cedula | `cedula`, `cedula de identidad`, `cedula ciudadania`, `registro civil`, `identidad` | 50 |
| Ecuador Passport | `pasaporte`, `ecuadorian passport`, `ecuador passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Ecuador RUC | `ruc`, `registro unico de contribuyentes`, `sri`, `contribuyente`, `tax id`, `identifiant fiscal`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Latin America - Paraguay (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Paraguay Cedula | `cedula`, `cedula de identidad`, `identidad civil`, `documento identidad`, `policia nacional` | 50 |
| Paraguay Passport | `pasaporte`, `paraguayan passport`, `paraguay passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Paraguay RUC | `ruc`, `registro unico de contribuyentes`, `set`, `dnit`, `contribuyente` | 50 |

## Latin America - Peru (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Peru Carnet Extranjeria | `carnet de extranjeria`, `carnet extranjeria`, `ce`, `migraciones`, `extranjero` | 50 |
| Peru DNI | `dni`, `documento nacional de identidad`, `reniec`, `identidad`, `documento identidad` | 50 |
| Peru Passport | `pasaporte`, `peruvian passport`, `peru passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Peru RUC | `ruc`, `registro unico de contribuyentes`, `sunat`, `contribuyente`, `tax id`, `identifiant fiscal`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Latin America - Uruguay (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Uruguay Cedula | `cedula`, `cedula de identidad`, `documento identidad`, `identidad`, `dnic` | 50 |
| Uruguay Passport | `pasaporte`, `uruguayan passport`, `uruguay passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Uruguay RUT | `rut`, `registro unico tributario`, `dgi`, `contribuyente`, `tax id`, `identifiant fiscal`, `numéro fiscal`, `codice fiscale`, `identificación fiscal`, `nif`, `número fiscal`, `partita iva`, `steuer-id`, `steuernummer` | 50 |

## Latin America - Venezuela (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Venezuela Cedula | `cedula`, `cedula de identidad`, `ci`, `saime`, `venezolano` | 50 |
| Venezuela Passport | `pasaporte`, `venezuelan passport`, `venezuela passport`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Venezuela RIF | `rif`, `registro de informacion fiscal`, `seniat`, `fiscal`, `contribuyente` | 50 |

## Legal Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Court Docket Number | `docket number`, `docket no`, `court case`, `case file`, `case reference`, `court number` | 50 |
| US Federal Case Number | `case number`, `case no`, `docket`, `civil action`, `case#`, `filing number` | 50 |

## Loan and Mortgage Data (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| LTV Ratio | `ltv`, `loan-to-value`, `loan to value`, `ltv ratio`, `combined ltv`, `cltv` | 50 |
| Loan Number | `loan number`, `loan no`, `loan id`, `loan account`, `loan#`, `lending number`, `compte de prêt`, `numéro de prêt` | 50 |
| MERS MIN | `mers`, `mortgage identification number`, `min number`, `mers min`, `mortgage electronic` | 50 |
| Universal Loan Identifier | `uli`, `universal loan identifier`, `hmda`, `loan identifier` | 50 |

## Medical Identifiers (4 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| DEA Number | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance`, `contrôle des drogues` | 50 |
| Health Plan ID | `health plan`, `insurance id`, `beneficiary`, `member id`, `subscriber id`, `bénéficiaire`, `no d'assurance`, `numéro d'abonné`, `numéro d'assurance`, `numéro de membre`, `régime d'assurance maladie`, `régime de santé`, `assicurazione sanitaria`, `begunstigter`, `begünstigter`, `beneficiario`, `gesundheitsplan`, `krankenversicherung`, `numero de seguro`, `numero di assicurazione`, `número de seguro`, `número do seguro`, `piano sanitario`, `plan de salud`, `plano de saude`, `plano de saúde`, `seguro de salud`, `versicherungsnummer` | 50 |
| ICD-10 Code | `icd`, `icd-10`, `diagnosis code`, `diagnostic code`, `condition code`, `icd code`, `code de diagnostic`, `codice di diagnosi`, `código de diagnóstico`, `diagnosecode`, `diagnoseschlüssel` | 50 |
| NDC Code | `ndc`, `national drug code`, `drug code`, `medication code`, `pharmaceutical`, `code de médicament`, `code national de médicament` | 50 |

## Messaging Service Secrets (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Mailgun API Key | `mailgun`, `email`, `courriel`, `courrier électronique`, `correio eletronico`, `correio eletrônico`, `correo`, `correo electrónico`, `e-mail-adresse`, `posta elettronica` | 80 |
| SendGrid API Key | `sendgrid`, `email api` | 80 |
| Slack Bot Token | `slack`, `bot token`, `slack bot` | 80 |
| Slack User Token | `slack`, `user token`, `slack user` | 80 |
| Slack Webhook | `slack`, `webhook`, `incoming webhook` | 80 |
| Twilio API Key | `twilio`, `sms`, `messaging` | 80 |

## Middle East - Bahrain (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Bahrain CPR | `cpr`, `central population registration`, `bahrain id`, `personal number`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Bahrain Passport | `bahraini passport`, `bahrain passport`, `passport number`, `passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `pasaporte`, `passaporte`, `passaporto`, `passnummer`, `reisepass`, `reisepassnummer` | 50 |

## Middle East - Iran (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Iran Melli Code | `melli code`, `shomareh melli`, `kart melli`, `national code`, `iranian id` | 50 |
| Iran Passport | `iranian passport`, `iran passport`, `passport number`, `gozarnameh`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Middle East - Iraq (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Iraq National ID | `national card`, `bitaqa wataniya`, `iraqi id`, `civil status`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Iraq Passport | `iraqi passport`, `iraq passport`, `passport number`, `passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `pasaporte`, `passaporte`, `passaporto`, `passnummer`, `reisepass`, `reisepassnummer` | 50 |

## Middle East - Israel (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Israel Passport | `israeli passport`, `israel passport`, `darkon`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Israel Teudat Zehut | `teudat zehut`, `mispar zehut`, `identity number`, `israeli id`, `zehut`, `numéro d'identité` | 50 |

## Middle East - Jordan (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Jordan National ID | `national number`, `raqam watani`, `jordanian id`, `civil status`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Jordan Passport | `jordanian passport`, `jordan passport`, `passport number`, `passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `pasaporte`, `passaporte`, `passaporto`, `passnummer`, `reisepass`, `reisepassnummer` | 50 |

## Middle East - Kuwait (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Kuwait Civil ID | `civil id`, `paci`, `kuwait id`, `civil information`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| Kuwait Passport | `kuwaiti passport`, `kuwait passport`, `passport number`, `passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `pasaporte`, `passaporte`, `passaporto`, `passnummer`, `reisepass`, `reisepassnummer` | 50 |

## Middle East - Lebanon (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Lebanon ID | `lebanese id`, `national id`, `identity card`, `hawiyya`, `interior ministry`, `carte d'identité`, `carte nationale d'identité`, `identité nationale`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis`, `tarjeta de identidad` | 50 |
| Lebanon Passport | `lebanese passport`, `lebanon passport`, `passport number`, `general security`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Middle East - Qatar (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Qatar Passport | `qatar passport`, `qatari passport`, `passport number`, `jawaz`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| Qatar QID | `qid`, `qatar id`, `resident permit`, `moi qatar`, `identity card`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |

## Middle East - Saudi Arabia (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Saudi Arabia National ID | `national id`, `iqama`, `saudi id`, `huwiyya`, `ministry of interior`, `carte nationale d'identité`, `identité nationale`, `documento d'identità`, `documento de identidade`, `documento nacional`, `identidade nacional`, `identificación nacional`, `personalausweis` | 50 |
| Saudi Arabia Passport | `saudi passport`, `saudi arabia passport`, `jawaz safar`, `passport number`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |

## Middle East - UAE (3 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| UAE Emirates ID | `emirates id`, `eid`, `uae id`, `identity card`, `federal authority`, `carte d'identité`, `pièce d'identité`, `bilhete de identidade`, `carta d'identità`, `carta di identità`, `cartão de identidade`, `cédula de identidad`, `personalausweis`, `tarjeta de identidad` | 50 |
| UAE Passport | `uae passport`, `emirati passport`, `passport number`, `passport`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `pasaporte`, `passaporte`, `passaporto`, `passnummer`, `reisepass`, `reisepassnummer` | 50 |
| UAE Visa Number | `visa number`, `entry permit`, `uae visa`, `residence visa`, `visa file` | 50 |

## North America - Canada (29 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Alberta DL | `alberta driver's licence`, `alberta dl`, `ab dl` | 50 |
| Alberta HC | `ahcip`, `alberta health card`, `alberta phn`, `alberta health care insurance`, `ab health` | 50 |
| BC HC | `bc msp`, `medical services plan`, `bc health card`, `bc phn`, `personal health number` | 50 |
| British Columbia DL | `british columbia driver's licence`, `bc dl`, `bc driver's licence` | 50 |
| Canada BN | `business number`, `canada bn`, `cra business`, `numéro d'entreprise` | 50 |
| Canada Bank Code | `transit number`, `institution number`, `bank transit` | 50 |
| Canada NEXUS | `nexus`, `nexus card`, `pass id`, `trusted traveler`, `nexus number`, `cbp pass` | 50 |
| Canada PR Card | `permanent resident`, `pr card`, `permanent resident card`, `immigration`, `landed immigrant`, `carte de résident permanent`, `carte rp`, `résident permanent`, `résidente permanente` | 50 |
| Canada Passport | `canadian passport`, `canada passport`, `passport canada`, `passeport canadien`, `passeport du canada` | 50 |
| Canada SIN | `social insurance number`, `sin`, `social insurance no`, `nas`, `no d'assurance sociale`, `numéro d'assurance sociale` | 50 |
| Manitoba DL | `manitoba driver's licence`, `manitoba dl`, `mb dl` | 50 |
| Manitoba HC | `manitoba phin`, `manitoba health card`, `mb health`, `personal health identification number` | 50 |
| NWT DL | `northwest territories driver's licence`, `nwt dl`, `nt dl` | 50 |
| New Brunswick DL | `new brunswick driver's licence`, `new brunswick dl`, `nb dl` | 50 |
| New Brunswick HC | `new brunswick health card`, `nb medicare`, `nb health`, `new brunswick medicare` | 50 |
| Newfoundland DL | `newfoundland driver's licence`, `newfoundland dl`, `nl dl`, `labrador dl` | 50 |
| Newfoundland HC | `newfoundland mcp`, `mcp card`, `mcp number`, `medical care plan`, `nl health card` | 50 |
| Nova Scotia DL | `nova scotia driver's licence`, `nova scotia dl`, `ns dl` | 50 |
| Nova Scotia HC | `nova scotia msi`, `msi card`, `msi number`, `nova scotia health card`, `ns health` | 50 |
| Nunavut DL | `nunavut driver's licence`, `nunavut dl`, `nu dl` | 50 |
| Ontario DL | `ontario driver's licence`, `ontario dl`, `on dl` | 50 |
| Ontario HC | `ohip`, `ontario health card`, `ontario health insurance`, `health card number`, `ohip number` | 50 |
| PEI DL | `pei driver's licence`, `prince edward island dl`, `pe dl` | 50 |
| PEI HC | `pei health card`, `prince edward island health`, `pe health card` | 50 |
| Quebec DL | `quebec driver's licence`, `quebec dl`, `qc dl`, `permis de conduire` | 50 |
| Quebec HC | `ramq`, `carte soleil`, `quebec health card`, `regie assurance maladie`, `health insurance quebec` | 50 |
| Saskatchewan DL | `saskatchewan driver's licence`, `saskatchewan dl`, `sk dl` | 50 |
| Saskatchewan HC | `saskatchewan health card`, `sk health`, `sk phn`, `saskatchewan health number` | 50 |
| Yukon DL | `yukon driver's licence`, `yukon dl`, `yt dl` | 50 |

## North America - Mexico (7 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Mexico CURP | `curp`, `clave unica`, `clave unica de registro`, `registro de poblacion`, `population registry` | 50 |
| Mexico Clave Elector | `clave de elector`, `credencial para votar`, `credencial elector`, `ine`, `ife`, `voter credential` | 50 |
| Mexico INE CIC | `cic`, `codigo de identificacion`, `ine cic`, `credential identification code` | 50 |
| Mexico INE OCR | `ocr`, `ine ocr`, `optical character recognition`, `credencial ocr` | 50 |
| Mexico NSS | `nss`, `numero de seguro social`, `imss`, `seguro social`, `instituto mexicano del seguro social` | 50 |
| Mexico Passport | `pasaporte mexicano`, `mexico passport`, `mexican passport`, `pasaporte` | 50 |
| Mexico RFC | `rfc`, `registro federal`, `registro federal de contribuyentes`, `federal taxpayer`, `tax id mexico` | 50 |

## North America - US Generic DL (1 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Generic US DL | `driver's license`, `dl number`, `driving license`, `license id`, `driver license`, `drivers license`, `licence number`, `license number`, `dl no`, `no de permis`, `numéro de permis`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |

## North America - United States (63 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Alabama DL | `driver license`, `drivers license`, `driver's license`, `dl`, `alabama dl`, `alabama license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Alaska DL | `driver license`, `drivers license`, `driver's license`, `dl`, `alaska dl`, `alaska license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Arizona DL | `driver license`, `drivers license`, `driver's license`, `dl`, `arizona dl`, `arizona license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Arkansas DL | `driver license`, `drivers license`, `driver's license`, `dl`, `arkansas dl`, `arkansas license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| California DL | `driver license`, `drivers license`, `driver's license`, `dl`, `california dl`, `california license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Colorado DL | `driver license`, `drivers license`, `driver's license`, `dl`, `colorado dl`, `colorado license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Connecticut DL | `driver license`, `drivers license`, `driver's license`, `dl`, `connecticut dl`, `connecticut license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| DC DL | `driver license`, `drivers license`, `driver's license`, `dl`, `dc dl`, `district of columbia license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Delaware DL | `driver license`, `drivers license`, `driver's license`, `dl`, `delaware dl`, `delaware license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Florida DL | `driver license`, `drivers license`, `driver's license`, `dl`, `florida dl`, `florida license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Georgia DL | `driver license`, `drivers license`, `driver's license`, `dl`, `georgia dl`, `georgia license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Hawaii DL | `driver license`, `drivers license`, `driver's license`, `dl`, `hawaii dl`, `hawaii license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Idaho DL | `driver license`, `drivers license`, `driver's license`, `dl`, `idaho dl`, `idaho license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Illinois DL | `driver license`, `drivers license`, `driver's license`, `dl`, `illinois dl`, `illinois license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Indiana DL | `driver license`, `drivers license`, `driver's license`, `dl`, `indiana dl`, `indiana license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Iowa DL | `driver license`, `drivers license`, `driver's license`, `dl`, `iowa dl`, `iowa license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Kansas DL | `driver license`, `drivers license`, `driver's license`, `dl`, `kansas dl`, `kansas license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Kentucky DL | `driver license`, `drivers license`, `driver's license`, `dl`, `kentucky dl`, `kentucky license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Louisiana DL | `driver license`, `drivers license`, `driver's license`, `dl`, `louisiana dl`, `louisiana license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Maine DL | `driver license`, `drivers license`, `driver's license`, `dl`, `maine dl`, `maine license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Maryland DL | `driver license`, `drivers license`, `driver's license`, `dl`, `maryland dl`, `maryland license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Massachusetts DL | `driver license`, `drivers license`, `driver's license`, `dl`, `massachusetts dl`, `massachusetts license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Michigan DL | `driver license`, `drivers license`, `driver's license`, `dl`, `michigan dl`, `michigan license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Minnesota DL | `driver license`, `drivers license`, `driver's license`, `dl`, `minnesota dl`, `minnesota license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Mississippi DL | `driver license`, `drivers license`, `driver's license`, `dl`, `mississippi dl`, `mississippi license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Missouri DL | `driver license`, `drivers license`, `driver's license`, `dl`, `missouri dl`, `missouri license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Montana DL | `driver license`, `drivers license`, `driver's license`, `dl`, `montana dl`, `montana license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Nebraska DL | `driver license`, `drivers license`, `driver's license`, `dl`, `nebraska dl`, `nebraska license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Nevada DL | `driver license`, `drivers license`, `driver's license`, `dl`, `nevada dl`, `nevada license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| New Hampshire DL | `driver license`, `drivers license`, `driver's license`, `dl`, `new hampshire dl`, `new hampshire license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| New Jersey DL | `driver license`, `drivers license`, `driver's license`, `dl`, `new jersey dl`, `new jersey license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| New Mexico DL | `driver license`, `drivers license`, `driver's license`, `dl`, `new mexico dl`, `new mexico license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| New York DL | `driver license`, `drivers license`, `driver's license`, `dl`, `new york dl`, `new york license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| North Carolina DL | `driver license`, `drivers license`, `driver's license`, `dl`, `north carolina dl`, `north carolina license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| North Dakota DL | `driver license`, `drivers license`, `driver's license`, `dl`, `north dakota dl`, `north dakota license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Ohio DL | `driver license`, `drivers license`, `driver's license`, `dl`, `ohio dl`, `ohio license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Oklahoma DL | `driver license`, `drivers license`, `driver's license`, `dl`, `oklahoma dl`, `oklahoma license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Oregon DL | `driver license`, `drivers license`, `driver's license`, `dl`, `oregon dl`, `oregon license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Pennsylvania DL | `driver license`, `drivers license`, `driver's license`, `dl`, `pennsylvania dl`, `pennsylvania license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Rhode Island DL | `driver license`, `drivers license`, `driver's license`, `dl`, `rhode island dl`, `rhode island license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| South Carolina DL | `driver license`, `drivers license`, `driver's license`, `dl`, `south carolina dl`, `south carolina license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| South Dakota DL | `driver license`, `drivers license`, `driver's license`, `dl`, `south dakota dl`, `south dakota license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Tennessee DL | `driver license`, `drivers license`, `driver's license`, `dl`, `tennessee dl`, `tennessee license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Texas DL | `driver license`, `drivers license`, `driver's license`, `dl`, `texas dl`, `texas license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| US DEA Number | `dea number`, `dea registration`, `dea no`, `drug enforcement`, `contrôle des drogues` | 50 |
| US DoD ID | `dod id`, `military id`, `edipi`, `cac card`, `common access card`, `department of defense` | 50 |
| US Known Traveler Number | `known traveler`, `ktn`, `global entry`, `trusted traveler`, `pass id`, `nexus`, `sentri` | 50 |
| US MBI | `mbi`, `medicare beneficiary`, `beneficiary identifier`, `medicare number`, `medicare id` | 50 |
| US NPI | `npi`, `national provider identifier`, `provider number` | 50 |
| US Phone Number | `phone`, `telephone`, `tel`, `cell`, `mobile`, `call`, `fax`, `cellulaire`, `portable`, `tél`, `téléphone`, `cellulare`, `celular`, `handy`, `mobiltelefon`, `móvil`, `telefon`, `telefone`, `telefono`, `telemóvel`, `teléfono` | 50 |
| USA EIN | `employer identification`, `ein`, `federal tax id`, `fein` | 50 |
| USA ITIN | `individual taxpayer`, `itin`, `taxpayer identification` | 50 |
| USA Passport | `us passport`, `usa passport`, `american passport`, `passport number`, `passport book`, `no de passeport`, `numéro de passeport`, `numero de pasaporte`, `numero di passaporto`, `numero do passaporte`, `número de pasaporte`, `número do passaporte`, `passnummer`, `reisepassnummer` | 50 |
| USA Passport Card | `passport card`, `us passport card`, `usa passport card` | 50 |
| USA Routing Number | `routing number`, `aba routing`, `routing transit`, `numero de transit`, `numéro de transit`, `bankleitzahl`, `blz`, `codice di instradamento`, `número de encaminhamento`, `número de ruta` | 50 |
| USA SSN | `social security number`, `ssn`, `social security no`, `numéro d'assurance sociale`, `numéro de sécurité sociale`, `numero de seguro social`, `numero di previdenza sociale`, `número de segurança social`, `número de seguro social`, `sozialversicherungsnummer` | 50 |
| Utah DL | `driver license`, `drivers license`, `driver's license`, `dl`, `utah dl`, `utah license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Vermont DL | `driver license`, `drivers license`, `driver's license`, `dl`, `vermont dl`, `vermont license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Virginia DL | `driver license`, `drivers license`, `driver's license`, `dl`, `virginia dl`, `virginia license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Washington DL | `driver license`, `drivers license`, `driver's license`, `dl`, `washington dl`, `washington license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| West Virginia DL | `driver license`, `drivers license`, `driver's license`, `dl`, `west virginia dl`, `west virginia license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Wisconsin DL | `driver license`, `drivers license`, `driver's license`, `dl`, `wisconsin dl`, `wisconsin license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |
| Wyoming DL | `driver license`, `drivers license`, `driver's license`, `dl`, `wyoming dl`, `wyoming license`, `permis de conduire`, `carta de condução`, `carteira de habilitação`, `carteira de motorista`, `fuhrerschein`, `führerschein`, `licencia de conducir`, `patente di guida`, `permiso de conducir` | 50 |

## PCI Sensitive Data (1 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Cardholder Name Pattern | `cardholder`, `cardholder name`, `name on card`, `card holder`, `card member`, `détenteur de carte`, `membre de la carte`, `nom du titulaire`, `nom sur la carte`, `titulaire de la carte`, `karteninhaber`, `titolare della carta`, `titular de la tarjeta`, `titular do cartão` | 30 |

## Payment Service Secrets (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Stripe Publishable Key | `stripe`, `publishable`, `stripe key` | 80 |
| Stripe Secret Key | `stripe`, `payment`, `stripe secret` | 80 |

## Personal Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Date of Birth | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b`, `anniversaire`, `date de naissance`, `né le`, `née le`, `aniversario`, `aniversário`, `compleanno`, `cumpleaños`, `data de nascimento`, `data di nascita`, `fecha de nacimiento`, `geboren am`, `geburtsdatum`, `geburtstag`, `nacida el`, `nacido el`, `nascida em`, `nascido em`, `nata il`, `nato il` | 30 |
| Gender Marker | `gender`, `sex`, `identified as`, `gender identity`, `biological sex`, `genre`, `sexe`, `genere`, `genero`, `geschlecht`, `género`, `gênero`, `sesso`, `sexo` | 30 |

## Postal Codes (5 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Brazil CEP | `cep`, `codigo postal`, `brazilian address` | 50 |
| Canada Postal Code | `postal code`, `code postal`, `canadian address` | 50 |
| Japan Postal Code | `postal code`, `yubin bangou`, `japanese address` | 50 |
| UK Postcode | `postcode`, `post code`, `postal code`, `uk address` | 50 |
| US ZIP+4 Code | `zip`, `zip code`, `zipcode`, `postal code`, `mailing address`, `zip+4` | 50 |

## Primary Account Numbers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Masked PAN | `masked pan`, `truncated pan`, `masked card`, `truncated card`, `last four`, `first six` | 50 |
| PAN | `pan`, `primary account number`, `account number`, `card number`, `cardholder number`, `full card`, `no de carte`, `no de compte`, `numero de carte`, `numero de compte`, `numéro de carte`, `numéro de compte`, `kartennummer`, `kontonummer`, `numero da conta`, `numero de cuenta`, `numero de tarjeta`, `numero della carta`, `numero di carta`, `numero di conto`, `numero do cartao`, `número da conta`, `número de cuenta`, `número de tarjeta`, `número do cartão` | 50 |

## Privacy Classification (10 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| CCPA/CPRA | `ccpa`, `cpra`, `california consumer`, `california privacy`, `consumer rights` | 80 |
| FERPA | `ferpa`, `educational records`, `student records`, `student privacy` | 80 |
| GDPR Personal Data | `gdpr`, `personal data`, `data subject`, `data protection`, `eu regulation`, `données personnelles`, `données à caractère personnel`, `protection des données`, `dados pessoais`, `datenschutz`, `dati personali`, `datos personales`, `personenbezogene daten`, `protección de datos`, `protezione dei dati`, `proteção de dados` | 80 |
| GLBA | `glba`, `gramm-leach-bliley`, `financial privacy`, `consumer financial`, `confidentialité financière` | 80 |
| HIPAA | `hipaa`, `health insurance portability`, `medical privacy`, `health data`, `confidentialité médicale` | 80 |
| NPI | `npi`, `non-public personal`, `financial privacy`, `glba`, `consumer information`, `confidentialité financière` | 80 |
| PCI-DSS | `pci`, `pci-dss`, `cardholder data`, `payment card`, `card data environment` | 80 |
| PHI Label | `phi`, `protected health`, `health information`, `medical records`, `patient data`, `informations de santé`, `renseignements sur la santé` | 80 |
| PII Label | `pii`, `personally identifiable`, `personal information`, `sensitive data`, `données personnelles`, `informations personnelles`, `renseignements personnels`, `dati personali identificabili`, `información personal`, `información personal identificable`, `informazioni personali`, `informação pessoal identificável`, `informações pessoais`, `personenbezogene daten`, `persönliche informationen` | 80 |
| SOX | `sox`, `sarbanes-oxley`, `financial reporting`, `internal controls`, `audit` | 80 |

## Privileged Information (7 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Attorney-Client Privilege | `attorney`, `client`, `privilege`, `legal counsel`, `law firm`, `privileged communication`, `avocat`, `avocate`, `privilège`, `abogada`, `abogado`, `advogada`, `advogado`, `anwalt`, `avvocata`, `avvocato`, `privileg`, `privilegio`, `privilégio`, `rechtsanwalt` | 100 |
| Legal Privilege | `legal`, `privilege`, `attorney`, `counsel`, `protected communication`, `avocat`, `avocate`, `conseiller juridique`, `juridique`, `légal`, `privilège`, `abogada`, `abogado`, `advogada`, `advogado`, `anwalt`, `avvocata`, `avvocato`, `giuridico`, `juridico`, `juristisch`, `jurídico`, `legale`, `privileg`, `privilegio`, `privilégio`, `rechtlich`, `rechtsanwalt` | 100 |
| Litigation Hold | `litigation`, `legal hold`, `preservation`, `hold notice`, `document retention`, `contentieux`, `litige`, `mise en suspens juridique`, `blocco legale`, `litigio`, `litígio`, `prozess`, `rechtliche aufbewahrungspflicht`, `rechtsstreit`, `retención legal`, `retenção legal` | 100 |
| Privileged Information | `privileged`, `legal`, `attorney`, `counsel`, `protected`, `avocat`, `avocate`, `conseiller juridique`, `juridique`, `légal`, `privilégié`, `privilégiée`, `abogada`, `abogado`, `advogada`, `advogado`, `anwalt`, `avvocata`, `avvocato`, `giuridico`, `juridico`, `juristisch`, `jurídico`, `legale`, `rechtlich`, `rechtsanwalt` | 100 |
| Privileged and Confidential | `privileged`, `confidential`, `legal`, `attorney`, `counsel`, `avocat`, `avocate`, `confidentiel`, `confidentielle`, `conseiller juridique`, `juridique`, `légal`, `privilégié`, `privilégiée`, `abogada`, `abogado`, `advogada`, `advogado`, `anwalt`, `avvocata`, `avvocato`, `confidencial`, `confidenziale`, `giuridico`, `juridico`, `juristisch`, `jurídico`, `legale`, `rechtlich`, `rechtsanwalt`, `riservato`, `vertraulich` | 100 |
| Protected by Privilege | `privilege`, `protected`, `attorney`, `legal`, `exempt from disclosure`, `avocat`, `avocate`, `juridique`, `légal`, `privilège`, `abogada`, `abogado`, `advogada`, `advogado`, `anwalt`, `avvocata`, `avvocato`, `giuridico`, `juridico`, `juristisch`, `jurídico`, `legale`, `privileg`, `privilegio`, `privilégio`, `rechtlich`, `rechtsanwalt` | 100 |
| Work Product | `work product`, `attorney`, `litigation`, `legal`, `prepared in anticipation`, `avocat`, `avocate`, `contentieux`, `juridique`, `litige`, `légal`, `produit du travail`, `abogada`, `abogado`, `advogada`, `advogado`, `anwalt`, `avvocata`, `avvocato`, `giuridico`, `juridico`, `juristisch`, `jurídico`, `legale`, `litigio`, `litígio`, `prozess`, `rechtlich`, `rechtsanwalt`, `rechtsstreit` | 100 |

## Property Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Parcel Number | `parcel number`, `apn`, `assessor parcel`, `parcel id`, `lot number`, `property id` | 50 |
| Title Deed Number | `title number`, `deed number`, `deed of trust`, `title deed`, `land title`, `property title` | 50 |

## Regulatory Identifiers (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| AML Case ID | `aml`, `anti-money laundering`, `money laundering`, `aml case`, `aml investigation`, `bsa` | 50 |
| CTR Number | `ctr`, `currency transaction report`, `ctr filing`, `ctr number`, `cash transaction` | 50 |
| Compliance Case Number | `compliance case`, `investigation number`, `regulatory case`, `compliance id`, `audit case`, `examination number` | 50 |
| FinCEN Report Number | `fincen`, `financial crimes`, `fincen report`, `fincen filing`, `bsa filing` | 50 |
| OFAC SDN Entry | `ofac`, `sdn`, `specially designated`, `sanctions`, `ofac list`, `blocked persons` | 50 |
| SAR Filing Number | `sar`, `suspicious activity report`, `sar filing`, `sar number`, `suspicious activity` | 50 |

## Securities Identifiers (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| CUSIP | `cusip`, `committee on uniform securities`, `security identifier`, `bond cusip`, `cusip number` | 50 |
| FIGI | `figi`, `financial instrument global identifier`, `bloomberg`, `bbg`, `openfigi` | 50 |
| ISIN | `isin`, `international securities`, `securities identification`, `isin code`, `isin number` | 50 |
| LEI | `lei`, `legal entity identifier`, `gleif`, `entity identifier`, `lei code` | 50 |
| SEDOL | `sedol`, `stock exchange daily official list`, `london stock`, `uk securities` | 50 |
| Ticker Symbol | `ticker`, `stock symbol`, `trading symbol`, `nyse`, `nasdaq`, `equity symbol`, `stock ticker` | 50 |

## Social Media Identifiers (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| Hashtag | `hashtag`, `tagged`, `trending`, `topic` | 50 |
| Twitter Handle | `twitter`, `tweet`, `x.com`, `twitter handle`, `twitter username`, `follow` | 50 |

## Supervisory Information (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| CSI | `confidential supervisory`, `csi`, `examination report`, `regulatory report`, `supervisory letter` | 80 |
| Examination Findings | `examination`, `mra`, `mria`, `findings`, `regulatory`, `corrective action`, `consent order` | 80 |
| Non-Public Supervisory | `non-public`, `supervisory`, `regulatory`, `examination`, `not for release` | 80 |
| Restricted Supervisory | `restricted`, `supervisory`, `regulatory`, `compliance`, `enforcement`, `accès restreint`, `restreint`, `restreinte`, `beschränkt`, `eingeschränkt`, `limitato`, `restringida`, `restringido`, `restrita`, `restrito`, `riservato` | 80 |
| Supervisory Confidential | `supervisory`, `confidential`, `regulator`, `examination`, `bank examination`, `confidentiel`, `confidentielle`, `confidencial`, `confidenziale`, `riservato`, `vertraulich` | 80 |
| Supervisory Controlled | `supervisory`, `controlled`, `occ`, `fdic`, `federal reserve`, `regulator`, `examination` | 80 |

## URLs with Credentials (2 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| URL with Password | `url`, `link`, `endpoint`, `connection`, `connect` | 80 |
| URL with Token | `url`, `link`, `endpoint`, `api`, `callback` | 80 |

## Vehicle Identification (1 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| VIN | `vin`, `vehicle identification`, `vehicle id`, `chassis number`, `vehicle number` | 50 |

## Wire Transfer Data (6 keyword groups)

| Pattern | Keywords | Distance |
|---|---|---:|
| ACH Batch Number | `ach batch`, `batch number`, `batch id`, `ach file`, `nacha batch` | 50 |
| ACH Trace Number | `ach trace`, `trace number`, `trace id`, `ach transaction`, `ach payment`, `nacha` | 50 |
| CHIPS UID | `chips`, `chips uid`, `chips transfer`, `clearing house`, `interbank payment` | 50 |
| Fedwire IMAD | `imad`, `input message accountability`, `fedwire`, `fed reference`, `wire reference`, `référence de virement` | 50 |
| SEPA Reference | `sepa`, `sepa reference`, `end-to-end`, `e2e reference`, `sepa transfer`, `sepa credit` | 50 |
| Wire Reference Number | `wire reference`, `wire transfer`, `wire number`, `remittance reference`, `payment reference`, `transfer reference`, `référence de virement`, `virement`, `virement bancaire`, `banküberweisung`, `bonifico`, `bonifico bancario`, `transferencia`, `transferencia bancaria`, `transferência bancária`, `überweisung` | 50 |
