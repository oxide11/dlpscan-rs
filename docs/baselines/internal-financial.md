# Internal Financial Data Monitoring

Detects internal financial data including banking identifiers, transaction
records, securities data, cryptocurrency addresses, regulatory filings,
and customer financial information. Aligns with SOX, GLBA, BSA/AML,
FINRA, and internal risk management requirements.

## Control Objective

Prevent the unauthorized disclosure of non-public financial data including
customer account information, internal banking references, wire transfer
details, securities identifiers, regulatory filings, and market-sensitive
information.

---

## Patterns & Keywords

### Banking & Account Data

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` | `iban`, `international bank account number`, `bank account` |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` | `swift`, `bic`, `bank identifier code`, `swift code`, `routing code` |
| ABA Routing Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{7}\b` | `routing number`, `routing no`, `aba`, `aba routing`, `transit routing`, `bank routing`, `rtn` |
| US Bank Account Number | `\b\d{8,17}\b` | `account number`, `account no`, `bank account`, `checking account`, `savings account`, `acct`, `acct no`, `deposit account` |
| Canada Transit Number | `\b\d{5}[-.\s]?\d{3}\b` | `transit number`, `institution number`, `canadian bank`, `bank transit` |

### Internal Banking References

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Internal Account Ref | `\b[A-Z]{2,4}\d{8,14}\b` | `internal reference`, `account reference`, `internal id`, `system id`, `core banking id` |
| Teller ID | `\b[A-Z]{1,3}\d{4,8}\b` | `teller id`, `teller number`, `officer id`, `banker id`, `employee id`, `user id` |
| Branch Code | `\b\d{4,6}\b` | `branch code`, `branch number`, `branch id`, `cost center`, `branch no`, `office code` |
| Customer ID | `\b\d{6,12}\b` | `customer id`, `cif`, `cid`, `customer number`, `client id`, `customer identification`, `client number` |

### Customer Financial Data

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Account Balance | `(?<!\w)[$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` | `balance`, `account balance`, `available balance`, `current balance`, `ledger balance`, `closing balance` |
| Balance with Currency Code | `\b(?:USD\|EUR\|GBP\|JPY\|CAD\|AUD\|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` | `balance`, `amount`, `total`, `funds`, `available`, `ledger` |
| Income Amount | `(?<!\w)[$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` | `income`, `salary`, `annual income`, `monthly income`, `gross income`, `net income`, `compensation`, `wages`, `earnings` |
| DTI Ratio | `\b\d{1,2}\.\d{1,2}%\b` | `dti`, `debt-to-income`, `debt to income`, `dti ratio`, `debt ratio` |
| Credit Score | `\b[3-8]\d{2}\b` | `credit score`, `fico`, `fico score`, `credit rating`, `vantagescore`, `credit bureau`, `experian`, `equifax`, `transunion` |

### Wire Transfer & Payment Data

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Fedwire IMAD | `\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b` | `imad`, `input message accountability`, `fedwire`, `fed reference`, `wire reference` |
| CHIPS UID | `\b\d{6}[A-Z0-9]{4,10}\b` | `chips`, `chips uid`, `chips transfer`, `clearing house`, `interbank payment` |
| Wire Reference Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{16,35}\b` | `wire reference`, `wire transfer`, `wire number`, `remittance reference`, `payment reference`, `transfer reference` |
| ACH Trace Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{13}\b` | `ach trace`, `trace number`, `trace id`, `ach transaction`, `ach payment`, `nacha` |
| ACH Batch Number | `\b\d{7}\b` | `ach batch`, `batch number`, `batch id`, `ach file`, `nacha batch` |
| SEPA Reference | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{12,35}\b` | `sepa`, `sepa reference`, `end-to-end`, `e2e reference`, `sepa transfer`, `sepa credit` |

### Loan & Mortgage Data

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Loan Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}\b` | `loan number`, `loan no`, `loan id`, `loan account`, `loan#`, `lending number` |
| MERS MIN | `\b\d{18}\b` | `mers`, `mortgage identification number`, `min number`, `mers min`, `mortgage electronic` |
| Universal Loan Identifier | `\b[A-Z0-9]{4}00[A-Z0-9]{17,39}\b` | `uli`, `universal loan identifier`, `hmda`, `loan identifier` |
| LTV Ratio | `\b\d{1,3}\.\d{1,2}%\b` | `ltv`, `loan-to-value`, `loan to value`, `ltv ratio`, `combined ltv`, `cltv` |

### Securities Identifiers

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| CUSIP | `\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b` | `cusip`, `committee on uniform securities`, `security identifier`, `bond cusip`, `cusip number` |
| ISIN | `\b[A-Z]{2}[0-9A-Z]{9}\d\b` | `isin`, `international securities`, `securities identification`, `isin code`, `isin number` |
| SEDOL | `\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b` | `sedol`, `stock exchange daily official list`, `london stock`, `uk securities` |
| FIGI | `\bBBG[A-Z0-9]{9}\b` | `figi`, `financial instrument global identifier`, `bloomberg`, `bbg`, `openfigi` |
| LEI | `\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b` | `lei`, `legal entity identifier`, `gleif`, `entity identifier`, `lei code` |
| Ticker Symbol | `(?<!\w)\$[A-Z]{1,5}\b` | `ticker`, `stock symbol`, `trading symbol`, `nyse`, `nasdaq`, `equity symbol`, `stock ticker` |

### Cryptocurrency

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Bitcoin Address (Legacy) | `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` | `bitcoin`, `btc`, `wallet`, `crypto` |
| Bitcoin Address (Bech32) | `\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b` | `bitcoin`, `btc`, `segwit`, `wallet` |
| Ethereum Address | `\b0x[0-9a-fA-F]{40}\b` | `ethereum`, `eth`, `ether`, `wallet`, `crypto` |
| Litecoin Address | `\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b` | `litecoin`, `ltc`, `wallet` |
| Bitcoin Cash Address | `\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b` | `bitcoin cash`, `bch`, `wallet` |
| Monero Address | `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` | `monero`, `xmr`, `wallet` |
| Ripple Address | `\br[1-9A-HJ-NP-Za-km-z]{24,34}\b` | `ripple`, `xrp`, `wallet` |

### Regulatory Identifiers

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| SAR Filing Number | `\b\d{14,20}\b` | `sar`, `suspicious activity report`, `sar filing`, `sar number`, `suspicious activity` |
| CTR Number | `\b\d{14,20}\b` | `ctr`, `currency transaction report`, `ctr filing`, `ctr number`, `cash transaction` |
| AML Case ID | `\b[A-Z]{2,4}[-]?\d{6,12}\b` | `aml`, `anti-money laundering`, `money laundering`, `aml case`, `aml investigation`, `bsa` |
| OFAC SDN Entry | `\b\d{4,6}\b` | `ofac`, `sdn`, `specially designated`, `sanctions`, `ofac list`, `blocked persons` |
| FinCEN Report Number | `\b\d{14}\b` | `fincen`, `financial crimes`, `fincen report`, `fincen filing`, `bsa filing` |
| Compliance Case Number | `\b[A-Z]{2,5}[-]?\d{4}[-]?\d{4,8}\b` | `compliance case`, `investigation number`, `regulatory case`, `compliance id`, `audit case`, `examination number` |

### Financial Regulatory Labels

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| MNPI | `\b(?:MNPI\|[Mm]aterial\s+[Nn]on-?[Pp]ublic\s+[Ii]nformation)\b` | `mnpi`, `material`, `non-public`, `insider`, `trading`, `securities` |
| Inside Information | `\b[Ii]nside(?:r)?\s+[Ii]nformation\b` | `inside information`, `insider`, `material`, `non-public`, `trading restriction` |
| Pre-Decisional | `\b[Pp]re-?[Dd]ecisional\b` | `pre-decisional`, `draft`, `deliberative`, `not final`, `preliminary` |
| Draft Not for Circulation | `\b[Dd]raft\s*[-–—]\s*[Nn]ot\s+[Ff]or\s+[Cc]irculation\b` | `draft`, `circulation`, `preliminary`, `not final`, `review only` |
| Market Sensitive | `\b[Mm]arket\s+[Ss]ensitive\b` | `market sensitive`, `price sensitive`, `stock`, `securities`, `trading` |
| Information Barrier | `\b(?:[Ii]nformation\s+[Bb]arrier\|[Cc]hinese\s+[Ww]all)\b` | `information barrier`, `chinese wall`, `wall crossing`, `restricted side`, `public side` |
| Investment Restricted | `\b[Rr]estricted\s+[Ll]ist\b` | `restricted list`, `watch list`, `grey list`, `restricted securities`, `trading restriction` |

### Supervisory Information

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` | `supervisory`, `controlled`, `occ`, `fdic`, `federal reserve`, `regulator`, `examination` |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` | `supervisory`, `confidential`, `regulator`, `examination`, `bank examination` |
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` | `confidential supervisory`, `csi`, `examination report`, `regulatory report`, `supervisory letter` |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` | `non-public`, `supervisory`, `regulatory`, `examination`, `not for release` |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` | `restricted`, `supervisory`, `regulatory`, `compliance`, `enforcement` |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` | `examination`, `mra`, `mria`, `findings`, `regulatory`, `corrective action`, `consent order` |

### Banking Authentication

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| PIN Block | `\b[0-9A-F]{16}\b` | `pin block`, `encrypted pin`, `pin encryption`, `iso 9564`, `pin format` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |

---

## Regulatory Mapping

| Regulation | Scope | Key Patterns |
|-----------|-------|--------------|
| **SOX** (Sarbanes-Oxley) | Internal financial controls | Customer financial data, regulatory labels |
| **GLBA** (Gramm-Leach-Bliley) | Customer financial information | Account data, wire transfers, loan data |
| **BSA/AML** (Bank Secrecy Act) | Anti-money laundering | SAR, CTR, OFAC, FinCEN, AML Case ID |
| **FINRA** | Securities industry | MNPI, securities identifiers, information barriers |
| **Dodd-Frank** | Financial stability | Supervisory information, regulatory identifiers |
| **MiFID II** (EU) | Markets in financial instruments | ISIN, LEI, market sensitive data |
