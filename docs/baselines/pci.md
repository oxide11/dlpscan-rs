# Payment Card Industry Information (PCI)

Detects payment card data subject to PCI-DSS requirements. Covers primary
account numbers, cardholder data, sensitive authentication data, and
supporting payment infrastructure identifiers.

## Control Objective

Prevent the unauthorized storage, transmission, or disclosure of cardholder
data and sensitive authentication data as defined by PCI-DSS requirements
3, 4, and 7.

---

## Patterns & Keywords

### Credit Card Numbers

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Visa | `\b4\d{3}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` | `visa`, `credit card`, `card number`, `card no`, `pan`, `primary account` |
| MasterCard | `\b(?:5[1-5]\d{2}\|2(?:2[2-9]\d\|2[3-9]\d\|[3-6]\d{2}\|7[01]\d\|720))[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` | `mastercard`, `mc`, `credit card`, `card number`, `card no`, `pan`, `primary account` |
| Amex | `\b3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5}\b` | `amex`, `american express`, `credit card`, `card number`, `pan`, `primary account` |
| Discover | `\b6(?:011\|5\d{2}\|4[4-9]\d)[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` | `discover`, `credit card`, `card number`, `pan`, `primary account` |
| JCB | `\b35(?:2[89]\|[3-8]\d)[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b` | `jcb`, `credit card`, `card number`, `pan`, `primary account` |
| Diners Club | `\b3(?:0[0-5]\|[68]\d)\d[-.\s]?\d{6}[-.\s]?\d{4}\b` | `diners club`, `diners`, `credit card`, `card number`, `pan`, `primary account` |
| UnionPay | `\b62\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}(?:[-.\s]?\d{1,3})?\b` | `unionpay`, `union pay`, `credit card`, `card number`, `pan`, `primary account` |

### Credit Card Security Codes

| Pattern Name | Regex | Keywords (proximity: 30 chars) |
|---|---|---|
| CVV/CVC/CCV | `\b\d{3}\b` | `cvv`, `cvc`, `ccv`, `cvv2`, `cvc2`, `security code`, `card verification`, `verification value`, `verification code`, `csv` |
| Amex CID | `\b\d{4}\b` | `cid`, `card identification`, `amex security`, `amex cvv`, `four digit`, `4 digit security` |

### Primary Account Numbers

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| PAN | `\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{1,7}\b` | `pan`, `primary account number`, `account number`, `card number`, `cardholder number`, `full card` |
| Masked PAN | `\b\d{4}[-.\s]?[Xx*]{4}[-.\s]?[Xx*]{4}[-.\s]?\d{4}\b` | `masked pan`, `truncated pan`, `masked card`, `truncated card`, `last four`, `first six` |
| BIN/IIN | `\b\d{6,8}\b` | `bin`, `iin`, `bank identification number`, `issuer identification`, `card prefix`, `bin number` |

### Cardholder Data

| Pattern Name | Regex | Keywords (proximity: 30 chars) |
|---|---|---|
| Cardholder Name Pattern | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` | `cardholder`, `cardholder name`, `name on card`, `card holder`, `card member` |
| Card Expiry | `\b(?:0[1-9]\|1[0-2])\s?/\s?(?:\d{2}\|\d{4})\b` | `expiry`, `expiration`, `exp date`, `exp`, `valid thru`, `valid through`, `good thru`, `card expires`, `mm/yy` |

### PCI Sensitive Data

| Pattern Name | Regex | Keywords (proximity: 30 chars) |
|---|---|---|
| Dynamic CVV | `\b\d{3}\b` | `icvv`, `dcvv`, `dynamic cvv`, `chip cvv`, `dynamic verification`, `cavv` |
| PVKI | `\b\d{1}\b` | `pvki`, `pin verification key indicator`, `key indicator` |
| PVV | `\b\d{4}\b` | `pvv`, `pin verification value`, `pin value` |
| Service Code | `\b\d{3}\b` | `service code`, `svc code`, `magstripe service`, `card service code` |

### Sensitive Authentication Data (Track Data)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Track 1 Data | `%B\d{13,19}\^[A-Z\s/]+\^\d{4}\d*` | `track 1`, `track1`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |
| Track 2 Data | `;\d{13,19}=\d{4}\d*\?` | `track 2`, `track2`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |

### Banking Authentication (Payment Infrastructure)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| PIN Block | `\b[0-9A-F]{16}\b` | `pin block`, `encrypted pin`, `pin encryption`, `iso 9564`, `pin format` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |
| PIN | `\b\d{4,6}\b` | `pin`, `personal identification number`, `atm pin`, `debit pin`, `pin number`, `pin code`, `card pin` |

### Check and MICR Data

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| MICR Line | `[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}` | `micr`, `magnetic ink`, `check bottom`, `cheque line`, `micr line`, `e13b` |
| Check Number | `\b\d{4,6}\b` | `check number`, `check no`, `cheque number`, `check#`, `ck no`, `check num` |
| Cashier Check Number | `\b\d{8,15}\b` | `cashier check`, `cashiers check`, `certified check`, `money order`, `bank check`, `official check` |

### Payment Service Secrets

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| Stripe Secret Key | `\bsk_live_[0-9a-zA-Z]{24,}\b` | `stripe`, `stripe key`, `secret key`, `payment`, `api key` |
| Stripe Publishable Key | `\bpk_live_[0-9a-zA-Z]{24,}\b` | `stripe`, `publishable`, `public key`, `payment`, `client key` |

---

## PCI-DSS Requirement Mapping

| PCI-DSS Requirement | Patterns Covered |
|---------------------|------------------|
| **Req 3** -- Protect stored account data | Credit card numbers, PAN, cardholder name, card expiry, track data |
| **Req 3.3** -- Mask PAN when displayed | Masked PAN detection |
| **Req 3.4** -- Render PAN unreadable | Full PAN detection in plaintext |
| **Req 4** -- Encrypt transmission of cardholder data | All cardholder data patterns (detect unencrypted transmission) |
| **Req 7** -- Restrict access to cardholder data | Stripe keys, HSM keys, encryption keys |
| **Req 8** -- Identify users and authenticate access | PIN, PIN Block |
