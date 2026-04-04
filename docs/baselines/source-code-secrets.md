# Source Code and Secrets Control

Detects secrets, credentials, API keys, tokens, and connection strings that
may be embedded in source code, configuration files, or documentation.
Aligns with SOC 2, ISO 27001, NIST 800-53, and secure development lifecycle
requirements.

## Control Objective

Prevent the exposure of authentication credentials, API keys, private keys,
access tokens, and connection strings in code repositories, logs, chat
messages, and documents. Detect secrets from all major cloud providers,
code platforms, messaging services, and payment processors.

---

## Patterns & Keywords

### Generic Secrets

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| Bearer Token | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` | `authorization`, `bearer`, `auth token` |
| JWT Token | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | `jwt`, `json web token`, `auth`, `token` |
| Private Key | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` | `private key`, `rsa`, `ssh key`, `pem` |
| Generic API Key | `(?:api[_-]?key\|apikey\|api[_-]?secret\|api[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9\-._~+/]{16,}["']?` | `api key`, `api_key`, `apikey`, `api secret` |
| Generic Secret Assignment | `(?:password\|passwd\|pwd\|secret\|token\|credential)\s*[=:]\s*["']?[^\s"']{8,}["']?` | `password`, `secret`, `credential`, `passwd` |
| Database Connection String | `(?:mongodb(?:\+srv)?\|mysql\|postgres(?:ql)?\|redis\|mssql)://[^:\s]+:[^@\s]+@[^\s]+` | `database`, `db connection`, `connection string`, `mongodb`, `postgres`, `mysql`, `redis` |

### URLs with Embedded Credentials

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| URL with Password | `https?://[^:\s]+:[^@\s]+@[^\s]+` | `url`, `link`, `endpoint`, `connection`, `connect` |
| URL with Token | `https?://[^\s]*[?&](?:token\|key\|api_key\|apikey\|access_token\|secret\|password\|passwd\|pwd)=[^\s&]+` | `url`, `link`, `endpoint`, `api`, `callback` |

### Cloud Provider Secrets

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| AWS Access Key | `\b(?:A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}\b` | `aws`, `amazon`, `access key`, `iam`, `credentials` |
| AWS Secret Key | `(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])` | `aws`, `secret key`, `secret access key`, `aws_secret` |
| Google API Key | `\bAIza[0-9A-Za-z\\-_]{35}\b` | `google`, `gcp`, `api key`, `google cloud`, `firebase` |

### Code Platform Secrets

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| GitHub Token (Classic) | `\bghp_[A-Za-z0-9]{36}\b` | `github`, `token`, `pat`, `personal access token` |
| GitHub Token (Fine-Grained) | `\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b` | `github`, `fine-grained`, `pat`, `personal access token` |
| GitHub OAuth Token | `\bgho_[A-Za-z0-9]{36}\b` | `github`, `oauth`, `token`, `app token` |
| NPM Token | `\bnpm_[A-Za-z0-9]{36}\b` | `npm`, `npmjs`, `registry`, `publish token` |
| PyPI Token | `\bpypi-[A-Za-z0-9-_]{16,}\b` | `pypi`, `python`, `package`, `upload token` |

### Messaging Service Secrets

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| Slack Bot Token | `\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b` | `slack`, `bot`, `token`, `workspace` |
| Slack User Token | `\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b` | `slack`, `user`, `token`, `workspace` |
| Slack Webhook | `\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}\b` | `slack`, `webhook`, `incoming`, `notification` |
| SendGrid API Key | `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b` | `sendgrid`, `email`, `api key`, `mail` |
| Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` | `twilio`, `sms`, `api key`, `messaging` |
| Mailgun API Key | `\bkey-[0-9a-zA-Z]{32}\b` | `mailgun`, `email`, `api key`, `mail` |

### Payment Service Secrets

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| Stripe Secret Key | `\bsk_live_[0-9a-zA-Z]{24,}\b` | `stripe`, `stripe key`, `secret key`, `payment`, `api key` |
| Stripe Publishable Key | `\bpk_live_[0-9a-zA-Z]{24,}\b` | `stripe`, `publishable`, `public key`, `payment`, `client key` |

### Authentication Tokens

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Session ID | `\b[0-9a-f]{32,64}\b` | `session id`, `session_id`, `sessionid`, `sess_id`, `session token`, `phpsessid`, `jsessionid`, `asp.net_sessionid` |
| CSRF Token | `\b[0-9a-zA-Z_-]{32,64}\b` | `csrf`, `csrf_token`, `xsrf`, `anti-forgery`, `request token`, `authenticity_token`, `_token` |
| OTP Code | `\b\d{6,8}\b` | `otp`, `one-time password`, `one time password`, `verification code`, `two-factor`, `2fa`, `mfa code`, `authenticator code`, `totp` |
| Refresh Token | `\b[0-9a-zA-Z_-]{40,}\b` | `refresh_token`, `refresh token`, `rt_token`, `oauth refresh` |

### Banking Authentication (Infrastructure Secrets)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |

---

## Common Leak Vectors

| Vector | Example |
|--------|---------|
| **Git commits** | Hardcoded API keys in source code |
| **CI/CD logs** | Secrets printed in build output |
| **Configuration files** | `.env`, `config.yaml`, `docker-compose.yml` |
| **Documentation** | API keys pasted in README or wiki pages |
| **Chat & email** | Credentials shared via Slack, Teams, email |
| **Log files** | Connection strings in application logs |
| **Jupyter notebooks** | Embedded tokens in notebook cells |

## Framework Mapping

| Framework | Controls | Key Patterns |
|-----------|----------|--------------|
| **SOC 2** (CC6.1) | Logical access security | All API keys, tokens, credentials |
| **ISO 27001** (A.9) | Access control | Private keys, connection strings |
| **NIST 800-53** (IA-5) | Authenticator management | All secrets and tokens |
| **CIS Controls** (16) | Application software security | Generic secrets, embedded credentials |
| **OWASP Top 10** (A07) | Authentication failures | Hardcoded secrets, leaked tokens |
