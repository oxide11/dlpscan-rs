//! Context keyword definitions for all pattern categories.
//!
//! Each entry maps (category, sub_category) to a set of keywords and
//! a context distance value.

use super::ContextEntry;

/// All context keywords indexed by (category, sub_category).
pub static CONTEXT_KEYWORDS: &[(&str, &str, ContextEntry)] = &[
    // Credit Card Numbers
    ("Credit Card Numbers", "Visa", ContextEntry { keywords: &["visa", "credit card", "card number", "card no", "pan", "primary account"], distance: 50 }),
    ("Credit Card Numbers", "MasterCard", ContextEntry { keywords: &["mastercard", "credit card", "card number", "card no", "pan", "primary account"], distance: 50 }),
    ("Credit Card Numbers", "Amex", ContextEntry { keywords: &["amex", "american express", "credit card", "card number", "pan", "primary account"], distance: 50 }),
    ("Credit Card Numbers", "Discover", ContextEntry { keywords: &["discover", "credit card", "card number", "pan", "primary account"], distance: 50 }),
    ("Credit Card Numbers", "JCB", ContextEntry { keywords: &["jcb", "credit card", "card number", "pan", "primary account"], distance: 50 }),
    ("Credit Card Numbers", "Diners Club", ContextEntry { keywords: &["diners club", "diners", "credit card", "card number", "pan", "primary account"], distance: 50 }),
    ("Credit Card Numbers", "UnionPay", ContextEntry { keywords: &["unionpay", "union pay", "credit card", "card number", "pan", "primary account"], distance: 50 }),

    // Primary Account Numbers
    ("Primary Account Numbers", "PAN", ContextEntry { keywords: &["pan", "primary account number", "account number", "card number", "cardholder number", "full card"], distance: 50 }),
    ("Primary Account Numbers", "Masked PAN", ContextEntry { keywords: &["masked pan", "truncated pan", "masked card", "truncated card", "last four", "first six"], distance: 50 }),

    // Card Track Data
    ("Card Track Data", "Track 1 Data", ContextEntry { keywords: &["track 1", "track1", "magnetic stripe", "magstripe", "swipe data", "card track"], distance: 50 }),
    ("Card Track Data", "Track 2 Data", ContextEntry { keywords: &["track 2", "track2", "magnetic stripe", "magstripe", "swipe data", "card track"], distance: 50 }),

    // Card Expiration Dates
    ("Card Expiration Dates", "Card Expiry", ContextEntry { keywords: &["expiry", "expiration", "exp date", "exp", "valid thru", "valid through", "good thru", "card expires", "mm/yy"], distance: 30 }),

    // Contact Information
    ("Contact Information", "Email Address", ContextEntry { keywords: &["email", "e-mail", "email address", "mail to", "contact"], distance: 50 }),
    ("Contact Information", "E.164 Phone Number", ContextEntry { keywords: &["phone", "telephone", "tel", "mobile", "contact number"], distance: 50 }),
    ("Contact Information", "IPv4 Address", ContextEntry { keywords: &["ip address", "ip", "server", "host", "network"], distance: 50 }),
    ("Contact Information", "IPv6 Address", ContextEntry { keywords: &["ip address", "ipv6", "server", "host", "network"], distance: 50 }),
    ("Contact Information", "MAC Address", ContextEntry { keywords: &["mac address", "hardware address", "physical address", "mac"], distance: 50 }),

    // Banking and Financial
    ("Banking and Financial", "IBAN Generic", ContextEntry { keywords: &["iban", "international bank account number", "bank account"], distance: 50 }),
    ("Banking and Financial", "SWIFT/BIC", ContextEntry { keywords: &["swift", "bic", "bank identifier code", "swift code", "routing code"], distance: 50 }),
    ("Banking and Financial", "ABA Routing Number", ContextEntry { keywords: &["routing number", "routing no", "aba", "aba routing", "transit routing", "bank routing", "rtn"], distance: 50 }),
    ("Banking and Financial", "US Bank Account Number", ContextEntry { keywords: &["account number", "account no", "bank account", "checking account", "savings account", "acct", "acct no", "deposit account"], distance: 50 }),
    ("Banking and Financial", "Canada Transit Number", ContextEntry { keywords: &["transit number", "institution number", "canadian bank", "bank transit"], distance: 50 }),

    // Wire Transfer Data
    ("Wire Transfer Data", "Fedwire IMAD", ContextEntry { keywords: &["imad", "input message accountability", "fedwire", "fed reference", "wire reference"], distance: 50 }),
    ("Wire Transfer Data", "CHIPS UID", ContextEntry { keywords: &["chips", "chips uid", "chips transfer", "clearing house", "interbank payment"], distance: 50 }),
    ("Wire Transfer Data", "Wire Reference Number", ContextEntry { keywords: &["wire reference", "wire transfer", "wire number", "remittance reference", "payment reference", "transfer reference"], distance: 50 }),
    ("Wire Transfer Data", "ACH Trace Number", ContextEntry { keywords: &["ach trace", "trace number", "trace id", "ach transaction", "ach payment", "nacha"], distance: 50 }),
    ("Wire Transfer Data", "ACH Batch Number", ContextEntry { keywords: &["ach batch", "batch number", "batch id", "ach file", "nacha batch"], distance: 50 }),
    ("Wire Transfer Data", "SEPA Reference", ContextEntry { keywords: &["sepa", "sepa reference", "end-to-end", "e2e reference", "sepa transfer", "sepa credit"], distance: 50 }),

    // Check and MICR Data
    ("Check and MICR Data", "MICR Line", ContextEntry { keywords: &["micr", "magnetic ink", "check bottom", "cheque line", "micr line", "e13b"], distance: 50 }),
    ("Check and MICR Data", "Check Number", ContextEntry { keywords: &["check number", "check no", "cheque number", "check#", "ck no", "check num"], distance: 50 }),
    ("Check and MICR Data", "Cashier Check Number", ContextEntry { keywords: &["cashier check", "cashiers check", "certified check", "money order", "bank check", "official check"], distance: 50 }),

    // Securities Identifiers
    ("Securities Identifiers", "CUSIP", ContextEntry { keywords: &["cusip", "committee on uniform securities", "security identifier", "bond cusip", "cusip number"], distance: 50 }),
    ("Securities Identifiers", "ISIN", ContextEntry { keywords: &["isin", "international securities", "securities identification", "isin code", "isin number"], distance: 50 }),
    ("Securities Identifiers", "SEDOL", ContextEntry { keywords: &["sedol", "stock exchange daily official list", "london stock", "uk securities"], distance: 50 }),
    ("Securities Identifiers", "FIGI", ContextEntry { keywords: &["figi", "financial instrument global identifier", "bloomberg", "bbg", "openfigi"], distance: 50 }),
    ("Securities Identifiers", "LEI", ContextEntry { keywords: &["lei", "legal entity identifier", "gleif", "entity identifier", "lei code"], distance: 50 }),
    ("Securities Identifiers", "Ticker Symbol", ContextEntry { keywords: &["ticker", "stock symbol", "trading symbol", "nyse", "nasdaq", "equity symbol", "stock ticker"], distance: 50 }),

    // Loan and Mortgage Data
    ("Loan and Mortgage Data", "Loan Number", ContextEntry { keywords: &["loan number", "loan no", "loan id", "loan account", "loan#", "lending number"], distance: 50 }),
    ("Loan and Mortgage Data", "MERS MIN", ContextEntry { keywords: &["mers", "mortgage identification number", "min number", "mers min", "mortgage electronic"], distance: 50 }),
    ("Loan and Mortgage Data", "Universal Loan Identifier", ContextEntry { keywords: &["uli", "universal loan identifier", "hmda", "loan identifier"], distance: 50 }),
    ("Loan and Mortgage Data", "LTV Ratio", ContextEntry { keywords: &["ltv", "loan-to-value", "loan to value", "ltv ratio", "combined ltv", "cltv"], distance: 50 }),

    // Regulatory Identifiers
    ("Regulatory Identifiers", "SAR Filing Number", ContextEntry { keywords: &["sar", "suspicious activity report", "sar filing", "sar number", "suspicious activity"], distance: 50 }),
    ("Regulatory Identifiers", "CTR Number", ContextEntry { keywords: &["ctr", "currency transaction report", "ctr filing", "ctr number", "cash transaction"], distance: 50 }),
    ("Regulatory Identifiers", "AML Case ID", ContextEntry { keywords: &["aml", "anti-money laundering", "money laundering", "aml case", "aml investigation", "bsa"], distance: 50 }),
    ("Regulatory Identifiers", "OFAC SDN Entry", ContextEntry { keywords: &["ofac", "sdn", "specially designated", "sanctions", "ofac list", "blocked persons"], distance: 50 }),
    ("Regulatory Identifiers", "FinCEN Report Number", ContextEntry { keywords: &["fincen", "financial crimes", "fincen report", "fincen filing", "bsa filing"], distance: 50 }),
    ("Regulatory Identifiers", "Compliance Case Number", ContextEntry { keywords: &["compliance case", "investigation number", "regulatory case", "compliance id", "audit case", "examination number"], distance: 50 }),

    // Banking Authentication
    ("Banking Authentication", "PIN Block", ContextEntry { keywords: &["pin block", "encrypted pin", "pin encryption", "iso 9564", "pin format"], distance: 50 }),
    ("Banking Authentication", "HSM Key", ContextEntry { keywords: &["hsm", "hardware security module", "hsm key", "master key", "key material"], distance: 50 }),
    ("Banking Authentication", "Encryption Key", ContextEntry { keywords: &["kek", "zmk", "tmk", "zone master key", "key encrypting", "terminal master key", "transport key", "working key"], distance: 50 }),

    // Customer Financial Data
    ("Customer Financial Data", "Account Balance", ContextEntry { keywords: &["balance", "account balance", "available balance", "current balance", "ledger balance", "closing balance"], distance: 50 }),
    ("Customer Financial Data", "Balance with Currency Code", ContextEntry { keywords: &["balance", "amount", "total", "funds", "available", "ledger"], distance: 50 }),
    ("Customer Financial Data", "Income Amount", ContextEntry { keywords: &["income", "salary", "annual income", "monthly income", "gross income", "net income", "compensation", "wages", "earnings"], distance: 50 }),
    ("Customer Financial Data", "DTI Ratio", ContextEntry { keywords: &["dti", "debt-to-income", "debt to income", "dti ratio", "debt ratio"], distance: 50 }),

    // Internal Banking References
    ("Internal Banking References", "Internal Account Ref", ContextEntry { keywords: &["internal reference", "account reference", "internal id", "system id", "core banking id"], distance: 50 }),
    ("Internal Banking References", "Teller ID", ContextEntry { keywords: &["teller id", "teller number", "officer id", "banker id", "employee id", "user id"], distance: 50 }),

    // PCI Sensitive Data
    ("PCI Sensitive Data", "Cardholder Name Pattern", ContextEntry { keywords: &["cardholder", "cardholder name", "name on card", "card holder", "card member"], distance: 30 }),

    // Cryptocurrency
    ("Cryptocurrency", "Bitcoin Address (Legacy)", ContextEntry { keywords: &["bitcoin", "btc", "wallet", "crypto"], distance: 50 }),
    ("Cryptocurrency", "Bitcoin Address (Bech32)", ContextEntry { keywords: &["bitcoin", "btc", "segwit", "wallet"], distance: 50 }),
    ("Cryptocurrency", "Ethereum Address", ContextEntry { keywords: &["ethereum", "eth", "ether", "wallet", "crypto"], distance: 50 }),
    ("Cryptocurrency", "Litecoin Address", ContextEntry { keywords: &["litecoin", "ltc", "wallet"], distance: 50 }),
    ("Cryptocurrency", "Bitcoin Cash Address", ContextEntry { keywords: &["bitcoin cash", "bch", "wallet"], distance: 50 }),
    ("Cryptocurrency", "Monero Address", ContextEntry { keywords: &["monero", "xmr", "wallet"], distance: 50 }),
    ("Cryptocurrency", "Ripple Address", ContextEntry { keywords: &["ripple", "xrp", "wallet"], distance: 50 }),

    // Vehicle Identification
    ("Vehicle Identification", "VIN", ContextEntry { keywords: &["vin", "vehicle identification", "vehicle id", "chassis number", "vehicle number"], distance: 50 }),

    // Dates
    ("Dates", "Date ISO", ContextEntry { keywords: &["date of birth", "dob", "birth date", "birthday", "born on", "born", "birthdate"], distance: 50 }),
    ("Dates", "Date US", ContextEntry { keywords: &["date of birth", "dob", "birth date", "birthday", "born on", "born", "birthdate"], distance: 50 }),
    ("Dates", "Date EU", ContextEntry { keywords: &["date of birth", "dob", "birth date", "birthday", "born on", "born", "birthdate"], distance: 50 }),

    // URLs with Credentials
    ("URLs with Credentials", "URL with Password", ContextEntry { keywords: &["url", "link", "endpoint", "connection", "connect"], distance: 80 }),
    ("URLs with Credentials", "URL with Token", ContextEntry { keywords: &["url", "link", "endpoint", "api", "callback"], distance: 80 }),

    // Generic Secrets
    ("Generic Secrets", "Bearer Token", ContextEntry { keywords: &["authorization", "bearer", "auth token"], distance: 80 }),
    ("Generic Secrets", "JWT Token", ContextEntry { keywords: &["jwt", "json web token", "auth", "token"], distance: 80 }),
    ("Generic Secrets", "Private Key", ContextEntry { keywords: &["private key", "rsa", "ssh key", "pem"], distance: 80 }),
    ("Generic Secrets", "Generic API Key", ContextEntry { keywords: &["api key", "api_key", "apikey", "api secret"], distance: 80 }),
    ("Generic Secrets", "Generic Secret Assignment", ContextEntry { keywords: &["password", "secret", "credential", "passwd"], distance: 80 }),
    ("Generic Secrets", "Database Connection String", ContextEntry { keywords: &["database", "db connection", "connection string", "mongodb", "postgres", "mysql", "redis"], distance: 80 }),

    // Personal Identifiers
    ("Personal Identifiers", "Date of Birth", ContextEntry { keywords: &["date of birth", "dob", "born on", "birth date", "birthday", "birthdate", "d.o.b"], distance: 30 }),
    ("Personal Identifiers", "Gender Marker", ContextEntry { keywords: &["gender", "sex", "identified as", "gender identity", "biological sex"], distance: 30 }),

    // Geolocation
    ("Geolocation", "GPS Coordinates", ContextEntry { keywords: &["latitude", "longitude", "lat", "lng", "lon", "coordinates", "gps", "geolocation", "location", "coord"], distance: 50 }),
    ("Geolocation", "GPS DMS", ContextEntry { keywords: &["latitude", "longitude", "coordinates", "gps", "dms", "degrees minutes seconds"], distance: 50 }),
    ("Geolocation", "Geohash", ContextEntry { keywords: &["geohash", "geo hash", "location hash"], distance: 50 }),

    // Postal Codes
    ("Postal Codes", "US ZIP+4 Code", ContextEntry { keywords: &["zip", "zip code", "zipcode", "postal code", "mailing address", "zip+4"], distance: 50 }),
    ("Postal Codes", "UK Postcode", ContextEntry { keywords: &["postcode", "post code", "postal code", "uk address"], distance: 50 }),
    ("Postal Codes", "Canada Postal Code", ContextEntry { keywords: &["postal code", "code postal", "canadian address"], distance: 50 }),
    ("Postal Codes", "Japan Postal Code", ContextEntry { keywords: &["postal code", "yubin bangou", "japanese address"], distance: 50 }),
    ("Postal Codes", "Brazil CEP", ContextEntry { keywords: &["cep", "codigo postal", "brazilian address"], distance: 50 }),

    // Device Identifiers
    ("Device Identifiers", "IMEI", ContextEntry { keywords: &["imei", "international mobile equipment identity", "device imei", "handset id", "phone imei", "equipment identity"], distance: 50 }),
    ("Device Identifiers", "IMEISV", ContextEntry { keywords: &["imeisv", "imei software version", "imei sv", "software version number"], distance: 50 }),
    ("Device Identifiers", "MEID", ContextEntry { keywords: &["meid", "mobile equipment identifier", "cdma device", "equipment id"], distance: 50 }),
    ("Device Identifiers", "ICCID", ContextEntry { keywords: &["iccid", "sim card number", "sim number", "integrated circuit card", "sim id", "sim serial"], distance: 50 }),
    ("Device Identifiers", "IDFA/IDFV", ContextEntry { keywords: &["idfa", "idfv", "advertising identifier", "identifier for advertisers", "vendor identifier", "apple device id"], distance: 50 }),

    // Medical Identifiers
    ("Medical Identifiers", "Health Plan ID", ContextEntry { keywords: &["health plan", "insurance id", "beneficiary", "member id", "subscriber id"], distance: 50 }),
    ("Medical Identifiers", "DEA Number", ContextEntry { keywords: &["dea", "dea number", "drug enforcement", "prescriber", "controlled substance"], distance: 50 }),
    ("Medical Identifiers", "ICD-10 Code", ContextEntry { keywords: &["icd", "icd-10", "diagnosis code", "diagnostic code", "condition code", "icd code"], distance: 50 }),
    ("Medical Identifiers", "NDC Code", ContextEntry { keywords: &["ndc", "national drug code", "drug code", "medication code", "pharmaceutical"], distance: 50 }),

    // Insurance Identifiers
    ("Insurance Identifiers", "Insurance Policy Number", ContextEntry { keywords: &["policy number", "policy no", "insurance policy", "policy id", "coverage number", "policy#"], distance: 50 }),
    ("Insurance Identifiers", "Insurance Claim Number", ContextEntry { keywords: &["claim number", "claim no", "claim id", "claim#", "claims reference", "incident number"], distance: 50 }),

    // Authentication Tokens
    ("Authentication Tokens", "Session ID", ContextEntry { keywords: &["session id", "session_id", "sessionid", "sess_id", "session token", "phpsessid", "jsessionid", "asp.net_sessionid"], distance: 50 }),

    // Social Media Identifiers
    ("Social Media Identifiers", "Twitter Handle", ContextEntry { keywords: &["twitter", "tweet", "x.com", "twitter handle", "twitter username", "follow"], distance: 50 }),
    ("Social Media Identifiers", "Hashtag", ContextEntry { keywords: &["hashtag", "tagged", "trending", "topic"], distance: 50 }),

    // Education Identifiers
    ("Education Identifiers", "EDU Email", ContextEntry { keywords: &["student email", "edu email", "university email", "academic email", "school email", "college email"], distance: 50 }),

    // Legal Identifiers
    ("Legal Identifiers", "US Federal Case Number", ContextEntry { keywords: &["case number", "case no", "docket", "civil action", "case#", "filing number"], distance: 50 }),
    ("Legal Identifiers", "Court Docket Number", ContextEntry { keywords: &["docket number", "docket no", "court case", "case file", "case reference", "court number"], distance: 50 }),

    // Employment Identifiers
    ("Employment Identifiers", "Employee ID", ContextEntry { keywords: &["employee id", "employee number", "emp id", "staff id", "personnel number", "emp no", "worker id", "badge number"], distance: 50 }),
    ("Employment Identifiers", "Work Permit Number", ContextEntry { keywords: &["work permit", "work visa", "employment authorization", "ead", "labor permit", "work authorization"], distance: 50 }),

    // Biometric Identifiers
    ("Biometric Identifiers", "Biometric Hash", ContextEntry { keywords: &["biometric", "fingerprint hash", "fingerprint", "facial recognition", "iris scan", "palm print", "voiceprint", "retina scan"], distance: 50 }),
    ("Biometric Identifiers", "Biometric Template ID", ContextEntry { keywords: &["biometric template", "facial template", "fingerprint template", "enrollment id", "biometric id"], distance: 50 }),

    // Property Identifiers
    ("Property Identifiers", "Parcel Number", ContextEntry { keywords: &["parcel number", "apn", "assessor parcel", "parcel id", "lot number", "property id"], distance: 50 }),
    ("Property Identifiers", "Title Deed Number", ContextEntry { keywords: &["title number", "deed number", "deed of trust", "title deed", "land title", "property title"], distance: 50 }),

    // Supervisory Information
    ("Supervisory Information", "Supervisory Controlled", ContextEntry { keywords: &["supervisory", "controlled", "occ", "fdic", "federal reserve", "regulator", "examination"], distance: 80 }),
    ("Supervisory Information", "Supervisory Confidential", ContextEntry { keywords: &["supervisory", "confidential", "regulator", "examination", "bank examination"], distance: 80 }),
    ("Supervisory Information", "CSI", ContextEntry { keywords: &["confidential supervisory", "csi", "examination report", "regulatory report", "supervisory letter"], distance: 80 }),
    ("Supervisory Information", "Non-Public Supervisory", ContextEntry { keywords: &["non-public", "supervisory", "regulatory", "examination", "not for release"], distance: 80 }),
    ("Supervisory Information", "Restricted Supervisory", ContextEntry { keywords: &["restricted", "supervisory", "regulatory", "compliance", "enforcement"], distance: 80 }),
    ("Supervisory Information", "Examination Findings", ContextEntry { keywords: &["examination", "mra", "mria", "findings", "regulatory", "corrective action", "consent order"], distance: 80 }),

    // Privileged Information
    ("Privileged Information", "Attorney-Client Privilege", ContextEntry { keywords: &["attorney", "client", "privilege", "legal counsel", "law firm", "privileged communication"], distance: 100 }),
    ("Privileged Information", "Privileged and Confidential", ContextEntry { keywords: &["privileged", "confidential", "legal", "attorney", "counsel"], distance: 100 }),
    ("Privileged Information", "Work Product", ContextEntry { keywords: &["work product", "attorney", "litigation", "legal", "prepared in anticipation"], distance: 100 }),
    ("Privileged Information", "Privileged Information", ContextEntry { keywords: &["privileged", "legal", "attorney", "counsel", "protected"], distance: 100 }),
    ("Privileged Information", "Legal Privilege", ContextEntry { keywords: &["legal", "privilege", "attorney", "counsel", "protected communication"], distance: 100 }),
    ("Privileged Information", "Litigation Hold", ContextEntry { keywords: &["litigation", "legal hold", "preservation", "hold notice", "document retention"], distance: 100 }),
    ("Privileged Information", "Protected by Privilege", ContextEntry { keywords: &["privilege", "protected", "attorney", "legal", "exempt from disclosure"], distance: 100 }),

    // Data Classification Labels
    ("Data Classification Labels", "Top Secret", ContextEntry { keywords: &["classified", "top secret", "ts", "sci", "national security", "clearance"], distance: 100 }),
    ("Data Classification Labels", "Secret Classification", ContextEntry { keywords: &["classified", "secret", "national security", "clearance", "noforn"], distance: 100 }),
    ("Data Classification Labels", "Confidential Classification", ContextEntry { keywords: &["classified", "confidential", "national security", "government"], distance: 100 }),
    ("Data Classification Labels", "FOUO", ContextEntry { keywords: &["official use", "fouo", "government", "not for public release"], distance: 100 }),
    ("Data Classification Labels", "CUI", ContextEntry { keywords: &["cui", "controlled unclassified", "sensitive information", "marking"], distance: 100 }),
    ("Data Classification Labels", "SBU", ContextEntry { keywords: &["sensitive", "unclassified", "sbu", "government"], distance: 100 }),
    ("Data Classification Labels", "LES", ContextEntry { keywords: &["law enforcement", "sensitive", "les", "police", "investigation"], distance: 100 }),
    ("Data Classification Labels", "NOFORN", ContextEntry { keywords: &["noforn", "foreign nationals", "not releasable", "classification"], distance: 100 }),

    // Corporate Classification
    ("Corporate Classification", "Internal Only", ContextEntry { keywords: &["internal", "company", "employees only", "staff only", "not for external"], distance: 80 }),
    ("Corporate Classification", "Restricted", ContextEntry { keywords: &["restricted", "limited distribution", "access controlled", "need to know"], distance: 80 }),
    ("Corporate Classification", "Corporate Confidential", ContextEntry { keywords: &["confidential", "company", "corporate", "business", "proprietary"], distance: 80 }),
    ("Corporate Classification", "Highly Confidential", ContextEntry { keywords: &["highly confidential", "sensitive", "restricted", "executive only"], distance: 80 }),
    ("Corporate Classification", "Do Not Distribute", ContextEntry { keywords: &["distribute", "distribution", "circulation", "forward", "share"], distance: 80 }),
    ("Corporate Classification", "Need to Know", ContextEntry { keywords: &["need to know", "restricted access", "limited distribution", "authorized personnel"], distance: 80 }),
    ("Corporate Classification", "Eyes Only", ContextEntry { keywords: &["eyes only", "recipient only", "personal", "addressee only"], distance: 80 }),
    ("Corporate Classification", "Proprietary", ContextEntry { keywords: &["proprietary", "trade secret", "intellectual property", "confidential business"], distance: 80 }),
    ("Corporate Classification", "Embargoed", ContextEntry { keywords: &["embargo", "embargoed", "hold until", "not for release", "publication date"], distance: 80 }),

    // Financial Regulatory Labels
    ("Financial Regulatory Labels", "MNPI", ContextEntry { keywords: &["mnpi", "material", "non-public", "insider", "trading", "securities"], distance: 80 }),
    ("Financial Regulatory Labels", "Inside Information", ContextEntry { keywords: &["inside information", "insider", "material", "non-public", "trading restriction"], distance: 80 }),
    ("Financial Regulatory Labels", "Pre-Decisional", ContextEntry { keywords: &["pre-decisional", "draft", "deliberative", "not final", "preliminary"], distance: 80 }),
    ("Financial Regulatory Labels", "Draft Not for Circulation", ContextEntry { keywords: &["draft", "circulation", "preliminary", "not final", "review only"], distance: 80 }),
    ("Financial Regulatory Labels", "Market Sensitive", ContextEntry { keywords: &["market sensitive", "price sensitive", "stock", "securities", "trading"], distance: 80 }),
    ("Financial Regulatory Labels", "Information Barrier", ContextEntry { keywords: &["information barrier", "chinese wall", "wall crossing", "restricted side", "public side"], distance: 80 }),
    ("Financial Regulatory Labels", "Investment Restricted", ContextEntry { keywords: &["restricted list", "watch list", "grey list", "restricted securities", "trading restriction"], distance: 80 }),

    // Privacy Classification
    ("Privacy Classification", "PII Label", ContextEntry { keywords: &["pii", "personally identifiable", "personal information", "sensitive data"], distance: 80 }),
    ("Privacy Classification", "PHI Label", ContextEntry { keywords: &["phi", "protected health", "health information", "medical records", "patient data"], distance: 80 }),
    ("Privacy Classification", "HIPAA", ContextEntry { keywords: &["hipaa", "health insurance portability", "medical privacy", "health data"], distance: 80 }),
    ("Privacy Classification", "GDPR Personal Data", ContextEntry { keywords: &["gdpr", "personal data", "data subject", "data protection", "eu regulation"], distance: 80 }),
    ("Privacy Classification", "PCI-DSS", ContextEntry { keywords: &["pci", "pci-dss", "cardholder data", "payment card", "card data environment"], distance: 80 }),
    ("Privacy Classification", "FERPA", ContextEntry { keywords: &["ferpa", "educational records", "student records", "student privacy"], distance: 80 }),
    ("Privacy Classification", "GLBA", ContextEntry { keywords: &["glba", "gramm-leach-bliley", "financial privacy", "consumer financial"], distance: 80 }),
    ("Privacy Classification", "CCPA/CPRA", ContextEntry { keywords: &["ccpa", "cpra", "california consumer", "california privacy", "consumer rights"], distance: 80 }),
    ("Privacy Classification", "SOX", ContextEntry { keywords: &["sox", "sarbanes-oxley", "financial reporting", "internal controls", "audit"], distance: 80 }),
    ("Privacy Classification", "NPI", ContextEntry { keywords: &["npi", "non-public personal", "financial privacy", "glba", "consumer information"], distance: 80 }),

    // Cloud Provider Secrets
    ("Cloud Provider Secrets", "AWS Access Key", ContextEntry { keywords: &["aws", "amazon", "access key", "aws key"], distance: 80 }),
    ("Cloud Provider Secrets", "AWS Secret Key", ContextEntry { keywords: &["aws secret", "secret access key", "aws_secret"], distance: 80 }),
    ("Cloud Provider Secrets", "Google API Key", ContextEntry { keywords: &["google", "gcp", "google api", "google cloud"], distance: 80 }),

    // Code Platform Secrets
    ("Code Platform Secrets", "GitHub Token (Classic)", ContextEntry { keywords: &["github", "gh token", "personal access token"], distance: 80 }),
    ("Code Platform Secrets", "GitHub Token (Fine-Grained)", ContextEntry { keywords: &["github", "fine-grained", "pat"], distance: 80 }),
    ("Code Platform Secrets", "GitHub OAuth Token", ContextEntry { keywords: &["github oauth", "oauth token"], distance: 80 }),
    ("Code Platform Secrets", "NPM Token", ContextEntry { keywords: &["npm", "node package", "npm token"], distance: 80 }),
    ("Code Platform Secrets", "PyPI Token", ContextEntry { keywords: &["pypi", "python package", "pip"], distance: 80 }),

    // Payment Service Secrets
    ("Payment Service Secrets", "Stripe Secret Key", ContextEntry { keywords: &["stripe", "payment", "stripe secret"], distance: 80 }),
    ("Payment Service Secrets", "Stripe Publishable Key", ContextEntry { keywords: &["stripe", "publishable", "stripe key"], distance: 80 }),

    // Messaging Service Secrets
    ("Messaging Service Secrets", "Slack Bot Token", ContextEntry { keywords: &["slack", "bot token", "slack bot"], distance: 80 }),
    ("Messaging Service Secrets", "Slack User Token", ContextEntry { keywords: &["slack", "user token", "slack user"], distance: 80 }),
    ("Messaging Service Secrets", "Slack Webhook", ContextEntry { keywords: &["slack", "webhook", "incoming webhook"], distance: 80 }),
    ("Messaging Service Secrets", "SendGrid API Key", ContextEntry { keywords: &["sendgrid", "email api"], distance: 80 }),
    ("Messaging Service Secrets", "Twilio API Key", ContextEntry { keywords: &["twilio", "sms", "messaging"], distance: 80 }),
    ("Messaging Service Secrets", "Mailgun API Key", ContextEntry { keywords: &["mailgun", "email"], distance: 80 }),

    // North America - United States
    ("North America - United States", "USA SSN", ContextEntry { keywords: &["social security number", "ssn", "social security no"], distance: 50 }),
    ("North America - United States", "USA ITIN", ContextEntry { keywords: &["individual taxpayer", "itin", "taxpayer identification"], distance: 50 }),
    ("North America - United States", "USA EIN", ContextEntry { keywords: &["employer identification", "ein", "federal tax id", "fein"], distance: 50 }),
    ("North America - United States", "USA Passport", ContextEntry { keywords: &["us passport", "usa passport", "american passport", "passport number", "passport book"], distance: 50 }),
    ("North America - United States", "USA Passport Card", ContextEntry { keywords: &["passport card", "us passport card", "usa passport card"], distance: 50 }),
    ("North America - United States", "USA Routing Number", ContextEntry { keywords: &["routing number", "aba routing", "routing transit"], distance: 50 }),
    ("North America - United States", "US DEA Number", ContextEntry { keywords: &["dea number", "dea registration", "dea no", "drug enforcement"], distance: 50 }),
    ("North America - United States", "US NPI", ContextEntry { keywords: &["npi", "national provider identifier", "provider number"], distance: 50 }),
    ("North America - United States", "US MBI", ContextEntry { keywords: &["mbi", "medicare beneficiary", "beneficiary identifier", "medicare number", "medicare id"], distance: 50 }),
    ("North America - United States", "US DoD ID", ContextEntry { keywords: &["dod id", "military id", "edipi", "cac card", "common access card", "department of defense"], distance: 50 }),
    ("North America - United States", "US Known Traveler Number", ContextEntry { keywords: &["known traveler", "ktn", "global entry", "trusted traveler", "pass id", "nexus", "sentri"], distance: 50 }),
    ("North America - United States", "US Phone Number", ContextEntry { keywords: &["phone", "telephone", "tel", "cell", "mobile", "call", "fax"], distance: 50 }),
    ("North America - United States", "Alabama DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "alabama dl", "alabama license"], distance: 50 }),
    ("North America - United States", "Alaska DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "alaska dl", "alaska license"], distance: 50 }),
    ("North America - United States", "Arizona DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "arizona dl", "arizona license"], distance: 50 }),
    ("North America - United States", "Arkansas DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "arkansas dl", "arkansas license"], distance: 50 }),
    ("North America - United States", "California DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "california dl", "california license"], distance: 50 }),
    ("North America - United States", "Colorado DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "colorado dl", "colorado license"], distance: 50 }),
    ("North America - United States", "Connecticut DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "connecticut dl", "connecticut license"], distance: 50 }),
    ("North America - United States", "Delaware DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "delaware dl", "delaware license"], distance: 50 }),
    ("North America - United States", "DC DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "dc dl", "district of columbia license"], distance: 50 }),
    ("North America - United States", "Florida DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "florida dl", "florida license"], distance: 50 }),
    ("North America - United States", "Georgia DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "georgia dl", "georgia license"], distance: 50 }),
    ("North America - United States", "Hawaii DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "hawaii dl", "hawaii license"], distance: 50 }),
    ("North America - United States", "Idaho DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "idaho dl", "idaho license"], distance: 50 }),
    ("North America - United States", "Illinois DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "illinois dl", "illinois license"], distance: 50 }),
    ("North America - United States", "Indiana DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "indiana dl", "indiana license"], distance: 50 }),
    ("North America - United States", "Iowa DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "iowa dl", "iowa license"], distance: 50 }),
    ("North America - United States", "Kansas DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "kansas dl", "kansas license"], distance: 50 }),
    ("North America - United States", "Kentucky DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "kentucky dl", "kentucky license"], distance: 50 }),
    ("North America - United States", "Louisiana DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "louisiana dl", "louisiana license"], distance: 50 }),
    ("North America - United States", "Maine DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "maine dl", "maine license"], distance: 50 }),
    ("North America - United States", "Maryland DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "maryland dl", "maryland license"], distance: 50 }),
    ("North America - United States", "Massachusetts DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "massachusetts dl", "massachusetts license"], distance: 50 }),
    ("North America - United States", "Michigan DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "michigan dl", "michigan license"], distance: 50 }),
    ("North America - United States", "Minnesota DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "minnesota dl", "minnesota license"], distance: 50 }),
    ("North America - United States", "Mississippi DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "mississippi dl", "mississippi license"], distance: 50 }),
    ("North America - United States", "Missouri DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "missouri dl", "missouri license"], distance: 50 }),
    ("North America - United States", "Montana DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "montana dl", "montana license"], distance: 50 }),
    ("North America - United States", "Nebraska DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "nebraska dl", "nebraska license"], distance: 50 }),
    ("North America - United States", "Nevada DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "nevada dl", "nevada license"], distance: 50 }),
    ("North America - United States", "New Hampshire DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "new hampshire dl", "new hampshire license"], distance: 50 }),
    ("North America - United States", "New Jersey DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "new jersey dl", "new jersey license"], distance: 50 }),
    ("North America - United States", "New Mexico DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "new mexico dl", "new mexico license"], distance: 50 }),
    ("North America - United States", "New York DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "new york dl", "new york license"], distance: 50 }),
    ("North America - United States", "North Carolina DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "north carolina dl", "north carolina license"], distance: 50 }),
    ("North America - United States", "North Dakota DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "north dakota dl", "north dakota license"], distance: 50 }),
    ("North America - United States", "Ohio DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "ohio dl", "ohio license"], distance: 50 }),
    ("North America - United States", "Oklahoma DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "oklahoma dl", "oklahoma license"], distance: 50 }),
    ("North America - United States", "Oregon DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "oregon dl", "oregon license"], distance: 50 }),
    ("North America - United States", "Pennsylvania DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "pennsylvania dl", "pennsylvania license"], distance: 50 }),
    ("North America - United States", "Rhode Island DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "rhode island dl", "rhode island license"], distance: 50 }),
    ("North America - United States", "South Carolina DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "south carolina dl", "south carolina license"], distance: 50 }),
    ("North America - United States", "South Dakota DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "south dakota dl", "south dakota license"], distance: 50 }),
    ("North America - United States", "Tennessee DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "tennessee dl", "tennessee license"], distance: 50 }),
    ("North America - United States", "Texas DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "texas dl", "texas license"], distance: 50 }),
    ("North America - United States", "Utah DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "utah dl", "utah license"], distance: 50 }),
    ("North America - United States", "Vermont DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "vermont dl", "vermont license"], distance: 50 }),
    ("North America - United States", "Virginia DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "virginia dl", "virginia license"], distance: 50 }),
    ("North America - United States", "Washington DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "washington dl", "washington license"], distance: 50 }),
    ("North America - United States", "West Virginia DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "west virginia dl", "west virginia license"], distance: 50 }),
    ("North America - United States", "Wisconsin DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "wisconsin dl", "wisconsin license"], distance: 50 }),
    ("North America - United States", "Wyoming DL", ContextEntry { keywords: &["driver license", "drivers license", "driver's license", "dl", "wyoming dl", "wyoming license"], distance: 50 }),

    // North America - US Generic DL
    ("North America - US Generic DL", "Generic US DL", ContextEntry { keywords: &["driver's license", "dl number", "driving license", "license id", "driver license", "drivers license", "licence number", "license number", "dl no"], distance: 50 }),

    // North America - Canada
    ("North America - Canada", "Canada SIN", ContextEntry { keywords: &["social insurance number", "sin", "social insurance no"], distance: 50 }),
    ("North America - Canada", "Canada BN", ContextEntry { keywords: &["business number", "canada bn", "cra business"], distance: 50 }),
    ("North America - Canada", "Canada Passport", ContextEntry { keywords: &["canadian passport", "canada passport", "passport canada"], distance: 50 }),
    ("North America - Canada", "Canada Bank Code", ContextEntry { keywords: &["transit number", "institution number", "bank transit"], distance: 50 }),
    ("North America - Canada", "Canada PR Card", ContextEntry { keywords: &["permanent resident", "pr card", "permanent resident card", "immigration", "landed immigrant"], distance: 50 }),
    ("North America - Canada", "Canada NEXUS", ContextEntry { keywords: &["nexus", "nexus card", "pass id", "trusted traveler", "nexus number", "cbp pass"], distance: 50 }),
    ("North America - Canada", "Ontario DL", ContextEntry { keywords: &["ontario driver's licence", "ontario dl", "on dl"], distance: 50 }),
    ("North America - Canada", "Ontario HC", ContextEntry { keywords: &["ohip", "ontario health card", "ontario health insurance", "health card number", "ohip number"], distance: 50 }),
    ("North America - Canada", "Quebec DL", ContextEntry { keywords: &["quebec driver's licence", "quebec dl", "qc dl", "permis de conduire"], distance: 50 }),
    ("North America - Canada", "Quebec HC", ContextEntry { keywords: &["ramq", "carte soleil", "quebec health card", "regie assurance maladie", "health insurance quebec"], distance: 50 }),
    ("North America - Canada", "British Columbia DL", ContextEntry { keywords: &["british columbia driver's licence", "bc dl", "bc driver's licence"], distance: 50 }),
    ("North America - Canada", "BC HC", ContextEntry { keywords: &["bc msp", "medical services plan", "bc health card", "bc phn", "personal health number"], distance: 50 }),
    ("North America - Canada", "Alberta DL", ContextEntry { keywords: &["alberta driver's licence", "alberta dl", "ab dl"], distance: 50 }),
    ("North America - Canada", "Alberta HC", ContextEntry { keywords: &["ahcip", "alberta health card", "alberta phn", "alberta health care insurance", "ab health"], distance: 50 }),
    ("North America - Canada", "Saskatchewan DL", ContextEntry { keywords: &["saskatchewan driver's licence", "saskatchewan dl", "sk dl"], distance: 50 }),
    ("North America - Canada", "Saskatchewan HC", ContextEntry { keywords: &["saskatchewan health card", "sk health", "sk phn", "saskatchewan health number"], distance: 50 }),
    ("North America - Canada", "Manitoba DL", ContextEntry { keywords: &["manitoba driver's licence", "manitoba dl", "mb dl"], distance: 50 }),
    ("North America - Canada", "Manitoba HC", ContextEntry { keywords: &["manitoba phin", "manitoba health card", "mb health", "personal health identification number"], distance: 50 }),
    ("North America - Canada", "New Brunswick DL", ContextEntry { keywords: &["new brunswick driver's licence", "new brunswick dl", "nb dl"], distance: 50 }),
    ("North America - Canada", "New Brunswick HC", ContextEntry { keywords: &["new brunswick health card", "nb medicare", "nb health", "new brunswick medicare"], distance: 50 }),
    ("North America - Canada", "Nova Scotia DL", ContextEntry { keywords: &["nova scotia driver's licence", "nova scotia dl", "ns dl"], distance: 50 }),
    ("North America - Canada", "Nova Scotia HC", ContextEntry { keywords: &["nova scotia msi", "msi card", "msi number", "nova scotia health card", "ns health"], distance: 50 }),
    ("North America - Canada", "PEI DL", ContextEntry { keywords: &["pei driver's licence", "prince edward island dl", "pe dl"], distance: 50 }),
    ("North America - Canada", "PEI HC", ContextEntry { keywords: &["pei health card", "prince edward island health", "pe health card"], distance: 50 }),
    ("North America - Canada", "Newfoundland DL", ContextEntry { keywords: &["newfoundland driver's licence", "newfoundland dl", "nl dl", "labrador dl"], distance: 50 }),
    ("North America - Canada", "Newfoundland HC", ContextEntry { keywords: &["newfoundland mcp", "mcp card", "mcp number", "medical care plan", "nl health card"], distance: 50 }),
    ("North America - Canada", "Yukon DL", ContextEntry { keywords: &["yukon driver's licence", "yukon dl", "yt dl"], distance: 50 }),
    ("North America - Canada", "NWT DL", ContextEntry { keywords: &["northwest territories driver's licence", "nwt dl", "nt dl"], distance: 50 }),
    ("North America - Canada", "Nunavut DL", ContextEntry { keywords: &["nunavut driver's licence", "nunavut dl", "nu dl"], distance: 50 }),

    // North America - Mexico
    ("North America - Mexico", "Mexico CURP", ContextEntry { keywords: &["curp", "clave unica", "clave unica de registro", "registro de poblacion", "population registry"], distance: 50 }),
    ("North America - Mexico", "Mexico RFC", ContextEntry { keywords: &["rfc", "registro federal", "registro federal de contribuyentes", "federal taxpayer", "tax id mexico"], distance: 50 }),
    ("North America - Mexico", "Mexico Clave Elector", ContextEntry { keywords: &["clave de elector", "credencial para votar", "credencial elector", "ine", "ife", "voter credential"], distance: 50 }),
    ("North America - Mexico", "Mexico INE CIC", ContextEntry { keywords: &["cic", "codigo de identificacion", "ine cic", "credential identification code"], distance: 50 }),
    ("North America - Mexico", "Mexico INE OCR", ContextEntry { keywords: &["ocr", "ine ocr", "optical character recognition", "credencial ocr"], distance: 50 }),
    ("North America - Mexico", "Mexico Passport", ContextEntry { keywords: &["pasaporte mexicano", "mexico passport", "mexican passport", "pasaporte"], distance: 50 }),
    ("North America - Mexico", "Mexico NSS", ContextEntry { keywords: &["nss", "numero de seguro social", "imss", "seguro social", "instituto mexicano del seguro social"], distance: 50 }),

    // Europe - United Kingdom
    ("Europe - United Kingdom", "UK NIN", ContextEntry { keywords: &["national insurance number", "nin", "national insurance no", "ni number"], distance: 50 }),
    ("Europe - United Kingdom", "UK UTR", ContextEntry { keywords: &["unique taxpayer reference", "utr", "tax reference", "self assessment"], distance: 50 }),
    ("Europe - United Kingdom", "UK Passport", ContextEntry { keywords: &["uk passport", "british passport", "united kingdom passport", "hmpo"], distance: 50 }),
    ("Europe - United Kingdom", "UK Sort Code", ContextEntry { keywords: &["sort code", "uk sort", "bank sort", "bank account"], distance: 50 }),
    ("Europe - United Kingdom", "British NHS", ContextEntry { keywords: &["nhs number", "nhs no", "national health service", "nhs"], distance: 50 }),
    ("Europe - United Kingdom", "UK Phone Number", ContextEntry { keywords: &["phone", "telephone", "tel", "mobile", "uk phone"], distance: 50 }),
    ("Europe - United Kingdom", "UK DL", ContextEntry { keywords: &["driving licence", "driver licence", "dvla", "uk driving", "uk dl"], distance: 50 }),

    // Europe - Germany
    ("Europe - Germany", "Germany ID", ContextEntry { keywords: &["personalausweis", "german id", "identification number", "ausweisnummer"], distance: 50 }),
    ("Europe - Germany", "Germany Passport", ContextEntry { keywords: &["german passport", "germany passport", "reisepass"], distance: 50 }),
    ("Europe - Germany", "Germany Tax ID", ContextEntry { keywords: &["steueridentifikationsnummer", "steuer-id", "tax identification", "tin", "steuernummer"], distance: 50 }),
    ("Europe - Germany", "Germany Social Insurance", ContextEntry { keywords: &["sozialversicherungsnummer", "social insurance", "sv-nummer", "rentenversicherung"], distance: 50 }),
    ("Europe - Germany", "Germany DL", ContextEntry { keywords: &["fuhrerschein", "driving licence", "german driving", "fahrerlaubnis"], distance: 50 }),
    ("Europe - Germany", "Germany IBAN", ContextEntry { keywords: &["iban", "german bank", "bankverbindung", "kontonummer"], distance: 50 }),

    // Europe - France
    ("Europe - France", "France NIR", ContextEntry { keywords: &["insee", "nir", "securite sociale", "french social security", "numero de securite"], distance: 50 }),
    ("Europe - France", "France Passport", ContextEntry { keywords: &["french passport", "france passport", "passeport"], distance: 50 }),
    ("Europe - France", "France CNI", ContextEntry { keywords: &["carte nationale", "carte identite", "cni", "french id card"], distance: 50 }),
    ("Europe - France", "France DL", ContextEntry { keywords: &["permis de conduire", "french driving", "permis"], distance: 50 }),
    ("Europe - France", "France IBAN", ContextEntry { keywords: &["iban", "french bank", "compte bancaire", "rib"], distance: 50 }),

    // Europe - Italy
    ("Europe - Italy", "Italy Codice Fiscale", ContextEntry { keywords: &["codice fiscale", "fiscal code", "italian tax", "cf"], distance: 50 }),
    ("Europe - Italy", "Italy Passport", ContextEntry { keywords: &["italian passport", "italy passport", "passaporto"], distance: 50 }),
    ("Europe - Italy", "Italy DL", ContextEntry { keywords: &["patente di guida", "italian driving", "patente"], distance: 50 }),
    ("Europe - Italy", "Italy SSN", ContextEntry { keywords: &["italian ssn", "tessera sanitaria", "health card"], distance: 50 }),
    ("Europe - Italy", "Italy Partita IVA", ContextEntry { keywords: &["partita iva", "vat number", "p.iva", "piva"], distance: 50 }),

    // Europe - Netherlands
    ("Europe - Netherlands", "Netherlands BSN", ContextEntry { keywords: &["burgerservicenummer", "bsn", "citizen service number", "sofinummer"], distance: 50 }),
    ("Europe - Netherlands", "Netherlands Passport", ContextEntry { keywords: &["dutch passport", "netherlands passport", "nl passport"], distance: 50 }),
    ("Europe - Netherlands", "Netherlands DL", ContextEntry { keywords: &["rijbewijs", "dutch driving", "netherlands driving licence"], distance: 50 }),
    ("Europe - Netherlands", "Netherlands IBAN", ContextEntry { keywords: &["iban", "dutch bank", "nl bank", "rekeningnummer"], distance: 50 }),

    // Europe - Spain
    ("Europe - Spain", "Spain DNI", ContextEntry { keywords: &["dni", "documento nacional de identidad", "spanish id"], distance: 50 }),
    ("Europe - Spain", "Spain NIE", ContextEntry { keywords: &["nie", "numero de identidad de extranjero", "foreigner id"], distance: 50 }),
    ("Europe - Spain", "Spain Passport", ContextEntry { keywords: &["spanish passport", "pasaporte", "spain passport"], distance: 50 }),
    ("Europe - Spain", "Spain NSS", ContextEntry { keywords: &["numero seguridad social", "nss", "spanish social security"], distance: 50 }),
    ("Europe - Spain", "Spain DL", ContextEntry { keywords: &["permiso de conducir", "carnet de conducir", "spanish driving"], distance: 50 }),

    // Europe - Poland
    ("Europe - Poland", "Poland PESEL", ContextEntry { keywords: &["pesel", "polish id", "personal identification number", "numer pesel"], distance: 50 }),
    ("Europe - Poland", "Poland NIP", ContextEntry { keywords: &["nip", "numer identyfikacji podatkowej", "tax identification"], distance: 50 }),
    ("Europe - Poland", "Poland REGON", ContextEntry { keywords: &["regon", "statistical number", "business registration"], distance: 50 }),
    ("Europe - Poland", "Poland ID Card", ContextEntry { keywords: &["dowod osobisty", "polish id card", "identity card"], distance: 50 }),
    ("Europe - Poland", "Poland Passport", ContextEntry { keywords: &["polish passport", "paszport"], distance: 50 }),
    ("Europe - Poland", "Poland DL", ContextEntry { keywords: &["prawo jazdy", "polish driving", "driving licence"], distance: 50 }),

    // Europe - Sweden
    ("Europe - Sweden", "Sweden PIN", ContextEntry { keywords: &["personnummer", "swedish id", "personal identity number", "swedish personal number"], distance: 50 }),
    ("Europe - Sweden", "Sweden Passport", ContextEntry { keywords: &["swedish passport", "sverige pass"], distance: 50 }),
    ("Europe - Sweden", "Sweden DL", ContextEntry { keywords: &["korkort", "swedish driving", "driving licence"], distance: 50 }),
    ("Europe - Sweden", "Sweden Organisation Number", ContextEntry { keywords: &["organisationsnummer", "org number", "swedish company"], distance: 50 }),

    // Europe - Portugal
    ("Europe - Portugal", "Portugal NIF", ContextEntry { keywords: &["nif", "contribuinte", "tax identification", "numero fiscal"], distance: 50 }),
    ("Europe - Portugal", "Portugal CC", ContextEntry { keywords: &["cartao cidadao", "citizen card", "cartao de cidadao", "cc number"], distance: 50 }),
    ("Europe - Portugal", "Portugal Passport", ContextEntry { keywords: &["portuguese passport", "passaporte"], distance: 50 }),
    ("Europe - Portugal", "Portugal NISS", ContextEntry { keywords: &["niss", "seguranca social", "social security", "numero seguranca"], distance: 50 }),

    // Europe - Switzerland
    ("Europe - Switzerland", "Switzerland AHV", ContextEntry { keywords: &["ahv", "avs", "swiss social security", "ahv-nummer", "oasi"], distance: 50 }),
    ("Europe - Switzerland", "Switzerland Passport", ContextEntry { keywords: &["swiss passport", "schweizer pass"], distance: 50 }),
    ("Europe - Switzerland", "Switzerland DL", ContextEntry { keywords: &["fuhrerschein", "swiss driving", "fahrausweis", "permis de conduire"], distance: 50 }),
    ("Europe - Switzerland", "Switzerland UID", ContextEntry { keywords: &["uid", "unternehmens-identifikationsnummer", "swiss company", "che number"], distance: 50 }),

    // Europe - Turkey
    ("Europe - Turkey", "Turkey TC Kimlik", ContextEntry { keywords: &["tc kimlik", "turkish id", "kimlik numarasi", "tc no"], distance: 50 }),
    ("Europe - Turkey", "Turkey Passport", ContextEntry { keywords: &["turkish passport", "turk pasaportu"], distance: 50 }),
    ("Europe - Turkey", "Turkey DL", ContextEntry { keywords: &["surucu belgesi", "ehliyet", "turkish driving"], distance: 50 }),
    ("Europe - Turkey", "Turkey Tax ID", ContextEntry { keywords: &["vergi kimlik", "vergi numarasi", "turkish tax", "vkn"], distance: 50 }),

    // Europe - Austria
    ("Europe - Austria", "Austria SVN", ContextEntry { keywords: &["sozialversicherungsnummer", "svnr", "sv-nummer", "austrian social security", "versicherungsnummer"], distance: 50 }),
    ("Europe - Austria", "Austria Passport", ContextEntry { keywords: &["austrian passport", "osterreichischer reisepass", "reisepass"], distance: 50 }),
    ("Europe - Austria", "Austria ID Card", ContextEntry { keywords: &["personalausweis", "austrian id", "identity card"], distance: 50 }),
    ("Europe - Austria", "Austria DL", ContextEntry { keywords: &["fuhrerschein", "austrian driving", "driving licence"], distance: 50 }),
    ("Europe - Austria", "Austria Tax Number", ContextEntry { keywords: &["steuernummer", "austrian tax", "tax number", "abgabenkontonummer"], distance: 50 }),

    // Europe - Belgium
    ("Europe - Belgium", "Belgium NRN", ContextEntry { keywords: &["rijksregisternummer", "nrn", "national register number", "registre national", "insz"], distance: 50 }),
    ("Europe - Belgium", "Belgium Passport", ContextEntry { keywords: &["belgian passport", "belgisch paspoort", "passeport belge"], distance: 50 }),
    ("Europe - Belgium", "Belgium DL", ContextEntry { keywords: &["belgisch rijbewijs", "belgian driving", "permis de conduire belge"], distance: 50 }),
    ("Europe - Belgium", "Belgium VAT", ContextEntry { keywords: &["btw", "tva", "belgian vat", "ondernemingsnummer", "numero entreprise"], distance: 50 }),

    // Europe - Ireland
    ("Europe - Ireland", "Ireland PPS", ContextEntry { keywords: &["pps", "ppsn", "personal public service", "pps number"], distance: 50 }),
    ("Europe - Ireland", "Ireland Passport", ContextEntry { keywords: &["irish passport", "ireland passport"], distance: 50 }),
    ("Europe - Ireland", "Ireland DL", ContextEntry { keywords: &["irish driving", "driving licence", "ceadunas tiomana"], distance: 50 }),
    ("Europe - Ireland", "Ireland Eircode", ContextEntry { keywords: &["eircode", "irish postcode", "postal code"], distance: 50 }),

    // Europe - Denmark
    ("Europe - Denmark", "Denmark CPR", ContextEntry { keywords: &["cpr", "personnummer", "cpr-nummer", "danish personal", "civil registration"], distance: 50 }),
    ("Europe - Denmark", "Denmark Passport", ContextEntry { keywords: &["danish passport", "dansk pas"], distance: 50 }),
    ("Europe - Denmark", "Denmark DL", ContextEntry { keywords: &["korekort", "danish driving", "driving licence"], distance: 50 }),

    // Europe - Finland
    ("Europe - Finland", "Finland HETU", ContextEntry { keywords: &["henkilotunnus", "hetu", "finnish personal identity", "personal identity code", "henkilotunnus"], distance: 50 }),
    ("Europe - Finland", "Finland Passport", ContextEntry { keywords: &["finnish passport", "suomen passi"], distance: 50 }),
    ("Europe - Finland", "Finland DL", ContextEntry { keywords: &["ajokortti", "finnish driving", "driving licence"], distance: 50 }),

    // Europe - Norway
    ("Europe - Norway", "Norway FNR", ContextEntry { keywords: &["fodselsnummer", "fnr", "norwegian personal", "birth number", "personnummer"], distance: 50 }),
    ("Europe - Norway", "Norway D-Number", ContextEntry { keywords: &["d-nummer", "d-number", "norwegian temporary"], distance: 50 }),
    ("Europe - Norway", "Norway Passport", ContextEntry { keywords: &["norwegian passport", "norsk pass"], distance: 50 }),
    ("Europe - Norway", "Norway DL", ContextEntry { keywords: &["forerkort", "norwegian driving", "driving licence"], distance: 50 }),

    // Europe - Czech Republic
    ("Europe - Czech Republic", "Czech Birth Number", ContextEntry { keywords: &["rodne cislo", "birth number", "czech personal", "rc"], distance: 50 }),
    ("Europe - Czech Republic", "Czech Passport", ContextEntry { keywords: &["czech passport", "cesky pas"], distance: 50 }),
    ("Europe - Czech Republic", "Czech DL", ContextEntry { keywords: &["ridicsky prukaz", "czech driving", "driving licence"], distance: 50 }),
    ("Europe - Czech Republic", "Czech ICO", ContextEntry { keywords: &["ico", "identifikacni cislo", "business id"], distance: 50 }),

    // Europe - Hungary
    ("Europe - Hungary", "Hungary Personal ID", ContextEntry { keywords: &["szemelyazonosito", "personal id", "hungarian id", "szemelyi szam"], distance: 50 }),
    ("Europe - Hungary", "Hungary TAJ", ContextEntry { keywords: &["taj szam", "social security", "taj", "egeszsegbiztositasi"], distance: 50 }),
    ("Europe - Hungary", "Hungary Tax Number", ContextEntry { keywords: &["adoazonosito", "tax number", "hungarian tax", "ado szam"], distance: 50 }),
    ("Europe - Hungary", "Hungary Passport", ContextEntry { keywords: &["hungarian passport", "magyar utlevel"], distance: 50 }),
    ("Europe - Hungary", "Hungary DL", ContextEntry { keywords: &["jogositvany", "hungarian driving", "veztoi engedely"], distance: 50 }),

    // Europe - Romania
    ("Europe - Romania", "Romania CNP", ContextEntry { keywords: &["cnp", "cod numeric personal", "romanian personal", "personal numeric code"], distance: 50 }),
    ("Europe - Romania", "Romania CIF", ContextEntry { keywords: &["cif", "cod identificare fiscala", "romanian tax", "fiscal code"], distance: 50 }),
    ("Europe - Romania", "Romania Passport", ContextEntry { keywords: &["romanian passport", "pasaport"], distance: 50 }),
    ("Europe - Romania", "Romania DL", ContextEntry { keywords: &["permis de conducere", "romanian driving", "driving licence"], distance: 50 }),

    // Europe - Greece
    ("Europe - Greece", "Greece AFM", ContextEntry { keywords: &["afm", "arithmos forologikou mitroou", "greek tax", "tax number"], distance: 50 }),
    ("Europe - Greece", "Greece AMKA", ContextEntry { keywords: &["amka", "social security", "arithmos mitroou koinonikis asfalisis"], distance: 50 }),
    ("Europe - Greece", "Greece ID Card", ContextEntry { keywords: &["taftotita", "greek id", "deltio taftotitas", "identity card"], distance: 50 }),
    ("Europe - Greece", "Greece Passport", ContextEntry { keywords: &["greek passport", "elliniko diavatirio"], distance: 50 }),
    ("Europe - Greece", "Greece DL", ContextEntry { keywords: &["adeia odigisis", "greek driving", "driving licence"], distance: 50 }),

    // Europe - Croatia
    ("Europe - Croatia", "Croatia OIB", ContextEntry { keywords: &["oib", "osobni identifikacijski broj", "croatian personal", "personal identification number"], distance: 50 }),
    ("Europe - Croatia", "Croatia Passport", ContextEntry { keywords: &["croatian passport", "hrvatska putovnica"], distance: 50 }),
    ("Europe - Croatia", "Croatia ID Card", ContextEntry { keywords: &["osobna iskaznica", "croatian id", "identity card"], distance: 50 }),
    ("Europe - Croatia", "Croatia DL", ContextEntry { keywords: &["vozacka dozvola", "croatian driving", "driving licence"], distance: 50 }),

    // Europe - Bulgaria
    ("Europe - Bulgaria", "Bulgaria EGN", ContextEntry { keywords: &["egn", "edinen grazhdanski nomer", "bulgarian personal", "unified civil number"], distance: 50 }),
    ("Europe - Bulgaria", "Bulgaria LNC", ContextEntry { keywords: &["lnch", "lichna karta", "foreigner number", "personal number of foreigner"], distance: 50 }),
    ("Europe - Bulgaria", "Bulgaria ID Card", ContextEntry { keywords: &["lichna karta", "bulgarian id", "identity card"], distance: 50 }),
    ("Europe - Bulgaria", "Bulgaria Passport", ContextEntry { keywords: &["bulgarian passport", "bulgarski pasport"], distance: 50 }),

    // Europe - Slovakia
    ("Europe - Slovakia", "Slovakia Birth Number", ContextEntry { keywords: &["rodne cislo", "birth number", "slovak personal", "rc"], distance: 50 }),
    ("Europe - Slovakia", "Slovakia Passport", ContextEntry { keywords: &["slovak passport", "slovensky pas"], distance: 50 }),
    ("Europe - Slovakia", "Slovakia DL", ContextEntry { keywords: &["vodicsky preukaz", "slovak driving", "driving licence"], distance: 50 }),

    // Europe - Lithuania
    ("Europe - Lithuania", "Lithuania Asmens Kodas", ContextEntry { keywords: &["asmens kodas", "lithuanian personal", "personal code", "ak"], distance: 50 }),
    ("Europe - Lithuania", "Lithuania Passport", ContextEntry { keywords: &["lithuanian passport", "lietuvos pasas"], distance: 50 }),
    ("Europe - Lithuania", "Lithuania DL", ContextEntry { keywords: &["vairuotojo pazymejimas", "lithuanian driving", "driving licence"], distance: 50 }),

    // Europe - Latvia
    ("Europe - Latvia", "Latvia Personas Kods", ContextEntry { keywords: &["personas kods", "latvian personal", "personal code", "pk"], distance: 50 }),
    ("Europe - Latvia", "Latvia Passport", ContextEntry { keywords: &["latvian passport", "latvijas pase"], distance: 50 }),
    ("Europe - Latvia", "Latvia DL", ContextEntry { keywords: &["vaditaja aplieciba", "latvian driving", "driving licence"], distance: 50 }),

    // Europe - Estonia
    ("Europe - Estonia", "Estonia Isikukood", ContextEntry { keywords: &["isikukood", "estonian personal", "personal identification code", "id-kood"], distance: 50 }),
    ("Europe - Estonia", "Estonia Passport", ContextEntry { keywords: &["estonian passport", "eesti pass"], distance: 50 }),
    ("Europe - Estonia", "Estonia DL", ContextEntry { keywords: &["juhiluba", "estonian driving", "driving licence"], distance: 50 }),

    // Europe - Slovenia
    ("Europe - Slovenia", "Slovenia EMSO", ContextEntry { keywords: &["emso", "enotna maticna stevilka", "slovenian personal", "personal number"], distance: 50 }),
    ("Europe - Slovenia", "Slovenia Tax Number", ContextEntry { keywords: &["davcna stevilka", "slovenian tax", "tax number"], distance: 50 }),
    ("Europe - Slovenia", "Slovenia Passport", ContextEntry { keywords: &["slovenian passport", "slovenski potni list"], distance: 50 }),
    ("Europe - Slovenia", "Slovenia DL", ContextEntry { keywords: &["voznisko dovoljenje", "slovenian driving", "driving licence"], distance: 50 }),

    // Europe - Luxembourg
    ("Europe - Luxembourg", "Luxembourg NIN", ContextEntry { keywords: &["matricule", "luxembourg id", "national identification", "nin"], distance: 50 }),
    ("Europe - Luxembourg", "Luxembourg Passport", ContextEntry { keywords: &["luxembourg passport", "passeport"], distance: 50 }),
    ("Europe - Luxembourg", "Luxembourg DL", ContextEntry { keywords: &["permis de conduire", "luxembourg driving", "driving licence"], distance: 50 }),

    // Europe - Malta
    ("Europe - Malta", "Malta ID Card", ContextEntry { keywords: &["maltese id", "identity card", "karta tal-identita"], distance: 50 }),
    ("Europe - Malta", "Malta Passport", ContextEntry { keywords: &["maltese passport", "passaport malti"], distance: 50 }),
    ("Europe - Malta", "Malta TIN", ContextEntry { keywords: &["maltese tax", "tin", "tax identification"], distance: 50 }),

    // Europe - Cyprus
    ("Europe - Cyprus", "Cyprus ID Card", ContextEntry { keywords: &["cypriot id", "identity card", "taftotita"], distance: 50 }),
    ("Europe - Cyprus", "Cyprus Passport", ContextEntry { keywords: &["cypriot passport", "kypriako diavatirio"], distance: 50 }),
    ("Europe - Cyprus", "Cyprus TIN", ContextEntry { keywords: &["cypriot tax", "tin", "tax identification"], distance: 50 }),

    // Europe - Iceland
    ("Europe - Iceland", "Iceland Kennitala", ContextEntry { keywords: &["kennitala", "icelandic id", "personal id number", "kt"], distance: 50 }),
    ("Europe - Iceland", "Iceland Passport", ContextEntry { keywords: &["icelandic passport", "islenskt vegabref"], distance: 50 }),

    // Europe - Liechtenstein
    ("Europe - Liechtenstein", "Liechtenstein PIN", ContextEntry { keywords: &["liechtenstein personal", "personal identification", "pin"], distance: 50 }),
    ("Europe - Liechtenstein", "Liechtenstein Passport", ContextEntry { keywords: &["liechtenstein passport"], distance: 50 }),

    // Europe - EU
    ("Europe - EU", "EU ETD", ContextEntry { keywords: &["eu emergency travel document", "etd", "emergency travel"], distance: 50 }),
    ("Europe - EU", "EU VAT Generic", ContextEntry { keywords: &["vat number", "vat registration", "eu vat", "value added tax"], distance: 50 }),

    // Asia-Pacific - India
    ("Asia-Pacific - India", "India PAN", ContextEntry { keywords: &["permanent account number", "pan", "pan card", "income tax", "pan no"], distance: 50 }),
    ("Asia-Pacific - India", "India Aadhaar", ContextEntry { keywords: &["aadhaar", "aadhar", "aadhaar number", "uid number", "uidai"], distance: 50 }),
    ("Asia-Pacific - India", "India Passport", ContextEntry { keywords: &["indian passport", "india passport", "passport number", "passport no", "travel document"], distance: 50 }),
    ("Asia-Pacific - India", "India DL", ContextEntry { keywords: &["driving licence", "driver licence", "indian dl", "driving license india", "rto"], distance: 50 }),
    ("Asia-Pacific - India", "India Voter ID", ContextEntry { keywords: &["voter id", "epic", "election commission", "voter card", "electoral"], distance: 50 }),
    ("Asia-Pacific - India", "India Ration Card", ContextEntry { keywords: &["ration card", "ration number", "public distribution", "food supply", "bpl card"], distance: 50 }),

    // Asia-Pacific - China
    ("Asia-Pacific - China", "China Resident ID", ContextEntry { keywords: &["resident id", "identity card", "shenfenzheng", "id card number", "citizen id"], distance: 50 }),
    ("Asia-Pacific - China", "China Passport", ContextEntry { keywords: &["chinese passport", "china passport", "passport number", "huzhao"], distance: 50 }),
    ("Asia-Pacific - China", "Hong Kong ID", ContextEntry { keywords: &["hong kong id", "hkid", "identity card", "hk id card", "hong kong identity"], distance: 50 }),
    ("Asia-Pacific - China", "Macau ID", ContextEntry { keywords: &["macau id", "bir", "macau identity", "macau resident", "bilhete de identidade"], distance: 50 }),
    ("Asia-Pacific - China", "Taiwan National ID", ContextEntry { keywords: &["taiwan id", "national id", "identity number", "taiwan national", "roc id"], distance: 50 }),

    // Asia-Pacific - Japan
    ("Asia-Pacific - Japan", "Japan My Number", ContextEntry { keywords: &["my number", "individual number", "kojin bango", "mynumber", "social security tax"], distance: 50 }),
    ("Asia-Pacific - Japan", "Japan Passport", ContextEntry { keywords: &["japanese passport", "japan passport", "passport number", "ryoken"], distance: 50 }),
    ("Asia-Pacific - Japan", "Japan DL", ContextEntry { keywords: &["driving licence", "driver license", "unten menkyo", "japan licence", "japanese dl"], distance: 50 }),
    ("Asia-Pacific - Japan", "Japan Juminhyo Code", ContextEntry { keywords: &["juminhyo", "resident record", "resident registration", "juki net", "basic resident registry"], distance: 50 }),
    ("Asia-Pacific - Japan", "Japan Health Insurance", ContextEntry { keywords: &["health insurance", "hoken", "insurer number", "hokensho", "medical insurance"], distance: 50 }),
    ("Asia-Pacific - Japan", "Japan Residence Card", ContextEntry { keywords: &["residence card", "zairyu card", "zairyu", "residence permit", "foreigner registration"], distance: 50 }),

    // Asia-Pacific - South Korea
    ("Asia-Pacific - South Korea", "South Korea RRN", ContextEntry { keywords: &["resident registration", "rrn", "jumin deungnok", "jumin", "resident number"], distance: 50 }),
    ("Asia-Pacific - South Korea", "South Korea Passport", ContextEntry { keywords: &["korean passport", "korea passport", "passport number", "yeogwon"], distance: 50 }),
    ("Asia-Pacific - South Korea", "South Korea DL", ContextEntry { keywords: &["driving licence", "driver license", "korean dl", "unjon myonho", "korea licence"], distance: 50 }),

    // Asia-Pacific - Singapore
    ("Asia-Pacific - Singapore", "Singapore NRIC", ContextEntry { keywords: &["nric", "national registration", "identity card", "singapore id", "ic number"], distance: 50 }),
    ("Asia-Pacific - Singapore", "Singapore FIN", ContextEntry { keywords: &["fin", "foreign identification", "foreign id", "work permit", "employment pass"], distance: 50 }),
    ("Asia-Pacific - Singapore", "Singapore Passport", ContextEntry { keywords: &["singapore passport", "passport number", "sg passport", "travel document"], distance: 50 }),
    ("Asia-Pacific - Singapore", "Singapore DL", ContextEntry { keywords: &["driving licence", "driver license", "singapore dl", "singapore licence", "traffic police"], distance: 50 }),

    // Asia-Pacific - Australia
    ("Asia-Pacific - Australia", "Australia TFN", ContextEntry { keywords: &["tax file number", "tfn", "australian tax", "ato", "tax return"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia Medicare", ContextEntry { keywords: &["medicare", "medicare number", "medicare card", "health insurance", "bulk billing"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia Passport", ContextEntry { keywords: &["australian passport", "australia passport", "passport number", "travel document"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL NSW", ContextEntry { keywords: &["nsw licence", "new south wales licence", "nsw driver", "rms", "service nsw"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL VIC", ContextEntry { keywords: &["vic licence", "victoria licence", "vicroads", "victorian driver"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL QLD", ContextEntry { keywords: &["qld licence", "queensland licence", "tmr", "queensland driver"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL WA", ContextEntry { keywords: &["wa licence", "western australia licence", "wa driver", "dol wa"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL SA", ContextEntry { keywords: &["sa licence", "south australia licence", "sa driver", "dpti"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL TAS", ContextEntry { keywords: &["tas licence", "tasmania licence", "tasmanian driver"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL ACT", ContextEntry { keywords: &["act licence", "canberra licence", "act driver"], distance: 50 }),
    ("Asia-Pacific - Australia", "Australia DL NT", ContextEntry { keywords: &["nt licence", "northern territory licence", "nt driver"], distance: 50 }),

    // Asia-Pacific - New Zealand
    ("Asia-Pacific - New Zealand", "New Zealand IRD", ContextEntry { keywords: &["ird", "inland revenue", "tax number", "ird number", "nz tax"], distance: 50 }),
    ("Asia-Pacific - New Zealand", "New Zealand Passport", ContextEntry { keywords: &["new zealand passport", "nz passport", "passport number", "aotearoa passport"], distance: 50 }),
    ("Asia-Pacific - New Zealand", "New Zealand NHI", ContextEntry { keywords: &["nhi", "national health index", "health index", "nhi number", "health system"], distance: 50 }),
    ("Asia-Pacific - New Zealand", "New Zealand DL", ContextEntry { keywords: &["driving licence", "driver licence", "nz licence", "nzta", "waka kotahi"], distance: 50 }),

    // Asia-Pacific - Philippines
    ("Asia-Pacific - Philippines", "Philippines PhilSys", ContextEntry { keywords: &["philsys", "national id", "philid", "psn", "philippine identification"], distance: 50 }),
    ("Asia-Pacific - Philippines", "Philippines TIN", ContextEntry { keywords: &["tin", "tax identification", "bir", "bureau of internal revenue", "taxpayer"], distance: 50 }),
    ("Asia-Pacific - Philippines", "Philippines SSS", ContextEntry { keywords: &["sss", "social security", "sss number", "social security system"], distance: 50 }),
    ("Asia-Pacific - Philippines", "Philippines PhilHealth", ContextEntry { keywords: &["philhealth", "health insurance", "pin", "philhealth number", "medical insurance"], distance: 50 }),
    ("Asia-Pacific - Philippines", "Philippines Passport", ContextEntry { keywords: &["philippine passport", "philippines passport", "passport number", "dfa passport"], distance: 50 }),
    ("Asia-Pacific - Philippines", "Philippines UMID", ContextEntry { keywords: &["umid", "unified multi-purpose", "crn", "common reference number", "umid card"], distance: 50 }),

    // Asia-Pacific - Thailand
    ("Asia-Pacific - Thailand", "Thailand National ID", ContextEntry { keywords: &["thai id", "national id", "bat prachakon", "citizen id", "identity card"], distance: 50 }),
    ("Asia-Pacific - Thailand", "Thailand Passport", ContextEntry { keywords: &["thai passport", "thailand passport", "passport number", "nangsue doen thang"], distance: 50 }),
    ("Asia-Pacific - Thailand", "Thailand DL", ContextEntry { keywords: &["driving licence", "driver license", "thai dl", "bai kap khi", "land transport"], distance: 50 }),
    ("Asia-Pacific - Thailand", "Thailand Tax ID", ContextEntry { keywords: &["tax id", "tax number", "revenue department", "tin thailand", "vat number"], distance: 50 }),

    // Asia-Pacific - Malaysia
    ("Asia-Pacific - Malaysia", "Malaysia MyKad", ContextEntry { keywords: &["mykad", "ic number", "identity card", "kad pengenalan", "nric malaysia"], distance: 50 }),
    ("Asia-Pacific - Malaysia", "Malaysia Passport", ContextEntry { keywords: &["malaysian passport", "malaysia passport", "passport number", "pasport"], distance: 50 }),

    // Asia-Pacific - Indonesia
    ("Asia-Pacific - Indonesia", "Indonesia NIK", ContextEntry { keywords: &["nik", "nomor induk kependudukan", "ktp", "identity card", "kartu tanda penduduk"], distance: 50 }),
    ("Asia-Pacific - Indonesia", "Indonesia NPWP", ContextEntry { keywords: &["npwp", "nomor pokok wajib pajak", "tax id", "taxpayer number", "pajak"], distance: 50 }),
    ("Asia-Pacific - Indonesia", "Indonesia Passport", ContextEntry { keywords: &["indonesian passport", "indonesia passport", "passport number", "paspor"], distance: 50 }),

    // Asia-Pacific - Vietnam
    ("Asia-Pacific - Vietnam", "Vietnam CCCD", ContextEntry { keywords: &["cccd", "cmnd", "citizen id", "can cuoc cong dan", "identity card"], distance: 50 }),
    ("Asia-Pacific - Vietnam", "Vietnam Passport", ContextEntry { keywords: &["vietnamese passport", "vietnam passport", "passport number", "ho chieu"], distance: 50 }),
    ("Asia-Pacific - Vietnam", "Vietnam Tax Code", ContextEntry { keywords: &["tax code", "ma so thue", "mst", "tax id", "tax number"], distance: 50 }),

    // Asia-Pacific - Pakistan
    ("Asia-Pacific - Pakistan", "Pakistan CNIC", ContextEntry { keywords: &["cnic", "computerized national identity", "nadra", "national identity card", "identity card"], distance: 50 }),
    ("Asia-Pacific - Pakistan", "Pakistan NICOP", ContextEntry { keywords: &["nicop", "national identity card overseas", "overseas pakistani", "nadra nicop"], distance: 50 }),
    ("Asia-Pacific - Pakistan", "Pakistan Passport", ContextEntry { keywords: &["pakistani passport", "pakistan passport", "passport number", "travel document"], distance: 50 }),

    // Asia-Pacific - Bangladesh
    ("Asia-Pacific - Bangladesh", "Bangladesh NID", ContextEntry { keywords: &["nid", "national id", "voter id", "national identity", "smart card bangladesh"], distance: 50 }),
    ("Asia-Pacific - Bangladesh", "Bangladesh Passport", ContextEntry { keywords: &["bangladeshi passport", "bangladesh passport", "passport number", "e-passport"], distance: 50 }),
    ("Asia-Pacific - Bangladesh", "Bangladesh TIN", ContextEntry { keywords: &["tin", "tax identification", "nbr", "national board of revenue", "taxpayer"], distance: 50 }),

    // Asia-Pacific - Sri Lanka
    ("Asia-Pacific - Sri Lanka", "Sri Lanka NIC Old", ContextEntry { keywords: &["nic", "national identity card", "identity card", "sri lanka id", "jatika handunumpat"], distance: 50 }),
    ("Asia-Pacific - Sri Lanka", "Sri Lanka NIC New", ContextEntry { keywords: &["nic", "national identity card", "identity card", "sri lanka id", "new nic"], distance: 50 }),
    ("Asia-Pacific - Sri Lanka", "Sri Lanka Passport", ContextEntry { keywords: &["sri lankan passport", "sri lanka passport", "passport number", "travel document"], distance: 50 }),

    // Latin America - Brazil
    ("Latin America - Brazil", "Brazil CPF", ContextEntry { keywords: &["cpf", "cadastro de pessoas fisicas", "cadastro pessoa fisica", "contribuinte", "receita federal"], distance: 50 }),
    ("Latin America - Brazil", "Brazil CNPJ", ContextEntry { keywords: &["cnpj", "cadastro nacional", "pessoa juridica", "empresa", "razao social"], distance: 50 }),
    ("Latin America - Brazil", "Brazil RG", ContextEntry { keywords: &["rg", "registro geral", "identidade", "carteira de identidade", "documento de identidade"], distance: 50 }),
    ("Latin America - Brazil", "Brazil CNH", ContextEntry { keywords: &["cnh", "carteira de habilitacao", "habilitacao", "driving licence", "carteira nacional"], distance: 50 }),
    ("Latin America - Brazil", "Brazil SUS Card", ContextEntry { keywords: &["sus", "cartao nacional de saude", "cns", "saude", "cartao sus"], distance: 50 }),
    ("Latin America - Brazil", "Brazil Passport", ContextEntry { keywords: &["passaporte", "brazilian passport", "brazil passport", "passport number"], distance: 50 }),

    // Latin America - Argentina
    ("Latin America - Argentina", "Argentina DNI", ContextEntry { keywords: &["dni", "documento nacional de identidad", "documento nacional", "identidad", "renaper"], distance: 50 }),
    ("Latin America - Argentina", "Argentina CUIL/CUIT", ContextEntry { keywords: &["cuil", "cuit", "clave unica", "identificacion tributaria", "afip"], distance: 50 }),
    ("Latin America - Argentina", "Argentina Passport", ContextEntry { keywords: &["pasaporte", "argentinian passport", "argentina passport", "passport number"], distance: 50 }),

    // Latin America - Colombia
    ("Latin America - Colombia", "Colombia Cedula", ContextEntry { keywords: &["cedula", "cedula de ciudadania", "cc", "documento identidad", "registraduria"], distance: 50 }),
    ("Latin America - Colombia", "Colombia NIT", ContextEntry { keywords: &["nit", "numero de identificacion tributaria", "dian", "contribuyente", "tax id"], distance: 50 }),
    ("Latin America - Colombia", "Colombia NUIP", ContextEntry { keywords: &["nuip", "numero unico de identificacion personal", "identificacion personal", "tarjeta identidad"], distance: 50 }),
    ("Latin America - Colombia", "Colombia Passport", ContextEntry { keywords: &["pasaporte", "colombian passport", "colombia passport", "passport number"], distance: 50 }),

    // Latin America - Chile
    ("Latin America - Chile", "Chile RUN/RUT", ContextEntry { keywords: &["rut", "run", "rol unico tributario", "rol unico nacional", "cedula identidad"], distance: 50 }),
    ("Latin America - Chile", "Chile Passport", ContextEntry { keywords: &["pasaporte", "chilean passport", "chile passport", "passport number"], distance: 50 }),

    // Latin America - Peru
    ("Latin America - Peru", "Peru DNI", ContextEntry { keywords: &["dni", "documento nacional de identidad", "reniec", "identidad", "documento identidad"], distance: 50 }),
    ("Latin America - Peru", "Peru RUC", ContextEntry { keywords: &["ruc", "registro unico de contribuyentes", "sunat", "contribuyente", "tax id"], distance: 50 }),
    ("Latin America - Peru", "Peru Carnet Extranjeria", ContextEntry { keywords: &["carnet de extranjeria", "carnet extranjeria", "ce", "migraciones", "extranjero"], distance: 50 }),
    ("Latin America - Peru", "Peru Passport", ContextEntry { keywords: &["pasaporte", "peruvian passport", "peru passport", "passport number"], distance: 50 }),

    // Latin America - Venezuela
    ("Latin America - Venezuela", "Venezuela Cedula", ContextEntry { keywords: &["cedula", "cedula de identidad", "ci", "saime", "venezolano"], distance: 50 }),
    ("Latin America - Venezuela", "Venezuela RIF", ContextEntry { keywords: &["rif", "registro de informacion fiscal", "seniat", "fiscal", "contribuyente"], distance: 50 }),
    ("Latin America - Venezuela", "Venezuela Passport", ContextEntry { keywords: &["pasaporte", "venezuelan passport", "venezuela passport", "passport number"], distance: 50 }),

    // Latin America - Ecuador
    ("Latin America - Ecuador", "Ecuador Cedula", ContextEntry { keywords: &["cedula", "cedula de identidad", "cedula ciudadania", "registro civil", "identidad"], distance: 50 }),
    ("Latin America - Ecuador", "Ecuador RUC", ContextEntry { keywords: &["ruc", "registro unico de contribuyentes", "sri", "contribuyente", "tax id"], distance: 50 }),
    ("Latin America - Ecuador", "Ecuador Passport", ContextEntry { keywords: &["pasaporte", "ecuadorian passport", "ecuador passport", "passport number"], distance: 50 }),

    // Latin America - Uruguay
    ("Latin America - Uruguay", "Uruguay Cedula", ContextEntry { keywords: &["cedula", "cedula de identidad", "documento identidad", "identidad", "dnic"], distance: 50 }),
    ("Latin America - Uruguay", "Uruguay RUT", ContextEntry { keywords: &["rut", "registro unico tributario", "dgi", "contribuyente", "tax id"], distance: 50 }),
    ("Latin America - Uruguay", "Uruguay Passport", ContextEntry { keywords: &["pasaporte", "uruguayan passport", "uruguay passport", "passport number"], distance: 50 }),

    // Latin America - Paraguay
    ("Latin America - Paraguay", "Paraguay Cedula", ContextEntry { keywords: &["cedula", "cedula de identidad", "identidad civil", "documento identidad", "policia nacional"], distance: 50 }),
    ("Latin America - Paraguay", "Paraguay RUC", ContextEntry { keywords: &["ruc", "registro unico de contribuyentes", "set", "dnit", "contribuyente"], distance: 50 }),
    ("Latin America - Paraguay", "Paraguay Passport", ContextEntry { keywords: &["pasaporte", "paraguayan passport", "paraguay passport", "passport number"], distance: 50 }),

    // Latin America - Costa Rica
    ("Latin America - Costa Rica", "Costa Rica Cedula", ContextEntry { keywords: &["cedula", "cedula de identidad", "tse", "costarricense", "tribunal supremo"], distance: 50 }),
    ("Latin America - Costa Rica", "Costa Rica DIMEX", ContextEntry { keywords: &["dimex", "documento migratorio", "extranjero", "migracion", "residencia"], distance: 50 }),
    ("Latin America - Costa Rica", "Costa Rica Passport", ContextEntry { keywords: &["pasaporte", "costa rican passport", "costa rica passport", "passport number"], distance: 50 }),

    // Middle East - Saudi Arabia
    ("Middle East - Saudi Arabia", "Saudi Arabia National ID", ContextEntry { keywords: &["national id", "iqama", "saudi id", "huwiyya", "ministry of interior"], distance: 50 }),
    ("Middle East - Saudi Arabia", "Saudi Arabia Passport", ContextEntry { keywords: &["saudi passport", "saudi arabia passport", "jawaz safar", "passport number"], distance: 50 }),

    // Middle East - UAE
    ("Middle East - UAE", "UAE Emirates ID", ContextEntry { keywords: &["emirates id", "eid", "uae id", "identity card", "federal authority"], distance: 50 }),
    ("Middle East - UAE", "UAE Visa Number", ContextEntry { keywords: &["visa number", "entry permit", "uae visa", "residence visa", "visa file"], distance: 50 }),
    ("Middle East - UAE", "UAE Passport", ContextEntry { keywords: &["uae passport", "emirati passport", "passport number", "passport"], distance: 50 }),

    // Middle East - Israel
    ("Middle East - Israel", "Israel Teudat Zehut", ContextEntry { keywords: &["teudat zehut", "mispar zehut", "identity number", "israeli id", "zehut"], distance: 50 }),
    ("Middle East - Israel", "Israel Passport", ContextEntry { keywords: &["israeli passport", "israel passport", "darkon", "passport number"], distance: 50 }),

    // Middle East - Qatar
    ("Middle East - Qatar", "Qatar QID", ContextEntry { keywords: &["qid", "qatar id", "resident permit", "moi qatar", "identity card"], distance: 50 }),
    ("Middle East - Qatar", "Qatar Passport", ContextEntry { keywords: &["qatar passport", "qatari passport", "passport number", "jawaz"], distance: 50 }),

    // Middle East - Kuwait
    ("Middle East - Kuwait", "Kuwait Civil ID", ContextEntry { keywords: &["civil id", "paci", "kuwait id", "civil information", "identity card"], distance: 50 }),
    ("Middle East - Kuwait", "Kuwait Passport", ContextEntry { keywords: &["kuwaiti passport", "kuwait passport", "passport number", "passport"], distance: 50 }),

    // Middle East - Bahrain
    ("Middle East - Bahrain", "Bahrain CPR", ContextEntry { keywords: &["cpr", "central population registration", "bahrain id", "personal number", "identity card"], distance: 50 }),
    ("Middle East - Bahrain", "Bahrain Passport", ContextEntry { keywords: &["bahraini passport", "bahrain passport", "passport number", "passport"], distance: 50 }),

    // Middle East - Jordan
    ("Middle East - Jordan", "Jordan National ID", ContextEntry { keywords: &["national number", "raqam watani", "jordanian id", "civil status", "identity card"], distance: 50 }),
    ("Middle East - Jordan", "Jordan Passport", ContextEntry { keywords: &["jordanian passport", "jordan passport", "passport number", "passport"], distance: 50 }),

    // Middle East - Lebanon
    ("Middle East - Lebanon", "Lebanon ID", ContextEntry { keywords: &["lebanese id", "national id", "identity card", "hawiyya", "interior ministry"], distance: 50 }),
    ("Middle East - Lebanon", "Lebanon Passport", ContextEntry { keywords: &["lebanese passport", "lebanon passport", "passport number", "general security"], distance: 50 }),

    // Middle East - Iraq
    ("Middle East - Iraq", "Iraq National ID", ContextEntry { keywords: &["national card", "bitaqa wataniya", "iraqi id", "civil status", "identity card"], distance: 50 }),
    ("Middle East - Iraq", "Iraq Passport", ContextEntry { keywords: &["iraqi passport", "iraq passport", "passport number", "passport"], distance: 50 }),

    // Middle East - Iran
    ("Middle East - Iran", "Iran Melli Code", ContextEntry { keywords: &["melli code", "shomareh melli", "kart melli", "national code", "iranian id"], distance: 50 }),
    ("Middle East - Iran", "Iran Passport", ContextEntry { keywords: &["iranian passport", "iran passport", "passport number", "gozarnameh"], distance: 50 }),

    // Africa - South Africa
    ("Africa - South Africa", "South Africa ID", ContextEntry { keywords: &["south african id", "sa id", "identity number", "id number", "home affairs"], distance: 50 }),
    ("Africa - South Africa", "South Africa Passport", ContextEntry { keywords: &["south african passport", "sa passport", "passport number", "home affairs"], distance: 50 }),
    ("Africa - South Africa", "South Africa DL", ContextEntry { keywords: &["driver's licence", "driving licence", "south african dl", "licence number", "traffic department"], distance: 50 }),

    // Africa - Nigeria
    ("Africa - Nigeria", "Nigeria NIN", ContextEntry { keywords: &["nin", "national identification number", "nimc", "national identity", "identity number"], distance: 50 }),
    ("Africa - Nigeria", "Nigeria BVN", ContextEntry { keywords: &["bvn", "bank verification number", "bank verification", "nibss", "cbn"], distance: 50 }),
    ("Africa - Nigeria", "Nigeria TIN", ContextEntry { keywords: &["tin", "tax identification number", "firs", "tax id", "joint tax board"], distance: 50 }),
    ("Africa - Nigeria", "Nigeria Voter Card", ContextEntry { keywords: &["voter card", "pvc", "voter identification", "inec", "permanent voter"], distance: 50 }),
    ("Africa - Nigeria", "Nigeria Driver Licence", ContextEntry { keywords: &["driver's licence", "driving licence", "frsc", "licence number", "ndl"], distance: 50 }),
    ("Africa - Nigeria", "Nigeria Passport", ContextEntry { keywords: &["nigerian passport", "nigeria passport", "passport number", "immigration"], distance: 50 }),

    // Africa - Kenya
    ("Africa - Kenya", "Kenya National ID", ContextEntry { keywords: &["national id", "kenyan id", "identity card", "huduma namba", "maisha namba"], distance: 50 }),
    ("Africa - Kenya", "Kenya KRA PIN", ContextEntry { keywords: &["kra pin", "kra", "kenya revenue", "tax pin", "itax"], distance: 50 }),
    ("Africa - Kenya", "Kenya NHIF", ContextEntry { keywords: &["nhif", "national hospital insurance", "health insurance", "nhif number"], distance: 50 }),
    ("Africa - Kenya", "Kenya Passport", ContextEntry { keywords: &["kenyan passport", "kenya passport", "passport number", "immigration"], distance: 50 }),

    // Africa - Egypt
    ("Africa - Egypt", "Egypt National ID", ContextEntry { keywords: &["national id", "raqam qawmi", "egyptian id", "identity card", "civil registry"], distance: 50 }),
    ("Africa - Egypt", "Egypt Tax ID", ContextEntry { keywords: &["tax id", "tax registration", "maslahat al-darayeb", "tax number", "eta"], distance: 50 }),
    ("Africa - Egypt", "Egypt Passport", ContextEntry { keywords: &["egyptian passport", "egypt passport", "passport number", "jawaz safar"], distance: 50 }),

    // Africa - Ghana
    ("Africa - Ghana", "Ghana Card", ContextEntry { keywords: &["ghana card", "nia", "national identification", "identity card", "ghana id"], distance: 50 }),
    ("Africa - Ghana", "Ghana TIN", ContextEntry { keywords: &["tin", "tax identification", "gra", "taxpayer", "tax number"], distance: 50 }),
    ("Africa - Ghana", "Ghana NHIS", ContextEntry { keywords: &["nhis", "national health insurance", "health insurance", "nhia", "health card"], distance: 50 }),
    ("Africa - Ghana", "Ghana Passport", ContextEntry { keywords: &["ghanaian passport", "ghana passport", "passport number", "immigration"], distance: 50 }),

    // Africa - Ethiopia
    ("Africa - Ethiopia", "Ethiopia National ID", ContextEntry { keywords: &["fayda", "national id", "ethiopian id", "identity number", "fayda id"], distance: 50 }),
    ("Africa - Ethiopia", "Ethiopia TIN", ContextEntry { keywords: &["tin", "tax identification", "erca", "ministry of revenue", "tax number"], distance: 50 }),
    ("Africa - Ethiopia", "Ethiopia Passport", ContextEntry { keywords: &["ethiopian passport", "ethiopia passport", "passport number", "immigration"], distance: 50 }),

    // Africa - Tanzania
    ("Africa - Tanzania", "Tanzania NIDA", ContextEntry { keywords: &["nida", "national id", "tanzanian id", "nin", "national identification"], distance: 50 }),
    ("Africa - Tanzania", "Tanzania TIN", ContextEntry { keywords: &["tin", "tax identification", "tra", "tanzania revenue", "tax number"], distance: 50 }),
    ("Africa - Tanzania", "Tanzania Passport", ContextEntry { keywords: &["tanzanian passport", "tanzania passport", "passport number", "immigration"], distance: 50 }),

    // Africa - Morocco
    ("Africa - Morocco", "Morocco CIN", ContextEntry { keywords: &["cin", "cnie", "carte nationale", "carte identite", "identite nationale"], distance: 50 }),
    ("Africa - Morocco", "Morocco Tax ID", ContextEntry { keywords: &["identifiant fiscal", "if", "dgi", "tax id", "impots"], distance: 50 }),
    ("Africa - Morocco", "Morocco Passport", ContextEntry { keywords: &["moroccan passport", "morocco passport", "passeport", "passport number"], distance: 50 }),

    // Africa - Tunisia
    ("Africa - Tunisia", "Tunisia CIN", ContextEntry { keywords: &["cin", "carte identite nationale", "carte identite", "tunisian id", "identity card"], distance: 50 }),
    ("Africa - Tunisia", "Tunisia Passport", ContextEntry { keywords: &["tunisian passport", "tunisia passport", "passeport", "passport number"], distance: 50 }),

    // Africa - Uganda
    ("Africa - Uganda", "Uganda NIN", ContextEntry { keywords: &["nin", "national identification number", "nira", "national id", "ugandan id"], distance: 50 }),
    ("Africa - Uganda", "Uganda Passport", ContextEntry { keywords: &["ugandan passport", "uganda passport", "passport number", "immigration"], distance: 50 }),
];

