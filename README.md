<div align="center">

<img src="https://img.shields.io/badge/HackMatrix%202026-🏆%20Hackathon%20Submission-blueviolet?style=for-the-badge&logo=shield&logoColor=white" alt="HackMatrix Badge"/>

# 🛡️ AegisTrust AI
### Intelligent Phishing Detection & Malicious Website Threat Intelligence Platform

*Built for **HackMatrix** — the premier national cybersecurity hackathon*

<br/>

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-v4-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![STIX 2.1](https://img.shields.io/badge/OASIS-STIX%202.1-orange?style=flat-square)](https://oasis-open.github.io/cti-documentation/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![HackMatrix](https://img.shields.io/badge/Event-HackMatrix-purple?style=flat-square)]()

<br/>

> **AegisTrust AI** is a full-stack, production-grade cybersecurity platform that unifies intelligent phishing detection, real-time X.509 TLS certificate trust chain validation, Certificate Authority (CA) cryptographic anomaly detection (including dedicated mitigation for the **eMudhra TLS certificate incident**), HTTP application security posture assessment, and collaborative community-driven threat intelligence — all accessible through a modern, real-time React dashboard and a standards-compliant OASIS STIX 2.1 REST API.

<br/>

![AegisTrust Platform Demo](https://img.shields.io/badge/🚀%20Live%20Platform-localhost%3A8000-cyan?style=for-the-badge)

</div>

---

## 🏆 HackMatrix Hackathon Context

This project was designed and built as a submission to **HackMatrix**, addressing the challenge of making internet users, organizations, and security operations centers safer from increasingly sophisticated digital threats.

### Problem Statement

The internet underpins critical global infrastructure — online banking, academic recruitment, healthcare, government services, e-commerce, and business communication. However, this reliance has created an unprecedented attack surface:

| Threat Vector | Real-World Impact |
|---|---|
| 🎣 **Phishing & Credential Theft** | Lookalike portals for Chase, HDFC, PayPal, universities, and government tax portals steal millions in financial data and identity credentials |
| 🔐 **The HTTPS Padlock Fallacy** | 83% of phishing sites now have valid TLS certificates — users wrongly trust the green padlock as a safety signal |
| 🏛️ **CA Trust Infrastructure Attacks** | The **eMudhra TLS Incident** demonstrated that Certificate Authority weaknesses can allow adversaries to mint legitimate-looking certificates for impersonation and MitM attacks |
| 📧 **Email Spoofing & Lures** | Domains without strict DMARC (`p=reject`) enforcement can be forged to send convincing spear-phishing emails |
| 🌐 **Existing Tool Fragmentation** | Current security tools address these threats in isolation — no unified, accessible platform exists |

**AegisTrust AI** solves all of these in a single, integrated platform.

---

## ✨ Core Features

<table>
<tr>
<td width="50%" valign="top">

### 🔬 1. Multi-Vector Threat Analysis Engine
- **Typosquatting & Combosquatting Detection** using Levenshtein distance across **40+ protected brands** (Banks, Universities, Government agencies, Web3)
- **IDN Homoglyph Detection** — unmasks Cyrillic/Greek character spoofing (е, а, о → e, a, o)
- **IP-as-Hostname & High-Abuse TLD Flagging** (`.xyz`, `.top`, `.club`, `.work`, `.icu`, `.tk`)
- **Credential Harvesting Form Detection** — passwords, CVV codes, debit card numbers, Aadhaar/SSN fields
- **Discord Webhook Exfiltration Detection** — identifies phishing kits using `discord.com/api/webhooks/` to steal credentials
- **Psychological Urgency Pattern Matching** — "Account suspended within 24 hours", "Claim tax refund now"

</td>
<td width="50%" valign="top">

### 🔑 2. Certificate & eMudhra CA Trust Validation Engine
- **Live TLS Socket Handshake** — extracts X.509 leaf certificate directly via Python `ssl` + `cryptography`
- **eMudhra Incident Detection** — flags certificates from distrusted/probationary CAs
- **Shannon Entropy Analysis** — tests RSA public key moduli for defective RNG patterns (ROCA, Debian weak keys)
- **Certificate Transparency (SCT) Verification** — validates embedded Signed Certificate Timestamps
- **Brand vs. Automated DV Mismatch** — detects when a bank claims EV-tier but uses a 90-day free DV cert
- **Full X.509 Chain Hierarchy Visualization**

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🌐 3. Web Security Posture Assessment
- **HTTP Security Headers Checklist** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Security Grade** (A+ → F) with actionable gap analysis
- **DMARC / SPF Email Anti-Spoofing Audit**
- **Server Banner Information Disclosure Detection**
- **Live HTTP header fetching** via `httpx` with redirect tracking

</td>
<td width="50%" valign="top">

### 🤝 4. Collaborative Threat Intelligence Exchange
- **Community Threat Reporting** — submit malicious URLs with evidence, sector classification, and attack vector tags
- **Peer Consensus Voting** — 👍 Confirm Malicious / 👎 Report False Positive
- **Analyst Verification Endorsement** — expert-tier confidence signals
- **OASIS STIX 2.1 Export** — standardized `Indicator`, `AttackPattern`, `Identity`, and `Relationship` SDOs for SIEM/SOAR ingestion
- **Sector-Filtered Threat Feed** — Banking, Academia, Government, Web3, Recruitment

</td>
</tr>
</table>

---

## 🧪 Built-In Attack Scenario Simulator

The platform ships with **6 pre-configured, realistic threat vectors** for immediate demonstration — no live malicious sites required:

| # | Scenario | Category | Key Indicators |
|---|---|---|---|
| 1 | **eMudhra CA Weak Key Impersonation** | 🏛️ CA Vulnerability / MitM | Defective RSA entropy, CT log omission, distrusted CA chain |
| 2 | **Chase Bank Credential Harvester** | 🏦 Financial Phishing | Combosquatting `.xyz`, password + SSN + CVV form, Discord webhook exfil |
| 3 | **Oxford University Fake Careers Portal** | 🎓 Academic Recruitment Scam | Plaintext HTTP, passport scan + payment card harvesting |
| 4 | **IRS Tax Refund Impersonation Portal** | 🏛️ Government Identity Theft | Non-`.gov` domain, free DV cert on US federal entity, SSN + bank account harvest |
| 5 | **MetaMask Web3 Wallet Drainer** | ₿ Crypto / Digital Assets | Brand impersonation on `.top`, seed phrase harvesting, malicious approval scripts |
| 6 | **Google LLC — Clean Enterprise Baseline** | ✅ Legitimate Reference | GTS root, ECDSA P-256, HSTS preload, strict CSP — **Threat Score: 0** |

---

## 🏗️ System Architecture

```
                           [ URL / Domain Input ]
                                    │
           ┌────────────────────────┼───────────────────────┐
           ▼                        ▼                        ▼
  ┌─────────────────┐    ┌────────────────────┐   ┌────────────────────┐
  │  Threat & Brand │    │  Certificate &     │   │   Web Security     │
  │  Engine         │    │  Trust Engine      │   │   Posture Engine   │
  │─────────────────│    │────────────────────│   │────────────────────│
  │ Typosquat       │    │ Live TLS Socket    │   │ HSTS / CSP Audit   │
  │ Homoglyphs      │    │ eMudhra CA Detect  │   │ X-Frame-Options    │
  │ Credential Forms│    │ Shannon Entropy    │   │ MIME Sniffing      │
  │ Discord Webhooks│    │ CT / SCT Verify    │   │ DMARC / SPF Audit  │
  │ Urgency Lures   │    │ DV Mismatch Alert  │   │ Security Grading   │
  └────────┬────────┘    └─────────┬──────────┘   └────────┬───────────┘
           │                       │                        │
           └───────────────────────┼────────────────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │  Threat Intelligence Correlator│
                   │  (SQLite IOC Registry)         │
                   │  Community Voting & STIX 2.1   │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │   Unified Risk Verdict Engine  │
                   │   Composite 0 → 100 Gauge      │
                   │                                │
                   │  🟢 CLEAN (0–19)               │
                   │  🟡 LOW RISK (20–39)           │
                   │  🟠 SUSPICIOUS (40–69)         │
                   │  🔴 CRITICAL MALICIOUS (70–100)│
                   └───────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/SAPTARSHI-coder/AegisTrust-AI.git
cd AegisTrust-AI
```

### 2. Backend Setup
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # macOS / Linux
# venv\Scripts\activate           # Windows

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Frontend Build
```bash
cd frontend
npm install
npm run build
cd ..
```

### 4. Launch the Platform
```bash
# Option A: One-command runner (macOS/Linux)
./run.sh

# Option B: Manual start
export PYTHONPATH="$(pwd)"
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Open the Dashboard
| Interface | URL |
|---|---|
| **Web Platform Dashboard** | http://127.0.0.1:8000 |
| **Interactive API Docs (Swagger)** | http://127.0.0.1:8000/docs |
| **STIX 2.1 Threat Export** | http://127.0.0.1:8000/api/threats/export/stix |
| **Community Threat Feed** | http://127.0.0.1:8000/api/threats |

---

## 📡 REST API Reference

### Scan a URL (Multi-Engine Analysis)
```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://chase-security-verify.xyz", "live_scan": true}'
```

**Response snippet:**
```json
{
  "verdict": {
    "category": "CRITICAL_MALICIOUS",
    "label": "Malicious / Phishing Threat Detected",
    "threat_score": 92,
    "critical_indicators": 4
  },
  "engines": {
    "certificate_and_trust": {
      "emudhra_incident_analysis": {
        "is_emudhra_ca": true,
        "weak_key_anomaly": true
      }
    }
  },
  "recommendations": {
    "for_end_users": ["DO NOT enter passwords or card numbers on this page."],
    "for_soc_analysts": ["Deploy DNS sinkhole and ingest cert fingerprint into EDR."]
  }
}
```

### Run a Pre-Built Threat Scenario
```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"scenario_id": "emudhra-ca-incident"}'
```

### Available Scenario IDs
| ID | Description |
|---|---|
| `emudhra-ca-incident` | eMudhra CA weak key & CT log omission |
| `chase-credential-harvester` | Chase bank combosquat + Discord webhook exfil |
| `oxford-recruitment-scam` | Oxford fake careers portal (HTTP, passport harvest) |
| `irs-tax-refund-portal` | IRS federal tax lure (non-.gov domain, SSN harvest) |
| `crypto-web3-drainer` | MetaMask airdrop drainer + seed phrase harvest |
| `legitimate-google-baseline` | Google.com verified clean reference (score: 0) |

### Submit Community Threat Report
```bash
curl -X POST "http://localhost:8000/api/threats/report" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://sbi-kyc-verify-card.top",
    "target_brand": "State Bank of India",
    "target_sector": "Banking & Finance",
    "threat_type": "Phishing & Credential Theft",
    "evidence_notes": "SMS lure threatening SIM block, posts to Discord webhook",
    "submitted_by": "SOC_Analyst_Rajan"
  }'
```

### Export STIX 2.1 Bundle (for SIEM/SOAR)
```bash
curl "http://localhost:8000/api/threats/export/stix" \
  -o aegistrust_stix21_bundle.json
```

---

## 🔬 The eMudhra TLS Certificate Incident — Technical Deep Dive

The eMudhra TLS incident is one of this platform's central research subjects, addressed by a dedicated analysis engine:

### What Happened?
In 2024–2025, security auditors and browser trust programs (Mozilla, Chromium) documented systemic failures in eMudhra's Certificate Authority operations:

```
1. Defective RNG in HSMs → Low-entropy RSA key pairs
   └→ Adversaries could mathematically factor predictable moduli
   
2. Certificate Transparency (CT) omissions
   └→ Certificates issued without submitting precertificates to public append-only logs
   └→ Rogue or test certificates escaped global monitoring
   
3. Browser enforcement response
   └→ Probationary distrust, shortened certificate lifespans, restricted sub-CAs
```

### How AegisTrust Detects This
```python
# Shannon Entropy on RSA Public Modulus (certificate_engine.py)
byte_counts = {}
for ch in modulus_hex:
    byte_counts[ch] = byte_counts.get(ch, 0) + 1

entropy = -sum(
    (cnt / len(modulus_hex)) * math.log2(cnt / len(modulus_hex))
    for cnt in byte_counts.values()
)

if entropy < 3.2:   # Healthy hex distribution ≈ 3.9–4.0 bits/byte
    # Flag: ROCA / defective RNG pattern detected
```

The platform checks every live certificate's RSA modulus Shannon entropy, SCT extension presence, CA issuer against the distrust watchlist, and validates that the CA tier matches the brand's expected assurance level.

---

## 📂 Project Structure

```
AegisTrust-AI/
│
├── 📄 README.md                        — Full documentation (you're reading it!)
├── 📄 requirements.txt                 — Python dependencies
├── 📄 run.sh                           — One-command launch script
│
├── 🐍 backend/
│   ├── main.py                         — FastAPI app: routes, CORS, static serving
│   │
│   ├── scanner/
│   │   ├── analyzer.py                 — Unified coordinator & weighted risk synthesis
│   │   ├── threat_engine.py            — Typosquat, homoglyphs, credential harvesting
│   │   ├── certificate_engine.py       — Live TLS, eMudhra CA, Shannon entropy
│   │   ├── security_engine.py          — HTTP headers, DMARC, security grading
│   │   └── scenarios.py                — Pre-built simulation attack vectors
│   │
│   └── threat_intel/
│       ├── database.py                 — SQLite threat registry, voting, IOC query
│       └── stix_exporter.py            — OASIS STIX 2.1 bundle generator
│
└── ⚛️  frontend/
    ├── index.html
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── App.jsx                     — Root app, tab state, interstitial modal
        ├── index.css                   — Tailwind v4 + custom glow utilities
        └── components/
            ├── Header.jsx              — Live telemetry ticker, navigation
            ├── ScannerView.jsx         — URL bar, verdict card, 4-tab analysis
            ├── ThreatIntelView.jsx     — Community feed, submission modal, STIX export
            ├── CertificateLabView.jsx  — eMudhra dossier, padlock fallacy, entropy tool
            ├── BrowserWarningModal.jsx — Browser-style interstitial intercept screen
            └── ApiSandboxView.jsx      — REST API docs, code snippets, live sandbox
```

---

## 🌍 Platform UI Walkthrough

### 🛡️ Threat Scanner Tab
- Paste any URL or domain into the search bar
- Select a preset simulation scenario for instant demonstration
- Toggle **Live TLS Socket & Network Inspection** for real-time analysis
- Results organized across 4 sub-tabs: Brand Threat → Certificate & CA → Web Security → Actionable Remediation
- Trigger a **browser interstitial warning screen** for critical verdicts

### 🗄️ Threat Intelligence Tab  
- Browse crowdsourced phishing reports filtered by industry sector
- Vote to confirm threats or flag false positives
- Submit new malicious sites with evidence notes
- Export entire feed as **OASIS STIX 2.1** or JSON

### 🔑 eMudhra & CA Lab Tab
- **The eMudhra Incident Breakdown** — full technical dossier with attack chain
- **The HTTPS Padlock Fallacy** — why encryption ≠ legitimacy
- **Interactive Shannon Entropy Tester** — paste any RSA hex modulus and score its randomness
- **Global CA Trust Store Matrix** — eMudhra, WoSign, DigiCert, Google Trust Services status

### 🌐 Browser Warning Tab
- Simulates the actual browser interstitial screen a user would see when blocked
- Expandable forensic details showing exact triggered rules

### ⚙️ API & STIX Tab
- Full REST endpoint documentation with curl / Python / JavaScript snippets
- One-click live endpoint sandbox execution

---

## 🔐 Supported Brand Protection Registry (40+ Entities)

| Sector | Protected Entities |
|---|---|
| **Banking & Finance** | Chase, Wells Fargo, Bank of America, Citibank, PayPal, Stripe, SBI, HDFC, Barclays, HSBC, Revolut, Venmo |
| **Education & Academia** | Oxford, Harvard, Cambridge, MIT, Stanford, Coursera, Blackboard |
| **Government & Services** | IRS, Income Tax India, UIDAI/Aadhaar, GOV.UK, USPS, DHL |
| **Recruitment** | LinkedIn, Indeed, Workday, Greenhouse |
| **Technology & Cloud** | Google, Microsoft, Apple, Dropbox, Netflix, Amazon |
| **Cryptocurrency & Web3** | Binance, Coinbase, MetaMask, Phantom, OpenSea |

---

## 📊 Platform Metrics at Submission

| Metric | Value |
|---|---|
| Community Threat Reports | 7 (pre-seeded) |
| Analyst Verified IOCs | 6 |
| CA Watchlist Entries | 4 (eMudhra, WoSign, Symantec Legacy, Camerfirma) |
| Protected Brands | 40+ |
| Attack Scenario Vectors | 6 |
| STIX 2.1 SDO Types | Indicator, AttackPattern, Identity, Relationship |
| API Endpoints | 10+ |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend Framework** | FastAPI 0.162 (async, Pydantic v2) |
| **TLS Analysis** | Python `ssl`, `socket`, `cryptography` 50.0 |
| **HTTP Fetching** | HTTPX (async, redirect-aware) |
| **Database** | SQLite (via Python `sqlite3`) |
| **Frontend Framework** | React 19 + Vite 6 |
| **UI Styling** | Tailwind CSS v4 + custom cyber utilities |
| **Icons** | Lucide React |
| **Standards** | OASIS STIX 2.1, RFC 5280, RFC 9162, CA/B Forum BR |

---

## 📜 Standards & Compliance

- **[OASIS STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro)** — Structured Threat Information Expression for SIEM/SOAR integration
- **[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)** — Internet X.509 Public Key Infrastructure Certificate Profile
- **[RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162)** — Certificate Transparency Version 2.0
- **[CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements/)** — 398-day validity limit and domain validation mandates
- **[MITRE ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/)** — Spearphishing Link (ATT&CK technique mapped in STIX exports)

---

## 🔮 Future Roadmap

- [ ] Browser extension for real-time page interception
- [ ] VirusTotal / OpenPhish / URLhaus API integration
- [ ] ML-based visual similarity detection (favicon and screenshot comparison)
- [ ] Multi-perspective DNS validation (RFC 8555 MPV)
- [ ] Automated certificate revocation list (CRL/OCSP) cross-referencing
- [ ] Webhooks for SIEM push notifications
- [ ] Docker Compose deployment for production hosting

---

## 👨‍💻 Author

**Saptarshi Sadhu**  
GitHub: [@SAPTARSHI-coder](https://github.com/SAPTARSHI-coder)  
Email: saptarshisadhuofficial@gmail.com

Built with ❤️ for **HackMatrix** — Pushing the boundaries of accessible cybersecurity tooling.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**⭐ Star this repository if AegisTrust AI helped you understand internet security threats!**

*Made for HackMatrix | AegisTrust AI © 2026 | Protecting the Web's Trust Infrastructure*

</div>
