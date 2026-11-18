# PhishGuard: Real-Time Adversarial Phishing Intelligence

An end-to-end browser defense architecture coupling a client-side Manifest V3 Chrome extension with an asynchronous FastAPI threat inspection backend to intercept zero-day credential harvesting and homoglyph domain attacks.

![PhishGuard Banner](banner.png)

---

## Technical Overview

Modern phishing infrastructure relies on rapid domain cycling, mixed-script homoglyph substitution, and short-lived hosts that easily bypass traditional static blacklists. Because DNS and reputation databases suffer from a multi-hour lag window, PhishGuard evaluates threats deterministically at request time directly within the client browser.

The platform operates across two synchronized tiers:
1. Client Tier (Manifest V3 Extension): Intercepts navigation events, monitors DOM hyperlink structures, and communicates asynchronously with the local inspection daemon without stalling render threads.
2. Analysis Tier (FastAPI Backend): Processes candidate URLs against multi-factor heuristic evaluators, computing lexical risk factors, character entropy, and homoglyph code-points in sub-10ms latency.

---

## Extension Interface & Detection Telemetry

The client-side extension provides immediate visual feedback regarding active browsing context. Threat metrics update automatically on tab activation or DOM navigation.

### Zero-Day Threat Interception
When navigating to high-entropy domains or homoglyph landing pages, the extension surfaces an alert banner, displays the composite threat score, and logs the specific heuristic triggers.

![Threat Alert Interface](docs/screenshots/popup_threat_alert.png)

### Verified Domain Inspection
On legitimate web applications, the background worker completes verification silently, establishing low risk scores while monitoring anchor tags for lateral malicious redirects.

![Secure Inspection Interface](docs/screenshots/popup_secure.png)

---

## System Architecture

```text
[ Web Browser ]
      |
      +---> content.js (DOM Anchor Analysis & Warning Overlay)
      |
      +---> background.js (Asynchronous Service Worker Gateway)
      |         |
      |         | (HTTP POST /scan, non-blocking)
      |         v
[ FastAPI Threat Inspection Daemon ]
      |
      +---> Shannon Entropy Engine (Calculates character distribution randomness)
      +---> Punycode & Mixed-Script Detector (Flags non-ASCII unicode code-points)
      +---> Lexical Anomaly Analyzer (Extracts IP hosts, keyword density, path depth)
      +---> Target Brand Heuristic (Flags unauthorized auth/banking impersonation)
      |
      +---> Multi-Factor Risk Synthesizer
                |
                v
         [ Verdict: SAFE | SUSPICIOUS | MALICIOUS ]
```

---

## Detection Methodology & Heuristic Formulation

### 1. Unicode Homoglyph & Punycode Identification
Attackers frequently exploit visually indistinguishable characters from foreign scripts (such as substituting Latin 'a' with Cyrillic 'а' / U+0430). The homoglyph engine extracts the normalized domain name, identifies the presence of internationalized domain name (IDN) prefixes (`xn--`), and parses raw character byte values:

$$\text{is\_spoofed}(D) = (D \text{ contains } \text{"xn--"}) \lor \exists c \in D : \text{ord}(c) > 127$$

### 2. Shannon Entropy for DGA Detection
Algorithmic Domain Generation (DGA) generates high-entropy hostnames designed to evade domain reputation filters. PhishGuard evaluates character-level entropy:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Hostnames exceeding an entropy threshold ($H > 4.2$) are flagged for algorithmic randomness.

### 3. Lexical and Structural Indicators
The lexical parser assesses ten structural risk dimensions:

| Risk Indicator | Evaluated Pattern | Score Weight |
|---|---|---|
| Raw IP Host | Numeric IPv4 / IPv6 addresses utilized as hostnames | +35 points |
| Subdomain Chaining | Domain depth greater than three dot-delimited tiers | +20 points |
| Credential Clustering | High-frequency keywords (`login`, `signin`, `verify`, `banking`, `wallet`) | +25 points |
| Mixed Script Spoofing | Coexistence of Latin and non-Latin character sets | +40 points |
| Punycode Encoding | Presence of `xn--` prefix with target brand substring | +50 points |

---

## API Specification

The FastAPI inspection engine exposes high-throughput endpoints designed for local daemon or containerized cluster deployment.

### Endpoint: POST /scan

Request Payload:
```json
{
  "url": "http://xn--pypal-4ve.com/login/verify.php"
}
```

Response Payload:
```json
{
  "url": "http://xn--pypal-4ve.com/login/verify.php",
  "domain": "xn--pypal-4ve.com",
  "risk_score": 96,
  "verdict": "MALICIOUS",
  "reasons": [
    "Punycode homoglyph detected (Cyrillic substitution)",
    "Shannon entropy: 4.82 (High DGA randomness)",
    "Credential keyword clustering: [login, verify]"
  ],
  "latency_ms": 3.8
}
```

---

## Repository Structure

```text
PhishGuard/
├── backend/
│   ├── main.py              # FastAPI server and routing definitions
│   └── detector.py          # Entropy calculations, Punycode parser, and heuristics
├── extension/
│   ├── manifest.json        # Chrome Extension Manifest V3 configuration
│   ├── background.js        # Service worker for non-blocking HTTP dispatch
│   ├── content.js           # DOM anchor scanning and page banner injection
│   └── popup/
│       ├── popup.html       # Clean inspector popup UI
│       ├── popup.css        # High-contrast dark theme styles
│       └── popup.js         # Client-side state binding and telemetry rendering
├── docs/screenshots/        # Extension interface captures and threat alerts
├── tests/
│   └── test_phishguard.py   # Unit test suite verifying entropy and heuristics
├── pyproject.toml           # Python packaging configuration
└── requirements.txt         # Runtime dependencies
```

---

## Local Installation & Quick Start

### 1. Backend Service Setup
```bash
git clone https://github.com/harctik/PhishGuard.git
cd PhishGuard
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

### 2. Browser Extension Installation
1. Open Google Chrome and enter `chrome://extensions/` in the address bar.
2. Enable Developer mode via the toggle switch in the upper right corner.
3. Click Load unpacked and select the `PhishGuard/extension` directory.
4. The PhishGuard shield badge will initialize in the browser extension toolbar.

### 3. Running Unit Tests
```bash
pytest tests/ -v
```

---

## Author and Engineering Attribution

All architecture, heuristic formulations, backend API development, and Chrome Extension Manifest V3 implementation in this repository were engineered end-to-end by Avvari Naga Harthikanand (Harthik).

Developer: Avvari Naga Harthikanand
Location: Bangalore, Karnataka, India
LinkedIn: https://www.linkedin.com/in/harthik
GitHub: https://github.com/harctik
Email: harthikanand90@gmail.com
License: MIT License
