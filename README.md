<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Chrome Extension](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Sec--Ops%20%7C%20Threat%20Intel-black?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

# 🛡️ PhishGuard: Real-Time Adversarial Phishing Intelligence

**A dual-layer cybersecurity defense system pairing a Manifest V3 browser shield with a FastAPI heuristic inspection backend to detect zero-day credential harvesting and homoglyph domain spoofing in real time.**

[Architecture](#-system-architecture) • [Core Detection Engines](#-detection-signals) • [Quick Start](#-quick-start) • [API Reference](#-api-reference) • [Testing](#-testing)

</div>

---

## 🛑 The Threat Landscape

Traditional reputation-based blacklists (Google Safe Browsing, PhishTank) suffer from an inherent **detection lag window of 2 to 24 hours**. Adversarial threat actors bypass static domain reputation by:
1. **Punycode / Homoglyph Spoofing:** Registering lookalike domains using non-ASCII or Cyrillic characters (e.g. `pаypal.com` with Cyrillic `а` / `U+0430`).
2. **Algorithmic Domain Generation (DGA):** Spinning up short-lived high-entropy subdomains.
3. **Targeted Subdomain Camouflage:** Abusing high-reputation hosting platforms with deeply nested credential paths.

PhishGuard solves this by evaluating URLs **in-situ and sub-10ms** before credentials can be transmitted.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph Browser Layer (Manifest V3)
        TAB[Active Browser Tab] --> CS[content.js: In-Page Link Scanner]
        CS --> |URL Telemetry| BG[background.js: Service Worker]
        BG --> |Threat Score Trigger| POPUP[popup.html: Threat Inspector]
        BG --> |Critical Alert| BANNER[DOM Alert Banner]
    end

    subgraph Defense Engine (FastAPI)
        BG --> |POST /scan| API[FastAPI Gateway]
        API --> ENTROPY[Shannon Entropy Evaluator]
        API --> HOMO[Punycode & Homoglyph Detector]
        API --> LEX[Lexical & Keyword Feature Extractor]
        API --> TLD[High-Risk TLD & Brand Spoof Rulebase]
        ENTROPY & HOMO & LEX & TLD --> SCORE[Multi-Signal Risk Scorer: 0-100]
    end

    SCORE --> |Risk Payload: SAFE / SUSPICIOUS / MALICIOUS| BG
```

---

## 🔬 Detection Signals

| Signal Module | Adversarial Vector Analyzed | Defense Technique |
|---|---|---|
| **Homoglyph & Punycode** | Mixed-script character replacement (Cyrillic, Greek, Latin) | Checks for `xn--` prefix and character Unicode code-points `ord(char) > 127` |
| **Shannon Entropy** | Algorithmic Domain Generation (DGA) | Computes $H(X) = -\sum p(x) \log_2 p(x)$ over hostname characters; alerts when $H > 4.2$ |
| **Lexical Anomalies** | IP-in-hostname, credential keywords, excessive depth | Regular expression pattern matching over URL components and subdomains |
| **Brand Camouflage** | Target brand spoofing in subdomains or URL path | Matches high-value brands (`paypal`, `chase`, `coinbase`, `apple`) against unauthorized parent domains |
| **Transport Security** | Cleartext credential transmission | Verifies SSL/TLS scheme integrity |

---

## ⚡ Quick Start

### 1. Launch the Backend Inspection Engine

```bash
git clone https://github.com/harctik/PhishGuard.git
cd PhishGuard
python -m venv venv

# Activate Virtual Environment:
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

### 2. Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right corner.
3. Click **Load unpacked** and select the `PhishGuard/extension` directory.
4. Pin the PhishGuard icon to your browser bar.

---

## 📡 API Reference

### `POST /scan`
Evaluates a single URL and returns an aggregated threat verdict.

**Request:**
```json
{
  "url": "http://192.168.1.50/paypal-update/secure/verify"
}
```

**Response:**
```json
{
  "url": "http://192.168.1.50/paypal-update/secure/verify",
  "hostname": "192.168.1.50",
  "risk_score": 95,
  "verdict": "MALICIOUS",
  "entropy": 2.8554,
  "reasons": [
    "Raw IP address used instead of legitimate registered domain",
    "Targeted brand spoofing detected: paypal",
    "Multiple credential-harvesting keywords found: update, secure, verify",
    "Unencrypted HTTP transmission"
  ]
}
```

---

## 🧪 Testing

The repository includes automated unit tests verifying homoglyph detection, entropy mathematics, and lexical analysis:

```bash
pytest tests/ -v
```

Automated builds and tests run on every push via GitHub Actions.

---

## 📄 License

This project is licensed under the MIT License.
