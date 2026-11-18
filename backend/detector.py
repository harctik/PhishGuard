"""
PhishGuard Core Detection Engine
Provides multi-signal adversarial analysis:
- Shannon entropy analysis (detects algorithmic domain generation)
- Unicode Homoglyph & Punycode spoofing detection (mixed-script detection)
- Lexical URL feature extraction (suspicious keywords, subdomain depth, IP-in-hostname)
- Risk scoring and threat classification
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

# Suspicious high-value financial & auth brand targets
TARGET_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "binance", "coinbase"
]

# Sensitive auth-related keywords commonly abused in phishing paths
AUTH_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "banking",
    "account", "password", "credential", "auth", "wallet", "recover"
]

# High-risk TLDs frequently abused in automated phishing kits
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".buzz", ".club", ".work", ".cfd", ".sbs", ".cam"
}


def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy of a string to detect algorithmic domain generation (DGA)."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_homoglyphs(domain: str) -> Dict[str, Any]:
    """Detects Punycode and internationalized mixed-script lookalike characters."""
    is_punycode = domain.startswith("xn--") or ".xn--" in domain
    non_ascii_chars = [char for char in domain if ord(char) > 127]
    has_mixed_script = len(non_ascii_chars) > 0

    return {
        "is_punycode": is_punycode,
        "has_mixed_script": has_mixed_script,
        "non_ascii_count": len(non_ascii_chars),
        "spoofed": is_punycode or has_mixed_script
    }


def extract_lexical_features(url: str) -> Dict[str, Any]:
    """Extracts structural and lexical indicators from a URL."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path.lower()
    query = parsed.query.lower()

    # IP address as host check
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

    # Subdomain depth
    subdomains = hostname.split(".")
    subdomain_count = max(0, len(subdomains) - 2)

    # Keywords abused
    keywords_found = [kw for kw in AUTH_KEYWORDS if kw in path or kw in query]

    # Brand target spoofing in subdomains/path
    brand_mentions = [brand for brand in TARGET_BRANDS if brand in hostname and not hostname.endswith(f"{brand}.com")]

    # High-risk TLD
    has_risky_tld = any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS)

    return {
        "hostname": hostname,
        "url_length": len(url),
        "is_ip_host": is_ip,
        "subdomain_count": subdomain_count,
        "keywords_found": keywords_found,
        "brand_mentions": brand_mentions,
        "has_risky_tld": has_risky_tld,
        "uses_https": parsed.scheme == "https",
        "has_at_symbol": "@" in url
    }


def evaluate_url(url: str) -> Dict[str, Any]:
    """Evaluates URL safety score (0-100) and returns classification and threat reasons."""
    features = extract_lexical_features(url)
    hostname = features["hostname"]
    entropy = calculate_entropy(hostname)
    homoglyphs = detect_homoglyphs(hostname)

    score = 0
    reasons: List[str] = []

    if homoglyphs["spoofed"]:
        score += 45
        reasons.append("Punycode or non-ASCII homoglyph character spoofing detected")

    if features["is_ip_host"]:
        score += 35
        reasons.append("Raw IP address used instead of legitimate registered domain")

    if features["brand_mentions"]:
        score += 40
        reasons.append(f"Targeted brand spoofing detected: {', '.join(features['brand_mentions'])}")

    if features["has_at_symbol"]:
        score += 30
        reasons.append("Embedded '@' credential character in URL")

    if features["has_risky_tld"]:
        score += 20
        reasons.append("Domain registered under high-risk phishing TLD")

    if features["subdomain_count"] >= 3:
        score += 15
        reasons.append(f"Excessive subdomain depth ({features['subdomain_count']} levels)")

    if len(features["keywords_found"]) >= 2:
        score += 20
        reasons.append(f"Multiple credential-harvesting keywords found: {', '.join(features['keywords_found'])}")

    if entropy > 4.2:
        score += 20
        reasons.append(f"High domain entropy ({entropy}) indicates algorithmic domain generation (DGA)")

    if not features["uses_https"]:
        score += 10
        reasons.append("Unencrypted HTTP transmission")

    # Clamp score to [0, 100]
    score = min(100, score)

    if score >= 60:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "url": url,
        "hostname": hostname,
        "risk_score": score,
        "verdict": verdict,
        "entropy": entropy,
        "reasons": reasons,
        "features": features,
        "homoglyph_analysis": homoglyphs
    }

