"""
Vanguard Core Detection Engine
Provides multi-signal adversarial analysis:
- Shannon entropy analysis (detects algorithmic domain generation)
- Unicode Homoglyph & Punycode spoofing detection (mixed-script detection)
- Lexical URL feature extraction (suspicious keywords, subdomain depth, IP-in-hostname)
- Risk scoring and threat classification
"""

import math
import re
import unicodedata
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

# Longest address the API will score
MAX_URL_LENGTH = 8192

# Common two-part public suffixes. This is not the full Public Suffix List.
# A brand name directly in front of a "co." or "com." ending here counts as the brand's own domain.
BRAND_TWO_PART_SUFFIXES = {
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za", "co.id", "co.il", "co.th", "co.cr",
    "co.ke", "com.au", "com.br", "com.cn", "com.hk", "com.sg", "com.mx", "com.ar", "com.tr",
    "com.tw", "com.my", "com.ph", "com.pk", "com.sa", "com.eg", "com.co", "com.pe", "com.vn",
    "com.ng", "com.ua", "com.bd"
}
TWO_PART_SUFFIXES = BRAND_TWO_PART_SUFFIXES | {
    "org.uk", "me.uk", "ac.uk", "gov.uk", "net.au", "org.au", "edu.au", "gov.au", "net.in",
    "org.in", "ac.in", "gov.in", "or.jp", "ne.jp", "ac.jp", "or.kr", "org.nz", "org.za",
    "net.br", "org.br", "gov.br", "net.cn", "org.cn", "gov.cn", "org.hk", "edu.sg"
}
# Endings on which "<brand>.<ending>" is accepted. Ownership is not verified.
BRAND_SUFFIXES = BRAND_TWO_PART_SUFFIXES | {
    "com", "de", "fr", "it", "es", "nl", "ca", "in", "ie", "at", "be", "ch", "se", "pl"
}

# Non-Latin (and unusual Latin) letters that pass for an ASCII letter
CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u043a": "k", "\u043c": "m", "\u043d": "h",
    "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y", "\u0445": "x",
    "\u0455": "s", "\u0456": "i", "\u0458": "j", "\u04bb": "h", "\u04cf": "l", "\u0501": "d",
    "\u051b": "q", "\u051d": "w", "\u03b1": "a", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v",
    "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u0131": "i", "\u0251": "a",
    "\u0261": "g"
})
# The stricter subset used to flag a label written wholly in lookalike Cyrillic or Greek letters
WHOLE_LABEL_CONFUSABLES = set(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u04bb\u04cf\u0501\u051b\u051d\u03bf"
)
CJK_SCRIPTS = ("CJK", "HIRAGANA", "KATAKANA", "HANGUL", "BOPOMOFO", "IDEOGRAPHIC")


def registrable_domain(hostname: str) -> str:
    """Returns the registrable part of a hostname, e.g. 'google.co.uk' for 'www.google.co.uk'."""
    labels = hostname.split(".")
    size = 3 if ".".join(labels[-2:]) in TWO_PART_SUFFIXES else 2
    return ".".join(labels[-size:])


def is_brand_domain(hostname: str, brand: str) -> bool:
    """True when the registrable domain is exactly the brand name on an accepted ending."""
    name, _, suffix = registrable_domain(hostname).partition(".")
    return name == brand and suffix in BRAND_SUFFIXES


def _decode_label(label: str):
    """Returns the Unicode form of a hostname label, or None for broken punycode."""
    if label.startswith("xn--"):
        try:
            label = label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError, IndexError, OverflowError):
            return None
        if not label or label.isascii():
            return None
    return unicodedata.normalize("NFKC", label).lower()


def _scripts(label: str) -> set:
    """Names the writing systems used by the letters in a label."""
    found = set()
    for char in label:
        if char.isalpha():
            script = unicodedata.name(char, "UNKNOWN").split()[0]
            found.add("CJK" if script.startswith(CJK_SCRIPTS) else script)
    return found


def _imitates_brand(label: str) -> bool:
    """True when swapping lookalike letters and removing accents reveals a brand name."""
    decomposed = unicodedata.normalize("NFKD", label.translate(CONFUSABLES))
    skeleton = "".join(c for c in decomposed if not unicodedata.combining(c))
    return any(brand in skeleton and brand not in label for brand in TARGET_BRANDS)


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
    """
    Inspects internationalised hostnames, decoding punycode labels first.

    'spoofed' is set only for lookalike patterns: Latin, Cyrillic, Greek or other scripts mixed
    in one label (Latin with CJK is allowed), a label made entirely of Latin-lookalike Cyrillic
    or Greek letters, a label that imitates a listed brand, or punycode that does not decode.
    Other internationalised names set only 'is_idn'.
    """
    labels = domain.lower().split(".")
    is_punycode = any(label.startswith("xn--") for label in labels)
    non_ascii_count = sum(1 for char in domain if ord(char) > 127)

    mixed = False
    lookalike = False
    for raw in labels:
        if raw.isascii() and not raw.startswith("xn--"):
            continue
        label = _decode_label(raw)
        if label is None:
            lookalike = True
            continue
        scripts = _scripts(label)
        if len(scripts) > 1 and scripts != {"LATIN", "CJK"}:
            mixed = True
        letters = [char for char in label if char.isalpha()]
        whole = bool(letters) and all(char in WHOLE_LABEL_CONFUSABLES for char in letters)
        if whole or _imitates_brand(label):
            lookalike = True

    return {
        "is_punycode": is_punycode,
        "is_idn": is_punycode or non_ascii_count > 0,
        "has_mixed_script": mixed,
        "non_ascii_count": non_ascii_count,
        "spoofed": mixed or lookalike
    }


def extract_lexical_features(url: str) -> Dict[str, Any]:
    """Extracts structural and lexical indicators from a URL. Raises ValueError if it cannot be parsed."""
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").rstrip(".")
    if not hostname:
        raise ValueError("URL has no hostname")
    path = parsed.path.lower()
    query = parsed.query.lower()

    # IP address as host check
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

    # Subdomain depth
    subdomain_count = 0
    if not is_ip:
        subdomain_count = len(hostname.split(".")) - len(registrable_domain(hostname).split("."))

    # Keywords abused
    keywords_found = [kw for kw in AUTH_KEYWORDS if kw in path or kw in query]

    # Brand target spoofing in subdomains/path
    brand_mentions = [
        brand for brand in TARGET_BRANDS if brand in hostname and not is_brand_domain(hostname, brand)
    ]

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
    elif homoglyphs["is_idn"]:
        score += 15
        reasons.append("Internationalised domain name (no lookalike pattern recognised)")

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
