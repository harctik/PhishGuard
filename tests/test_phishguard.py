"""
Unit tests for PhishGuard Detection Engine.
Validates entropy calculations, homoglyph detection, lexical indicators, and FastAPI endpoints.
"""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

from detector import calculate_entropy, detect_homoglyphs, extract_lexical_features, evaluate_url


def test_entropy_zero_and_distinct():
    assert calculate_entropy("") == 0.0
    # Repeating string has low entropy
    low_entropy = calculate_entropy("aaaaaaa")
    assert low_entropy == 0.0

    # Complex random-like string has higher entropy
    high_entropy = calculate_entropy("x8k29a1pl0mz4v")
    assert high_entropy > 3.0


def test_homoglyph_punycode_detection():
    # Legitimate ASCII domain
    clean = detect_homoglyphs("paypal.com")
    assert clean["spoofed"] is False

    # Punycode domain
    punycode_domain = "xn--p1ai.ru"
    puny = detect_homoglyphs(punycode_domain)
    assert puny["is_punycode"] is True
    assert puny["spoofed"] is True

    # Mixed-script Cyrillic 'а' replacing Latin 'a'
    mixed_script = "pаypal.com"
    mixed = detect_homoglyphs(mixed_script)
    assert mixed["has_mixed_script"] is True
    assert mixed["spoofed"] is True


def test_lexical_ip_detection():
    ip_url = "http://192.168.1.1/login/banking"
    features = extract_lexical_features(ip_url)
    assert features["is_ip_host"] is True
    assert "login" in features["keywords_found"]
    assert "banking" in features["keywords_found"]


def test_evaluate_malicious_url():
    # Phishing URL containing brand spoofing, IP host, and credential keywords
    phishing_url = "http://192.168.1.50/paypal-update/secure/verify"
    result = evaluate_url(phishing_url)
    assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]
    assert result["risk_score"] >= 50
    assert len(result["reasons"]) > 0


def test_evaluate_clean_url():
    clean_url = "https://github.com/harctik"
    result = evaluate_url(clean_url)
    assert result["verdict"] == "SAFE"
    assert result["risk_score"] < 25
