"""
Unit tests for the Vanguard detection engine.
Validates entropy calculations, homoglyph detection, lexical indicators, and FastAPI endpoints.
"""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

from fastapi.testclient import TestClient

from detector import (
    MAX_URL_LENGTH, calculate_entropy, detect_homoglyphs, extract_lexical_features, evaluate_url,
    registrable_domain
)
from main import app

client = TestClient(app, raise_server_exceptions=False)


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

    # Punycode lookalike (Cyrillic 'a' inside a Latin label)
    puny = detect_homoglyphs("xn--pypal-4ve.com")
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


@pytest.mark.parametrize("host", [
    "evilpaypal.com", "paypal.com.evil.net", "paypal-login.com", "paypal.evil.co.uk",
    "paypal.co.com", "paypal.org.uk", "google.co.uk.attacker.com",
])
def test_brand_lookalike_hosts_are_flagged(host):
    result = evaluate_url(f"https://{host}/")
    assert result["features"]["brand_mentions"]
    assert result["risk_score"] >= 40


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "paypal.com.", "google.co.uk", "www.google.co.uk",
    "accounts.google.com", "amazon.in", "amazon.com.au", "WWW.PayPal.COM",
])
def test_brand_own_domains_are_not_flagged(host):
    result = evaluate_url(f"https://{host}/")
    assert result["features"]["brand_mentions"] == []
    assert result["risk_score"] == 0


def test_registrable_domain_and_subdomain_depth():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("a.b.example.com") == "example.com"
    assert extract_lexical_features("https://a.b.example.co.uk/")["subdomain_count"] == 2
    assert extract_lexical_features("https://a.b.c.example.co.uk/")["subdomain_count"] == 3


@pytest.mark.parametrize("host", [
    "xn--mnchen-3ya.de", "m\u00fcnchen.de", "xn--p1ai.ru",
    "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",  # a Russian word
    "\u65e5\u672c\u306e\u30b5\u30fc\u30d3\u30b9.jp",  # Japanese: kanji, hiragana, katakana
])
def test_ordinary_international_domain_scores_low(host):
    result = evaluate_url(f"https://{host}/")
    assert result["homoglyph_analysis"]["is_idn"] is True
    assert result["homoglyph_analysis"]["spoofed"] is False
    assert (result["risk_score"], result["verdict"]) == (15, "SAFE")


@pytest.mark.parametrize("host", [
    "xn--pypal-4ve.com",
    "p\u0430ypal.com",  # mixed Latin and Cyrillic
    "\u0430\u0440\u0440\u04cf\u0435.com",  # wholly Cyrillic imitation of "apple"
    "p\u00e0ypal.com",  # accented Latin imitating a brand
    "xn--!!!.com",  # punycode that does not decode
])
def test_lookalike_international_domain_scores_45(host):
    result = evaluate_url(f"https://{host}/")
    assert result["homoglyph_analysis"]["spoofed"] is True
    assert result["risk_score"] == 45


@pytest.mark.parametrize("url", ["http://[abc", "http://abc]/", "http://", "https:///path", "//["])
def test_malformed_url_returns_400(url):
    response = client.post("/scan", json={"url": url})
    assert response.status_code == 400


@pytest.mark.parametrize("route, body", [
    ("/scan", rb'{"url": "http://\ud800.com"}'), ("/scan/bulk", rb'{"urls": ["http://\ud800.com"]}')
])
def test_lone_surrogate_returns_400(route, body):
    response = client.post(route, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400


def test_uppercase_scheme_is_recognised():
    features = extract_lexical_features("HTTPS://example.com/")
    assert features["hostname"] == "example.com"
    assert features["uses_https"] is True


def test_bulk_malformed_item_is_unknown_not_fatal():
    response = client.post("/scan/bulk", json={"urls": ["https://example.com", "http://[abc"]})
    assert response.status_code == 200
    assert [item["verdict"] for item in response.json()] == ["SAFE", "UNKNOWN"]
    assert response.json()[1]["risk_score"] is None


def test_bulk_count_limit():
    assert client.post("/scan/bulk", json={"urls": ["https://a.com"] * 100}).status_code == 200
    assert client.post("/scan/bulk", json={"urls": ["https://a.com"] * 101}).status_code == 400


@pytest.mark.parametrize("route, wrap", [("/scan", lambda u: {"url": u}), ("/scan/bulk", lambda u: {"urls": [u]})])
def test_url_length_limit(route, wrap):
    base = "https://a.com/"
    at_limit = base + "x" * (MAX_URL_LENGTH - len(base))
    assert client.post(route, json=wrap(at_limit)).status_code == 200
    assert client.post(route, json=wrap(at_limit + "x")).status_code == 400


@pytest.mark.parametrize("origin", [
    "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
    "moz-extension://12345678-1234-1234-1234-123456789abc",
    "http://localhost:8000", "http://127.0.0.1:5173", "http://[::1]:3000",
])
def test_cors_allows_extension_and_local_origins(origin):
    headers = {"Origin": origin, "Access-Control-Request-Method": "POST",
               "Access-Control-Request-Headers": "content-type"}
    preflight = client.options("/scan", headers=headers)
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-credentials" not in preflight.headers


@pytest.mark.parametrize("origin", [
    "https://evil.example", "http://localhost.evil.example", "http://127.0.0.1.evil.example",
    "https://evil.example/http://localhost", "null", "chrome-extension://short",
])
def test_cors_refuses_other_origins(origin):
    headers = {"Origin": origin, "Access-Control-Request-Method": "POST"}
    assert client.options("/scan", headers=headers).status_code == 400
    response = client.post("/scan", json={"url": "https://a.com"}, headers={"Origin": origin})
    assert "access-control-allow-origin" not in response.headers
