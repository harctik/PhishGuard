"""
Vanguard FastAPI Backend Service
Exposes REST endpoints for real-time URL inspection, bulk evaluation, and health checks.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detector import MAX_URL_LENGTH, evaluate_url


app = FastAPI(
    title="Vanguard API",
    version="1.0.0",
    description="Rule-based phishing risk scoring for URLs."
)

# Browser extensions and pages served from this machine only. An unpacked extension's ID
# differs per install, so any extension ID is accepted. No cookies or credentials are used.
ALLOWED_ORIGIN_REGEX = (
    r"chrome-extension://[a-p]{32}"
    r"|moz-extension://[0-9a-f-]{36}"
    r"|https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?"
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class URLScanRequest(BaseModel):
    url: str


class BulkScanRequest(BaseModel):
    urls: List[str]


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Vanguard URL Risk Service",
        "version": "1.0.0"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


def check_url_text(url: str) -> None:
    """Rejects text that is too long, or cannot be echoed back as UTF-8 (a lone surrogate)."""
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail=f"URL is longer than {MAX_URL_LENGTH} characters")
    try:
        url.encode("utf-8")
    except UnicodeEncodeError:
        raise HTTPException(status_code=400, detail="URL is not valid Unicode")


@app.post("/scan")
def scan_url(request: URLScanRequest) -> Dict[str, Any]:
    """Inspects a single URL and returns multi-signal phishing risk assessment."""
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    check_url_text(url)
    try:
        return evaluate_url(url)
    except ValueError:
        raise HTTPException(status_code=400, detail="URL could not be parsed")


def scan_one_of_many(url: str) -> Dict[str, Any]:
    """Like evaluate_url, but a malformed address does not fail the rest of the batch."""
    try:
        return evaluate_url(url)
    except ValueError:
        return {"url": url, "verdict": "UNKNOWN", "risk_score": None, "reasons": ["URL could not be parsed"]}


@app.post("/scan/bulk")
def scan_bulk(request: BulkScanRequest) -> List[Dict[str, Any]]:
    """Inspects a batch of URLs, one after another."""
    if len(request.urls) > 100:
        raise HTTPException(status_code=400, detail="Bulk limit is 100 URLs per request")
    urls = [u.strip() for u in request.urls if u.strip()]
    for url in urls:
        check_url_text(url)
    return [scan_one_of_many(u) for u in urls]
