"""
PhishGuard FastAPI Backend Service
Exposes REST endpoints for real-time URL inspection, bulk evaluation, and health checks.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detector import evaluate_url


app = FastAPI(
    title="PhishGuard Security API",
    version="1.0.0",
    description="Real-time adversarial phishing intelligence and URL anomaly detection service."
)

# Enable CORS for Chrome Extension integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLScanRequest(BaseModel):
    url: str


class BulkScanRequest(BaseModel):
    urls: List[str]


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "PhishGuard Real-Time Phishing Intelligence",
        "version": "1.0.0"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan")
def scan_url(request: URLScanRequest) -> Dict[str, Any]:
    """Inspects a single URL and returns multi-signal phishing risk assessment."""
    if not request.url or len(request.url.strip()) == 0:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return evaluate_url(request.url.strip())


@app.post("/scan/bulk")
def scan_bulk(request: BulkScanRequest) -> List[Dict[str, Any]]:
    """Inspects a batch of URLs concurrently (e.g., all links on a rendered webpage)."""
    if len(request.urls) > 100:
        raise HTTPException(status_code=400, detail="Bulk limit is 100 URLs per request")
    return [evaluate_url(u.strip()) for u in request.urls if u.strip()]
