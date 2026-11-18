/**
 * PhishGuard Service Worker
 * Coordinates API threat requests and caches scanned results.
 */

const API_ENDPOINT = "http://localhost:8000/scan";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanCurrentPage") {
    fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: request.url })
    })
      .then((res) => res.json())
      .then((data) => {
        sendResponse(data);
      })
      .catch((err) => {
        console.warn("[PhishGuard] Backend unreachable, falling back to local heuristic.", err);
        sendResponse({ verdict: "SAFE", risk_score: 0 });
      });
    return true; // Keep channel open for async response
  }
});

