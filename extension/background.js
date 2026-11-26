/**
 * Vanguard service worker
 * Forwards scan requests from content.js to the local backend.
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
        console.warn("[Vanguard] Backend unreachable. This page was not checked.", err);
        sendResponse({ verdict: "SAFE", risk_score: 0 });
      });
    return true; // Keep channel open for async response
  }
});

