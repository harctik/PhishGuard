/**
 * Vanguard shared scan client
 * Used by the service worker and the popup. The default backend is loopback only:
 * addresses are sent over plain HTTP, so use HTTPS if you ever point this at another machine.
 */

const API_ENDPOINT = "http://localhost:8000/scan";
const SCAN_TIMEOUT_MS = 5000;
const CHECKED_VERDICTS = ["SAFE", "SUSPICIOUS", "MALICIOUS"];

/**
 * Returns the address to send to the backend, or null if it is not a web address.
 * The fragment is dropped. A username or password is replaced by the word "redacted",
 * so the backend's "@" rule still applies without receiving either value.
 */
function sanitizeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  url.hash = "";
  if (url.username || url.password) {
    url.username = "redacted";
    url.password = "";
  }
  return url.href;
}

/** A result that means "not checked". It must never be presented as safe. */
function unknownResult(cause) {
  return { verdict: "UNKNOWN", risk_score: null, cause };
}

/**
 * Always resolves. cause on an UNKNOWN result is "unsupported" (not a web address),
 * "offline" (no answer from the backend) or "rejected" (no usable verdict in the answer).
 */
async function scanUrl(raw) {
  const url = sanitizeUrl(raw);
  if (!url) return unknownResult("unsupported");

  let res;
  try {
    res = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS)
    });
  } catch {
    return unknownResult("offline");
  }

  try {
    if (!res.ok) return unknownResult("rejected");
    const data = await res.json();
    if (!data || !CHECKED_VERDICTS.includes(data.verdict) || typeof data.risk_score !== "number") {
      return unknownResult("rejected");
    }
    return data;
  } catch {
    return unknownResult("rejected");
  }
}

/** Marks a tab's toolbar icon with "?" while its page has not been checked. */
function setCheckedBadge(tabId, result) {
  const unchecked = result.verdict === "UNKNOWN";
  chrome.action.setBadgeText({ tabId, text: unchecked ? "?" : "" });
  if (unchecked) chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b6b68" });
  chrome.action.setTitle({ tabId, title: unchecked ? "Vanguard: this page was not checked" : "Vanguard" });
}
