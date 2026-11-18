/**
 * PhishGuard Content Script
 * Scans page anchors for homoglyphs and suspicious credential targets.
 */

(() => {
  const currentUrl = window.location.href;

  // Notify background worker to assess current page safety
  chrome.runtime.sendMessage({ action: "scanCurrentPage", url: currentUrl }, (response) => {
    if (response && response.verdict === "MALICIOUS") {
      showPhishingBanner(response);
    }
  });

  function showPhishingBanner(threat) {
    const banner = document.createElement("div");
    banner.id = "phishguard-warning-banner";
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; z-index: 2147483647;
      background: #E63946; color: #FFFFFF; font-family: -apple-system, sans-serif;
      padding: 14px 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      display: flex; justify-content: space-between; align-items: center;
      font-size: 14px; font-weight: 600;
    `;
    banner.innerHTML = `
      <div>
        ⚠️ <strong>PHISHGUARD ALERT:</strong> This site exhibits strong phishing indicators (Risk Score: ${threat.risk_score}/100). Do NOT enter credentials.
      </div>
      <button id="phishguard-dismiss" style="background:#000;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;">
        Dismiss
      </button>
    `;
    document.body.prepend(banner);
    document.getElementById("phishguard-dismiss").onclick = () => banner.remove();
  }
})();
