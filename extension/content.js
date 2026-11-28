/**
 * Vanguard content script
 * Sends the current page URL for scoring and shows a warning banner on a MALICIOUS verdict.
 * An UNKNOWN verdict (not checked) draws nothing in the page; the service worker marks the
 * toolbar icon with "?" instead.
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
    banner.id = "vanguard-warning-banner";
    banner.setAttribute("role", "alert");
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; z-index: 2147483647; box-sizing: border-box;
      background: #161616; color: #f4f3f0; border-bottom: 4px solid #e5484d;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; text-align: left;
      padding: 12px 20px; box-shadow: 0 6px 18px rgba(0,0,0,0.35);
      display: flex; justify-content: space-between; align-items: center; gap: 16px;
    `;

    const message = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = "Vanguard: this address looks like phishing. ";
    title.style.color = "#ff7a7e";
    message.append(title, `Risk score ${Number(threat.risk_score)}/100. Don't enter passwords or card details here.`);

    const dismiss = document.createElement("button");
    dismiss.id = "vanguard-dismiss";
    dismiss.type = "button";
    dismiss.textContent = "Dismiss";
    dismiss.style.cssText = `
      flex: none; background: #f4f3f0; color: #161616; border: 0; border-radius: 2px;
      padding: 7px 16px; font: 600 13px system-ui, sans-serif; cursor: pointer;
    `;
    dismiss.onclick = () => banner.remove();

    banner.append(message, dismiss);
    document.body.prepend(banner);
  }
})();
