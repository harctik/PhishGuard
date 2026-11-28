/**
 * Vanguard service worker
 * Forwards scan requests from content.js to the local backend.
 */

importScripts("shared.js");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanCurrentPage") {
    scanUrl(request.url).then((result) => {
      if (sender.tab) setCheckedBadge(sender.tab.id, result);
      if (result.cause === "offline" || result.cause === "rejected") {
        console.warn(`[Vanguard] This page was not checked (backend ${result.cause}).`);
      }
      sendResponse(result);
    });
    return true; // Keep channel open for async response
  }
});
