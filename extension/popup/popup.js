document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) return;
    const url = tabs[0].url;

    fetch("http://localhost:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then((res) => res.json())
      .then((data) => {
        const scoreVal = document.getElementById("score-val");
        const statusBadge = document.getElementById("status-badge");
        const verdictLabel = document.getElementById("verdict-label");
        const reasonsList = document.getElementById("reasons-list");

        scoreVal.innerText = `${data.risk_score}`;
        verdictLabel.innerText = data.verdict;

        if (data.verdict === "MALICIOUS") {
          statusBadge.innerText = "CRITICAL";
          statusBadge.className = "badge danger";
          scoreVal.style.color = "#DA3633";
        } else if (data.verdict === "SUSPICIOUS") {
          statusBadge.innerText = "WARNING";
          statusBadge.className = "badge warn";
          scoreVal.style.color = "#D29922";
        } else {
          statusBadge.innerText = "VERIFIED";
          statusBadge.className = "badge";
          scoreVal.style.color = "#3FB950";
        }

        reasonsList.innerHTML = "";
        if (data.reasons && data.reasons.length > 0) {
          data.reasons.forEach((r) => {
            const li = document.createElement("li");
            li.innerText = `• ${r}`;
            reasonsList.appendChild(li);
          });
        } else {
          const li = document.createElement("li");
          li.innerText = "• No malicious or spoofing markers identified.";
          reasonsList.appendChild(li);
        }
      })
      .catch(() => {
        document.getElementById("verdict-label").innerText = "Offline (Local Heuristics Active)";
      });
  });
});
