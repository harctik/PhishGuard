function showUnchecked(label, badge, detail) {
  document.getElementById("status-badge").innerText = badge;
  document.getElementById("status-badge").className = "badge idle";
  document.getElementById("verdict-label").innerText = label;
  const li = document.createElement("li");
  li.innerText = detail;
  document.getElementById("reasons-list").replaceChildren(li);
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) {
      showUnchecked("This tab has no address to check.", "NOT CHECKED", "There is nothing to score here.");
      return;
    }
    const url = tabs[0].url;

    fetch("http://localhost:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then((res) => {
        if (!res.ok) throw new Error(`Backend returned ${res.status}`);
        return res.json();
      })
      .then((data) => {
        const scoreVal = document.getElementById("score-val");
        const statusBadge = document.getElementById("status-badge");
        const verdictLabel = document.getElementById("verdict-label");
        const reasonsList = document.getElementById("reasons-list");

        scoreVal.innerText = `${data.risk_score}`;
        verdictLabel.innerText = data.verdict;

        if (data.verdict === "MALICIOUS") {
          statusBadge.innerText = "HIGH RISK";
          statusBadge.className = "badge danger";
          scoreVal.style.color = "#B3262E";
        } else if (data.verdict === "SUSPICIOUS") {
          statusBadge.innerText = "CAUTION";
          statusBadge.className = "badge warn";
          scoreVal.style.color = "#8A5A00";
        } else {
          statusBadge.innerText = "LOW RISK";
          statusBadge.className = "badge";
          scoreVal.style.color = "#17693F";
        }

        reasonsList.innerHTML = "";
        if (data.reasons && data.reasons.length > 0) {
          data.reasons.forEach((r) => {
            const li = document.createElement("li");
            li.innerText = r;
            reasonsList.appendChild(li);
          });
        } else {
          const li = document.createElement("li");
          li.innerText = "None of the URL rules matched. This does not prove the page is safe.";
          reasonsList.appendChild(li);
        }
      })
      .catch(() => {
        showUnchecked("Backend offline. Page not checked.", "OFFLINE", "Start the backend on localhost:8000, then reopen this popup.");
      });
  });
});

