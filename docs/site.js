// Shows saved detector outputs from samples.js. Nothing is scanned in the browser.
(() => {
  const samples = window.VANGUARD_SAMPLES || [];
  const list = document.getElementById("specimens");
  const byId = (id) => document.getElementById(id);
  const colour = { SAFE: "#17693f", SUSPICIOUS: "#8a5a00", MALICIOUS: "#b3262e" };

  function show(index) {
    const { result, note } = samples[index];
    byId("r-score").textContent = result.risk_score;
    byId("r-verdict").textContent = result.verdict.toLowerCase();
    byId("r-verdict").style.background = colour[result.verdict];
    byId("r-url").textContent = result.url;
    byId("r-fill").style.width = `${result.risk_score}%`;
    byId("r-fill").style.background = colour[result.verdict];
    const reasons = result.reasons.length ? result.reasons : ["No rule matched."];
    byId("r-reasons").replaceChildren(...reasons.map((text) => {
      const li = document.createElement("li");
      li.textContent = text;
      return li;
    }));
    byId("r-note").textContent = note;
    [...list.children].forEach((button, i) => button.setAttribute("aria-pressed", String(i === index)));
  }

  samples.forEach((sample, i) => {
    const button = document.createElement("button");
    button.type = "button";
    const label = document.createElement("span");
    label.textContent = sample.label;
    const address = document.createElement("code");
    address.textContent = sample.result.url;
    button.append(label, address);
    button.addEventListener("click", () => show(i));
    list.append(button);
  });

  if (samples.length) show(0);
})();
