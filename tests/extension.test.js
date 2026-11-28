// Tests for the extension scripts. Run with: node --test tests/extension.test.js
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const read = (file) => fs.readFileSync(path.join(__dirname, "..", "extension", file), "utf8");
const settle = () => new Promise((resolve) => setImmediate(resolve));
const reply = (body, ok = true) => async () => ({ ok, json: async () => body });
const offline = async () => { throw new TypeError("Failed to fetch"); };

// Loads background.js, with shared.js behind importScripts, against a fake chrome and fetch.
function loadWorker(fetchImpl) {
  const sent = [];
  const badge = {};
  let listener;
  const context = vm.createContext({
    URL, AbortSignal,
    console: { warn() {} },
    fetch: (url, options) => {
      sent.push({ url, body: JSON.parse(options.body) });
      return fetchImpl(url, options);
    },
    chrome: {
      runtime: { onMessage: { addListener: (fn) => { listener = fn; } } },
      action: {
        setBadgeText: ({ text }) => { badge.text = text; },
        setBadgeBackgroundColor() {},
        setTitle: ({ title }) => { badge.title = title; }
      }
    }
  });
  context.importScripts = (file) => vm.runInContext(read(file), context);
  vm.runInContext(read("background.js"), context);

  const scan = (url) => new Promise((resolve) => {
    listener({ action: "scanCurrentPage", url }, { tab: { id: 1 } }, resolve);
  });
  return { scan, sent, badge };
}

const failures = {
  "unreachable backend": [offline, "offline"],
  "HTTP error": [reply({ detail: "bad" }, false), "rejected"],
  "body that is not JSON": [async () => ({ ok: true, json: async () => { throw new SyntaxError(); } }), "rejected"],
  "body without a verdict": [reply({}), "rejected"]
};

for (const [name, [fetchImpl, cause]] of Object.entries(failures)) {
  test(`${name} is UNKNOWN, never SAFE`, async () => {
    const worker = loadWorker(fetchImpl);
    const result = await worker.scan("https://example.com/");
    assert.strictEqual(result.verdict, "UNKNOWN");
    assert.strictEqual(result.risk_score, null);
    assert.strictEqual(result.cause, cause);
    assert.strictEqual(worker.badge.text, "?");
    assert.match(worker.badge.title, /not checked/);
  });
}

test("a real verdict passes through and clears the badge", async () => {
  const worker = loadWorker(reply({ verdict: "SAFE", risk_score: 0 }));
  const result = await worker.scan("https://example.com/");
  assert.strictEqual(result.verdict, "SAFE");
  assert.strictEqual(worker.badge.text, "");
});

test("fragments and credentials are not sent; the @ signal is kept", async () => {
  const worker = loadWorker(reply({ verdict: "SAFE", risk_score: 0 }));
  await worker.scan("https://alice:hunter2@example.com/p?q=1#access_token=abc");
  assert.strictEqual(worker.sent[0].body.url, "https://redacted@example.com/p?q=1");
  await worker.scan("https://example.com/p#frag");
  assert.strictEqual(worker.sent[1].body.url, "https://example.com/p");
});

test("the default backend is loopback", async () => {
  const worker = loadWorker(offline);
  await worker.scan("https://example.com/");
  assert.strictEqual(new URL(worker.sent[0].url).hostname, "localhost");
});

test("non-web addresses are not sent", async () => {
  const worker = loadWorker(offline);
  for (const url of ["file:///C:/secret.txt", "chrome://extensions", "about:blank", "http://[abc"]) {
    const result = await worker.scan(url);
    assert.strictEqual(result.cause, "unsupported");
  }
  assert.strictEqual(worker.sent.length, 0);
});

// Runs content.js with a canned worker response and counts the elements added to the page.
function bannersFor(response) {
  let added = 0;
  const element = () => ({ style: {}, setAttribute() {}, append() {}, remove() {} });
  vm.runInNewContext(read("content.js"), {
    window: { location: { href: "https://example.com/" } },
    chrome: { runtime: { sendMessage: (message, callback) => callback(response) } },
    document: { createElement: element, body: { prepend: () => { added += 1; } } }
  });
  return added;
}

test("content script warns only on MALICIOUS", () => {
  assert.strictEqual(bannersFor({ verdict: "MALICIOUS", risk_score: 75 }), 1);
  assert.strictEqual(bannersFor({ verdict: "UNKNOWN", risk_score: null, cause: "offline" }), 0);
  assert.strictEqual(bannersFor(undefined), 0);
});

// Runs popup.js with shared.js and returns the text of each element it wrote to.
async function popupFor(tabUrl, fetchImpl) {
  const elements = {};
  const element = () => ({ innerText: "", className: "", style: {}, replaceChildren() {}, appendChild() {} });
  const context = vm.createContext({
    URL, AbortSignal,
    fetch: fetchImpl,
    chrome: {
      tabs: { query: (query, callback) => callback([{ id: 1, url: tabUrl }]) },
      action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setTitle() {} }
    },
    document: {
      getElementById: (id) => (elements[id] ||= element()),
      createElement: element,
      addEventListener: (name, fn) => fn()
    }
  });
  vm.runInContext(read("shared.js"), context);
  vm.runInContext(read("popup/popup.js"), context);
  await settle();
  await settle();
  return elements;
}

test("popup shows the not-checked states without a score", async () => {
  const cases = [
    ["https://example.com/", offline, "OFFLINE"],
    ["https://example.com/", reply({ detail: "bad" }, false), "NOT CHECKED"],
    ["chrome://extensions", offline, "NOT CHECKED"]
  ];
  for (const [url, fetchImpl, badge] of cases) {
    const elements = await popupFor(url, fetchImpl);
    assert.strictEqual(elements["status-badge"].innerText, badge);
    assert.strictEqual(elements["status-badge"].className, "badge idle");
    assert.strictEqual(elements["score-val"], undefined);
  }
});

test("popup shows a returned score", async () => {
  const elements = await popupFor("https://example.com/", reply({ verdict: "MALICIOUS", risk_score: 75, reasons: [] }));
  assert.strictEqual(elements["score-val"].innerText, "75");
  assert.strictEqual(elements["status-badge"].innerText, "HIGH RISK");
});
