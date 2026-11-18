// Store screenshots (1280x800) of the extension UI with the fake native host from
// real-chromium-panels.cjs (demo data only, no app or vault). Not part of `npm test`.
// In a scratch folder: npm install --no-save playwright-core, then
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj "/CN=example.com"
//   node <repo>/tests/extension/manual/store-screenshots.cjs <repo> <outdir>
// The demo site is served as https://example.com (mapped to 127.0.0.1). The toolbar popup is opened in a
// tab, so its active-tab and diagnostics calls are stubbed to show the connected state.
const fs = require("fs"), path = require("path"), http = require("https"), os = require("os");
const { chromium } = require("playwright-core");
const REPO = process.argv[2], OUT = process.argv[3];
fs.mkdirSync(OUT, { recursive: true });

// Reuse the fake native host and extension patcher from the manual harness.
const harness = fs.readFileSync(path.join(REPO, "tests/extension/manual/real-chromium-panels.cjs"), "utf8");
const head = harness.slice(harness.indexOf("const USER"), harness.indexOf("const PAGES"))
  .replace('"alice.e2e@test.example"', '"alex@example.com"')
  .replace('label:"Demo account"', 'label:"Example Cloud"')
  .replace('label:"Second account",username:"bob.e2e@test.example"', 'label:"Example Cloud (work)",username:"alex.work@example.com"')
  .replaceAll('profile:{name:"E2E"}', 'profile:{name:"Personal"}');
// eval of the repo's own test harness (trusted local source), so its fake host stays in one place.
eval(head.replace(/^const /gm, "var "));

const SHELL = (title, body) => `<!doctype html><html><head><title>${title}</title><style>
*{box-sizing:border-box}body{margin:0;font:15px/1.5 "Segoe UI",system-ui,sans-serif;background:linear-gradient(135deg,#eef2f7,#dfe7f1);color:#1d2733;height:100vh}
header{height:64px;display:flex;align-items:center;padding:0 40px;background:#fff;border-bottom:1px solid #e3e8ef;font-weight:700;font-size:18px;gap:10px}
.logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#3a7bd5,#00d2ff)}
main{display:flex;justify-content:center;padding-top:70px}
.card{width:420px;background:#fff;border-radius:14px;box-shadow:0 10px 40px rgba(20,40,80,.12);padding:36px 40px}
h1{font-size:24px;margin:0 0 6px}p{margin:0 0 22px;color:#5b6775}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}
input{display:block;width:100%;height:42px;border:1px solid #cdd6e1;border-radius:8px;padding:0 12px;font-size:15px}
button{margin-top:22px;width:100%;height:44px;border:0;border-radius:8px;background:#2f6fd0;color:#fff;font-size:15px;font-weight:600}
</style></head><body><header><span class="logo"></span>Example Cloud</header><main><div class="card">${body}</div></main></body></html>`;
const PAGES = {
  "/login": SHELL("Sign in", `<h1>Sign in</h1><p>Welcome back to Example Cloud.</p><form method="post" action="/done"><label>Email</label><input id="user" autocomplete="username" name="u"><label>Password</label><input id="password" type="password" autocomplete="current-password" name="p"><button>Sign in</button></form>`),
  "/signup": SHELL("Create account", `<h1>Create your account</h1><p>It takes less than a minute.</p><form method="post" action="/done"><label>Email</label><input id="user" autocomplete="username" name="u" value="alex@example.com"><label>Password</label><input id="np1" type="password" autocomplete="new-password" name="p"><label>Confirm password</label><input id="np2" type="password" autocomplete="new-password"><button>Create account</button></form>`),
  "/otp": SHELL("Verify", `<h1>Two-step verification</h1><p>Enter the 6-digit code from your authenticator.</p><form method="post" action="/done"><label>Code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" name="code"><button>Verify</button></form>`),
  "/done": SHELL("Welcome", `<h1>You're signed in</h1><p>Welcome to Example Cloud.</p>`),
};
const serve = () => new Promise(res => { const s = http.createServer({ key: fs.readFileSync(process.cwd() + "/key.pem"), cert: fs.readFileSync(process.cwd() + "/cert.pem") }, (q, r) => { const b = PAGES[q.url.split("?")[0]]; if (!b) { r.writeHead(404); return r.end(); } r.writeHead(200, { "content-type": "text/html; charset=utf-8" }); r.end(b); }).listen(0, "127.0.0.1", () => res(s)); });

(async () => {
  const main = await serve(), base = "https://example.com";
  const ext = makeExtension({ err: 1, look: 2 });
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-shot-"));
  const ctx = await chromium.launchPersistentContext(profile, { headless: false, ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1,
    executablePath: path.join(process.env.LOCALAPPDATA, "ms-playwright", "chromium-1243", "chrome-win64", "chrome.exe"),
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, "--no-first-run", "--ignore-certificate-errors", `--host-resolver-rules=MAP example.com 127.0.0.1:${main.address().port}`] });
  const sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent("serviceworker", { timeout: 10000 });
  const extId = sw.url().split("/")[2];
  const pg = await ctx.newPage();
  const goto = async u => { await pg.goto(u); await pg.waitForTimeout(900); };
  const panel = async () => { for (let i = 0; i < 60; i++) { const f = pg.frames().filter(f => f.url().includes("/panel.html")).pop(); if (f) { try { await f.waitForSelector("button", { timeout: 1500 }); return f; } catch {} } await pg.waitForTimeout(100); } throw new Error("no panel"); };
  const clickIcon = async (sel, field) => { await pg.waitForSelector(sel, { state: "attached", timeout: 8000 }); const fb = await (await pg.$(field)).boundingBox(); let best, bd = 1e9; for (const i of await pg.$$(sel)) { const b = await i.boundingBox(); if (b && Math.abs(b.y - fb.y) < bd) { bd = Math.abs(b.y - fb.y); best = b; } } await pg.mouse.click(best.x + best.width / 2, best.y + best.height / 2); };
  const shot = async (n, note) => { await pg.waitForTimeout(700); await pg.screenshot({ path: path.join(OUT, n) }); console.log("ok", n, note || ""); };
  const step = async (n, fn) => { try { await fn(); } catch (e) { console.log("FAIL", n, e.message); } };

  await step("5", async () => {
    await goto(base + "/login");
    const tab = await sw.evaluate(() => chrome.tabs.query({ url: "https://example.com/*" }).then(t => t[0]));
    const pop = await ctx.newPage(); await pop.setViewportSize({ width: 380, height: 600 });
    await pop.addInitScript(t => { chrome.tabs.query = (o, cb) => { const r = Promise.resolve([t]); if (cb) { r.then(cb); return; } return r; };
      const sm = chrome.runtime.sendMessage.bind(chrome.runtime);
      chrome.runtime.sendMessage = (m, ...a) => { if (m && m.type === "diagnostics") return Promise.resolve({ ok: true, version: "0.4.12", locked: false }); return sm(m, ...a); }; }, tab);
    await pop.goto(`chrome-extension://${extId}/popup.html`); await pop.waitForTimeout(1500);
    const h = await pop.evaluate(() => document.documentElement.scrollHeight); await pop.setViewportSize({ width: 380, height: Math.min(h, 640) });
    const bh = await pop.evaluate(() => Math.ceil(Math.max(...[...document.body.children].map(e => e.getBoundingClientRect().bottom)))); const img = (await pop.screenshot({ clip: { x: 0, y: 0, width: 380, height: bh } })).toString("base64"); await pop.close();
    await pg.bringToFront(); await pg.waitForTimeout(300);
    const bg = (await pg.screenshot()).toString("base64");
    await pg.setContent(`<body style="margin:0;width:1280px;height:800px;position:relative;overflow:hidden"><img src="data:image/png;base64,${bg}" style="position:absolute;inset:0;filter:brightness(.92)"><img src="data:image/png;base64,${img}" style="position:absolute;right:24px;top:8px;border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.35)"></body>`);
    await shot("5-toolbar-popup.png");
  });
  await step("1", async () => { await goto(base + "/login"); await clickIcon("[data-localvault-field-icon]", "#user"); await panel(); await shot("1-login-picker.png"); });
  await step("2", async () => { await goto(base + "/signup"); await clickIcon("[data-localgatekeys-generate-icon]", "#np1"); await panel(); await shot("2-generate-password.png"); });
  await step("3", async () => { await goto(base + "/otp"); await clickIcon("[data-localgatekeys-otp-icon]", "#otp"); await panel(); await shot("3-one-time-code.png"); });
  await step("4", async () => {
    await goto(base + "/login"); await pg.fill("#user", "alex@example.com"); await pg.fill("#password", "Correct-Horse-Battery-42");
    await pg.click("form button"); await pg.waitForTimeout(2500);
    await shot("4-save-prompt.png", pg.frames().map(f => f.url()).filter(u => u.includes("extension")).join(","));
  });
  await ctx.close(); main.close();
})();
