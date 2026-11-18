// Manual real-Firefox check of the extension panels (docs/PENDING.md: extension panel frame, Firefox).
// Not part of `npm test`. Firefox counterpart of real-chromium-panels.cjs (same fake native host, same
// 127.0.0.1 pages): the Firefox build (build-firefox-manifest.cjs) is installed as a temporary add-on
// into a throwaway profile of the installed Firefox through WebDriver BiDi (puppeteer-core). BiDi does
// not expose moz-extension frames, so rows are clicked by position and keys go to the focused frame.
//
//   PUPPETEER_SKIP_DOWNLOAD=1 npm install --no-save puppeteer-core   (in a scratch folder, run from there)
//   node real-firefox-panels.cjs <repo>
const fs = require("fs"), path = require("path"), http = require("http"), os = require("os");
const puppeteer = require("puppeteer-core");
const sleep = ms => new Promise(r => setTimeout(r, ms));
const REPO = process.argv[2];
const USER = "alice.e2e@test.example";
const PASS = "Test-Only-E2E-Secret-91!";

const FAKE = `
let __pending=null;
async function __fakeNative(host,p){
  const o=String(p.origin||""), port=(o.match(/:(\\d+)$/)||[])[1];
  const nonce="0123456789abcdef0123456789abcdef";
  const choice={entry_id:"e1",label:"Demo account",username:${JSON.stringify(USER)}};
  const two=[choice,{entry_id:"e2",label:"Second account",username:"bob.e2e@test.example"}];
  switch(p.action){
    case "ping": return {ok:true,version:"e2e",locked:false,browser_enabled:true,session_id:"s1"};
    case "begin_gesture_browser": return {ok:true,gesture_nonce:nonce,gesture_expires_in:30};
    case "begin_browser": return port===globalThis.__ERRPORT?{ok:false,error:"vault_locked"}:{ok:true,grant:"g1",session_id:"s1",profile:{name:"E2E"},choices:two,gesture_nonce:nonce};
    case "get_browser": return {ok:true,session_id:"s1",credential:{username:${JSON.stringify(USER)},password:${JSON.stringify(PASS)}}};
    case "validate_browser": case "submit_browser": case "cancel_browser": return {ok:true};
    case "begin_totp_browser": return {ok:true,grant:"g2",session_id:"s1",profile:{name:"E2E"},choices:two,gesture_nonce:nonce};
    case "get_totp_browser": return {ok:true,code:"123456",remaining:25};
    case "begin_card_browser": return {ok:true,session_id:"s1",profile:{name:"E2E"},choices:[{entry_id:"c1",revision:1,title:"Holiday Visa",brand:"Visa",last4:"4242",fields:{"cc-name":{present:true},"cc-number":{present:true},"cc-exp":{present:true},"cc-csc":{present:true}}},{entry_id:"c2",revision:1,title:"Work card",brand:"Mastercard",last4:"5454",fields:{"cc-number":{present:true}}}]};
    case "approve_card_browser": return {ok:true,approval:"approval-card-1",gesture_nonce:nonce};
    case "release_card_browser": { const v={"cc-name":"Alice Test","cc-number":"4242424242424242","cc-exp":"12/30","cc-csc":"123"}; const values={}; for(const f of p.fields)values[f]=v[f]; return {ok:true,fields:p.fields,values}; }
    case "cancel_card_browser": case "cancel_identity_browser": return {ok:true};
    case "begin_identity_browser": return {ok:true,session_id:"s1",profile:{name:"E2E"},choices:[{entry_id:"i1",revision:1,title:"Home identity",fields:["name","email"]},{entry_id:"i2",revision:1,title:"Work identity",fields:["name","email"]}]};
    case "approve_identity_browser": return {ok:true,approval:"approval-id-1"};
    case "release_identity_browser": { const v={name:"Alice Test",email:"alice.home@test.example"}; const values={}; for(const f of p.fields)values[f]=v[f]; return {ok:true,fields:p.fields,values}; }
    case "classify_site_browser": return port===globalThis.__LOOKPORT?{ok:true,kind:"lookalike",reason:"typo",matched:"example.com"}:{ok:true,kind:"unknown"};
    case "check_browser": return {ok:true,prompt:true,status:"new"};
    case "capture_browser": __pending={username:p.username,token:"fedcba9876543210fedcba9876543210"}; return {ok:true,pending_token:__pending.token};
    case "pending_browser": return __pending?{ok:true,pending:true,pending_token:__pending.token,username:__pending.username,status:"new",age_ms:1000}:{ok:true,pending:false};
    case "save_pending_browser": case "save_browser": __pending=null; return {ok:true};
    case "discard_pending_browser": case "clear_pending_browser": __pending=null; return {ok:true};
    case "new_site_username_browser": return {ok:true,elsewhere:false};
    default: return {ok:true};
  }
}
`;

function makeExtension(ports) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-ext-"));
  require("child_process").execFileSync("node",[path.join(REPO,"browser-extension","build-firefox-manifest.cjs"),dir]);
  const bg = path.join(dir, "background.js");
  let src = fs.readFileSync(bg, "utf8");
  if (!src.includes("api.runtime.sendNativeMessage(HOST_NAME, ")) throw new Error("patch point moved");
  src = src.replace("api.runtime.sendNativeMessage(HOST_NAME, ", "__fakeNative(HOST_NAME, ");
  src += `\nglobalThis.__ERRPORT=${JSON.stringify(String(ports.err))};globalThis.__LOOKPORT=${JSON.stringify(String(ports.look))};\n` + FAKE;
  fs.writeFileSync(bg, src);
  if (process.env.DBG) { const c = path.join(dir, "content.js"); let t = fs.readFileSync(c, "utf8");
    t = t.replace('if(r.visible===false || !hostIntact(panelHost,point)){', 'console.log("LGKDBG", JSON.stringify({visible:r.visible, layout:hostLayoutIntact(panelHost), intact:hostIntact(panelHost,point), point, box:{l:box.left,t:box.top,w:box.width,h:box.height}, want:placed.get(panelHost)}));if(r.visible===false || !hostIntact(panelHost,point)){');
    fs.writeFileSync(c, t); }
  return dir;
}

const PAGES = {
  "/login": `<form method="post" action="/done"><input id="user" autocomplete="username" name="u"><input id="password" type="password" autocomplete="current-password" name="p"><button id="go">Sign in</button></form>`,
  "/bottom": `<div style="height:calc(100vh - 200px)"></div><form method="post" action="/done"><input id="user" autocomplete="username"><input id="password" type="password" autocomplete="current-password"><button>Sign in</button></form>`,
  "/signup": `<form method="post" action="/done"><input id="user" autocomplete="username"><input id="np1" type="password" autocomplete="new-password"><input id="np2" type="password" autocomplete="new-password"><button>Create account</button></form>`,
  "/change": `<form method="post" action="/done"><input id="cur" type="password" autocomplete="current-password"><input id="np1" type="password" autocomplete="new-password"><input id="np2" type="password" autocomplete="new-password"><button>Change password</button></form>`,
  "/otp": `<form method="post" action="/done"><input id="otp" autocomplete="one-time-code" inputmode="numeric" name="code"><button>Verify</button></form>`,
  "/card": `<form method="post" action="/done"><input id="ccname" autocomplete="cc-name"><input id="ccnum" autocomplete="cc-number"><input id="ccexp" autocomplete="cc-exp"><input id="cccsc" autocomplete="cc-csc"><button>Pay</button></form>`,
  "/identity": `<form method="post" action="/done"><input id="name" autocomplete="name" name="name"><input id="email" type="email" autocomplete="email" name="email"><button>Send</button></form>`,
  "/done": `<p>Signed in.</p>`,
};
const CSS = `<style>body{font:16px sans-serif;padding:40px;background:#f4f6f9}input{display:block;width:320px;height:36px;margin:10px 0}</style>`;

function serve(csp) {
  return new Promise(res => {
    const s = http.createServer((req, rsp) => {
      const p = req.url.split("?")[0];
      const body = PAGES[p];
      if (!body) { rsp.writeHead(404); return rsp.end(); }
      const h = { "content-type": "text/html; charset=utf-8" };
      if (csp) h["content-security-policy"] = csp;
      rsp.writeHead(200, h);
      rsp.end(`<!doctype html><html><head><title>t</title>${CSS}</head><body>${body}</body></html>`);
    }).listen(0, "127.0.0.1", () => res(s));
  });
}

const results = [];
async function check(name, fn) {
  try { const note = await fn(); results.push(["PASS", name, note || ""]); console.log("PASS", name, note || ""); }
  catch (e) { try { const g = globalThis.__pg.frames().filter(x => x.url().includes("/panel.html")).pop(); e.message += " | frame: " + (g ? (await g.evaluate(() => document.body.innerText)).replace(/\s+/g," ").slice(0,160) : "none");  } catch {} results.push(["FAIL", name, String(e && e.message || e)]); console.log("FAIL", name, e && e.stack || e); }
}
const assert = (c, m) => { if (!c) throw new Error(m); };

(async () => {
  const main = await serve(null), err = await serve(null), look = await serve(null), nocsp = await serve("frame-src 'none'");
  const port = s => s.address().port;
  const ext = makeExtension({ err: port(err), look: port(look) });
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-ffprof-"));
  const ctx = await puppeteer.launch({ browser: "firefox", headless: false, userDataDir: profile,
    executablePath: "C:/Program Files/Mozilla Firefox/firefox.exe", defaultViewport: { width: 1100, height: 760 } });
  const extId = await ctx.installExtension(ext);
  console.log("browser", await ctx.version(), "ext", extId);
  const base = s => `http://127.0.0.1:${port(s)}`;
  const pg = await ctx.newPage(); await sleep(1500); globalThis.__pg = pg; pg.on("console", m => { if (m.text().includes("LGKDBG")) console.log(m.text()); });
  const panelBox = () => pg.evaluate(() => {
    const host = [...document.documentElement.children].find(e => e.tagName === "DIV" && e.hasAttribute("popover"));
    if (!host || !host.isConnected) return null;
    const r = host.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, left: r.left, width: r.width, height: r.height };
  });
  const clickIcon = async (selector, fieldSel) => {
    await pg.waitForSelector(selector, { timeout: 8000, state: "attached" });
    const icons = await pg.$$(selector);
    const field = await pg.$(fieldSel); const fb = await field.boundingBox();
    let best = null, bd = 1e9;
    for (const i of icons) { const b = await i.boundingBox(); if (!b) continue; const d = Math.abs(b.y - fb.y); if (d < bd) { bd = d; best = b; } }
    assert(best, "icon has no box");
    await pg.mouse.click(best.x + best.width / 2, best.y + best.height / 2);
  };
  const goto = async url => { await pg.goto(url); await sleep(700); };
  const ARM = +(process.env.ARM||900);


  const iv = sel => pg.$eval(sel, e => e.value);
  const waitBox = async (t = 5000) => { const end = Date.now() + t; while (Date.now() < end) { const b = await panelBox(); if (b && b.height > 0) { await sleep(ARM); return b; } await sleep(100); } throw new Error("no panel"); };
  const fallback = () => pg.evaluate(() => window.find("#1") || window.find("Card 1"));
  const at = (b, dy) => pg.mouse.click(b.left + 150, b.top + dy);
  const shot = n => pg.screenshot({ path: n + ".png" });
  await check("login picker: frame, mouse fill, window.find false", async () => {
    await goto(base(main) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password");
    const b = await waitBox(); assert(!(await fallback()), "fallback #1 shown");
    assert(await pg.evaluate(u => window.find(u), USER) === false, "window.find found username");
    await at(b, 122); await sleep(700);
    assert(await iv("#password") === PASS && await iv("#user") === USER, "not filled"); return `height ${b.height}`;
  });
  await check("login picker keyboard: Escape closes; ArrowDown Enter fills", async () => {
    await goto(base(main) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password");
    await waitBox(); await pg.keyboard.press("Escape"); await sleep(400);
    assert(await panelBox() === null, "Escape did not close");
    await clickIcon("[data-localvault-field-icon]", "#password"); await waitBox();
    await pg.keyboard.press("ArrowDown"); await sleep(150); await shot("kbd");
    await pg.keyboard.press("Enter"); await sleep(700);
    const u = await iv("#user"); assert(await iv("#password") === PASS, "Enter did not fill"); return "filled " + u;
  });
  await check("bottom: opens above the field", async () => {
    await goto(base(main) + "/bottom"); await clickIcon("[data-localvault-field-icon]", "#password");
    const b = await waitBox(); const fb = await (await pg.$("#password")).boundingBox();
    assert(b.bottom <= fb.y + 1, `panel ${b.bottom} field ${fb.y}`);
  });
  await check("sign-up generate panel", async () => {
    await goto(base(main) + "/signup"); await clickIcon("[data-localgatekeys-generate-icon]", "#np1");
    await waitBox(); await shot("gen");
  });
  await check("otp picker mouse", async () => {
    await goto(base(main) + "/otp"); await clickIcon("[data-localgatekeys-otp-icon]", "#otp");
    const b = await waitBox(); assert(!(await fallback()), "fallback"); await at(b, 122); await sleep(600);
    assert(await iv("#otp") === "123456", "otp not filled");
  });
  await check("card picker", async () => {
    await goto(base(main) + "/card"); await clickIcon("[data-localgatekeys-card-icon]", "#ccnum");
    const b = await waitBox(); assert(!(await fallback()), "Card 1 fallback");
    assert(await pg.evaluate(() => window.find("Holiday Visa")) === false, "find card title");
    await at(b, 122); await sleep(900); await waitBox(); await shot("cardfields");
  });
  await check("identity picker", async () => {
    await goto(base(main) + "/identity"); await clickIcon("[data-localgatekeys-identity-icon]", "#name");
    await waitBox(); assert(await pg.evaluate(() => window.find("Home identity")) === false, "find identity");
    await pg.keyboard.press("ArrowDown"); await sleep(150); await pg.keyboard.press("Enter"); await sleep(900); await waitBox(); await shot("idfields");
  });
  await check("error panel", async () => { await goto(base(err) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password"); await waitBox(); await shot("err"); });
  await check("save prompt", async () => {
    await goto(base(main) + "/login"); await pg.click("#user"); await pg.keyboard.type("carol.e2e@test.example");
    await pg.click("#password"); await pg.keyboard.type("Typed-Only-Test-1!"); await pg.click("#go");
    await pg.waitForFunction(() => location.pathname === "/done"); await sleep(1500);
    await waitBox(8000); assert(await pg.evaluate(() => window.find("carol.e2e")) === false, "find username"); await shot("save");
  });
  await check("lookalike guard", async () => {
    await goto(base(look) + "/login"); await pg.click("#user"); await pg.keyboard.type("dave.e2e@test.example");
    await pg.click("#password"); await pg.keyboard.type("Typed-Only-Test-2!"); await pg.click("#go"); await sleep(2500);
    await waitBox(8000); assert(await pg.evaluate(() => window.find("example.com")) === false, "find host"); await shot("look");
  });
  await check("faded host refuses click", async () => {
    await goto(base(main) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password"); const b = await waitBox();
    await pg.evaluate(() => { const h = [...document.documentElement.children].find(e => e.tagName === "DIV" && e.hasAttribute("popover")); h.style.setProperty("opacity", "0.1", "important"); });
    await sleep(200); await at(b, 122); await sleep(800); assert(await iv("#password") === "", "filled despite fade");
    await pg.evaluate(() => { const h = [...document.documentElement.children].find(e => e.tagName === "DIV" && e.hasAttribute("popover")); h && h.style.removeProperty("opacity"); }); await shot("fade");
  });
  await check("covered host refuses click", async () => {
    await goto(base(main) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password"); const b = await waitBox();
    await pg.evaluate(b => { const d = document.createElement("div"); d.style.cssText = `position:fixed;inset:auto;margin:0;left:${b.left}px;top:${b.top}px;width:${b.width}px;height:${b.height}px;background:rgba(255,255,255,.02);z-index:2147483647;pointer-events:none`; d.popover = "manual"; document.body.append(d); d.showPopover(); }, b);
    await sleep(300); await at(b, 122); await sleep(800); assert(await iv("#password") === "", "filled despite cover"); await shot("cover");
  });
  // Design decision 2026-11-12: a cover popover in a closed shadow root, and a far popover whose ::backdrop paints.
  await check("closed-root cover refuses click", async () => {
    await goto(base(main) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password"); const b = await waitBox();
    await pg.evaluate(b => { const h = document.createElement("div"); document.body.append(h); const r = h.attachShadow({ mode: "closed" }); const d = document.createElement("div"); d.style.cssText = `position:fixed;inset:auto;margin:0;left:${b.left}px;top:${b.top}px;width:${b.width}px;height:${b.height}px;background:rgba(255,255,255,.02);pointer-events:none`; d.popover = "manual"; r.append(d); d.showPopover(); }, b);
    await sleep(300); await at(b, 122); await sleep(800); assert(await iv("#password") === "", "filled despite closed-root cover"); await shot("closed-cover");
  });
  await check("backdrop cover refuses click", async () => {
    await goto(base(main) + "/login"); await clickIcon("[data-localvault-field-icon]", "#password"); const b = await waitBox();
    await pg.evaluate(() => { const s = document.createElement("style"); s.textContent = "#far::backdrop{background:rgba(255,255,255,.02)}"; document.head.append(s); const d = document.createElement("div"); d.id = "far"; d.style.cssText = "position:fixed;inset:auto;margin:0;left:0;top:0;width:4px;height:4px;pointer-events:none"; d.popover = "manual"; document.body.append(d); d.showPopover(); });
    await sleep(300); await at(b, 122); await sleep(800); assert(await iv("#password") === "", "filled despite backdrop cover"); await shot("backdrop-cover");
  });
  await ctx.close(); for (const s of [main, err, look, nocsp]) s.close();
  fs.rmSync(profile, { recursive: true, force: true }); fs.rmSync(ext, { recursive: true, force: true });
  console.log(results.filter(r => r[0] === "PASS").length + "/" + results.length + " passed");
})();
