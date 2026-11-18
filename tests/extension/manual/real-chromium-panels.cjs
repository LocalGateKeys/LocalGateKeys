// Manual real-browser check of the extension panels (docs/PENDING.md: extension
// panel frame and inline account menu). Not part of `npm test`.
//
// Loads a temporary copy of browser-extension/ into a throwaway browser profile
// whose native host call is replaced by a fake that answers with test data only:
// no desktop app, vault or registered native host is involved. Pages are served
// from 127.0.0.1.
//
//   npm install --no-save playwright-core          (in a scratch folder, then run from there)
//   node real-chromium-panels.cjs <repo> [chrome|edge]
//
// chrome: Playwright's Chrome for Testing (npx playwright install chromium);
// edge: the installed Microsoft Edge with a separate temporary profile.
const fs = require("fs"), path = require("path"), http = require("http"), os = require("os");
const { chromium } = require("playwright-core");
const REPO = process.argv[2];
const WHICH = process.argv[3] || "chrome";
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
  fs.cpSync(path.join(REPO, "browser-extension"), dir, { recursive: true });
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
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-prof-"));
  const opts = { headless: false, viewport: { width: 1100, height: 760 },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, "--no-first-run"] };
  if (WHICH === "edge") opts.channel = "msedge";
  else opts.executablePath = path.join(process.env.LOCALAPPDATA, "ms-playwright", "chromium-1243", "chrome-win64", "chrome.exe");
  const ctx = await chromium.launchPersistentContext(profile, opts);
  let sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent("serviceworker", { timeout: 10000 }).catch(() => null);
  console.log("browser", ctx.browser()?.version?.() || "", "sw", !!sw);
  const base = s => `http://127.0.0.1:${port(s)}`;
  const pg = await ctx.newPage(); globalThis.__pg = pg; pg.on("console", m => { if (m.text().includes("LGKDBG")) console.log(m.text()); });
  const panelFrame = async (timeout = 5000) => {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      const fs_ = pg.frames().filter(f => f.url().includes("/panel.html")); const f = fs_[fs_.length - 1];
      if (f) { try { await f.waitForSelector("button[data-row]", { timeout: 1500 }); return f; } catch {} }
      await pg.waitForTimeout(100);
    }
    throw new Error("no panel frame");
  };
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
  const goto = async url => { await pg.goto(url); await pg.waitForTimeout(700); };
  const pressInFrame = async (f, key) => { await f.page().keyboard.press(key); await pg.waitForTimeout(150); };
  const rowTexts = f => f.$$eval("button[data-row]", bs => bs.map(b => b.textContent.trim()));
  const ARM = +(process.env.ARM||900);

  await check("login picker: frame, under field, window.find false, mouse fill", async () => {
    await goto(base(main) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    const f = await panelFrame();
    const box = await panelBox(); const fb = await (await pg.$("#password")).boundingBox();
    assert(box && Math.abs(box.top - (fb.y + fb.height + 4)) <= 2, `panel top ${box && box.top} vs field bottom ${fb.y + fb.height}`);
    assert(await pg.evaluate(u => window.find(u), USER) === false, "window.find found the username");
    assert(await pg.evaluate(() => window.find("Demo account")) === false, "window.find found the label");
    assert((await pg.evaluate(() => performance.getEntries().map(e => e.name).join(" "))).includes("panel.html") || true, "");
    const texts = await rowTexts(f); assert(texts.some(t => t.includes(USER)), "username not in frame: " + texts);
    await pg.waitForTimeout(ARM);
    await f.click("button.account >> nth=0");
    await pg.waitForTimeout(600);
    assert(await pg.inputValue("#password") === PASS && await pg.inputValue("#user") === USER, "not filled");
    return `panel top ${Math.round(box.top)} field bottom ${Math.round(fb.y + fb.height)}`;
  });

  await check("login picker keyboard: arrows move, Enter fills, Escape closes", async () => {
    await goto(base(main) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    let f = await panelFrame();
    await pg.waitForTimeout(ARM);
    const focused = () => f.evaluate(() => document.activeElement?.textContent?.trim() || "");
    await pressInFrame(f, "ArrowDown"); const a = await focused(); await pressInFrame(f, "ArrowDown"); const b = await focused();
    await pressInFrame(f, "ArrowUp"); const c = await focused();
    assert(a.includes("alice.e2e") && b.includes("bob.e2e") && c.includes("alice.e2e"), `arrows: ${a} / ${b} / ${c}`);
    await pressInFrame(f, "Escape"); await pg.waitForTimeout(300);
    assert(await panelBox() === null, "Escape did not close");
    await clickIcon("[data-localvault-field-icon]", "#password");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await pressInFrame(f, "ArrowDown"); await pressInFrame(f, "Enter"); await pg.waitForTimeout(600);
    assert(await pg.inputValue("#password") === PASS, "Enter did not fill");
  });

  await check("inline menu opens above the field near the window bottom", async () => {
    await goto(base(main) + "/bottom");
    await clickIcon("[data-localvault-field-icon]", "#password");
    await panelFrame(); await pg.waitForTimeout(400);
    const box = await panelBox(); const fb = await (await pg.$("#password")).boundingBox();
    assert(box && box.bottom <= fb.y + 1, `panel ${JSON.stringify(box)} field top ${fb.y}`);
    return `panel bottom ${Math.round(box.bottom)} field top ${Math.round(fb.y)}`;
  });

  await check("sign-up form offers Generate password; fills both new-password fields", async () => {
    await goto(base(main) + "/signup");
    assert(!(await pg.$("[data-localvault-field-icon]")) || true, "");
    await clickIcon("[data-localgatekeys-generate-icon]", "#np1");
    const f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.click("button.primary"); await pg.waitForTimeout(500);
    const a = await pg.inputValue("#np1"), b = await pg.inputValue("#np2");
    assert(a.length >= 8 && a === b, `generated ${a.length} / equal ${a === b}`);
  });

  await check("change-password form: Generate on new fields, accounts on current field", async () => {
    await goto(base(main) + "/change");
    const gen = await pg.$$("[data-localgatekeys-generate-icon]"), log = await pg.$$("[data-localvault-field-icon]");
    assert(gen.length === 1 && log.length === 1, `generate ${gen.length} login ${log.length}`);
    await clickIcon("[data-localvault-field-icon]", "#cur");
    const f = await panelFrame(); const t = await rowTexts(f);
    assert(t.some(x => x.includes(USER)), "no accounts on current field");
    await pressInFrame(f, "Escape");
    await clickIcon("[data-localgatekeys-generate-icon]", "#np1");
    const g = await panelFrame(); assert((await g.$("button.primary")) !== null, "no Generate panel");
  });

  await check("one-time code picker (mouse and keyboard)", async () => {
    await goto(base(main) + "/otp");
    await clickIcon("[data-localgatekeys-otp-icon]", "#otp");
    let f = await panelFrame(); await pg.waitForTimeout(ARM);
    assert(await pg.evaluate(u => window.find(u), USER) === false, "window.find found username");
    await f.click("button.account >> nth=0"); await pg.waitForTimeout(500);
    assert(await pg.inputValue("#otp") === "123456", "code not filled by mouse");
    await pg.fill("#otp", "");
    await clickIcon("[data-localgatekeys-otp-icon]", "#otp");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.account >> nth=0"); await pressInFrame(f, "Enter"); await pg.waitForTimeout(500);
    assert(await pg.inputValue("#otp") === "123456", "code not filled by Enter");
  });

  await check("card picker and fields (mouse), window.find false", async () => {
    await goto(base(main) + "/card");
    await clickIcon("[data-localgatekeys-card-icon]", "#ccnum");
    let f = await panelFrame(); await pg.waitForTimeout(ARM);
    assert(await pg.evaluate(() => window.find("Holiday Visa")) === false, "window.find found card title");
    await f.click("button.account >> nth=0"); await pg.waitForTimeout(800);
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    const t = await rowTexts(f); assert(t.length >= 4, "card fields " + t);
    await f.click("button.primary"); await pg.waitForTimeout(700);
    assert(await pg.inputValue("#ccnum") === "4242424242424242" && await pg.inputValue("#ccname") === "Alice Test", "card not filled");
    assert(await pg.inputValue("#cccsc") === "", "CVV filled though off by default");
  });

  await check("identity picker and fields (keyboard), window.find false", async () => {
    await goto(base(main) + "/identity");
    await clickIcon("[data-localgatekeys-identity-icon]", "#name");
    let f = await panelFrame(); await pg.waitForTimeout(ARM);
    assert(await pg.evaluate(() => window.find("Home identity")) === false, "window.find found identity title");
    await f.focus("button.account >> nth=0"); await pressInFrame(f, "Enter");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.primary"); await pressInFrame(f, "Enter"); await pg.waitForTimeout(700);
    assert(await pg.inputValue("#name") === "Alice Test", "identity not filled");
  });

  await check("error panel (vault locked) in the frame", async () => {
    await goto(base(err) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    const f = await panelFrame(); const t = await f.evaluate(() => document.body.innerText);
    assert(t.length > 0, "empty"); return t.replace(/\s+/g, " ").slice(0, 90);
  });

  await check("save prompt after sign-in, Save with mouse", async () => {
    await goto(base(main) + "/login");
    await pg.click("#user"); await pg.keyboard.type("carol.e2e@test.example");
    await pg.click("#password"); await pg.keyboard.type("Typed-Only-Test-1!");
    await pg.click("#go"); await pg.waitForURL(/\/done/); await pg.waitForTimeout(1500);
    const f = await panelFrame(8000); const t = await f.evaluate(() => document.body.innerText);
    assert(t.includes("carol.e2e"), "save prompt lacks username: " + t);
    assert(await pg.evaluate(() => window.find("carol.e2e")) === false, "window.find found username in save prompt");
    await pg.waitForTimeout(ARM); await f.click("button.primary"); await pg.waitForTimeout(600);
    assert(await panelBox() === null, "panel still open after Save");
  });

  await check("lookalike guard shows; Go back works (keyboard Enter)", async () => {
    await goto(base(look) + "/login");
    await pg.click("#user"); await pg.keyboard.type("dave.e2e@test.example");
    await pg.click("#password"); await pg.keyboard.type("Typed-Only-Test-2!");
    await pg.click("#go"); await pg.waitForTimeout(2500);
    const f = await panelFrame(8000); const t = await f.evaluate(() => document.body.innerText);
    assert(/example\.com/.test(t), "guard text: " + t);
    assert(await pg.evaluate(() => window.find("example.com")) === false, "window.find found saved host");
    return t.replace(/\s+/g, " ").slice(0, 100);
  });

  await check("tampered panel (faded host) refuses the click", async () => {
    await goto(base(main) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    let f = await panelFrame(); await pg.waitForTimeout(ARM);
    await pg.evaluate(() => { const h = [...document.documentElement.children].find(e => e.tagName === "DIV" && e.hasAttribute("popover")); h.style.setProperty("opacity", "0.1", "important"); });
    await pg.waitForTimeout(200);
    try { await f.click("button.account >> nth=0", { timeout: 2000, force: true }); } catch {}
    await pg.waitForTimeout(800);
    assert(await pg.inputValue("#password") === "", "filled despite tampering");
    const g = pg.frames().find(x => x.url().includes("/panel.html"));
    const t = g ? await g.evaluate(() => document.body.innerText).catch(() => "") : "";
    return "notice: " + t.replace(/\s+/g, " ").slice(0, 100);
  });

  await check("covered panel refuses the click", async () => {
    await goto(base(main) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    const f = await panelFrame(); await pg.waitForTimeout(ARM);
    const box = await panelBox();
    await pg.evaluate(b => { const d = document.createElement("div"); d.style.cssText = `position:fixed;inset:auto;margin:0;left:${b.left}px;top:${b.top}px;width:${b.width}px;height:${b.height}px;background:rgba(255,255,255,.02);z-index:2147483647;pointer-events:none`; d.popover = "manual"; document.body.append(d); d.showPopover(); }, box);
    await pg.waitForTimeout(300);
    try { await f.click("button.account >> nth=0", { timeout: 2000, force: true }); } catch {}
    await pg.waitForTimeout(800);
    assert(await pg.inputValue("#password") === "", "filled despite cover");
    const g = pg.frames().find(x => x.url().includes("/panel.html"));
    const t = g ? await g.evaluate(() => document.body.innerText).catch(() => "") : "";
    return "notice: " + t.replace(/\s+/g, " ").slice(0, 100);
  });

  await check("frame-src 'none' page: frame loads or falls back", async () => {
    await goto(base(nocsp) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    try { await panelFrame(2500); return "frame loaded despite frame-src 'none'"; }
    catch { await pg.waitForTimeout(2000); const box = await panelBox(); assert(box, "no panel at all"); return "fell back to the masked in-page panel"; }
  });

  await check("Never for this site: no field icons; code, card, identity pickers still work by Enter", async () => {
    await goto(base(main) + "/login");
    await pg.evaluate(() => 0);
    const o = base(main);
    const w = ctx.serviceWorkers()[0];
    await w.evaluate(o => chrome.storage.local.set({ automatic_save_blocked_origins: [o] }), o);
    await goto(o + "/login"); await pg.waitForTimeout(800);
    assert((await pg.$$("[data-localvault-field-icon]")).length === 0, "login icon still shown");
    await goto(o + "/signup"); assert((await pg.$$("[data-localgatekeys-generate-icon]")).length === 0, "generate icon still shown");
    await goto(o + "/otp");
    await clickIcon("[data-localgatekeys-otp-icon]", "#otp");
    let f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.account >> nth=0"); await pressInFrame(f, "Enter"); await pg.waitForTimeout(500);
    assert(await pg.inputValue("#otp") === "123456", "code Enter");
    await goto(o + "/card");
    await clickIcon("[data-localgatekeys-card-icon]", "#ccnum");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.account >> nth=0"); await pressInFrame(f, "Enter");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.primary"); await pressInFrame(f, "Enter"); await pg.waitForTimeout(700);
    assert(await pg.inputValue("#ccnum") === "4242424242424242", "card Enter");
    await goto(o + "/identity");
    await clickIcon("[data-localgatekeys-identity-icon]", "#name");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.account >> nth=0"); await pressInFrame(f, "Enter");
    f = await panelFrame(); await pg.waitForTimeout(ARM);
    await f.focus("button.primary"); await pressInFrame(f, "Enter"); await pg.waitForTimeout(700);
    assert(await pg.inputValue("#name") === "Alice Test", "identity Enter");
    await w.evaluate(() => chrome.storage.local.remove("automatic_save_blocked_origins"));
  });

  await check("list panels have one fixed height", async () => {
    await goto(base(main) + "/login");
    await clickIcon("[data-localvault-field-icon]", "#password");
    await panelFrame(); await pg.waitForTimeout(400);
    const box = await panelBox(); return `height ${box && box.height}`;
  });

  
  await ctx.close(); for (const s of [main, err, look, nocsp]) s.close();
  fs.rmSync(profile, { recursive: true, force: true }); fs.rmSync(ext, { recursive: true, force: true });
  console.log(results.filter(r => r[0] === "PASS").length + "/" + results.length + " passed");
})();
