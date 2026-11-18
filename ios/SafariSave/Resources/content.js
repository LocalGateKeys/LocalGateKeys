"use strict";
(() => {
  // Re-injection guard. A Symbol key, not a string property: a page element
  // with a matching id/name is reachable through named property access on
  // window (DOM clobbering) and must not switch the script off.
  const LOADED=Symbol.for("localgatekeys.content.loaded");
  if (globalThis[LOADED] === true) return;
  // Runs in the top frame and in iframes whose entire ancestor chain shares
  // this document's origin. A cross-origin ancestor anywhere in the chain
  // disables the script: the service worker enforces the same rule from the
  // browser-provided frame tree, so this is a UX guard, not the boundary.
  function sameOriginAncestry(){
    try{
      for(let w=window;w!==window.top;w=w.parent){
        if(w.parent.location.origin!==location.origin)return false;
      }
      return true;
    }catch{return false;}
  }
  if (!sameOriginAncestry()) return;
  // An opaque-origin document (sandboxed iframe or a CSP-sandboxed page) has
  // the site's URL, so location.origin names the site, but it is not the site:
  // self.origin is "null" there. No fill, save or picker in such a document.
  if (self.origin !== location.origin) return;
  const S=typeof globalThis.LGKLoginSafety?.snapshot==="function"?globalThis.LGKLoginSafety:null;
  const H=typeof globalThis.LGKHeuristics?.isSignInLabel==="function"?globalThis.LGKHeuristics:null;
  if (!S || !H) return;
  Object.defineProperty(globalThis,LOADED,{value:true});
  const icons=new Map(), generateIcons=new Map();
  // Run function of each row of the shown panel (mouse and keyboard share it).
  let rowRuns=new WeakMap();
  // Sites where the user chose "Never for this site": no inline menu there.
  let inlineBlocked=false;
  const identityIcons=new Map();
  const otpIcons=new Map();
  let otpActive=null;
  let generation=0, active=null, identityActive=null, panelHost=null, panelShadow=null, statusTimer=null;
  let recentFilledCredential=null;
  const pageStartedAt=Date.now();
  const newId=()=>crypto.randomUUID();
  // Random per-document key, drawn once when this document's script loads.
  // Firefox and Safari give the background no documentId: this key binds
  // nonces and pending captures to this document there (Chromium uses its own).
  const documentKey=crypto.randomUUID().replace(/-/g,"");
  const origin=()=>location.origin;
  // Page URL for multi-URL matching (starts_with rows): no fragment, never
  // credentials. The service worker re-derives the origin and drops any url
  // that does not belong to the sender before forwarding it.
  function pageUrl(){
    try{const u=new URL(location.href);u.hash="";u.username="";u.password="";return u.href.length<=4096?u.href:undefined;}
    catch{return undefined;}
  }
  let cardActive=null;
  const cardIcons=new Map();
  let automaticSaveEnabled=false;
  let logoutInProgress=false;
  // Phishing-shield state (see loadVerdict below).
  const VERDICT_KINDS=new Set(["exact","related","lookalike","unknown"]);
  const VERDICT_LABELS={exact:()=>tr("site_verified"),related:()=>tr("site_related"),lookalike:()=>tr("site_lookalike"),unknown:()=>tr("site_new")};
  const SAME_ACCOUNT_KEY="lookalike_same_account_pairs";
  let siteVerdict=null, verdictAt=0, verdictRequest=null, verdictAskedAt=-Infinity, guardConfirmed=false, guardOpen=false;
  // ---- Capability switch. The iPhone Safari background (background-safari.js)
  // answers status with features:{fill:false}: no fill icons, pickers or
  // generator there, only the save prompt. Replies without `features` (the
  // desktop extensions never send it) leave filling as it is.
  let fillEnabled=true;
  function applyFeatures(response){
    const fill=response?.features?.fill;
    if(typeof fill!=="boolean" || fill===fillEnabled)return;
    fillEnabled=fill;syncIcons();
  }
  // Safari on the Mac with AI agents allowed in the app: with filling off, the
  // sign-in field icon stays only to release an agent's sign-in the user
  // approved there (agentFill). Nothing else fills.
  let agentOnly=false;
  function applyAgent(response){
    const on=response?.ok===true && response.agent===true;
    if(on===agentOnly)return;
    agentOnly=on;syncIcons();
  }
  // Only a manifest that loads the Safari background asks for status.
  function safariBackground(){
    try{const scripts=api.runtime.getManifest?.()?.background?.scripts;return Array.isArray(scripts) && scripts.includes("background-safari.js");}
    catch{return false;}
  }
  // Optional message from the background shown in the save panel (Safari:
  // "saved" and "vault full"). The desktop never sends one.
  function noticeOf(response){const n=response?.notice;return typeof n==="string" && !!n.trim() && n.length<=500?n:"";}
  // What the save panel may know about a captured login: new or exists, never
  // whether its password matches (audit M-3). A desktop app from before that
  // change still answers "exact" / "password_changed"; both are shown as the
  // same neutral "exists" prompt, so a page sees identical DOM for a right and
  // a wrong password guess. The desktop app compares after the Save click.
  function saveStatus(status){return status==="exact"||status==="password_changed"?"exists":status;}
  // ---- Broker gesture nonces. begin_browser / begin_totp_browser /
  // begin_gesture_browser mint a single-use nonce (32 hex) that lives
  // gesture_expires_in (30 s) seconds and is bound to this origin + document
  // + operation. It is kept only on the operation object, never past its
  // expiry, and presented once with the follow-up request.
  const GESTURE_NONCE_TTL_MS=30000, GESTURE_WINDOW_MS=5000, NONCE_PATTERN=/^[0-9a-f]{32}$/;
  let lastGestureAt=0;
  function noteGesture(){lastGestureAt=Date.now();}
  // A trusted click handled moments ago counts as a gesture still in flight.
  function gestureInFlight(){return Date.now()-lastGestureAt<GESTURE_WINDOW_MS;}
  function rememberNonce(op,response){
    const nonce=response?.gesture_nonce;
    if(typeof nonce==="string" && NONCE_PATTERN.test(nonce)){
      const seconds=Number(response.gesture_expires_in);
      const ttl=Number.isFinite(seconds)&&seconds>0?Math.min(seconds*1000,GESTURE_NONCE_TTL_MS):GESTURE_NONCE_TTL_MS;
      op.nonce=nonce;op.nonceExpiresAt=Date.now()+ttl;
    } else {op.nonce=null;op.nonceExpiresAt=0;}
  }
  function takeNonce(op){
    const nonce=op.nonce && Date.now()<op.nonceExpiresAt ? op.nonce : null;
    op.nonce=null;op.nonceExpiresAt=0;
    return nonce;
  }
  async function mintNonce(op){
    const fresh=await msg("begin_gesture_browser",{user_gesture:true},op);
    if(!fresh.ok)return null;
    rememberNonce(op,fresh);
    return takeNonce(op);
  }
  // Send a gesture-gated action with proof: the nonce minted at the original
  // click, or a fresh one when that nonce aged out and the user has just
  // clicked again. After gesture_nonce_invalid/required one retry is made,
  // only while a real gesture is still in flight; otherwise the broker's
  // "click again" message is shown by the caller.
  async function gestured(action,payload,op,stillValid=()=>true){
    let nonce=takeNonce(op);
    if(!nonce && gestureInFlight()){nonce=await mintNonce(op);if(!stillValid())return {ok:false,error:"destination_changed",message:tr("content_page_changed_click_again")};}
    let response=await msg(action,{...payload,user_gesture:true,...(nonce?{gesture_nonce:nonce}:{})},op);
    if((response.error==="gesture_nonce_invalid" || response.error==="gesture_nonce_required") && gestureInFlight() && stillValid()){
      nonce=await mintNonce(op);
      if(nonce && stillValid()) response=await msg(action,{...payload,user_gesture:true,gesture_nonce:nonce},op);
    }
    return response;
  }
  // Sites where the user turned the save prompt off; all others ask by default.
  const automaticOriginKey="automatic_save_blocked_origins";
  // Sites where the user chose "Always use the toolbar popup": no inline
  // icons or menus there (the popup is browser UI a page cannot cover).
  const popupOnlyKey="popup_only_origins";
  let popupOnly=false;
  // Popup-only also covers the automatic panels (save prompt, password update,
  // passkey note): none is drawn into this site's pages and no capture is kept
  // for one (finding W-L15). The popup's own Save and fill still work.
  function updateInline(){
    const blocked=!automaticSaveEnabled || popupOnly;
    if(popupOnly){clearTimeout(pendingTimer);pendingAttempt=null;lastPromptToken=null;}
    if(inlineBlocked!==blocked){inlineBlocked=blocked;if(popupOnly)hidePanel();syncIcons();}
  }
  function automaticPanels(){return automaticSaveEnabled && !popupOnly;}
  function applyPopupOnlySetting(origins){popupOnly=Array.isArray(origins) && origins.includes(origin());updateInline();}
  function applyAutomaticSaveSetting(origins){
    const enabled=!(Array.isArray(origins) && origins.includes(origin()));
    automaticSaveEnabled=enabled;
    updateInline();
    if(!enabled){
      clearTimeout(pendingTimer);
      pendingAttempt=null;
      lastPromptToken=null;
      hidePanel();
    }
  }
  async function loadAutomaticSaveSetting(){
    try{
      const result=await api.storage.local.get({[automaticOriginKey]:[],[popupOnlyKey]:[]});
      popupOnly=Array.isArray(result[popupOnlyKey]) && result[popupOnlyKey].includes(origin());
      applyAutomaticSaveSetting(result[automaticOriginKey]);
    }catch{automaticSaveEnabled=false;}
  }
  api.storage.onChanged.addListener((changes,area)=>{
    if(area==="local" && changes[automaticOriginKey])applyAutomaticSaveSetting(changes[automaticOriginKey].newValue);
    if(area==="local" && changes[popupOnlyKey])applyPopupOnlySetting(changes[popupOnlyKey].newValue);
  });
  // App logo (the 48 px toolbar icon) for the in-page panel header.
  const PANEL_MARK="data:image/png;base64,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";
  const styles=`
    :host{all:initial;}
    .panel{--bg:#FFFFFF;--ws:#F5F7FB;--line:#E3E8F0;--line2:#CDD5E1;--ink:#16202E;--muted:#5B6678;--acc:#1F5BE8;--acc-h:#1749C4;--acc-p:#123A9C;--soft:#EAF1FF;--warn:#9A6200;--shadow:0 12px 32px rgba(16,32,64,.16),0 2px 6px rgba(16,32,64,.08);color-scheme:light;box-sizing:border-box;width:100%;max-height:400px;overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:14px;color:var(--ink);font:13px/1.5 "Segoe UI Variable Text","Segoe UI Variable","Segoe UI",system-ui,sans-serif;box-shadow:var(--shadow);padding:14px;}
    @media (prefers-color-scheme:dark){.panel{--bg:#0F1A2B;--ws:#0A1322;--line:#22324A;--line2:#2F4361;--ink:#EAF0FA;--muted:#9AA9BF;--acc:#1F5BE8;--acc-h:#3A72F0;--acc-p:#1749C4;--soft:#16294A;--warn:#E0B65C;--shadow:0 16px 40px rgba(0,0,0,.5),0 2px 6px rgba(0,0,0,.3);color-scheme:dark;}}
    .panel.list{height:100%;max-height:none;} .hidden{display:none;}
    .gen{display:grid;gap:8px;margin:10px 0 12px;} .gen-out{display:flex;gap:6px;align-items:center;}
    .gen-value{flex:1;min-width:0;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--ws);color:var(--ink);font:13px/1.35 Consolas,"Cascadia Mono",monospace;overflow-wrap:anywhere;user-select:all;}
    .gen .gen-again{all:unset;box-sizing:border-box;width:36px;height:36px;display:grid;place-items:center;border:1px solid var(--line2);border-radius:10px;cursor:pointer;color:var(--acc);background:var(--bg);font-size:16px;}
    .gen .gen-again:hover,.gen .gen-again:focus-visible{background:var(--soft);border-color:var(--acc);}
    .gen-len{display:flex;align-items:center;gap:8px;color:var(--muted);} .gen-len input{flex:1;accent-color:var(--acc);} .gen-len b{min-width:22px;text-align:right;color:var(--ink);}
    .gen-checks{display:flex;flex-wrap:wrap;gap:4px 12px;color:var(--muted);} .gen-checks input{accent-color:var(--acc);margin:0 2px 0 0;}
    h3{display:flex;align-items:center;gap:8px;font-size:14px;font-weight:600;margin:0 0 8px;color:var(--ink);} h3::before{content:"";flex:0 0 auto;width:22px;height:22px;border-radius:6px;background:var(--mark) center/contain no-repeat;}
    .origin{display:inline-block;max-width:100%;box-sizing:border-box;font-size:11px;line-height:1.4;color:var(--muted);background:var(--ws);border:1px solid var(--line);border-radius:999px;padding:2px 9px;overflow-wrap:anywhere;} .origin:empty{display:none;}
    p{margin:8px 0 12px;color:var(--muted);overflow-wrap:anywhere;} p:empty{display:none;}
    button{font:inherit;font-weight:600;min-height:36px;border:1px solid var(--line2);border-radius:10px;background:var(--bg);color:var(--ink);padding:7px 14px;cursor:pointer;margin:4px 6px 0 0;transition:background .12s,border-color .12s;} button:hover{background:var(--soft);border-color:var(--acc);} button:active{background:var(--soft);} button:focus-visible{outline:2px solid var(--acc);outline-offset:2px;}
    .primary{min-height:40px;background:var(--acc);border-color:var(--acc);color:#fff;} .primary:hover{background:var(--acc-h);border-color:var(--acc-h);} .primary:active{background:var(--acc-p);border-color:var(--acc-p);}
    .account{display:block;box-sizing:border-box;width:100%;text-align:left;margin:6px 0;font-weight:500;border-color:var(--line);border-radius:12px;padding:8px 12px;} .account:hover{background:var(--soft);border-color:var(--acc);} .account span{display:block;overflow-wrap:anywhere;} .secondary{font-size:11px;font-weight:400;color:var(--muted);} .match{color:var(--warn);} .account.has-logo{display:flex;align-items:center;gap:10px;} .account .logo{display:grid;place-items:center;flex:0 0 auto;width:28px;height:28px;border-radius:8px;} .logo svg{width:16px;height:16px;display:block;} .account .text{flex:1;min-width:0;} .account:has(.fill-pill){display:flex;align-items:center;gap:10px;} .account .fill-pill{display:inline-flex;align-items:center;flex:0 0 auto;height:28px;box-sizing:border-box;padding:0 12px;border-radius:8px;background:#1F5BE8;color:#fff;font-size:12px;font-weight:600;overflow-wrap:normal;white-space:nowrap;} .account:hover .fill-pill{background:#1749C4;} @media (prefers-color-scheme:dark){.account .fill-pill{background:#4C7DFF;color:#fff;} .account:hover .fill-pill{background:#3A68E0;}}
    .check{display:flex;align-items:center;gap:8px;} .check .tick{display:inline-grid;place-items:center;width:16px;height:16px;flex:0 0 auto;border:1px solid var(--line2);border-radius:4px;font-size:11px;color:#fff;background:var(--bg);} .check[aria-checked="true"] .tick{background:var(--acc);border-color:var(--acc);} .note{font-size:11px;color:var(--warn);margin:4px 0 0;}
    .panel::-webkit-scrollbar{width:8px}.panel::-webkit-scrollbar-thumb{background:var(--line2);border-radius:8px}.panel::-webkit-scrollbar-track{background:transparent}
  `;
  // ---- In-page UI integrity (clickjacking). The icon and panel hosts are
  // light-DOM elements, so the page can restyle, move, cover or fade them and
  // lure a click onto an invisible LocalGateKeys button. Each host is pinned
  // with !important inline styles, promoted to the top layer where supported
  // (popover="manual", above every non-top-layer page element), and checked
  // again on every click: computed style untouched, size and position as
  // placed, on screen, and the topmost element at the click point. A click
  // that fails any check is refused before anything is requested or shown.
  const placed=new WeakMap();
  const HOST_BASE={position:"fixed",margin:"0",padding:"0",border:"0",background:"transparent",overflow:"visible",
    opacity:"1",visibility:"visible",transform:"none",filter:"none","clip-path":"none",mask:"none","pointer-events":"auto","mix-blend-mode":"normal"};
  function pin(host,props){for(const [name,value] of Object.entries(props))host.style.setProperty(name,value,"important");}
  // The panel host is marked with an attribute whose name is random per page
  // and known only to this closure, so a page cannot select it by a fixed name.
  const PANEL_ATTR="data-"+Array.from(crypto.getRandomValues(new Uint8Array(12)),b=>String.fromCharCode(97+b%26)).join("");
  function uiHost(dataKey,props){
    const host=document.createElement(dataKey===PANEL_ATTR?"div":"span");
    if(dataKey===PANEL_ATTR)host.setAttribute(PANEL_ATTR,"");else host.dataset[dataKey]="true";
    pin(host,{...HOST_BASE,display:"none",...props});
    return host;
  }
  // Top layer: rendered above every page element that is not itself in the
  // top layer, whatever its z-index. Re-raised when shown so that the most
  // recent LocalGateKeys surface is the topmost one.
  function toTopLayer(host,raise=false){
    if(typeof host.showPopover!=="function" || !host.isConnected)return;
    try{
      if(host.getAttribute("popover")!=="manual")host.setAttribute("popover","manual");
      const open=host.matches(":popover-open");
      if(open && raise)host.hidePopover();
      if(!open || raise)host.showPopover();
    }catch{/* no top layer: z-index and the click-time checks still apply */}
  }
  // box: {width, height?, left?, top?, right?, bottom?} in CSS px.
  // When a shown host last moved: clicks within MOVE_GRACE_MS of a move are
  // ignored (a page that slides our panel under the pointer just before a
  // click gets nothing).
  // A new panel screen's own first placement is not a move (the frame's
  // arm delay covers a new screen); later re-placements of it are.
  const movedAt=new WeakMap(), MOVE_GRACE_MS=500, settledViews=new WeakSet();
  let placingFirst=false;
  function place(host,box,raise=false){
    const px=v=>v==null?"auto":`${v}px`;
    const before=placed.get(host);
    if(before && !(host===panelHost && placingFirst) && ["width","height","left","top","right","bottom"].some(k=>(before[k]??null)!==(box[k]??null)))movedAt.set(host,Date.now());
    pin(host,{display:"block",width:px(box.width),height:box.height==null?"auto":px(box.height),left:px(box.left),top:px(box.top),right:px(box.right),bottom:px(box.bottom)});
    placed.set(host,{...box});
    toTopLayer(host,raise);
  }
  function hideHost(host){if(host)host.style.setProperty("display","none","important");}
  function justMoved(host){const at=movedAt.get(host);return at!==undefined && Date.now()-at<MOVE_GRACE_MS;}
  const noEffect=v=>v==null || v==="" || v==="none";
  // Longhands only: a serialised `mask` shorthand is not "none" in every engine.
  function untouched(s){
    return s.visibility==="visible" && Number(s.opacity)>=1 &&
      ["transform","translate","rotate","scale","filter","clipPath","maskImage","webkitMaskImage"].every(k=>noEffect(s[k])) &&
      (noEffect(s.mixBlendMode) || s.mixBlendMode==="normal");
  }
  function ownHosts(){
    const out=new Set(panelHost?[panelHost]:[]);
    for(const map of [icons,generateIcons,otpIcons,cardIcons,identityIcons])for(const {host} of map.values())out.add(host);
    return out;
  }
  // A page element in the top layer (its own popover, modal dialog or
  // fullscreen element) can sit above ours, even with pointer-events:none
  // that elementFromPoint does not see. Also one in a closed shadow root, a
  // ::backdrop that paints over the viewport, and a running view transition
  // (login-safety.js topLayerCover; design decision 2026-11-12).
  function topLayerRival(rect){
    try{return S.topLayerCover(rect,ownHosts());}catch{return true;}
  }
  // Style and geometry as placed (no click point): also checked whenever the
  // panel host's attributes change.
  function hostLayoutIntact(host){
    try{
      const want=placed.get(host);
      if(!want || !host.isConnected || host.parentNode!==document.documentElement)return false;
      const s=getComputedStyle(host);
      if(s.display!=="block" || s.position!=="fixed" || s.pointerEvents==="none" || (s.clip && s.clip!=="auto") || !untouched(s))return false;
      let inTopLayer=false;try{inTopLayer=host.matches(":popover-open");}catch{}
      // Outside the top layer the root element's opacity/filter/etc. apply too.
      if(!inTopLayer && !untouched(getComputedStyle(document.documentElement)))return false;
      const r=host.getBoundingClientRect();
      const near=(a,b)=>Math.abs(a-b)<=1;
      if(!near(r.width,want.width) || (want.height!=null?!near(r.height,want.height):r.height<24))return false;
      if((want.left!=null && !near(r.left,want.left)) || (want.top!=null && !near(r.top,want.top)))return false;
      return true;
    }catch{return false;}
  }
  function hostIntact(host,e){
    try{
      if(!hostLayoutIntact(host))return false;
      const r=host.getBoundingClientRect();
      // Pointer clicks carry the point; keyboard activation (detail 0, no
      // coordinates) is checked at the centre of the host.
      const pointer=e.detail>0 || e.clientX!==0 || e.clientY!==0;
      const x=pointer?e.clientX:r.left+r.width/2, y=pointer?e.clientY:r.top+r.height/2;
      if(x<r.left-1 || x>r.right+1 || y<r.top-1 || y>r.bottom+1 || x<0 || y<0 || x>=innerWidth || y>=innerHeight)return false;
      if(document.elementFromPoint(x,y)!==host)return false;
      // The rest of the host must be uncovered too (a page overlay over part
      // of the panel, or a transparent layer beside the click point): its
      // centre and four points just inside its corners, where on screen. Our
      // own hosts (an icon under the panel's edge) do not count as covers.
      const own=ownHosts(), inset=4;
      for(const [px,py] of [[r.left+r.width/2,r.top+r.height/2],[r.left+inset,r.top+inset],[r.right-inset,r.top+inset],[r.left+inset,r.bottom-inset],[r.right-inset,r.bottom-inset]]){
        if(px<0 || py<0 || px>=innerWidth || py>=innerHeight)continue;
        const hit=document.elementFromPoint(px,py);
        if(hit!==host && !(hit && own.has(hit)))return false;
      }
      return !topLayerRival(r);
    }catch{return false;}
  }
  const TAMPERED=`${tr("content_tampered")} ${tr("content_use_toolbar")}`;
  // Every click on a LocalGateKeys button goes through here: trusted events
  // only, and only while the host is intact. A tampered click cancels every
  // flow in progress; the notice contains no vault data.
  function uiClick(e,host){
    if(!e.isTrusted)return false;
    if(justMoved(host)){e.preventDefault();e.stopPropagation();return false;}
    if(hostIntact(host,e))return true;
    e.preventDefault();e.stopPropagation();
    if(host===panelHost)tampered();else reset(TAMPERED);
    return false;
  }
  // Released values are blanked from memory on every path, including early
  // returns where the page changed while the release was in flight.
  function blankCredential(response){
    const c=response?.credential;
    if(c && typeof c==="object"){c.password="";c.username="";}
  }
  function blankValues(response){
    const values=response?.values;
    if(values && typeof values==="object")for(const key of Object.keys(values))values[key]="";
    if(response && typeof response==="object" && "values" in response)response.values=null;
  }
  function blankCode(response){
    if(response && typeof response==="object"){if("code" in response)response.code="";if("next_code" in response)response.next_code="";}
  }
  function msg(type, payload={}, op=null) {
    const operation_id=op?.id || newId();
    // Promise form only: works for chrome.* (MV3) and Firefox browser.*.
    return Promise.resolve()
      .then(()=>api.runtime.sendMessage({type,origin:origin(),operation_id,document_key:documentKey,...payload}))
      .then(response=>response || {ok:false,error:"connection_lost",message:tr("content_reload_page")})
      .catch(()=>({ok:false,error:"connection_lost",message:tr("content_reload_extension_and_page")}));
  }
  // ---- Panels. Nothing from the vault (usernames, labels, titles, card brand
  // and last four, identity titles, the profile name, saved hosts) is ever
  // put in DOM the page can reach. A closed shadow root is not enough: the
  // page can still search rendered text with window.find(). The panel is
  // therefore drawn in panel.html, an extension page framed into the page
  // (web-accessible, use_dynamic_url on Chromium). The page sees an opaque
  // cross-origin frame; the frame gets its content from this script through
  // the service worker (extension messaging only, never postMessage or the
  // URL) and sends the user's clicks back the same way. Where the frame is not
  // available (a manifest without the web-accessible panel, or, on Safari, a
  // page that keeps the frame from loading) the panel is drawn in the page as
  // before, with every vault string replaced by a neutral placeholder.
  //
  // The panel host is in the document only while the panel is shown: hidden,
  // it is detached (not left in place with display:none), so a page cannot
  // poll a node's style to learn whether a save prompt appeared.
  const PANEL_PAGE="panel.html", FRAME_TIMEOUT_MS=3000, MASK="•••";
  const FRAME_STYLE=':host{all:initial;} iframe{display:block;width:100%;height:100%;margin:0;padding:0;border:0;border-radius:14px;box-shadow:0 12px 32px rgba(16,32,64,.18),0 2px 6px rgba(16,32,64,.08);color-scheme:light dark;background:transparent;} iframe.pending{position:absolute;left:0;top:0;visibility:hidden;}';
  // A string the page must not see, with what the in-page fallback shows instead.
  const secret=(full,safe=MASK)=>({secret:true,full:String(full??""),safe:String(safe??"")});
  const shownText=(value,inFrame)=>value && typeof value==="object" && value.secret===true?(inFrame?value.full:value.safe):String(value??"");
  function frameCapable(){
    try{
      // Safari's build always ships panel.html web-accessible, but Safari's
      // getManifest() can omit web_accessible_resources (seen after an app
      // update): try the frame there; it falls back if the frame never reports.
      if(safariBackground())return typeof api.runtime.getURL==="function";
      const war=api.runtime.getManifest?.()?.web_accessible_resources;
      // Firefox reports the resources with a leading "/" ("/panel.html").
      return typeof api.runtime.getURL==="function" && Array.isArray(war) && war.some(entry=>Array.isArray(entry?.resources) && entry.resources.some(r=>String(r).replace(/^\//,"")===PANEL_PAGE));
    }catch{return false;}
  }
  let frameMode=frameCapable();
  // Chromium and Firefox always draw panels in the extension frame. A frame
  // that does not report there means the page removed or blocked it: that is
  // tampering, never a reason to draw saved-item lists into the page. Safari
  // frames its save prompts too, but a page's CSP may keep its extension
  // frame from loading; its panels hold no saved-item lists (it cannot read
  // the vault), so there the in-page fallback takes over instead.
  const FRAME_REQUIRED=frameMode && !safariBackground();
  // pendingView: built this task, shown at the next microtask (callers add
  // rows after panel() returns). currentView: on screen. uiFrame: the frame
  // that draws currentView (or is loading it).
  let pendingView=null, currentView=null, uiFrame=null;
  const randomHex=bytes=>Array.from(crypto.getRandomValues(new Uint8Array(bytes)),b=>b.toString(16).padStart(2,"0")).join("");
  function panel(title, text, actions=[], target=null, siteOrigin=origin()) {
    const view={title,text,origin:siteOrigin,target,anchor:null,focus:false,generator:null,rows:[],
      add(row){const r={kind:"button",...row,id:`r${this.rows.length}`};this.rows.push(r);return r;},
      checked(){return this.rows.filter(r=>r.kind==="check" && r.checked).map(r=>r.key);}};
    for(const action of actions)view.add({kind:"button",label:action.label,primary:!!action.primary,run:action.run});
    pendingView=view;
    queueMicrotask(()=>{if(pendingView===view){pendingView=null;showView(view);}});
    return view;
  }
  function ensurePanelHost(){
    if (!panelHost) {
      panelHost=uiHost(PANEL_ATTR,{"z-index":"2147483647",width:"320px"});
      panelShadow=panelHost.attachShadow({mode:"closed"});
      hostWatch.observe(panelHost,{attributes:true});
    }
    if (!panelHost.isConnected) document.documentElement.appendChild(panelHost);
  }
  function showView(view){
    ensurePanelHost();
    currentView=view;rowRuns=new WeakMap();
    if(frameMode && !view.inPage)showInFrame(view);else renderInPage(view);
  }
  // A click handled for one row, from the frame or from the in-page fallback.
  function runRow(row,ctx={}){noteGesture();row.run?.(ctx);}
  // Under the field (inline menu), next to the target, or bottom right.
  // height: the frame's reported height; null in the page (measured instead).
  function placePanel(view,height){
    placingFirst=!settledViews.has(view);
    try{placePanelAt(view,height);}finally{placingFirst=false;settledViews.add(view);}
  }
  function placePanelAt(view,height){
    const sized=box=>height==null?box:{...box,height};
    if(view.anchor && S.visible(view.anchor))return anchorUnder(view.anchor,height);
    // 320 px wide, narrower on a phone-width viewport (iPhone Safari) so the
    // whole panel stays on screen.
    const width=Math.round(Math.min(320,Math.max(240,innerWidth-16))), right=innerWidth-width>=36?18:8;
    const target=view.target;
    if(target && S.visible(target)) {
      const r=target.getBoundingClientRect();
      place(panelHost,sized({width,left:Math.round(Math.max(8,Math.min(innerWidth-width-8,r.right-width))),top:Math.round(Math.max(8,Math.min(innerHeight-220,r.bottom+8)))}),true);
    } else place(panelHost,sized({width,right,bottom:18}),true);
  }
  // ---- The frame. One frame per panel screen, with a fresh random token as
  // its window name: the frame presents the token with every request, the
  // service worker routes it to this tab (and to this frame where the browser
  // reports the parent), and only this script knows which token is current.
  // The first frame that presents it is bound (browser-reported frame id and
  // document); any other is refused. The frame reads the token once and
  // clears its window name, so a document the page navigates the frame to
  // finds nothing (and could not message the extension anyway).
  function showInFrame(view){
    const rec={token:randomHex(16),view,el:document.createElement("iframe"),who:null,ready:false,timer:null,height:0};
    rec.el.name=rec.token;
    rec.el.setAttribute("title","LocalGateKeys");
    rec.el.src=api.runtime.getURL(PANEL_PAGE);
    // While a ready frame is on screen the new one loads hidden beside it and
    // replaces it once it has drawn (no flash between screens).
    const showing=uiFrame?.ready && panelHost.isConnected && placed.has(panelHost);
    if(showing)rec.el.className="pending";
    else{const style=document.createElement("style");style.textContent=FRAME_STYLE;panelShadow.replaceChildren(style);}
    if(uiFrame)clearTimeout(uiFrame.timer);
    uiFrame=rec;
    panelShadow.append(rec.el);
    // No frame within the timeout. Where the frame is required, the page
    // removed or blocked it: cancel every flow and say so (no item data).
    // Otherwise (a browser without frame support) draw panels in the page.
    rec.timer=setTimeout(()=>{
      if(uiFrame!==rec || rec.ready)return;
      if(FRAME_REQUIRED){frameBlocked();return;}
      frameMode=false;dropFrames();
      if(currentView===view)renderInPage(view);
    },FRAME_TIMEOUT_MS);
  }
  function frameBlocked(){
    reset();
    const view=panel("LocalGateKeys",tr("content_frame_blocked"),[{label:tr("content_close"),run:hidePanel}]);
    view.inPage=true;
  }
  function dropFrames(){
    if(uiFrame)clearTimeout(uiFrame.timer);
    uiFrame=null;
    for(const el of panelShadow?.querySelectorAll("iframe")||[])el.remove();
  }
  // What the frame draws: resolved strings only, no functions.
  function frameSpec(view){
    const text=v=>shownText(v,true);
    return {title:text(view.title),text:text(view.text),origin:text(view.origin),focus:view.focus===true?"first":view.focus||"",fixed:listView(view),
      generator:view.generator?{...view.generator}:null,
      rows:view.rows.map(r=>({id:r.id,kind:r.kind,key:typeof r.key==="string"?r.key:"",label:text(r.label),secondary:r.secondary==null?"":text(r.secondary),
        extra:(r.extra||[]).map(text),logo:r.logo||null,action:typeof r.action==="string"?r.action:"",primary:!!r.primary,checked:!!r.checked,
        group:typeof r.group==="string"?r.group:"",value:r.value==null?"":text(r.value)}))};
  }
  // Screens with saved items (logins, cards, identities, field choices) get
  // one fixed height and scroll inside, so the page cannot count the rows
  // from the host's size; so do screens marked fixed (the save and update
  // prompts, whose text names a saved login). Other screens size to their text.
  const LIST_HEIGHT=320;
  function listView(view){return view.fixed===true || view.rows.some(r=>r.kind==="account"||r.kind==="check");}
  function frameSized(rec,height){
    const first=!rec.ready;
    rec.height=listView(rec.view)?LIST_HEIGHT:Math.round(Math.min(400,Math.max(40,Number(height)||0)));
    if(first){
      rec.ready=true;clearTimeout(rec.timer);
      for(const old of panelShadow.querySelectorAll("iframe"))if(old!==rec.el)old.remove();
      rec.el.className="";
    }
    if(currentView!==rec.view || !panelHost.isConnected)return;
    placePanel(rec.view,rec.height);
    if(first && rec.view.focus)try{rec.el.focus();}catch{}
  }
  // A click or key in the frame. The frame accepts only trusted input, after
  // the panel has been on screen briefly and, where the browser can tell
  // (IntersectionObserver v2), while it is really visible; here the host must
  // still be intact at the click point, exactly as for an in-page click.
  function frameEvent(rec,r){
    if(uiFrame!==rec || !rec.ready || currentView!==rec.view)return;
    if(r.id==="__escape"){reset();return;}
    const row=rec.view.rows.find(x=>x.id===r.id && x.kind!=="note");
    if(!row)return;
    const box=panelHost.getBoundingClientRect();
    const pointer=Number(r.detail)>0;
    const point=pointer?{detail:1,clientX:box.left+Number(r.x),clientY:box.top+Number(r.y)}:{detail:0,clientX:0,clientY:0};
    if(justMoved(panelHost))return;
    if(r.visible===false || !hostIntact(panelHost,point)){tampered();return;}
    if(r.checks && typeof r.checks==="object")for(const x of rec.view.rows)if(x.kind==="check" && typeof r.checks[x.id]==="boolean")x.checked=r.checks[x.id];
    if(row.kind==="check")return;
    runRow(row,{value:typeof r.value==="string"?r.value:undefined});
  }
  // Requests from the frame, relayed by the service worker. Only the current
  // frame's token is answered; everything else gets no reply at all (the
  // worker may ask every frame of the tab when the parent is unknown).
  function onUi(r){
    const rec=uiFrame;
    if(!rec || typeof r.token!=="string" || r.token!==rec.token)return null;
    const id=r.frame && Number.isInteger(r.frame.id)?r.frame.id:null;
    if(id===null)return null;
    const who=`${id}:${typeof r.frame.document==="string"?r.frame.document:""}`;
    if(rec.who===null)rec.who=who;
    else if(rec.who!==who)return {ok:false};
    if(r.op==="pull")return {ok:true,spec:frameSpec(rec.view)};
    if(r.op==="size"){frameSized(rec,r.height);return {ok:true};}
    if(r.op==="event"){queueMicrotask(()=>frameEvent(rec,r));return {ok:true};}
    return {ok:false};
  }
  // ---- In-page fallback: the same panel in a closed shadow root, with every
  // secret() string replaced by its neutral placeholder.
  function renderInPage(view){
    const text=v=>shownText(v,false);
    panelShadow.replaceChildren();rowRuns=new WeakMap();
    const style=document.createElement("style");style.textContent=styles;
    const box=document.createElement("section");box.className=listView(view)?"panel list":"panel";box.setAttribute("role","dialog");box.setAttribute("aria-label",text(view.title));
    const head=document.createElement("h3");head.textContent=text(view.title);box.append(head);
    const site=document.createElement("div");site.className="origin";site.textContent=text(view.origin);box.append(site);
    const p=document.createElement("p");p.textContent=text(view.text);box.append(p);
    for(const row of view.rows){
      // Editable rows exist only in the extension frame.
      if(row.kind==="input")continue;
      if(row.kind==="note"){const shown=text(row.label);if(!shown)continue;const note=document.createElement("p");note.className="note";note.textContent=shown;box.append(note);continue;}
      const b=document.createElement("button");b.type="button";
      if(row.kind==="account"){
        b.className="account";
        const label=document.createElement("span");label.className="text";
        const name=document.createElement("span");name.textContent=text(row.label);label.append(name);
        const sub=row.secondary==null?"":text(row.secondary);
        if(sub){const s=document.createElement("span");s.className="secondary";s.textContent=sub;label.append(s);}
        for(const extra of row.extra||[]){if(!text(extra))continue;const s=document.createElement("span");s.className="secondary match";s.textContent=text(extra);label.append(s);}
        const tile=logoTile(row.logo);
        if(tile){b.classList.add("has-logo");b.append(tile);}
        b.append(label);
        if(row.action){const pill=document.createElement("span");pill.className="fill-pill";pill.setAttribute("aria-hidden","true");pill.textContent=row.action;b.append(pill);}
      } else if(row.kind==="check"){
        b.className="account check";b.setAttribute("role","checkbox");b.dataset.token=row.key||"";
        const tick=document.createElement("span");tick.className="tick";const label=document.createElement("span");label.textContent=text(row.label);
        const paint=()=>{b.setAttribute("aria-checked",String(!!row.checked));tick.textContent=row.checked?"✓":"";};
        paint();b.append(tick,label);
        b.addEventListener("click",e=>{if(!uiClick(e,panelHost))return;e.preventDefault();e.stopPropagation();
          if(row.group){for(const other of view.rows)if(other.kind==="check" && other.group===row.group)other.checked=other===row;for(const x of box.querySelectorAll("button[role=checkbox]"))x.dispatchEvent(new Event("lgk-paint"));}
          else row.checked=!row.checked;paint();});
        b.addEventListener("lgk-paint",paint);
        box.append(b);continue;
      } else {b.textContent=text(row.label);b.className=row.primary?"primary":"";}
      b.addEventListener("click",e=>{if(!uiClick(e,panelHost))return;e.preventDefault();e.stopPropagation();runRow(row);});
      rowRuns.set(b,()=>runRow(row));
      box.append(b);
    }
    box.addEventListener("keydown",menuKey);
    panelShadow.append(style,box);
    // The header mark goes in through CSSOM, not style text, so its base64
    // never shows up in anything the page can read or search.
    try{style.sheet?.insertRule(`.panel{--mark:url("${PANEL_MARK}")}`,style.sheet.cssRules.length);}catch{}
    placePanel(view,listView(view)?LIST_HEIGHT:null);
    if(view.focus)(view.focus==="primary"&&box.querySelector("button.primary")||box.querySelector("button"))?.focus();
  }
  // Any change to the panel host's attributes that breaks its pinned layout
  // (a page restyling, hiding or moving it) cancels every flow at once, before
  // a click can land on it. The tampered host is thrown away; a second
  // tampering while the notice is shown just closes it.
  const hostWatch=new MutationObserver(()=>{
    if(panelHost && panelHost.isConnected && placed.has(panelHost) && !hostLayoutIntact(panelHost))tampered();
  });
  function tampered(){
    const again=shownText(currentView?.text,false)===TAMPERED;
    hostWatch.disconnect();
    if(panelHost){try{if(panelHost.matches(":popover-open"))panelHost.hidePopover();}catch{}panelHost.remove();placed.delete(panelHost);}
    panelHost=null;panelShadow=null;uiFrame=null;currentView=null;pendingView=null;
    if(again){reset();return;}
    reset(TAMPERED);
  }
  // Keyboard in our panel: arrows move between rows, Enter runs the focused
  // row. Only the user's own keys count, and Enter runs a row only while the
  // panel is intact (the same check as a keyboard click at its centre).
  function menuKey(e){
    if(!e.isTrusted || !panelShadow)return;
    const rows=Array.from(panelShadow.querySelectorAll("button"));
    const i=rows.indexOf(panelShadow.activeElement);
    const move={ArrowDown:i+1,ArrowUp:i-1,Home:0,End:rows.length-1}[e.key];
    if(move!=null && rows.length){e.preventDefault();e.stopPropagation();rows[(move+rows.length)%rows.length].focus();return;}
    // Rows without a stored action (identity, card and code pickers) keep the
    // button's own activation: its trusted click goes through uiClick.
    const run=i>=0?rowRuns.get(rows[i]):null;
    if(e.key==="Enter" && run){
      e.preventDefault();e.stopPropagation();
      if(!hostIntact(panelHost,{detail:0,clientX:0,clientY:0})){tampered();return;}
      run();
    }
  }
  // Inline menu: directly under the field, as wide as the field (at least
  // 280 px), kept inside the viewport. Without room below, it opens above the
  // field instead of covering it.
  // known: the frame's reported height (null: measure the in-page panel).
  function anchorUnder(field,known=null){
    if(!panelHost || !field || !S.visible(field))return;
    const r=field.getBoundingClientRect();
    const width=Math.round(Math.min(Math.max(280,r.width),Math.max(280,innerWidth-16)));
    const left=Math.round(Math.max(8,Math.min(innerWidth-width-8,r.left)));
    const sized=box=>known==null?box:{...box,height:known};
    place(panelHost,sized({width,left,top:Math.round(r.bottom+4)}),true);
    const height=known??Math.min(400,panelHost.getBoundingClientRect().height||0);
    if(r.bottom+4+height<=innerHeight-8)return;
    const above=r.top-4-height;
    const top=above>=8?above:Math.max(8,innerHeight-8-height);
    place(panelHost,sized({width,left,top:Math.round(top)}),true);
  }
  function panelShown(){return !!pendingView || (!!panelHost && panelHost.isConnected);}
  function hidePanel(){
    pendingView=null;currentView=null;
    if(panelHost?.isConnected){try{if(panelHost.matches(":popover-open"))panelHost.hidePopover();}catch{}panelHost.remove();}
    if(panelHost)placed.delete(panelHost);
    dropFrames();
    panelShadow?.replaceChildren();
  }
  function resetIdentity(reason=false) {
    if(identityActive?.approval) msg("cancel_identity_browser",{approval:identityActive.approval,identity_protocol:1},identityActive);
    identityActive=null;hidePanel();
    for(const {button} of identityIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");button.title=tr("content_fill_identity_title");}
    if(reason) panel("LocalGateKeys",reason,[{label:tr("content_close"),run:hidePanel}]);
  }
  function reset(reason=false) {
    resetIdentity();
    resetCard();
    resetTotp();
    generation++;
    if(active?.grant) msg("cancel_browser",{grant:active.grant},active);
    if(active){active.nonce=null;active.nonceExpiresAt=0;}
    active=null; clearInterval(statusTimer);statusTimer=null; hidePanel();
    for(const {button} of icons.values()) {button.disabled=false;button.setAttribute("aria-busy","false");button.title=fillTitle();}
    if(reason) panel("LocalGateKeys",reason,[{label:tr("content_close"),run:hidePanel}]);
  }
  function valid(op){return active===op && generation===op.generation && S.unchanged(op.ctx);}
  function itemLimitText(limit){return tr("content_item_limit",Number.isInteger(limit)&&limit>0?limit:7);}
  // Panel text for a failed reply. A message from the app or the service
  // worker is shown in the frame; the in-page fallback shows only the
  // extension's own text for the error code.
  function error(response){
    const known=errorText(response), message=response?.message;
    return typeof message==="string" && message && message!==known?secret(message,known):known;
  }
  function errorText(response){return (response?.error==="item_limit"?itemLimitText(response.limit):"") || ({user_cancelled:tr("content_err_user_cancelled"),gesture_nonce_invalid:tr("content_err_nonce_invalid"),gesture_nonce_required:tr("content_err_nonce_required"),user_gesture_required:tr("content_err_gesture_required"),not_found:tr("content_err_not_found"),session_changed:tr("content_err_session_changed"),fill_disabled:tr("content_err_fill_disabled"),totp_not_found:tr("content_err_totp_not_found"),card_not_found:tr("content_err_card_not_found"),invalid_card_fields:tr("content_err_invalid_card_fields"),invalid_approval:tr("content_err_invalid_approval"),entry_required:tr("content_err_entry_required"),entry_not_for_site:tr("content_err_entry_not_for_site")}[response?.error] || tr("content_err_generic"));}
  function valueset(field,value){
    const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set;
    setter.call(field,value);
    field.dispatchEvent(new Event("input",{bubbles:true}));
    field.dispatchEvent(new Event("change",{bubbles:true}));
  }
  // Open shadow roots are included in every field scan; the form scope stays
  // the field's own form when it has one.
  const q=(selector,root=document)=>S.queryAll(selector,root);
  function usernameFor(field) {
    const root=field.form || field.getRootNode();
    const candidates=q('input',root).filter(el=>el!==field && ["text","email","tel"].includes(el.type) && S.onTop(el));
    return candidates.find(el=>el.autocomplete==="username" || el.type==="email") || candidates[0] || null;
  }
  function finish(op){if(active===op){active=null;clearInterval(statusTimer);statusTimer=null;hidePanel();}for(const {button} of icons.values()){button.disabled=false;button.setAttribute("aria-busy","false");}}
  const identityAutocomplete={
    "name":"name","given-name":"given_name","additional-name":"middle_name","family-name":"family_name",
    "organization":"organization","organization-title":"job_title","email":"email","tel":"phone",
    "street-address":"address","address-line1":"address_line1","address-line2":"address_line2",
    "address-level2":"city","address-level1":"state","postal-code":"postal_code","country":"country",
    "url":"website"
  };
  function identityFieldName(field){
    if(!(field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) || field.type==="password" || !S.visible(field))return null;
    const tokens=String(field.autocomplete||"").toLowerCase().split(/\s+/).filter(Boolean);
    for(const token of tokens){if(identityAutocomplete[token])return identityAutocomplete[token];}
    if(field instanceof HTMLInputElement && field.type==="email")return "email";
    if(field instanceof HTMLInputElement && field.type==="tel")return "phone";
    return identityHint(field);
  }
  // Name/id/label guesses: single-line text inputs only (never textareas,
  // search boxes, rich editors or combo boxes), and only when the same form
  // (or page, without a form) has a second guessed identity field, so a lone
  // "Title" or "Message" box on a post or chat page gets no icon.
  const identityTextTypes=new Set(["text",""]);
  function identityHintRaw(field){
    if(!(field instanceof HTMLInputElement) || !identityTextTypes.has(field.type) || !S.visible(field))return null;
    if(/^(combobox|searchbox)$/i.test(field.getAttribute("role")||"") || field.closest('[role="search"],[contenteditable="true"]'))return null;
    const hint=[field.name,field.id,field.getAttribute("aria-label"),field.getAttribute("placeholder")].filter(Boolean).join(" ").toLowerCase().replace(/[_-]+/g," ");
    const checks=[
      [/\b(first|given)\s*name\b/,"given_name"],[/\b(middle)\s*name\b/,"middle_name"],[/\b(last|family)\s*name\b/,"family_name"],
      [/\b(full|display)\s*name\b/,"name"],[/\b(company)\b/,"company"],[/\b(organization|organisation)\b/,"organization"],[/\bjob\s*(title|role)\b/,"job_title"],
      [/\b(e[- ]?mail)\b/,"email"],[/\b(phone|mobile|tel)\b/,"phone"],[/\b(address|street)\b/,"address"],
      [/\b(city|town)\b/,"city"],[/\b(state|province|region)\b/,"state"],[/\b(zip|postal)\b/,"postal_code"],[/\bcountry\b/,"country"],
      [/\b(website|url|site)\b/,"website"]
    ];
    return checks.find(([pattern])=>pattern.test(hint))?.[1] || null;
  }
  function identityHint(field){
    const name=identityHintRaw(field);if(!name)return null;
    const others=q("input",field.form||document).filter(other=>other!==field && !other.form===!field.form);
    return others.some(other=>{const n=identityHintRaw(other);return n&&n!==name;})?name:null;
  }
  function identitySnapshot(field){
    if(!identityFieldName(field) || !S.onTop(field))throw new Error(tr("err_identity_field_hidden"));
    const form=field.form;if(form&&!S.safeForm(form))throw new Error(tr("err_form_other_origin_short"));
    return {field,form,origin:origin(),type:field.type,autocomplete:field.autocomplete,name:field.name,id:field.id,
      action:form?.getAttribute("action"),method:form?.getAttribute("method"),target:form?.getAttribute("target")};
  }
  function identityUnchanged(ctx){
    return identityActive?.ctx===ctx && ctx.origin===origin() && document.visibilityState==="visible" &&
      ctx.field.isConnected && ctx.field.form===ctx.form && ctx.field.type===ctx.type &&
      ctx.field.autocomplete===ctx.autocomplete && ctx.field.name===ctx.name && ctx.field.id===ctx.id && S.onTop(ctx.field) &&
      (!ctx.form || (S.safeForm(ctx.form) && ctx.form.getAttribute("action")===ctx.action &&
        ctx.form.getAttribute("method")===ctx.method && ctx.form.getAttribute("target")===ctx.target));
  }
  function identityValueSet(field,value){
    const proto=field instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
    const setter=Object.getOwnPropertyDescriptor(proto,"value").set;setter.call(field,value);
    field.dispatchEvent(new Event("input",{bubbles:true}));field.dispatchEvent(new Event("change",{bubbles:true}));
  }
  function identityTargets(name,root){
    return q("input,textarea",root||document).filter(field=>identityFieldName(field)===name && S.onTop(field));
  }
  function finishIdentity(op){if(identityActive===op){identityActive=null;hidePanel();}for(const {button} of identityIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");button.title=tr("content_fill_identity_title");}}
  async function releaseIdentity(op){
    if(identityActive!==op || !identityUnchanged(op.ctx))return resetIdentity();
    const response=await msg("release_identity_browser",{identity_protocol:1,approval:op.approval,entry_id:op.entryId,revision:op.revision,fields:op.fields},op);
    if(identityActive!==op || !identityUnchanged(op.ctx)){blankValues(response);return resetIdentity();}
    if(!response.ok){blankValues(response);resetIdentity();return panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
    try{
      if(!Array.isArray(response.fields) || response.fields.length!==op.fields.length || !response.values ||
         response.fields.some(field=>!op.fields.includes(field) || typeof response.values[field]!=="string"))throw new Error(tr("err_identity_approved_changed"));
      // The field checklist is done; it must not cover (and so block) the fields it fills.
      hidePanel();
      const root=op.ctx.form||document;const targets={};
      for(const field of op.fields){const found=identityTargets(field,root);if(found.length!==1)throw new Error(tr("err_identity_ambiguous"));targets[field]=found[0];}
      if(!identityUnchanged(op.ctx))throw new Error(tr("err_identity_form_changed"));
      for(const field of op.fields){if(!S.onTop(targets[field]))throw new Error(tr("err_identity_field_gone"));identityValueSet(targets[field],response.values[field]);}
      finishIdentity(op);
    }catch(e){resetIdentity();panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
    finally{blankValues(response);}
  }
  // index: the choice's place in the picker (the in-page fallback names it "#n").
  function showIdentityFields(op,choice,index=1){
    op.entryId=choice.entry_id;op.revision=choice.revision;
    const allowed=choice.fields.filter(field=>field!=="template_id");
    const initial=identityFieldName(op.ctx.field);
    const view=panel(tr("content_choose_identity_fields"),secret(tr("content_profile_origin",choice.title,origin()),tr("content_profile_origin",MASK,origin())),[],op.ctx.field);
    for(const field of allowed)view.add({kind:"check",key:field,label:field,checked:field===initial});
    view.add({label:tr("content_review_approve"),primary:true,run:async()=>{
      if(op.approving)return;
      const fields=view.checked();
      if(!fields.length||!identityUnchanged(op.ctx))return resetIdentity();
      op.approving=true;op.fields=fields;
      const response=await msg("approve_identity_browser",{identity_protocol:1,entry_id:op.entryId,revision:op.revision,fields:op.fields,session_id:op.sessionId,user_gesture:true},op);
      if(identityActive!==op||!identityUnchanged(op.ctx))return resetIdentity();if(!response.ok){resetIdentity();return panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
      op.approval=response.approval;void releaseIdentity(op);}});
    view.add({label:tr("content_cancel"),run:()=>resetIdentity()});
    view.focus=true;
  }
  function showIdentityPicker(op,choices){
    const view=panel(tr("content_choose_identity"),secret(tr("content_profile_origin",op.profileName,origin()),tr("content_profile_origin",MASK,origin())),[],op.ctx.field);
    choices.forEach((choice,i)=>view.add({kind:"account",label:secret((choice.favorite?"★ ":"")+choice.title,MASK),run:()=>showIdentityFields(op,choice,i+1)}));
    view.add({label:tr("content_cancel"),run:()=>resetIdentity()});
  }
  async function beginIdentity(field){
    reset();let ctx;try{ctx=identitySnapshot(field);}catch(e){return panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}],field);}
    const op={id:newId(),ctx,sessionId:null,entryId:null,revision:null,fields:[],approval:null,profileName:""};identityActive=op;
    const icon=identityIcons.get(field);if(icon){icon.button.disabled=true;icon.button.setAttribute("aria-busy","true");}
    const response=await msg("begin_identity_browser",{identity_protocol:1,user_gesture:true},op);
    if(identityActive!==op||!identityUnchanged(op.ctx))return resetIdentity();if(!response.ok){resetIdentity();return panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],field);}
    op.sessionId=response.session_id;op.profileName=response.profile?.name||"current profile";const choices=response.choices||[];
    if(choices.length===1)showIdentityFields(op,choices[0]);else showIdentityPicker(op,choices);
  }
  // ---- Card fill (card_protocol 1). Mirrors the identity flow: metadata
  // only until the user ticks fields in this panel, the desktop app shows the
  // trusted review, release is gesture-gated like get_browser, only the
  // approved tokens are filled, nothing is ever submitted, and every released
  // value is blanked from memory right after the fill.
  const CARD_PROTOCOL=1;
  const CARD_LABELS={"cc-name":tr("content_card_name"),"cc-number":tr("content_card_number"),"cc-exp":tr("content_card_expiry"),"cc-exp-month":tr("content_card_expiry_month"),"cc-exp-year":tr("content_card_expiry_year"),"cc-csc":tr("content_card_cvv"),"cc-type":tr("content_card_brand")};
  function resetCard(reason=false){
    if(cardActive?.approval) msg("cancel_card_browser",{approval:cardActive.approval,card_protocol:CARD_PROTOCOL},cardActive);
    if(cardActive){cardActive.nonce=null;cardActive.nonceExpiresAt=0;}
    cardActive=null;
    for(const {button} of cardIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");}
    if(reason) panel("LocalGateKeys",reason,[{label:tr("content_close"),run:hidePanel}]);
  }
  function cardValid(op){return cardActive===op && S.cardUnchanged(op.ctx);}
  function finishCard(op){if(cardActive===op){cardActive=null;hidePanel();}for(const {button} of cardIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");}}
  function cardFail(op,text){resetCard();panel("LocalGateKeys",text,[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
  function cardValueSet(control,value){
    if(control instanceof HTMLSelectElement){
      const setter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,"value").set;setter.call(control,value);
    } else valueset(control,value);
    if(control instanceof HTMLSelectElement){control.dispatchEvent(new Event("input",{bubbles:true}));control.dispatchEvent(new Event("change",{bubbles:true}));}
  }
  // Value to type into one page control for one approved token, or null when
  // the page control cannot represent it (then nothing is written there).
  function cardPresentation(token,control,value){
    if(control instanceof HTMLSelectElement){
      let candidates;
      if(token==="cc-exp-month"){const m=S.formatCardMonth(value);candidates=m?[m,String(Number(m))]:[];}
      else if(token==="cc-exp-year"){const raw=String(value||"").trim();const full=raw.length===2?`20${raw}`:raw;candidates=/^\d{4}$/.test(full)?[full,full.slice(-2)]:[];}
      else candidates=[value];
      const option=S.cardSelectOption(control,candidates);
      return option?option.value:null;
    }
    if(token==="cc-exp")return S.formatCardExpiry(value,control);
    if(token==="cc-exp-month")return S.formatCardMonth(value);
    if(token==="cc-exp-year")return S.formatCardYear(value,control);
    return value;
  }
  function cardTargets(ctx){
    const map=S.cardFieldMap(ctx.scope);const targets={};
    for(const token of ctx.tokens){const found=map[token]||[];if(found.length===1 && S.onTop(found[0]))targets[token]=found[0];}
    return targets;
  }
  async function releaseCard(op){
    if(!cardValid(op))return resetCard();
    if(op.releasing)return;op.releasing=true;
    const response=await gestured("release_card_browser",{card_protocol:CARD_PROTOCOL,approval:op.approval,entry_id:op.entryId,revision:op.revision,fields:op.fields},op,()=>cardValid(op));
    op.approval=null; // single use: consumed (or invalidated) by the broker either way
    if(!cardValid(op)){blankValues(response);return resetCard();}
    if(!response.ok){blankValues(response);const text=error(response);return cardFail(op,text);}
    const values=response.values;
    try{
      if(!Array.isArray(response.fields) || response.fields.length!==op.fields.length || !values || typeof values!=="object" ||
         response.fields.some(field=>!op.fields.includes(field) || typeof values[field]!=="string"))throw new Error(tr("err_card_approved_changed"));
      if(Object.keys(values).some(field=>!op.fields.includes(field)))throw new Error(tr("err_card_unapproved"));
      // The field checklist is done; it must not cover (and so block) the fields it fills.
      hidePanel();
      const targets=cardTargets(op.ctx);
      for(const field of op.fields){if(!targets[field])throw new Error(tr("err_card_ambiguous"));}
      if(!S.cardUnchanged(op.ctx))throw new Error(tr("err_card_form_changed"));
      for(const field of op.fields){
        const control=targets[field];
        if(!S.onTop(control))throw new Error(tr("err_card_field_gone"));
        const shown=cardPresentation(field,control,values[field]);
        if(shown!==null)cardValueSet(control,shown);
        // Synchronous site handlers may rebuild the form; stop before the next field.
        if(!S.cardUnchanged(op.ctx))throw new Error(tr("err_card_form_changed_filling"));
      }
      finishCard(op);
    }catch(e){cardFail(op,e.message);}
    finally{
      for(const key of Object.keys(values||{}))values[key]="";
      response.values=null;
    }
  }
  // index: the card's place in the picker (the in-page fallback says "Card n").
  function showCardFields(op,choice,index=1){
    op.entryId=choice.entry_id;op.revision=choice.revision;
    const meta=choice.fields&&typeof choice.fields==="object"?choice.fields:{};
    // Only tokens the page has and the card holds. CVV is opt-in every time.
    const offered=op.ctx.tokens.filter(token=>S.CARD_TOKENS.has(token) && meta[token]?.present===true);
    if(!offered.length)return cardFail(op,tr("content_card_no_fields"));
    const summary=[choice.brand,choice.last4?`•••• ${choice.last4}`:""].filter(Boolean).join(" ");
    const view=panel(tr("content_choose_card_fields"),secret(tr("content_card_origin",choice.title+(summary?` (${summary})`:""),origin()),tr("content_card_origin",tr("content_card"),origin())),[],op.ctx.field);
    for(const token of offered){
      const plain=CARD_LABELS[token]||token;
      view.add({kind:"check",key:token,label:meta[token]?.label&&meta[token].label!==plain?secret(meta[token].label,plain):plain,checked:token!=="cc-csc"});
    }
    // The CVV note tells whether a CVV is stored: shown in the frame only.
    if(offered.includes("cc-csc"))view.add({kind:"note",label:secret(tr("content_cvv_note"),"")});
    view.add({label:tr("content_review_approve"),primary:true,run:async()=>{
      if(op.approving)return;
      const chosen=new Set(view.checked());
      if(!chosen.size||!cardValid(op))return resetCard();
      op.approving=true;op.fields=offered.filter(token=>chosen.has(token));
      const response=await msg("approve_card_browser",{card_protocol:CARD_PROTOCOL,entry_id:op.entryId,revision:op.revision,fields:op.fields,session_id:op.sessionId,user_gesture:true},op);
      if(!cardValid(op))return resetCard();if(!response.ok){const text=error(response);return cardFail(op,text);}
      if(!validText(response.approval))return cardFail(op,tr("content_card_approval_invalid"));
      op.approval=response.approval;rememberNonce(op,response);void releaseCard(op);}});
    view.add({label:tr("content_cancel"),run:()=>{resetCard();hidePanel();}});
    view.focus=true;
  }
  function validText(value){return typeof value==="string" && value.length>0 && value.length<=128 && !value.includes("\0");}
  function showCardPicker(op,choices){
    const view=panel(tr("content_choose_card"),secret(tr("content_profile_origin",op.profileName,origin()),tr("content_profile_origin",MASK,origin())),[],op.ctx.field);
    choices.forEach((choice,i)=>view.add({kind:"account",
      label:secret((choice.favorite?"★ ":"")+(choice.title||tr("content_card")),tr("content_card")),
      secondary:secret([choice.brand,choice.last4?`•••• ${choice.last4}`:""].filter(Boolean).join(" ")||tr("content_card"),""),
      run:()=>showCardFields(op,choice,i+1)}));
    view.add({label:tr("content_cancel"),run:()=>{resetCard();hidePanel();}});
    view.focus=true;
  }
  async function beginCard(field){
    reset();let ctx;try{ctx=S.cardSnapshot(field);}catch(e){return panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}],field);}
    const op={id:newId(),ctx,sessionId:null,entryId:null,revision:null,fields:[],approval:null,profileName:""};cardActive=op;
    const icon=cardIcons.get(field);if(icon){icon.button.disabled=true;icon.button.setAttribute("aria-busy","true");}
    const waiting=setTimeout(()=>{if(cardValid(op))panel("LocalGateKeys",tr("content_unlock_in_desktop"),[{label:tr("content_cancel"),run:()=>resetCard()}],field);},500);
    const response=await msg("begin_card_browser",{card_protocol:CARD_PROTOCOL,user_gesture:true},op);clearTimeout(waiting);
    if(!cardValid(op))return resetCard();
    if(!response.ok){const text=error(response);return cardFail(op,text);}
    op.sessionId=response.session_id ?? null;op.profileName=response.profile?.name||"current profile";rememberNonce(op,response);
    const choices=Array.isArray(response.choices)?response.choices.filter(c=>c&&typeof c==="object"&&typeof c.entry_id==="string"&&Number.isInteger(c.revision)):[];
    if(!choices.length)return cardFail(op,error({error:"card_not_found"}));
    if(choices.length===1)showCardFields(op,choices[0]);else showCardPicker(op,choices);
  }
  async function release(op,entryId) {
    if(!valid(op)) return reset();
    if(op.releasing)return;op.releasing=true;
    const response=await gestured("get_browser",{grant:op.grant,entry_id:entryId,username_only:op.ctx.usernameOnly,url:pageUrl()},op,()=>valid(op));
    if(!valid(op)){blankCredential(response);return reset();}
    if(!response.ok || !response.credential){blankCredential(response);const text=error(response);reset();return panel("LocalGateKeys",text,[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
    const c=response.credential;
    if(!op.ctx.usernameOnly && typeof c.username==="string" && c.username){
      // Multi-step login pages can remove the username field before the
      // password submission is observed. Keep only the username briefly and
      // bind it to this exact field/form/document for automatic-save matching.
      recentFilledCredential={field:op.ctx.field,form:op.ctx.form,username:c.username,
        usernameField:usernameFor(op.ctx.field),origin:origin(),at:Date.now()};
    }
    try {
      const permitted=await msg("validate_browser",{grant:op.grant,entry_id:entryId},op);
      if(!permitted.ok || !valid(op)) throw new Error(tr("err_request_cancelled"));
      // The picker is done; it must not cover (and so block) the form's own controls.
      hidePanel();
      const field=op.ctx.field;
      if(op.ctx.usernameOnly) valueset(field,c.username||"");
      else {
        const user=usernameFor(field);
        if(user) valueset(user,c.username||"");
        // Synchronous site input handlers may replace/hide/change the password field.
        if(!valid(op)) throw new Error(tr("err_login_form_changed"));
        valueset(field,c.password||"");
      }
      const wanted=c.password;
      c.password="";
      if(response.sign_in===true && !op.ctx.usernameOnly) {
        const button=S.submitCandidate(op.ctx);
        if(button) {
          const approved=await msg("submit_browser",{grant:op.grant,entry_id:entryId},op);
          if(!approved.ok || !valid(op)) throw new Error(tr("err_signin_cancelled_changed"));
          if(S.submitCandidate(op.ctx)!==button || field.value!==wanted) throw new Error(tr("err_signin_cancelled_form"));
          // No Enter injection, no form.submit(), no validation bypass, one attempt.
          if(!op.ctx.form.checkValidity()) throw new Error(tr("err_review_required"));
          const form=op.ctx.form;
          finish(op);
          HTMLFormElement.prototype.requestSubmit.call(form,button);
          return;
        }
        finish(op);
        return panel("LocalGateKeys",tr("content_autosignin_skipped"),[{label:tr("content_close"),run:hidePanel}],field);
      }
      finish(op);
    } catch(e) {c.password="";reset();panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
  }
  // The site's logo (background.js adds site_logo from the bundled set for
  // this page's origin), drawn as inline SVG like the field icons. It comes
  // from this page's own origin, not from the vault.
  function cleanLogo(logo){
    return logo && typeof logo.hex==="string" && /^#[0-9a-f]{6}$/i.test(logo.hex) && typeof logo.path==="string" && /^[0-9a-z.,\- ]{1,20000}$/i.test(logo.path)?{hex:logo.hex,path:logo.path}:null;
  }
  function logoTile(logo){
    logo=cleanLogo(logo);if(!logo)return null;
    const n=parseInt(logo.hex.slice(1),16);const light=(0.299*(n>>16)+0.587*((n>>8)&255)+0.114*(n&255))/255>0.7;
    const tile=document.createElement("span");tile.className="logo";tile.style.background=logo.hex;
    tile.append(svgEl("svg",{viewBox:"0 0 24 24","aria-hidden":"true",focusable:"false"},[svgEl("path",{d:logo.path,fill:light?"#111111":"#ffffff"})]));
    return tile;
  }
  // One account row: [logo] name / username (+ extra lines). The in-page
  // fallback (Safari) shows only masks: no row number, no match hint.
  function accountRow(c,index,logo,extra=[]){
    return {kind:"account",label:secret((c.favorite?"★ ":"")+(c.label||c.username),MASK),
      secondary:secret(c.username || tr("content_no_username")),extra,logo:cleanLogo(logo),action:tr("panel_fill_login")};
  }
  function showAccountPicker(op,choices,profile,logo=null) {
    const view=panel(tr("content_choose_account"),secret(tr("content_profile",profile?.name||""),tr("content_profile",MASK)),[],op.ctx.field);
    // Broker match kind for multi-URL logins; exact-origin rows are the norm
    // and say nothing, the wider rows are labelled so the user can tell.
    const matchHint={host:tr("content_match_host"),base_domain:tr("content_match_domain"),starts_with:tr("content_match_prefix")};
    choices.forEach((c,i)=>{
      const extra=typeof c.match==="string" && c.match!=="exact_origin" && matchHint[c.match]?[secret(matchHint[c.match],"")]:[];
      view.add({...accountRow(c,i+1,logo,extra),run:()=>release(op,c.entry_id)});
    });
    view.add({label:tr("content_cancel"),run:()=>reset()});
    view.anchor=op.ctx.field;view.focus=true;
  }
  // fromIcon: started by a click on the in-page icon, which lives in the page
  // and can be clickjacked; even a single match then needs a second, explicit
  // click in the picker. The toolbar popup is browser UI and fills directly.
  // entryId: a login the user picked in the toolbar popup; filled only if
  // the app lists it for this page, through the same checks as any fill.
  async function begin(field, fromIcon=false, entryId=null) {
    logoutInProgress=false;
    recentFilledCredential=null;
    reset();
    const usernameOnly=field.type!=="password";
    let ctx;try{ctx=S.snapshot(field,usernameOnly);}catch(e){panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}]);return;}
    const op={id:newId(),generation,ctx,grant:null,sessionId:null};active=op;
    const icon=icons.get(field);if(icon){icon.button.setAttribute("aria-busy","true");icon.button.title=tr("content_waiting_title");icon.button.disabled=true;}
    const waiting=setTimeout(()=>{if(valid(op))panel("LocalGateKeys",tr("content_unlock_in_desktop"),[{label:tr("content_cancel"),run:()=>reset()}],field);},500);
    const response=await msg("begin_browser",{user_gesture:true,url:pageUrl()},op);clearTimeout(waiting);
    if(!valid(op))return reset();
    if(!response.ok){reset();return panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],field);}
    op.grant=response.grant;op.sessionId=response.session_id ?? null;rememberNonce(op,response);
    // ping is unauthenticated metadata ({ok, version, locked} only): it tells
    // us when the vault locked, nothing more. Grant/lease continuity is
    // enforced by the broker on get_browser (session_changed).
    statusTimer=setInterval(async()=>{
      if(!valid(op))return reset();
      const state=await msg("ping",{},op);
      if(active===op && (!state.ok || state.locked===true)) reset();
    },1200);
    const choices=Array.isArray(response.choices)?response.choices:[];
    // fill:never logins are left out by the broker; no empty menu.
    if(!choices.length){reset();return panel("LocalGateKeys",error({error:"not_found"}),[{label:tr("content_close"),run:hidePanel}],field);}
    if(entryId!==null){
      const chosen=choices.find(c=>c.entry_id===entryId);
      if(chosen)release(op,chosen.entry_id);
      else{reset();panel("LocalGateKeys",error({error:"not_found"}),[{label:tr("content_close"),run:hidePanel}],field);}
    }
    else if(choices.length===1 && !fromIcon)release(op,choices[0].entry_id);
    else showAccountPicker(op,choices,response.profile,response.site_logo);
  }
  // ---- AI agent sign-in (LocalGateKeys agent gate). After the user approved
  // an agent's sign-in in the app, the app arms a one-use grant for the exact
  // approved hosts and logins. It is asked for only after the user's own
  // (trusted) click on our inline icon, never on page focus or load, so a page
  // script or an agent driving the browser cannot release it. The approved
  // login(s) then open in the normal picker and the user picks one with a
  // second click there, as for any icon click. With nothing armed the app
  // answers not_found and the icon click goes on as a normal fill. A grant for a
  // login with a passkey never fills the password: the app answers
  // agent_passkey and we only say to use the site's passkey sign-in.
  async function agentFill(field){
    if((!fillEnabled && !agentOnly) || inlineBlocked)return false;
    let ctx;try{ctx=S.snapshot(field,field.type!=="password");}catch{return false;}
    reset();
    const op={id:newId(),generation,ctx,grant:null,sessionId:null};
    const response=await msg("fill_grant_browser",{url:pageUrl()},op);
    if(response?.error==="agent_passkey" && !active && generation===op.generation && S.unchanged(ctx)){
      panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],field);
      return true;
    }
    if(!response || response.ok!==true || active || generation!==op.generation || !S.unchanged(ctx))return false;
    const choices=Array.isArray(response.choices)?response.choices:[];
    if(!choices.length || typeof response.grant!=="string")return false;
    active=op;op.grant=response.grant;op.sessionId=response.session_id ?? null;rememberNonce(op,response);
    showAccountPicker(op,choices,response.profile,response.site_logo);
    return true;
  }
  // The inline icon's click handler (trusted clicks only, see uiClick).
  async function iconClicked(field){
    noteGesture();
    if(await agentFill(field))return;
    // Safari agent-only icon: no approved sign-in is waiting for this site.
    if(!fillEnabled){reset();panel("LocalGateKeys",error({error:"not_found"}),[{label:tr("content_close"),run:hidePanel}],field);return;}
    begin(field,true);
  }
  // ---- Generated passwords. The value is written only into the form's own
  // new-password fields (one or two, same form, form posting to this origin).
  function newPasswordFields(field){
    const scope=field.form || field.getRootNode();
    return q('input[type="password"]').filter(f=>(f.form || f.getRootNode())===scope && S.visible(f) && S.newPassword(f));
  }
  // Random index below n: rejection sampling, not modulo-biased byte mapping.
  function randomBelow(n){const limit=Math.floor(0x100000000/n)*n,b=new Uint32Array(1);for(;;){crypto.getRandomValues(b);if(b[0]<limit)return b[0]%n;}}
  // Password with the popup generator's saved length / character groups
  // (generator_options); defaults: 24 characters, all groups, no look-alikes.
  function strongPassword(o={}){
    const ambiguous="Il1O0o|`'\"",keep=s=>Array.from(s).filter(c=>o.avoidAmbiguous===false||!ambiguous.includes(c)).join("");
    const groups=[["lowercase","abcdefghijklmnopqrstuvwxyz"],["uppercase","ABCDEFGHIJKLMNOPQRSTUVWXYZ"],["digits","0123456789"],["symbols","!@#$%^&*()-_=+[]{}:,.?"]]
      .filter(([k])=>o[k]!==false).map(([,s])=>keep(s));
    if(!groups.length)groups.push(keep("abcdefghijklmnopqrstuvwxyz"));
    const length=Number.isInteger(o.length)?Math.max(8,Math.min(128,o.length)):24;
    const chars=groups.map(g=>g[randomBelow(g.length)]),pool=groups.join("");
    while(chars.length<length)chars.push(pool[randomBelow(pool.length)]);
    for(let i=chars.length-1;i>0;i--){const j=randomBelow(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
    return chars.join("");
  }
  async function savedGeneratorOptions(){
    try{const o=(await api.storage.local.get({generator_options:{}})).generator_options;return o&&typeof o==="object"?o:{};}catch{return {};}
  }
  // A value handed over by the popup generator: printable, no control characters.
  const validGenerated=v=>typeof v==="string" && v.length>=8 && v.length<=256 && !/[\u0000-\u001f\u007f]/.test(v);
  function fillGenerated(fields,given){
    if(!fields.length || fields.length>2 || fields.some(f=>f.form!==fields[0].form) || (fields[0].form&&!S.safeForm(fields[0].form)))return false;
    const value=validGenerated(given)?given:strongPassword();
    fields.forEach(f=>valueset(f,value));
    panel(tr("content_pw_generated"),tr("content_pw_generated_body"),[{label:tr("content_save_in_vault"),primary:true,run:()=>offerSave(fields[0],true)},{label:tr("content_close"),run:hidePanel}],fields[0]);
    return true;
  }
  // Inline menu of a new-password field (sign-up or the new field of a
  // change-password form): Generate only, no vault access.
  // Shows a suggested password with a refresh button, a length slider and the
  // character groups; changes are saved as the popup generator's settings.
  async function showGenerateMenu(field){
    reset();
    const opts={length:20,lowercase:true,uppercase:true,digits:true,symbols:true,avoidAmbiguous:true,...await savedGeneratorOptions()};
    const view=panel(tr("content_generate_password"),tr("content_generate_body"),[
      {label:tr("gen_fill"),primary:true,run:({value}={})=>{
        hidePanel();
        // The suggestion the frame showed; the in-page fallback shows none and fills a fresh one.
        const chosen=validGenerated(value)?value:strongPassword(opts);
        if(!field.isConnected || !fillGenerated(newPasswordFields(field).filter(S.onTop),chosen))panel("LocalGateKeys",tr("content_no_new_password"),[{label:tr("content_close"),run:hidePanel}],field);
      }},
      {label:tr("content_cancel"),run:hidePanel}
    ],field);
    // The frame draws the suggestion with a refresh button, the length and
    // the character groups, and saves changes as the popup generator's settings.
    view.generator=opts;view.anchor=field;view.focus="primary";
  }
  // ---- 2FA one-time codes. The page receives a code, never the setup key.
  function resetTotp(){
    if(otpActive){otpActive.nonce=null;otpActive.nonceExpiresAt=0;}
    otpActive=null;
    for(const {button} of otpIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");}
  }
  function totpValid(op){return otpActive===op && S.unchanged(op.ctx);}
  function fillCode(ctx,code){
    if(ctx.boxes){
      if(ctx.boxes.length!==code.length) throw new Error(tr("err_code_boxes"));
      ctx.boxes.forEach((box,i)=>valueset(box,code[i]));
    } else valueset(ctx.field,code);
  }
  async function releaseTotp(op,entryId){
    if(!totpValid(op))return resetTotp();
    if(op.releasing)return;op.releasing=true;
    const response=await gestured("get_totp_browser",{grant:op.grant,entry_id:entryId},op,()=>totpValid(op));
    if(!totpValid(op)){blankCode(response);return resetTotp();}
    if(!response.ok || typeof response.code!=="string"){
      blankCode(response);resetTotp();return panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],op.ctx.field);
    }
    let code=response.code;
    try{
      if(response.remaining<4 && typeof response.next_code==="string"){
        // Avoid typing a code that expires before the site checks it.
        panel("LocalGateKeys",tr("content_totp_waiting"),[],op.ctx.field);
        await new Promise(r=>setTimeout(r,(response.remaining+1)*1000));
        code=response.next_code;
        if(!totpValid(op))return resetTotp();
      }
      fillCode(op.ctx,code);hidePanel();
    }catch(e){panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}],op.ctx.field);}
    finally{response.code=response.next_code="";resetTotp();}
  }
  async function beginTotp(field, fromIcon=false){
    reset();
    let ctx;try{ctx=S.otpSnapshot(field);}catch(e){return panel("LocalGateKeys",e.message,[{label:tr("content_close"),run:hidePanel}],field);}
    const op={id:newId(),ctx,grant:null,sessionId:null};otpActive=op;
    const icon=otpIcons.get(field);if(icon){icon.button.disabled=true;icon.button.setAttribute("aria-busy","true");}
    const response=await msg("begin_totp_browser",{user_gesture:true},op);
    if(!totpValid(op))return resetTotp();
    if(!response.ok){resetTotp();return panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}],field);}
    op.grant=response.grant;op.sessionId=response.session_id ?? null;rememberNonce(op,response);
    const choices=response.choices||[];
    if(choices.length===1 && !fromIcon)return releaseTotp(op,choices[0].entry_id);
    const view=panel(tr("content_which_totp"),secret(tr("content_profile",response.profile?.name||""),tr("content_profile",MASK)),[],field);
    choices.forEach((c,i)=>view.add({...accountRow(c,i+1,response.site_logo),run:()=>releaseTotp(op,c.entry_id)}));
    view.add({label:tr("content_cancel"),run:()=>{resetTotp();hidePanel();}});
    view.focus=true;
  }
  function position(field,host) {
    if(!S.visible(field)){hideHost(host);return;}
    const r=field.getBoundingClientRect();
    place(host,{width:24,height:24,left:Math.round(r.right-30),top:Math.round(r.top+(r.height-24)/2)});
  }
  // The vault-dial mark (assets/brand/localgatekeys-icon-small.svg) drawn as
  // inline SVG inside the closed shadow root: no extension URL is ever
  // referenced from a web page, so pages cannot probe for the extension
  // through web_accessible_resources, and no page CSP can block the image.
  const SVG_NS="http://www.w3.org/2000/svg";
  function svgEl(name,attrs={},children=[]){
    const el=document.createElementNS(SVG_NS,name);
    for(const [k,v] of Object.entries(attrs))el.setAttribute(k,v);
    el.append(...children);
    return el;
  }
  function logoGlyph(){
    const stops=list=>list.map(([offset,color])=>svgEl("stop",{offset,"stop-color":color}));
    const diagonal={x1:"0",y1:"0",x2:"1",y2:"1"};
    return svgEl("svg",{viewBox:"0 0 256 256","aria-hidden":"true",focusable:"false"},[
      svgEl("defs",{},[
        svgEl("linearGradient",{id:"lgk-tile",...diagonal},stops([["0","#173A6E"],["1","#050B18"]])),
        svgEl("linearGradient",{id:"lgk-arc",...diagonal},stops([["0","#67E8F9"],[".55","#3B82F6"],["1","#1D3FBF"]])),
        svgEl("radialGradient",{id:"lgk-face",cx:".4",cy:".35",r:".75"},stops([["0","#2A4E8C"],["1","#0A1630"]])),
      ]),
      svgEl("rect",{width:"256",height:"256",rx:"58",fill:"url(#lgk-tile)"}),
      svgEl("rect",{x:"1.5",y:"1.5",width:"253",height:"253",rx:"56.5",fill:"none",stroke:"#FFFFFF","stroke-opacity":".09","stroke-width":"3"}),
      svgEl("circle",{cx:"128",cy:"128",r:"84",fill:"none",stroke:"#1B3566","stroke-width":"28"}),
      svgEl("circle",{cx:"128",cy:"128",r:"84",fill:"none",stroke:"url(#lgk-arc)","stroke-width":"28","stroke-linecap":"round","stroke-dasharray":"180 400",transform:"rotate(-200 128 128)"}),
      svgEl("circle",{cx:"128",cy:"128",r:"62",fill:"url(#lgk-face)"}),
      svgEl("g",{transform:"translate(128 125) scale(.48)",fill:"#F4F8FF"},[svgEl("circle",{cx:"0",cy:"-36",r:"40"}),svgEl("path",{d:"M-24 -8 H24 L40 94 H-40 Z"})]),
    ]);
  }
  // Inline glyph: a card outline with its magnetic stripe.
  function cardGlyph(){
    return svgEl("svg",{viewBox:"0 0 24 24","aria-hidden":"true",focusable:"false"},[
      svgEl("rect",{x:"2",y:"5",width:"20",height:"14",rx:"3",fill:"none",stroke:"#83cfe4","stroke-width":"1.8"}),
      svgEl("rect",{x:"2",y:"8.5",width:"20",height:"3",fill:"#83cfe4"}),
    ]);
  }
  const ICON_STYLE='button{display:grid;place-items:center;width:24px;height:24px;padding:0;border:1px solid #3c607e;border-radius:7px;background:#091421;cursor:pointer}button:focus-visible{outline:2px solid #5dbeff;outline-offset:2px}button[aria-busy="true"]{opacity:.5}svg{width:22px;height:22px;display:block}svg.card{width:18px;height:18px}button[data-verdict="exact"],button[data-verdict="related"]{border-color:#2fbf71}button[data-verdict="lookalike"]{border-color:#ff5c6c;box-shadow:0 0 0 1px #ff5c6c}';
  // One in-page icon on one field. run(field) starts the flow; it is called
  // only for a trusted click on an intact host (see uiClick).
  function addIcon(map,field,dataKey,title,glyph,run){
    const host=uiHost(dataKey,{"z-index":"2147483646",width:"24px",height:"24px"});
    const shadow=host.attachShadow({mode:"closed"});
    const style=document.createElement("style");style.textContent=ICON_STYLE;
    const button=document.createElement("button");button.type="button";button.title=title;button.setAttribute("aria-label",title);button.append(glyph);
    button.onmousedown=e=>e.preventDefault();
    button.onclick=e=>{if(!uiClick(e,host))return;e.preventDefault();e.stopPropagation();run(field);};
    shadow.append(style,button);document.documentElement.append(host);map.set(field,{host,button});position(field,host);
  }
  function removeFillIcons(){
    for(const map of [icons,generateIcons,cardIcons,otpIcons,identityIcons]){for(const {host} of map.values())host.remove();map.clear();}
  }
  function syncIcons(){
    watchShadowRoots();
    if(!fillEnabled && !agentOnly){removeFillIcons();return;}
    const fields=inlineBlocked?[]:q('input').filter(el=>S.visible(el) && (
      (el.type==="password" && !S.newPassword(el)) ||
      (el.autocomplete==="username" && !el.form?.querySelector('input[type="password"]'))));
    const set=new Set(fields);
    for(const [f,{host}] of icons){if(!set.has(f)){host.remove();icons.delete(f);}else position(f,host);}
    for(const field of fields){if(icons.has(field))continue;
      addIcon(icons,field,"localvaultFieldIcon",fillTitle(),logoGlyph(),f=>{void iconClicked(f);});
    }
    markIcons();
    if(!fillEnabled){
      // Agent-only (Safari): the sign-in icons above and nothing else.
      for(const map of [generateIcons,cardIcons,otpIcons,identityIcons]){for(const {host} of map.values())host.remove();map.clear();}
      return;
    }
    // One generate icon per form: on its first visible new-password field.
    const generateFields=[];
    if(!inlineBlocked){
      const seen=new Set();
      for(const el of q('input[type="password"]')){
        if(!S.visible(el) || !S.newPassword(el))continue;
        const scope=el.form || el.getRootNode();if(seen.has(scope))continue;seen.add(scope);
        const group=newPasswordFields(el);
        if(group.length<=2 && (!el.form || S.safeForm(el.form)))generateFields.push(el);
      }
    }
    const generateSet=new Set(generateFields);
    for(const [f,{host}] of generateIcons){if(!generateSet.has(f)){host.remove();generateIcons.delete(f);}else position(f,host);}
    for(const field of generateFields){if(generateIcons.has(field))continue;
      addIcon(generateIcons,field,"localgatekeysGenerateIcon",tr("content_generate_title"),logoGlyph(),f=>{noteGesture();showGenerateMenu(f);});
    }
    // Payment forms: one card button on the (single, visible) card-number
    // field of each scope. Card controls never get OTP or identity buttons.
    const cardControls=new Set();const cardNumberFields=[];
    const scopes=new Set();
    for(const el of q('input,select')){if(!S.visible(el))continue;const token=S.cardToken(el,true);if(token)scopes.add(S.cardScope(el));}
    for(const scope of scopes){
      const map=S.cardFieldMap(scope);
      for(const list of Object.values(map))for(const el of list)cardControls.add(el);
      if(map["cc-number"]?.length===1)cardNumberFields.push(map["cc-number"][0]);
    }
    const cardSet=new Set(cardNumberFields);
    for(const [f,{host}] of cardIcons){if(!cardSet.has(f)){host.remove();cardIcons.delete(f);}else position(f,host);}
    for(const field of cardNumberFields){if(cardIcons.has(field))continue;
      const glyph=cardGlyph();glyph.setAttribute("class","card");
      addIcon(cardIcons,field,"localgatekeysCardIcon",tr("content_fill_card_title"),glyph,f=>{noteGesture();beginCard(f);});
    }
    const otpFields=q('input').filter(el=>!icons.has(el) && !cardControls.has(el) && S.otpField(el));
    const otpSet=new Set(otpFields);
    for(const [field,{host}] of otpIcons){if(!otpSet.has(field)){host.remove();otpIcons.delete(field);}else position(field,host);}
    for(const field of otpFields){if(otpIcons.has(field))continue;
      addIcon(otpIcons,field,"localgatekeysOtpIcon",tr("content_fill_otp_title"),logoGlyph(),f=>{noteGesture();beginTotp(f,true);});
    }
    const identityFields=q('input,textarea').filter(field=>!cardControls.has(field) && identityFieldName(field) && S.visible(field) && field.type!=="password" && !field.form?.querySelector('input[type="password"]'));
    const identitySet=new Set(identityFields);
    for(const [field,{host}] of identityIcons){if(!identitySet.has(field)){host.remove();identityIcons.delete(field);}else position(field,host);}
    for(const field of identityFields){if(identityIcons.has(field))continue;
      addIcon(identityIcons,field,"localgatekeysIdentityIcon",tr("content_fill_identity_title"),logoGlyph(),f=>beginIdentity(f));
    }
  }
  let syncTimer;
  function schedule(){if(syncTimer)return;syncTimer=setTimeout(()=>{syncTimer=null;syncIcons();if(active&&!S.unchanged(active.ctx))reset();if(identityActive&&!identityUnchanged(identityActive.ctx))resetIdentity();if(cardActive&&!S.cardUnchanged(cardActive.ctx))resetCard();if(otpActive&&!S.unchanged(otpActive.ctx))resetTotp();},40);}
  const observerOptions={childList:true,subtree:true,attributes:true,attributeFilter:["type","autocomplete","disabled","readonly","class","style","action","method","target"]};
  const observer=new MutationObserver(records=>{
    const owned=node=>node instanceof Element && !!node.closest(`[${PANEL_ATTR}],[data-localvault-field-icon],[data-localgatekeys-generate-icon],[data-localgatekeys-identity-icon],[data-localgatekeys-otp-icon],[data-localgatekeys-card-icon]`);
    if(records.some(r=>!owned(r.target) && (r.type!=="childList" || [...r.addedNodes,...r.removedNodes].some(n=>!owned(n)))))schedule();
  });
  observer.observe(document.documentElement,observerOptions);
  // Mutation records and the non-composed "submit" event do not cross shadow
  // boundaries, so every open shadow root found during a scan is observed and
  // listened to once. Closed roots (our own UI) are never reachable here.
  const watchedRoots=new WeakSet();
  function watchShadowRoots(){
    for(const root of S.shadowRoots(document)){
      if(watchedRoots.has(root))continue;
      watchedRoots.add(root);
      observer.observe(root,observerOptions);
      root.addEventListener("submit",onSubmit,true);
    }
  }
  addEventListener("scroll",schedule,true);addEventListener("resize",schedule);addEventListener("pagehide",()=>{if(logoutInProgress)void msg("clear_pending_browser",{}, {id:newId()});recentFilledCredential=null;reset();});
  addEventListener("hashchange",()=>{reset();schedulePendingChecks([200,900]);});addEventListener("popstate",()=>{reset();schedulePendingChecks([200,900]);});
  document.addEventListener("visibilitychange",()=>{if(document.visibilityState!=="visible")reset();else schedulePendingChecks([120,500,1200]);});
  // Only the user's own Escape closes our UI: a page-dispatched key event must
  // not dismiss the save panel (or learn from closing it).
  document.addEventListener("keydown",e=>{if(e.isTrusted && e.key==="Escape")reset();},true);
  // Safari: filling stays off unless the background's status reply turns it on.
  if(safariBackground()){fillEnabled=false;void msg("status").then(r=>{applyFeatures(r);return fillEnabled?null:msg("agent_status_browser");}).then(r=>{if(r)applyAgent(r);});}
  syncIcons();

  // ---- Phishing shield: "Verified site" and the lookalike guard. The app
  // compares this origin with the saved origins (they never leave it) and
  // answers a verdict: exact (Verified), related (same site), lookalike or
  // unknown (New site). Asked only when the user starts working with a login
  // (focus on a login field, a credential submit, a save prompt, the popup),
  // never on page load. On a lookalike the submit and save paths ask first.
  function fillTitle(){
    const label=siteVerdict&&VERDICT_LABELS[siteVerdict.kind];
    return label?`${tr("content_fill_title")} · ${label()}`:tr("content_fill_title");
  }
  function markIcons(){
    for(const {button} of icons.values()){
      if(siteVerdict)button.dataset.verdict=siteVerdict.kind;
      if(button.getAttribute("aria-busy")!=="true")button.title=fillTitle();
    }
  }
  function cleanVerdict(r){
    if(!r || r.ok!==true || !VERDICT_KINDS.has(r.kind))return null;
    const matched=typeof r.matched==="string" && r.matched.length<=253 && /^[\x21-\x7e]+$/.test(r.matched)?r.matched:null;
    const pair=typeof r.pair==="string" && /^[0-9a-f]{32}$/.test(r.pair)?r.pair:null;
    return {kind:r.kind,reason:typeof r.reason==="string"?r.reason.slice(0,32):"",matched,pair};
  }
  async function rememberedPairs(){
    try{const stored=await api.storage.local.get({[SAME_ACCOUNT_KEY]:[]});return Array.isArray(stored[SAME_ACCOUNT_KEY])?stored[SAME_ACCOUNT_KEY]:[];}
    catch{return [];}
  }
  // Only the app's opaque pair id is stored, never a saved origin.
  async function rememberSameAccount(pair){
    const pairs=await rememberedPairs();
    if(!pairs.includes(pair))try{await api.storage.local.set({[SAME_ACCOUNT_KEY]:[...pairs,pair].slice(-500)});}catch{}
  }
  // A verdict is kept for VERDICT_TTL_MS, then asked for again, so a vault
  // that was locked meanwhile (the app then answers "locked") clears it. An
  // unanswered request is repeated at most every 5 s.
  const VERDICT_TTL_MS=60000;
  const verdictFresh=()=>!!siteVerdict && Date.now()-verdictAt<VERDICT_TTL_MS;
  function loadVerdict(){
    if(verdictFresh())return Promise.resolve(siteVerdict);
    if(verdictRequest)return verdictRequest;
    if(Date.now()-verdictAskedAt<5000)return Promise.resolve(verdictFresh()?siteVerdict:null);
    verdictAskedAt=Date.now();
    verdictRequest=msg("classify_site_browser",{}, {id:newId()}).then(async r=>{
      let v=cleanVerdict(r);
      if(v && v.kind==="lookalike" && v.reason==="other-suffix" && v.pair && (await rememberedPairs()).includes(v.pair))
        v={...v,kind:"related",reason:"same-account"};
      siteVerdict=v;verdictAt=Date.now();
      if(!v)for(const {button} of icons.values())delete button.dataset.verdict;
      markIcons();
      return v;
    }).catch(()=>null).finally(()=>{verdictRequest=null;});
    return verdictRequest;
  }
  const guarded=v=>v?.kind==="lookalike" && !guardConfirmed;
  // Leave a page the user does not trust: the typed password is blanked
  // first, then the tab goes back, or to about:blank when it has no history
  // (a link opened in a new tab), so "Go back" never leaves the form as it was.
  function leavePage(form=null){
    for(const field of q('input[type="password"]',form||document))try{valueset(field,"");}catch{}
    try{if(history.length>1)history.back();else location.replace("about:blank");}catch{}
  }
  // "Is this the right site?" (or, for the same name on another ending, the
  // softer "Is this the same account as ...?", remembered per origin pair).
  // "Go back" is the default; "Continue on <this host>" names the page the
  // user is really on (Ruling T4) and continues the interrupted action.
  function showGuard(v,proceed,target=null){
    const host=location.hostname;
    const soft=v.reason==="other-suffix" && !!v.matched;
    // v.matched is a saved host: shown in the frame only, masked in the page.
    const title=soft?secret(tr("content_same_account_title",v.matched),tr("content_same_account_title",MASK)):tr("content_guard_title");
    const text=soft?secret(tr("content_same_account_body",host,v.matched),tr("content_same_account_body",host,MASK))
      :v.matched?secret(tr("content_guard_body",host,v.matched),tr("content_guard_body",host,MASK)):tr("content_guard_body_mixed",host);
    guardOpen=true;
    panel(title,text,[
      {label:tr("content_guard_go_back"),primary:true,run:()=>{guardOpen=false;hidePanel();leavePage(target?.form||null);}},
      {label:soft?tr("content_same_account_yes"):tr("content_guard_continue",host),run:async()=>{
        guardConfirmed=true;guardOpen=false;hidePanel();
        if(soft && v.pair)await rememberSameAccount(v.pair);
        proceed?.();
      }}
    ],target);
  }
  // Review R1: the app classifies every save again after unlock. A save made
  // with no verdict here (a capture while the vault was locked) comes back as
  // "lookalike_site" with the verdict: ask the guard question, then retry
  // once with lookalike_confirmed; the app still warns in its own dialog.
  // A "same account" pair the user already confirmed retries at once.
  async function guardedSave(action,payload,op,stillValid,done){
    const response=await gestured(action,payload,op,stillValid);
    if(response?.error!=="lookalike_site" || payload.lookalike_confirmed)return done(response);
    const v=cleanVerdict({...response,ok:true});
    if(!v)return done({ok:false,error:"lookalike_site"});
    const retry=async()=>done(await gestured(action,{...payload,lookalike_confirmed:true},op,stillValid));
    if(v.reason==="other-suffix" && v.pair && (await rememberedPairs()).includes(v.pair))return retry();
    siteVerdict=v;verdictAt=Date.now();guardConfirmed=false;markIcons();
    showGuard(v,()=>{if(stillValid())void retry();});
  }
  document.addEventListener("focusin",e=>{
    if(!e.isTrusted || verdictFresh())return;
    const target=eventTarget(e);
    if(target instanceof HTMLInputElement && (target.type==="password" || icons.has(target) || target.autocomplete==="username"))void loadVerdict();
  },true);
  // Values the user typed (trusted input events), per field: the new-site
  // username check below runs only on a value the page did not set by script.
  const typedValues=new WeakMap();
  document.addEventListener("input",e=>{
    const target=eventTarget(e);
    if(e.isTrusted && target instanceof HTMLInputElement)typedValues.set(target,target.value);
  },true);
  // Ruling T4b: a new site asking for a username that is saved for another
  // site. Checked in the app, only on the user's own submit of a username the
  // user typed, once per document, and shown as a soft note (the submit goes
  // on). The page cannot ask: it cannot message the extension, and a value it
  // set by script, or a submit it fired itself, is never checked.
  let newSiteChecked=false;
  async function checkNewSiteUsername(form){
    if(newSiteChecked || siteVerdict?.kind!=="unknown" || !verdictFresh())return;
    if(navigator.userActivation && navigator.userActivation.hasBeenActive===false)return;
    const field=passwordForForm(form);
    const u=field&&usernameForSave(field);
    const username=u?.value||"";
    if(!username || typedValues.get(u)!==username)return;
    newSiteChecked=true;
    const r=await msg("new_site_username_browser",{username,user_gesture:true},{id:newId()});
    if(r?.ok!==true || r.elsewhere!==true || guardOpen)return;
    const host=location.hostname;
    panel(tr("content_new_site_title"),tr("content_new_site_body",host),[
      {label:tr("content_guard_go_back"),primary:true,run:()=>{hidePanel();leavePage(form.isConnected?form:null);}},
      {label:tr("content_guard_continue",host),run:hidePanel}
    ],field&&field.isConnected?field:null);
  }
  // A credential submit on a lookalike is held until the user answers. The
  // verdict must already be known (it is asked for when a login field gets
  // focus). This listener runs before the save capture's, so a held submit
  // is not captured and the page's own form handlers do not run. It is a
  // guard against plain form-post phishing and the LocalGateKeys save path,
  // not a wall: a page listener on window runs before it, and a hostile page
  // can read the password as it is typed or send it with form.submit() or
  // fetch, which fire no submit event. The warning is the defence there.
  function guardSubmit(e){
    if(!e.isTrusted)return;
    const form=eventTarget(e);
    if(!(form instanceof HTMLFormElement))return;
    const field=passwordForForm(form);
    if(!field)return;
    if(!guarded(siteVerdict)){void checkNewSiteUsername(form);return;}
    e.preventDefault();e.stopImmediatePropagation();
    const submitter=e.submitter instanceof HTMLElement && e.submitter.form===form?e.submitter:null;
    showGuard(siteVerdict,()=>{if(!form.isConnected)return;try{if(submitter)form.requestSubmit(submitter);else form.requestSubmit();}catch{}},field);
  }
  document.addEventListener("submit",guardSubmit,true);

  // Browser-only save/update detection. The submitted password is sent only to
  // the local native app, which keeps it in process RAM briefly. The page prompt
  // is shown only after the login surface appears to have succeeded/disappeared.
  let pendingAttempt=null, pendingTimer=null, lastPromptToken=null;
  // The capture the user just answered (Not now, Never, saved): a check that
  // was already in flight must not draw its prompt again.
  let closedToken=null;
  const captured=new WeakMap();

  function usernameForSave(field) {
    const root=field.form || field.getRootNode();
    const fields=q('input',root).filter(el=>el!==field && ["text","email","tel","hidden"].includes(el.type) && el.value);
    return fields.find(el=>el.autocomplete==="username") ||
      fields.find(el=>el.type==="email") ||
      // Hidden inputs named like "login_token" or "user_id" are not usernames.
      fields.find(el=>el.type!=="hidden" && el.name && /user|email|login/i.test(el.name)) ||
      fields.find(S.onTop) || null;
  }
  async function offerSave(field, explicit=false) {
    if(!S.onTop(field)||!field.value)return;
    const form=field.form;
    if(form&&!S.safeForm(form))return;
    const u=usernameForSave(field), username=u?.value||"", password=field.value, href=location.href;
    const verdict=await loadVerdict();
    if(guarded(verdict)){showGuard(verdict,()=>offerSave(field,explicit),field);return;}
    const savedGeneration=generation;
    const op={id:newId()};
    const check=await msg("check_browser",{username,password},op);
    if(savedGeneration!==generation || href!==location.href || !field.isConnected || field.value!==password)return;
    applyFeatures(check);
    // check.match is ignored: it says nothing a page may learn (audit M-3).
    if(!explicit && (!check.ok || check.prompt===false))return;
    // "exists" says only that the account is saved, never whether the
    // password matches; the desktop app compares after the Save click.
    const status=saveStatus(check.status), exists=status==="exists";
    const notice=noticeOf(check), full=status==="full" && !!notice;
    panel(exists?tr("content_save_update_title"):tr("content_save_title"),`${username||tr("content_no_username")}\n${notice||tr("content_confirm_in_app")}`,[
      ...(full?[]:[{label:exists?tr("content_save_update"):tr("content_save"),primary:true,run:async()=>{
        if(savedGeneration!==generation || href!==location.href || !S.onTop(field) || field.value!==password){hidePanel();return;}
        // The Save click is the trusted gesture: mint a nonce for this same
        // operation (same context) and present it with save_browser.
        await guardedSave("save_browser",{username,password},op,()=>savedGeneration===generation && href===location.href && field.isConnected,response=>{
          if(response.ok)showNoticeOrHide(response);else panel("LocalGateKeys",error(response),[{label:tr("content_close"),run:hidePanel}]);
        });
      }}]),{label:tr("content_not_now"),run:hidePanel}
    ],field);
  }
  function showNoticeOrHide(response){
    const notice=noticeOf(response);
    if(notice)panel("LocalGateKeys",notice,[{label:tr("content_close"),run:hidePanel}]);else hidePanel();
  }
  // The password a submit sets: a filled new-password field (sign-up, change
  // form) wins over the current one; new + confirm must agree, else nothing
  // is captured (never the old password as the new one).
  function passwordForForm(form=null) {
    const fields=q('input[type="password"]',form||document).filter(f=>f.value && S.onTop(f));
    const fresh=fields.filter(S.newPassword);
    if(fresh.length)return fresh.every(f=>f.value===fresh[0].value)?fresh[0]:null;
    return fields[fields.length-1] || null;
  }
  // Identifier-first logins: the username submitted on step one, kept in this
  // script's memory (and the worker's, per tab) for 5 minutes, same origin
  // only, and dropped once a capture uses it.
  const STEP_USERNAME_MS=300000;
  let stepUsername=null;
  function rememberStepUsername(form, target){
    if(!automaticSaveEnabled || logoutInProgress)return;
    if(form && q('input[type="password"]',form).some(S.onTop))return;
    const pool=form?q('input',form):(target instanceof HTMLInputElement?[target]:[]);
    const hits=pool.filter(el=>["text","email","tel"].includes(el.type) && el.value.trim() && S.onTop(el) &&
      (el.autocomplete==="username" || el.type==="email" || /user|email|login|account|identifier/i.test(`${el.name} ${el.id}`)));
    if(hits.length!==1)return;
    const username=hits[0].value.trim();if(username.length>512)return;
    stepUsername={origin:origin(),username,at:Date.now()};
    void msg("step_username_browser",{username},{id:newId()});
  }
  function changePasswordForm(form){
    const fields=q('input[type="password"]',form||document).filter(S.onTop);
    return fields.some(f=>(f.getAttribute("autocomplete")||"").trim().toLowerCase()==="current-password") && fields.some(S.newPassword);
  }
  async function recallStepUsername(){
    const local=stepUsername;stepUsername=null;
    const recalled=await msg("recall_username_browser",{},{id:newId()});
    if(local && local.origin===origin() && Date.now()-local.at<=STEP_USERNAME_MS)return local.username;
    return recalled?.ok && typeof recalled.username==="string"?recalled.username:"";
  }
  function associatedForm(control) {
    if(control instanceof HTMLButtonElement || control instanceof HTMLInputElement) {
      if(control.form)return control.form;
      const id=control.getAttribute("form");
      const scope=control.getRootNode();
      const byId=id && typeof scope.getElementById==="function"?scope.getElementById(id):null;
      if(byId instanceof HTMLFormElement)return byId;
    }
    return control.closest("form");
  }
  // The real (possibly shadow-internal) event target; events are retargeted
  // to the shadow host by the time they reach document listeners.
  function eventTarget(e){
    const path=typeof e.composedPath==="function"?e.composedPath():null;
    const first=path&&path.length?path[0]:e.target;
    return first instanceof Element?first:null;
  }
  function likelyLoginControl(control) {
    if(likelyLogoutControl(control))return false;
    if(control instanceof HTMLInputElement && control.type==="submit")return true;
    if(control instanceof HTMLButtonElement && (control.type||"submit")==="submit")return true;
    const label=(control.getAttribute("aria-label")||control.textContent||control.getAttribute("value")||"").trim();
    return H.isLoginControlLabel(label);
  }
  function schedulePendingChecks(delays=[500]) {
    if(!automaticSaveEnabled || logoutInProgress)return;
    clearTimeout(pendingTimer);
    const queue=[...delays];
    const next=()=>{
      if(!queue.length)return;
      pendingTimer=setTimeout(async()=>{if(!logoutInProgress)await showPendingSave();next();},queue.shift());
    };
    next();
  }
  // userInput: called from a trusted keydown (Enter) or pointerdown on the
  // sign-in control, which a page script cannot produce.
  async function captureSubmission(field,userInput=false) {
    if(!automaticPanels() || logoutInProgress)return;
    if(!(field instanceof HTMLInputElement) || field.type!=="password" || !field.value)return;
    const userActive=userInput || !(navigator.userActivation && navigator.userActivation.isActive===false);
    const form=field.form;if(form&&!S.safeForm(form))return;
    const verdict=siteVerdict||await loadVerdict();
    if(guarded(verdict)){if(!(guardOpen && panelShown()))showGuard(verdict,()=>captureSubmission(field,userInput),field);return;}
    const now=Date.now(), previous=captured.get(field);
    if(previous && previous.value===field.value && now-previous.at<1500)return;
    captured.set(field,{value:field.value,at:now});
    const u=usernameForSave(field);
    const recent=recentFilledCredential;
    let username=u?.value||"";
    if(!username && recent && recent.field===field && recent.form===field.form &&
       recent.origin===origin() && Date.now()-recent.at<=15000){
      username=recent.username;
    }
    // A change-password form (a field marked current-password next to a new
    // one) never takes a step username: an earlier "change email" or
    // newsletter form on the same site is not this login's name (finding L6).
    if(!username && !changePasswordForm(form))username=await recallStepUsername();
    // A password-only capture (change-password form) later lists this site's
    // saved logins in the update offer, so it is kept only for a submit the
    // user just made (transient activation where the engine reports it), not
    // for a script's requestSubmit long after a click (finding W-L2).
    if(!username && !userActive){if(captured.get(field)?.at===now)captured.delete(field);return;}
    pendingAttempt={field,form,href:location.href,at:now,token:null};
    const response=await msg("capture_browser",{username,password:field.value},{id:newId()});
    if(!response?.ok || !response.stored){pendingAttempt=null;if(response?.ok)watchSignInForPasskey(field,form,location.href);return;}
    pendingAttempt.token=response.pending_token||response.token||null;
    // Check quickly for SPA/form disappearance, then fall back to an explicit
    // tr("content_signin_question") prompt instead of leaving the credential pending
    // until an unrelated navigation such as logout.
    schedulePendingChecks([250,450,800,1400,2200,3500,5000]);
  }
  function visibleLoginSurface() {
    const fields=q('input[type="password"]').filter(f=>f.autocomplete!=="new-password" && S.onTop(f));
    if(!fields.length)return false;
    return fields.some(field=>{
      const form=field.form;
      if(form && S.visible(form))return true;
      const container=field.closest('form,[role="form"],main,section,div') || field.getRootNode();
      return q('button,input[type="submit"],input[type="button"],[role="button"]',container).some(c=>S.onTop(c)&&likelyLoginControl(c));
    });
  }
  function failureTextVisible() {
    const selectors='[role="alert"],[aria-live="assertive"],.error,.errors,.error-message,.alert-danger,[data-error]';
    return q(selectors).some(el=>S.visible(el) && H.hasFailureText(el.textContent||""));
  }
  function loginFailureVisible() {
    const inputs=q('input[aria-invalid="true"],input:invalid').filter(S.onTop);
    if(inputs.length)return true;
    return failureTextVisible();
  }
  // A password-only capture (change-password form) is judged by the submitted
  // form only: other forms of a settings page ("change email") keep their
  // empty required fields, and an SPA clears its own form after a successful
  // change, so an empty required field is no failure here. A field the site
  // marks invalid (aria-invalid, a custom or format error) or a visible error
  // message still is. After a navigation (no submitted form in this document)
  // only this page's password fields count.
  function passwordChangeFailureVisible() {
    const form=pendingAttempt?.form;
    const fields=form && form.isConnected?q("input",form):q('input[type="password"]');
    const flagged=fields.some(f=>S.onTop(f) && (f.getAttribute("aria-invalid")==="true" ||
      (f.validity && !f.validity.valid && !f.validity.valueMissing)));
    return flagged || failureTextVisible();
  }
  function loginOutcome(response,failureVisible=loginFailureVisible) {
    if(document.visibilityState!=="visible")return "wait";
    if(failureVisible())return "failure";
    const now=Date.now();
    if(pendingAttempt){
      const age=now-pendingAttempt.at;
      if(age<450)return "wait";
      const urlChanged=location.href!==pendingAttempt.href;
      const fieldGone=!pendingAttempt.field?.isConnected || !S.onTop(pendingAttempt.field);
      const formGone=!!pendingAttempt.form && (!pendingAttempt.form.isConnected || !S.visible(pendingAttempt.form));
      // The original login surface disappearing is the strongest same-document
      // success signal. A same-origin URL transition is also meaningful once no
      // visible error is present.
      if(fieldGone || formGone || urlChanged)return "success";
      // Some SPAs retain a hidden/repurposed login tree after authentication.
      // Do not wait indefinitely: ask the user explicitly after a short window.
      if(age>=4200)return "uncertain";
      return "wait";
    }
    // New document after a normal navigation: DOM references from the submitted
    // page no longer exist. If there is no visible login surface, prompt quickly.
    const documentAge=now-pageStartedAt;
    if(documentAge<450)return "wait";
    if(!visibleLoginSurface())return "success";
    const nativeAge=Number.isFinite(response?.age_ms)?response.age_ms:0;
    if(documentAge>=3600 || nativeAge>=6000)return "uncertain";
    return "wait";
  }
  async function showPendingSave(force=false) {
    if(!automaticPanels() || logoutInProgress)return;
    const response=await msg("pending_browser",{}, {id:newId()});
    if(logoutInProgress || !automaticPanels())return;
    const token=response?.pending_token||response?.token;
    if(!response?.ok || !response.pending || !token || token===closedToken)return;
    // A capture typed on another origin of this site (sign-in redirect): the
    // background names only that origin, never the username, to this page.
    const handoff=response.handoff===true && typeof response.origin==="string" && response.origin!==origin();
    // The app keeps a password-only capture as "update_only": it can only
    // update a saved login the user picks (entry_id), never create one.
    const updateOnly=response.status==="update_only";
    // This page's list is for its own origin, not the one the capture was
    // typed on: no offer for a handed-off password-only capture (it expires).
    if(handoff && updateOnly)return;
    if(!handoff && (updateOnly || typeof response.username!=="string" || !response.username.trim())){
      // No username anywhere (a change-password form): the user may pick one
      // of this site's saved logins to update. Never guessed: with no list
      // (older app, locked, none saved) the capture is dropped as before.
      // A failure reading only waits: a later check decides, and the capture
      // still ends with its expiry. A change the site visibly refused never
      // reaches the offer, since every check then reads "failure".
      const outcome=force?"uncertain":loginOutcome(response,passwordChangeFailureVisible);
      if(outcome==="wait" || outcome==="failure")return;
      // Already offered: do not list the site's logins again on every check.
      if(lastPromptToken===token && panelShown())return;
      const logins=await siteLogins();
      if(token===closedToken || logoutInProgress || (lastPromptToken===token && panelShown()))return;
      // Finding L2: the page sees the same host (size, attributes, timing,
      // lifetime) whether the site has 0, 1 or several saved logins, or the
      // app could not list them (locked, probe budget): with nothing to
      // offer, a neutral note in the same fixed-size frame. The capture is
      // kept and answered exactly like an offer (Close = Not now).
      lastPromptToken=token;
      if(logins?.length)offerPasswordUpdate(token,logins);else offerNoUpdate(token);
      return;
    }
    const recent=recentFilledCredential;
    if(!handoff && recent && response.username===recent.username && recent.origin===origin() &&
       Date.now()-recent.at<=30000){
      pendingAttempt=null;lastPromptToken=null;hidePanel();
      void msg("clear_pending_browser",{}, {id:newId()});
      return;
    }
    const outcome=force?"uncertain":loginOutcome(response);
    if(outcome==="wait" || outcome==="failure")return;
    if(lastPromptToken===token && panelShown())return;
    const verdict=await loadVerdict();
    if(guarded(verdict)){if(!(guardOpen && panelShown()))showGuard(verdict,()=>{lastPromptToken=null;void showPendingSave(force);});return;}
    lastPromptToken=token;
    // A capture made while the vault was locked has no trustworthy account
    // classification yet.  The native save path reclassifies after unlock;
    // keep that deferred state visible instead of calling it a new login.
    const status=saveStatus(response.status);
    const deferred=status==="deferred" || status==="unknown";
    const exists=!deferred && status==="exists";
    const uncertain=outcome==="uncertain";
    // Safari: a full free vault answers status "full" with a notice; the
    // panel then shows the notice and offers no Save button.
    const notice=noticeOf(response), full=status==="full" && !!notice;
    // A sign-in that moved to another subdomain of the same site: the login
    // is saved for the origin it was typed on, so the panel names that one.
    const savedFor=typeof response.origin==="string" && /^https?:\/\/[^/]+$/.test(response.origin) && response.origin.length<=300?response.origin:origin();
    const title=deferred
      ? tr("content_unlock_review_title")
      : full?tr("content_save_title"):(uncertain?tr("content_signin_question"):(exists?tr("content_save_update_title"):tr("content_save_title")));
    const who=handoff?tr("content_login_typed_on",savedFor):(response.username||tr("content_no_username"));
    const text=notice
      ? `${who}\n${notice}`
      : uncertain
      ? `${who}\n${tr("content_save_uncertain")}`
      : deferred
        ? `${who}\n${tr("content_save_deferred")}`
        : exists
          ? `${who}\n${tr("content_save_exists")}`
          : `${who}\n${tr("content_save_new")}`;
    // In the extension frame the username is an editable field and, when the
    // login exists and the site has more than one saved login, the user can
    // pick which one to update. Both stay in the frame; the in-page fallback
    // keeps the read-only text. Safari cannot list the site's logins (its
    // background answers site_logins_browser unsupported): no choice there.
    const editable=frameMode && !handoff && !full && !deferred;
    const listed=editable && exists?await siteLogins():null;
    if(lastPromptToken!==token)return;
    const statusText=notice||(uncertain?tr("content_save_uncertain"):deferred?tr("content_save_deferred"):exists?tr("content_save_exists"):tr("content_save_new"));
    const view=panel(title,editable?secret(statusText,text):text,[],null,savedFor);
    // One height for every save prompt (finding L2): the page must not learn
    // from the host's size whether the login exists or how many are listed.
    view.fixed=true;
    if(editable)view.add({kind:"input",label:tr("content_username_label"),value:secret(response.username,"")});
    if(listed && listed.length>1){
      view.add({kind:"note",label:secret(tr("content_update_which"),"")});
      for(const l of listed)view.add({kind:"check",group:"target",key:"",entryId:l.entry_id,label:secret(loginName(l),MASK)});
    }
    if(!full)view.add({label:deferred?tr("content_unlock_review"):(exists?tr("content_save_update"):tr("content_save_login")),primary:true,run:async(ctx={})=>{
      // One operation id for begin_gesture_browser and save_pending_browser:
      // the nonce is bound to the request context, which includes it.
      const payload={pending_token:token};
      const edited=typeof ctx.value==="string"?ctx.value.trim():"";
      if(editable && edited && edited!==response.username)payload.username=edited;
      const chosen=view.rows.find(r=>r.kind==="check" && r.group==="target" && r.checked);
      if(chosen)payload.entry_id=chosen.entryId;
      await guardedSave("save_pending_browser",payload,{id:newId()},()=>true,saved=>{
        if(saved.ok){closedToken=token;pendingAttempt=null;lastPromptToken=null;showNoticeOrHide(saved);if(!panelShown() && !uncertain && !deferred)void maybePasskeyHint();}
        else panel("LocalGateKeys",error(saved),[{label:tr("content_close"),run:hidePanel}]);
      });
    }});
    for(const action of [{label:tr("content_not_now"),run:()=>{closedToken=token;msg("discard_pending_browser",{pending_token:token},{id:newId()});pendingAttempt=null;lastPromptToken=null;hidePanel();}},
      {label:tr("content_never_site"),run:async()=>{
        closedToken=token;msg("discard_pending_browser",{pending_token:token},{id:newId()});pendingAttempt=null;lastPromptToken=null;hidePanel();
        // The worker appends (single writer, no lost entries across tabs).
        const done=await msg("never_site_browser",{},{id:newId()});
        if(done?.ok)return;
        const stored=await api.storage.local.get({[automaticOriginKey]:[]});
        const blocked=Array.isArray(stored[automaticOriginKey])?stored[automaticOriginKey]:[];
        if(!blocked.includes(origin()))await api.storage.local.set({[automaticOriginKey]:[...blocked,origin()]});
      }}
    ])view.add(action);
  }
  // This site's saved logins (title and username, no secrets), from the app,
  // for the top frame only. null when the app cannot list them (an older app
  // answers unsupported_request, a locked vault answers locked).
  async function siteLogins(){
    if(window!==window.top)return null;
    const r=await msg("site_logins_browser",{},{id:newId()});
    return r?.ok===true && Array.isArray(r.logins)?r.logins.filter(l=>l && typeof l.entry_id==="string"):null;
  }
  function loginName(l){
    const title=typeof l.title==="string"?l.title.trim():"", user=typeof l.username==="string"?l.username.trim():"";
    return title && user && title!==user?`${title} (${user})`:(title||user||tr("content_no_username"));
  }
  // A password set on a form without any username field (change password):
  // "Update password for <login>" with the site's one saved login, or a
  // choice when there are several. Nothing is saved until the user clicks.
  // Only entry_id is sent: the app keeps the chosen login's own username and
  // answers entry_required / entry_not_for_site, shown as readable errors.
  function offerPasswordUpdate(token,logins){
    const save=l=>async()=>{
      await guardedSave("save_pending_browser",{pending_token:token,entry_id:l.entry_id},{id:newId()},()=>true,saved=>{
        if(saved.ok){closedToken=token;pendingAttempt=null;lastPromptToken=null;showNoticeOrHide(saved);}
        else panel("LocalGateKeys",error(saved),[{label:tr("content_close"),run:hidePanel}]);
      });
    };
    const notNow=declineUpdate(token);
    if(logins.length===1){
      const l=logins[0];
      // The list height too (finding L2): sized to its text, the host would
      // show the page the length of the login's name.
      panel(tr("content_update_pw_title"),tr("content_update_pw_one"),[
        {label:secret(tr("content_update_pw_for",loginName(l)),tr("content_update_pw_for",MASK)),primary:true,run:save(l)},
        {label:tr("content_not_now"),run:notNow}]).fixed=true;
      return;
    }
    const view=panel(tr("content_update_pw_title"),tr("content_update_pw_many"),[]);
    for(const l of logins)view.add({kind:"account",label:secret(typeof l.title==="string" && l.title.trim()?l.title:loginName(l),MASK),
      secondary:secret(l.username||tr("content_no_username"),""),action:tr("content_update_pw_action"),run:save(l)});
    view.add({label:tr("content_not_now"),run:notNow});
    view.fixed=true;
  }
  function declineUpdate(token){
    return ()=>{closedToken=token;msg("discard_pending_browser",{pending_token:token},{id:newId()});pendingAttempt=null;lastPromptToken=null;hidePanel();};
  }
  // Nothing to update (no saved login, or the app could not list them): the
  // same fixed host as the offer, with a short note and Close. No passkey
  // note follows on this path, so its presence tells the page nothing either.
  function offerNoUpdate(token){
    panel(tr("content_update_pw_title"),tr("content_update_pw_none"),[{label:tr("content_close"),run:declineUpdate(token)}]).fixed=true;
  }
  // ---- Passkey hint. After a password sign-in that worked, on a site the
  // app's passkey directory lists as supporting passkeys and for which the
  // vault holds no passkey, a one-time note says so. It creates nothing.
  // Needs the app's passkey_hint_browser; an older app answers
  // unsupported_request and nothing is shown.
  const passkeyNeverKey="passkey_hint_never_origins";
  let passkeyHintDone=false;
  async function maybePasskeyHint(){
    if(passkeyHintDone || !automaticPanels() || window!==window.top || panelShown() || logoutInProgress || loginFailureVisible())return;
    passkeyHintDone=true;
    try{const stored=await api.storage.local.get({[passkeyNeverKey]:[]});if(Array.isArray(stored[passkeyNeverKey]) && stored[passkeyNeverKey].includes(origin()))return;}catch{return;}
    const r=await msg("passkey_hint_browser",{},{id:newId()});
    if(r?.ok!==true || r.supported!==true || r.has_passkey!==false || panelShown())return;
    panel(tr("content_passkey_title"),tr("content_passkey_body"),[
      {label:tr("content_not_now"),run:hidePanel},
      {label:tr("content_passkey_never"),run:async()=>{
        hidePanel();
        try{const stored=await api.storage.local.get({[passkeyNeverKey]:[]});const list=Array.isArray(stored[passkeyNeverKey])?stored[passkeyNeverKey]:[];
          if(!list.includes(origin()))await api.storage.local.set({[passkeyNeverKey]:[...list,origin()].slice(-500)});}catch{}
      }}]);
  }
  // A sign-in with a login the vault already has (nothing to save): watch the
  // same document briefly for the login form going away.
  function watchSignInForPasskey(field,form,href){
    const check=()=>{
      if(passkeyHintDone)return;
      const gone=!field.isConnected || !S.onTop(field) || (!!form && (!form.isConnected || !S.visible(form))) || location.href!==href;
      if(gone && !loginFailureVisible())void maybePasskeyHint();
    };
    setTimeout(check,1500);setTimeout(check,4000);
  }
  function likelyLogoutControl(control) {
    const label=["aria-label","title","value","data-testid","data-qa","name"]
      .map(name=>control.getAttribute(name)||"").concat(control.textContent||"").join(" ").trim();
    return H.isLogoutLabel(label) || H.isLogoutHref(control.getAttribute("href")||"");
  }
  async function discardPendingForLogout() {
    if(!automaticSaveEnabled)return;
    logoutInProgress=true;
    clearTimeout(pendingTimer);pendingTimer=null;
    pendingAttempt=null;lastPromptToken=null;hidePanel();
    const clear=msg("clear_pending_browser",{}, {id:newId()});
    const response=await msg("pending_browser",{}, {id:newId()});
    const token=response?.pending_token||response?.token;
    if(response?.ok && response.pending && token)await msg("discard_pending_browser",{pending_token:token},{id:newId()});
    await clear;
  }
  document.addEventListener("input",e=>{
    const target=eventTarget(e);
    if(e.isTrusted && recentFilledCredential &&
       (recentFilledCredential.field===target || recentFilledCredential.usernameField===target)){
      recentFilledCredential=null;
    }
  },true);
  function onSubmit(e){
    if(!automaticSaveEnabled)return;
    if(e.submitter instanceof Element && likelyLogoutControl(e.submitter)){
      void discardPendingForLogout();
      return;
    }
    const target=eventTarget(e);
    // form.requestSubmit() fires a trusted submit event, so a page script
    // could test password guesses through the save prompt. A page the user
    // never clicked or typed in (sticky activation, where the engine reports
    // it) gets no capture; the background also rate-limits these checks.
    if(navigator.userActivation && navigator.userActivation.hasBeenActive===false)return;
    if(e.isTrusted && target instanceof HTMLFormElement){const f=passwordForForm(target);if(f)captureSubmission(f);else rememberStepUsername(target,null);}
  }
  document.addEventListener("submit",onSubmit,true);
  document.addEventListener("keydown",e=>{
    if(!automaticSaveEnabled)return;
    if(!e.isTrusted || e.key!=="Enter")return;
    const target=eventTarget(e);
    const logout=target?.closest('a,button,input[type="submit"],input[type="button"],[role="button"],[role="menuitem"]');
    if(logout && likelyLogoutControl(logout)){void discardPendingForLogout();return;}
    const form=target?.closest("form");
    const f=passwordForForm(form)||(!form?passwordForForm():null);if(f)captureSubmission(f,true);
    else if(!(navigator.userActivation && navigator.userActivation.hasBeenActive===false))rememberStepUsername(form,target);
  },true);
  document.addEventListener("pointerdown",e=>{
    if(!automaticSaveEnabled)return;
    const target=eventTarget(e);
    if(!e.isTrusted || !target)return;
    const logout=target.closest('a,button,input[type="submit"],input[type="button"],[role="button"],[role="menuitem"]');
    if(logout && likelyLogoutControl(logout)){void discardPendingForLogout();return;}
  },true);
  document.addEventListener("pointerdown",e=>{
    if(!automaticSaveEnabled)return;
    const target=eventTarget(e);
    if(!e.isTrusted || !target)return;
    const control=target.closest('button,input[type="submit"],input[type="button"],[role="button"]');
    if(!control || !likelyLoginControl(control))return;
    const form=associatedForm(control);
    const f=passwordForForm(form)||(!form?passwordForForm():null);if(f)captureSubmission(f,true);else if(form)rememberStepUsername(form,null);
  },true);
  // New same-origin documents and SPAs can recover a pending submission without
  // the user first opening the extension popup.
  const automaticSaveLoaded=loadAutomaticSaveSetting();
  // Safari: a form-post login lands on a new document while the background
  // still holds the capture; its tabs.onUpdated nudge can be missed, so the
  // top frame asks on its own once the setting is known.
  if(safariBackground() && window===window.top)void automaticSaveLoaded.then(()=>schedulePendingChecks([300,900,1800,3000]));
  // Save banners contain no stored-vault password and pending native values expire.
  setInterval(()=>{if(!active && !cardActive && panelShown())hidePanel();},90000);
  api.runtime.onMessage.addListener((r,s,reply)=>{
    if(s.id!==api.runtime.id || !r || typeof r!=="object")return false;
    // The panel frame's requests, relayed by the service worker. Only the
    // frame that holds the current token gets an answer.
    if(r.command==="ui"){const out=onUi(r);if(out)reply(out);return false;}
    // The popup's "Why no icon?" note names another site's frame only when
    // that frame holds a password field. Yes/no only, nothing else.
    if(r.command==="has_password_field"){reply({ok:true,password:q('input[type="password"]').some(S.onTop)});return false;}
    if(r.command==="site_state"){void loadVerdict().then(verdict=>reply({ok:true,verdict}),()=>reply({ok:true,verdict:null}));return true;}
    if(r.command==="check_pending_save") {void automaticSaveLoaded.then(()=>{if(automaticSaveEnabled)schedulePendingChecks([80,500,1400]);});reply({ok:true});return false;}
    if(!fillEnabled && ["fill_current","fill_identity","fill_card","fill_totp","generate_new"].includes(r.command)){reply({ok:false,error:"unsupported"});return false;}
    if(r.command==="fill_current") {
      const entryId=r.entry_id===undefined?null:r.entry_id;
      if(entryId!==null && !validText(entryId)){reply({ok:false,error:"not_found"});return false;}
      // The popup's fill also works where inline icons are off for this site.
      const f=Array.from(icons.keys()).find(S.onTop) || (inlineBlocked?q('input[type="password"]').find(x=>S.onTop(x) && !S.newPassword(x)):null);
      if(f)begin(f,false,entryId);reply({ok:!!f});return false;
    }
    if(r.command==="fill_identity") {
      const f=Array.from(identityIcons.keys()).find(S.onTop);
      if(f)beginIdentity(f);
      reply(f?{ok:true}:{ok:false,error:"identity_not_found"});return false;
    }
    if(r.command==="fill_card") {
      const f=Array.from(cardIcons.keys()).find(S.onTop);
      if(f)beginCard(f);
      reply(f?{ok:true}:{ok:false,error:"card_form_not_found"});return false;
    }
    if(r.command==="fill_totp") {
      const f=Array.from(otpIcons.keys()).find(S.onTop);if(f)beginTotp(f);reply({ok:!!f});return false;
    }
    if(r.command==="save_current"){
      const f=passwordForForm();if(f)offerSave(f,true);reply({ok:!!f});return false;
    }
    if(r.command==="generate_new") {
      const fields=q('input[type="password"]').filter(f=>S.onTop(f) && S.newPassword(f));
      if(!fillGenerated(fields,r.value)){reply({ok:false,message:tr("content_no_new_password")});return false;}
      reply({ok:true});return false;
    }
    return false;
  });
})();
