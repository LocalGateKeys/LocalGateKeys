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
  const S=typeof globalThis.LGKLoginSafety?.snapshot==="function"?globalThis.LGKLoginSafety:null;
  const H=typeof globalThis.LGKHeuristics?.isSignInLabel==="function"?globalThis.LGKHeuristics:null;
  if (!S || !H) return;
  Object.defineProperty(globalThis,LOADED,{value:true});
  const icons=new Map();
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
    if(!nonce && gestureInFlight()){nonce=await mintNonce(op);if(!stillValid())return {ok:false,error:"destination_changed",message:"The page changed. Click again."};}
    let response=await msg(action,{...payload,user_gesture:true,...(nonce?{gesture_nonce:nonce}:{})},op);
    if((response.error==="gesture_nonce_invalid" || response.error==="gesture_nonce_required") && gestureInFlight() && stillValid()){
      nonce=await mintNonce(op);
      if(nonce && stillValid()) response=await msg(action,{...payload,user_gesture:true,gesture_nonce:nonce},op);
    }
    return response;
  }
  // Sites where the user turned the save prompt off; all others ask by default.
  const automaticOriginKey="automatic_save_blocked_origins";
  function applyAutomaticSaveSetting(origins){
    const enabled=!(Array.isArray(origins) && origins.includes(origin()));
    automaticSaveEnabled=enabled;
    if(!enabled){
      clearTimeout(pendingTimer);
      pendingAttempt=null;
      lastPromptToken=null;
      hidePanel();
    }
  }
  async function loadAutomaticSaveSetting(){
    try{
      const result=await api.storage.local.get({[automaticOriginKey]:[]});
      applyAutomaticSaveSetting(result[automaticOriginKey]);
    }catch{automaticSaveEnabled=false;}
  }
  api.storage.onChanged.addListener((changes,area)=>{
    if(area==="local" && changes[automaticOriginKey])applyAutomaticSaveSetting(changes[automaticOriginKey].newValue);
  });
  const styles=`
    :host{all:initial;} .panel{box-sizing:border-box;width:320px;max-height:400px;overflow:auto;background:#081321;border:1px solid #24405e;border-radius:14px;color:#eef5ff;font:13px/1.5 "Segoe UI",system-ui,sans-serif;box-shadow:0 16px 48px #0009;padding:14px;}
    h3{font-size:14px;margin:0 0 6px;} p{margin:6px 0 12px;color:#b3c6d9;overflow-wrap:anywhere;} .origin{font-size:11px;color:#83cfe4;}
    button{font:inherit;border:1px solid #33516f;border-radius:10px;background:#13253a;color:#f5faff;padding:8px 12px;cursor:pointer;margin:4px 6px 0 0;} button:hover{background:#1c3450;} button:focus-visible{outline:2px solid #60bbff;outline-offset:2px;}
    .account{display:block;box-sizing:border-box;width:100%;text-align:left;margin:6px 0;} .account span{display:block;overflow-wrap:anywhere;} .secondary{font-size:11px;color:#a5bad0;} .match{color:#d8b86a;} .account.has-logo{display:flex;align-items:center;gap:10px;} .account .logo{display:grid;place-items:center;flex:0 0 auto;width:28px;height:28px;border-radius:7px;} .logo svg{width:16px;height:16px;display:block;} .account .text{flex:1;min-width:0;} .primary{background:#326ef0;border-color:#326ef0;} .hidden{display:none;}
    .check{display:flex;align-items:center;gap:8px;} .check .tick{display:inline-grid;place-items:center;width:16px;height:16px;flex:0 0 auto;border:1px solid #5b7a9c;border-radius:4px;font-size:11px;} .check[aria-checked="true"] .tick{background:#326ef0;border-color:#326ef0;} .note{font-size:11px;color:#d8b86a;margin:4px 0 0;}
    .panel::-webkit-scrollbar{width:8px}.panel::-webkit-scrollbar-thumb{background:#314967;border-radius:8px}.panel::-webkit-scrollbar-track{background:#0a1625}
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
  function place(host,box,raise=false){
    const px=v=>v==null?"auto":`${v}px`;
    pin(host,{display:"block",width:px(box.width),height:box.height==null?"auto":px(box.height),left:px(box.left),top:px(box.top),right:px(box.right),bottom:px(box.bottom)});
    placed.set(host,{...box});
    toTopLayer(host,raise);
  }
  function hideHost(host){if(host)host.style.setProperty("display","none","important");}
  const noEffect=v=>v==null || v==="" || v==="none";
  // Longhands only: a serialised `mask` shorthand is not "none" in every engine.
  function untouched(s){
    return s.visibility==="visible" && Number(s.opacity)>=1 &&
      ["transform","translate","rotate","scale","filter","clipPath","maskImage","webkitMaskImage"].every(k=>noEffect(s[k])) &&
      (noEffect(s.mixBlendMode) || s.mixBlendMode==="normal");
  }
  function ownHosts(){
    const out=new Set(panelHost?[panelHost]:[]);
    for(const map of [icons,otpIcons,cardIcons,identityIcons])for(const {host} of map.values())out.add(host);
    return out;
  }
  // A page element in the top layer (its own popover, modal dialog or
  // fullscreen element) can sit above ours, even with pointer-events:none
  // that elementFromPoint does not see.
  function topLayerRival(rect){
    const ours=ownHosts();
    for(const selector of [":popover-open","dialog:modal",":fullscreen"]){
      let found=[];try{found=S.queryAll(selector);}catch{continue;}
      for(const el of found){
        if(ours.has(el))continue;
        const r=el.getBoundingClientRect();
        if(r.right>rect.left && r.left<rect.right && r.bottom>rect.top && r.top<rect.bottom)return true;
      }
    }
    return false;
  }
  function hostIntact(host,e){
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
      // Pointer clicks carry the point; keyboard activation (detail 0, no
      // coordinates) is checked at the centre of the host.
      const pointer=e.detail>0 || e.clientX!==0 || e.clientY!==0;
      const x=pointer?e.clientX:r.left+r.width/2, y=pointer?e.clientY:r.top+r.height/2;
      if(x<r.left-1 || x>r.right+1 || y<r.top-1 || y>r.bottom+1 || x<0 || y<0 || x>=innerWidth || y>=innerHeight)return false;
      if(document.elementFromPoint(x,y)!==host)return false;
      return !topLayerRival(r);
    }catch{return false;}
  }
  const TAMPERED="This page hid, moved or covered a LocalGateKeys button, so the click was ignored.";
  // Every click on a LocalGateKeys button goes through here: trusted events
  // only, and only while the host is intact. A tampered click cancels every
  // flow in progress; the notice contains no vault data.
  function uiClick(e,host){
    if(!e.isTrusted)return false;
    if(hostIntact(host,e))return true;
    e.preventDefault();e.stopPropagation();
    reset(TAMPERED);
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
      .then(response=>response || {ok:false,error:"connection_lost",message:"Reload this page after updating the extension."})
      .catch(()=>({ok:false,error:"connection_lost",message:"Reload the extension and this page."}));
  }
  // The panel host is in the document only while the panel is shown: hidden,
  // it is detached (not left in place with display:none), so a page cannot
  // poll a node's style to learn whether a save prompt appeared. Its content
  // lives in a closed shadow root.
  function panel(title, text, actions=[], target=null, siteOrigin=origin()) {
    if (!panelHost) {
      panelHost=uiHost(PANEL_ATTR,{"z-index":"2147483647",width:"320px"});
      panelShadow=panelHost.attachShadow({mode:"closed"});
    }
    if (!panelHost.isConnected) document.documentElement.appendChild(panelHost);
    panelShadow.replaceChildren();
    const style=document.createElement("style");style.textContent=styles;
    const box=document.createElement("section");box.className="panel";box.setAttribute("role","dialog");box.setAttribute("aria-label",title);
    const head=document.createElement("h3");head.textContent=title;box.append(head);
    const site=document.createElement("div");site.className="origin";site.textContent=siteOrigin;box.append(site);
    const p=document.createElement("p");p.textContent=text;box.append(p);
    for(const action of actions) {
      const b=document.createElement("button");b.type="button";b.textContent=action.label;b.className=action.primary?"primary":"";
      b.addEventListener("click",e=>{if(!uiClick(e,panelHost))return;e.preventDefault();e.stopPropagation();noteGesture();action.run();});box.append(b);
    }
    panelShadow.append(style,box);
    if(target && S.visible(target)) {
      const r=target.getBoundingClientRect();
      place(panelHost,{width:320,left:Math.round(Math.max(8,Math.min(innerWidth-328,r.right-320))),top:Math.round(Math.max(8,Math.min(innerHeight-220,r.bottom+8)))},true);
    } else place(panelHost,{width:320,right:18,bottom:18},true);
    return box;
  }
  function panelShown(){return !!panelHost && panelHost.isConnected;}
  function hidePanel(){
    if(panelHost?.isConnected){try{if(panelHost.matches(":popover-open"))panelHost.hidePopover();}catch{}panelHost.remove();}
    if(panelHost)placed.delete(panelHost);
    panelShadow?.replaceChildren();
  }
  function resetIdentity(reason=false) {
    if(identityActive?.approval) msg("cancel_identity_browser",{approval:identityActive.approval,identity_protocol:1},identityActive);
    identityActive=null;hidePanel();
    for(const {button} of identityIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");button.title="Fill identity with LocalGateKeys";}
    if(reason) panel("LocalGateKeys",reason,[{label:"Close",run:hidePanel}]);
  }
  function reset(reason=false) {
    resetIdentity();
    resetCard();
    resetTotp();
    generation++;
    if(active?.grant) msg("cancel_browser",{grant:active.grant},active);
    if(active){active.nonce=null;active.nonceExpiresAt=0;}
    active=null; clearInterval(statusTimer);statusTimer=null; hidePanel();
    for(const {button} of icons.values()) {button.disabled=false;button.setAttribute("aria-busy","false");button.title="Fill with LocalGateKeys";}
    if(reason) panel("LocalGateKeys",reason,[{label:"Close",run:hidePanel}]);
  }
  function valid(op){return active===op && generation===op.generation && S.unchanged(op.ctx);}
  function itemLimitText(limit){return `Your free LocalGateKeys holds ${Number.isInteger(limit)&&limit>0?limit:4} items. Upgrade to Pro for unlimited.`;}
  function error(response){return response?.message || (response?.error==="item_limit"?itemLimitText(response.limit):"") || ({user_cancelled:"Unlock or confirmation cancelled.",gesture_nonce_invalid:"The click expired or belongs to another page. Click again.",gesture_nonce_required:"Update the browser extension and reload this page.",user_gesture_required:"Start this action from the extension or an in-page LocalGateKeys button.",not_found:"No saved login for this site.",session_changed:"Vault/profile changed. Click the icon again.",fill_disabled:"Filling is disabled for this login.",totp_not_found:"No saved login for this exact site has a 2FA setup key.",card_not_found:"No payment card is saved in this profile.",invalid_card_fields:"Choose only the reviewed card fields.",invalid_approval:"The approval is invalid or expired. Start again."}[response?.error] || "Could not complete this request. Open Connections in LocalGateKeys.");}
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
    const hint=[field.name,field.id,field.getAttribute("aria-label"),field.getAttribute("placeholder")].filter(Boolean).join(" ").toLowerCase();
    const checks=[
      [/\b(first|given)\s*name\b/,"given_name"],[/\b(middle)\s*name\b/,"middle_name"],[/\b(last|family)\s*name\b/,"family_name"],
      [/\b(full|display)\s*name\b/,"name"],[/\b(company)\b/,"company"],[/\b(organization|organisation)\b/,"organization"],[/\b(job|role|title)\b/,"job_title"],
      [/\b(e[- ]?mail)\b/,"email"],[/\b(phone|mobile|tel)\b/,"phone"],[/\b(address|street)\b/,"address"],
      [/\b(city|town)\b/,"city"],[/\b(state|province|region)\b/,"state"],[/\b(zip|postal)\b/,"postal_code"],[/\bcountry\b/,"country"],
      [/\b(website|url|site)\b/,"website"]
    ];
    return checks.find(([pattern])=>pattern.test(hint))?.[1] || null;
  }
  function identitySnapshot(field){
    if(!identityFieldName(field) || !S.onTop(field))throw new Error("The identity field is hidden, covered, or unsupported.");
    const form=field.form;if(form&&!S.safeForm(form))throw new Error("The form points to another origin.");
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
  function finishIdentity(op){if(identityActive===op){identityActive=null;hidePanel();}for(const {button} of identityIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");button.title="Fill identity with LocalGateKeys";}}
  async function releaseIdentity(op){
    if(identityActive!==op || !identityUnchanged(op.ctx))return resetIdentity();
    const response=await msg("release_identity_browser",{identity_protocol:1,approval:op.approval,entry_id:op.entryId,revision:op.revision,fields:op.fields},op);
    if(identityActive!==op || !identityUnchanged(op.ctx)){blankValues(response);return resetIdentity();}
    if(!response.ok){blankValues(response);resetIdentity();return panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}],op.ctx.field);}
    try{
      if(!Array.isArray(response.fields) || response.fields.length!==op.fields.length || !response.values ||
         response.fields.some(field=>!op.fields.includes(field) || typeof response.values[field]!=="string"))throw new Error("The approved identity fields changed.");
      // The field checklist is done; it must not cover (and so block) the fields it fills.
      hidePanel();
      const root=op.ctx.form||document;const targets={};
      for(const field of op.fields){const found=identityTargets(field,root);if(found.length!==1)throw new Error("The page has a missing or ambiguous identity field.");targets[field]=found[0];}
      if(!identityUnchanged(op.ctx))throw new Error("The identity form changed before filling.");
      for(const field of op.fields){if(!S.onTop(targets[field]))throw new Error("An approved identity field is no longer visible.");identityValueSet(targets[field],response.values[field]);}
      finishIdentity(op);
    }catch(e){resetIdentity();panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}],op.ctx.field);}
    finally{blankValues(response);}
  }
  function showIdentityFields(op,choice){
    op.entryId=choice.entry_id;op.revision=choice.revision;
    const allowed=choice.fields.filter(field=>field!=="template_id");
    const initial=identityFieldName(op.ctx.field);const selected=new Set(allowed.includes(initial)?[initial]:[]);
    const box=panel("Choose identity fields",`Profile: ${choice.title}\nOrigin: ${origin()}`,[],op.ctx.field);
    const buttons=new Map();
    for(const field of allowed){const button=document.createElement("button");button.type="button";button.className="account";button.textContent=(selected.has(field)?"✓ ":"")+field;
      button.onclick=e=>{if(!uiClick(e,panelHost))return;if(selected.has(field))selected.delete(field);else selected.add(field);button.textContent=(selected.has(field)?"✓ ":"")+field;};box.append(button);buttons.set(field,button);}
    const approve=document.createElement("button");approve.type="button";approve.className="primary";approve.textContent="Review and approve";
    approve.onclick=async e=>{if(!uiClick(e,panelHost))return;if(!selected.size||!identityUnchanged(op.ctx))return resetIdentity();approve.disabled=true;op.fields=[...selected];
      const response=await msg("approve_identity_browser",{identity_protocol:1,entry_id:op.entryId,revision:op.revision,fields:op.fields,session_id:op.sessionId,user_gesture:true},op);
      if(identityActive!==op||!identityUnchanged(op.ctx))return resetIdentity();if(!response.ok){resetIdentity();return panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}],op.ctx.field);}
      op.approval=response.approval;void releaseIdentity(op);};box.append(approve);
    const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";cancel.onclick=()=>resetIdentity();box.append(cancel);box.querySelector("button")?.focus();
  }
  function showIdentityPicker(op,choices){
    const box=panel("Choose identity",`Profile: ${op.profileName}\nOrigin: ${origin()}`,[],op.ctx.field);
    for(const choice of choices){const button=document.createElement("button");button.type="button";button.className="account";button.textContent=(choice.favorite?"★ ":"")+choice.title;
      button.onclick=e=>{if(!uiClick(e,panelHost))return;showIdentityFields(op,choice);};box.append(button);}
    const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";cancel.onclick=()=>resetIdentity();box.append(cancel);
  }
  async function beginIdentity(field){
    reset();let ctx;try{ctx=identitySnapshot(field);}catch(e){return panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}],field);}
    const op={id:newId(),ctx,sessionId:null,entryId:null,revision:null,fields:[],approval:null,profileName:""};identityActive=op;
    const icon=identityIcons.get(field);if(icon){icon.button.disabled=true;icon.button.setAttribute("aria-busy","true");}
    const response=await msg("begin_identity_browser",{identity_protocol:1,user_gesture:true},op);
    if(identityActive!==op||!identityUnchanged(op.ctx))return resetIdentity();if(!response.ok){resetIdentity();return panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}],field);}
    op.sessionId=response.session_id;op.profileName=response.profile?.name||"current profile";const choices=response.choices||[];
    if(choices.length===1)showIdentityFields(op,choices[0]);else showIdentityPicker(op,choices);
  }
  // ---- Card fill (card_protocol 1). Mirrors the identity flow: metadata
  // only until the user ticks fields in this panel, the desktop app shows the
  // trusted review, release is gesture-gated like get_browser, only the
  // approved tokens are filled, nothing is ever submitted, and every released
  // value is blanked from memory right after the fill.
  const CARD_PROTOCOL=1;
  const CARD_LABELS={"cc-name":"Cardholder name","cc-number":"Card number","cc-exp":"Expiry","cc-exp-month":"Expiry month","cc-exp-year":"Expiry year","cc-csc":"Security code (CVV)","cc-type":"Card brand"};
  function resetCard(reason=false){
    if(cardActive?.approval) msg("cancel_card_browser",{approval:cardActive.approval,card_protocol:CARD_PROTOCOL},cardActive);
    if(cardActive){cardActive.nonce=null;cardActive.nonceExpiresAt=0;}
    cardActive=null;
    for(const {button} of cardIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");}
    if(reason) panel("LocalGateKeys",reason,[{label:"Close",run:hidePanel}]);
  }
  function cardValid(op){return cardActive===op && S.cardUnchanged(op.ctx);}
  function finishCard(op){if(cardActive===op){cardActive=null;hidePanel();}for(const {button} of cardIcons.values()){button.disabled=false;button.setAttribute("aria-busy","false");}}
  function cardFail(op,text){resetCard();panel("LocalGateKeys",text,[{label:"Close",run:hidePanel}],op.ctx.field);}
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
         response.fields.some(field=>!op.fields.includes(field) || typeof values[field]!=="string"))throw new Error("The approved card fields changed.");
      if(Object.keys(values).some(field=>!op.fields.includes(field)))throw new Error("The card release contained unapproved fields.");
      // The field checklist is done; it must not cover (and so block) the fields it fills.
      hidePanel();
      const targets=cardTargets(op.ctx);
      for(const field of op.fields){if(!targets[field])throw new Error("The page has a missing or ambiguous card field.");}
      if(!S.cardUnchanged(op.ctx))throw new Error("The payment form changed before filling.");
      for(const field of op.fields){
        const control=targets[field];
        if(!S.onTop(control))throw new Error("An approved card field is no longer visible.");
        const shown=cardPresentation(field,control,values[field]);
        if(shown!==null)cardValueSet(control,shown);
        // Synchronous site handlers may rebuild the form; stop before the next field.
        if(!S.cardUnchanged(op.ctx))throw new Error("The payment form changed while filling.");
      }
      finishCard(op);
    }catch(e){cardFail(op,e.message);}
    finally{
      for(const key of Object.keys(values||{}))values[key]="";
      response.values=null;
    }
  }
  function showCardFields(op,choice){
    op.entryId=choice.entry_id;op.revision=choice.revision;
    const meta=choice.fields&&typeof choice.fields==="object"?choice.fields:{};
    // Only tokens the page has and the card holds. CVV is opt-in every time.
    const offered=op.ctx.tokens.filter(token=>S.CARD_TOKENS.has(token) && meta[token]?.present===true);
    if(!offered.length)return cardFail(op,"This card has none of the fields on this payment form.");
    const selected=new Set(offered.filter(token=>token!=="cc-csc"));
    const summary=[choice.brand,choice.last4?`•••• ${choice.last4}`:""].filter(Boolean).join(" ");
    const box=panel("Choose card fields",`Card: ${choice.title}${summary?` (${summary})`:""}\nOrigin: ${origin()}`,[],op.ctx.field);
    for(const token of offered){
      const button=document.createElement("button");button.type="button";button.className="account check";button.setAttribute("role","checkbox");button.dataset.token=token;
      const tick=document.createElement("span");tick.className="tick";const label=document.createElement("span");label.textContent=meta[token]?.label||CARD_LABELS[token]||token;
      const render=()=>{const on=selected.has(token);button.setAttribute("aria-checked",String(on));tick.textContent=on?"✓":"";};
      render();button.append(tick,label);
      button.onclick=e=>{if(!uiClick(e,panelHost))return;if(selected.has(token))selected.delete(token);else selected.add(token);render();};box.append(button);
    }
    if(offered.includes("cc-csc")){const note=document.createElement("p");note.className="note";note.textContent="The security code is unticked by default; tick it only when this payment needs it.";box.append(note);}
    const approve=document.createElement("button");approve.type="button";approve.className="primary";approve.textContent="Review and approve";
    approve.onclick=async e=>{if(!uiClick(e,panelHost))return;if(!selected.size||!cardValid(op))return resetCard();noteGesture();approve.disabled=true;op.fields=offered.filter(token=>selected.has(token));
      const response=await msg("approve_card_browser",{card_protocol:CARD_PROTOCOL,entry_id:op.entryId,revision:op.revision,fields:op.fields,session_id:op.sessionId,user_gesture:true},op);
      if(!cardValid(op))return resetCard();if(!response.ok){const text=error(response);return cardFail(op,text);}
      if(!validText(response.approval))return cardFail(op,"The card approval was invalid.");
      op.approval=response.approval;rememberNonce(op,response);void releaseCard(op);};box.append(approve);
    const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";cancel.onclick=()=>{resetCard();hidePanel();};box.append(cancel);box.querySelector("button")?.focus();
  }
  function validText(value){return typeof value==="string" && value.length>0 && value.length<=128 && !value.includes("\0");}
  function showCardPicker(op,choices){
    const box=panel("Choose a card",`Profile: ${op.profileName}\nOrigin: ${origin()}`,[],op.ctx.field);
    for(const choice of choices){
      const b=document.createElement("button");b.type="button";b.className="account";
      const name=document.createElement("span");name.textContent=(choice.favorite?"★ ":"")+(choice.title||"Card");
      const sub=document.createElement("span");sub.className="secondary";sub.textContent=[choice.brand,choice.last4?`•••• ${choice.last4}`:""].filter(Boolean).join(" ")||"Card";
      b.append(name,sub);b.onclick=e=>{if(!uiClick(e,panelHost))return;showCardFields(op,choice);};box.append(b);
    }
    const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";cancel.onclick=()=>{resetCard();hidePanel();};box.append(cancel);
    box.querySelector("button")?.focus();
  }
  async function beginCard(field){
    reset();let ctx;try{ctx=S.cardSnapshot(field);}catch(e){return panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}],field);}
    const op={id:newId(),ctx,sessionId:null,entryId:null,revision:null,fields:[],approval:null,profileName:""};cardActive=op;
    const icon=cardIcons.get(field);if(icon){icon.button.disabled=true;icon.button.setAttribute("aria-busy","true");}
    const waiting=setTimeout(()=>{if(cardValid(op))panel("LocalGateKeys","Unlock in the LocalGateKeys desktop window. Your master password is never requested on this website.",[{label:"Cancel",run:()=>resetCard()}],field);},500);
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
    if(!response.ok || !response.credential){blankCredential(response);const text=error(response);reset();return panel("LocalGateKeys",text,[{label:"Close",run:hidePanel}],op.ctx.field);}
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
      if(!permitted.ok || !valid(op)) throw new Error("The request was cancelled before filling.");
      // The picker is done; it must not cover (and so block) the form's own controls.
      hidePanel();
      const field=op.ctx.field;
      if(op.ctx.usernameOnly) valueset(field,c.username||"");
      else {
        const user=usernameFor(field);
        if(user) valueset(user,c.username||"");
        // Synchronous site input handlers may replace/hide/change the password field.
        if(!valid(op)) throw new Error("The login form changed while filling.");
        valueset(field,c.password||"");
      }
      const wanted=c.password;
      c.password="";
      if(response.sign_in===true && !op.ctx.usernameOnly) {
        const button=S.submitCandidate(op.ctx);
        if(button) {
          const approved=await msg("submit_browser",{grant:op.grant,entry_id:entryId},op);
          if(!approved.ok || !valid(op)) throw new Error("Sign-in cancelled: vault, profile, or page changed.");
          if(S.submitCandidate(op.ctx)!==button || field.value!==wanted) throw new Error("Sign-in cancelled because the form changed.");
          // No Enter injection, no form.submit(), no validation bypass, one attempt.
          if(!op.ctx.form.checkValidity()) throw new Error("Review the required fields before signing in.");
          const form=op.ctx.form;
          finish(op);
          HTMLFormElement.prototype.requestSubmit.call(form,button);
          return;
        }
        finish(op);
        return panel("LocalGateKeys","Filled. Automatic sign-in was skipped because this form is unsupported or ambiguous. Sign in manually.",[{label:"Close",run:hidePanel}],field);
      }
      finish(op);
    } catch(e) {c.password="";reset();panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}],op.ctx.field);}
  }
  // The site's logo (background.js adds site_logo from the bundled set for
  // this page's origin), drawn as inline SVG like the field icons.
  function logoTile(logo){
    if(!logo || typeof logo.hex!=="string" || !/^#[0-9a-f]{6}$/i.test(logo.hex) || typeof logo.path!=="string" || !/^[0-9a-z.,\- ]{1,20000}$/i.test(logo.path))return null;
    const n=parseInt(logo.hex.slice(1),16);const light=(0.299*(n>>16)+0.587*((n>>8)&255)+0.114*(n&255))/255>0.7;
    const tile=document.createElement("span");tile.className="logo";tile.style.background=logo.hex;
    tile.append(svgEl("svg",{viewBox:"0 0 24 24","aria-hidden":"true",focusable:"false"},[svgEl("path",{d:logo.path,fill:light?"#111111":"#ffffff"})]));
    return tile;
  }
  // One account row: [logo] name / username (+ extra lines).
  function accountButton(c,logo,extra=[]){
    const b=document.createElement("button");b.type="button";b.className="account";
    const text=document.createElement("span");text.className="text";
    const name=document.createElement("span");name.textContent=(c.favorite?"★ ":"")+(c.label||c.username);
    const sub=document.createElement("span");sub.className="secondary";sub.textContent=c.username || "No username";
    text.append(name,sub,...extra);
    const tile=logoTile(logo);
    if(tile){b.classList.add("has-logo");b.append(tile);}
    b.append(text);
    return b;
  }
  function showAccountPicker(op,choices,profile,logo=null) {
    const box=panel("Choose an account",`Profile: ${profile.name}`,[],op.ctx.field);
    // Broker match kind for multi-URL logins; exact-origin rows are the norm
    // and say nothing, the wider rows are labelled so the user can tell.
    const matchHint={host:"matches host",base_domain:"matches domain",starts_with:"matches URL prefix"};
    for(const c of choices){
      const extra=[];
      if(typeof c.match==="string" && c.match!=="exact_origin" && matchHint[c.match]){
        const kind=document.createElement("span");kind.className="secondary match";kind.textContent=matchHint[c.match];extra.push(kind);
      }
      const b=accountButton(c,logo,extra);
      b.addEventListener("click",e=>{if(!uiClick(e,panelHost))return;e.preventDefault();e.stopPropagation();noteGesture();release(op,c.entry_id);});box.append(b);
    }
    const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";cancel.onclick=()=>reset();box.append(cancel);
    const first=box.querySelector("button");first?.focus();
  }
  // fromIcon: started by a click on the in-page icon, which lives in the page
  // and can be clickjacked; even a single match then needs a second, explicit
  // click in the picker. The toolbar popup is browser UI and fills directly.
  async function begin(field, fromIcon=false) {
    logoutInProgress=false;
    recentFilledCredential=null;
    reset();
    const usernameOnly=field.type!=="password";
    let ctx;try{ctx=S.snapshot(field,usernameOnly);}catch(e){panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}]);return;}
    const op={id:newId(),generation,ctx,grant:null,sessionId:null};active=op;
    const icon=icons.get(field);if(icon){icon.button.setAttribute("aria-busy","true");icon.button.title="Waiting for LocalGateKeys…";icon.button.disabled=true;}
    const waiting=setTimeout(()=>{if(valid(op))panel("LocalGateKeys","Unlock in the LocalGateKeys desktop window. Your master password is never requested on this website.",[{label:"Cancel",run:()=>reset()}],field);},500);
    const response=await msg("begin_browser",{user_gesture:true,url:pageUrl()},op);clearTimeout(waiting);
    if(!valid(op))return reset();
    if(!response.ok){reset();return panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}],field);}
    op.grant=response.grant;op.sessionId=response.session_id ?? null;rememberNonce(op,response);
    // ping is unauthenticated metadata ({ok, version, locked} only): it tells
    // us when the vault locked, nothing more. Grant/lease continuity is
    // enforced by the broker on get_browser (session_changed).
    statusTimer=setInterval(async()=>{
      if(!valid(op))return reset();
      const state=await msg("ping",{},op);
      if(active===op && (!state.ok || state.locked===true)) reset();
    },1200);
    const choices=response.choices || [];
    if(choices.length===1 && !fromIcon)release(op,choices[0].entry_id);
    else showAccountPicker(op,choices,response.profile,response.site_logo);
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
      if(ctx.boxes.length!==code.length) throw new Error("This code field has an unexpected number of boxes.");
      ctx.boxes.forEach((box,i)=>valueset(box,code[i]));
    } else valueset(ctx.field,code);
  }
  async function releaseTotp(op,entryId){
    if(!totpValid(op))return resetTotp();
    if(op.releasing)return;op.releasing=true;
    const response=await gestured("get_totp_browser",{grant:op.grant,entry_id:entryId},op,()=>totpValid(op));
    if(!totpValid(op)){blankCode(response);return resetTotp();}
    if(!response.ok || typeof response.code!=="string"){
      blankCode(response);resetTotp();return panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}],op.ctx.field);
    }
    let code=response.code;
    try{
      if(response.remaining<4 && typeof response.next_code==="string"){
        // Avoid typing a code that expires before the site checks it.
        panel("LocalGateKeys","Waiting a moment for a fresh 2FA code\u2026",[],op.ctx.field);
        await new Promise(r=>setTimeout(r,(response.remaining+1)*1000));
        code=response.next_code;
        if(!totpValid(op))return resetTotp();
      }
      fillCode(op.ctx,code);hidePanel();
    }catch(e){panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}],op.ctx.field);}
    finally{response.code=response.next_code="";code="";resetTotp();}
  }
  async function beginTotp(field, fromIcon=false){
    reset();
    let ctx;try{ctx=S.otpSnapshot(field);}catch(e){return panel("LocalGateKeys",e.message,[{label:"Close",run:hidePanel}],field);}
    const op={id:newId(),ctx,grant:null,sessionId:null};otpActive=op;
    const icon=otpIcons.get(field);if(icon){icon.button.disabled=true;icon.button.setAttribute("aria-busy","true");}
    const response=await msg("begin_totp_browser",{user_gesture:true},op);
    if(!totpValid(op))return resetTotp();
    if(!response.ok){resetTotp();return panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}],field);}
    op.grant=response.grant;op.sessionId=response.session_id ?? null;rememberNonce(op,response);
    const choices=response.choices||[];
    if(choices.length===1 && !fromIcon)return releaseTotp(op,choices[0].entry_id);
    const box=panel("Which account's 2FA code?",`Profile: ${response.profile?.name||""}`,[],field);
    for(const c of choices){
      const b=accountButton(c,response.site_logo);
      b.addEventListener("click",e=>{if(!uiClick(e,panelHost))return;e.preventDefault();e.stopPropagation();noteGesture();releaseTotp(op,c.entry_id);});box.append(b);
    }
    const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";cancel.onclick=()=>{resetTotp();hidePanel();};box.append(cancel);
    box.querySelector("button")?.focus();
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
  const ICON_STYLE='button{display:grid;place-items:center;width:24px;height:24px;padding:0;border:1px solid #3c607e;border-radius:7px;background:#091421;cursor:pointer}button:focus-visible{outline:2px solid #5dbeff;outline-offset:2px}button[aria-busy="true"]{opacity:.5}svg{width:22px;height:22px;display:block}svg.card{width:18px;height:18px}';
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
    for(const map of [icons,cardIcons,otpIcons,identityIcons]){for(const {host} of map.values())host.remove();map.clear();}
  }
  function syncIcons(){
    watchShadowRoots();
    if(!fillEnabled){removeFillIcons();return;}
    const fields=q('input').filter(el=>S.visible(el) && (
      (el.type==="password" && el.autocomplete!=="new-password") ||
      (el.autocomplete==="username" && !el.form?.querySelector('input[type="password"]'))));
    const set=new Set(fields);
    for(const [f,{host}] of icons){if(!set.has(f)){host.remove();icons.delete(f);}else position(f,host);}
    for(const field of fields){if(icons.has(field))continue;
      addIcon(icons,field,"localvaultFieldIcon","Fill with LocalGateKeys",logoGlyph(),f=>{noteGesture();begin(f,true);});
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
      addIcon(cardIcons,field,"localgatekeysCardIcon","Fill card with LocalGateKeys",glyph,f=>{noteGesture();beginCard(f);});
    }
    const otpFields=q('input').filter(el=>!icons.has(el) && !cardControls.has(el) && S.otpField(el));
    const otpSet=new Set(otpFields);
    for(const [field,{host}] of otpIcons){if(!otpSet.has(field)){host.remove();otpIcons.delete(field);}else position(field,host);}
    for(const field of otpFields){if(otpIcons.has(field))continue;
      addIcon(otpIcons,field,"localgatekeysOtpIcon","Fill 2FA code with LocalGateKeys",logoGlyph(),f=>{noteGesture();beginTotp(f,true);});
    }
    const identityFields=q('input,textarea').filter(field=>!cardControls.has(field) && identityFieldName(field) && S.visible(field) && field.type!=="password" && !field.form?.querySelector('input[type="password"]'));
    const identitySet=new Set(identityFields);
    for(const [field,{host}] of identityIcons){if(!identitySet.has(field)){host.remove();identityIcons.delete(field);}else position(field,host);}
    for(const field of identityFields){if(identityIcons.has(field))continue;
      addIcon(identityIcons,field,"localgatekeysIdentityIcon","Fill identity with LocalGateKeys",logoGlyph(),f=>beginIdentity(f));
    }
  }
  let syncTimer;
  function schedule(){if(syncTimer)return;syncTimer=setTimeout(()=>{syncTimer=null;syncIcons();if(active&&!S.unchanged(active.ctx))reset();if(identityActive&&!identityUnchanged(identityActive.ctx))resetIdentity();if(cardActive&&!S.cardUnchanged(cardActive.ctx))resetCard();if(otpActive&&!S.unchanged(otpActive.ctx))resetTotp();},40);}
  const observerOptions={childList:true,subtree:true,attributes:true,attributeFilter:["type","autocomplete","disabled","readonly","class","style","action","method","target"]};
  const observer=new MutationObserver(records=>{
    const owned=node=>node instanceof Element && !!node.closest(`[${PANEL_ATTR}],[data-localvault-field-icon],[data-localgatekeys-identity-icon],[data-localgatekeys-otp-icon],[data-localgatekeys-card-icon]`);
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
  if(safariBackground()){fillEnabled=false;void msg("status").then(applyFeatures);}
  syncIcons();

  // Browser-only save/update detection. The submitted password is sent only to
  // the local native app, which keeps it in process RAM briefly. The page prompt
  // is shown only after the login surface appears to have succeeded/disappeared.
  let pendingAttempt=null, pendingTimer=null, lastPromptToken=null;
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
    panel(exists?"Save / update in LocalGateKeys?":"Save this login?",`${username||"No username"}\n${notice||"Changes are confirmed in the desktop app."}`,[
      ...(full?[]:[{label:exists?"Save / update":"Save",primary:true,run:async()=>{
        if(savedGeneration!==generation || href!==location.href || !S.onTop(field) || field.value!==password){hidePanel();return;}
        // The Save click is the trusted gesture: mint a nonce for this same
        // operation (same context) and present it with save_browser.
        const response=await gestured("save_browser",{username,password},op,()=>savedGeneration===generation && href===location.href && field.isConnected);
        if(response.ok)showNoticeOrHide(response);else panel("LocalGateKeys",error(response),[{label:"Close",run:hidePanel}]);
      }}]),{label:"Not now",run:hidePanel}
    ],field);
  }
  function showNoticeOrHide(response){
    const notice=noticeOf(response);
    if(notice)panel("LocalGateKeys",notice,[{label:"Close",run:hidePanel}]);else hidePanel();
  }
  function passwordForForm(form=null) {
    const fields=q('input[type="password"]',form||document).filter(f=>f.value && f.autocomplete!=="new-password" && S.onTop(f));
    return fields[fields.length-1] || null;
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
  async function captureSubmission(field) {
    if(!automaticSaveEnabled || logoutInProgress)return;
    if(!(field instanceof HTMLInputElement) || field.type!=="password" || !field.value)return;
    const form=field.form;if(form&&!S.safeForm(form))return;
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
    pendingAttempt={field,form,href:location.href,at:now,token:null};
    const response=await msg("capture_browser",{username,password:field.value},{id:newId()});
    if(!response?.ok || !response.stored){pendingAttempt=null;return;}
    pendingAttempt.token=response.pending_token||response.token||null;
    // Check quickly for SPA/form disappearance, then fall back to an explicit
    // "Did you just sign in?" prompt instead of leaving the credential pending
    // until an unrelated navigation such as logout.
    schedulePendingChecks([250,450,800,1400,2200]);
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
  function loginFailureVisible() {
    const inputs=q('input[aria-invalid="true"],input:invalid').filter(S.onTop);
    if(inputs.length)return true;
    const selectors='[role="alert"],[aria-live="assertive"],.error,.errors,.error-message,.alert-danger,[data-error]';
    return q(selectors).some(el=>S.visible(el) && H.hasFailureText(el.textContent||""));
  }
  function loginOutcome(response) {
    if(document.visibilityState!=="visible")return "wait";
    if(loginFailureVisible())return "failure";
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
    if(!automaticSaveEnabled || logoutInProgress)return;
    const response=await msg("pending_browser",{}, {id:newId()});
    if(logoutInProgress)return;
    const token=response?.pending_token||response?.token;
    if(!response?.ok || !response.pending || !token)return;
    // A capture typed on another origin of this site (sign-in redirect): the
    // background names only that origin, never the username, to this page.
    const handoff=response.handoff===true && typeof response.origin==="string" && response.origin!==origin();
    if(!handoff && (typeof response.username!=="string" || !response.username.trim())){
      pendingAttempt=null;lastPromptToken=null;hidePanel();
      void msg("clear_pending_browser",{}, {id:newId()});
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
      ? "Unlock to review this login"
      : full?"Save this login?":(uncertain?"Did you just sign in?":(exists?"Save / update in LocalGateKeys?":"Save this login?"));
    const who=handoff?`A login typed on ${savedFor}`:(response.username||"No username");
    const text=notice
      ? `${who}\n${notice}`
      : uncertain
      ? `${who}\nLocalGateKeys captured a login attempt but could not confirm the site's success state. Save only if the sign-in succeeded.`
      : deferred
        ? `${who}\nThe login was captured while LocalGateKeys was locked. Unlock the desktop app to review whether it matches a saved login.`
        : exists
          ? `${who}\nThis account is already in LocalGateKeys. Send this sign-in to the app? It shows whether anything changed before saving.`
          : `${who}\nLogin completed. Save it in your local encrypted vault?`;
    panel(title,text,[
      ...(full?[]:[{label:deferred?"Unlock to review":(exists?"Save / update":"Save login"),primary:true,run:async()=>{
        // One operation id for begin_gesture_browser and save_pending_browser:
        // the nonce is bound to the request context, which includes it.
        const saved=await gestured("save_pending_browser",{pending_token:token},{id:newId()});
        if(saved.ok){pendingAttempt=null;lastPromptToken=null;showNoticeOrHide(saved);}
        else panel("LocalGateKeys",error(saved),[{label:"Close",run:hidePanel}]);
      }}]),{label:"Not now",run:()=>{msg("discard_pending_browser",{pending_token:token},{id:newId()});pendingAttempt=null;lastPromptToken=null;hidePanel();}},
      {label:"Never on this site",run:async()=>{
        msg("discard_pending_browser",{pending_token:token},{id:newId()});pendingAttempt=null;lastPromptToken=null;hidePanel();
        const stored=await api.storage.local.get({[automaticOriginKey]:[]});
        const blocked=Array.isArray(stored[automaticOriginKey])?stored[automaticOriginKey]:[];
        if(!blocked.includes(origin()))await api.storage.local.set({[automaticOriginKey]:[...blocked,origin()]});
      }}
    ],null,savedFor);
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
    if(e.isTrusted && target instanceof HTMLFormElement){const f=passwordForForm(target);if(f)captureSubmission(f);}
  }
  document.addEventListener("submit",onSubmit,true);
  document.addEventListener("keydown",e=>{
    if(!automaticSaveEnabled)return;
    if(!e.isTrusted || e.key!=="Enter")return;
    const target=eventTarget(e);
    const logout=target?.closest('a,button,input[type="submit"],input[type="button"],[role="button"],[role="menuitem"]');
    if(logout && likelyLogoutControl(logout)){void discardPendingForLogout();return;}
    const form=target?.closest("form");
    const f=passwordForForm(form)||(!form?passwordForForm():null);if(f)captureSubmission(f);
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
    const f=passwordForForm(form)||(!form?passwordForForm():null);if(f)captureSubmission(f);
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
    if(r.command==="check_pending_save") {void automaticSaveLoaded.then(()=>{if(automaticSaveEnabled)schedulePendingChecks([80,500,1400]);});reply({ok:true});return false;}
    if(!fillEnabled && ["fill_current","fill_identity","fill_card","fill_totp","generate_new"].includes(r.command)){reply({ok:false,error:"unsupported"});return false;}
    if(r.command==="fill_current") {
      const f=Array.from(icons.keys()).find(S.onTop);if(f)begin(f);reply({ok:!!f});return false;
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
      const f=q('input[type="password"]').find(S.onTop);if(f)offerSave(f,true);reply({ok:!!f});return false;
    }
    if(r.command==="generate_new") {
      const fields=q('input[autocomplete="new-password"]').filter(S.onTop);
      if(!fields.length || fields.length>2 || fields.some(f=>f.form!==fields[0].form) || (fields[0].form&&!S.safeForm(fields[0].form))){reply({ok:false,message:"No unambiguous new-password fields were found."});return false;}
      const alphabet="abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%-_";
      // Rejection sampling, not modulo-biased byte mapping.
      let value="";while(value.length<24){const bytes=crypto.getRandomValues(new Uint8Array(32));for(const n of bytes){if(n<Math.floor(256/alphabet.length)*alphabet.length)value+=alphabet[n%alphabet.length];if(value.length===24)break;}}
      fields.forEach(f=>valueset(f,value));
      panel("Password generated","Filled the new-password fields. Save this password before leaving the page.",[{label:"Save in vault",primary:true,run:()=>offerSave(fields[0],true)},{label:"Close",run:hidePanel}],fields[0]);reply({ok:true});return false;
    }
    return false;
  });
})();
