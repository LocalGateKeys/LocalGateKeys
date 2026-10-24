"use strict";
// Testable, conservative DOM policy. No network or vault access in this module.
(() => {
 // Strict shape check: a page element with id="LGKHeuristics" is reachable
 // through named property access and must never stand in for the module.
 const H=typeof globalThis.LGKHeuristics?.isSignInLabel==="function"?globalThis.LGKHeuristics:null;
 const fallbackSignIn=new Set(["sign in","signin","log in","login","log on","zaloguj","zaloguj się"]);
 const isSignInLabel=label=>H?H.isSignInLabel(label):fallbackSignIn.has(clean(label));
 const clean = s => String(s || "").replace(/\s+/g," ").trim().toLowerCase();
 // Page-controlled attribute and label text is cut to this length before any
 // field-hint regex runs: a 60 kB attribute must not stall the content script
 // (some hint patterns backtrack). Real names, ids and labels are far shorter.
 const HINT_TEXT_MAX=256;
 const hintText = parts => parts.map(v=>String(v ?? "").slice(0,HINT_TEXT_MAX)).join(" ");
 // ---- Open shadow DOM traversal. Closed roots (including our own UI) are
 // invisible to this walk by construction. Depth is bounded.
 const MAX_SHADOW_DEPTH=6;
 function shadowRoots(root=document, depth=0, out=[]) {
   if (depth>MAX_SHADOW_DEPTH || !root || typeof root.querySelectorAll!=="function") return out;
   for (const el of root.querySelectorAll("*")) {
     if (el.shadowRoot) { out.push(el.shadowRoot); shadowRoots(el.shadowRoot, depth+1, out); }
   }
   return out;
 }
 function queryAll(selector, root=document) {
   const out=Array.from(root.querySelectorAll(selector));
   for (const sr of shadowRoots(root)) out.push(...sr.querySelectorAll(selector));
   return out;
 }
 // Composed-tree parent: crosses from a shadow root up to its host.
 function composedParent(el) {
   if (el.parentElement) return el.parentElement;
   const root=el.getRootNode?.();
   return root && root.host instanceof Element ? root.host : null;
 }
 // Opacity below this is treated as invisible: a near-transparent field is a
 // harvesting trick, not a design choice.
 const MIN_OPACITY=0.1;
 // clip-path shapes that leave nothing (or next to nothing) of the box.
 function clipPathHides(value) {
   const v=clean(value);
   if (!v || v==="none") return false;
   const inset=/^inset\(([^)]*)\)/.exec(v);
   if (inset) return inset[1].split(/\s+round\s+/)[0].trim().split(/\s+/).some(part=>/%$/.test(part) && parseFloat(part)>=50);
   return /^(circle|ellipse)\(\s*0(px|%)?(\s|\)|$)/.test(v);
 }
 // Legacy `clip: rect(...)` (the "screen-reader only" pattern) with no area.
 function clipHides(value) {
   const m=/^rect\(([^)]*)\)$/.exec(clean(value));
   if (!m) return false;
   const n=m[1].split(/[\s,]+/).filter(Boolean).map(x=>x==="auto"?null:parseFloat(x));
   if (n.length!==4 || n.some(x=>x!==null && !Number.isFinite(x))) return false;
   const [top,right,bottom,left]=n;
   return (right!==null && left!==null && right-left<1) || (bottom!==null && top!==null && bottom-top<1);
 }
 const clipsOverflow=s=>[s.overflow,s.overflowX,s.overflowY].some(v=>v==="hidden" || v==="clip");
 function visible(el) {
   if (!(el instanceof HTMLElement) || !el.isConnected || el.hidden || el.closest('[inert],[aria-hidden="true"]')) return false;
   if (el instanceof HTMLInputElement && (el.disabled || el.readOnly)) return false;
   for (let p=el;p instanceof HTMLElement;p=composedParent(p)) {
     const s=getComputedStyle(p);
     if (s.display === "none" || s.visibility !== "visible" || !(Number(s.opacity) >= MIN_OPACITY)) return false;
     if (clipPathHides(s.clipPath) || clipHides(s.clip)) return false;
     // A zero-size ancestor that clips its overflow hides everything inside it.
     if (p!==el && clipsOverflow(s)) { const pr=p.getBoundingClientRect(); if (pr.width<1 || pr.height<1) return false; }
   }
   const r=el.getBoundingClientRect();
   return r.width>=4 && r.height>=4 && r.bottom>0 && r.right>0 && r.top<innerHeight && r.left<innerWidth;
 }
 // Topmost element at a point, descending through open shadow hosts so that a
 // field inside a shadow tree is recognised while an overlay still rejects it.
 function deepElementFromPoint(x,y) {
   let hit=document.elementFromPoint(x,y);
   for (let i=0;i<MAX_SHADOW_DEPTH && hit && hit.shadowRoot && typeof hit.shadowRoot.elementFromPoint==="function";i++) {
     const inner=hit.shadowRoot.elementFromPoint(x,y);
     if (!inner || inner===hit) break;
     hit=inner;
   }
   return hit;
 }
 function onTop(el) {
   if (!visible(el)) return false;
   const r=el.getBoundingClientRect();
   // Left inner point avoids our small icon on the right edge of the field.
   const x=Math.max(1,Math.min(innerWidth-1,r.left+Math.min(10,r.width/2)));
   const y=Math.max(1,Math.min(innerHeight-1,r.top+r.height/2));
   const hit=deepElementFromPoint(x,y);
   return hit===el || el.contains(hit);
 }
 function currentPassword(el) { return el instanceof HTMLInputElement && el.type==="password" && clean(el.autocomplete)!=="new-password" && onTop(el); }
 // ---- Form destination. A form is safe only when every way it can be
 // submitted stays on this origin in this browsing context: its own action and
 // target, every submit button's formaction / formtarget (including buttons
 // associated through form="id"), the document base URL and base target.
 // HTMLFormElement is [LegacyOverrideBuiltIns] (a control named "action",
 // "elements" or "getAttribute" shadows the property), so the prototype
 // accessors are called instead of the page-shadowable instance properties.
 const getter=(proto,name)=>Object.getOwnPropertyDescriptor(proto,name)?.get;
 const elementGetAttribute=Element.prototype.getAttribute, elementHasAttribute=Element.prototype.hasAttribute;
 const attr=(el,name)=>elementGetAttribute.call(el,name);
 const hasAttr=(el,name)=>elementHasAttribute.call(el,name);
 const formElements=getter(HTMLFormElement.prototype,"elements");
 const formActionIdl=getter(HTMLFormElement.prototype,"action");
 const submitterActionIdl=el=>getter(el instanceof HTMLButtonElement?HTMLButtonElement.prototype:HTMLInputElement.prototype,"formAction");
 function sameOrigin(url) { try { return new URL(url).origin===location.origin; } catch { return false; } }
 function selfTarget(value) { const t=clean(value); return !t || t==="_self"; }
 // An injected <base href> re-targets every relative URL on the page and a
 // <base target> every form without its own target.
 function baseSafe() {
   if (!sameOrigin(document.baseURI)) return false;
   const base=document.querySelector("base[target]");
   return !base || selfTarget(attr(base,"target"));
 }
 // The URL the browser submits to, resolved against the document base URL by
 // the IDL attributes (form.action / submitter.formAction). An empty
 // formaction / action means the document URL.
 function resolvedAction(form, submitter) {
   if (submitter && hasAttr(submitter,"formaction")) {
     const raw=attr(submitter,"formaction");
     if (!raw.trim()) return location.href;
     const idl=submitterActionIdl(submitter);
     return idl ? idl.call(submitter) : new URL(raw,document.baseURI).href;
   }
   const raw=attr(form,"action");
   if (raw===null || !raw.trim()) return location.href;
   return formActionIdl ? formActionIdl.call(form) : new URL(raw,document.baseURI).href;
 }
 function resolvedTarget(form, submitter) {
   if (submitter && hasAttr(submitter,"formtarget")) return attr(submitter,"formtarget");
   return attr(form,"target") ?? "";
 }
 // Every control that can submit this form: <button type=submit>, input
 // type=submit, and input type=image (left out of form.elements by spec).
 function formSubmitters(form) {
   const listed=Array.from(formElements.call(form)).filter(el=>(el instanceof HTMLButtonElement && el.type==="submit") || (el instanceof HTMLInputElement && el.type==="submit"));
   const root=form.getRootNode();
   const images=typeof root.querySelectorAll==="function" ? Array.from(root.querySelectorAll('input[type="image" i]')).filter(el=>el.form===form) : [];
   return [...listed, ...images];
 }
 function safeForm(form, submitter=null) {
   if (!(form instanceof HTMLFormElement) || !form.isConnected) return false;
   try {
     if (!baseSafe()) return false;
     const ways=[null, ...formSubmitters(form)];
     if (submitter && !ways.includes(submitter)) ways.push(submitter);
     return ways.every(b=>sameOrigin(resolvedAction(form,b)) && selfTarget(resolvedTarget(form,b)));
   } catch { return false; }
 }
 // Attribute fingerprint of the form, compared by unchanged()/cardUnchanged().
 function formState(form) {
   return form ? {action:attr(form,"action"),method:attr(form,"method"),target:attr(form,"target")} : {action:undefined,method:undefined,target:undefined};
 }
 function sameFormState(ctx) {
   const now=formState(ctx.form);
   return now.action===ctx.action && now.method===ctx.method && now.target===ctx.target;
 }
 function snapshot(field, usernameOnly=false) {
   if (!onTop(field) || (!usernameOnly && !currentPassword(field))) throw new Error("The target field is hidden, covered, or no longer a login field.");
   const form=field.form;
   if (form && !safeForm(form)) throw new Error("The form points to another origin. LocalGateKeys will not fill it.");
   return {field,form,origin:location.origin,type:field.type,autocomplete:field.autocomplete,usernameOnly,...formState(form)};
 }
 function unchanged(ctx) {
   return ctx.origin===location.origin && document.visibilityState==="visible" && ctx.field.form===ctx.form &&
     ctx.field.type===ctx.type && ctx.field.autocomplete===ctx.autocomplete && onTop(ctx.field) &&
     (!ctx.form || (safeForm(ctx.form) && sameFormState(ctx)));
 }
 function submitCandidate(ctx) {
   if (ctx.usernameOnly || !unchanged(ctx) || !ctx.form) return null;
   const form=ctx.form;
   const controls=Array.from(formElements.call(form));
   const passwords=controls.filter(el=>el instanceof HTMLInputElement && el.type==="password");
   if (passwords.length!==1 || passwords[0]!==ctx.field || controls.some(el=>clean(el.autocomplete)==="new-password" || clean(el.autocomplete)==="one-time-code")) return null;
   const possible=controls.filter(el=>(el instanceof HTMLButtonElement && el.type==="submit") || (el instanceof HTMLInputElement && el.type==="submit"));
   const candidates=possible.filter(el=>visible(el) && onTop(el) && !el.disabled && el.getAttribute("aria-disabled")!=="true");
   if (candidates.length!==1) return null;
   const b=candidates[0];
   const label=attr(b,"aria-label") || (b instanceof HTMLInputElement ? b.value : b.textContent);
   if (!isSignInLabel(label) || !safeForm(form,b)) return null;
   const method=clean(attr(b,"formmethod") || attr(form,"method") || "get");
   if (method!=="post" || form.noValidate || b.formNoValidate) return null;
   return b;
 }
 // One-time-code fields. Conservative: explicit autocomplete, or a strong name/label hint.
 const otpHint=/(^|[^a-z])(otp|totp|2fa|mfa|one[\s_-]?time|verification[\s_-]?code|security[\s_-]?code|auth(entication|enticator)?[\s_-]?code|two[\s_-]?factor|6[\s_-]?digit)/i;
 const otpTypes=new Set(["text","tel","number",""]);
 function otpText(el){
   const labels=Array.from(el.labels||[]).slice(0,4).map(l=>String(l.textContent||"").slice(0,HINT_TEXT_MAX)).join(" ");
   return hintText([el.name,el.id,el.placeholder,el.getAttribute("aria-label"),labels]);
 }
 function otpBoxes(el){
   // Split inputs: 6-8 single-character boxes sharing one container.
   if (el.maxLength!==1 || !el.parentElement) return null;
   let root=el.parentElement;
   for (let i=0;i<3 && root;i++,root=root.parentElement){
     const boxes=Array.from(root.querySelectorAll("input")).filter(x=>x.maxLength===1 && otpTypes.has(x.type) && visible(x));
     if (boxes.length>=6 && boxes.length<=8) return boxes;
     if (boxes.length>8) return null;
   }
   return null;
 }
 function otpField(el){
   if (!(el instanceof HTMLInputElement) || !otpTypes.has(el.type) || !visible(el)) return false;
   const ac=clean(el.autocomplete);
   if (ac==="one-time-code") return true;
   if (ac==="username" || ac==="email" || ac.startsWith("cc-")) return false;
   const boxes=otpBoxes(el);
   if (boxes) return boxes[0]===el && (otpHint.test(otpText(el)) || boxes.some(b=>clean(b.autocomplete)==="one-time-code") ||
                                       el.inputMode==="numeric");
   if (el.maxLength>0 && (el.maxLength<6 || el.maxLength>8)) return false;
   return otpHint.test(otpText(el));
 }
 function otpSnapshot(field){
   if (!onTop(field) || !otpField(field)) throw new Error("The code field is hidden, covered, or no longer a 2FA field.");
   const form=field.form;
   if (form && !safeForm(form)) throw new Error("The form points to another origin. LocalGateKeys will not fill it.");
   return {field,form,origin:location.origin,type:field.type,autocomplete:field.autocomplete,usernameOnly:true,boxes:otpBoxes(field),...formState(form)};
 }
 // ---- Payment cards. Explicit HTML autocomplete tokens are authoritative.
 // Name/id/label heuristics cover only number, expiry and CVV (plus the
 // cardholder name when it is unmistakable), and only inside a scope that
 // already has a card-number-like field: a lone "expiry" or "security code"
 // field never makes a payment form on its own.
 const CARD_TOKENS=new Set(["cc-name","cc-number","cc-exp","cc-exp-month","cc-exp-year","cc-csc","cc-type"]);
 const CARD_SELECT_TOKENS=new Set(["cc-exp-month","cc-exp-year","cc-type"]);
 const cardTextTypes=new Set(["text","tel","number",""]);
 const cardHints=[
   ["cc-number",/(^|[^a-z])((card|cc|credit|debit)[\s_-]*(number|num|no|nr)|ccnum|ccnumber|cardnumber|cardnum)($|[^a-z])/i],
   ["cc-exp-month",/(^|[^a-z])((exp(iry|iration)?|cc|card)[\s_-]*(date[\s_-]*)?(month|mm)|expmonth|exp_month|ccmonth)($|[^a-z])/i],
   ["cc-exp-year",/(^|[^a-z])((exp(iry|iration)?|cc|card)[\s_-]*(date[\s_-]*)?(year|yy|yyyy)|expyear|exp_year|ccyear)($|[^a-z])/i],
   ["cc-exp",/(^|[^a-z])((card|cc)?[\s_-]*exp(iry|iration|ires)?([\s_-]*date)?|mm[\s/_-]*yy(yy)?)($|[^a-z])/i],
   ["cc-csc",/(^|[^a-z])(cvv2?|cvc2?|cvn|csc|cid|security[\s_-]?code|card[\s_-]?(verification|security)[\s_-]?(code|value|number)?)($|[^a-z])/i],
   ["cc-name",/(^|[^a-z])(card[\s_-]?holder|name[\s_-]?on[\s_-]?card|(cc|card)[\s_-]?name)($|[^a-z])/i],
 ];
 function cardText(el){
   const labels=Array.from(el.labels||[]).slice(0,4).map(l=>String(l.textContent||"").slice(0,HINT_TEXT_MAX)).join(" ");
   return hintText([el.name,el.id,el.getAttribute("placeholder"),el.getAttribute("aria-label"),labels]);
 }
 // The card token of one control, or null. Heuristics run only when asked.
 function cardToken(el, heuristic=false) {
   const isInput=el instanceof HTMLInputElement, isSelect=el instanceof HTMLSelectElement;
   if (!isInput && !isSelect) return null;
   if (isInput && !cardTextTypes.has(el.type)) return null;
   const tokens=clean(String(el.autocomplete||"").slice(0,HINT_TEXT_MAX)).split(/\s+/).filter(Boolean);
   const explicit=tokens.find(t=>CARD_TOKENS.has(t));
   if (explicit) return isSelect && !CARD_SELECT_TOKENS.has(explicit) ? null : explicit;
   // Any other declared purpose (username, email, cc-given-name, ...) excludes the control.
   if (tokens.some(t=>t!=="on" && t!=="off" && !/^section-/.test(t) && t!=="billing" && t!=="shipping")) return null;
   if (!heuristic) return null;
   const text=cardText(el);
   for (const [token,pattern] of cardHints) {
     if (!pattern.test(text)) continue;
     if (isSelect && !CARD_SELECT_TOKENS.has(token)) return null;
     return token;
   }
   return null;
 }
 // The scope a card field belongs to: its form, else its document or shadow root.
 function cardScope(el){ return el.form || el.getRootNode(); }
 // token -> visible controls inside one scope. Hidden duplicates (mobile /
 // desktop variants) are left out so that one visible control per token remains.
 function cardFieldMap(scope) {
   const controls=queryAll("input,select",scope).filter(visible);
   const hasNumber=controls.some(c=>cardToken(c,true)==="cc-number");
   const map={};
   for (const c of controls) { const t=cardToken(c,hasNumber); if (t) (map[t] ??= []).push(c); }
   return map;
 }
 function cardSnapshot(field) {
   const scope=cardScope(field);
   const map=cardFieldMap(scope);
   if (!onTop(field) || !(map["cc-number"]||[]).includes(field)) throw new Error("The card field is hidden, covered, or no longer part of a payment form.");
   const form=field.form;
   if (form && !safeForm(form)) throw new Error("The form points to another origin. LocalGateKeys will not fill it.");
   const tokens=Object.keys(map).filter(t=>map[t].length===1 && onTop(map[t][0]));
   return {field,form,scope,origin:location.origin,type:field.type,autocomplete:field.autocomplete,name:field.name,id:field.id,tokens,...formState(form)};
 }
 function cardUnchanged(ctx) {
   return ctx.origin===location.origin && document.visibilityState==="visible" && ctx.field.isConnected &&
     ctx.field.form===ctx.form && ctx.field.type===ctx.type && ctx.field.autocomplete===ctx.autocomplete &&
     ctx.field.name===ctx.name && ctx.field.id===ctx.id && onTop(ctx.field) &&
     (!ctx.form || (safeForm(ctx.form) && sameFormState(ctx)));
 }
 // Expiry presentation of a single text field. The broker releases MM/YYYY;
 // the page's placeholder, label, pattern or maxlength decides MM/YY vs
 // MM/YYYY and the separator. Without any hint MM/YY is the web default.
 function cardExpiryShape(field) {
   const hint=clean([field.getAttribute("placeholder"),field.getAttribute("aria-label"),field.getAttribute("pattern"),field.getAttribute("data-format"),
     Array.from(field.labels||[]).map(l=>l.textContent).join(" ")].join(" "));
   const max=field.maxLength>0?field.maxLength:0;
   const year=(/y{4}|a{4}|j{4}/.test(hint) || /\d{2}\s*[/ -]\s*\d{4}/.test(hint) || max===6 || max===7) ? 4 : 2;
   let separator="/";
   if (max===4 || max===6) separator="";
   else if (/m{2}\s*-\s*[ya]{2}/.test(hint) || /\d{2}-\d{2}/.test(hint)) separator="-";
   else if (/m{2} [ya]{2}/.test(hint)) separator=" ";
   return {year,separator};
 }
 function cardExpiryParts(value) {
   const m=/^\s*(\d{1,2})\s*[/\-. ]\s*(\d{2}|\d{4})\s*$/.exec(String(value||""));
   if (!m) return null;
   const month=m[1].padStart(2,"0");
   const year=m[2].length===2?`20${m[2]}`:m[2];
   return {month,year};
 }
 function formatCardExpiry(value, field) {
   const parts=cardExpiryParts(value);
   if (!parts) return null;
   const shape=cardExpiryShape(field);
   return `${parts.month}${shape.separator}${shape.year===2?parts.year.slice(-2):parts.year}`;
 }
 function formatCardYear(value, field) {
   const raw=String(value||"").trim();
   if (!/^\d{2}$|^\d{4}$/.test(raw)) return null;
   const full=raw.length===2?`20${raw}`:raw;
   const hint=clean([field.getAttribute("placeholder"),field.getAttribute("aria-label")].join(" "));
   const two=field.maxLength===2 || /(^|[^y])yy($|[^y])/.test(hint);
   return two?full.slice(-2):full;
 }
 function formatCardMonth(value) {
   const raw=String(value||"").trim();
   if (!/^\d{1,2}$/.test(raw)) return null;
   return raw.padStart(2,"0");
 }
 // Option whose value or text equals one of the candidates (case-insensitive).
 function cardSelectOption(select, candidates) {
   const wanted=new Set(candidates.map(c=>clean(c)));
   return Array.from(select.options).find(o=>wanted.has(clean(o.value)) || wanted.has(clean(o.textContent))) || null;
 }
 const api={visible,clipHides,clipPathHides,onTop,currentPassword,safeForm,formState,sameFormState,snapshot,unchanged,submitCandidate,otpField,otpBoxes,otpSnapshot,queryAll,shadowRoots,isSignInLabel,
   cardToken,cardScope,cardFieldMap,cardSnapshot,cardUnchanged,cardExpiryShape,cardExpiryParts,formatCardExpiry,formatCardYear,formatCardMonth,cardSelectOption,CARD_TOKENS};
 globalThis.LGKLoginSafety=api;
})();
