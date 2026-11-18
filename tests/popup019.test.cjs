/* Popup behavior against deterministic DOM/Chrome mocks. No network. */
'use strict';
const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');const assert=require('node:assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../browser-extension/popup.js'),'utf8');
const shim=fs.readFileSync(path.join(__dirname,'../browser-extension/api.js'),'utf8');
const same=(actual,expected)=>assert.deepEqual(JSON.parse(JSON.stringify(actual)),expected);
// ping is {ok, version, locked} only: no session_id, protocol or browser_enabled.
function harness({url='https://example.test/login',diagnostics={ok:true,version:'0.3.2',locked:false},origins=[],actionDelay=0,actionResponse={ok:true},siteState={ok:true,verdict:null}}={}){
 const nodes=new Map(),runtimeRequests=[],injections=[],messages=[],siteRequests=[],storageWrites=[],timers=[];let closed=false;
 const node=id=>{if(!nodes.has(id)){const listeners={};const item={id,dataset:{},attributes:{},listeners,disabled:false,hidden:false,textContent:'',focusCount:0,focus(){this.focusCount++;},addEventListener:(name,listener)=>{listeners[name]=listener;}};item.setAttribute=(name,value)=>{item.attributes[name]=value;};item.getAttribute=name=>item.attributes[name]??null;nodes.set(id,item);}return nodes.get(id);};
 const chrome={
  i18n:{getMessage:require('./extension/i18n-stub.cjs').getMessage},
  tabs:{query:async()=>url?[{id:17,url}]:[],sendMessage:async(...args)=>{if(args[1]?.command==='site_state'){siteRequests.push(args);return siteState;}messages.push(args);if(actionDelay)await new Promise(resolve=>setTimeout(resolve,actionDelay));return actionResponse;}},
  runtime:{sendMessage:async request=>{runtimeRequests.push(request);return diagnostics;}},
  storage:{local:{get:async defaults=>({automatic_save_blocked_origins:origins}),set:async value=>{storageWrites.push(value);origins=value.automatic_save_blocked_origins;}}},
  scripting:{executeScript:async value=>{injections.push(value);}},
  webNavigation:{getAllFrames:async()=>[{frameId:0,url,errorOccurred:false}]},
 };
 const context=vm.createContext({chrome,document:{getElementById:node,body:node('body'),addEventListener:(name,listener)=>{node('document').listeners[name]=listener;}},URL,Promise,setTimeout:(fn,delay)=>{timers.push({fn,delay});},window:{close:()=>{closed=true;}}});
 vm.runInContext(shim,context);vm.runInContext(source,context);
 return {nodes,runtimeRequests,injections,messages,siteRequests,storageWrites,timers,get origins(){return origins;},get closed(){return closed;},click:async id=>{const handler=node(id).listeners.click;assert.ok(handler,`missing click handler for ${id}`);handler();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));}};
}
(async()=>{let count=0;
 async function test(name,fn){await fn();count++;console.log('PASS',name);}
 await test('initialization checks the bridge without unlocking or injecting scripts',async()=>{
  const h=harness({url:'https://example.test:8443/login'});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  same(h.runtimeRequests,[{type:'diagnostics'}]);assert.equal(h.nodes.get('site').textContent,'https://example.test:8443');
  assert.equal(h.nodes.get('chip').textContent,'Unlocked');assert.equal(h.nodes.get('chip').dataset.state,'connected');assert.equal(h.nodes.get('fill').disabled,false);assert.equal(h.injections.length,0);
  assert.match(h.nodes.get('chip').title,/0\.3\.2/);
  assert.equal(h.nodes.get('logins-ready').hidden,false);assert.equal(h.nodes.get('logins-gate').hidden,true);
 });
 await test('a ping without session_id, protocol or browser_enabled still enables the page actions',async()=>{
  const h=harness({diagnostics:{ok:true,version:'0.3.2',locked:false}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('chip').textContent,'Unlocked');
  for(const id of ['fill','identity','card','save','generate'])assert.equal(h.nodes.get(id).disabled,false,id);
  const stale=harness({diagnostics:{ok:true,version:'0.3.2'}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(stale.nodes.get('chip').textContent,'Setup required','a ping without a boolean locked flag is not treated as ready');
  assert.equal(stale.nodes.get('logins-gate').hidden,false);assert.equal(stale.nodes.get('gate-action').textContent,'Check again');
 });
 await test('locked vault actions run only after a click and only in the top frame',async()=>{
  const h=harness({diagnostics:{ok:true,version:'0.3.2',locked:true}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('chip').textContent,'Locked');assert.equal(h.nodes.get('chip').dataset.state,'locked');
  assert.equal(h.nodes.get('logins-ready').hidden,true);assert.equal(h.nodes.get('logins-gate').hidden,false);
  assert.match(h.nodes.get('gate-text').textContent,/until you unlock/);assert.equal(h.nodes.get('gate-action').textContent,'Unlock in the desktop app');
  assert.equal(h.nodes.get('gate-action').hidden,false);assert.equal(h.injections.length,0);
  await h.click('gate-action');same(h.injections,[{target:{tabId:17,frameIds:[0]},files:['api.js','heuristics.js','login-safety.js','content.js']}]);
  same(h.messages,[[17,{command:'fill_current'},{frameId:0}]]);assert.equal(h.runtimeRequests.length,1);
 });
 await test('offline shows one "Check again" action that only re-runs diagnostics',async()=>{
  const h=harness({diagnostics:{ok:false,error:'agent_offline'}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('chip').textContent,'Offline');assert.equal(h.nodes.get('logins-gate').hidden,false);
  assert.equal(h.nodes.get('gate-action').textContent,'Check again');assert.ok(h.nodes.get('gate-text').textContent);
  for(const id of ['fill','identity','card','save'])assert.equal(h.nodes.get(id).disabled,true,id);
  await h.click('gate-action');same(h.runtimeRequests,[{type:'diagnostics'},{type:'diagnostics'}]);
  assert.equal(h.injections.length,0);assert.equal(h.messages.length,0);
 });
 await test('Enter fills like the Fill button, but not while focus is on another control',async()=>{
  const h=harness();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  const keydown=h.nodes.get('document').listeners.keydown;assert.ok(keydown);
  let prevented=0;const event=target=>({key:'Enter',target,defaultPrevented:false,isComposing:false,preventDefault(){prevented++;}});
  keydown(event({tagName:'BUTTON'}));keydown(event({tagName:'INPUT'}));assert.equal(prevented,0);
  let clicked=0;h.nodes.get('fill').click=()=>{clicked++;};
  keydown(event(h.nodes.get('body')));assert.equal(clicked,1);assert.equal(prevented,1);
  h.nodes.get('fill').disabled=true;keydown(event(h.nodes.get('body')));assert.equal(clicked,1,'a disabled Fill is not triggered');
 });
 await test('Generate password opens the generator panel and sends nothing to the page',async()=>{
  const h=harness();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  await h.click('generate');assert.equal(h.nodes.get('generator').open,true);assert.equal(h.nodes.get('generate').getAttribute('aria-expanded'),'true');
  assert.equal(h.nodes.get('gen-fill').focusCount,1);assert.equal(h.messages.length,0);assert.equal(h.injections.length,0);
  await h.click('generate');assert.equal(h.nodes.get('generator').open,false);assert.equal(h.nodes.get('generate').getAttribute('aria-expanded'),'false');
 });
 await test('the popup only ever asks the background for diagnostics (no vault data request exists)',async()=>{
  const h=harness();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  await h.click('fill');same(h.runtimeRequests,[{type:'diagnostics'}]);same(h.messages.map(m=>m[1]),[{command:'fill_current'}]);
  assert.doesNotMatch(source,/begin_browser|get_browser|choices|entry_id/);
 });
 await test('one pending action disables sibling actions and prevents a second prompt',async()=>{
  const h=harness({actionDelay:40});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  await h.click('fill');for(const id of ['fill','identity','card','save'])assert.equal(h.nodes.get(id).disabled,true,id);
  await h.click('identity');assert.equal(h.injections.length,1);assert.equal(h.messages.length,1);
  await new Promise(resolve=>setTimeout(resolve,60));
  for(const id of ['fill','identity','card','save'])assert.equal(h.nodes.get(id).disabled,false,id);
 });
 await test('recoverable field-action failure restores keyboard focus to its action',async()=>{
  const h=harness({actionResponse:{ok:false,error:'not_found'}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  await h.click('fill');assert.equal(h.nodes.get('fill').disabled,false);assert.equal(h.nodes.get('fill').focusCount,1);
  assert.match(h.nodes.get('status').textContent,/No saved login was found/);
 });
 await test('automatic-save settings match the exact origin including subdomain and port',async()=>{
  const h=harness({url:'https://login.example.test:8443/account',origins:['https://example.test','https://login.example.test','https://login.example.test:8443']});
  await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('automatic').getAttribute('aria-checked'),'false');
  await h.click('automatic');same(h.origins,['https://example.test','https://login.example.test']);
  await h.click('automatic');same(h.origins,['https://example.test','https://login.example.test','https://login.example.test:8443']);
 });
 await test('browser-internal pages keep all page actions disabled',async()=>{
  const h=harness({url:'chrome://settings'});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('site').textContent,'This page is not available to LocalGateKeys.');
  for(const id of ['fill','identity','card','save','automatic'])assert.equal(h.nodes.get(id).disabled,true,id);
  assert.equal(h.nodes.get('logins-gate').hidden,false);assert.equal(h.nodes.get('gate-action').hidden,true,'no action to offer on a browser page');
  assert.equal(h.injections.length,0);
 });
 await test('site row shows the app verdict for the page, asked from the top frame only',async()=>{
  const states={exact:'Verified site',related:'Related site',lookalike:'Lookalike site',unknown:'New site'};
  for(const [kind,label] of Object.entries(states)){
   const h=harness({siteState:{ok:true,verdict:{kind,reason:'x',matched:null,pair:null}}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
   same(h.siteRequests,[[17,{command:'site_state'},{frameId:0}]]);
   assert.equal(h.nodes.get('site-state').textContent,label);assert.equal(h.nodes.get('site-state').dataset.state,kind);assert.equal(h.nodes.get('site-state').hidden,false);
   assert.equal(h.injections.length,0,'no script injection for the state');
  }
  for(const siteState of [{ok:true,verdict:null},{ok:true,verdict:{kind:'trusted'}},null]){
   const h=harness({siteState});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
   assert.equal(h.nodes.get('site-state').hidden,true);assert.equal(h.nodes.get('site-state').textContent,'');
  }
 });
 console.log(`${count} popup cases passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
