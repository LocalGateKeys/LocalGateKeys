/* Popup behavior against deterministic DOM/Chrome mocks. No network. */
'use strict';
const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');const assert=require('node:assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../browser-extension/popup.js'),'utf8');
const shim=fs.readFileSync(path.join(__dirname,'../browser-extension/api.js'),'utf8');
const same=(actual,expected)=>assert.deepEqual(JSON.parse(JSON.stringify(actual)),expected);
// ping is {ok, version, locked} only: no session_id, protocol or browser_enabled.
function harness({url='https://example.test/login',diagnostics={ok:true,version:'0.3.2',locked:false},origins=[],actionDelay=0,actionResponse={ok:true}}={}){
 const nodes=new Map(),runtimeRequests=[],injections=[],messages=[],storageWrites=[],timers=[];let closed=false;
 const node=id=>{if(!nodes.has(id)){const listeners={};const item={id,dataset:{},attributes:{},listeners,disabled:false,hidden:false,textContent:'',focusCount:0,focus(){this.focusCount++;},addEventListener:(name,listener)=>{listeners[name]=listener;}};item.setAttribute=(name,value)=>{item.attributes[name]=value;};item.getAttribute=name=>item.attributes[name]??null;nodes.set(id,item);}return nodes.get(id);};
 const chrome={
  tabs:{query:async()=>url?[{id:17,url}]:[],sendMessage:async(...args)=>{messages.push(args);if(actionDelay)await new Promise(resolve=>setTimeout(resolve,actionDelay));return actionResponse;}},
  runtime:{sendMessage:async request=>{runtimeRequests.push(request);return diagnostics;}},
  storage:{local:{get:async defaults=>({automatic_save_blocked_origins:origins}),set:async value=>{storageWrites.push(value);origins=value.automatic_save_blocked_origins;}}},
  scripting:{executeScript:async value=>{injections.push(value);}},
  webNavigation:{getAllFrames:async()=>[{frameId:0,url,errorOccurred:false}]},
 };
 const context=vm.createContext({chrome,document:{getElementById:node},URL,Promise,setTimeout:(fn,delay)=>{timers.push({fn,delay});},window:{close:()=>{closed=true;}}});
 vm.runInContext(shim,context);vm.runInContext(source,context);
 return {nodes,runtimeRequests,injections,messages,storageWrites,timers,get origins(){return origins;},get closed(){return closed;},click:async id=>{const handler=node(id).listeners.click;assert.ok(handler,`missing click handler for ${id}`);handler();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));}};
}
(async()=>{let count=0;
 async function test(name,fn){await fn();count++;console.log('PASS',name);}
 await test('initialization checks the bridge without unlocking or injecting scripts',async()=>{
  const h=harness({url:'https://example.test:8443/login'});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  same(h.runtimeRequests,[{type:'diagnostics'}]);assert.equal(h.nodes.get('site').textContent,'https://example.test:8443');
  assert.equal(h.nodes.get('connection-title').textContent,'Connected');assert.equal(h.nodes.get('fill').disabled,false);assert.equal(h.injections.length,0);
  assert.match(h.nodes.get('connection-description').textContent,/0\.3\.2/);
 });
 await test('a ping without session_id, protocol or browser_enabled still enables the page actions',async()=>{
  const h=harness({diagnostics:{ok:true,version:'0.3.2',locked:false}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('connection-title').textContent,'Connected');
  for(const id of ['fill','identity','save','generate'])assert.equal(h.nodes.get(id).disabled,false,id);
  const stale=harness({diagnostics:{ok:true,version:'0.3.2'}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(stale.nodes.get('connection-title').textContent,'Setup required','a ping without a boolean locked flag is not treated as ready');
 });
 await test('locked vault actions run only after a click and only in the top frame',async()=>{
  const h=harness({diagnostics:{ok:true,version:'0.3.2',locked:true}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('fill').disabled,false);assert.match(h.nodes.get('site-hint').textContent,/request unlock/);assert.equal(h.injections.length,0);
  await h.click('fill');same(h.injections,[{target:{tabId:17,frameIds:[0]},files:['api.js','heuristics.js','login-safety.js','content.js']}]);
  same(h.messages,[[17,{command:'fill_current'},{frameId:0}]]);assert.equal(h.runtimeRequests.length,1);
 });
 await test('one pending action disables sibling actions and prevents a second prompt',async()=>{
  const h=harness({actionDelay:40});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  await h.click('fill');for(const id of ['fill','identity','save','generate'])assert.equal(h.nodes.get(id).disabled,true,id);
  await h.click('identity');assert.equal(h.injections.length,1);assert.equal(h.messages.length,1);
  await new Promise(resolve=>setTimeout(resolve,60));
  for(const id of ['fill','identity','save','generate'])assert.equal(h.nodes.get(id).disabled,false,id);
 });
 await test('recoverable field-action failure restores keyboard focus to its action',async()=>{
  const h=harness({actionResponse:{ok:false,error:'not_found'}});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  await h.click('fill');assert.equal(h.nodes.get('fill').disabled,false);assert.equal(h.nodes.get('fill').focusCount,1);
  assert.match(h.nodes.get('status').textContent,/No saved login was found/);
 });
 await test('automatic-save settings match the exact origin including subdomain and port',async()=>{
  const h=harness({url:'https://login.example.test:8443/account',origins:['https://example.test','https://login.example.test','https://login.example.test:8443']});
  await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('automatic').getAttribute('aria-pressed'),'false');
  await h.click('automatic');same(h.origins,['https://example.test','https://login.example.test']);
  await h.click('automatic');same(h.origins,['https://example.test','https://login.example.test','https://login.example.test:8443']);
 });
 await test('browser-internal pages keep all page actions disabled',async()=>{
  const h=harness({url:'chrome://settings'});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.nodes.get('site').textContent,'This page is not available to LocalGateKeys.');
  for(const id of ['fill','identity','save','generate','automatic'])assert.equal(h.nodes.get(id).disabled,true,id);
  assert.equal(h.injections.length,0);
 });
 console.log(`${count} popup cases passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
