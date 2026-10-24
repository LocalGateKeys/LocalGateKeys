/* Service-worker behavior against deterministic browser/native mocks. No network. */
'use strict';
const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');const assert=require('node:assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../browser-extension/background.js'),'utf8');
const shim=fs.readFileSync(path.join(__dirname,'../browser-extension/api.js'),'utf8');
function harness({afterNative=null,response={ok:true},framePatch={},tabPatch={},nativeError=null}={}){
 let listener;const calls=[],nudges=[],navListeners={};const id='testextension';const url='https://example.test/login';
 const frame={documentId:'document-A',url,documentLifecycle:'active',errorOccurred:false,parentFrameId:-1,...framePatch};
 const frames={0:frame};
 const tab={active:true,discarded:false,...tabPatch};
 // Promise-only mocks: the extension never passes callbacks (Firefox browser.* has none).
 const chrome={runtime:{id,getManifest:()=>({version:'0.3.0',permissions:['favicon']}),getURL:p=>`chrome-extension://${id}/${p}`,
 onMessage:{addListener:f=>listener=f},sendNativeMessage:(host,req)=>{calls.push({host,req});if(afterNative)afterNative(frame,tab);return nativeError?Promise.reject(nativeError):Promise.resolve({...response});}},
 webNavigation:{getFrame:async({frameId})=>frames[frameId],onDOMContentLoaded:{addListener:f=>navListeners.dom=f},onCompleted:{addListener:f=>navListeners.completed=f},onHistoryStateUpdated:{addListener:f=>navListeners.history=f}},tabs:{get:async()=>tab,sendMessage:(tabId,message,options)=>{nudges.push({tabId,message,options});return Promise.resolve();}}};
 const context=vm.createContext({chrome,URL,Set,Promise,setTimeout,clearTimeout,fetch:async()=>({ok:false})});
 vm.runInContext(shim,context);vm.runInContext(source,context);
 const sender={id,tab:{id:8},frameId:0,documentId:'document-A',url};
 return {calls,nudges,navListeners,frame,tab,sender,send:(req={},who=sender)=>new Promise(resolve=>listener({type:'begin_browser',origin:'https://example.test',operation_id:'operation123',user_gesture:true,...req},who,resolve))};
}
(async()=>{let count=0;
 async function test(name,f){await f();count++;console.log('PASS',name);}
 await test('browser assigns document context; ignores forged identifiers',async()=>{
  const h=harness();const r=await h.send({context:'forged',tabId:999,documentId:'forged'});assert.equal(r.ok,true);
  assert.deepEqual(JSON.parse(h.calls[0].req.context),[8,'document-A','https://example.test','operation123']);
  assert.equal(h.calls[0].req.protocol,2);
 });

 await test('DOMContentLoaded, completed and SPA navigation nudge the page to check pending saves',async()=>{
  const h=harness();h.navListeners.dom({tabId:8,frameId:0,url:'https://example.test/home'});h.navListeners.completed({tabId:8,frameId:0,url:'https://example.test/home'});h.navListeners.history({tabId:8,frameId:0,url:'https://example.test/app'});
  assert.equal(h.nudges.length,3);assert.equal(h.nudges[0].message.command,'check_pending_save');
  assert.equal(h.nudges[0].options.frameId,0);
 });
 await test('cross-origin request refused before native access',async()=>{const h=harness();assert.equal((await h.send({origin:'https://other.test'})).ok,false);assert.equal(h.calls.length,0);});
 await test('non-extension sender refused',async()=>{const h=harness();assert.equal((await h.send({}, {...h.sender,id:'imposter'})).ok,false);assert.equal(h.calls.length,0);});
 await test('subframe refused',async()=>{const h=harness();assert.equal((await h.send({}, {...h.sender,frameId:2})).ok,false);assert.equal(h.calls.length,0);});
 await test('stale document refused',async()=>{const h=harness({framePatch:{documentId:'document-B'}});assert.equal((await h.send()).ok,false);assert.equal(h.calls.length,0);});
 await test('inactive lifecycle refused',async()=>{const h=harness({framePatch:{documentLifecycle:'cached'}});assert.equal((await h.send()).ok,false);assert.equal(h.calls.length,0);});
 await test('same-origin SPA route change is allowed',async()=>{const h=harness({framePatch:{url:'https://example.test/auth?flow=login#step'}});assert.equal((await h.send()).ok,true);});
 await test('cross-origin frame URL is refused',async()=>{const h=harness({framePatch:{url:'https://other.test/login'}});assert.equal((await h.send()).ok,false);assert.equal(h.calls.length,0);});
 await test('inactive tab cannot release credentials',async()=>{const h=harness({tabPatch:{active:false}});assert.equal((await h.send({type:'get_browser',grant:'grant',entry_id:'id'})).ok,false);assert.equal(h.calls.length,0);});
 await test('new document while native request runs drops response',async()=>{const h=harness({afterNative:f=>{f.documentId='document-B';}});assert.equal((await h.send()).error,'destination_changed');});
 await test('same-document same-origin route change during native request is allowed',async()=>{const h=harness({afterNative:f=>{f.url='https://example.test/auth/continue?x=1';}});assert.equal((await h.send()).ok,true);});
 await test('tab switch while native request runs drops response',async()=>{const h=harness({afterNative:(_,t)=>{t.active=false;}});assert.equal((await h.send()).error,'destination_changed');});
 await test('only packaged popup may request non-tab diagnostics',async()=>{
  const h=harness();assert.equal((await h.send({type:'diagnostics'},{id:h.sender.id,url:'chrome-extension://testextension/popup.html'})).ok,true);
  assert.equal((await h.send({type:'get_browser'},{id:h.sender.id,url:'chrome-extension://testextension/popup.html'})).ok,false);
 });
 await test('unknown actions never forwarded',async()=>{const h=harness();assert.equal((await h.send({type:'dump_vault'})).ok,false);assert.equal(h.calls.length,0);});
 await test('identity requests forward only typed reviewed fields and browser context',async()=>{
  const h=harness();const r=await h.send({type:'approve_identity_browser',identity_protocol:1,entry_id:'identity-1',revision:3,fields:['email','phone'],approval:'approval-1'});
  assert.equal(r.ok,true);assert.equal(h.calls.length,1);
  const payload=h.calls[0].req;assert.equal(payload.action,'approve_identity_browser');assert.equal(payload.identity_protocol,1);
  assert.deepEqual(Array.from(payload.fields),['email','phone']);assert.equal(payload.entry_id,'identity-1');assert.equal(payload.revision,3);assert.equal(payload.approval,'approval-1');
  assert.equal(payload.tabId,undefined);assert.deepEqual(JSON.parse(payload.context),[8,'document-A','https://example.test','operation123']);
 });
 await test('identity rejects credential-like fields before native access',async()=>{
  const h=harness();const r=await h.send({type:'release_identity_browser',identity_protocol:1,fields:['password']});
  assert.equal(r.error,'invalid_identity_fields');assert.equal(h.calls.length,0);
 });
 await test('native exit error becomes actionable non-sensitive message',async()=>{const h=harness({nativeError:{message:'Native host has exited.'}});const r=await h.send();assert.equal(r.error,'native_host_error');assert.match(r.message,/Connections/);});
 await test('oversized username rejected',async()=>{const h=harness();assert.equal((await h.send({type:'save_browser',username:'x'.repeat(513),password:'dummy'})).ok,false);assert.equal(h.calls.length,0);});
 await test('identity rejection stays actionable, not app-offline',async()=>{
  const h=harness({response:{ok:false,error:'client_not_allowed',message:'ignored'}});
  const r=await h.send();assert.equal(r.error,'client_not_allowed');assert.match(r.message,/repair_browser_bridge/);assert.equal(h.calls.length,1);
 });
 await test('bridge access denied is distinct from missing app',async()=>{
  const h=harness({response:{ok:false,error:'agent_access_denied',stage:'connect',winerror:5}});
  const r=await h.send();assert.equal(r.error,'agent_access_denied');assert.match(r.message,/Windows denied/);assert.equal(r.winerror,5);
 });
 await test('older generic offline reply explains it may be a bridge error',async()=>{
  const h=harness({response:{ok:false,error:'agent_offline'}});
  const r=await h.send();assert.match(r.message,/older native host/);assert.match(r.message,/already open/);
 });
 await test('lost sign-in reply is never automatically retried',async()=>{
  const h=harness({response:{ok:false,error:'agent_connection_lost'}});
  const r=await h.send({type:'submit_browser',entry_id:'demo',grant:'demo-grant'});
  assert.equal(r.error,'agent_connection_lost');assert.equal(h.calls.length,1);assert.match(r.message,/No automatic retry/);
 });
 await test('missing state tells user to finish profile selection',async()=>{
  const h=harness({response:{ok:false,error:'agent_state_missing'}});
  assert.match((await h.send()).message,/choosing a profile/);
 });
 await test('gesture nonce is forwarded verbatim; malformed nonces are refused before native access',async()=>{
  const nonce='ab'.repeat(16);
  const h=harness({response:{ok:true,credential:{username:'alice',password:'pw'}}});
  const r=await h.send({type:'get_browser',grant:'grant-1',entry_id:'e1',gesture_nonce:nonce});
  assert.equal(r.ok,true);assert.equal(h.calls.length,1);
  assert.equal(h.calls[0].req.gesture_nonce,nonce);assert.equal(h.calls[0].req.user_gesture,true);
  for(const bad of ['ZZ'.repeat(16),'ab'.repeat(15),'ab'.repeat(17),42,{}]){
   const refused=await h.send({type:'get_browser',grant:'grant-1',entry_id:'e1',gesture_nonce:bad});
   assert.equal(refused.error,'invalid_gesture_nonce');
  }
  assert.equal(h.calls.length,1,'no malformed nonce reached the native host');
  const without=await h.send({type:'get_browser',grant:'grant-1',entry_id:'e1'});
  assert.equal(without.ok,true);assert.equal('gesture_nonce' in h.calls[1].req,false,'absent nonce is not invented');
 });
 await test('begin_gesture_browser is allowed, carries user_gesture and needs the active tab',async()=>{
  const h=harness({response:{ok:true,gesture_nonce:'cd'.repeat(16),gesture_expires_in:30}});
  const r=await h.send({type:'begin_gesture_browser'});
  assert.equal(r.ok,true);assert.equal(r.gesture_nonce,'cd'.repeat(16));
  assert.equal(h.calls[0].req.action,'begin_gesture_browser');assert.equal(h.calls[0].req.user_gesture,true);
  assert.deepEqual(JSON.parse(h.calls[0].req.context),[8,'document-A','https://example.test','operation123']);
  const inactive=harness({tabPatch:{active:false}});
  assert.equal((await inactive.send({type:'begin_gesture_browser'})).error,'destination_changed');assert.equal(inactive.calls.length,0);
 });
 await test('gesture errors get actionable messages',async()=>{
  for(const [error,pattern] of [['gesture_nonce_invalid',/Click again/],['gesture_nonce_required',/Update the browser extension/],['user_gesture_required',/in-page LocalGateKeys button/]]){
   const h=harness({response:{ok:false,error}});
   const r=await h.send({type:'save_browser',username:'alice',password:'pw',gesture_nonce:'ef'.repeat(16)});
   assert.equal(r.error,error);assert.match(r.message,pattern);
  }
 });
 await test('ping diagnostics pass {ok, version, locked} through without inventing lease fields',async()=>{
  const h=harness({response:{ok:true,version:'0.3.2',locked:true}});
  const r=await h.send({type:'diagnostics'},{id:h.sender.id,url:'chrome-extension://testextension/popup.html'});
  assert.equal(r.ok,true);assert.equal(r.locked,true);assert.equal(r.version,'0.3.2');assert.equal(r.extension_version,'0.3.0');
  assert.equal(r.session_id,undefined);assert.equal(r.browser_enabled,undefined);assert.equal(r.protocol,undefined);
  assert.equal(h.calls[0].req.action,'ping');
 });
 console.log(`${count} service-worker cases passed`);
})().catch(e=>{console.error(e);process.exitCode=1;});
