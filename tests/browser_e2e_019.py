"""Offline Chromium DOM behavior tests with a simulated origin, native bridge and dummy credentials.
Run manually: python tests/browser_e2e_019.py [path-to-chromium]
No internet or real accounts are used. Not a Windows native-messaging test.
"""
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
URL='http://localhost:8765/login'
HTML='''<!doctype html><html><head><base href="http://localhost:8765/login"><style>body{padding:60px;background:#edf1f6}input{display:block;width:320px;height:40px;margin:12px}button{padding:12px;margin:12px}</style></head><body>
<form id="login" method="post" action="/signin"><input id="user" autocomplete="username" required><input id="password" type="password" autocomplete="current-password" required><button id="signin" type="submit">Sign in</button></form>
<script>window.submits=0;document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submits++;});</script></body></html>'''
STUB='''window.requests=[];window.signIn=false;window.failureStage='';window.delayStage='';
window.chrome={runtime:{id:'demo-extension',lastError:null,getURL:p=>'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jN5cAAAAASUVORK5CYII=',
onMessage:{addListener:f=>window.contentListener=f},sendMessage:(r,cb)=>{
window.requests.push(r.type);let value={ok:true};
if(r.type===window.failureStage)value={ok:false,error:'session_changed'};
else if(r.type==='begin_browser')value={ok:true,choices:[{entry_id:'one',label:'Demo',username:'test@example.test'}],grant:'grant-demo',session_id:'session-demo',profile:{name:'Demo',color:'#123abc'}};
else if(r.type==='get_browser')value={ok:true,session_id:'session-demo',sign_in:window.signIn,credential:{entry_id:'one',username:'test@example.test',password:'Test-Only-Secret-019!'}};
else if(r.type==='ping')value={ok:true,locked:false,browser_enabled:true,session_id:'session-demo'};
setTimeout(()=>cb(value),r.type===window.delayStage?150:1);
}}};'''

def run():
 results=[]
 with sync_playwright() as p:
  browser=p.chromium.launch(executable_path=sys.argv[1] if len(sys.argv)>1 else '/usr/bin/chromium',headless=True,args=['--no-sandbox'])
  def page(html=HTML):
   context=browser.new_context(viewport={'width':1100,'height':800})
   # This sandbox's Chromium policy blocks navigation, including localhost. Use
   # an offline DOM with an injected origin/secure-crypto context for these tests.
   # Production files are not altered; live extension/native integration remains a Windows test.
   pg=context.new_page();pg.set_content(html);pg.evaluate(STUB)
   pg.evaluate("window.testLocation={origin:'http://localhost:8765',href:'http://localhost:8765/login'}")
   prefix="const location=window.testLocation;const crypto={getRandomValues:a=>window.crypto.getRandomValues(a),randomUUID:()=>String(Math.random())+String(Date.now())};\n"
   for file in ('login-safety.js','content.js'):
    pg.add_script_tag(content='(()=>{'+prefix+(ROOT/'browser-extension'/file).read_text()+'})()')
   return pg
  def click(pg):
   host=pg.locator('[data-localvault-field-icon]').last
   host.wait_for();box=host.bounding_box();pg.mouse.click(box['x']+12,box['y']+12);pg.wait_for_timeout(350)
  def check(name,fn):
   fn();results.append(name);print('PASS',name)
  def default_off():
   pg=page();click(pg);assert pg.locator('#password').input_value()=='Test-Only-Secret-019!';assert pg.evaluate('submits')==0;pg.context.close()
  check('fill only by default',default_off)
  def enabled():
   pg=page();pg.evaluate('signIn=true');click(pg);assert pg.evaluate('submits')==1;assert pg.evaluate('requests.filter(x=>x==="submit_browser").length')==1;pg.context.close()
  check('one opt-in sign-in',enabled)
  def ambiguous():
   pg=page(HTML.replace('</form>','<button type="submit">Sign in</button></form>'));pg.evaluate('signIn=true');click(pg);assert pg.evaluate('submits')==0;assert pg.locator('#password').input_value();pg.context.close()
  check('ambiguous submit buttons stay manual',ambiguous)
  def get_form():
   pg=page(HTML.replace('method="post"','method="get"'));pg.evaluate('signIn=true');click(pg);assert pg.evaluate('submits')==0;pg.context.close()
  check('GET form never auto-submits credentials',get_form)
  def changed():
   pg=page();pg.evaluate("document.querySelector('#user').addEventListener('input',()=>{const old=document.querySelector('#password');const next=old.cloneNode();next.value='';old.replaceWith(next);},{once:true})")
   click(pg);assert pg.locator('#password').input_value()=='';assert pg.evaluate('submits')==0;pg.context.close()
  check('replaced password field refused after username event',changed)
  def stale(stage, filled):
   pg=page();pg.evaluate('signIn=true');pg.evaluate('(s)=>failureStage=s',stage);click(pg)
   assert pg.evaluate('submits')==0;assert bool(pg.locator('#password').input_value())==filled;pg.context.close()
  check('lock before credential release cancels',lambda:stale('get_browser',False))
  check('lock before field write cancels',lambda:stale('validate_browser',False))
  check('lock after fill cancels submission',lambda:stale('submit_browser',True))
  def same_origin_spa_navigation():
   pg=page();pg.evaluate("delayStage='get_browser'");pg.evaluate("setTimeout(()=>testLocation.href='http://localhost:8765/different?step=2#login',60)");click(pg)
   assert pg.locator('#password').input_value()=='Test-Only-Secret-019!';pg.context.close()
  check('same-origin SPA route change keeps valid pending fill',same_origin_spa_navigation)
  def hidden():
   pg=page(HTML.replace('id="password"','id="password" style="display:none"'));assert pg.locator('[data-localvault-field-icon]').count()==0;assert pg.evaluate('requests.length')==0;pg.context.close()
  check('hidden password fields are not offered',hidden)
  def cross_origin():
   pg=page(HTML.replace('action="/signin"','action="https://other.example.test/login"'));click(pg);assert pg.locator('#password').input_value()=='';assert pg.evaluate('requests.length')==0;pg.context.close()
  check('cross-origin form action is refused',cross_origin)
  def generate():
   html=HTML.replace('autocomplete="current-password"','autocomplete="new-password"').replace('<button id=', '<input id="confirm" type="password" autocomplete="new-password"><button id=')
   pg=page(html);pg.evaluate("contentListener({command:'generate_new'},{id:'demo-extension'},r=>window.result=r)")
   value=pg.locator('#password').input_value();assert len(value)==24 and value==pg.locator('#confirm').input_value();assert pg.evaluate('submits')==0;pg.context.close()
  check('generate new password fills confirmation without submit',generate)
  def change_form():
   pg=page(HTML.replace('<button id=', '<input type="password" autocomplete="new-password"><button id='));pg.evaluate('signIn=true');click(pg);assert pg.evaluate('submits')==0;pg.context.close()
  check('password-change form not automatically submitted',change_form)
  browser.close()
 print(json.dumps({'browser_cases_passed':len(results),'cases':results},indent=2))
if __name__=='__main__':run()
