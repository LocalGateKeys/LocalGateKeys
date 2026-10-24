from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

import pytest

from localvault.access_policy import is_sign_in_label, may_sign_in, normalized_policy
from localvault.backup import (
    BackupError,
    export_encrypted_backup,
    restore_verified_backup,
    verify_encrypted_backup,
)
from localvault.breach_check import BreachCheckError, check_password
from localvault.browser_broker import BrowserBroker
from localvault.import_preview import ImportError as PreviewError
from localvault.import_preview import apply_import, classify, load_import
from broker_host import BrokerHostBase as RuntimeActions
from localvault.session_guard import SessionGuard, StaleSession
from localvault.settings import AppSettings
from localvault.vault import InvalidMasterPassword, VaultError, create_vault, unlock_vault

MASTER='Demo-only-master-019!'
NEW='Demo-only-new-master-019!'
KDF={'memory_cost_kib':8192,'time_cost':1,'parallelism':1}
@pytest.fixture
def vault(tmp_path):
    s=create_vault(tmp_path/'vault.json',MASTER,kdf_overrides=KDF)
    yield s
    s.lock()

def add(s,user='alice',password='Test-only-password-019!'):
    return s.upsert_web(origin='https://example.test',username=user,password=password,label=user)

class Clock:
    def __init__(self):self.m=100.;self.w=1000.
    def tick(self,n):self.m+=n;self.w+=n
    def guard(self):return SessionGuard('alice',monotonic=lambda:self.m,wall_clock=lambda:self.w)

def test_workday_is_overall_not_sliding():
    c=Clock();g=c.guard();lease=g.open(28800)
    for _ in range(7):c.tick(3600);g.require(lease)
    assert g.remaining()==3600
    c.tick(3600)
    assert g.expired()
    with pytest.raises(StaleSession):g.lease()

def test_workday_counts_sleep_and_wall_clock_cannot_extend():
    c=Clock();g=c.guard();lease=g.open(28800);c.w+=28801
    assert not g.valid(lease)
    c=Clock();g=c.guard();lease=g.open(60);c.w-=2000;c.m+=61
    assert not g.valid(lease)

@pytest.mark.parametrize('change',['lock','profile','unlock_again'])
def test_invalidate_all_capabilities(change):
    c=Clock();g=c.guard();l=g.open(28800);token=g.grant('https://a.test','document-A',['a'])
    if change=='profile':g.invalidate('bob')
    elif change=='unlock_again':g.open(28800)
    else:g.invalidate()
    assert not g.valid(l)
    with pytest.raises(StaleSession):g.permission(token,'https://a.test','document-A','a')

@pytest.mark.parametrize('origin,context,entry',[('https://evil.test','doc','a'),('https://a.test','newdoc','a'),('https://a.test','doc','b')])
def test_grant_scope(origin,context,entry):
    g=SessionGuard('a');g.open(3600);token=g.grant('https://a.test','doc',['a'])
    with pytest.raises(StaleSession):g.permission(token,origin,context,entry,release=True)

def test_grant_is_one_release_and_one_submit():
    g=SessionGuard('a');g.open(3600);t=g.grant('https://a.test','doc',['a','b'])
    with pytest.raises(StaleSession):g.permission(t,'https://a.test','doc','a',submit=True)
    g.permission(t,'https://a.test','doc','a',release=True)
    with pytest.raises(StaleSession):g.permission(t,'https://a.test','doc','a',release=True)
    with pytest.raises(StaleSession):g.permission(t,'https://a.test','doc','b',submit=True)
    g.permission(t,'https://a.test','doc','a',submit=True)
    with pytest.raises(StaleSession):g.permission(t,'https://a.test','doc','a',submit=True)

def test_grant_short_window():
    c=Clock();g=c.guard();g.open(3600);t=g.grant('o','d',['a']);g.permission(t,'o','d','a',release=True)
    c.tick(9)
    with pytest.raises(StaleSession):g.permission(t,'o','d','a',submit=True)

@pytest.mark.parametrize('name,expected',[('Sign in',True),('Log in',True),('Zaloguj się',True),('Continue',False),('Buy now',False),('Submit',False),('Reset password',False),('Delete account',False)])
def test_narrow_signin_labels(name,expected):assert is_sign_in_label(name)==expected

def test_signin_off_and_entry_policy():
    assert not may_sign_in({},False)
    assert may_sign_in({},True)
    assert not may_sign_in({'policy':{'sign_in':'never'}},True)
    assert not may_sign_in({'policy':{'fill':'never','sign_in':'enabled'}},True)
    assert may_sign_in({'policy':{'sign_in':'enabled'}},False)
    assert normalized_policy({'fill':'garbage'})['fill']=='never'

def test_settings_migrate_conservatively(tmp_path):
    p=tmp_path/'settings.json';p.write_text(json.dumps({'version':2,'auto_lock_seconds':28800,'fill_and_sign_in':'true'}))
    s=AppSettings.load(p)
    assert s.max_session_seconds==28800 and s.auto_lock_seconds==28800
    assert not s.fill_and_sign_in and not s.breach_check_enabled
    s.idle_source='vault';s.save(p);assert AppSettings.load(p).idle_source=='vault'

def test_trash_roundtrip_and_no_fill(vault):
    i=add(vault);vault.set_details(i,favorite=True,tags=['work'],policy={'sign_in':'enabled'})
    vault.delete(i)
    assert not vault.find_web('https://example.test') and vault.get_entry(i) is None
    assert vault.trash_summaries()[0]['id']==i
    assert 'password' not in vault.trash_summaries()[0]
    vault.restore_deleted(i)
    assert vault.get_entry(i)['tags']==['work']
    assert vault.get_entry(i)['policy']['sign_in']=='never'
    vault.delete(i);vault.purge_deleted(i);assert not vault.trash_summaries()

def test_trash_does_not_overwrite_new_account(vault):
    i=add(vault);vault.delete(i);add(vault)
    with pytest.raises(VaultError):vault.restore_deleted(i)
    assert len(vault.summaries())==1

def test_metadata_totp_and_history_encrypted(vault):
    i=add(vault)
    vault.set_details(i,favorite=True,tags=['private'],notes='sensitive note',totp={'secret':'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'},recovery_codes=['secret-code'],custom_fields=[{'name':'PIN','value':'918273','hidden':True}])
    for n in range(8):add(vault,password=f'Test-only-new-{n}!')
    assert len(vault.password_history(i))==5
    assert vault.consume_recovery_code(i,0)=='secret-code'
    assert vault.get_entry(i)['recovery_codes']==[]
    raw=vault.path.read_text()
    for s in ('alice','sensitive note','918273','GEZDGNBV','secret-code'):assert s not in raw

def test_master_password_change_keeps_content(tmp_path,vault):
    i=add(vault);old=vault.path.read_bytes();oldkey=vault._key
    vault.change_master_password(MASTER,NEW)
    assert not any(oldkey)
    vault.lock()
    with pytest.raises(InvalidMasterPassword):unlock_vault(vault.path,MASTER)
    new=unlock_vault(vault.path,NEW);assert new.get_entry(i)['username']=='alice';new.lock()
    previous=tmp_path/'old.json';previous.write_bytes(old)
    old=unlock_vault(previous,MASTER);assert old.get_entry(i);old.lock()

def test_failed_rekey_rolls_back(vault,monkeypatch):
    add(vault);old=vault.path.read_bytes()
    import localvault.vault as module
    def fail(*args,**kwargs):raise OSError('disk unavailable')
    monkeypatch.setattr(module,'atomic_write_json',fail)
    with pytest.raises(VaultError):vault.change_master_password(MASTER,NEW)
    assert vault.path.read_bytes()==old
    vault.verify_master_password(MASTER)

def test_failed_write_restores_memory(vault,monkeypatch):
    i=add(vault);old=vault.get_entry(i);disk=vault.path.read_bytes()
    import localvault.vault as module
    monkeypatch.setattr(module,'atomic_write_json',lambda *a,**k:(_ for _ in ()).throw(OSError('failure')))
    with pytest.raises(VaultError):vault.update_entry_fields(i,password='New-not-saved!')
    assert vault.get_entry(i)==old and vault.path.read_bytes()==disk

def test_transaction_invalid_fields_leaves_no_partial_changes(vault):
    i=add(vault);before=vault.get_entry(i)
    with pytest.raises(VaultError):
        with vault.transaction():
            vault.update_entry_fields(i,label='Changed')
            vault.set_details(i,custom_fields='invalid')
    assert vault.get_entry(i)==before

def test_changed_file_refuses_overwrite(vault):
    i=add(vault);vault.path.write_text('{}')
    with pytest.raises(VaultError,match='changed on disk'):vault.update_entry_fields(i,label='No')
    assert vault.path.read_text()=='{}'

def test_backup_verify_restore_no_overwrite(tmp_path,vault):
    i=add(vault);vault.set_details(i,policy={'sign_in':'enabled'})
    backup=tmp_path/'backup.lgk';original=vault.path.read_bytes()
    export_encrypted_backup(backup,vault_file=vault.path,settings_file=None,profile_name='demo',backup_password=NEW)
    report=verify_encrypted_backup(backup,backup_password=NEW,vault_password=MASTER)
    assert report['entries']==1 and vault.path.read_bytes()==original
    with pytest.raises(BackupError):verify_encrypted_backup(backup,backup_password=MASTER,vault_password=MASTER)
    with pytest.raises(BackupError):verify_encrypted_backup(backup,backup_password=NEW,vault_password=NEW)
    with pytest.raises(BackupError):restore_verified_backup(backup,vault_file=vault.path,settings_file=None,backup_password=NEW,vault_password=MASTER)
    dest=tmp_path/'restored.json'
    restore_verified_backup(backup,vault_file=dest,settings_file=None,backup_password=NEW,vault_password=MASTER)
    r=unlock_vault(dest,MASTER);assert r.get_entry(i)['policy']['sign_in']=='never';r.lock()

def test_backup_rejects_unbounded_params(tmp_path,vault):
    p=tmp_path/'backup.lgk';export_encrypted_backup(p,vault_file=vault.path,settings_file=None,profile_name='x',backup_password=NEW)
    data=json.loads(p.read_text());data['kdf']['memory_cost_kib']=2**40;p.write_text(json.dumps(data))
    with pytest.raises(BackupError):verify_encrypted_backup(p,backup_password=NEW,vault_password=MASTER)

def test_import_preview_and_explicit_conflicts(tmp_path,vault):
    add(vault);path=tmp_path/'logins.csv';path.write_text('name,url,username,password\nExample,https://example.test/login,alice,different-password\nNew,https://example.test/login,bob,another-password\n')
    rows,issues=load_import(path);classify(rows,vault.all_entries())
    assert [r.status for r in rows]==['conflict','new'] and rows[0].selected=='skip'
    assert 'different-password' not in repr(rows[0])
    assert apply_import(vault,rows)==1
    rows[0].selected='replace';rows[1].selected='skip';assert apply_import(vault,rows)==1
    assert vault.find_web('https://example.test')[0]['password']=='different-password'

def test_import_changed_target_rejected(tmp_path,vault):
    p=tmp_path/'a.csv';p.write_text('url,username,password\nhttps://example.test,alice,testpassword\n')
    rows,_=load_import(p);add(vault)
    with pytest.raises(PreviewError):apply_import(vault,rows)

def test_breach_optin_and_prefix_only():
    sent=[];password='Test-not-real-password-019!';digest=hashlib.sha1(password.encode()).hexdigest().upper()
    def fetch(prefix):sent.append(prefix);return digest[5:]+':37\n'+'0'*35+':0\n'
    with pytest.raises(BreachCheckError):check_password(password,consent=False,fetch=fetch)
    assert not sent
    assert check_password(password,consent=True,fetch=fetch)==37 and sent==[digest[:5]]
    with pytest.raises(BreachCheckError):check_password(password,consent=True,fetch=lambda p:'invalid')

def test_strict_offline_breach_check_never_calls_fetch():
    sent=[]
    with pytest.raises(BreachCheckError, match='strict offline'):
        check_password('offline-password', consent=True, strict_offline=True,
                       fetch=lambda prefix: sent.append(prefix) or '')
    assert sent == []

class Broker(RuntimeActions,BrowserBroker):
    def __init__(self,vault):
        self.session=vault;self.guard=SessionGuard('a');self.guard.open(28800)
        self.settings=AppSettings(auto_lock_seconds=0)
        self.active_profile=SimpleNamespace(id='a',name='Alice',color='#12ABCD')
        self._remote_busy=False;self.last_extension_seen=0;self.last_extension_version=''
        self.last_secret_use=1234;self._closing=False
    def ensure_unlocked(self):return self._session_available()
    def run_on_ui(self,f,timeout=0):return f()
    def _touch_secret(self):self.last_secret_use=time.monotonic()
    def reauthenticate(self,*args):return True
    def _validate_remote_text(self,v,*args):
        if not isinstance(v,str):raise ValueError()
        return v
    def request(self,action,**kw):
        return self.dispatch_remote({'action':action,'protocol':2,'extension_version':'0.3.0','origin':'https://example.test','context':'tab-1-document-1-operation-1',**kw})
    def nonce(self,**kw):
        # A fresh broker gesture nonce, as the extension mints one per click.
        return self.request('begin_gesture_browser',user_gesture=True,**kw)['gesture_nonce']

def test_broker_metadata_then_one_password(vault):
    one=add(vault);two=add(vault,'bob','Other-test-password!');b=Broker(vault)
    start=b.request('begin_browser',user_gesture=True)
    assert start['ok'] and len(start['choices'])==2
    assert all('password' not in c for c in start['choices'])
    assert 'Test-only-password-019!' not in json.dumps(start)
    got=b.request('get_browser',grant=start['grant'],entry_id=one,gesture_nonce=start['gesture_nonce'])
    assert got['credential']['username']=='alice' and not got['sign_in']
    nonce=b.request('begin_gesture_browser',user_gesture=True)['gesture_nonce']
    assert not b.request('get_browser',grant=start['grant'],entry_id=two,gesture_nonce=nonce)['ok']
    assert not b.request('submit_browser',grant=start['grant'],entry_id=one)['ok']

@pytest.mark.parametrize('change',['lock','switch','reunlock'])
def test_broker_rejects_stale_fill_and_submit(vault,change):
    i=add(vault);b=Broker(vault);b.settings.fill_and_sign_in=True
    start=b.request('begin_browser',user_gesture=True);got=b.request('get_browser',grant=start['grant'],entry_id=i,gesture_nonce=start['gesture_nonce'])
    assert got['sign_in']
    if change=='switch':b.guard.invalidate('different-profile');b.guard.open(28800)
    elif change=='reunlock':b.guard.open(28800)
    else:b.guard.invalidate()
    assert not b.request('validate_browser',grant=start['grant'],entry_id=i)['ok']
    assert not b.request('submit_browser',grant=start['grant'],entry_id=i)['ok']

def test_broker_ping_never_resets_activity(vault):
    add(vault);b=Broker(vault);old=b.last_secret_use
    for _ in range(5):assert b.request('ping')['ok']
    assert b.last_secret_use==old

def test_broker_old_protocol_refused(vault):
    add(vault);b=Broker(vault)
    assert b.dispatch_remote({'action':'get_browser','origin':'https://example.test'})['error']=='version_mismatch'

def test_broker_no_implicit_unlock_for_comparison(vault):
    add(vault);b=Broker(vault);b.guard.invalidate()
    result=b.request('check_browser',username='alice',password='anything')
    assert result['locked']

def test_broker_submit_only_once(vault):
    i=add(vault);b=Broker(vault);b.settings.fill_and_sign_in=True
    start=b.request('begin_browser',user_gesture=True)
    assert b.request('get_browser',grant=start['grant'],entry_id=i,gesture_nonce=start['gesture_nonce'])['ok']
    assert b.request('submit_browser',grant=start['grant'],entry_id=i)['ok']
    assert not b.request('submit_browser',grant=start['grant'],entry_id=i)['ok']

def test_broker_reauth_invalidated_mid_dialog(vault):
    i=add(vault);vault.set_details(i,policy={'require_master_password':True});b=Broker(vault)
    b.reauthenticate=lambda *args:(b.guard.invalidate() or True)
    start=b.request('begin_browser',user_gesture=True)
    result=b.request('get_browser',grant=start['grant'],entry_id=i,gesture_nonce=start['gesture_nonce'])
    assert result.get('error')!='gesture_nonce_required'
    assert not result['ok'] and 'credential' not in result

def test_unicode_password_history_and_metadata(tmp_path):
    from localvault.vault import create_vault
    v=create_vault(tmp_path/'unicode.json','Dummy master password 019',kdf_overrides={'memory_cost_kib':8192,'time_cost':1,'parallelism':1})
    eid=v.upsert_web(origin='https://example.test',username='δοκιμή',password='żółć-κλειδί-123!')
    v.update_entry_fields(eid,password='καινούργιο-Żółć-456!')
    assert v.password_history(eid)[0]['password']=='żółć-κλειδί-123!'
    v.upsert_web(origin='https://example.test',username='δοκιμή',password='next-test-only')
    assert v.password_history(eid)[0]['changed_at']>0
    assert v.get_entry('not-existing-δοκιμή') is None
    v.lock()

def test_rename_cannot_overwrite_another_browser_account(vault):
    from localvault.vault import VaultError
    one=vault.upsert_web(origin='https://example.test',username='one',password='dummy-one')
    vault.upsert_web(origin='https://example.test',username='two',password='dummy-two')
    with pytest.raises(VaultError):vault.update_entry_fields(one,username='two')
    assert vault.get_entry(one)['username']=='one'

def test_profile_signin_optin_is_encrypted_and_default_off(vault):
    assert not vault.fill_and_sign_in_enabled()
    vault.set_fill_and_sign_in_enabled(True)
    assert vault.fill_and_sign_in_enabled()
    assert b'fill_and_sign_in' not in vault.path.read_bytes()
    with pytest.raises(Exception):vault.set_fill_and_sign_in_enabled('true')

@pytest.mark.parametrize('password',['aaaaaaaaaaaaaaaaaaaaaaaa','abababababababababab','VeryLongPasswordPassword','abcdefghijklmnopqrstuvwxyz','apple-gate-amber'])
def test_obvious_patterns_are_not_health_green(password):
    from localvault.password_tools import assess_password
    assert assess_password(password).score < 60


def test_browser_pending_save_uses_canonical_token_and_no_popup_click(vault):
    b = Broker(vault)
    capture = b.request(
        'capture_browser', username='new-user', password='Submitted-test-password-1!',
        context=json.dumps([8, 'document-A', 'https://example.test', 'operation-save-1'])
    )
    assert capture['ok'] and capture['stored']
    assert capture['pending_token'] == capture['token']
    pending = b.request('pending_browser', context=json.dumps([8, 'document-B', 'https://example.test', 'operation-pending']))
    assert pending['pending'] and pending['pending_token'] == capture['pending_token']
    assert pending['username'] == 'new-user'
    assert 'password' not in pending

    discarded = b.request('discard_pending_browser', pending_token=pending['pending_token'], context=json.dumps([8, 'document-B', 'https://example.test', 'operation-discard']))
    assert discarded['ok']
    assert b.request('pending_browser', context=json.dumps([8, 'document-B', 'https://example.test', 'operation-pending'])) == {'ok': True, 'pending': False}


def test_browser_pending_save_survives_redirect_window_and_expires(vault):
    b = Broker(vault)
    result = b.request('capture_browser', username='new-user', password='Submitted-test-password-2!', context=json.dumps([9, 'document-A', 'https://example.test', 'operation-save-2']))
    assert result['stored']
    key = next(iter(b._browser_pending_saves))
    # A normal redirect/page load remains inside the 90-second recovery window.
    b._browser_pending_saves[key]['created'] = time.monotonic() - 5
    assert b.request('pending_browser', context=json.dumps([9, 'document-B', 'https://example.test', 'operation-pending-2']))['pending']
    # Stale values are wiped and removed rather than retained indefinitely.
    b._browser_pending_saves[key]['created'] = time.monotonic() - 91
    assert b.request('pending_browser', context=json.dumps([9, 'document-B', 'https://example.test', 'operation-expired'])) == {'ok': True, 'pending': False}


def test_browser_pending_save_rejects_late_same_origin_document(vault):
    b = Broker(vault)
    result = b.request('capture_browser', username='new-user', password='Submitted-test-password-3!', context=json.dumps([10, 'document-A', 'https://example.test', 'operation-save-3']))
    assert result['stored']
    key = next(iter(b._browser_pending_saves))
    b._browser_pending_saves[key]['created'] = time.monotonic() - 13
    assert b.request('pending_browser', context=json.dumps([10, 'document-B', 'https://example.test', 'operation-pending-3'])) == {'ok': True, 'pending': False}


def test_browser_pending_save_requires_an_unambiguous_username():
    # The fail-closed path runs before vault access, so keep this regression
    # test independent of pytest's restricted temporary-directory fixture.
    b = Broker(None)
    result = b.request(
        'capture_browser', username='', password='Submitted-test-password-4!',
        context=json.dumps([11, 'document-A', 'https://example.test', 'operation-save-4'])
    )
    assert result == {'ok': True, 'stored': False, 'status': 'username_required'}
    assert not getattr(b, '_browser_pending_saves', {})


def test_browser_pending_save_can_be_cleared_for_logout():
    b = Broker(None)
    b._browser_pending_saves = {
        (11, 'https://example.test'): {'password': 'temporary-secret'}
    }
    result = b.request(
        'clear_pending_browser',
        context=json.dumps([11, 'document-A', 'https://example.test', 'operation-logout'])
    )
    assert result == {'ok': True}
    assert not b._browser_pending_saves
