from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

import localvault.bridge_diagnostics as diag
import localvault.bridge_status as status
import localvault.config as config
import localvault.native_host as host
import localvault.pipe_transport as pipe


class WinError(Exception):
    """Match pywintypes.error's (code, operation, description) argument shape."""


@pytest.mark.parametrize("exc,stage,code", [
    (FileNotFoundError(2, 'private-file'), 'state', 'agent_state_missing'),
    (PermissionError(13, 'private-path'), 'state', 'agent_access_denied'),
    (ValueError('SECRET'), 'state', 'agent_state_invalid'),
    (ImportError('PRIVATE PACKAGE PATH'), 'imports', 'bridge_dependencies_missing'),
    (WinError(5, 'CreateFile', 'PRIVATE PATH'), 'connect', 'agent_access_denied'),
    (WinError(2, 'WaitNamedPipe', 'PRIVATE PIPE'), 'connect', 'agent_unavailable'),
    (WinError(3, 'WaitNamedPipe', 'PRIVATE PIPE'), 'connect', 'agent_unavailable'),
    (WinError(121, 'WaitNamedPipe', 'PRIVATE PIPE'), 'connect', 'agent_busy'),
    (WinError(231, 'CreateFile', 'PRIVATE PIPE'), 'connect', 'agent_busy'),
    (WinError(109, 'ReadFile', 'PRIVATE PIPE'), 'receive', 'agent_connection_lost'),
    (WinError(232, 'ReadFile', 'PRIVATE PIPE'), 'receive', 'agent_connection_lost'),
    (WinError(233, 'WriteFile', 'PRIVATE PIPE'), 'send', 'agent_connection_lost'),
    (EOFError('SECRET'), 'receive', 'agent_connection_lost'),
    (RuntimeError('PASSWORD=SECRET'), 'forward', 'bridge_internal_error'),
])
def test_errors_keep_reason_without_secrets(exc, stage, code):
    r = status.classify_failure(exc, stage)
    assert r['error'] == code
    assert r['stage'] == stage
    assert 'PRIVATE' not in json.dumps(r) and 'SECRET' not in json.dumps(r)
    assert r['error'] != 'agent_offline'


def test_numeric_windows_error_supported_in_both_exception_shapes():
    e = OSError('do not echo this'); e.winerror = 5
    assert status.error_number(e) == 5
    assert status.error_number(WinError(109, 'ReadFile', 'secret')) == 109
    assert status.error_number(RuntimeError('bad')) is None


@pytest.mark.parametrize('exception,code', [
    (PermissionError('secret path'), 'agent_access_denied'),
    (FileNotFoundError('secret path'), 'agent_state_missing'),
    (ValueError('secret JSON'), 'agent_state_invalid'),
])
def test_native_state_failures_not_reported_offline(monkeypatch, exception, code):
    monkeypatch.setattr(config, 'agent_state_path', lambda: 'unused')
    def fail(_): raise exception
    monkeypatch.setattr(config, 'read_json', fail)
    logs = []; monkeypatch.setattr(host, '_log', lambda e, exc=None: logs.append(e))
    r = host._forward({'action': 'ping'})
    assert r['error'] == code
    assert 'secret' not in repr(r) and 'secret' not in repr(logs)


def test_native_passes_single_state_snapshot(monkeypatch):
    state = {'transport':'named_pipe', 'token':'private-token'}
    monkeypatch.setattr(config, 'agent_state_path', lambda: 'unused')
    calls = []
    monkeypatch.setattr(config, 'read_json', lambda p: (calls.append(p) or state))
    monkeypatch.setattr(host, 'os', NS(name='nt'))
    monkeypatch.setattr(host, '_log', lambda *a: None)
    def forward(req, timeout_ms, *, state):
        assert state is original and req == {'action':'ping'}
        return {'ok':True,'locked':True}
    original = state
    monkeypatch.setattr(pipe, 'forward_named_pipe', forward)
    assert host._forward({'action':'ping'}) == {'ok':True,'locked':True}
    assert calls == ['unused']


def test_windows_does_not_downgrade_to_legacy_socket(monkeypatch):
    monkeypatch.setattr(config, 'agent_state_path', lambda:'unused')
    monkeypatch.setattr(config, 'read_json', lambda p: {'port':1234,'token':'x'*40})
    monkeypatch.setattr(host, 'os', NS(name='nt'))
    monkeypatch.setattr(host, '_log', lambda *a:None)
    monkeypatch.setattr(host, '_forward_legacy_socket', lambda *a:pytest.fail('No TCP fallback'))
    assert host._forward({'action':'ping'})['error'] == 'agent_state_invalid'


@pytest.mark.parametrize('chain,redirector_pin,hash_bad,expected', [
    (['host.exe'], False, '', True),
    (['python.exe','host.exe'], False, '', True),
    (['python.exe','venv-python.exe','host.exe'], True, '', True),
    (['python.exe','venv-python.exe','host.exe'], False, '', False),
    (['python.exe','unknown.exe','host.exe'], True, '', False),
    (['python.exe','venv-python.exe','unknown.exe'], True, '', False),
    (['python.exe','venv-python.exe','host.exe'], True, 'venv-python.exe', False),
    (['python.exe','venv-python.exe','host.exe'], True, 'python.exe', False),
    (['python.exe','venv-python.exe','host.exe'], True, 'host.exe', False),
    (['python.exe','venv-python.exe','venv-python.exe','host.exe'], True, '', False),
    (['python.exe'], True, '', False),
    (['unknown.exe','host.exe'], True, '', False),
])
def test_exact_pinned_windows_launcher_chains(monkeypatch, chain, redirector_pin, hash_bad, expected):
    # Repository mode: the browser registration pins host.exe; install.json
    # cross-checks its hash and pins the Python launcher chain.
    pins = {'native_host_path':'host.exe','native_host_sha256':'A'*64,
            'interpreter_path':'python.exe','interpreter_sha256':'B'*64}
    if redirector_pin:
        pins.update(venv_redirector_path='venv-python.exe', venv_redirector_sha256='C'*64)
    def process(i):
        return NS(exe=lambda:chain[i], parent=lambda:process(i+1) if i+1<len(chain) else None)
    monkeypatch.setattr(pipe,'os',NS(name='nt',path=os.path))
    monkeypatch.setattr(pipe,'_registered_native_host_paths',lambda:{'Chrome':'host.exe'})
    monkeypatch.setattr(sys,'frozen',False,raising=False)
    monkeypatch.setattr(pipe,'read_json',lambda p:pins)
    monkeypatch.setattr(pipe,'install_config_path',lambda:'unused')
    monkeypatch.setattr(pipe,'_named_pipe_client_pid',lambda h:1)
    monkeypatch.setattr(pipe,'_sha256_file',lambda p:'D'*64 if p==hash_bad else {'host.exe':'A'*64,'python.exe':'B'*64,'venv-python.exe':'C'*64}.get(p,'D'*64))
    monkeypatch.setitem(sys.modules,'psutil',NS(Process=lambda pid:process(0)))
    assert bool(pipe._verify_native_host_client(1)) is expected


def test_rejected_client_receives_reply_before_disconnect(monkeypatch):
    events = []; pending=[]; received=[]
    def flush(h): events.append('flush'); received.extend(pending);pending.clear()
    def disconnect(h):events.append('disconnect');pending.clear()
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:events.append('close'),FlushFileBuffers=flush))
    monkeypatch.setitem(sys.modules,'win32pipe',NS(DisconnectNamedPipe=disconnect))
    monkeypatch.setattr(pipe,'_verify_native_host_client',lambda h:False)
    monkeypatch.setattr(pipe,'_pipe_log',lambda *a:None)
    monkeypatch.setattr(pipe,'_recv_pipe',lambda h:pytest.fail('Rejected peers cannot send operations'))
    monkeypatch.setattr(pipe,'_send_pipe',lambda h,r:(events.append('send'),pending.append(r)))
    s=pipe.NamedPipeAgentServer(lambda r:pytest.fail('Rejected peer reached vault'))
    s._handle_client(7)
    assert events == ['send','flush','disconnect','close']
    assert received[0]['error']=='client_not_allowed'


def test_token_rejection_does_not_dispatch(monkeypatch):
    events=[]
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:None))
    monkeypatch.setitem(sys.modules,'win32pipe',NS(DisconnectNamedPipe=lambda h:None))
    monkeypatch.setattr(pipe,'_flush_reply',lambda h:events.append('flush'))
    monkeypatch.setattr(pipe,'_verify_native_host_client',lambda h:True)
    monkeypatch.setattr(pipe,'_recv_pipe',lambda h:{'action':'get_browser','token':'wrong'})
    monkeypatch.setattr(pipe,'_send_pipe',lambda h,r:events.append(r['error']))
    s=pipe.NamedPipeAgentServer(lambda r:pytest.fail('Wrong token reached vault'))
    s._handle_client(8)
    assert events==['unauthorized','flush']


def test_failure_to_flush_never_sends_a_second_response(monkeypatch):
    responses=[]
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:None))
    monkeypatch.setitem(sys.modules,'win32pipe',NS(DisconnectNamedPipe=lambda h:None))
    monkeypatch.setattr(pipe,'_pipe_log',lambda *a:None)
    monkeypatch.setattr(pipe,'_verify_native_host_client',lambda h:False)
    monkeypatch.setattr(pipe,'_send_pipe',lambda h,r:responses.append(r))
    def fail(h):raise WinError(109,'flush','secret')
    monkeypatch.setattr(pipe,'_flush_reply',fail)
    pipe.NamedPipeAgentServer(lambda r:{})._handle_client(8)
    assert len(responses)==1 and responses[0]['error']=='client_not_allowed'


def test_first_pipe_exists_before_state_is_published(monkeypatch,tmp_path):
    events=[]
    monkeypatch.setattr(pipe,'os',NS(name='nt',getpid=lambda:12))
    monkeypatch.setattr(pipe,'_security_attributes_for_current_user',lambda:(None,'S-1-TEST'))
    monkeypatch.setattr(pipe,'agent_state_path',lambda:tmp_path/'state.json')
    monkeypatch.setattr(pipe,'atomic_write_json',lambda p,d:events.append('publish'))
    monkeypatch.setattr(pipe,'_pipe_log',lambda *a:None)
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:events.append('close')))
    class Thread:
        def __init__(self,**kwargs):pass
        def start(self):events.append('thread')
    monkeypatch.setattr(pipe.threading,'Thread',Thread)
    server=pipe.NamedPipeAgentServer(lambda r:{})
    monkeypatch.setattr(server,'_create_pipe',lambda **kw:(events.append('create') or 7))
    server.start()
    assert events==['create','publish','thread']


def test_create_failure_does_not_publish_success(monkeypatch,tmp_path):
    monkeypatch.setattr(pipe,'os',NS(name='nt',getpid=lambda:12))
    monkeypatch.setattr(pipe,'_security_attributes_for_current_user',lambda:(None,'S-1-TEST'))
    monkeypatch.setattr(pipe,'agent_state_path',lambda:tmp_path/'missing-state.json')
    monkeypatch.setattr(pipe,'atomic_write_json',lambda *a:pytest.fail('Cannot publish before pipe creation'))
    monkeypatch.setattr(pipe,'_pipe_log',lambda *a:None)
    server=pipe.NamedPipeAgentServer(lambda r:{})
    def fail(**kw):raise WinError(5,'CreateNamedPipe','private')
    monkeypatch.setattr(server,'_create_pipe',fail)
    with pytest.raises(WinError):server.start()


def test_open_retries_only_transient_pre_send_races(monkeypatch):
    attempts=[]
    def wait(name,ms):
        attempts.append('wait')
        if len(attempts)==1:raise WinError(2,'WaitNamedPipe','private')
    def create(*args):
        attempts.append('open')
        if attempts.count('open')==1:raise WinError(231,'CreateFile','private')
        return 19
    monkeypatch.setitem(sys.modules,'win32pipe',NS(WaitNamedPipe=wait))
    monkeypatch.setitem(sys.modules,'win32file',NS(CreateFile=create))
    monkeypatch.setitem(sys.modules,'win32con',NS(GENERIC_READ=1,GENERIC_WRITE=2,OPEN_EXISTING=3))
    assert pipe._open_pipe('irrelevant',300)==19
    assert attempts==['wait','wait','open','wait','open']


def test_acl_error_is_not_retried(monkeypatch):
    count=[]
    def fail(*a):count.append(1);raise WinError(5,'WaitNamedPipe','secret')
    monkeypatch.setitem(sys.modules,'win32pipe',NS(WaitNamedPipe=fail))
    monkeypatch.setitem(sys.modules,'win32file',NS())
    monkeypatch.setitem(sys.modules,'win32con',NS())
    with pytest.raises(status.BridgeFailure) as e:pipe._open_pipe('irrelevant',100)
    assert e.value.code=='agent_access_denied' and len(count)==1


@pytest.fixture
def connected(monkeypatch):
    state={'transport':'named_pipe','pipe':pipe.PIPE_PREFIX+'a'*32,'token':'x'*40,'user_sid':'S-1-TEST','pid':123}
    events=[]
    monkeypatch.setattr(pipe,'os',NS(name='nt'))
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:events.append('close')))
    monkeypatch.setattr(pipe,'_current_user_sid_string',lambda:'S-1-TEST')
    monkeypatch.setattr(pipe,'_open_pipe',lambda *a:(events.append('open') or 7))
    monkeypatch.setattr(pipe,'_named_pipe_server_pid',lambda h:123)
    monkeypatch.setattr(pipe,'_send_pipe',lambda h,r:events.append('send'))
    monkeypatch.setattr(pipe,'_recv_pipe',lambda h:{'ok':True})
    return state,events


def test_valid_connection_is_one_roundtrip(connected):
    state,events=connected
    assert pipe.forward_named_pipe({'action':'ping'},state=state)=={'ok':True}
    assert events==['open','send','close']


def test_server_pid_mismatch_never_sends_token(monkeypatch,connected):
    state,events=connected
    monkeypatch.setattr(pipe,'_named_pipe_server_pid',lambda h:456)
    with pytest.raises(status.BridgeFailure) as e:pipe.forward_named_pipe({'action':'ping'},state=state)
    assert e.value.code=='agent_connection_changed' and events==['open','close']


@pytest.mark.parametrize('key,value',[('pid',0),('pid',True),('token','short'),('pipe',r'\\remote\pipe\x'),('user_sid',''),('transport','socket')])
def test_invalid_pipe_state_never_connects(connected,key,value):
    state,events=connected;state[key]=value
    with pytest.raises(status.BridgeFailure) as e:pipe.forward_named_pipe({'action':'ping'},state=state)
    assert e.value.code=='agent_state_invalid' and not events


def test_other_windows_user_never_connects(monkeypatch,connected):
    state,events=connected
    monkeypatch.setattr(pipe,'_current_user_sid_string',lambda:'S-1-OTHER')
    with pytest.raises(status.BridgeFailure) as e:pipe.forward_named_pipe({'action':'ping'},state=state)
    assert e.value.code=='agent_access_denied' and not events


@pytest.mark.parametrize('stage',['send','receive'])
def test_never_retries_dispatched_operation(monkeypatch,connected,stage):
    state,events=connected
    def fail(*a):events.append('fail');raise WinError(109,'ReadFile','secret')
    monkeypatch.setattr(pipe,'_send_pipe' if stage=='send' else '_recv_pipe',fail)
    with pytest.raises(status.BridgeFailure) as e:pipe.forward_named_pipe({'action':'submit_browser'},state=state)
    assert e.value.code=='agent_connection_lost' and e.value.stage==stage
    assert events.count('open')==1 and events.count('fail')==1 and events[-1]=='close'


def test_redacted_ping_never_prints_session_or_profile():
    r=diag._redacted_ping({'ok':True,'version':'0.3.2','protocol':2,'locked':False,'browser_enabled':True,
        'session_id':'SECRET SESSION','profile_name':'PRIVATE PERSON','token':'SECRET TOKEN','password':'SECRET'})
    assert r=={'status':'connected','desktop_version':'0.3.2','protocol':2,'vault_locked':False,'browser_integration_enabled':True}


def test_redacted_error_uses_own_message():
    r=diag._redacted_ping({'ok':False,'error':'client_not_allowed','message':'SECRET PATH','winerror':5,
                          'stage':'peer','token':'SECRET'})
    assert r['error']=='client_not_allowed' and r['winerror']==5 and 'SECRET' not in json.dumps(r)
    assert diag._redacted_ping({'ok':False,'error':['SECRET'],'message':'SECRET'})['error']=='unexpected_native_reply'


def test_connection_test_launches_only_ping_and_redacts(monkeypatch):
    monkeypatch.setattr(diag,'_pin_matches',lambda *a:True)
    body=io.BytesIO();host._write_native_message(body,{'ok':True,'version':'0.3.2','protocol':2,'locked':False,
                                                     'session_id':'SECRET','profile_name':'SECRET'})
    calls=[]
    class Process:
        def communicate(self,data,timeout):
            request=host._read_native_message(io.BytesIO(data));calls.append(request)
            return body.getvalue(),b'PRIVATE STDERR'
    monkeypatch.setattr(diag.subprocess,'Popen',lambda *a,**kw:Process())
    r=diag._ping_host({'native_host_path':'host.exe','allowed_extension_origins':list(config.EXTENSION_ORIGINS)})
    from localvault.version import APP_VERSION
    assert calls==[{'action':'ping','protocol':2,'extension_version':APP_VERSION}]
    assert r['status']=='connected' and 'SECRET' not in json.dumps(r)


def test_connection_test_never_launches_unpinned_host(monkeypatch):
    monkeypatch.setattr(diag,'_pin_matches',lambda *a:False)
    monkeypatch.setattr(diag.subprocess,'Popen',lambda *a,**kw:pytest.fail('must not launch'))
    assert diag._ping_host({})['error']=='native_host_pin_mismatch'


def test_repair_is_repository_only_and_pins_redirector():
    text=(Path(__file__).parents[1]/'scripts/repair_browser_bridge.ps1').read_text()
    assert 'venv_redirector_path=$Python' in text and 'venv_redirector_sha256=' in text
    assert text.index('/grant:r') < text.index('/inheritance:r')
    lines='\n'.join(s for s in text.splitlines() if not s.strip().startswith('#'))
    assert 'Set-Acl ' not in lines and 'HKLM:' not in lines and 'Copy-Item' not in lines
    assert 'Remove-Item' not in lines
    assert 'HKCU:' in text


def test_listener_failure_removes_advertised_state(monkeypatch,tmp_path):
    monkeypatch.setitem(sys.modules,'pywintypes',NS(error=WinError))
    monkeypatch.setitem(sys.modules,'win32pipe',NS())
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:None))
    monkeypatch.setattr(pipe,'_pipe_log',lambda *a:None)
    monkeypatch.setattr(pipe,'agent_state_path',lambda:tmp_path/'state.json')
    server=pipe.NamedPipeAgentServer(lambda r:{})
    config.atomic_write_json(tmp_path/'state.json',{'pid':os.getpid(),'token':server.token})
    def fail(**kw):raise WinError(5,'CreateNamedPipe','private')
    monkeypatch.setattr(server,'_create_pipe',fail)
    server._run()
    assert not (tmp_path/'state.json').exists()


def test_listener_does_not_remove_another_agents_state(monkeypatch,tmp_path):
    monkeypatch.setattr(pipe,'agent_state_path',lambda:tmp_path/'state.json')
    server=pipe.NamedPipeAgentServer(lambda r:{})
    config.atomic_write_json(tmp_path/'state.json',{'pid':os.getpid(),'token':'OTHER TOKEN'})
    server._remove_owned_state()
    assert config.read_json(tmp_path/'state.json')['token']=='OTHER TOKEN'


def test_connected_before_accept_supports_pywintypes_args(monkeypatch):
    events=[]
    monkeypatch.setitem(sys.modules,'pywintypes',NS(error=WinError))
    def connected(*a):raise WinError(535,'ConnectNamedPipe','private')
    monkeypatch.setitem(sys.modules,'win32pipe',NS(ConnectNamedPipe=connected))
    monkeypatch.setitem(sys.modules,'win32file',NS(CloseHandle=lambda h:events.append('close')))
    monkeypatch.setattr(pipe,'_pipe_log',lambda *a:None)
    server=pipe.NamedPipeAgentServer(lambda r:{})
    monkeypatch.setattr(server,'_remove_owned_state',lambda:events.append('cleanup'))
    class Thread:
        def __init__(self, **kwargs):events.append('worker-created')
        def start(self):events.append('worker-started');server.stop_event.set()
    monkeypatch.setattr(pipe.threading,'Thread',Thread)
    server._run(7)
    assert events==['worker-created','worker-started','cleanup']
