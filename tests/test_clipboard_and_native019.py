from __future__ import annotations

import sys
from types import SimpleNamespace as NS

import pytest

import localvault.clipboard_guard as clip
import localvault.pipe_transport as pipe


class Root:
    def __init__(self): self.text=''; self.jobs=[]; self.clears=0
    def clipboard_clear(self): self.text='';self.clears+=1
    def clipboard_append(self,value): self.text=value
    def clipboard_get(self): return self.text
    def after(self,ms,callback): self.jobs.append(callback)

def test_clipboard_does_not_erase_other_app_text(monkeypatch):
    monkeypatch.setattr(clip, 'os', NS(name='posix'))
    root=Root();g=clip.ClipboardGuard(root)
    g.copy('temporary secret');root.text='other application document'
    g.clear()
    assert root.text=='other application document'

def test_old_clipboard_timer_does_not_erase_new_copy(monkeypatch):
    monkeypatch.setattr(clip, 'os', NS(name='posix'))
    root=Root();g=clip.ClipboardGuard(root)
    g.copy('old secret');old=root.jobs[-1]
    g.copy('new secret');old();assert root.text=='new secret'
    g.clear();assert root.text==''

def test_windows_clipboard_sequence_captured_before_releasing_lock(monkeypatch):
    monkeypatch.setattr(clip, 'os', NS(name='nt'))
    state={'open':False,'sequence':5,'text':'','events':[],'replace_on_close':True}
    def open_():state['open']=True
    def empty():state['sequence']+=1;state['text']='';state['events'].append('empty')
    def close():
        state['open']=False
        if state['replace_on_close']:
            state['sequence']+=1;state['text']='someone else copied text';state['replace_on_close']=False
    def set_(fmt,value):
        state['sequence']+=1
        if fmt==13:state['text']=value
        state['events'].append(fmt)
    def sequence():
        assert state['open'], 'Ownership must be read while the clipboard is locked'
        return state['sequence']
    cb=NS(OpenClipboard=open_,EmptyClipboard=empty,CloseClipboard=close,
          SetClipboardData=set_,RegisterClipboardFormat=lambda name:name)
    monkeypatch.setitem(sys.modules,'win32clipboard',cb)
    monkeypatch.setitem(sys.modules,'win32con',NS(CF_UNICODETEXT=13))
    monkeypatch.setattr(clip,'_clipboard_sequence',sequence)
    g=clip.ClipboardGuard(Root());g.copy('secret')
    assert state['events'].index('CanIncludeInClipboardHistory')<state['events'].index(13)
    g.clear();assert state['text']=='someone else copied text'

@pytest.mark.parametrize('registered,exe,parent,expected',[
    (False,'host.exe','',False),  # no browser registration: fail closed
    (True,'host.exe','',True),
    (True,'python.exe','host.exe',True),
    (True,'python.exe','other.exe',False),
    (True,'other.exe','host.exe',False),
])
def test_native_peer_requires_pins_and_expected_parent(monkeypatch,registered,exe,parent,expected):
    monkeypatch.setattr(pipe,'os',NS(name='nt',path=pipe.os.path))
    monkeypatch.setattr(sys,'frozen',False,raising=False)
    monkeypatch.setattr(pipe,'_registered_native_host_paths',lambda:{'Chrome':'host.exe'} if registered else {})
    config={'native_host_path':'host.exe','native_host_sha256':'A'*64,
            'interpreter_path':'python.exe','interpreter_sha256':'B'*64}
    monkeypatch.setattr(pipe,'read_json',lambda path:config)
    monkeypatch.setattr(pipe,'install_config_path',lambda:'not-used')
    monkeypatch.setattr(pipe,'_named_pipe_client_pid',lambda h:123)
    monkeypatch.setattr(pipe,'_sha256_file',lambda path:{'host.exe':'A'*64,'python.exe':'B'*64}.get(path,'C'*64))
    monkeypatch.setitem(sys.modules,'psutil',NS(Process=lambda pid:NS(exe=lambda:exe,parent=lambda:NS(exe=lambda:parent))))
    assert bool(pipe._verify_native_host_client(1)) is expected
