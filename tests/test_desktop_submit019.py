"""Portable tests of desktop policy/ordering using mocked UIA/Win32, not OS compatibility."""
import sys
from dataclasses import replace
from types import SimpleNamespace as NS

import pytest

import localvault.uia as uia
from localvault.session_guard import StaleSession


def target(events):
    user=uia.ControlDescriptor(0,'Username','user','Edit','Win32',False,True,True,(0,0,100,20))
    password=uia.ControlDescriptor(1,'','password','Edit','Win32',True,True,True,(0,25,100,45))
    button=uia.ControlDescriptor(0,'Sign in','loginButton','Button','Win32',False,True,True,(0,50,100,70),
                                 NS(iface_invoke=NS(Invoke=lambda:events.append('invoke'))))
    snap=uia.WindowSnapshot(42,100,'Example login','/apps/example.exe','A'*64,[user,password],None,[button])
    entry={'id':'demo','username':'dummy','password':'dummy-only-secret','scope':{
        'exe_path':snap.exe_path,'exe_sha256':snap.exe_sha256,'window_title':snap.title,
        'control_fingerprint':snap.control_fingerprint(),'username_selector':user.selector(),
        'password_selector':password.selector(),'sign_in_selector':button.selector()}}
    return snap,entry

def mock_os(monkeypatch,snap,events):
    monkeypatch.setattr(uia,'_require_windows',lambda:None)
    monkeypatch.setattr(uia,'scan_window',lambda *a,**k:snap)
    monkeypatch.setattr(uia,'_restore_foreground',lambda hwnd:events.append('focus'))
    monkeypatch.setattr(uia,'_write_control',lambda control,value,hwnd,guard=None:events.append(control.automation_id))
    monkeypatch.setitem(sys.modules,'win32gui',NS(GetForegroundWindow=lambda:42))

def test_desktop_signin_off_by_default(monkeypatch):
    events=[];snap,entry=target(events);mock_os(monkeypatch,snap,events)
    assert uia.fill_desktop_entry(entry,snap) is False
    assert events==['focus','user','password']

def test_desktop_signin_once_only_after_fresh_verification(monkeypatch):
    events=[];snap,entry=target(events);mock_os(monkeypatch,snap,events)
    def scan(*a,**k):events.append('scan');return snap
    monkeypatch.setattr(uia,'scan_window',scan)
    assert uia.fill_desktop_entry(entry,snap,sign_in=True)
    assert events==['scan','focus','user','password','scan','invoke']

@pytest.mark.parametrize('case',['button_changed','ambiguous','executable_changed','focus_changed','session_locked'])
def test_desktop_rechecks_before_submit(monkeypatch,case):
    events=[];snap,entry=target(events);mock_os(monkeypatch,snap,events);calls=0
    def scan(*a,**k):
        nonlocal calls
        calls+=1
        if calls==1:return snap
        if case=='button_changed':return replace(snap,buttons=[replace(snap.buttons[0],name='Reset password')])
        if case=='ambiguous':return replace(snap,buttons=snap.buttons*2)
        if case=='executable_changed':return replace(snap,exe_sha256='B'*64)
        if case=='focus_changed':monkeypatch.setitem(sys.modules,'win32gui',NS(GetForegroundWindow=lambda:99))
        return snap
    def check():
        if calls>1 and case=='session_locked':raise StaleSession('Locked')
    monkeypatch.setattr(uia,'scan_window',scan)
    with pytest.raises((uia.UIAutomationError,StaleSession)):
        uia.fill_desktop_entry(entry,snap,guard=check,sign_in=True)
    assert 'invoke' not in events

@pytest.mark.parametrize('name',['Continue','Buy','Reset password','Confirm transfer','Delete','Next'])
def test_generic_buttons_cannot_be_bound_as_login(name):
    snap,entry=target([]);selector=entry['scope']['sign_in_selector'];selector['name']=name
    with pytest.raises(uia.UIAutomationError):uia.resolve_sign_in_button(snap,selector)
