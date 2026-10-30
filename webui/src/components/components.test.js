import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { tick } from 'svelte';
import Button from './Button.svelte';
import Field from './Field.svelte';
import Modal from './Modal.svelte';
import Unlock from '../screens/Unlock.svelte';
import TopBar from './TopBar.svelte';
import NewItem from './NewItem.svelte';
import ItemMenu from './ItemMenu.svelte';
import Chips from './Chips.svelte';
import SortMenu from './SortMenu.svelte';
import QuickAccess from './QuickAccess.svelte';
import BackupPasswordSheet from './BackupPasswordSheet.svelte';
import MasterSheet from './MasterSheet.svelte';
import ShareSheet from './ShareSheet.svelte';
import IncomingSheet from './IncomingSheet.svelte';
import ImportExportMenu from './ImportExportMenu.svelte';
import PasswordModal from './PasswordModal.svelte';
import CameraView from './CameraView.svelte';
import PhraseCard from './PhraseCard.svelte';
import WorkspacePages from './WorkspacePages.svelte';
import UnlockingPage from './UnlockingPage.svelte';
import ConnectionsPage from './ConnectionsPage.svelte';
import LicencePage from './LicencePage.svelte';
import RecoveryPage from './RecoveryPage.svelte';
import SyncStatusPage from './SyncStatusPage.svelte';
import SecurityPage from './SecurityPage.svelte';
import ProfilesPage from './ProfilesPage.svelte';
import OnboardingPage from './OnboardingPage.svelte';
import SettingsPage from './SettingsPage.svelte';
import SyncPage from './SyncPage.svelte';
import { fakeApi } from '../test/fakeApi.js';
import { setMessages } from '../lib/i18n.svelte.js';
import enCatalog from '../../../src/localvault/assets/i18n/en.json';
import pseudoCatalog from '../../../src/localvault/assets/i18n/en-XA.json';

describe('Button', () => {
  it('renders its label and calls onclick', async () => {
    const onclick = vi.fn();
    render(Button, { label: 'Unlock', onclick });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(onclick).toHaveBeenCalledOnce();
  });

  it('sets the variant class and is a pill', () => {
    render(Button, { label: 'Lock', variant: 'glass' });
    const button = screen.getByRole('button', { name: 'Lock' });
    expect(button).toHaveClass('btn', 'glass');
  });

  it('can be busy: disabled with a busy label', () => {
    render(Button, { label: 'Unlock', busy: true, busyLabel: 'Unlocking…' });
    expect(screen.getByRole('button', { name: 'Unlocking…' })).toBeDisabled();
  });
});

describe('Field', () => {
  it('links its label to the input', () => {
    render(Field, { label: 'Username', value: 'alex' });
    expect(screen.getByLabelText('Username')).toHaveValue('alex');
  });

  it('masks a password until Show is pressed', async () => {
    render(Field, { label: 'Master password', type: 'password', value: 'secret' });
    const input = screen.getByLabelText('Master password');
    expect(input).toHaveAttribute('type', 'password');
    await fireEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect(input).toHaveAttribute('type', 'text');
    expect(screen.getByRole('button', { name: 'Hide' })).toBeInTheDocument();
  });
});

describe('Modal', () => {
  it('shows title and message; Allow answers true', async () => {
    const onanswer = vi.fn();
    render(Modal, { title: 'Save new login?', message: 'Origin: https://a.test', onanswer });
    expect(screen.getByRole('dialog', { name: 'Save new login?' })).toBeInTheDocument();
    expect(screen.getByText('Origin: https://a.test')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Allow' }));
    expect(onanswer).toHaveBeenCalledWith(true);
  });

  it('an extra button sits beside Allow and takes the focus', async () => {
    const onanswer = vi.fn();
    const onextra = vi.fn();
    render(Modal, { title: 'Pro', message: 'M', allowLabel: 'Enter licence', denyLabel: 'Not now',
      extraLabel: 'Buy Pro', onextra, onanswer });
    const buy = screen.getByRole('button', { name: 'Buy Pro' });
    await tick();
    expect(buy).toHaveFocus();
    await fireEvent.click(buy);
    expect(onextra).toHaveBeenCalledOnce();
    expect(onanswer).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Enter licence' }));
    expect(onanswer).toHaveBeenCalledWith(true);
  });

  it('guarded: Deny has the focus and Enter or a click on Allow is ignored at first', async () => {
    vi.useFakeTimers();
    try {
      const onanswer = vi.fn();
      render(Modal, { title: 'T', message: 'M', guardMs: 500, onanswer });
      await tick();
      const allow = screen.getByRole('button', { name: 'Allow' });
      expect(screen.getByRole('button', { name: 'Deny' })).toHaveFocus();
      expect(allow).toBeDisabled();
      await fireEvent.click(allow);
      expect(onanswer).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(600);
      expect(allow).toBeEnabled();
      await fireEvent.click(allow);
      expect(onanswer).toHaveBeenCalledWith(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('Deny and Escape answer false', async () => {
    const onanswer = vi.fn();
    render(Modal, { title: 'T', message: 'M', onanswer });
    await fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onanswer.mock.calls).toEqual([[false], [false]]);
  });
});

describe('sidebar icons', () => {
  it('gives every built-in entry an icon that matches what it does', async () => {
    const { ICONS, navIconKey } = await import('./navIcons.js');
    const kinds = ['web', 'desktop', 'card', 'bank_account', 'identity', 'note', 'document', 'ssh_key', 'api_key',
      'wifi', 'license', 'purchase', 'warranty', 'subscription', 'bookmark', 'passkey'];
    for (const k of kinds) expect(navIconKey({ token: k })).toBe(k);
    expect(navIconKey({ token: null })).toBe('all');
    expect(navIconKey({ token: 'favorite' })).toBe('favorite');
    expect(navIconKey({ token: 'recent' })).toBe('recent');
    expect(navIconKey({ token: 'collection:abc' })).toBe('collection');
    expect(navIconKey({ token: 'view:abc' })).toBe('view');
    const actions = { security_health_clicked: 'security', reminders_clicked: 'reminders', sync_clicked: 'sync',
      connections_clicked: 'connections', licence_clicked: 'licence', import_export_clicked: 'import_export',
      scan_qr_clicked: 'scan_qr', activity_clicked: 'activity', trash_clicked: 'trash', settings_clicked: 'settings' };
    for (const [action, key] of Object.entries(actions)) expect(navIconKey({ action })).toBe(key);
    for (const key of Object.values(actions).concat(kinds, ['all', 'favorite', 'recent', 'collection', 'view'])) {
      expect(ICONS[key]?.length).toBeGreaterThan(0);
    }
    expect(navIconKey({ token: 'something-new' })).toBeNull();
    expect(navIconKey({ action: 'unknown_clicked' })).toBeNull();
  });
});

describe('extracted strings (5a screens and shell)', () => {
  afterEach(() => setMessages('en', enCatalog));

  it('leaves no plain English sentence when the pseudo-locale is active', () => {
    setMessages('en-XA', pseudoCatalog);
    const vault = { state: 'locked', vault_exists: false, hello: false, camera: false, recovery_phrase: false, profile: { name: 'Ana' } };
    const { container } = render(Unlock, { vault });
    render(TopBar, { query: '' }, { container });
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const plain = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.trim();
      if (/^[A-Za-z][a-z]+( [a-z]+)+$/.test(text)) plain.push(text);
    }
    expect(plain).toEqual([]);
  });
});

describe('extracted strings (5b items)', () => {
  afterEach(() => setMessages('en', enCatalog));

  it('leaves no plain English sentence when the pseudo-locale is active', () => {
    setMessages('en-XA', pseudoCatalog);
    const item = { ref: { source: 'credential', kind: 'web', id: 'a' }, target: 'example.com', favorite: false };
    const { container } = render(NewItem, { onchoose: () => {}, onclose: () => {} });
    render(ItemMenu, { item, at: { x: 0, y: 0 }, onpick: () => {}, onclose: () => {} }, { container });
    render(Chips, { counts: { attention: 2 }, onselect: () => {} }, { container });
    render(SortMenu, { sort: null, onchange: () => {} }, { container });
    render(QuickAccess, { onclose: () => {}, onopen: () => {} }, { container });
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const plain = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.trim();
      if (/^[A-Za-z][a-z]+( [a-z]+)+$/.test(text)) plain.push(text);
    }
    expect(plain).toEqual([]);
  });
});

describe('extracted strings (5c sheets and modals)', () => {
  afterEach(() => setMessages('en', enCatalog));

  it('leaves no plain English sentence when the pseudo-locale is active', () => {
    setMessages('en-XA', pseudoCatalog);
    const none = () => {};
    const { container } = render(BackupPasswordSheet, { onclose: none });
    render(MasterSheet, { onclose: none }, { container });
    render(ShareSheet, { item: { source: 'credential', id: 'a' }, onclose: none }, { container });
    render(IncomingSheet, { onclose: none }, { container });
    render(ImportExportMenu, { onpick: none, onclose: none, page: true, phoneBackup: true }, { container });
    render(PasswordModal, { title: 'x', onanswer: none }, { container });
    render(Modal, { title: 'x', onanswer: none }, { container });
    render(CameraView, {}, { container });
    render(PhraseCard, { card: { token: 't', intro: 'x', words: ['a'], positions: [1, 2, 3] }, ondone: none }, { container });
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const plain = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.trim();
      if (/^[A-Za-z][a-z]+( [a-z]+)+$/.test(text)) plain.push(text);
    }
    expect(plain).toEqual([]);
  });
});

describe('extracted strings (5d pages)', () => {
  afterEach(() => { setMessages('en', enCatalog); delete window.pywebview; });

  it('leaves no plain English sentence when the pseudo-locale is active', async () => {
    setMessages('en-XA', pseudoCatalog);
    const none = () => {};
    const ok = (extra) => vi.fn().mockResolvedValue({ ok: true, ...extra });
    fakeApi({
      collections_list: ok({ collections: [{ id: 'c1', name: 'X' }] }),
      reminders_list: ok({ rows: [] }),
      hello_status: ok({ supported: true, enabled: false, incomplete: false, tone: 'neutral', auto_start: true, status: 'x', guidance: 'x' }),
      face_status: ok({ supported: true, enabled: false, incomplete: false, tone: 'neutral', status: 'x' }),
      connections_view: ok({ headline: 'x', summary: 'x', tone: 'success', status: 'x', browsers: [], empty: 'x', can_repair: true, details: 'x', footer: 'x' }),
      licence_view: ok({ headline: 'x', details: [], can_remove: true, purchase_url: 'https://x.test' }),
      backup_status: ok({ intro: 'x', can_create: true, trial: false, kit_ready: true, phrase_enrolled: false, phrase_intro: 'x' }),
      sync_status: ok({ state: 'off', colour: 'green', text: 'x', devices: [] }),
      security_center: ok({ score: 80, label: 'x', headline: 'x', issues: [], panels: [], footnote: 'x' }),
      profiles_manage: ok({ intro: 'x', profiles: [{ id: 'p', name: 'X', color: '#3B82F6', initials: 'X', active: true }], note: 'x' }),
      onboarding_show: ok({ title: 'x', subtitle: 'x', progress: '1 of 5', done: 1, complete: false, current: 'vault', message: '',
        steps: [{ key: 'vault', label: 'x', state: 'current', text: 'x', primary: 'x' }, { key: 'import', label: 'y', state: 'skipped', text: 'x', primary: 'x' }] }),
      settings_page: ok({ saved_text: '', sections: [{ key: 'a', title: 'X', rows: [{ type: 'folder', key: 'f', title: 'x', value: '' }] }] }),
      sync_refresh: ok({ pro: true, intro: 'x', available: false, cards: [], skipped: [] }),
      sync_view: ok({ pro: true, intro: 'x', available: false, cards: [], skipped: [] }),
    });
    const pages = [
      [WorkspacePages, { kind: 'collections', onclose: none }],
      [UnlockingPage, { onclose: none }],
      [ConnectionsPage, { onclose: none }],
      [LicencePage, { onclose: none }],
      [RecoveryPage, { onclose: none }],
      [SyncStatusPage, { onclose: none, onsettings: none }],
      [SecurityPage, { onclose: none, onroute: none }],
      [ProfilesPage, { onclose: none }],
      [OnboardingPage, { onclose: none, onroute: none }],
      [SettingsPage, { onclose: none, onroute: none }],
      [SyncPage, { onclose: none, onlicence: none }],
    ];
    const plain = [];
    for (const [component, props] of pages) {
      const { container, unmount } = render(component, props);
      await waitFor(() => expect(container.querySelectorAll('button').length).toBeGreaterThan(0));
      await new Promise((resolve) => setTimeout(resolve, 30));
      await tick();
      const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        const text = n.textContent.trim();
        if (/^[A-Za-z][a-z]+( [a-z]+)+$/.test(text)) plain.push(text);
      }
      unmount();
    }
    expect(plain).toEqual([]);
  });
});
