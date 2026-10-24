<script>
  /** The unlocked home screen: sidebar | list | detail, with sheets for editor, generator, palette, new item. */
  import Chips from '../components/Chips.svelte';
  import DetailPane from '../components/DetailPane.svelte';
  import Generator from '../components/Generator.svelte';
  import CodesCard from '../components/CodesCard.svelte';
  import ItemList from '../components/ItemList.svelte';
  import ItemMenu from '../components/ItemMenu.svelte';
  import LoginEditor from '../components/LoginEditor.svelte';
  import NewItem from '../components/NewItem.svelte';
  import Overview from '../components/Overview.svelte';
  import Palette from '../components/Palette.svelte';
  import Sidebar from '../components/Sidebar.svelte';
  import StatusLine from '../components/StatusLine.svelte';
  import TopBar from '../components/TopBar.svelte';
  import TrashPage from '../components/TrashPage.svelte';
  import TypedEditor from '../components/TypedEditor.svelte';
  import SecurityPage from '../components/SecurityPage.svelte';
  import HealthPage from '../components/HealthPage.svelte';
  import MasterSheet from '../components/MasterSheet.svelte';
  import RecoveryPage from '../components/RecoveryPage.svelte';
  import UnlockingPage from '../components/UnlockingPage.svelte';
  import Modal from '../components/Modal.svelte';
  import SettingsPage from '../components/SettingsPage.svelte';
  import LicencePage from '../components/LicencePage.svelte';
  import ConnectionsPage from '../components/ConnectionsPage.svelte';
  import ProfilesPage from '../components/ProfilesPage.svelte';
  import BackupPasswordSheet from '../components/BackupPasswordSheet.svelte';
  import SyncPage from '../components/SyncPage.svelte';
  import ImportSheet from '../components/ImportSheet.svelte';
  import ExportSheet from '../components/ExportSheet.svelte';
  import TransferSheet from '../components/TransferSheet.svelte';
  import PhoneBackupSheet from '../components/PhoneBackupSheet.svelte';
  import ImportExportMenu from '../components/ImportExportMenu.svelte';
  import WorkspacePages from '../components/WorkspacePages.svelte';
  import OnboardingPage from '../components/OnboardingPage.svelte';
  import DesktopSheet from '../components/DesktopSheet.svelte';
  import QuickAccess from '../components/QuickAccess.svelte';
  import { call, on } from '../lib/api.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';

  let { vault } = $props();

  let nav = $state(null);
  let filter = $state(null);
  let chip = $state(null);
  let query = $state('');
  let list = $state(null);
  let selected = $state(null);
  let itemList = $state();
  let overview = $state(null);
  let status = $state(null);
  let quick = $state(false);
  let sheet = $state(null); // {kind: 'editor', ref} | {kind: 'generator'} | {kind: 'palette'} | {kind: 'new'}
  let menu = $state(null);
  let searchInput = $state();
  let searchTimer = null;
  let seq = 0;

  async function refresh() {
    const mine = ++seq;
    const [items, navResult] = await Promise.all([call('items_list', filter, chip, query), call('nav_get')]);
    if (mine !== seq) return;
    if (items.ok) {
      list = items;
      if (selected && !items.items.some((i) => i.ref.id === selected.id)) selected = null;
    }
    if (navResult.ok) nav = navResult;
  }

  async function refreshOverview() {
    const result = await call('overview_get');
    if (result.ok) overview = result;
  }

  async function refreshStatus() {
    const result = await call('status_get');
    if (result.ok) status = result;
  }

  // One-time Windows Hello offer after a password unlock (classic window behaviour).
  let offer = $state(null);
  $effect(() => { call('hello_offer').then((r) => { if (r.ok && r.offer) offer = r; }); });

  async function answerOffer(value) {
    const accepted = value?.choice === 'allow' || value === true;
    offer = null;
    await call('hello_offer_answer', accepted);
    if (accepted) push({ kind: 'unlocking', startHello: true });
  }

  $effect(() => {
    let after = null;
    try { after = JSON.parse(window.sessionStorage.getItem('lgk.afterUnlock') ?? 'null'); window.sessionStorage.removeItem('lgk.afterUnlock'); } catch { /* optional */ }
    if (after?.route) route(after.route, after.params ?? {});
  });

  $effect(() => {
    const open = (event) => route(event.detail.route, event.detail.params ?? {});
    window.addEventListener('lgk-route', open);
    return () => window.removeEventListener('lgk-route', open);
  });

  $effect(() => {
    refresh();
    refreshOverview();
    refreshStatus();
    const offs = [
      on('items.changed', () => { refresh(); refreshOverview(); }),
      on('autolock.tick', refreshStatus),
    ];
    return () => offs.forEach((off) => off());
  });

  function setFilter(token) { filter = token; chip = null; refresh(); }
  function setChip(value) { chip = value; refresh(); }
  function searched() { clearTimeout(searchTimer); searchTimer = setTimeout(refresh, 120); }
  function clearAll() { filter = null; chip = null; query = ''; refresh(); }

  function emptyAction(action) {
    if (action === 'Clear filters') clearAll();
    else if (action === 'New item') sheet = { kind: 'new' };
  }

  function openItem(ref) {
    selected = ref;
    if (ref.source === 'credential') sheet = { kind: 'editor', ref };
    else if (ref.source === 'typed') sheet = { kind: 'typed', ref, itemKind: ref.kind };
  }

  // Pages opened over the home screen stack: closing one returns to the page that opened it.
  let pages = $state([]);
  const page = $derived(pages.length ? pages[pages.length - 1] : null);
  let afterClose = [];
  let pageIds = 0;
  function push(next, refresh = null) {
    // Opening a page that is already open goes back to it instead of stacking a second copy.
    const existing = pages.findIndex((p) => p.kind === next.kind);
    if (existing !== -1) {
      pages = [...pages.slice(0, existing), { ...pages[existing], ...next, id: pages[existing].id }];
      afterClose = afterClose.slice(0, existing + 1);
      return;
    }
    afterClose.push(refresh);
    pages = [...pages, { ...next, id: ++pageIds }];
  }
  // Lower pages stay mounted (they keep their place) but hidden; a small sheet shows over the page beneath it.
  const OVERLAYS = new Set(['master', 'backup-password']);
  function shown(i) {
    const last = pages.length - 1;
    return i === last || (i === last - 1 && OVERLAYS.has(pages[last].kind));
  }
  function pop() {
    pages = pages.slice(0, -1);
    const refresh = afterClose.pop();
    if (refresh) refresh();
  }
  let update = $state(null);
  const updateText = $derived(update ? 'A newer version is available.\n\nCurrent version: ' + update.current
    + '\nLatest version: ' + update.latest + (update.note ? '\n\n' + update.note : '') : '');

  // After unlock: an old build suggests an update check (no network until the user says yes).
  let reminder = $state(null);
  $effect(() => { call('updates_reminder').then((r) => { if (r.ok && r.due) reminder = r; }); });
  function reminderAnswer(yes) {
    reminder = null;
    if (yes) checkUpdates(); else call('updates_snooze');
  }

  async function checkUpdates() {
    const result = await call('updates_check');
    if (!result.ok) { if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error'); return; }
    if (result.available) update = result;
    else toast(result.message);
  }

  async function openRelease(yes) {
    update = null;
    if (!yes) return;
    const result = await call('updates_open_release');
    if (!result.ok) toast(result.error.message, '', 'error');
  }

  async function backupPassword(params, refresh) {
    if (params.clear) {
      const result = await call('backup_password_clear');
      if (result.ok) toast(result.message);
      else if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error');
      if (refresh) refresh();
      return;
    }
    push({ kind: 'backup-password' }, refresh);
  }

  function route(target, params = {}, refresh = null) {
    if (target === 'security') push({ kind: 'security' }, refresh);
    else if (target === 'health') push({ kind: 'health', filter: params.filter ?? null, scanAll: !!params.scan_all }, refresh);
    else if (target === 'master') push({ kind: 'master' }, refresh);
    else if (target === 'recovery') push({ kind: 'recovery', initial: params.initial ?? null }, refresh);
    else if (target === 'hello' || target === 'face') push({ kind: 'unlocking', startHello: !!params.startHello }, refresh);
    else if (target === 'settings') push({ kind: 'settings', section: params.section ?? null }, refresh);
    else if (target === 'licence') push({ kind: 'licence' }, refresh);
    else if (target === 'connections') push({ kind: 'connections' }, refresh);
    else if (target === 'profiles' || target === 'switch-profile') push({ kind: 'profiles' }, refresh);
    else if (target === 'updates' || target === 'check-updates') checkUpdates();
    else if (target === 'backup_password') backupPassword(params, refresh);
    else if (target === 'sync') push({ kind: 'sync' }, refresh);
    else if (['reminders', 'activity', 'shortcuts', 'collections'].includes(target)) push({ kind: 'workspace', which: target }, refresh);
    else if (target === 'onboarding') push({ kind: 'onboarding' }, refresh);
    else if (target === 'desktop-bind') push({ kind: 'desktop', token: params.token ?? null }, refresh);
    else if (target === 'new-item') sheet = { kind: 'new' };
    else if (target === 'quick-access') quick = true;
    else if (target === 'import-menu') sheet = { kind: 'import-menu' };
    else if (target === 'import') push({ kind: 'import' }, refresh);
    else if (target === 'export') push({ kind: 'export' }, refresh);
    else if (target === 'transfer' || target === 'encrypted-transfer') push({ kind: 'transfer' }, refresh);
    else if (target === 'phone-backup') push({ kind: 'phone-backup' }, refresh);
    else navAction(target);
  }

  const NAV_ROUTES = { security_health_clicked: 'security', settings_clicked: 'settings', licence_clicked: 'licence',
    connections_clicked: 'connections', sync_clicked: 'sync', import_export_clicked: 'import-menu',
    import_clicked: 'import', export_clicked: 'export', transfer_clicked: 'transfer', reminders_clicked: 'reminders',
    activity_clicked: 'activity', show_shortcuts_clicked: 'shortcuts', onboarding_clicked: 'onboarding',
    quick_access_clicked: 'quick-access' };

  function navAction(action) {
    if (action === 'trash_clicked') { sheet = { kind: 'trash' }; return; }
    if (NAV_ROUTES[action]) { route(NAV_ROUTES[action]); return; }
    toast('Coming in a later update', 'This page is not in the new window yet. The classic window still has it.');
  }

  function navigate(target, params = {}) {
    if (['security', 'health', 'master', 'recovery', 'settings', 'licence', 'connections', 'profiles',
      'switch-profile', 'check-updates', 'updates', 'sync', 'import', 'export', 'encrypted-transfer', 'reminders',
      'activity', 'onboarding', 'shortcuts', 'collections'].includes(target)) route(target, params);
    else if (target === 'generator') sheet = { kind: 'generator' };
    else if (target === 'new-item') sheet = { kind: 'new' };
    else if (target === 'trash') sheet = { kind: 'trash' };
    else if (target === 'quick-access') quick = true;
    else if (target === 'devices-sync') route('connections');
    else if (target === 'sync-settings') route('sync');
    else if (target === 'error-log') call('errorlog_open').then((r) => okOrToast(r, 'Error log folder not opened'));
    else navAction(target);
  }

  async function menuPick(action) {
    const item = menu.item;
    const ref = item.ref;
    if (action === 'edit' || action === 'open') openItem(ref);
    else if (action.startsWith('copy-')) {
      const result = await call('item_copy', ref, action.slice(5));
      if (okOrToast(result, 'Not copied')) notice(result);
    } else if (action === 'open-website') okOrToast(await call('item_open_website', ref), 'Website not opened');
    else if (action === 'favorite') {
      const result = await call('item_favorite', ref, !item.favorite);
      if (okOrToast(result)) toast(result.message);
    } else if (action === 'trash') {
      const result = await call('item_trash', ref);
      if (okOrToast(result, 'Not moved to trash')) notice(result);
    }
  }

  // Typed items need the current catalog: offer the update first, as the classic window does.
  async function chooseNewKind(kind) {
    if (kind === 'web') { sheet = { kind: 'editor', ref: null }; return; }
    if (kind === 'desktop') { sheet = null; push({ kind: 'desktop' }); return; }
    const status = await call('catalog_status');
    if (!status.ok) { sheet = null; toast(status.error.message, '', 'error'); return; }
    if (status.needs_update) {
      const updated = await call('catalog_update');
      if (!updated.ok) { sheet = null; if (updated.error.code !== 'cancelled') toast(updated.error.message, '', 'error'); return; }
    }
    sheet = { kind: 'typed', ref: null, itemKind: kind };
  }

  async function trash(ref) {
    const result = await call('item_trash', ref);
    if (okOrToast(result, 'Not moved to trash')) notice(result);
  }

  async function copyPassword(ref) {
    if (ref.source !== 'credential') return;
    const result = await call('item_copy', ref, 'password');
    if (okOrToast(result, 'Not copied')) notice(result);
  }

  function inTextField(target) {
    const tag = target?.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable;
  }

  // Arrows, Enter and Ctrl+C reach the item list from anywhere on the main screen, including the search box
  // (arrows and Enter only there, so typing and copying text in it keep working).
  function listKeys(event) {
    if (!itemList || event.target?.closest?.('[role="listbox"]')) return false; // the list handles its own keys
    const inSearch = event.target === searchInput;
    if (inTextField(event.target) && !inSearch) return false;
    if (event.altKey || event.metaKey) return false;
    const arrow = event.key === 'ArrowDown' || event.key === 'ArrowUp';
    const copy = event.ctrlKey && (event.key === 'c' || event.key === 'C');
    if (inSearch && !(arrow || event.key === 'Enter')) return false;
    if (!arrow && event.key !== 'Enter' && !copy) return false;
    if (event.key === 'Enter' && !selected && list?.items?.length) selected = list.items[0].ref; // Enter in search opens the top hit
    return itemList.key(event);
  }

  function keys(event) {
    // F1 / ? open the shortcuts from the main screen only, never over a sheet, page or dialog.
    if ((event.key === 'F1' || (event.key === '?' && !inTextField(event.target))) && !event.ctrlKey && !event.altKey
        && !sheet && !pages.length && !update && !offer && !document.querySelector('.scrim')) {
      event.preventDefault();
      route('shortcuts');
      return;
    }
    if (sheet && sheet.kind !== 'editor' && sheet.kind !== 'typed') return;
    if (!sheet && !pages.length && !update && !offer && !document.querySelector('.scrim') && listKeys(event)) return;
    if (event.ctrlKey && (event.key === 'k' || event.key === 'K')) { event.preventDefault(); sheet = { kind: 'palette' }; }
    else if (event.ctrlKey && (event.key === 'n' || event.key === 'N')) { event.preventDefault(); sheet = { kind: 'new' }; }
    else if (event.ctrlKey && event.altKey && (event.key === 'l' || event.key === 'L')) { event.preventDefault(); call('lock_emergency'); }
    else if (event.ctrlKey && (event.key === 'l' || event.key === 'L')) { event.preventDefault(); call('vault_lock'); }
    else if (event.ctrlKey && (event.key === 'f' || event.key === 'F')) { event.preventDefault(); searchInput?.focus(); }
  }
</script>

<svelte:window onkeydown={keys} />

<div class="home">
  <aside class="side"><Sidebar {nav} active={filter} onfilter={setFilter} onaction={navAction} /></aside>
  <section class="center">
    <TopBar bind:query bind:searchInput oninput={searched} onlock={() => call('vault_lock')}
      onnew={() => (sheet = { kind: 'new' })} onpalette={() => (sheet = { kind: 'palette' })} />
    {#if !filter && !query && !chip}<Overview {overview} ongenerator={() => (sheet = { kind: 'generator' })} />{/if}
    {#if !filter && !query && !chip}<CodesCard />{/if}
    <div class="list-head">
      <h1>{list?.context.title ?? 'All items'}</h1>
      <span class="count">{list ? `${list.count} item${list.count === 1 ? '' : 's'}` : ''}</span>
    </div>
    <Chips counts={list?.chips ?? {}} active={chip} onselect={setChip} />
    <ItemList bind:this={itemList} items={list?.items ?? []} {selected} empty={list?.empty}
      onselect={(ref) => (selected = ref)} onopen={openItem} onemptyaction={emptyAction}
      onmenu={(item, at) => (menu = { item, at })} ontrash={trash} oncopy={copyPassword} />
  </section>
  <section class="right">
    <DetailPane {selected} icon={list?.items?.find((i) => i.ref.id === selected?.id)?.icon ?? null} onedit={openItem} onchanged={refresh} />
    {#if reminder}<Modal title={reminder.title} message={reminder.text} allowLabel="Check now" denyLabel="Not now" onanswer={reminderAnswer} />{/if}
    {#if quick}<QuickAccess onclose={() => (quick = false)} onopen={(ref) => { quick = false; openItem(ref); }} />{/if}
    {#if sheet?.kind === 'editor'}
      <LoginEditor ref={sheet.ref} newPassword={!!sheet.newPassword} onclose={(saved) => { sheet = null; if (saved) { selected = saved; refresh(); } }}
        onbinding={(entryId) => { sheet = null; push({ kind: 'desktop', entryId }); }} />
    {:else if sheet?.kind === 'typed'}
      <TypedEditor kind={sheet.itemKind} ref={sheet.ref} onclose={(saved) => { sheet = null; if (saved) { selected = saved; refresh(); } }} />
    {:else if sheet?.kind === 'generator'}
      <Generator onclose={() => (sheet = null)} />
    {/if}
  </section>
  <div class="status-row"><StatusLine {status} /></div>
</div>

{#if sheet?.kind === 'palette'}
  <Palette onclose={() => (sheet = null)} onopen={(ref) => { selected = ref; }} onnavigate={navigate} />
{:else if sheet?.kind === 'new'}
  <NewItem onclose={() => (sheet = null)} onchoose={chooseNewKind} />
{:else if sheet?.kind === 'import-menu'}
  <ImportExportMenu onclose={() => (sheet = null)} onpick={(target) => { sheet = null; route(target); }} />
{:else if sheet?.kind === 'trash'}
  <div class="trash-host"><TrashPage onclose={() => { sheet = null; refresh(); }} /></div>
{/if}
{#each pages as pg, i (pg.id)}
  <div class="trash-host" hidden={!shown(i)}>
    {#if pg.kind === 'security'}
      <SecurityPage onclose={pop} onroute={route} />
    {:else if pg.kind === 'health'}
      <HealthPage filter={pg.filter} scanAll={pg.scanAll} onclose={pop} onroute={route}
        onopen={(id) => { pages = []; afterClose = []; openItem({ source: 'credential', id, kind: 'web' }); }}
        onchangepassword={(id) => { sheet = { kind: 'editor', ref: { source: 'credential', id, kind: 'web' }, newPassword: true }; }} />
    {:else if pg.kind === 'master'}
      <MasterSheet onclose={pop} />
    {:else if pg.kind === 'unlocking'}
      <UnlockingPage startHello={!!pg.startHello} onclose={pop} />
    {:else if pg.kind === 'recovery'}
      <RecoveryPage initial={pg.initial} onclose={pop} />
    {:else if pg.kind === 'settings'}
      <SettingsPage section={pg.section} onclose={pop} onroute={route} />
    {:else if pg.kind === 'licence'}
      <LicencePage onclose={pop} />
    {:else if pg.kind === 'connections'}
      <ConnectionsPage onclose={pop} />
    {:else if pg.kind === 'profiles'}
      <ProfilesPage onclose={pop} />
    {:else if pg.kind === 'desktop'}
      <DesktopSheet token={pg.token ?? null} entryId={pg.entryId ?? null} onclose={() => { pop(); refresh(); }} />
    {:else if pg.kind === 'workspace'}
      <WorkspacePages kind={pg.which} onclose={pop} />
    {:else if pg.kind === 'onboarding'}
      <OnboardingPage onclose={pop} onroute={route} />
    {:else if pg.kind === 'import'}
      <ImportSheet onclose={() => { pop(); refresh(); }} />
    {:else if pg.kind === 'export'}
      <ExportSheet onclose={pop} />
    {:else if pg.kind === 'transfer'}
      <TransferSheet onclose={() => { pop(); refresh(); }} />
    {:else if pg.kind === 'phone-backup'}
      <PhoneBackupSheet onclose={() => { pop(); refresh(); }} />
    {:else if pg.kind === 'sync'}
      <SyncPage onclose={pop} onlicence={() => push({ kind: 'licence' }, refresh)} />
    {:else if pg.kind === 'backup-password'}
      <BackupPasswordSheet onclose={pop} />
    {/if}
  </div>
{/each}
{#if update}
  <Modal title="Update available" message={updateText} allowLabel="Open release page" denyLabel="Close" onanswer={openRelease} />
{/if}
{#if offer}
  <Modal title={offer.title} message={offer.text} allowLabel="Set up" denyLabel="Not now" onanswer={answerOffer} />
{/if}
{#if menu}
  <ItemMenu item={menu.item} at={menu.at} onpick={menuPick} onclose={() => (menu = null)} />
{/if}

<style>
  .home {
    height: 100%;
    display: grid;
    grid-template-columns: 210px minmax(320px, 1fr) minmax(340px, 0.9fr);
    grid-template-rows: 1fr auto;
    gap: 10px;
    padding: 10px 10px 0;
  }
  .side, .center, .right {
    min-height: 0; display: flex; flex-direction: column; position: relative;
    background: var(--wash-base); border-radius: 14px; border: 1px solid var(--separator);
  }
  .side { background: transparent; border-color: transparent; }
  .list-head { display: flex; align-items: baseline; gap: 10px; padding: 4px 16px 6px; }
  h1 { margin: 0; font: 600 20px var(--font-display); }
  .count { color: var(--text-faint); font-size: 12.5px; }
  .center :global(.list) { flex: 1; }
  .status-row { grid-column: 1 / -1; }
  .trash-host { position: fixed; inset: 0; z-index: 40; background: var(--scrim); }
</style>
