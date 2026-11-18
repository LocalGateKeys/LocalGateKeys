<script>
  /** The quick-search palette the quick-access shortcut opens over any app: search this profile, then fill the
   * app behind it (Enter) or copy a field (Ctrl+C password, Ctrl+U username, Ctrl+T code). It never shows a
   * password. Python shows and hides the window; locked, it shows the compact unlock. */
  import { t } from './lib/i18n.svelte.js';
  import Modal from './components/Modal.svelte';
  import PasswordModal from './components/PasswordModal.svelte';
  import AgentApproval from './components/AgentApproval.svelte';
  import ItemTile from './components/ItemTile.svelte';
  import { call, on } from './lib/api.js';
  import ProfileChooser from './screens/ProfileChooser.svelte';
  import Unlock from './screens/Unlock.svelte';

  const GUARD_MS = 500; // the palette appears over whatever the user was typing in
  const COPY_KEYS = { c: 'password', u: 'username', t: 'totp' };
  let vault = $state(null);
  let modals = $state([]);
  let choosingProfile = $state(false);
  let query = $state('');
  let rows = $state([]);
  let selected = $state(0);
  let message = $state('');
  let input = $state();
  let timer = null;
  let generation = 0;

  const unlocked = $derived(vault?.state === 'unlocked');

  $effect(() => {
    if (vault?.appearance === 'light' || vault?.appearance === 'dark') document.documentElement.dataset.theme = vault.appearance;
    else delete document.documentElement.dataset.theme;
  });

  function clear() {
    generation += 1;
    clearTimeout(timer);
    query = '';
    rows = [];
    selected = 0;
    message = '';
  }

  async function search() {
    if (!unlocked) return;
    const mine = ++generation;
    const result = await call('quick_search', query, '');
    if (mine !== generation) return; // a newer search, a hide or a lock came first
    if (result.ok) { rows = result.rows; selected = 0; message = ''; } else { rows = []; message = result.error?.message ?? ''; }
  }

  function focusBox() { queueMicrotask(() => input?.focus()); }

  $effect(() => {
    call('vault_state').then((result) => {
      if (!result.ok) return;
      vault = result;
      if (result.state === 'unlocked') { search(); focusBox(); }
    });
    const offs = [
      on('vault.state', (detail) => {
        const was = unlocked;
        vault = detail;
        if (detail.state === 'unlocked') { choosingProfile = false; if (!was) { search(); focusBox(); } } else clear();
      }),
      on('vault.locked', () => clear()),
      on('palette.hide', () => clear()),
      on('palette.show', () => {
        clear();
        call('vault_state').then((result) => {
          if (!result.ok) return;
          vault = result;
          if (result.state === 'unlocked') search();
        });
        focusBox();
      }),
      on('modal.request', (detail) => {
        if (detail.surface !== 'palette') return; // the main window's or the popup's own questions
        if (!['password', 'confirm', 'agent'].includes(detail.kind)) { call('modal_answer', detail.id, { choice: 'cancel' }); return; }
        modals.push(detail);
      }),
      on('modal.cancel', (detail) => {
        const ids = new Set(detail.ids ?? []);
        modals = modals.filter((m) => !ids.has(m.id));
      }),
    ];
    return () => offs.forEach((off) => off());
  });

  function answer(id, value) {
    modals = modals.filter((m) => m.id !== id);
    call('modal_answer', id, value);
    focusBox();
  }

  function hide() {
    clear();
    call('palette_hide');
  }

  async function copy(field) {
    const row = rows[selected];
    if (!row) return;
    const result = await call('palette_copy', row.ref, field);
    if (result.ok) hide();
    else if (result.error?.code !== 'cancelled') message = result.error?.message ?? '';
  }

  const BLUR_HIDE_MS = 150;
  let blurTimer = null;
  let filling = false; // Python hides the palette for a fill: that focus loss is not the user leaving

  function blurred() {
    if (filling) return;
    clearTimeout(blurTimer);
    blurTimer = setTimeout(hide, BLUR_HIDE_MS);
  }
  function focused() { clearTimeout(blurTimer); }

  async function fill() {
    const row = rows[selected];
    if (!row || filling) return;
    filling = true;
    clearTimeout(blurTimer);
    // Python checks the row can fill the window the palette opened over, hides the palette, then fills;
    // a refusal comes back here (the palette is shown again if it had hidden).
    const result = await call('palette_fill', row.ref).finally(() => { filling = false; });
    if (result.ok) clear();
    else if (result.error?.code !== 'cancelled') message = result.error?.message ?? '';
  }

  let list = $state();

  function focusRow(index) {
    selected = index;
    queueMicrotask(() => list?.querySelectorAll('[role="option"]')[index]?.focus());
  }

  function typed() { clearTimeout(timer); timer = setTimeout(search, 120); }

  function keys(event) {
    const onRow = event.currentTarget !== input;
    if (event.key === 'Escape') { event.preventDefault(); hide(); return; }
    if (event.key === 'ArrowDown' && rows.length) {
      event.preventDefault();
      focusRow(onRow ? Math.min(rows.length - 1, selected + 1) : selected);
      return;
    }
    if (event.key === 'ArrowUp' && rows.length) {
      event.preventDefault();
      if (onRow && selected === 0) input?.focus(); else focusRow(Math.max(0, selected - 1));
      return;
    }
    if (event.key === 'Enter') { event.preventDefault(); fill(); return; }
    const field = COPY_KEYS[String(event.key).toLowerCase()];
    if (!field || !event.ctrlKey || event.altKey || event.shiftKey || event.metaKey) return;
    // Ctrl+C in the search box copies its text as usual; the password only from a result row, nothing selected.
    if (field === 'password' && (!onRow || String(window.getSelection?.() ?? ''))) return;
    event.preventDefault();
    copy(field);
  }

  function windowKeys(event) {
    if (event.key === 'Escape' && !modals.length && !unlocked) { event.preventDefault(); hide(); }
  }
</script>

<svelte:window onkeydown={windowKeys} onblur={blurred} onfocus={focused} />

<div class="wash" aria-hidden="true"></div>
<main class="palette">
  {#if modals.length}
    {@const modal = modals[0]}
    {#key modal.id}
      {#if modal.kind === 'agent'}
        <AgentApproval request={modal} guardMs={GUARD_MS} onanswer={(value) => answer(modal.id, value)} />
      {:else if modal.kind === 'password'}
        <PasswordModal title={modal.title} message={modal.message} onanswer={(value) => answer(modal.id, value)} />
      {:else}
        <Modal title={modal.title} message={modal.message} guardMs={GUARD_MS} onanswer={(value) => answer(modal.id, value)} />
      {/if}
    {/key}
  {:else if vault && !unlocked}
    {#if choosingProfile || vault.state === 'no_profile'}
      <ProfileChooser onchosen={(state) => { vault = state; choosingProfile = false; }} />
    {:else}
      <Unlock {vault} brand={false} onswitchprofile={() => (choosingProfile = true)} />
    {/if}
  {:else if vault}
    <input class="search" type="search" bind:this={input} bind:value={query} oninput={typed} onkeydown={keys}
      placeholder={t('quickPalette.placeholder')} aria-label={t('quickPalette.placeholder')} autocomplete="off" spellcheck="false" />
    <div class="list" role="listbox" bind:this={list} aria-label={t('quickAccess.results')}>
      {#each rows as row, index (row.ref.id)}
        <div role="option" tabindex="-1" aria-selected={index === selected} class="row" class:selected={index === selected}
          onmousemove={() => (selected = index)} onclick={() => { selected = index; fill(); }}
          onkeydown={keys}>
          <ItemTile kind={row.ref.kind} size={24} />
          <span class="title">{row.title}</span>
          <span class="muted">{row.subtitle}</span>
        </div>
      {:else}
        {#if query}<p class="empty">{t('quickAccess.noMatches')}</p>{/if}
      {/each}
    </div>
    {#if message}<p class="message" role="alert">{message}</p>{/if}
    <p class="hint">{t('quickPalette.hint')}</p>
  {/if}
</main>

<style>
  .palette { height: 100%; display: flex; flex-direction: column; gap: 8px; padding: 12px; box-sizing: border-box; overflow: hidden; }
  .search { font-size: 16px; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--separator);
    background: var(--group); color: var(--text); user-select: text; }
  .list { flex: 1; overflow: auto; }
  .row { display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-radius: 8px; cursor: pointer; }
  .row.selected { background: var(--group); }
  .title { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .muted { color: var(--text-muted); font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 40%; }
  .empty { color: var(--text-muted); text-align: center; padding: 14px; margin: 0; }
  .message { color: var(--danger, #d33); font-size: 12.5px; margin: 0; }
  .hint { color: var(--text-muted); font-size: 11.5px; margin: 0; text-align: center; }
</style>
