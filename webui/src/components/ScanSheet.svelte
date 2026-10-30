<script>
  /** Scan QR code: add 2FA codes from a picture file, a pasted screenshot, a dropped file or the webcam.
   *  Pictures are read into memory and sent to Python, which checks them again; secrets never come back here. */
  import { call } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { readPicture } from '../lib/picture.js';
  import Button from './Button.svelte';
  import QrCameraView from './QrCameraView.svelte';

  let { onclose, onedit, ondone = undefined } = $props();

  let result = $state(null); // the scan: token, kind ('key' | 'export'), accounts, batch, complete
  let rows = $state([]); // export: {index, checked, target, website}
  let pick = $state(null); // single key: a login id or 'new'
  let status = $state('');
  let done = $state('');
  let scanning = $state(null); // 'image' | 'camera'
  let busy = $state(false);
  let dragging = $state(false);

  const guess = (issuer) => (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(issuer.trim()) ? issuer.trim().toLowerCase() : '');
  const name = (account) => account.issuer || account.label || t('scanSheet.account', { number: formatNumber(account.index + 1) });
  const skippedText = (s) => t('scanSheet.skippedItem', { name: s.issuer || s.label, reason: s.reason });
  const loginText = (login) => {
    const base = login.label + (login.username ? ` · ${login.username}` : '');
    return login.has_totp ? `${base} ${t('scanSheet.replacesTotp')}` : base;
  };

  function show(next) {
    result = next;
    done = '';
    if (next.kind === 'key') {
      pick = next.accounts[0]?.best ?? 'new';
    } else {
      const before = new Map(rows.map((row) => [row.index, row]));
      rows = next.accounts.map((a) => before.get(a.index) ?? {
        index: a.index, checked: !a.already, target: a.best ?? 'new', website: '', suggestion: guess(a.issuer),
      });
    }
    const batch = next.batch;
    const more = next.more_codes ? t('scanSheet.moreCodes', { number: formatNumber(next.more_codes + 1) }) : '';
    status = [next.complete ? '' : t('scanSheet.progress', { scanned: formatNumber(batch.scanned.length), size: formatNumber(batch.size) }), more]
      .filter(Boolean).join(' ');
  }

  async function scan(kind, image = null) {
    if (scanning) return;
    scanning = kind;
    status = kind === 'image' ? t('scanSheet.reading') : '';
    // The next part of a multi-part export joins the accounts already scanned.
    const token = result && result.kind === 'export' && !result.complete ? result.token : null;
    // A fresh scan replaces the previous one: Python forgets the old accounts now, not when the vault locks.
    if (result && !token) { const old = result.token; result = null; rows = []; await call('qr_sheet_discard', old); }
    const reply = kind === 'image' ? await call('qr_sheet_scan_image', image, token) : await call('qr_sheet_scan_camera', token);
    scanning = null;
    if (!reply.ok) {
      status = reply.error.code === 'cancelled' ? (result && !result.complete ? status : '') : reply.error.message;
      return;
    }
    show(reply);
  }

  async function picture(file) {
    if (!file) return;
    const read = await readPicture(file);
    if (read.error) { status = read.error; return; }
    scan('image', read.dataUrl);
  }

  function chosen(event) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    picture(file);
  }

  // Win+Shift+S then Ctrl+V: only an image paste is taken; text pastes as usual.
  function pasted(event) {
    const file = [...(event.clipboardData?.items ?? [])].find((item) => item.kind === 'file' && item.type.startsWith('image/'))?.getAsFile();
    if (!file) return;
    event.preventDefault();
    picture(file);
  }

  function dragover(event) {
    if (![...(event.dataTransfer?.types ?? [])].includes('Files')) return;
    event.preventDefault();
    dragging = true;
  }

  function dropped(event) {
    event.preventDefault();
    dragging = false;
    picture(event.dataTransfer?.files?.[0]);
  }

  // One key: open the chosen login (or a new one) in the editor with the key applied; the person saves there.
  async function openEditor() {
    if (busy) return;
    busy = true;
    const target = pick === 'new' ? null : pick;
    const reply = await call('qr_sheet_open', result.token, 0, target);
    busy = false;
    if (!reply.ok) { status = reply.error.message; return; }
    result = null;
    onedit(reply, target ? { source: 'credential', id: target, kind: reply.kind ?? 'web' } : null);
  }

  const selected = $derived(rows.filter((row) => row.checked));
  const ready = $derived(!!result && result.complete && selected.length > 0
    && selected.every((row) => row.target !== 'new' || row.website.trim()));

  async function add() {
    if (busy || !ready) return;
    busy = true;
    const replacing = selected.map((row) => result.accounts.find((a) => a.index === row.index).matches.find((m) => m.id === row.target))
      .filter((login) => login?.has_totp);
    if (replacing.length && !window.confirm?.(t('scanSheet.replaceConfirm', { names: replacing.map((l) => l.label).join(', ') }))) {
      busy = false;
      return;
    }
    const choices = selected.map((row) => ({ index: row.index, target: row.target, website: row.target === 'new' ? row.website.trim() : '',
      replace: replacing.some((l) => l.id === row.target) }));
    const reply = await call('qr_sheet_add', result.token, choices);
    busy = false;
    if (!reply.ok) { status = reply.error.message; return; }
    const skipped = reply.skipped.length ? ` ${t('scanSheet.skipped', { list: reply.skipped.map(skippedText).join('; ') })}` : '';
    done = reply.message + skipped;
    status = '';
    result = null;
    rows = [];
    ondone?.();
  }

  async function close() {
    if (result) { const old = result.token; result = null; await call('qr_sheet_discard', old); }
    onclose();
  }

  // Leaving the sheet any way (another sheet, a page, lock) drops the scanned accounts in Python.
  $effect(() => () => { if (result) call('qr_sheet_discard', result.token); });

  function keys(event) {
    if (event.key === 'Escape' && !scanning) { event.preventDefault(); close(); }
  }
</script>

<div class="sheet glass" class:dragging role="dialog" aria-label={t('scanSheet.title')} tabindex="-1"
  onkeydown={keys} onpaste={pasted} ondragover={dragover} ondragleave={() => (dragging = false)} ondrop={dropped}>
  <header><h2>{t('scanSheet.title')}</h2><button class="close" aria-label={t('common.close')} onclick={close}>✕</button></header>
  <p class="lead">{t('scanSheet.lead')}</p>

  {#if !result || result.kind === 'key' || !result.complete}
    <div class="group ways">
      <div class="way">
        <span class="k">{t('scanSheet.pasteScreenshot')}</span>
        <span class="v">{t('scanSheet.pasteScreenshotHelp')}</span>
      </div>
      <label class="way pickfile">
        <span class="k">{t('scanSheet.chooseImage')}</span>
        <span class="v">{t('scanSheet.chooseImageHelp')}</span>
        <input type="file" accept="image/png,image/jpeg,image/bmp" aria-label={t('scanSheet.chooseImage')} onchange={chosen} disabled={!!scanning} />
      </label>
      <div class="way">
        <span class="k">{t('scanSheet.webcam')}</span>
        <span class="v">{t('scanSheet.webcamHelp')}</span>
        <button class="text-btn" onclick={() => scan('camera')} disabled={!!scanning}>{t('scanSheet.useWebcam')}</button>
      </div>
    </div>
  {/if}

  {#if status}<p class="hint" role="status">{status}</p>{/if}
  {#if done}<p class="done" role="status">{done}</p>{/if}

  {#if result?.kind === 'key'}
    {@const account = result.accounts[0]}
    <div class="section-label">{t('scanSheet.found')}</div>
    <div class="group">
      <div class="field"><span class="account"><strong>{name(account)}</strong>{account.label && account.issuer ? ` · ${account.label}` : ''}</span></div>
      {#if account.already}<p class="hint">{t('scanSheet.alreadyIn', { where: account.already })}</p>{/if}
      {#if account.matches.length}
        <fieldset>
          <legend>{t('scanSheet.addItTo')}</legend>
          {#each account.matches as login (login.id)}
            <label class="choice"><input type="radio" name="target" value={login.id} bind:group={pick} />
              {loginText(login)}</label>
          {/each}
          <label class="choice"><input type="radio" name="target" value="new" bind:group={pick} /> {t('scanSheet.newLogin')}</label>
        </fieldset>
      {:else}
        <p class="hint">{t('scanSheet.noMatch', { name: name(account) })}</p>
      {/if}
    </div>
    <footer>
      <Button label={t('common.cancel')} onclick={close} />
      <Button label={t('scanSheet.openInEditor')} variant="primary" busy={busy} busyLabel={t('scanSheet.opening')} onclick={openEditor} />
    </footer>
  {:else if result?.kind === 'export'}
    <div class="section-label">{t('scanSheet.accountsInExport')}</div>
    <div class="group list">
      {#each result.accounts as account, i (account.index)}
        {@const row = rows[i]}
        <div class="acc">
          <label class="tick"><input type="checkbox" bind:checked={row.checked} />
            <span class="account"><strong>{name(account)}</strong>{account.label && account.issuer ? ` · ${account.label}` : ''}</span></label>
          {#if account.already}<span class="muted small">{t('scanSheet.alreadyInShort', { where: account.already })}</span>{/if}
          {#if row.checked}
            <div class="opts">
              <select aria-label={t('scanSheet.destinationFor', { name: name(account) })} bind:value={row.target}>
                <option value="new">{t('scanSheet.newLogin')}</option>
                {#if account.matches.length}<optgroup label={t('scanSheet.addToExisting')}>
                  {#each account.matches as login (login.id)}<option value={login.id}>{t('scanSheet.addTo', { login: loginText(login) })}</option>{/each}
                </optgroup>{/if}
              </select>
              {#if row.target === 'new'}
                <input class="site" aria-label={t('scanSheet.websiteFor', { name: name(account) })} placeholder={t('scanSheet.websitePlaceholder')} bind:value={row.website} />
                {#if row.suggestion && !row.website}
                  <button class="text-btn suggest" onclick={() => (row.website = row.suggestion)}>{t('scanSheet.suggest', { site: row.suggestion })}</button>
                {/if}
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
    {#if result.skipped.length}<p class="hint">{t('scanSheet.notImported', { list: result.skipped.map(skippedText).join('; ') })}</p>{/if}
    <p class="hint">{t('scanSheet.exportHint')}</p>
    <footer>
      <Button label={t('common.cancel')} onclick={close} />
      <Button label={t('scanSheet.addAccounts', { count: selected.length, number: formatNumber(selected.length) })} variant="primary" busy={busy} busyLabel={t('scanSheet.adding')}
        disabled={!ready} onclick={add} />
    </footer>
  {/if}
</div>
{#if scanning === 'camera'}<QrCameraView />{/if}

<style>
  .sheet {
    position: absolute; inset: 10px; z-index: 30;
    border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 86%, transparent); display: flex; flex-direction: column; gap: 6px;
  }
  .sheet.dragging { outline: 2px dashed var(--link); outline-offset: -6px; }
  header { display: flex; align-items: center; justify-content: space-between; }
  h2 { margin: 0; font: 600 17px var(--font-display); }
  .close { background: none; border: none; cursor: pointer; color: var(--text-muted); }
  .lead { margin: 0 0 6px; color: var(--text-muted); font-size: 12.5px; }
  .way, .field { display: flex; align-items: center; gap: 10px; padding: 9px 14px; min-height: 42px; flex-wrap: wrap; }
  .way + .way { border-top: 1px solid var(--separator); }
  .k { width: 130px; flex-shrink: 0; font-weight: 600; }
  .v { flex: 1; min-width: 160px; color: var(--text-muted); font-size: 12.5px; }
  .pickfile { cursor: pointer; }
  .pickfile input { position: absolute; width: 1px; height: 1px; opacity: 0; }
  .pickfile:focus-within { outline: 2px solid var(--link); outline-offset: -2px; border-radius: 10px; }
  .text-btn { background: none; border: none; color: var(--link); cursor: pointer; }
  .text-btn:disabled { color: var(--text-faint); cursor: default; }
  fieldset { border: none; margin: 0; padding: 4px 14px 10px; display: grid; gap: 6px; }
  legend { color: var(--text-muted); font-size: 12.5px; padding: 0 0 4px; }
  .choice, .tick { display: flex; align-items: center; gap: 8px; cursor: pointer; }
  .acc { padding: 8px 14px; display: grid; gap: 6px; }
  .acc + .acc { border-top: 1px solid var(--separator); }
  .opts { display: flex; gap: 8px; padding-left: 24px; flex-wrap: wrap; }
  .site { flex: 1; min-width: 140px; background: var(--group); border: 1px solid var(--glass-border); border-radius: 6px; padding: 3px 6px; user-select: text; }
  select { background: var(--group); border: 1px solid var(--glass-border); border-radius: 6px; padding: 3px 6px; }
  .muted { color: var(--text-muted); }
  .small { font-size: 12px; padding-left: 24px; }
  .hint { margin: 0; padding: 2px 4px; color: var(--text-muted); font-size: 12px; }
  .done { margin: 0; padding: 8px 12px; border-radius: 10px; background: var(--group); }
  footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 10px; }
</style>
