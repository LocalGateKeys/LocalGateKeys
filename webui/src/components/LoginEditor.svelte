<script>
  /** Website and desktop login editor. The draft lives in Python; every change is sent with login_update. */
  import { call } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';
  import { readPicture } from '../lib/picture.js';
  import Button from './Button.svelte';
  import QrCameraView from './QrCameraView.svelte';

  // draft: an editor the Scan sheet already opened in Python (with a scanned 2FA key applied).
  let { ref = null, draft = null, newPassword = false, onclose, onbinding = undefined } = $props();

  let view = $state(null);
  let busy = $state(false);
  let password = $state('');
  let totp = $state('');
  let changingPassword = $state(false);
  let banner = $state('');

  $effect(() => {
    (async () => {
      const result = draft ?? (ref ? await call('login_open', ref) : await call('login_new'));
      if (!okOrToast(result, t('loginEditor.couldNotOpen'))) { onclose(null); return; }
      view = result;
      if (newPassword) {
        // From Password health: a new password is ready; the user still changes it on the website.
        await regenerate('Random');
        banner = t('loginEditor.newPasswordReady');
      }
    })();
  });

  const heading = $derived(view?.is_new ? t('loginEditor.newWebsite') : view?.kind === 'desktop' ? t('loginEditor.editDesktop') : t('loginEditor.editLogin'));
  const errorFor = (field) => view?.errors?.find((e) => e.field === field || e.field.startsWith(`${field}[`))?.message;
  let shownErrors = $state(false);

  // Replies can arrive out of order (pywebview runs calls on worker threads):
  // only the newest one may replace the view, or typed characters would vanish.
  let updateSeq = 0;
  async function change(changes) {
    const mine = ++updateSeq;
    const result = await call('login_update', view.draft_id, changes);
    if (result.ok && mine === updateSeq) view = result;
  }

  function setUrl(index, url) {
    const urls = view.urls.map((row, i) => (i === index ? { ...row, url } : row));
    change({ urls });
  }

  async function regenerate(chip) {
    const result = await call('login_regenerate', view.draft_id, chip);
    if (result.ok) { view = result; changingPassword = false; password = ''; }
  }

  async function save() {
    if (busy) return;
    busy = true;
    if (changingPassword && password) await change({ password });
    if (totp.trim()) await change({ totp_text: totp });
    const result = await call('login_save', view.draft_id);
    busy = false;
    password = '';
    totp = '';
    if (result.ok) { onclose(result.ref); return; }
    shownErrors = true;
    if (result.view) view = result.view;
    banner = result.error.message;
  }

  // 2FA from a QR code: a snip the person pastes (the app never captures the screen), or the camera.
  let ga = $state(null);
  let gaIndex = $state(0);
  let gaStatus = $state('');
  let scanning = $state(null); // 'image' | 'camera'

  function showAccounts(result) {
    ga = result.accounts.length ? result : null;
    gaIndex = result.best ?? 0;
    const more = result.batch.size > 1;
    // One sentence per part, each its own catalog message, joined with spaces.
    const parts = [];
    if (more) parts.push(t('loginEditor.batchPart', { index: formatNumber(result.batch.index + 1), size: formatNumber(result.batch.size) }));
    parts.push(result.accounts.length
      ? t('loginEditor.accountsFound', { count: result.accounts.length, number: formatNumber(result.accounts.length) })
      : t('loginEditor.noAccounts'));
    if (result.accounts.length) parts.push(t(result.best !== null ? 'loginEditor.bestMatch' : 'loginEditor.chooseMatch'));
    if (more) parts.push(t('loginEditor.nextCode'));
    if (result.skipped.length) parts.push(t('loginEditor.skipped', { list: result.skipped.map((s) => t('loginEditor.skippedItem', { label: s.label, reason: s.reason })).join(', ') }));
    gaStatus = parts.join(' ');
  }

  // A pasted Google Authenticator export link still works, from the Setup key field.
  async function readExport(text) {
    const result = await call('ga_parse', text, view.label || view.label_hint || '', view.urls?.[0]?.url ?? '');
    if (!result.ok) { gaStatus = result.error.message; ga = null; return; }
    showAccounts(result);
  }

  function keyChanged() {
    if (!totp.trim().toLowerCase().startsWith('otpauth-migration:')) return;
    const text = totp;
    totp = '';
    readExport(text);
  }

  async function scan(kind, image = null) {
    if (scanning) return;
    scanning = kind;
    gaStatus = kind === 'image' ? t('loginEditor.reading') : '';
    const result = kind === 'image' ? await call('qr_scan_image', view.draft_id, image) : await call('qr_scan_camera', view.draft_id);
    scanning = null;
    gaStatus = '';
    if (!result.ok) { if (result.error.code !== 'cancelled') gaStatus = result.error.message; return; }
    if (result.found === 'key') {
      view = result.view;
      ga = null;
      banner = t('loginEditor.keyRead');
    } else showAccounts(result);
  }

  // Win+Shift+S then Ctrl+V anywhere in the editor: only an image paste is taken; text pastes as usual.
  function pasted(event) {
    const file = [...(event.clipboardData?.items ?? [])].find((item) => item.kind === 'file' && item.type.startsWith('image/'))?.getAsFile();
    if (!file || !view) return;
    event.preventDefault();
    const reader = new FileReader();
    reader.onload = () => scan('image', String(reader.result));
    reader.readAsDataURL(file);
  }

  // A saved picture of the QR code: chosen with the file picker or dropped on the editor (Pro only, like paste).
  async function picture(file) {
    if (!file || !view || view.totp_allowed === false) return;
    const read = await readPicture(file);
    if (read.error) { gaStatus = read.error; return; }
    scan('image', read.dataUrl);
  }

  function chosen(event) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    picture(file);
  }

  function dragover(event) {
    if ([...(event.dataTransfer?.types ?? [])].includes('Files')) event.preventDefault();
  }

  function dropped(event) {
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    event.preventDefault();
    picture(file);
  }

  async function gaUse() {
    const result = await call('ga_apply', view.draft_id, ga.token, Number(gaIndex));
    if (!result.ok) { gaStatus = result.error.message; return; }
    view = result;
    ga = null;
    gaStatus = '';
    banner = t('loginEditor.keyImported');
  }

  async function discard() {
    if (view?.dirty && !window.confirm?.(t('loginEditor.discard'))) return false;
    if (view) await call('login_close', view.draft_id);
    return true;
  }

  async function cancel() {
    if (await discard()) onclose(null);
  }

  // Desktop logins: the app binding (field mapping, fill now, sign-in button) has its own page.
  async function openBinding() {
    if (await discard()) onbinding(ref.id);
  }

  function keys(event) {
    if (event.key === 's' && event.ctrlKey) { event.preventDefault(); save(); }
    if (event.key === 'Escape') { event.preventDefault(); cancel(); }
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label={heading} tabindex="-1" onkeydown={keys} onpaste={pasted} ondragover={dragover} ondrop={dropped}>
  {#if view}
    <header>
      <h2>{heading}</h2>
      <span class="state">{banner || (view.dirty ? t('loginEditor.unsaved') : t('loginEditor.notSaved'))}</span>
    </header>
    <div class="group">
      <label class="field"><span class="k">{t('loginEditor.title')}</span>
        <input value={view.label} placeholder={view.label_hint} oninput={(e) => change({ label: e.currentTarget.value })} />
      </label>
      {#each view.urls as row, i (i)}
        <label class="field" class:bad={shownErrors && errorFor(`urls[${i}]`)}><span class="k">{i === 0 ? t('loginEditor.website') : ''}</span>
          <input value={row.url} placeholder={t('loginEditor.websitePlaceholder')} oninput={(e) => setUrl(i, e.currentTarget.value)} />
        </label>
        {#if shownErrors && errorFor(`urls[${i}]`)}<p class="error">{errorFor(`urls[${i}]`)}</p>{/if}
      {/each}
      {#if shownErrors && view.errors.find((e) => e.field === 'urls')}<p class="error">{view.errors.find((e) => e.field === 'urls').message}</p>{/if}
      {#if view.kind === 'desktop'}
        <div class="field"><span class="k">{t('loginEditor.app')}</span><span class="v path">{view.app_path}</span>
          {#if onbinding && ref}<button class="text-btn" onclick={openBinding}>{t('loginEditor.appBinding')}</button>{/if}
        </div>
      {/if}
      <label class="field"><span class="k">{t('loginEditor.username')}</span>
        <input value={view.username} placeholder={t('loginEditor.usernamePlaceholder')} autocomplete="off" oninput={(e) => change({ username: e.currentTarget.value })} />
      </label>
      <div class="field">
        <span class="k">{t('loginEditor.password')}</span>
        {#if changingPassword}
          <input type="password" bind:value={password} aria-label={t('loginEditor.newPassword')} autocomplete="new-password" />
        {:else}
          <span class="v">{view.password_set ? (view.is_new ? t('loginEditor.generated') : t('loginEditor.newPasswordSet')) : t('loginEditor.unchanged')}</span>
          <button class="text-btn" onclick={() => (changingPassword = true)}>{t('loginEditor.change')}</button>
        {/if}
      </div>
      <div class="field chips">
        <span class="k"></span>
        {#each [['Passphrase', 'loginEditor.chipPassphrase'], ['Random', 'loginEditor.chipRandom'], ['PIN', 'loginEditor.chipPin']] as [chip, chipLabel] (chip)}
          <button class="chip" onclick={() => regenerate(chip)}>{t(chipLabel)}</button>
        {/each}
        {#if view.strength}<span class="strength">{view.strength.label} · {view.strength.reuse_text}</span>{/if}
      </div>
      {#if shownErrors && errorFor('password')}<p class="error">{errorFor('password')}</p>{/if}
    </div>

    <div class="section-label">{t('loginEditor.twoFactor')}</div>
    <div class="group">
      {#if view.totp_allowed === false}
        <div class="field">
          <span class="k">{t('loginEditor.setupKey')}</span>
          <span class="muted">{view.totp_configured ? t('loginEditor.configured') : t('loginEditor.notSet')}</span>
          {#if view.totp_configured}<button class="text-btn" onclick={() => change({ totp_remove: true })}>{t('loginEditor.remove')}</button>{/if}
        </div>
        <p class="muted small">{t('loginEditor.needsPro')}</p>
      {:else}
      <div class="field">
        <span class="k">{t('loginEditor.setupKey')}</span>
        <input type="password" bind:value={totp} aria-label={t('loginEditor.setupKey')} autocomplete="off" onchange={keyChanged}
          placeholder={view.totp_configured ? t('loginEditor.keyPlaceholderConfigured') : t('loginEditor.keyPlaceholder')} />
        {#if view.totp_configured}<button class="text-btn" onclick={() => change({ totp_remove: true })}>{t('loginEditor.remove')}</button>{/if}
      </div>
      {#if shownErrors && errorFor('totp')}<p class="error">{errorFor('totp')}</p>{/if}
      <div class="field scan">
        <span class="k"></span>
        <button class="text-btn" onclick={() => scan('camera')} disabled={!!scanning}>{t('loginEditor.scanCamera')}</button>
        <label class="text-btn pickfile">{t('loginEditor.chooseImage')}
          <input type="file" accept="image/png,image/jpeg,image/bmp" aria-label={t('loginEditor.chooseImage')} onchange={chosen} disabled={!!scanning} />
        </label>
      </div>
      {/if}
      {#if ga}
        <div class="field">
          <select aria-label={t('loginEditor.accountFor')} bind:value={gaIndex}>
            {#each ga.accounts as account (account.index)}<option value={account.index}>{account.issuer || t('loginEditor.noIssuer')} — {account.label}</option>{/each}
          </select>
          <button class="text-btn" onclick={gaUse}>{t('loginEditor.useFor')}</button>
        </div>
      {/if}
      {#if gaStatus}<p class="hint" role="status">{gaStatus}</p>{/if}
      <p class="hint">{t('loginEditor.qrHint')}</p>
    </div>

    <div class="section-label">{t('loginEditor.notes')}</div>
    <div class="group">
      <textarea aria-label={t('loginEditor.notes')} value={view.notes} oninput={(e) => change({ notes: e.currentTarget.value })}></textarea>
    </div>

    <footer>
      <Button label={t('common.cancel')} onclick={cancel} />
      <Button label={t('loginEditor.save')} variant="primary" busy={busy} busyLabel={t('loginEditor.saving')} onclick={save} />
    </footer>
  {/if}
</div>
{#if scanning === 'camera'}<QrCameraView />{/if}

<style>
  .sheet {
    position: absolute; inset: 10px 10px 10px auto; width: min(520px, calc(100% - 20px)); z-index: 30;
    border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 86%, transparent); display: flex; flex-direction: column; gap: 4px;
  }
  header { display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px; }
  h2 { margin: 0; font: 600 17px var(--font-display); }
  .state { color: var(--text-muted); font-size: 12.5px; }
  .field { display: flex; align-items: center; gap: 10px; padding: 9px 14px; min-height: 42px; }
  .field + .field { border-top: 1px solid var(--separator); }
  .bad .k { color: var(--danger); }
  .k { width: 96px; flex-shrink: 0; color: var(--text-muted); }
  .muted { color: var(--text-muted); }
  .small { font-size: 12.5px; margin: 4px 0 0; }
  input, textarea { flex: 1; min-width: 0; background: none; border: none; outline: none; user-select: text; }
  input::placeholder { color: var(--text-faint); }
  textarea { width: 100%; min-height: 80px; padding: 10px 14px; resize: vertical; }
  .v { flex: 1; color: var(--text-muted); }
  .path { word-break: break-all; font-size: 12.5px; }
  .text-btn { background: none; border: none; color: var(--link); cursor: pointer; }
  .chips { gap: 6px; flex-wrap: wrap; }
  .scan { gap: 14px; }
  .pickfile { position: relative; }
  .pickfile input { position: absolute; width: 1px; height: 1px; opacity: 0; }
  .pickfile:focus-within { outline: 2px solid var(--link); outline-offset: 2px; border-radius: 4px; }
  .text-btn:disabled { color: var(--text-faint); cursor: default; }
  .chip { height: 24px; padding: 0 10px; border-radius: 12px; border: 1px solid var(--glass-border); background: var(--glass); cursor: pointer; font-size: 12px; }
  .strength { color: var(--text-muted); font-size: 12px; margin-left: 6px; }
  .error { margin: 0; padding: 0 14px 8px; color: var(--danger); font-size: 12.5px; }
  .hint { margin: 0; padding: 4px 14px 8px; color: var(--text-muted); font-size: 12px; }
  select { background: var(--group); border: 1px solid var(--glass-border); border-radius: 6px; padding: 3px 6px; flex: 1; }
  footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
</style>
