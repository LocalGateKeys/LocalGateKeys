<script>
  /** Incoming shared items: open a .lgkshare file, type the six-word code, preview, then Save to vault or Reject.
   * Closing without choosing keeps the item here until it expires. */
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { call } from '../lib/api.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, onchanged = undefined } = $props();
  let incoming = $state([]);
  let active = $state(null); // {id, sender}
  let code = $state('');
  let preview = $state(null);
  let shown = $state({});
  let error = $state('');
  let busy = $state(false);

  $effect(() => { call('share_incoming').then((r) => { if (r.ok) incoming = r.incoming; }); });
  $effect(() => () => { code = ''; preview = null; });

  function close() { active = null; code = ''; preview = null; shown = {}; error = ''; }

  async function openFile() {
    error = '';
    const r = await call('share_receive_file');
    if (!r.ok) { if (r.error.code !== 'cancelled') error = r.error.message; return; }
    incoming = r.incoming;
    pick({ id: r.id, sender: r.sender });
  }

  let pasting = $state(false);
  let pasted = $state('');

  async function received(r) {
    if (!r.ok) { error = r.error.message; return; }
    pasting = false; pasted = '';
    incoming = r.incoming;
    pick({ id: r.id, sender: r.sender });
  }

  /** A phone shows the item as a QR code: paste its text (from a scanner) or a snip of the QR (Win+Shift+S). */
  async function receivePasted() {
    error = '';
    await received(await call('share_receive_text', pasted.trim()));
  }

  function onPaste(e) {
    const file = [...(e.clipboardData?.items || [])].find((i) => i.kind === 'file' && i.type.startsWith('image/'))?.getAsFile();
    if (!file) return;
    e.preventDefault();
    const reader = new FileReader();
    reader.onload = async () => { error = ''; await received(await call('share_receive_qr_image', reader.result)); };
    reader.readAsDataURL(file);
  }

  function pick(row) { close(); active = row; }

  async function doPreview() {
    busy = true; error = '';
    const r = await call('share_preview', active.id, code);
    busy = false;
    if (r.ok) { preview = r; return; }
    error = r.error.message;
    if (['deleted', 'expired', 'already_opened', 'gone', 'not_shareable', 'unsupported'].includes(r.error.code)) {
      active = null; code = '';
      refresh();
    }
  }

  async function refresh() {
    const r = await call('share_incoming');
    if (r.ok) incoming = r.incoming;
  }

  async function save(mode) {
    busy = true; error = '';
    const r = await call('share_save', active.id, code, mode);
    busy = false;
    if (!r.ok) { error = r.error.message; return; }
    toast(r.status);
    close();
    await refresh();
    onchanged?.();
  }

  async function reject(id) {
    const r = await call('share_reject', id);
    if (r.ok) { incoming = r.incoming; toast(r.status); if (active?.id === id) close(); } else error = r.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('incomingSheet.title')}>
  <header>
    <h2>{t('incomingSheet.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  <p class="muted">{t('incomingSheet.intro')}</p>
  <div class="actions">
    <Button label={t('incomingSheet.openShared')} variant={active ? 'glass' : 'primary'} onclick={openFile} />
    <Button label={t('incomingSheet.pasteQr')} onclick={() => { pasting = !pasting; error = ''; }} />
  </div>
  {#if pasting}
    <div class="group pop" aria-label={t('incomingSheet.pasteQr')}>
      <p class="muted">{t('incomingSheet.pasteHelp')}</p>
      <textarea aria-label={t('incomingSheet.qrText')} rows="3" bind:value={pasted} onpaste={onPaste} autocomplete="off"
        spellcheck="false"></textarea>
      <footer>
        <Button label={t('common.cancel')} onclick={() => { pasting = false; pasted = ''; }} />
        <Button label={t('incomingSheet.receive')} variant="primary" disabled={!pasted.trim()} onclick={receivePasted} />
      </footer>
    </div>
  {/if}

  {#if active}
    <div class="group pop" aria-label={t('incomingSheet.sharedItem')}>
      <strong>{t('incomingSheet.sharedWithYou', { sender: active.sender || t('incomingSheet.someone') })}</strong>
      {#if !preview}
        <label class="row"><span>{t('incomingSheet.code')}</span>
          <input aria-label={t('incomingSheet.code')} bind:value={code} autocomplete="off" spellcheck="false"
            onkeydown={(e) => { if (e.key === 'Enter' && code.trim()) doPreview(); }} /></label>
        <footer>
          <Button label={t('incomingSheet.reject')} variant="danger" onclick={() => reject(active.id)} />
          <Button label={t('common.notNow')} onclick={close} />
          <Button label={t('incomingSheet.preview')} variant="primary" {busy} disabled={!code.trim()} onclick={doPreview} />
        </footer>
      {:else}
        <p class="kind">{preview.kind} · {preview.title}</p>
        {#if preview.passkey_warning}<p class="error">{t('incomingSheet.passkeyWarning')}</p>{/if}
        <div class="fields">
          {#each preview.fields as f, i (i)}
            <div class="field"><span>{f.name}</span>
              <code>{f.secret && !shown[i] ? '••••••••' : f.value}</code>
              {#if f.secret}<button class="reveal" onclick={() => (shown = { ...shown, [i]: !shown[i] })}>{shown[i] ? t('incomingSheet.hide') : t('incomingSheet.reveal')}</button>{/if}
            </div>
          {/each}
        </div>
        {#if preview.duplicate}<p class="muted">{t('incomingSheet.duplicate')}</p>{/if}
        <footer>
          <Button label={t('incomingSheet.reject')} variant="danger" onclick={() => reject(active.id)} />
          {#if preview.duplicate}
            <Button label={t('incomingSheet.replace')} {busy} onclick={() => save('replace')} />
            <Button label={t('incomingSheet.keepBoth')} variant="primary" {busy} onclick={() => save('keep')} />
          {:else}
            <Button label={t('incomingSheet.saveToVault')} variant="primary" {busy} onclick={() => save('keep')} />
          {/if}
        </footer>
      {/if}
    </div>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if incoming.length}
    <div class="group list" aria-label={t('incomingSheet.waiting')}>
      {#each incoming as row (row.id)}
        <div class="row item">
          <span class="who">{t('incomingSheet.hoursLeft', { sender: row.sender || t('incomingSheet.someone'), hours: formatNumber(row.hours_left) })}</span>
          <Button label={t('incomingSheet.open')} onclick={() => pick(row)} />
          <Button label={t('incomingSheet.reject')} onclick={() => reject(row.id)} />
        </div>
      {/each}
    </div>
  {:else if !active}
    <p class="muted" role="status">{t('incomingSheet.nothingWaiting')}</p>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 10px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  textarea { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px;
    padding: 6px; font: 12px var(--font-mono, monospace); resize: vertical; user-select: text; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .pop { padding: 12px 14px; display: grid; gap: 10px; }
  .row { display: flex; align-items: center; gap: 10px; font-size: 13px; }
  .row span { color: var(--text-muted); }
  .row input { flex: 1; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px; user-select: text; }
  .kind { margin: 0; font-weight: 600; }
  .fields { display: grid; gap: 6px; }
  .field { display: grid; grid-template-columns: 120px 1fr auto; gap: 8px; align-items: center; font-size: 13px; }
  .field span { color: var(--text-muted); }
  .field code { overflow-wrap: anywhere; user-select: text; }
  .reveal { background: none; border: none; color: var(--accent); cursor: pointer; }
  .list { padding: 6px 14px; }
  .item { padding: 6px 0; }
  .item + .item { border-top: 1px solid var(--separator); }
  .who { flex: 1; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
</style>
