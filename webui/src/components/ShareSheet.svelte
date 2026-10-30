<script>
  /** Share one item: confirm with the master password, then save a .lgkshare file or show a QR code. The six-word
   * code is shown here only; the other person types it. */
  import { call } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { item, onclose } = $props();
  let pending = $state(null); // {handle, code, title, size, qr, qr_limit, expires_hours}
  let qr = $state(null);
  let error = $state('');
  let busy = $state(false);

  $effect(() => () => { pending = null; qr = null; call('share_cancel'); });

  async function start() {
    busy = true; error = '';
    const r = await call('share_start', item);
    busy = false;
    if (r.ok) { pending = r; qr = null; } else if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function saveFile() {
    error = '';
    const r = await call('share_save_file', pending.handle);
    if (r.ok) toast(r.status); else if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function showQr() {
    error = '';
    const r = await call('share_qr', pending.handle);
    if (r.ok) qr = r.image; else error = r.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('shareSheet.title')}>
  <header>
    <h2>{pending?.title ? t('shareSheet.titleNamed', { title: pending.title }) : t('shareSheet.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  <p class="muted">{t('shareSheet.intro')}</p>
  {#if !pending}
    <footer><Button label={t('common.cancel')} onclick={onclose} />
      <Button label={t('shareSheet.create')} variant="primary" {busy} busyLabel={t('shareSheet.encrypting')} onclick={start} /></footer>
  {:else}
    <div class="group code" aria-label={t('shareSheet.codeBox')}>
      <span class="label">{t('shareSheet.codeInstruction')}</span>
      <strong class="words">{pending.code}</strong>
    </div>
    <div class="choices">
      <Button label={t('shareSheet.saveAsFile')} variant="primary" onclick={saveFile} />
      {#if pending.qr}
        <Button label={t('shareSheet.showQr')} onclick={showQr} />
      {:else}
        <span class="muted">{t('shareSheet.tooLarge', { limit: formatNumber(pending.qr_limit) })}</span>
      {/if}
    </div>
    {#if qr}
      <figure class="qr"><img src={qr} alt={t('shareSheet.qrAlt')} />
        <figcaption class="muted">{t('shareSheet.qrCaption')}</figcaption></figure>
    {/if}
    <p class="muted" role="status">{t('shareSheet.sendNote', { count: pending.expires_hours, number: formatNumber(pending.expires_hours) })}</p>
    <footer><Button label={t('common.done')} onclick={onclose} /></footer>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 10px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .code { padding: 12px 14px; display: grid; gap: 6px; }
  .label { color: var(--text-muted); font-size: 12.5px; }
  .words { font: 600 20px var(--font-display); letter-spacing: 0.02em; user-select: text; }
  .choices { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .qr { margin: 0; display: grid; justify-items: center; gap: 6px; }
  .qr img { background: #fff; padding: 8px; border-radius: 8px; image-rendering: pixelated; max-width: 100%; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
