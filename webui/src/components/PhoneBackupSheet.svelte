<script>
  /** Restore items from an Android or iPhone backup file: choose, preview, then restore explicitly. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let file = $state(null);
  let pw = $state('');
  let token = $state(null);
  let lines = $state([]);
  let status = $state('');
  let error = $state('');
  let busy = $state(''); // '' | 'preview' | 'restore'

  $effect(() => () => { pw = ''; call('phone_backup_cancel'); });

  const heading = $derived(file ? `${file.platform === 'ios' ? 'iPhone' : 'Android'} backup from ${file.created}` : 'No backup file chosen');

  async function choose() {
    if (busy) return;
    const r = await call('phone_backup_choose');
    if (r.ok) { file = r; token = null; lines = []; status = ''; error = ''; pw = ''; } else if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function doPreview() {
    if (busy) return;
    busy = 'preview'; error = ''; token = null;
    const r = await call('phone_backup_preview', file?.handle ?? '', pw);
    busy = '';
    if (r.ok) { token = r.token; lines = r.lines; status = r.status; return; }
    lines = []; status = ''; pw = ''; error = r.error.message;
  }

  async function restore() {
    if (busy || !token) return;
    busy = 'restore'; error = '';
    const t = token;
    token = null;
    pw = ''; // never kept after a restore attempt, whatever the outcome
    const r = await call('phone_backup_commit', t, file?.handle ?? '');
    busy = '';
    if (!r.ok) {
      lines = [];
      if (r.error.code === 'cancelled') status = r.error.message; else { status = ''; error = r.error.message; }
      return;
    }
    lines = r.lines; status = r.status;
    toast(r.status);
    if (r.changed) onclose?.();
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Restore phone backup">
  <header>
    <h2>Restore phone backup</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  <p class="muted">Bring back items from an Android or iPhone backup file. Nothing changes until you press Restore.</p>
  <div class="pathrow">
    <span class="path">{heading}</span>
    <Button label="Choose file…" disabled={!!busy} onclick={choose} />
  </div>
  <div class="group">
    <Field label="Backup password" type="password" bind:value={pw} oninput={() => { token = null; }} disabled={!!busy} autocomplete="off" />
  </div>
  {#if lines.length}<pre class="group summary" aria-label="Preview">{lines.join('\n')}</pre>{/if}
  {#if status}<p class="muted" role="status">{status}</p>{/if}
  {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
  <footer>
    <Button label="Cancel" onclick={onclose} />
    <Button label="Preview" busy={busy === 'preview'} busyLabel="Checking…" disabled={!file || !pw || !!busy} onclick={doPreview} />
    <Button label="Restore" variant="primary" busy={busy === 'restore'} busyLabel="Restoring…" disabled={!token || !!busy} onclick={restore} />
  </footer>
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .pathrow { display: flex; gap: 8px; align-items: center; }
  .path { flex: 1; font-size: 12.5px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .summary { padding: 10px 12px; font: 12px ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
