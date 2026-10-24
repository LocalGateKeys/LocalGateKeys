<script>
  /** Export to a file: format, optional 2FA secrets, the classic warnings; KDBX needs its own password. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let info = $state(null);
  let fmt = $state('kdbx');
  let totp = $state(false);
  let pw = $state('');
  let pw2 = $state('');
  let error = $state('');
  let busy = $state(false);

  async function load() {
    const r = await call('export_formats', fmt, totp);
    if (okOrToast(r, 'Could not open Export')) info = r;
  }
  $effect(() => { fmt; totp; load(); });
  $effect(() => () => { pw = ''; pw2 = ''; });

  async function run() {
    if (busy) return;
    busy = true; error = '';
    const r = await call('export_run', fmt, totp, pw, pw2);
    busy = false;
    pw = ''; pw2 = '';
    if (r.ok) { toast(r.title, r.message); onclose(); return; }
    if (r.error.code !== 'cancelled') error = r.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Export">
  <header>
    <h2>Export…</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if info}
    <p class="muted">{info.intro}</p>
    <div class="group">
      <label class="row"><span>Format</span>
        <select aria-label="Format" bind:value={fmt}>{#each info.formats as f (f.key)}<option value={f.key}>{f.label}</option>{/each}</select>
      </label>
      <label class="row"><input type="checkbox" bind:checked={totp} /> Include one-time password (2FA) secrets</label>
    </div>
    {#each info.warnings as w (w)}<p class="warn">{w}</p>{/each}
    {#if fmt === 'kdbx'}
      <div class="group">
        <Field label={`KDBX password (at least ${info.min_password} characters)`} type="password" bind:value={pw} autocomplete="new-password" />
        <Field label="Repeat the KDBX password" type="password" bind:value={pw2} autocomplete="new-password" />
      </div>
    {/if}
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label="Cancel" onclick={onclose} />
      <Button label="Export" variant="primary" busy={busy} busyLabel="Exporting…" onclick={run} />
    </footer>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row span { width: 80px; color: var(--text-muted); }
  select { flex: 1; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px; }
  .warn { margin: 0; color: var(--warning); font-size: 12.5px; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
