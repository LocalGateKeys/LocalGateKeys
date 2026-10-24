<script>
  /** Licence: status, paste a key or open a licence file, remove. Offline; no account. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();
  let data = $state(null);
  let key = $state('');
  let busy = $state(false);
  let error = $state('');

  async function load() {
    const result = await call('licence_view');
    if (okOrToast(result, 'Could not open Licence')) data = result;
  }
  $effect(() => { load(); });

  async function run(method, ...args) {
    if (busy) return;
    busy = true; error = '';
    const result = await call(method, ...args);
    busy = false;
    if (result.ok) { key = ''; toast(result.message); data = result; return; }
    if (result.error.code !== 'cancelled') error = result.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Licence">
  <header>
    <h2>Licence</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if data}
    <div class="group card">
      <h3 class:warn={data.warning}>{data.headline}</h3>
      {#each data.details as line (line)}<p class="muted">{line}</p>{/each}
    </div>
    <div class="section-label">Paste your licence key</div>
    <textarea aria-label="Paste your licence key" bind:value={key} placeholder="LGK1-…" spellcheck="false"></textarea>
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      {#if data.can_remove}<Button label="Remove licence" variant="danger" onclick={() => run('licence_remove')} />{/if}
      <span class="spacer"></span>
      <Button label="Open file…" onclick={() => run('licence_install_file')} />
      {#if data.purchase_url}<Button label="Buy Pro" onclick={() => call('system_open_url', data.purchase_url)} />{/if}
      <Button label="Install" variant="primary" busy={busy} busyLabel="Checking…" disabled={!key.trim()} onclick={() => run('licence_install', key)} />
    </footer>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0 0 6px; font: 600 16px var(--font-display); }
  h3.warn { color: var(--warning); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .card { padding: 14px; margin-top: 12px; }
  .muted { margin: 2px 0; color: var(--text-muted); font-size: 12.5px; }
  textarea { width: 100%; min-height: 90px; box-sizing: border-box; background: var(--group); color: var(--text); border: 1px solid var(--separator);
    border-radius: 10px; padding: 8px; font: 12px ui-monospace, monospace; user-select: text; }
  .error { color: var(--danger); }
  footer { display: flex; gap: 8px; margin-top: 10px; align-items: center; }
  .spacer { flex: 1; }
</style>
