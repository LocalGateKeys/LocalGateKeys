<script>
  /** Data from an earlier development version: import a copy or start fresh. Nothing loads until the user chooses. */
  import Button from '../components/Button.svelte';
  import { call } from '../lib/api.js';

  let { vault, onchosen } = $props();
  let busy = $state('');
  let error = $state('');

  async function choose(method) {
    if (busy) return;
    busy = method; error = '';
    const r = await call(method);
    busy = '';
    if (r.ok) { onchosen(r); return; }
    if (r.error.code === 'invalid') {
      // Already decided (a second click): show the current state instead of an error.
      const state = await call('vault_state');
      if (state.ok) { onchosen(state); return; }
    }
    error = r.error.message;
  }
</script>

<section class="legacy">
  <div class="card glass" role="dialog" aria-label={vault.legacy.title}>
    <h1>{vault.legacy.title}</h1>
    <p class="pre">{vault.legacy.text}</p>
    <p class="muted">{vault.legacy.location}</p>
    {#if error}<p class="error pre" role="alert">{error}</p>{/if}
    <div class="actions">
      <Button label="Start fresh" busy={busy === 'legacy_fresh'} busyLabel="Saving…" onclick={() => choose('legacy_fresh')} />
      <Button label="Import legacy data" variant="primary" busy={busy === 'legacy_import'} busyLabel="Importing…" onclick={() => choose('legacy_import')} />
    </div>
  </div>
</section>

<style>
  .legacy { height: 100%; display: grid; place-items: center; padding: 24px; }
  .card { width: min(560px, 100%); border-radius: var(--radius-card); padding: 26px 24px; display: grid; gap: 10px; }
  h1 { margin: 0; font: 600 20px var(--font-display); }
  .pre { white-space: pre-line; margin: 0; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; word-break: break-all; }
  .error { color: var(--danger); margin: 0; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 6px; }
</style>
