<script>
  /** Getting started: seven resumable stages; some open another page and are confirmed here afterwards. */
  import { call, on } from '../lib/api.js';
  import { okOrToast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, onroute } = $props();
  let view = $state(null);
  let offline = $state(true);
  let demo = $state(false);

  async function load() {
    const r = await call('onboarding_state');
    if (okOrToast(r, 'Could not open Getting started')) { view = r; offline = r.offline; }
  }
  $effect(() => {
    load();
    // A first item saved in the editor updates the status here.
    const off = on('items.changed', () => load());
    return off;
  });

  async function perform() {
    const choice = view.stage === 'welcome' ? offline : view.stage === 'demo' ? demo : null;
    // The connection test can take seconds: it runs as its own call, outside the vault lock.
    if (view.stage === 'bridge_diagnostic') await call('onboarding_test_connection');
    const r = await call('onboarding_perform', choice);
    if (!okOrToast(r)) return;
    if (r.done) { onclose(); return; }
    view = r;
    if (r.open) onroute(r.open.route, r.open.params ?? {}, load);
  }

  async function skip() {
    const r = await call('onboarding_skip');
    if (okOrToast(r)) view = r;
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Getting started">
  <header>
    <h2>{view?.title ?? 'Getting started'}</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if view}
    <p class="muted">{view.subtitle}</p>
    <p class="muted">{view.intro}</p>
    <ol class="tracker">
      {#each view.stages as s (s.key)}<li class={s.state}>{s.label}{s.state === 'done' ? ' ✓' : s.state === 'skipped' ? ' · skipped' : ''}</li>{/each}
    </ol>
    <section class="group card">
      <h3>{view.heading}</h3>
      <p>{view.purpose}</p>
      <p class="muted">{view.action}</p>
      {#if view.stage === 'welcome'}
        <label><input type="checkbox" bind:checked={offline} /> Keep strict offline mode enabled</label>
      {:else if view.stage === 'demo'}
        <label><input type="checkbox" bind:checked={demo} /> Open the safe metadata walkthrough</label>
      {/if}
      <p class="status" role="status">Status: {view.status}</p>
    </section>
    <footer>
      <Button label="Skip / do later" disabled={!view.can_skip} onclick={skip} />
      <Button label="Done" onclick={onclose} />
      <Button label={view.primary} variant="primary" onclick={perform} />
    </footer>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0; font: 600 15px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .tracker { display: flex; flex-wrap: wrap; gap: 6px; list-style: none; padding: 0; margin: 4px 0; }
  .tracker li { font-size: 12px; padding: 3px 10px; border-radius: 999px; background: var(--group); color: var(--text-muted); }
  .tracker li.current { background: var(--accent); color: #fff; }
  .tracker li.done { color: var(--success); }
  .card { padding: 14px; display: grid; gap: 6px; }
  .card p { margin: 0; }
  .status { font-weight: 600; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
