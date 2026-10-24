<script>
  /** Security center: score, what to fix first, unlock / backup / moving data / privacy panels. */
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, onroute } = $props();
  let data = $state(null);

  async function load() {
    const result = await call('security_center');
    if (okOrToast(result, 'Could not open the Security center')) data = result;
  }
  $effect(() => { load(); });

  async function run(action) {
    if (action.route === 'set') {
      const result = await call('security_set', action.params.key, action.params.value);
      if (okOrToast(result, 'Not saved')) toast(result.message);
      load();
      return;
    }
    onroute(action.route, action.params ?? {});
  }

  async function emergency() {
    okOrToast(await call('lock_emergency'), 'Not locked');
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Security center">
  <header>
    <h2>Security center</h2>
    <Button label="Check all for breaches" onclick={() => onroute('health', { scan_all: true })} />
    <Button label="Emergency lock · Ctrl+Alt+L" variant="danger" onclick={emergency} />
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if data}
    <div class="body">
      <section class="score group">
        <div class="ring" aria-label={`Score ${data.score ?? 'not available'}`}>{data.score ?? '–'}</div>
        <div><div class="label">{data.label}</div><p class="headline">{data.headline}</p></div>
      </section>
      <div class="section-label">Fix these first</div>
      {#if data.issues.length}
        <div class="group">
          {#each data.issues as issue (issue.key)}
            <div class="row">
              <span class="dot {issue.tone}" aria-hidden="true"></span>
              <div class="text"><div>{issue.count} · {issue.title}</div><div class="meta">{issue.description}</div></div>
              <Button label={issue.action.label} onclick={() => run(issue.action)} />
            </div>
          {/each}
        </div>
      {:else}
        <p class="meta">Nothing to fix right now.</p>
      {/if}
      {#each data.panels as panel (panel.title)}
        <div class="section-label">{panel.title}</div>
        <div class="group">
          {#each panel.rows as row (row.label)}
            <div class="row">
              <div class="text"><div>{row.label}</div><div class="meta {row.meta_tone}">{row.meta}</div></div>
              <Button label={row.action.label} onclick={() => run(row.action)} />
            </div>
          {/each}
        </div>
      {/each}
      <p class="foot">{data.footnote}</p>
    </div>
  {/if}
</div>

<style>
  .sheet {
    position: absolute; inset: 10px; z-index: 30; border-radius: 18px; padding: 16px 18px;
    display: flex; flex-direction: column; background: color-mix(in srgb, var(--wash-base-opaque) 90%, transparent);
  }
  header { display: flex; align-items: center; gap: 8px; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .body { overflow-y: auto; flex: 1; min-height: 0; padding-top: 10px; }
  .score { display: flex; gap: 16px; align-items: center; padding: 14px; }
  .ring { width: 64px; height: 64px; border-radius: 50%; border: 5px solid var(--accent); display: grid; place-items: center; font: 600 20px var(--font-display); }
  .label { font-weight: 600; }
  .headline { margin: 4px 0 0; color: var(--text-muted); }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; }
  .meta { color: var(--text-muted); font-size: 12.5px; }
  .meta.warning { color: var(--warning, #c58a00); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-faint); }
  .dot.danger { background: var(--danger); }
  .dot.warning { background: #e0a100; }
  .dot.accent { background: var(--accent); }
  .foot { color: var(--text-faint); font-size: 12px; margin-top: 14px; }
</style>
