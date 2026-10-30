<script>
  /** Devices & connections: the browser extension bridge status, repair, export report. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();
  let data = $state(null);
  let details = $state(false);

  async function load() {
    const result = await call('connections_view');
    if (okOrToast(result, t('connectionsPage.openFailed'))) data = result;
  }
  $effect(() => { load(); });

  async function act(method) {
    const result = await call(method);
    if (result.ok) { toast(result.title ?? result.message, result.title ? result.message : ''); load(); }
    else if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error');
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('connectionsPage.title')}>
  <header>
    <h2>{t('connectionsPage.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  <p class="muted">{t('connectionsPage.intro')}</p>
  {#if data}
    <div class="group card">
      <h3>{data.headline}</h3>
      <p class="muted">{data.summary}</p>
      <p class="status {data.tone}">● {data.status}</p>
    </div>
    <div class="section-label">{t('connectionsPage.bridge')}</div>
    <div class="group">
      {#each data.browsers as b (b.browser)}
        <div class="row"><span>{b.browser}</span><span class:ok={b.ok} class="state">{b.state}</span></div>
      {:else}
        <p class="row muted">{data.empty}</p>
      {/each}
    </div>
    <footer>
      <Button label={t('connectionsPage.refresh')} onclick={load} />
      {#if data.can_repair}<Button label={t('connectionsPage.repair')} variant="primary" onclick={() => act('connections_repair')} />{/if}
      <Button label={t('connectionsPage.export')} onclick={() => act('connections_export')} />
      <Button label={details ? t('connectionsPage.hideDetails') : t('connectionsPage.showDetails')} onclick={() => (details = !details)} />
    </footer>
    {#if details}<pre class="group details">{data.details}</pre>{/if}
    <p class="muted">{data.footer}</p>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0 0 4px; font: 600 16px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; }
  .card { padding: 14px; }
  .status { margin: 6px 0 0; font-weight: 600; }
  .status.success { color: var(--success); }
  .status.warning { color: var(--warning); }
  .row { display: flex; justify-content: space-between; padding: 10px 14px; margin: 0; }
  .row + .row { border-top: 1px solid var(--separator); }
  .state { color: var(--warning); font-weight: 600; font-size: 12.5px; }
  .state.ok { color: var(--success); }
  footer { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
  .details { padding: 12px; font: 11.5px ui-monospace, monospace; white-space: pre-wrap; user-select: text; max-height: 260px; overflow: auto; }
</style>
