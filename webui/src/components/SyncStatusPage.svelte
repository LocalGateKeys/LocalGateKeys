<script>
  /** Sync status: this device, then each paired device with its route, last sync and warnings. */
  import { call, on } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, onsettings } = $props();
  let status = $state(null);
  let busy = $state(false);

  async function load() {
    const result = await call('sync_status');
    if (okOrToast(result, t('syncStatusPage.openFailed'))) status = result;
  }
  $effect(() => {
    load();
    const off = on('sync.status', load);
    return off;
  });

  async function syncNow() {
    busy = true;
    try { okOrToast(await call('sync_now'), t('syncStatusPage.notStarted')); await load(); } finally { busy = false; }
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('syncStatusPage.title')}>
  <header>
    <h2>{t('syncStatusPage.title')}</h2>
    <button class="close" aria-label={t('syncStatusPage.close')} onclick={onclose}>✕</button>
  </header>
  {#if status}
    <p class="summary" role="status"><span class="dot {status.colour}" aria-hidden="true"></span>{status.text}</p>
    {#if status.state === 'off'}
      <p class="muted">{t('syncStatusPage.off')}</p>
    {:else}
      <ul class="devices">
        <li>
          <div class="name">{status.this_device?.name ?? t('syncStatusPage.thisPc')} <span class="tag">{t('syncStatusPage.thisDevice')}</span></div>
          <div class="muted">{status.this_device?.last_text}</div>
        </li>
        {#each status.devices as d (d.id)}
          <li>
            <div class="name">{d.name}</div>
            <div class="muted">{d.route} · {d.last_text}</div>
            {#each d.warnings as w}<div class="warn">{w}</div>{/each}
          </li>
        {/each}
      </ul>
    {/if}
    <footer>
      <Button label={t('syncStatusPage.openSettings')} onclick={onsettings} />
      {#if status.state !== 'off'}<Button label={t('syncStatusPage.syncNow')} variant="primary" disabled={busy} onclick={syncNow} />{/if}
    </footer>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .summary { display: flex; align-items: center; gap: 8px; margin: 0; font-weight: 600; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--text-faint); }
  .dot.green { background: var(--success); }
  .dot.orange { background: var(--warning, #d98a00); }
  .dot.red { background: var(--danger); }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .devices { list-style: none; margin: 0; padding: 0; border-radius: 12px; background: var(--group); }
  .devices li { padding: 10px 14px; display: grid; gap: 2px; }
  .devices li + li { border-top: 1px solid var(--separator); }
  .name { font-weight: 600; }
  .tag { font-weight: 400; font-size: 11.5px; color: var(--text-muted); margin-left: 6px; }
  .warn { color: var(--danger); font-size: 12.5px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
