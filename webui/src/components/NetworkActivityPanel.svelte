<script>
  /** Security center: Network activity, every outbound connection the app made (src/localvault/net_ledger.py). */
  import { call } from '../lib/api.js';
  import { t, formatDate } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';

  let { onroute, active = true } = $props();
  let data = $state(null);

  async function load() {
    const r = await call('network_activity');
    if (r.ok) data = r;
  }
  // Reloads each time the Security center is shown again (pages stay mounted under Password health).
  $effect(() => { if (active) load(); });

  const PURPOSES = ['update_check', 'revocation_list', 'breach_range', 'website_icon', 'lan_sync'];
  const purpose = (id) => (PURPOSES.includes(id) ? t(`securityPage.network.purpose.${id}`) : id);
  function result(value) {
    if (value === 'ok' || value === 'timeout') return t(`securityPage.network.result.${value}`);
    if (/^http_\d{3}$/.test(value ?? '')) return t('securityPage.network.result.http', { code: value.slice(5) });
    return t('securityPage.network.result.failed');
  }
  const host = (entry) => (entry.purpose === 'lan_sync' ? t('securityPage.network.localNetwork') : entry.host);
  function when(at) {
    const date = new Date(at);
    return Number.isNaN(date.getTime()) ? at : formatDate(date, { dateStyle: 'medium', timeStyle: 'short' });
  }
</script>

<div class="section-label">{t('securityPage.network.section')}</div>
<div class="group">
  <div class="row">
    <div class="text">
      <div class="meta">{t('securityPage.network.intro')}</div>
      <div class="meta">{t('securityPage.network.switches')}</div>
    </div>
    <Button label={t('securityPage.network.openPrivacy')} onclick={() => onroute?.('settings', { section: 'privacy' })} />
    <Button label={t('privacy.title')} onclick={() => onroute?.('privacy-proof')} />
  </div>
  {#if data}
    {#each data.entries as entry, index (index)}
      <div class="row entry" data-testid="network-entry">
        <span class="when meta">{when(entry.at)}</span>
        <span class="what">{purpose(entry.purpose)}{entry.count > 1 ? ` ×${entry.count}` : ''}</span>
        <span class="host">{host(entry)}</span>
        <span class="meta {entry.result === 'ok' ? '' : 'warning'}">{result(entry.result)}</span>
      </div>
    {/each}
    {#each data.earlier as earlier (earlier.purpose)}
      <div class="row"><span class="meta">{t('securityPage.network.earlier', { purpose: purpose(earlier.purpose), count: earlier.count })}</span></div>
    {/each}
    {#if !data.entries.length && !data.earlier.length}
      <div class="row"><span class="meta">{t('securityPage.network.empty')}</span></div>
    {/if}
  {/if}
</div>

<style>
  .section-label { margin: 14px 0 6px; font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; overflow-wrap: anywhere; }
  .meta { color: var(--text-muted); font-size: 12.5px; }
  .meta.warning { color: var(--warning, #c58a00); }
  .entry { font-size: 13px; }
  .when { flex: 0 0 160px; }
  .what { flex: 0 0 170px; }
  .host { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
