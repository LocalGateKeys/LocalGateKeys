<script>
  /** Overview cards above the list: password health, coming up, backup. */
  import { formatNumber, t } from '../lib/i18n.svelte.js';

  let { overview = null, ongenerator } = $props();

  function ago(seconds) {
    if (seconds < 3600) return t('overview.withinHour');
    if (seconds < 86400) {
      const h = Math.floor(seconds / 3600);
      return t('overview.hoursAgo', { count: h, number: formatNumber(h) });
    }
    const d = Math.floor(seconds / 86400);
    return t('overview.daysAgo', { count: d, number: formatNumber(d) });
  }
</script>

{#if overview}
  <div class="cards">
    <div class="card group">
      <div class="title">{t('overview.health')}</div>
      {#if overview.health?.score !== null && overview.health}
        <div class="big">{overview.health.score}<span class="of">{t('overview.scoreOf', { label: overview.health.label })}</span></div>
        <div class="pills"><span>{t('overview.weak', { number: formatNumber(overview.health.weak) })}</span><span>{t('overview.reused', { number: formatNumber(overview.health.reused) })}</span><span>{t('overview.no2fa', { number: formatNumber(overview.health.no_2fa) })}</span></div>
      {:else}
        <div class="muted">{overview.health?.label ?? t('overview.noLogins')}</div>
      {/if}
    </div>
    <div class="card group">
      <div class="title">{t('overview.comingUp')}</div>
      {#each overview.reminders as line (line.date + line.label)}
        <div class="line"><span class="date">{line.date}</span>{line.label}<span class="meta" class:overdue={line.overdue}>{line.meta}</span></div>
      {:else}
        <div class="muted">{t('overview.nothingComingUp')}</div>
      {/each}
    </div>
    <div class="card group">
      <div class="title">{t('overview.backup')}</div>
      {#if overview.backup?.last_at}
        <div class="pill" class:stale={overview.backup.stale}>{t('overview.lastBackup', { when: ago(Date.now() / 1000 - overview.backup.last_at) })}</div>
      {:else}
        <div class="pill stale">{t('overview.noBackup')}</div>
      {/if}
      {#if overview.backup?.warning}<div class="warn">{overview.backup.warning}</div>{/if}
    </div>
    <div class="card group">
      <div class="title">{t('overview.generator')}</div>
      <button class="link" onclick={ongenerator}>{t('overview.openGenerator')}</button>
    </div>
  </div>
{/if}

<style>
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; padding: 4px 14px 10px; }
  .card { padding: 12px 14px; min-height: 92px; display: grid; align-content: start; gap: 6px; }
  .title { font-weight: 600; }
  .big { font: 600 26px var(--font-display); }
  .of { font: 400 13px var(--font-ui); color: var(--text-muted); }
  .pills { display: flex; gap: 6px; flex-wrap: wrap; font-size: 12px; }
  .pills span, .pill { padding: 2px 8px; border-radius: 9px; background: var(--glass); width: fit-content; font-size: 12px; }
  .pill.stale { color: var(--warning); }
  .warn { color: var(--danger); font-size: 12.5px; }
  .muted { color: var(--text-muted); }
  .line { display: flex; gap: 8px; font-size: 12.5px; }
  .date { color: var(--text-faint); width: 48px; }
  .meta { margin-left: auto; color: var(--text-muted); }
  .overdue { color: var(--danger); }
  .link { background: none; border: none; color: var(--link); cursor: pointer; padding: 0; text-align: left; }
</style>
