<script>
  /** Overview boxes above the list: password health, coming up (opens Reminders), backup & recovery. */
  import { formatNumber, t } from '../lib/i18n.svelte.js';

  let { overview = null, onreminders = undefined } = $props();

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
    <button type="button" class="card group open" aria-label={`${t('overview.comingUp')}: ${t('overview.openReminders')}`}
      title={t('overview.openReminders')} onclick={() => onreminders?.()}>
      <span class="title">{t('overview.comingUp')}</span>
      {#each overview.reminders as line (line.date + line.label)}
        <span class="line"><span class="date">{line.date}</span><span class="what">{line.label}</span><span class="meta" class:overdue={line.overdue}>{line.meta}</span></span>
      {:else}
        <span class="muted">{t('overview.nothingComingUp')}</span>
      {/each}
    </button>
    <div class="card group">
      <div class="title">{t('overview.backup')}</div>
      {#if overview.backup?.last_at}
        <div class="pill" class:stale={overview.backup.stale}>{t('overview.lastBackup', { when: ago(Date.now() / 1000 - overview.backup.last_at) })}</div>
      {:else}
        <div class="pill stale">{t('overview.noBackup')}</div>
      {/if}
      {#if overview.backup?.warning}<div class="warn">{overview.backup.warning}</div>{/if}
    </div>
  </div>
{/if}

<style>
  /* Three small boxes in one row; text wraps inside them, nothing is clipped at the narrowest window. */
  .cards { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; padding: 4px 14px 8px; }
  .card { padding: 8px 10px; display: grid; grid-template-columns: minmax(0, 1fr); align-content: start; gap: 4px; min-width: 0; font-size: 12px;
    overflow-wrap: anywhere; }
  button.card { border: none; color: inherit; font: inherit; font-size: 12px; text-align: left; cursor: pointer; }
  button.card:hover { filter: brightness(1.15); }
  button.card:focus-visible { outline: 2px solid var(--link); outline-offset: 1px; }
  .title { font-weight: 600; font-size: 11.5px; hyphens: auto; overflow-wrap: break-word; word-break: normal; color: var(--text-muted); }
  .big { font: 600 18px var(--font-display); }
  .of { font: 400 12px var(--font-ui); color: var(--text-muted); }
  .pills { display: flex; gap: 4px; flex-wrap: wrap; }
  .pills span, .pill { padding: 1px 7px; border-radius: 9px; background: var(--glass); width: fit-content; max-width: 100%; font-size: 11px; }
  .pill.stale { color: var(--warning); }
  .warn { color: var(--danger); font-size: 11.5px; }
  .muted { color: var(--text-muted); }
  .line { display: flex; flex-wrap: wrap; column-gap: 6px; }
  .date { color: var(--text-faint); }
  .what { min-width: 0; }
  .meta { color: var(--text-muted); }
  .overdue { color: var(--danger); }
</style>
