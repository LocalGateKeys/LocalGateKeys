<script>
  /** "All" plus the attention / no-2FA / expiring chips that have items, and "Setup 3 of 5" while setup is unfinished. */
  import { formatNumber, t } from '../lib/i18n.svelte.js';

  let { counts = {}, active = null, onselect, setup = null, onsetup = undefined, onsetuphide = undefined } = $props();
  const LABELS = { attention: 'chips.attention', no2fa: 'chips.no2fa', expiring: 'chips.expiring' };
</script>

<div class="chips" role="group" aria-label={t('chips.quickFilters')}>
  <button class:on={!active} onclick={() => onselect(null)}>{t('chips.all')}</button>
  {#each Object.keys(LABELS) as key (key)}
    {#if counts[key] > 0}
      <button class:on={active === key} onclick={() => onselect(key)}>{t(LABELS[key])} · {formatNumber(counts[key])}</button>
    {/if}
  {/each}
  {#if setup}
    <button class="setup" title={t('home.finishSetupProgress', { progress: setup })} onclick={() => onsetup?.()}>{t('chips.setup', { progress: setup })}</button>
    {#if onsetuphide}<button class="hide" aria-label={t('home.hide')} title={t('home.hide')} onclick={onsetuphide}>✕</button>{/if}
  {/if}
</div>

<style>
  .chips { display: flex; gap: 6px; padding: 2px 14px 8px; flex-wrap: wrap; }
  button {
    height: 26px; padding: 0 12px; border-radius: 13px; cursor: pointer;
    background: var(--glass); border: 1px solid var(--glass-border); color: var(--text-muted); font-size: 12.5px;
  }
  button.setup { color: var(--link); }
  button.hide { width: 26px; padding: 0; margin-left: -4px; }
  button.on { background: var(--text); color: var(--wash-base-opaque); border-color: transparent; }
</style>
