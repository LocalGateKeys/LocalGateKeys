<script>
  /** "All" plus the attention / no-2FA / expiring chips that have items. */
  let { counts = {}, active = null, onselect } = $props();
  const LABELS = { attention: 'Needs attention', no2fa: 'No 2FA', expiring: 'Expiring' };
</script>

<div class="chips" role="group" aria-label="Quick filters">
  <button class:on={!active} onclick={() => onselect(null)}>All</button>
  {#each Object.keys(LABELS) as key (key)}
    {#if counts[key] > 0}
      <button class:on={active === key} onclick={() => onselect(key)}>{LABELS[key]} · {counts[key]}</button>
    {/if}
  {/each}
</div>

<style>
  .chips { display: flex; gap: 6px; padding: 2px 14px 8px; flex-wrap: wrap; }
  button {
    height: 26px; padding: 0 12px; border-radius: 13px; cursor: pointer;
    background: var(--glass); border: 1px solid var(--glass-border); color: var(--text-muted); font-size: 12.5px;
  }
  button.on { background: var(--text); color: var(--wash-base-opaque); border-color: transparent; }
</style>
