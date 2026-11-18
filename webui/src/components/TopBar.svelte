<script>
  import { t } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';

  let { query = $bindable(''), oninput, onlock, onnew, onpalette, searchInput = $bindable() } = $props();
</script>

<div class="topbar">
  <div class="search glass">
    <span class="icon" aria-hidden="true">⌕</span>
    <input
      bind:this={searchInput}
      type="search"
      placeholder={t('topbar.search')}
      aria-label={t('topbar.search')}
      bind:value={query}
      {oninput}
      spellcheck="false"
    />
    <button class="hint" onclick={onpalette} aria-label={t('topbar.palette')}>Ctrl K</button>
  </div>
  <div class="actions">
    <Button label={t('topbar.lock')} variant="glass" onclick={onlock} />
    <Button label={t('topbar.newItem')} variant="primary" onclick={onnew} />
  </div>
</div>

<style>
  /* Wraps the buttons under the search field when the list column is narrow, so nothing spills into the detail pane. */
  .topbar { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; padding: 10px 14px 6px; min-width: 0; }
  .search {
    flex: 1 1 180px; min-width: 0; max-width: 420px; height: 34px; border-radius: 17px;
    display: flex; align-items: center; gap: 8px; padding: 0 6px 0 12px;
  }
  .search input { flex: 1; min-width: 0; border: none; background: none; outline: none; user-select: text; }
  .search input::-webkit-search-cancel-button { display: none; }
  .icon { color: var(--text-faint); }
  .hint { border: none; background: none; color: var(--text-faint); font-size: 11px; cursor: pointer; padding: 4px 8px; }
  .actions { margin-left: auto; display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; min-width: 0; max-width: 100%; }
</style>
