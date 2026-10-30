<script>
  /** The vault list sort: an order plus "Favorites first". A typed search keeps its relevance order. */
  import { t } from '../lib/i18n.svelte.js';

  let { sort = null, searching = false, onchange } = $props();
  const FALLBACK = [
    { value: 'title_asc', label: 'sortMenu.titleAsc' }, { value: 'title_desc', label: 'sortMenu.titleDesc' },
    { value: 'modified_desc', label: 'sortMenu.modified' }, { value: 'created_desc', label: 'sortMenu.created' },
  ];
  // Python's options carry their own label; the fallback labels are catalog keys.
  const options = $derived(sort?.options ?? FALLBACK);
  const optionLabel = (o) => (sort?.options ? o.label : t(o.label));
  const option = $derived(sort?.option ?? 'title_asc');
  const favoritesFirst = $derived(sort?.favorites_first ?? true);
</script>

<div class="sort" role="group" aria-label={t('sortMenu.sort')}>
  {#if searching}
    <span class="note">{t('sortMenu.bestMatches')}</span>
  {:else}
    <label>
      <span class="label">{t('sortMenu.sort')}</span>
      <select aria-label={t('sortMenu.sortBy')} value={option} onchange={(e) => onchange(e.currentTarget.value, favoritesFirst)}>
        {#each options as o (o.value)}<option value={o.value}>{optionLabel(o)}</option>{/each}
      </select>
    </label>
    <label class="fav">
      <input type="checkbox" checked={favoritesFirst} onchange={(e) => onchange(option, e.currentTarget.checked)} />
      {t('sortMenu.favoritesFirst')}
    </label>
  {/if}
</div>

<style>
  .sort { margin-left: auto; display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--text-muted); }
  label { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; }
  .label { color: var(--text-faint); }
  select {
    height: 26px; padding: 0 8px; border-radius: 8px; font: inherit; color: var(--text);
    background: var(--glass); border: 1px solid var(--glass-border);
  }
  .note { color: var(--text-faint); }
</style>
