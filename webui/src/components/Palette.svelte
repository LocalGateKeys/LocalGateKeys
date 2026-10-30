<script>
  /** Ctrl+K command palette: items and actions; > actions, # tags, @ collections. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';

  let { onclose, onopen, onnavigate } = $props();

  let query = $state('');
  let rows = $state([]);
  let active = $state(0);
  let input = $state();
  let seq = 0;

  async function refresh() {
    const mine = ++seq;
    const result = await call('palette_query', query, 'everything');
    if (mine !== seq || !result.ok) return;
    rows = result.rows;
    active = 0;
  }

  $effect(() => { input?.focus(); refresh(); });

  async function run(row) {
    if (!row) return;
    if (row.kind === 'item') { onopen(row.ref); onclose(); return; }
    const result = await call('palette_run', row.command_id);
    if (!okOrToast(result)) return;
    onclose();
    if (result.done) toast(result.done);
    else if (result.navigate) onnavigate(result.navigate, result);
  }

  function key(event) {
    if (event.key === 'ArrowDown') { event.preventDefault(); active = Math.min(rows.length - 1, active + 1); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); active = Math.max(0, active - 1); }
    else if (event.key === 'Enter') { event.preventDefault(); run(rows[active]); }
    else if (event.key === 'Escape') { event.preventDefault(); onclose(); }
  }
</script>

<div class="scrim" role="presentation" onclick={onclose}>
  <div class="palette glass" role="dialog" aria-modal="true" aria-label={t('palette.title')} tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
    <input
      bind:this={input}
      role="combobox"
      aria-expanded="true"
      aria-controls="palette-rows"
      aria-label={t('palette.searchLabel')}
      placeholder={t('palette.placeholder')}
      bind:value={query}
      oninput={refresh}
      onkeydown={key}
    />
    <div id="palette-rows" role="listbox" aria-label={t('palette.results')}>
      {#each rows as row, i (i)}
        {#if i === 0 || rows[i - 1].group !== row.group}<div class="group-label">{row.group}</div>{/if}
        <div role="option" tabindex="-1" aria-selected={i === active} class="row" onclick={() => run(row)} onkeydown={() => {}}>
          <span>{row.title}</span><span class="sub">{row.subtitle}</span>
        </div>
      {:else}
        <p class="none">{t('palette.noMatches')}</p>
      {/each}
    </div>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; background: var(--scrim); z-index: 45; display: grid; justify-items: center; align-items: start; padding-top: 12vh; }
  .palette { width: min(620px, calc(100vw - 40px)); border-radius: 16px; padding: 10px; }
  input { width: 100%; height: 40px; border: none; outline: none; background: none; padding: 0 10px; font-size: 15px; user-select: text; }
  [role="listbox"] { max-height: 50vh; overflow-y: auto; border-top: 1px solid var(--separator); padding-top: 4px; }
  .group-label { color: var(--text-faint); font-size: 12px; padding: 8px 10px 2px; }
  .row { display: flex; gap: 10px; padding: 7px 10px; border-radius: 8px; cursor: pointer; }
  .row[aria-selected="true"] { background: var(--glass-hover); }
  .sub { color: var(--text-muted); margin-left: auto; font-size: 12.5px; }
  .none { color: var(--text-muted); padding: 10px; margin: 0; }
</style>
