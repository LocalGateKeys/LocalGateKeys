<script>
  /** Quick access: search this profile from anywhere (hotkey, tray, palette) and open the item. */
  import { call } from '../lib/api.js';
  import { okOrToast } from '../lib/toast.js';

  let { onclose, onopen } = $props();
  const KINDS = [['', 'All types'], ['credentials', 'Credentials'], ['note', 'Notes'], ['bookmark', 'Bookmarks'],
    ['safe', 'Safe items'], ['document', 'Documents'], ['identity', 'Identities']];
  let query = $state('');
  let kind = $state('');
  let rows = $state([]);
  let profile = $state('');
  let input = $state();
  let timer = null;

  async function search() {
    const r = await call('quick_search', query, kind);
    if (okOrToast(r)) { rows = r.rows; profile = r.profile; }
  }
  $effect(() => { search(); input?.focus(); });

  function typed() { clearTimeout(timer); timer = setTimeout(search, 120); }
  function keys(event) {
    if (event.key === 'Escape') { event.preventDefault(); onclose(); }
    if (event.key === 'Enter' && rows[0]) { event.preventDefault(); onopen(rows[0].ref); }
  }
</script>

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-label="Quick access" tabindex="-1" onkeydown={keys}>
    <h2>Quick access</h2>
    <p class="muted">Profile: {profile} · Search credential and typed-item metadata. Open a row for its deliberate action.</p>
    <div class="bar">
      <input bind:this={input} bind:value={query} oninput={typed} placeholder="Find a login, note or bookmark" aria-label="Find a login, note or bookmark" />
      <select aria-label="Type" bind:value={kind} onchange={search}>{#each KINDS as [value, label] (value)}<option {value}>{label}</option>{/each}</select>
    </div>
    <div class="group list" role="listbox" aria-label="Results">
      {#each rows as r (r.ref.id)}
        <button role="option" aria-selected="false" class="row" onclick={() => onopen(r.ref)}><span>{r.title}</span><span class="muted">{r.subtitle}</span></button>
      {:else}<p class="empty">No matches.</p>{/each}
    </div>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 55; background: var(--scrim); display: grid; place-items: start center; padding-top: 12vh; }
  .card { width: min(620px, calc(100% - 32px)); border-radius: 18px; padding: 18px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .bar { display: flex; gap: 8px; }
  input, select { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 10px; padding: 8px 10px; }
  input { flex: 1; user-select: text; }
  .list { max-height: 50vh; overflow: auto; }
  .row { display: flex; justify-content: space-between; gap: 10px; width: 100%; text-align: left; padding: 9px 14px; background: none; border: none; color: inherit; cursor: pointer; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row:hover { background: var(--group); }
  .empty { color: var(--text-muted); text-align: center; padding: 14px; margin: 0; }
</style>
