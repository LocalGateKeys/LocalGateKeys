<script>
  /** Live 2FA codes for every login, above the list: click one to copy it. */
  import { call, on } from '../lib/api.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import ItemTile from './ItemTile.svelte';

  const COLLAPSED = 4;

  let codes = $state([]);
  let expanded = $state(false);
  let now = $state(Date.now());
  let fetchedAt = 0;
  let timer = null;
  let seq = 0;

  async function load() {
    const mine = ++seq;
    clearTimeout(timer);
    const result = await call('codes_list');
    if (mine !== seq) return;
    if (!result.ok) { codes = []; return; }
    codes = result.codes;
    fetchedAt = Date.now();
    now = fetchedAt;
    // Fetch again when the first code rolls over.
    const live = codes.filter((c) => c.code);
    if (live.length) timer = setTimeout(load, Math.max(1, Math.min(...live.map((c) => c.remaining))) * 1000 + 50);
  }

  $effect(() => {
    load();
    const tick = setInterval(() => { now = Date.now(); }, 1000);
    const offs = [
      on('items.changed', load),
      on('vault.state', (state) => { if (state.state !== 'unlocked') { codes = []; clearTimeout(timer); } }),
    ];
    return () => { seq++; clearTimeout(timer); clearInterval(tick); offs.forEach((off) => off()); };
  });

  function left(entry) {
    return Math.max(0, entry.remaining - Math.floor((now - fetchedAt) / 1000));
  }

  async function copy(entry) {
    const result = await call('item_copy', entry.ref, 'totp');
    if (okOrToast(result, 'Not copied')) notice(result);
  }

  const shown = $derived(expanded ? codes : codes.slice(0, COLLAPSED));
</script>

{#if codes.length}
  <section class="codes" aria-label="One-time codes">
    <div class="head">
      <span class="title">One-time codes</span>
      {#if codes.length > COLLAPSED}
        <button class="link" onclick={() => (expanded = !expanded)}>{expanded ? 'Show fewer' : `Show all ${codes.length}`}</button>
      {/if}
    </div>
    <div class="grid">
      {#each shown as entry (entry.ref.id)}
        <button class="code-tile group" aria-label={`Copy 2FA code for ${entry.title}`} onclick={() => copy(entry)}>
          <ItemTile kind={entry.ref.kind} origin={entry.origin} icon={entry.icon} size={28} />
          <span class="text">
            <span class="name">{entry.title}</span>
            {#if entry.hidden}
              <span class="sub muted">Hidden · click to copy</span>
            {:else if entry.error}
              <span class="sub muted">{entry.error}</span>
            {:else}
              <span class="code">{entry.code}</span>
            {/if}
          </span>
          {#if entry.code}
            {@const fraction = left(entry) / (entry.period || 30)}
            <svg class="ring" width="18" height="18" aria-label={`Refreshes in ${left(entry)} s`}>
              <circle cx="9" cy="9" r="7.5" fill="none" stroke="var(--separator)" stroke-width="2" />
              <circle cx="9" cy="9" r="7.5" fill="none" stroke={left(entry) <= 5 ? 'var(--warning)' : 'var(--success)'} stroke-width="2"
                stroke-linecap="round" stroke-dasharray="47.1" stroke-dashoffset={47.1 - fraction * 47.1} transform="rotate(-90 9 9)" />
            </svg>
          {/if}
        </button>
      {/each}
    </div>
  </section>
{/if}

<style>
  .codes { padding: 0 14px 10px; }
  .head { display: flex; align-items: baseline; justify-content: space-between; padding: 0 2px 6px; }
  .title { font-weight: 600; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
  .code-tile {
    display: flex; align-items: center; gap: 10px; padding: 8px 12px; min-width: 0;
    border: none; color: inherit; font: inherit; text-align: left; cursor: pointer;
  }
  .code-tile:hover { filter: brightness(1.15); }
  .text { flex: 1; min-width: 0; display: grid; }
  .name { font-size: 12.5px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .code { font: 600 18px var(--font-mono); letter-spacing: 1.5px; }
  .sub { font-size: 12.5px; }
  .muted { color: var(--text-muted); }
  .ring { flex-shrink: 0; }
  .link { background: none; border: none; color: var(--link); cursor: pointer; padding: 0; font-size: 12.5px; }
</style>
