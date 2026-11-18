<script>
  /** Live 2FA codes for every login, above the list: click one to copy it. */
  import { call, on } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import ItemTile from './ItemTile.svelte';

  const COLLAPSED = 4;

  let codes = $state([]);
  let expanded = $state(false);
  // Collapsed to the header row (remembered on this device); no codes are rendered then.
  let collapsed = $state(false);
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
    if (typeof result.collapsed === 'boolean') collapsed = result.collapsed;
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
    if (okOrToast(result, t('home.notCopied'))) notice(result);
  }

  async function toggleCollapsed() {
    collapsed = !collapsed;
    await call('codes_collapsed_set', collapsed); // a failed save still applies until the app closes
  }

  const shown = $derived(expanded ? codes : codes.slice(0, COLLAPSED));
</script>

{#if codes.length}
  <section class="codes" aria-label={t('codesCard.title')}>
    <div class="head">
      <span class="title">{t('codesCard.title')} <span class="count">· {formatNumber(codes.length)}</span></span>
      <span class="actions">
        {#if !collapsed && codes.length > COLLAPSED}
          <button class="link" onclick={() => (expanded = !expanded)}>{expanded ? t('codesCard.showFewer') : t('codesCard.showAll', { count: formatNumber(codes.length) })}</button>
        {/if}
        <button class="chevron" class:closed={collapsed} aria-expanded={!collapsed} aria-controls="codes-grid"
          aria-label={collapsed ? t('codesCard.expand') : t('codesCard.collapse')} title={collapsed ? t('codesCard.expand') : t('codesCard.collapse')}
          onclick={toggleCollapsed}>
          <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M3 5l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" /></svg>
        </button>
      </span>
    </div>
    {#if !collapsed}
    <div class="grid" id="codes-grid">
      {#each shown as entry (entry.ref.id)}
        <button class="code-tile group" aria-label={t('codesCard.copyFor', { title: entry.title })} onclick={() => copy(entry)}>
          <ItemTile kind={entry.ref.kind} origin={entry.origin} icon={entry.icon} size={28} />
          <span class="text">
            <span class="name">{entry.title}</span>
            {#if entry.hidden}
              <span class="sub muted">{t('codesCard.hiddenCopy')}</span>
            {:else if entry.error}
              <span class="sub muted">{entry.error}</span>
            {:else}
              <span class="code">{entry.code}</span>
            {/if}
          </span>
          {#if entry.code}
            {@const fraction = left(entry) / (entry.period || 30)}
            <svg class="ring" width="18" height="18" aria-label={t('codesCard.refreshesIn', { seconds: formatNumber(left(entry)) })}>
              <circle cx="9" cy="9" r="7.5" fill="none" stroke="var(--separator)" stroke-width="2" />
              <circle cx="9" cy="9" r="7.5" fill="none" stroke={left(entry) <= 5 ? 'var(--warning)' : 'var(--success)'} stroke-width="2"
                stroke-linecap="round" stroke-dasharray="47.1" stroke-dashoffset={47.1 - fraction * 47.1} transform="rotate(-90 9 9)" />
            </svg>
          {/if}
        </button>
      {/each}
    </div>
    {/if}
  </section>
{/if}

<style>
  .codes { padding: 0 14px 10px; }
  .head { display: flex; align-items: center; justify-content: space-between; padding: 0 2px 6px; }
  .title { font-weight: 600; }
  .count { font-weight: 400; color: var(--text-muted); }
  .actions { display: inline-flex; align-items: center; gap: 8px; }
  .chevron {
    display: inline-grid; place-items: center; width: 22px; height: 22px; padding: 0; border-radius: 6px;
    background: none; border: none; color: var(--text-muted); cursor: pointer;
  }
  .chevron:hover { color: var(--text); background: var(--glass); }
  .chevron:focus-visible { outline: 2px solid var(--link); outline-offset: 1px; }
  .chevron svg { transition: transform 0.15s; }
  .chevron.closed svg { transform: rotate(-90deg); }
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
