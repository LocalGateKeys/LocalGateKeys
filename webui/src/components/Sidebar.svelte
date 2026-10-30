<script>
  /** Sidebar: vault filters, types, collections/views, tools and Settings. */
  let { nav, active = null, activeActions = [], onfilter, onaction } = $props();
  // A filter entry is on when it is the current filter; an action entry while its page is open on the right.
  const isOn = (entry) => (entry.action ? activeActions.includes(entry.action) : entry.token === active);
  import { t } from '../lib/i18n.svelte.js';
  import { ICONS, navIconKey } from './navIcons.js';
  import mark from '../../../src/localvault/assets/localgatekeys_icon.svg';
  // Every entry has an icon for what it does; one with none fitting shows its first letter. Narrow windows
  // show only the icons, with the full name as the tooltip and accessible name.
  const glyph = (label) => (label ?? '?').trim().charAt(0).toUpperCase();
</script>

{#snippet icon(entry)}
  {@const key = navIconKey(entry)}
  <span class="glyph" aria-hidden="true">
    {#if key}
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8"
        stroke-linecap="round" stroke-linejoin="round" data-icon={key}>
        {#each ICONS[key] as el, i (i)}
          {#if el.tag === 'path'}<path d={el.d} />
          {:else if el.tag === 'circle'}<circle cx={el.cx} cy={el.cy} r={el.r} />
          {:else}<rect x={el.x} y={el.y} width={el.width} height={el.height} rx={el.rx} />{/if}
        {/each}
      </svg>
    {:else}{glyph(entry.label)}{/if}
  </span>
{/snippet}

<nav class="sidebar" aria-label={t('sidebar.vault')}>
  <div class="brand"><img src={mark} alt="" width="28" height="28" /><span class="brand-name">Local<span>Gate</span>Keys</span></div>
  {#each nav?.groups ?? [] as group (group.name)}
    {#if group.entries.length}
      <div class="section-label">{group.name}</div>
      {#each group.entries as entry (entry.label + (entry.token ?? ''))}
        <button
          class="entry"
          class:on={isOn(entry)}
          aria-current={isOn(entry) ? 'page' : undefined}
          title={entry.label}
          onclick={() => (entry.action ? onaction(entry.action) : onfilter(entry.token))}
        >
          {@render icon(entry)}
          <span class="label">{entry.label}</span>
          {#if entry.count !== null && entry.count !== undefined}<span class="count">{entry.count}</span>{/if}
        </button>
      {/each}
    {/if}
  {/each}
  {#if nav?.settings}
    <button class="entry settings" class:on={activeActions.includes(nav.settings.action)}
      aria-current={activeActions.includes(nav.settings.action) ? 'page' : undefined} title={nav.settings.label}
      onclick={() => onaction(nav.settings.action)}>{@render icon(nav.settings)}<span class="label">{nav.settings.label}</span></button>
  {/if}
</nav>

<style>
  .sidebar { display: flex; flex-direction: column; padding: 6px 8px 10px; overflow-y: auto; min-height: 0; }
  .sidebar .section-label { padding: 12px 10px 4px; }
  .brand { display: flex; align-items: center; gap: 9px; padding: 8px 10px 12px; margin-bottom: 4px; border-bottom: 1px solid var(--separator); }
  .brand img { width: 28px; height: 28px; }
  .brand-name { font: 700 16px var(--font-display); letter-spacing: -0.01em; }
  .brand-name span { color: var(--brand-text); }
  .entry {
    display: flex; align-items: center; gap: 8px; width: 100%;
    padding: 6px 10px; border: none; border-radius: 8px; background: none;
    text-align: left; cursor: pointer; position: relative;
  }
  .entry:hover { background: var(--glass); }
  .entry.on { background: var(--glass-hover); }
  .entry.on::before {
    content: ""; position: absolute; left: 0; top: 7px; bottom: 7px; width: 3px;
    border-radius: 2px; background: var(--link);
  }
  .label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .count { color: var(--text-faint); font-size: 12px; }
  .settings { margin-top: auto; }
  .glyph {
    display: grid; place-items: center; flex: none; width: 18px; height: 18px;
    color: var(--text-muted); font-weight: 600; font-size: 12px;
  }
  .entry.on .glyph, .entry:hover .glyph { color: var(--text); }
  @media (max-width: 720px) {
    .sidebar { padding: 6px 4px 10px; }
    .sidebar .section-label, .label, .count, .brand-name { display: none; }
    .brand { justify-content: center; padding: 8px 0 10px; }
    .entry { justify-content: center; padding: 8px 0; }
    .glyph { width: 32px; height: 32px; border-radius: 8px; background: var(--glass); }
    .glyph svg { width: 18px; height: 18px; }
  }
</style>
