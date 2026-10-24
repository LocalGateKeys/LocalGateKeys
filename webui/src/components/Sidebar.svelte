<script>
  /** Sidebar: vault filters, types, collections/views, tools and Settings. */
  let { nav, active = null, onfilter, onaction } = $props();
</script>

<nav class="sidebar" aria-label="Vault">
  {#each nav?.groups ?? [] as group (group.name)}
    {#if group.entries.length}
      <div class="section-label">{group.name}</div>
      {#each group.entries as entry (entry.label + (entry.token ?? ''))}
        <button
          class="entry"
          class:on={!entry.action && entry.token === active}
          aria-current={!entry.action && entry.token === active ? 'page' : undefined}
          onclick={() => (entry.action ? onaction(entry.action) : onfilter(entry.token))}
        >
          <span class="label">{entry.label}</span>
          {#if entry.count !== null && entry.count !== undefined}<span class="count">{entry.count}</span>{/if}
        </button>
      {/each}
    {/if}
  {/each}
  {#if nav?.settings}
    <button class="entry settings" onclick={() => onaction(nav.settings.action)}>{nav.settings.label}</button>
  {/if}
</nav>

<style>
  .sidebar { display: flex; flex-direction: column; padding: 6px 8px 10px; overflow-y: auto; min-height: 0; }
  .sidebar .section-label { padding: 12px 10px 4px; }
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
</style>
