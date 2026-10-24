<script>
  /** Recently deleted: restore, permanently delete, empty. */
  import { call } from '../lib/api.js';
  import { okOrToast, openRoute, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();
  let data = $state(null);
  let selected = $state(new Set());

  async function load() {
    const result = await call('trash_list');
    if (okOrToast(result, 'Could not open Recently deleted')) { data = result; selected = new Set(); }
  }
  $effect(() => { load(); });

  function toggle(id) {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    selected = next;
  }

  async function act(method, ...args) {
    const result = await call(method, ...args);
    if (!okOrToast(result)) return;
    toast(result.message);
    for (const failed of result.failed ?? []) toast(failed.title, failed.message, 'error');
    load();
  }

  const day = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 16).replace('T', ' ');
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Recently deleted">
  <header>
    <h2>Recently deleted</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if data}
    <p class="note">{data.retention_text}
      {#if data.retention_action}
        <button class="link" onclick={() => { onclose(); openRoute(data.retention_action.route, data.retention_action.params); }}>{data.retention_action.label}</button>
      {/if}
    </p>
    {#if data.rows.length}
      <div class="group rows">
        {#each data.rows as row (row.id)}
          <label class="row">
            <input type="checkbox" aria-label={`Select ${row.title}`} checked={selected.has(row.id)} onchange={() => toggle(row.id)} />
            <span class="title">{row.title}</span>
            <span class="muted">{row.kind_label}{row.username ? ` · ${row.username}` : ''}</span>
            <span class="when">{day(row.deleted_at)}</span>
          </label>
        {/each}
      </div>
    {:else}
      <p class="empty">Recently deleted is empty.</p>
    {/if}
    <footer>
      <span class="count">{selected.size ? `${selected.size} of ${data.rows.length} selected` : `${data.rows.length} item(s)`}</span>
      <Button label="Empty trash" variant="danger" onclick={() => act('trash_empty')} disabled={!data.rows.length} />
      <Button label="Delete selected" variant="danger" onclick={() => act('trash_purge', [...selected])} disabled={!selected.size} />
      <Button label="Restore selected" variant="primary" onclick={() => act('trash_restore', [...selected])} disabled={!selected.size} />
    </footer>
  {/if}
</div>

<style>
  .link { border: 0; background: none; padding: 0 0 0 4px; font: inherit; color: var(--link); cursor: pointer; }
  .sheet {
    position: absolute; inset: 10px; z-index: 30; border-radius: 18px; padding: 16px 18px;
    display: flex; flex-direction: column; background: color-mix(in srgb, var(--wash-base-opaque) 90%, transparent);
  }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .note { color: var(--text-muted); font-size: 12.5px; }
  .rows { overflow-y: auto; flex: 1; min-height: 0; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; border-top: 1px solid var(--separator); cursor: pointer; }
  .row:first-child { border-top: none; }
  .title { flex: 1; }
  .muted, .when { color: var(--text-muted); font-size: 12.5px; }
  .empty { color: var(--text-muted); text-align: center; flex: 1; }
  footer { display: flex; align-items: center; gap: 8px; margin-top: 12px; }
  .count { margin-right: auto; color: var(--text-muted); font-size: 12.5px; }
</style>
