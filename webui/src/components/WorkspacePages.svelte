<script>
  /** Reminders, Activity history, Keyboard shortcuts and Collections: simple list pages over safe metadata. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, openRoute, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { kind, onclose } = $props();
  let data = $state(null);
  let picked = $state(null);
  let name = $state('');
  let renaming = $state(null);

  const LOADERS = { reminders: 'reminders_list', activity: 'activity_list', shortcuts: 'shortcuts_list', collections: 'collections_list' };
  const TITLES = $derived({ reminders: t('workspacePages.reminders'), activity: t('workspacePages.activity'), shortcuts: t('workspacePages.shortcuts'), collections: t('workspacePages.collections') });

  async function load() {
    const r = await call(LOADERS[kind]);
    if (okOrToast(r, t('workspacePages.openFailed', { title: TITLES[kind] }))) data = r;
  }
  $effect(() => { load(); });

  async function act(method, ...args) {
    const r = await call(method, ...args);
    if (okOrToast(r)) { data = r; picked = null; renaming = null; name = ''; }
  }

  function keys(event) {
    // Captured first, so one Escape closes only the shortcuts and nothing beneath.
    if (event.key === 'Escape') { event.stopImmediatePropagation(); event.preventDefault(); onclose(); }
  }
</script>

<svelte:window onkeydowncapture={kind === 'shortcuts' ? keys : undefined} />

<div class="sheet glass" role="dialog" aria-label={TITLES[kind]}>
  <header>
    <h2>{data?.title ?? TITLES[kind]}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if data}
    {#if data.subtitle}<p class="muted">{data.subtitle}
      {#if data.action}
        <button class="link" onclick={() => { onclose(); openRoute(data.action.route, data.action.params); }}>{data.action.label}</button>
      {/if}
    </p>{/if}
    {#if kind === 'reminders'}
      <div class="group rows" role="listbox" aria-label={t('workspacePages.reminders')}>
        {#each data.rows as r (r.id)}
          <button role="option" aria-selected={picked === r.id} class="row" class:on={picked === r.id} onclick={() => (picked = r.id)}>
            <span class="grow">{r.title}</span><span class="muted">{r.due}</span><span class="tag">{r.status}</span>
          </button>
        {:else}<p class="empty">{t('workspacePages.nothingComing')}</p>{/each}
      </div>
      <footer>
        <Button label={t('workspacePages.snooze')} disabled={!picked} onclick={() => act('reminders_snooze', picked)} />
        <Button label={t('workspacePages.complete')} variant="primary" disabled={!picked} onclick={() => act('reminders_complete', picked)} />
      </footer>
    {:else if kind === 'activity'}
      <div class="group rows">
        <div class="row head"><span class="grow">{t('workspacePages.when')}</span><span class="grow">{t('workspacePages.event')}</span><span>{t('workspacePages.result')}</span><span>{t('workspacePages.count')}</span></div>
        {#each data.rows as r, i (i)}
          <div class="row"><span class="grow">{r.when}</span><span class="grow">{r.event}</span><span>{r.result}</span><span>{r.count}</span></div>
        {:else}<p class="empty">{t('workspacePages.noActivity')}</p>{/each}
      </div>
    {:else if kind === 'shortcuts'}
      {#each [...new Set(data.rows.map((r) => r.group))] as group (group)}
        <div class="section-label">{group}</div>
        <div class="group">
          {#each data.rows.filter((r) => r.group === group) as r, i (i)}
            <div class="row"><kbd>{r.keys}</kbd><span class="grow">{r.description}</span></div>
          {/each}
        </div>
      {/each}
    {:else if kind === 'collections'}
      <div class="group rows">
        {#each data.collections as c (c.id)}
          <div class="row">
            {#if renaming === c.id}
              <input aria-label={t('workspacePages.collectionName')} bind:value={name} />
              <Button label={t('common.save')} variant="primary" disabled={!name.trim()} onclick={() => act('collections_rename', c.id, name.trim(), null)} />
              <Button label={t('common.cancel')} onclick={() => (renaming = null)} />
            {:else}
              <span class="grow">{c.name}</span>
              <Button label={t('workspacePages.rename')} onclick={() => { renaming = c.id; name = c.name; }} />
              <Button label={t('workspacePages.archive')} onclick={() => act('collections_archive', c.id)} />
            {/if}
          </div>
        {:else}<p class="empty">{t('workspacePages.noCollections')}</p>{/each}
      </div>
      <form class="add" onsubmit={(e) => { e.preventDefault(); if (!renaming) act('collections_create', name.trim(), ''); }}>
        <input aria-label={t('workspacePages.newName')} placeholder={t('workspacePages.newCollection')} bind:value={name} disabled={!!renaming} />
        <Button type="submit" label={t('workspacePages.addCollection')} disabled={!name.trim() || !!renaming} />
      </form>
    {/if}
  {/if}
</div>

<style>
  .link { border: 0; background: none; padding: 0 0 0 4px; font: inherit; color: var(--link); cursor: pointer; }
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .rows { overflow: auto; }
  .row { display: flex; gap: 12px; align-items: center; padding: 9px 14px; width: 100%; background: none; border: none; color: inherit; text-align: left; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row.on { background: color-mix(in srgb, var(--accent) 18%, transparent); }
  button.row { cursor: pointer; }
  .head { color: var(--text-muted); font-weight: 600; }
  .grow { flex: 1; }
  .tag { font-size: 11.5px; padding: 2px 8px; border-radius: 999px; background: var(--group); }
  kbd { font: 12px ui-monospace, monospace; padding: 3px 8px; border-radius: 6px; background: var(--group); border: 1px solid var(--separator); min-width: 150px; }
  .empty { color: var(--text-muted); text-align: center; padding: 16px; margin: 0; }
  input { flex: 1; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 6px 8px; user-select: text; }
  .add { display: flex; gap: 8px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
