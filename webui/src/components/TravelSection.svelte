<script>
  /** Settings › Privacy: travel mode (Pro). Hides chosen collections and tags on this device only. Never shown while
   *  the duress vault is open. Turning it off asks for the master password (the backend prompts). */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let data = $state(null);
  let collections = $state([]);
  let tags = $state([]);

  function show(result) {
    data = result;
    collections = [...(result.collections ?? [])];
    tags = [...(result.tags ?? [])];
  }

  $effect(() => { call('travel_get').then((r) => { if (r.ok) show(r); }); });

  const toggle = (list, value, on) => (on ? [...new Set([...list, value])] : list.filter((v) => v !== value));

  async function save() {
    const result = await call('travel_save', collections, tags);
    if (!okOrToast(result)) return;
    show(result);
    toast(result.message || t('travel.saved'));
  }

  async function turnOff() {
    const result = await call('travel_off');
    if (!okOrToast(result)) return;
    show(result);
    toast(result.message || t('travel.off'));
  }
</script>

{#if data && !data.duress}
  <h3 class="title">{t('travel.title')}</h3>
  <div class="group" data-testid="travel">
    <p class="row desc">{t('travel.summary')}</p>
    {#if data.on}
      <div class="row on" role="status">
        <div class="text"><div>{t('travel.on', { count: data.hidden_count ?? 0 })}</div><div class="desc">{t('travel.deviceOnly')}</div></div>
        <Button label={t('travel.turnOff')} onclick={turnOff} />
      </div>
    {:else if !data.pro}
      <p class="row desc">{t('travel.needsPro')}</p>
    {/if}
    {#if data.available_collections?.length}
      <fieldset class="row pick">
        <legend>{t('travel.chooseCollections')}</legend>
        {#each data.available_collections as c (c.id)}
          <label><input type="checkbox" checked={collections.includes(c.id)}
            onchange={(e) => (collections = toggle(collections, c.id, e.currentTarget.checked))} /> {c.name}</label>
        {/each}
      </fieldset>
    {/if}
    {#if data.available_tags?.length}
      <fieldset class="row pick">
        <legend>{t('travel.chooseTags')}</legend>
        {#each data.available_tags as tag (tag)}
          <label><input type="checkbox" checked={tags.includes(tag)}
            onchange={(e) => (tags = toggle(tags, tag, e.currentTarget.checked))} /> {tag}</label>
        {/each}
      </fieldset>
    {/if}
    <div class="row">
      <span class="desc grow">{t('travel.notRemoved')}</span>
      <Button label={t('common.save')} variant="primary" disabled={!collections.length && !tags.length} onclick={save} />
    </div>
  </div>
{/if}

<style>
  .title { margin: 16px 0 8px; font: 600 15px var(--font-display); }
  .row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; margin: 0; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; }
  .grow { flex: 1; }
  .desc { color: var(--text-muted); font-size: 12px; }
  .pick { flex-wrap: wrap; border: none; border-top: 1px solid var(--separator); }
  .pick legend { float: left; width: 100%; color: var(--text-muted); font-size: 12px; padding: 0; margin-bottom: 4px; }
  .pick label { display: inline-flex; align-items: center; gap: 4px; font-size: 13px; }
</style>
