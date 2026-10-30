<script>
  /** Profiles: one encrypted vault per person. Add, rename, recolour, photo, remove. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();
  const COLORS = ['#28C7FA', '#3B82F6', '#8B5CF6', '#EC4899', '#F97316', '#EAB308', '#22C55E', '#64748B'];
  let data = $state(null);
  let editing = $state(null); // {id, name, color}
  let adding = $state('');
  let error = $state('');

  async function load() {
    const result = await call('profiles_manage');
    if (okOrToast(result, t('profilesPage.openFailed'))) data = result;
  }
  $effect(() => { load(); });

  async function act(method, ...args) {
    error = '';
    const result = await call(method, ...args);
    if (!result.ok) { if (result.error.code !== 'cancelled') error = result.error.message; return false; }
    if (result.message) toast(result.message);
    await load();
    return true;
  }

  async function add(event) {
    event.preventDefault();
    if (await act('profiles_create', adding.trim())) adding = '';
  }

  async function save() {
    if (await act('profiles_update', editing.id, editing.name.trim(), editing.color)) editing = null;
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('profilesPage.title')}>
  <header>
    <h2>{t('profilesPage.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if data}
    <p class="muted">{data.intro}</p>
    <div class="grid">
      {#each data.profiles as p (p.id)}
        <div class="card group" class:active={p.active}>
          <div class="avatar" style:background={p.color}>
            {#if p.photo}<img src={p.photo} alt="" />{:else}{p.initials}{/if}
          </div>
          {#if editing?.id === p.id}
            <input aria-label={t('profilesPage.profileName')} bind:value={editing.name} />
            <div class="swatches" role="radiogroup" aria-label={t('profilesPage.accentColour')}>
              {#each COLORS as c (c)}
                <button role="radio" aria-checked={editing.color === c} aria-label={c} class:on={editing.color === c} style:background={c} onclick={() => (editing.color = c)}></button>
              {/each}
            </div>
            <div class="actions">
              <Button label={t('common.cancel')} onclick={() => (editing = null)} />
              <Button label={t('common.save')} variant="primary" onclick={save} />
            </div>
          {:else}
            <div class="name">{p.active ? t('profilesPage.thisProfile', { name: p.name }) : p.name}</div>
            <div class="actions">
              <Button label={t('profilesPage.edit')} onclick={() => (editing = { id: p.id, name: p.name, color: p.color })} />
              <Button label={t('profilesPage.photo')} onclick={() => act('profiles_photo', p.id)} />
              {#if p.photo}<Button label={t('profilesPage.removePhoto')} onclick={() => act('profiles_remove_photo', p.id)} />{/if}
              <Button label={t('profilesPage.remove')} variant="danger" onclick={() => act('profiles_delete', p.id)} />
            </div>
          {/if}
        </div>
      {/each}
    </div>
    <form class="add" onsubmit={add}>
      <input aria-label={t('profilesPage.newName')} placeholder={t('profilesPage.profileName')} bind:value={adding} />
      <Button type="submit" label={t('profilesPage.add')} disabled={!adding.trim()} />
    </form>
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <p class="muted note">{data.note}</p>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px; }
  .card { padding: 14px; display: grid; gap: 8px; justify-items: center; }
  .card.active { outline: 2px solid var(--accent); }
  .avatar { width: 56px; height: 56px; border-radius: 16px; display: grid; place-items: center; color: #fff; font: 600 20px var(--font-display); overflow: hidden; }
  .avatar img { width: 100%; height: 100%; object-fit: cover; }
  .name { font-weight: 600; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; justify-content: center; }
  .swatches { display: flex; gap: 6px; }
  .swatches button { width: 20px; height: 20px; border-radius: 50%; border: 2px solid transparent; cursor: pointer; }
  .swatches button.on { border-color: var(--text); }
  input { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 6px 8px; user-select: text; }
  .add { display: flex; gap: 8px; margin-top: 12px; }
  .add input { flex: 1; }
  .error { color: var(--danger); }
  .note { margin-top: 14px; }
</style>
