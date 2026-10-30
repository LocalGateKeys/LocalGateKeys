<script>
  /** Pick which person's vault to open, or add a profile (an empty vault, created on the next screen). */
  import { t } from '../lib/i18n.svelte.js';
  import ErrorLogLink from '../components/ErrorLogLink.svelte';
  import Button from '../components/Button.svelte';
  import Field from '../components/Field.svelte';
  import Group from '../components/Group.svelte';
  import Row from '../components/Row.svelte';
  import { call } from '../lib/api.js';

  let { onchosen } = $props();

  let profiles = $state([]);
  let error = $state('');
  let adding = $state(false);
  let name = $state('');
  let busy = $state(false);

  $effect(() => {
    call('profiles_list').then((result) => {
      if (result.ok) profiles = result.profiles;
      else error = result.error.message;
    });
  });

  async function choose(id) {
    const result = await call('profiles_select', id);
    if (result.ok) onchosen(result);
    else error = result.error.message;
  }

  async function add(event) {
    event.preventDefault();
    if (busy || !name.trim()) return;
    busy = true; error = '';
    const created = await call('profiles_create', name.trim());
    if (created.ok) await choose(created.profile.id);
    else error = created.error.message;
    busy = false;
  }
</script>

<section class="chooser">
  <div class="card glass">
    <h1>{t('profileChooser.title')}</h1>
    <Group>
      {#each profiles as profile (profile.id)}
        <Row title={profile.name} subtitle={profile.active ? t('profileChooser.current') : ''} onclick={() => choose(profile.id)}>
          {#snippet leading()}
            <span class="dot" style:background={profile.color} aria-hidden="true">{profile.name.slice(0, 1).toUpperCase()}</span>
          {/snippet}
        </Row>
      {/each}
      {#if !adding}
        <Row title={t('profileChooser.add')} subtitle={t('profileChooser.addHint')} onclick={() => { adding = true; error = ''; }}>
          {#snippet leading()}<span class="dot add" aria-hidden="true">+</span>{/snippet}
        </Row>
      {/if}
    </Group>
    {#if adding}
      <form class="add" onsubmit={add}>
        <div class="group"><Field label={t('profileChooser.name')} bind:value={name} placeholder={t('profileChooser.namePlaceholder')} autofocus /></div>
        <div class="buttons">
          <Button label={t('common.cancel')} onclick={() => { adding = false; name = ''; error = ''; }} />
          <Button type="submit" variant="primary" label={t('profileChooser.create')} busy={busy} busyLabel={t('common.creating')} disabled={!name.trim()} />
        </div>
      </form>
    {/if}
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
  </div>
</section>

<style>
  .chooser { height: 100%; display: grid; place-items: center; padding: 24px; }
  .card { width: min(420px, 100%); border-radius: var(--radius-card); padding: 22px; }
  h1 { margin: 0 0 6px; font: 600 18px var(--font-display); }
  .dot {
    width: 30px; height: 30px; border-radius: 9px; flex-shrink: 0;
    display: grid; place-items: center; color: #fff; font-weight: 600;
  }
  .dot.add { background: none; border: 1px dashed var(--text-faint); color: var(--text-muted); font-weight: 400; font-size: 18px; }
  .add { display: grid; gap: 10px; margin-top: 12px; }
  .buttons { display: flex; justify-content: flex-end; gap: 8px; }
  .error { color: var(--danger); }
</style>
