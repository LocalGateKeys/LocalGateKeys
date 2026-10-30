<script>
  /** Backup & restore: create, verify, restore as a new profile, test restore, recovery kit, recovery phrase.
   *  Every file is chosen in a Windows dialog opened by LocalGateKeys; passwords are cleared after each call. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import PhraseCard from './PhraseCard.svelte';

  let { initial = null, onclose } = $props();
  let status = $state(null);
  let form = $state(null); // 'create' | 'verify' | 'restore' | 'test' | 'trial' | 'phrase'
  let v = $state({ backup: '', confirm: '', vault: '', name: 'Restored profile' });
  let busy = $state(false);
  let error = $state('');
  let summary = $state('');
  let card = $state(null);
  // What replacing the phrase changed (old phrase dead, older backups still
  // open with it, Hello/camera to set up again); kept after the card closes.
  let phraseNotes = $state([]);

  const FORMS = $derived({
    create: { title: t('recoveryPage.createTitle'), text: t('recoveryPage.createText') },
    verify: { title: t('recoveryPage.verifyTitle'), text: t('recoveryPage.verifyText') },
    restore: { title: t('recoveryPage.restoreTitle'), text: t('recoveryPage.bothPasswords') },
    test: { title: t('recoveryPage.testTitle'), text: t('recoveryPage.bothPasswords') },
    trial: { title: t('recoveryPage.trialTitle'), text: t('recoveryPage.trialText') },
    phrase: { title: t('recoveryPage.phraseTitle'), text: '' },
  });

  async function load() {
    const result = await call('backup_status');
    if (okOrToast(result, t('recoveryPage.openFailed'))) status = result;
  }
  $effect(() => {
    load();
    const map = { create: 'create', verify: 'verify', restore: 'restore', kit: 'test' };
    if (initial && map[initial]) form = map[initial];
  });

  function wipe() { v = { backup: '', confirm: '', vault: '', name: v.name }; }
  function open(name) { form = name; error = ''; phraseNotes = []; wipe(); }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    const calls = {
      create: () => call('backup_create', v.backup, v.confirm, v.vault),
      verify: () => call('backup_verify', v.backup, v.vault),
      restore: () => call('backup_restore', v.name, v.backup, v.vault),
      test: () => call('backup_test', v.backup, v.vault),
      trial: () => call('backup_verify_trial', v.vault),
      phrase: () => call('phrase_create', v.vault),
    };
    const kind = form;
    const result = await calls[kind]();
    busy = false;
    wipe();
    if (!result.ok) { if (result.error.code !== 'cancelled') error = result.error.message; return; }
    form = null;
    if (kind === 'phrase') {
      card = result;
      phraseNotes = Array.isArray(result.notes) ? result.notes.filter((n) => typeof n === 'string' && n) : [];
      return;
    }
    phraseNotes = [];
    summary = result.message;
    load();
  }

  async function kit() {
    const result = await call('backup_kit');
    if (result.ok) summary = result.message;
    else if (result.error.code !== 'cancelled') summary = result.error.message;
  }

  async function cancelTrial() {
    const result = await call('backup_cancel_trial');
    if (result.ok) summary = result.message;
    load();
  }

  function cardDone(message) {
    if (message) summary = message;
    card = null;
    load();
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('recoveryPage.title')}>
  <header>
    <h2>{t('recoveryPage.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if status}
    <p class="note">{status.intro}</p>
    {#if summary}<p class="summary" role="status">{summary}</p>{/if}
    {#if phraseNotes.length}
      <ul class="phrase-notes" aria-label={t('recoveryPage.phraseChanged')}>
        {#each phraseNotes as note, i (i)}<li>{note}</li>{/each}
      </ul>
    {/if}
    {#if card}
      {#key card.token}<PhraseCard {card} ondone={cardDone} />{/key}
    {:else if form}
      <form class="group form" onsubmit={submit} aria-label={FORMS[form].title}>
        <h3>{FORMS[form].title}</h3>
        <p class="note">{form === 'phrase' ? status.phrase_intro : FORMS[form].text}</p>
        {#if form === 'restore'}<Field label={t('recoveryPage.restoredName')} bind:value={v.name} />{/if}
        {#if form !== 'trial' && form !== 'phrase'}
          <Field label={t('recoveryPage.backupPassword')} type="password" bind:value={v.backup} autofocus />
        {/if}
        {#if form === 'create'}<Field label={t('recoveryPage.confirmPassword')} type="password" bind:value={v.confirm} />{/if}
        <Field label={form === 'create' || form === 'phrase' ? t('recoveryPage.vaultPassword') : t('recoveryPage.vaultPasswordThen')}
               type="password" bind:value={v.vault} />
        {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
        <footer>
          <Button label={t('common.cancel')} onclick={() => { form = null; wipe(); }} />
          <Button type="submit" variant="primary" label={form === 'create' || form === 'phrase' ? t('common.continue') : t('recoveryPage.chooseBackup')} busy={busy} busyLabel={t('recoveryPage.working')} />
        </footer>
      </form>
    {:else}
      <div class="section-label">{t('recoveryPage.backups')}</div>
      <div class="group">
        <div class="row"><div class="text">{t('recoveryPage.createBackup')}<div class="meta">{t('recoveryPage.createBackupMeta')}</div></div>
          <Button label={t('recoveryPage.createBtn')} disabled={!status.can_create} onclick={() => open('create')} /></div>
        <div class="row"><div class="text">{t('recoveryPage.verifyBackup')}<div class="meta">{t('recoveryPage.verifyBackupMeta')}</div></div>
          <Button label={t('recoveryPage.verifyBtn')} onclick={() => open('verify')} /></div>
        <div class="row"><div class="text">{t('recoveryPage.restoreNew')}<div class="meta">{t('recoveryPage.restoreNewMeta')}</div></div>
          <Button label={t('recoveryPage.restoreBtn')} onclick={() => open('restore')} /></div>
      </div>
      {#if status.can_create}
        <div class="section-label">{t('recoveryPage.drill')}</div>
        <div class="group">
          <div class="row"><div class="text">{t('recoveryPage.testTitle')}<div class="meta">{t('recoveryPage.testRestoreMeta')}</div></div>
            <Button label={t('recoveryPage.testBtn')} onclick={() => open('test')} /></div>
          <div class="row"><div class="text">{t('recoveryPage.verifyTrial')}</div>
            <Button label={t('recoveryPage.verifyBtn')} disabled={!status.trial} onclick={() => open('trial')} /></div>
          <div class="row"><div class="text">{t('recoveryPage.writeKit')}<div class="meta">{t('recoveryPage.writeKitMeta')}</div></div>
            <Button label={t('recoveryPage.writeKitBtn')} disabled={!status.kit_ready} onclick={kit} /></div>
          {#if status.trial}<div class="row"><div class="text">{t('recoveryPage.discardTest')}</div><Button label={t('recoveryPage.cancelTest')} onclick={cancelTrial} /></div>{/if}
        </div>
        <div class="section-label">{t('recoveryPage.phraseTitle')}</div>
        <div class="group">
          <div class="row"><div class="text">{status.phrase_enrolled ? t('recoveryPage.phraseSet') : t('recoveryPage.phraseNone')}
            <div class="meta">{status.phrase_intro}</div></div>
            <Button label={status.phrase_enrolled ? t('recoveryPage.replace') : t('recoveryPage.createBtn')} onclick={() => open('phrase')} /></div>
        </div>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .sheet {
    position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent);
  }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0 0 4px; font: 600 15px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .note, .meta { color: var(--text-muted); font-size: 12.5px; }
  .summary { padding: 8px 12px; border-radius: 10px; background: color-mix(in srgb, var(--accent) 14%, transparent); }
  .phrase-notes { margin: 0; padding: 8px 12px 8px 28px; border-radius: 10px; font-size: 12.5px;
    background: color-mix(in srgb, var(--warning) 14%, transparent); display: grid; gap: 4px; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; }
  .form { padding: 14px; display: grid; gap: 8px; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
