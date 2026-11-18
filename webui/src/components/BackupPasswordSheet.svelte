<script>
  /** The scheduled-backup password: set, change (with re-lock), reset with the recovery phrase, link a new
   *  phrase, confirm after a rollback, remove. The app keeps only a public key, never the password.
   *  Every field is cleared from the page after each try. */
  import { dialog } from '../lib/dialog.js';
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { t } from '../lib/i18n.svelte.js';
  import { call } from '../lib/api.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { mode = 'set', onclose } = $props();
  let old = $state('');
  let first = $state('');
  let second = $state('');
  let phrase = $state('');
  let relock = $state(true);
  let withPhrase = $state(false);
  let error = $state('');
  let busy = $state(false);

  const TEXT = $derived({
    set: { title: t('backupPasswordSheet.title'), intro: t('backupPasswordSheet.intro'), note: t('backupKeySheet.setWarning') },
    change: { title: t('backupKeySheet.changeTitle'), intro: t('backupKeySheet.changeIntro'), note: t('backupKeySheet.setWarning') },
    reset: { title: t('backupKeySheet.resetTitle'), intro: t('backupKeySheet.resetIntro'), note: t('backupKeySheet.setWarning') },
    rebind: { title: t('backupKeySheet.rebindTitle'), intro: t('backupKeySheet.rebindIntro'), note: '' },
    confirm: { title: t('backupKeySheet.confirmTitle'), intro: t('backupKeySheet.confirmIntro'), note: '' },
    confirmSeen: { title: t('backupKeySheet.confirmTitle'), intro: t('backupKeySheet.confirmSeenIntro'), note: '' },
    remove: { title: t('backupKeySheet.removeTitle'), intro: t('backupKeySheet.removeIntro'), note: '' },
  });
  const text = $derived(TEXT[mode] ?? TEXT.set);
  const needsOld = $derived(mode === 'change' || mode === 'rebind' || mode === 'confirm' || mode === 'confirmSeen' || (mode === 'remove' && !withPhrase));
  const needsPhrase = $derived(mode === 'reset' || (mode === 'remove' && withPhrase));
  const needsNew = $derived(mode === 'set' || mode === 'change' || mode === 'reset');

  function wipe() { old = ''; first = ''; second = ''; phrase = ''; }
  $effect(() => () => wipe());

  function request() {
    if (mode === 'change') return call('backup_password_change', old, first, second, relock);
    if (mode === 'reset') return call('backup_password_reset', phrase, first, second);
    if (mode === 'rebind') return call('backup_key_rebind', old);
    if (mode === 'confirm' || mode === 'confirmSeen') return call('backup_key_confirm', old);
    if (mode === 'remove') return withPhrase ? call('backup_key_remove', null, phrase) : call('backup_key_remove', old, null);
    return call('backup_password_set', first, second);
  }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    const pending = request();
    wipe(); // the passwords leave the page once the call is sent
    const result = await pending;
    busy = false;
    if (result.ok) { toast(result.message); onclose(true); return; }
    if (result.error.code !== 'cancelled') error = result.error.message;
  }
</script>

<div class="scrim" role="dialog" aria-modal="true" use:dialog={{ onescape: () => onclose(false) }} aria-label={text.title}>
  <form class="sheet glass" onsubmit={submit}>
    <h2>{text.title}</h2>
    <p class="note">{text.intro}</p>
    {#if text.note}<p class="note">{text.note}</p>{/if}
    <div class="group">
      {#if needsOld}
        <Field label={t('backupKeySheet.current')} type="password" bind:value={old} autofocus autocomplete="current-password" />
      {/if}
      {#if needsPhrase}
        <label class="phrase">{t('backupKeySheet.phrase')}
          <textarea bind:value={phrase} rows="3" spellcheck="false" autocomplete="off"></textarea></label>
      {/if}
      {#if needsNew}
        <Field label={mode === 'set' ? t('backupPasswordSheet.title') : t('backupKeySheet.new')} type="password" bind:value={first}
          autofocus={mode === 'set'} autocomplete="new-password" />
        <Field label={mode === 'set' ? t('backupPasswordSheet.again') : t('backupKeySheet.again')} type="password" bind:value={second}
          autocomplete="new-password" />
      {/if}
    </div>
    {#if mode === 'change'}
      <label class="check"><input type="checkbox" bind:checked={relock} /> {t('backupKeySheet.relock')}</label>
      <p class="note">{t('backupKeySheet.relockNote')}</p>
    {/if}
    {#if mode === 'remove'}
      <button type="button" class="linkish" onclick={() => { withPhrase = !withPhrase; wipe(); }}>
        {withPhrase ? t('backupKeySheet.usePassword') : t('backupKeySheet.usePhrase')}</button>
    {/if}
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label={t('common.cancel')} onclick={() => onclose(false)} />
      <Button type="submit" variant="primary" label={mode === 'remove' ? t('backupKey.removeBtn') : t('common.save')} busy={busy} busyLabel={t('common.saving')} />
    </footer>
  </form>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 45; background: var(--scrim); display: grid; place-items: center; }
  .sheet { width: min(500px, calc(100% - 32px)); border-radius: 18px; padding: 18px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .note { margin: 0; color: var(--text-muted); font-size: 12.5px; }
  .phrase { display: grid; gap: 4px; padding: 8px 12px; font-size: 13px; }
  textarea { font: inherit; color: var(--text); background: var(--group); border: 1px solid var(--separator); border-radius: 8px;
    padding: 6px 8px; resize: vertical; user-select: text; }
  .check { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  .linkish { justify-self: start; border: 0; background: none; padding: 0; color: var(--link); cursor: pointer; font: inherit; font-size: 12.5px; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
