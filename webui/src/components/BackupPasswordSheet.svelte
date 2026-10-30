<script>
  /** Set the scheduled-backup password (kept only inside the encrypted vault). Cleared from the page after every try. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { t } from '../lib/i18n.svelte.js';
  import { call } from '../lib/api.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let first = $state('');
  let second = $state('');
  let error = $state('');
  let busy = $state(false);

  $effect(() => () => { first = ''; second = ''; });

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    const result = await call('backup_password_set', first, second);
    busy = false;
    first = ''; second = '';
    if (result.ok) { toast(result.message); onclose(true); return; }
    error = result.error.message;
  }
</script>

<div class="scrim" role="dialog" aria-modal="true" aria-label={t('backupPasswordSheet.title')}>
  <form class="sheet glass" onsubmit={submit}>
    <h2>{t('backupPasswordSheet.title')}</h2>
    <p class="note">{t('backupPasswordSheet.intro')}</p>
    <p class="note">{t('backupPasswordSheet.warning')}</p>
    <div class="group">
      <Field label={t('backupPasswordSheet.title')} type="password" bind:value={first} autofocus autocomplete="new-password" />
      <Field label={t('backupPasswordSheet.again')} type="password" bind:value={second} autocomplete="new-password" />
    </div>
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label={t('common.cancel')} onclick={() => onclose(false)} />
      <Button type="submit" variant="primary" label={t('common.save')} busy={busy} busyLabel={t('common.saving')} />
    </footer>
  </form>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 45; background: var(--scrim); display: grid; place-items: center; }
  .sheet { width: min(500px, calc(100% - 32px)); border-radius: 18px; padding: 18px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .note { margin: 0; color: var(--text-muted); font-size: 12.5px; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
