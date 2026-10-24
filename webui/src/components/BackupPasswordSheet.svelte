<script>
  /** Set the scheduled-backup password (kept only inside the encrypted vault). Cleared from the page after every try. */
  import ErrorLogLink from './ErrorLogLink.svelte';
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

<div class="scrim" role="dialog" aria-modal="true" aria-label="Backup password">
  <form class="sheet glass" onsubmit={submit}>
    <h2>Backup password</h2>
    <p class="note">Choose a backup password for scheduled backups (at least 12 characters).</p>
    <p class="note">Write it down or remember it: restoring after a disk failure needs it, and the copy kept inside the vault is lost with the disk.</p>
    <div class="group">
      <Field label="Backup password" type="password" bind:value={first} autofocus autocomplete="new-password" />
      <Field label="Enter the backup password again" type="password" bind:value={second} autocomplete="new-password" />
    </div>
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label="Cancel" onclick={() => onclose(false)} />
      <Button type="submit" variant="primary" label="Save" busy={busy} busyLabel="Saving…" />
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
