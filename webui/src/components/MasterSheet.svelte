<script>
  /** Change the master password: one form, one call; the vault locks afterwards. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let needsPhrase = $state(false);
  let current = $state('');
  let next = $state('');
  let again = $state('');
  let phrase = $state('');
  let busy = $state(false);
  let error = $state('');

  $effect(() => () => wipe());

  $effect(() => {
    call('master_info').then((r) => { if (okOrToast(r)) needsPhrase = r.needs_phrase; else onclose(); });
  });

  function wipe() { current = ''; next = ''; again = ''; phrase = ''; }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    if (next !== again) { error = 'The new passwords did not match.'; return; }
    busy = true; error = '';
    const result = await call('master_change', current, next, again, needsPhrase ? phrase : null);
    busy = false;
    // Never keep passwords in the page after a call, whatever the outcome.
    wipe();
    if (result.ok) {
      for (const note of result.notes) toast(note.title, note.text);
      onclose();
      return;
    }
    if (result.error.code !== 'cancelled') error = result.error.message;
  }
</script>

<div class="scrim" role="dialog" aria-modal="true" aria-label="Change master password">
  <form class="sheet glass" onsubmit={submit}>
    <h2>Change master password</h2>
    <div class="group">
      <Field label="Current master password" type="password" bind:value={current} autofocus autocomplete="current-password" />
      <Field label="New master password (at least 12 characters)" type="password" bind:value={next} autocomplete="new-password" />
      <Field label="Enter the new password again" type="password" bind:value={again} autocomplete="new-password" />
    </div>
    {#if needsPhrase}
      <p class="note">The vault is re-encrypted with a new key. Enter your 24-word recovery phrase to keep it working, or leave this blank and create a new phrase afterwards:</p>
      <div class="group"><Field label="Recovery phrase" type="password" bind:value={phrase} /></div>
    {/if}
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label="Cancel" onclick={() => { wipe(); onclose(); }} />
      <Button type="submit" variant="primary" label="Change password" busy={busy} busyLabel="Re-encrypting…" />
    </footer>
  </form>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 45; background: var(--scrim); display: grid; place-items: center; }
  .sheet { width: min(520px, calc(100% - 32px)); border-radius: 18px; padding: 18px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .note { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
