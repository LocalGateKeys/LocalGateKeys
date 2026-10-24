<script>
  /** Backup & restore: create, verify, restore as a new profile, test restore, recovery kit, recovery phrase.
   *  Every file is chosen in a Windows dialog opened by LocalGateKeys; passwords are cleared after each call. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
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

  const FORMS = {
    create: { title: 'Create backup', text: 'Choose a separate backup password. The vault password is used to check that the saved copy can be opened.' },
    verify: { title: 'Verify backup', text: 'Verification does not change your profile.' },
    restore: { title: 'Restore backup', text: 'Both passwords are needed to open this encrypted backup.' },
    test: { title: 'Test a restore', text: 'Both passwords are needed to open this encrypted backup.' },
    trial: { title: 'Verify test profile', text: 'This checks that the restored profile can be opened.' },
    phrase: { title: 'Recovery phrase', text: '' },
  };

  async function load() {
    const result = await call('backup_status');
    if (okOrToast(result, 'Could not open Backup & restore')) status = result;
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

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Backup & restore">
  <header>
    <h2>Backup &amp; restore</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if status}
    <p class="note">{status.intro}</p>
    {#if summary}<p class="summary" role="status">{summary}</p>{/if}
    {#if phraseNotes.length}
      <ul class="phrase-notes" aria-label="What changed with the new recovery phrase">
        {#each phraseNotes as note, i (i)}<li>{note}</li>{/each}
      </ul>
    {/if}
    {#if card}
      {#key card.token}<PhraseCard {card} ondone={cardDone} />{/key}
    {:else if form}
      <form class="group form" onsubmit={submit} aria-label={FORMS[form].title}>
        <h3>{FORMS[form].title}</h3>
        <p class="note">{form === 'phrase' ? status.phrase_intro : FORMS[form].text}</p>
        {#if form === 'restore'}<Field label="Name for the restored profile" bind:value={v.name} />{/if}
        {#if form !== 'trial' && form !== 'phrase'}
          <Field label="Backup password" type="password" bind:value={v.backup} autofocus />
        {/if}
        {#if form === 'create'}<Field label="Confirm backup password" type="password" bind:value={v.confirm} />{/if}
        <Field label={form === 'create' || form === 'phrase' ? 'Vault password' : 'Vault password from when the backup was made'}
               type="password" bind:value={v.vault} />
        {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
        <footer>
          <Button label="Cancel" onclick={() => { form = null; wipe(); }} />
          <Button type="submit" variant="primary" label={form === 'create' || form === 'phrase' ? 'Continue' : 'Choose backup…'} busy={busy} busyLabel="Working…" />
        </footer>
      </form>
    {:else}
      <div class="section-label">Backups</div>
      <div class="group">
        <div class="row"><div class="text">Create a backup<div class="meta">An encrypted file with your items and settings</div></div>
          <Button label="Create…" disabled={!status.can_create} onclick={() => open('create')} /></div>
        <div class="row"><div class="text">Verify a backup<div class="meta">Check that a backup opens</div></div>
          <Button label="Verify…" onclick={() => open('verify')} /></div>
        <div class="row"><div class="text">Restore as a new profile<div class="meta">Your existing profiles stay unchanged</div></div>
          <Button label="Restore…" onclick={() => open('restore')} /></div>
      </div>
      {#if status.can_create}
        <div class="section-label">Recovery drill</div>
        <div class="group">
          <div class="row"><div class="text">Test a restore<div class="meta">Opens a temporary copy in an isolated place</div></div>
            <Button label="Test…" onclick={() => open('test')} /></div>
          <div class="row"><div class="text">Verify the test profile</div>
            <Button label="Verify…" disabled={!status.trial} onclick={() => open('trial')} /></div>
          <div class="row"><div class="text">Write recovery kit<div class="meta">Keep it with your encrypted backup</div></div>
            <Button label="Write kit…" disabled={!status.kit_ready} onclick={kit} /></div>
          {#if status.trial}<div class="row"><div class="text">Discard the test copy</div><Button label="Cancel test" onclick={cancelTrial} /></div>{/if}
        </div>
        <div class="section-label">Recovery phrase</div>
        <div class="group">
          <div class="row"><div class="text">{status.phrase_enrolled ? 'A recovery phrase is set up' : 'No recovery phrase yet'}
            <div class="meta">{status.phrase_intro}</div></div>
            <Button label={status.phrase_enrolled ? 'Replace…' : 'Create…'} onclick={() => open('phrase')} /></div>
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
