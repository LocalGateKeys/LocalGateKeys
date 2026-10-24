<script>
  /** Windows Hello and camera verification for this profile: status, set up, remove. */
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import CameraView from './CameraView.svelte';
  import PhraseCard from './PhraseCard.svelte';

  let { onclose, startHello = false } = $props();
  let hello = $state(null);
  let face = $state(null);
  let busy = $state('');
  let message = $state('');
  // Removing camera verification with a recovery phrase replaces the phrase: the new one is shown once here.
  let card = $state(null);
  let phraseNotes = $state([]);
  let started = false;

  async function load() {
    const [h, f] = await Promise.all([call('hello_status'), call('face_status')]);
    if (okOrToast(h, 'Could not read Windows Hello')) hello = h;
    if (okOrToast(f, 'Could not read camera verification')) face = f;
  }

  async function run(method, kind) {
    if (busy) return;
    busy = kind;
    message = '';
    const result = await call(method);
    busy = '';
    if (result.ok) {
      message = result.message;
      if (result.phrase_card) {
        card = result.phrase_card;
        phraseNotes = Array.isArray(card.notes) ? card.notes.filter((n) => typeof n === 'string' && n) : [];
      }
    } else if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error');
    else if (result.error.message !== 'Cancelled.') message = result.error.message;
    load();
  }

  $effect(() => {
    load().then(() => { if (startHello && !started) { started = true; run('hello_enable', 'hello'); } });
  });

  async function autoStart(event) {
    const result = await call('hello_auto_start', event.currentTarget.checked);
    if (okOrToast(result, 'Not saved')) hello = { ...hello, auto_start: result.auto_start };
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Unlocking">
  <header>
    <h2>Unlocking</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if message}<p class="summary" role="status">{message}</p>{/if}
  {#if phraseNotes.length}
    <ul class="phrase-notes" aria-label="What changed with the new recovery phrase">
      {#each phraseNotes as note, i (i)}<li>{note}</li>{/each}
    </ul>
  {/if}
  {#if card}
    {#key card.token}<PhraseCard {card} ondone={(text) => { card = null; if (text) message = text; }} />{/key}
  {:else if hello}
    <div class="section-label">Windows Hello</div>
    <div class="group card">
      <p class="status {hello.tone}">{hello.status}</p>
      {#if hello.supported}
        <p class="note">{hello.guidance}</p>
        {#if busy === 'hello'}<p class="note" role="status">Complete the Windows Security prompt(s). Setup also tests that silent unlocking is refused.</p>{/if}
        <label class="toggle"><input type="checkbox" checked={hello.auto_start} onchange={autoStart} /> Start Windows Hello automatically on the unlock screen</label>
        <p class="note">Open Windows Settings &gt; Accounts &gt; Sign-in options on your Windows PC to manage face, fingerprint or PIN.</p>
        <footer>
          {#if hello.enabled || hello.incomplete}<Button label="Remove" variant="danger" onclick={() => run('hello_disable', 'hello')} disabled={!!busy} />{/if}
          {#if !hello.enabled}<Button label="Enable for this profile" variant="primary" busy={busy === 'hello'} busyLabel="Waiting for Windows…" onclick={() => run('hello_enable', 'hello')} disabled={!!busy || hello.incomplete} />{/if}
        </footer>
      {/if}
    </div>
  {/if}
  {#if face && !card}
    <div class="section-label">Camera verification</div>
    <div class="group card">
      <p class="status {face.tone}">{face.status}</p>
      {#if face.supported}
        <p class="note">An ordinary webcam with local face matching. A convenience, not hardware-backed authentication; Windows Hello is stronger when your PC supports it.</p>
        <footer>
          {#if face.enabled || face.incomplete}<Button label="Remove" variant="danger" onclick={() => run('face_disable', 'face')} disabled={!!busy} />{/if}
          {#if !face.enabled}<Button label="Set up camera verification" variant="primary" onclick={() => run('face_enable', 'face')} disabled={!!busy || face.incomplete} />{/if}
        </footer>
      {/if}
    </div>
  {/if}
</div>
{#if busy === 'face'}<CameraView title="Set up camera verification" mode="enroll" />{/if}

<style>
  .sheet {
    position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent);
  }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .card { padding: 14px; display: grid; gap: 8px; }
  .status { margin: 0; font-weight: 600; }
  .status.success { color: #34C759; }
  .status.danger { color: var(--danger); }
  .note { margin: 0; color: var(--text-muted); font-size: 12.5px; white-space: pre-line; }
  .summary { padding: 8px 12px; border-radius: 10px; background: color-mix(in srgb, var(--accent) 14%, transparent); }
  .phrase-notes { margin: 0; padding: 8px 12px 8px 28px; border-radius: 10px; font-size: 12.5px;
    background: color-mix(in srgb, var(--warning) 14%, transparent); display: grid; gap: 4px; }
  .toggle { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
