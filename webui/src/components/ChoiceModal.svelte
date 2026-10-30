<script>
  /** Two prompt kinds from Python: pick one account ("choose"), or confirm with an optional "remember" box. */
  import { t } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';

  let { request, onanswer, guardMs = 0 } = $props();

  // A trusted prompt (the popup) arms its approve button only after guardMs, so a
  // keystroke or click aimed at the app underneath never approves it by accident.
  let armed = $state(false);
  const ready = $derived(!guardMs || armed);
  $effect(() => {
    if (!guardMs) return undefined;
    const timer = setTimeout(() => { armed = true; }, guardMs);
    return () => clearTimeout(timer);
  });
  let picked = $state(null);
  let remember = $state(false);
  const choosing = $derived(request.kind === 'choose');

  function cancel() { onanswer(choosing ? null : { approved: false, remember: false }); }
  function accept() { if (ready) onanswer(choosing ? picked : { approved: true, remember }); }
  function keys(event) { if (event.key === 'Escape') { event.preventDefault(); cancel(); } }
</script>

<svelte:window onkeydown={keys} />

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-label={request.title}>
    <h2>{request.title}</h2>
    {#if request.message}<p class="body">{request.message}</p>{/if}
    {#if choosing}
      <div class="group options" role="radiogroup" aria-label={request.title}>
        {#each request.options as o (o.id)}
          <label><input type="radio" name="choice" value={o.id} bind:group={picked} />
            <span>{o.label}</span>{#if o.detail}<span class="muted">{' · '}{o.detail}</span>{/if}</label>
        {/each}
      </div>
    {:else if request.remember_label}
      <label class="remember"><input type="checkbox" bind:checked={remember} /> {request.remember_label}</label>
    {/if}
    <footer>
      <Button label={t('common.cancel')} onclick={cancel} />
      <Button label={choosing ? t('choiceModal.useAccount') : t('choiceModal.fill')} variant="primary" disabled={!ready || (choosing && !picked)} onclick={accept} />
    </footer>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 70; background: var(--scrim); display: grid; place-items: center; }
  .card { width: min(520px, calc(100% - 32px)); border-radius: 18px; padding: 20px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .body { margin: 0; white-space: pre-line; color: var(--text-muted); user-select: text; }
  .options { padding: 8px 12px; display: grid; gap: 6px; }
  .muted { color: var(--text-muted); }
  .remember { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
