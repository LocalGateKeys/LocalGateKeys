<script>
  /** Approval dialog for a Python modal.request. Escape and Deny answer false.
   * An optional extra button (extraLabel/onextra) sits between the two, e.g. "Buy Pro".
   * guardMs > 0 (the popup): Deny takes the focus and the other buttons ignore input until guardMs passed. */
  import Button from './Button.svelte';

  let {
    title,
    message = '',
    allowLabel = 'Allow',
    denyLabel = 'Deny',
    extraLabel = '',
    onextra = undefined,
    onanswer,
    guardMs = 0,
  } = $props();

  const titleId = `m-${Math.random().toString(36).slice(2, 9)}`;
  let allowButton = $state();
  let denyButton = $state();

  // A trusted prompt (the popup) arms its approve button only after guardMs, so a
  // keystroke or click aimed at the app underneath never approves it by accident.
  let armed = $state(false);
  const ready = $derived(!guardMs || armed);
  $effect(() => {
    if (!guardMs) return undefined;
    const timer = setTimeout(() => { armed = true; }, guardMs);
    return () => clearTimeout(timer);
  });

  function onkeydown(event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      onanswer(false);
    }
  }

  $effect(() => {
    if (guardMs) denyButton?.querySelector('button')?.focus();
    else allowButton?.querySelector('button')?.focus();
  });
</script>

<svelte:window {onkeydown} />

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-labelledby={titleId}>
    <h2 id={titleId}>{title}</h2>
    {#if message}<p class="message">{message}</p>{/if}
    <div class="actions">
      {#if denyLabel}<span bind:this={denyButton}><Button label={denyLabel} onclick={() => onanswer(false)} /></span>{/if}
      {#if extraLabel}
        <Button label={allowLabel} disabled={!ready} onclick={() => { if (ready) onanswer(true); }} />
        <span bind:this={allowButton}><Button label={extraLabel} variant="primary" disabled={!ready}
          onclick={() => { if (ready) onextra?.(); }} /></span>
      {:else}
        <span bind:this={allowButton}><Button label={allowLabel} variant="primary" disabled={!ready}
          onclick={() => { if (ready) onanswer(true); }} /></span>
      {/if}
    </div>
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    background: var(--scrim);
    z-index: 50;
  }
  .card {
    width: min(440px, calc(100vw - 48px));
    border-radius: var(--radius-card);
    padding: 22px 22px 18px;
  }
  h2 { margin: 0 0 8px; font: 600 17px/1.3 var(--font-display); }
  .message { margin: 0; color: var(--text-muted); white-space: pre-line; user-select: text; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
</style>
