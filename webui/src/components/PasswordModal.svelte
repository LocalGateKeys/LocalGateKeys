<script>
  /** Master-password re-authentication asked by Python (modal kind "password"). */
  import Button from './Button.svelte';

  let { title, message = '', onanswer } = $props();
  let value = $state('');
  let input = $state();
  $effect(() => { input?.focus(); });

  function submit(event) {
    event.preventDefault();
    const answer = value;
    value = '';
    onanswer(answer || null);
  }

  function cancel() {
    value = '';
    onanswer(null);
  }
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') { e.preventDefault(); cancel(); } }} />

<div class="scrim" role="dialog" aria-modal="true" aria-label={title}>
  <form class="card glass" onsubmit={submit}>
    <h2>{title}</h2>
    {#if message}<p class="message">{message}</p>{/if}
    <div class="group">
      <input bind:this={input} type="password" bind:value aria-label="Master password" autocomplete="current-password" />
    </div>
    <div class="actions">
      <Button label="Cancel" onclick={cancel} />
      <Button label="Confirm" variant="primary" type="submit" />
    </div>
  </form>
</div>

<style>
  .scrim { position: fixed; inset: 0; display: grid; place-items: center; background: var(--scrim); z-index: 55; }
  .card { width: min(420px, calc(100vw - 48px)); border-radius: var(--radius-card); padding: 20px; }
  h2 { margin: 0 0 6px; font: 600 17px var(--font-display); }
  .message { margin: 0 0 12px; color: var(--text-muted); white-space: pre-line; }
  input { width: 100%; padding: 11px 14px; background: none; border: none; outline: none; user-select: text; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }
</style>
