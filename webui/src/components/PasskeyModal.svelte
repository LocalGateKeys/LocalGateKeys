<script>
  /** Passkey save / sign-in approval, for a request from the browser extension. Copy comes from Python. */
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
  const text = $derived(request.text);
  const many = $derived(request.mode === 'get' && request.accounts.length > 1);
  let picked = $state(null);

  function approve() {
    if (!ready) return;
    const itemId = request.mode === 'get' ? (many ? picked : request.accounts[0]?.item_id ?? null) : null;
    onanswer({ choice: 'approve', item_id: itemId });
  }
  function keys(event) { if (event.key === 'Escape') { event.preventDefault(); onanswer({ choice: 'cancel' }); } }
</script>

<svelte:window onkeydown={keys} />

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-label={text.title}>
    <h2>{text.title}</h2>
    <p class="body">{text.body}</p>
    {#if many}
      <div class="group accounts" role="radiogroup" aria-label="Accounts">
        {#each request.accounts as a (a.item_id)}
          <label><input type="radio" name="passkey-account" value={a.item_id} bind:group={picked} /> {a.title || a.user_name}</label>
        {/each}
      </div>
    {/if}
    <footer>
      <Button label={text.cancel_label} onclick={() => onanswer({ choice: 'cancel' })} />
      <Button label={text.browser_label} onclick={() => onanswer({ choice: 'browser' })} />
      <Button label={text.approve_label} variant="primary" disabled={!ready || (many && !picked)} onclick={approve} />
    </footer>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 70; background: var(--scrim); display: grid; place-items: center; }
  .card { width: min(480px, calc(100% - 32px)); border-radius: 18px; padding: 20px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .body { margin: 0; white-space: pre-line; color: var(--text-muted); user-select: text; }
  .accounts { padding: 8px 12px; display: grid; gap: 6px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
</style>
