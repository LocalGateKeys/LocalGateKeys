<script>
  /** New item chooser (groups and order from shell/new_item.py). */

  let { onchoose, onclose } = $props();

  const GROUPS = [
    ['Sign-ins', [['web', 'Website login'], ['desktop', 'Desktop app login'], ['passkey', 'Passkey']]],
    ['Money', [['card', 'Payment card'], ['bank_account', 'Bank account']]],
    ['Personal', [['identity', 'Identity'], ['note', 'Secure note'], ['document', 'Document']]],
    ['Tech', [['ssh_key', 'SSH key'], ['api_key', 'API key'], ['wifi', 'Wi-Fi network'], ['bookmark', 'Bookmark']]],
    ['Things you own', [['license', 'License'], ['subscription', 'Subscription'], ['warranty', 'Warranty'], ['purchase', 'Purchase']]],
  ];
  let filter = $state('');
  const flat = GROUPS.flatMap(([, kinds]) => kinds);
  const visible = $derived(filter ? flat.filter(([, label]) => label.toLowerCase().includes(filter.toLowerCase())) : null);

  function choose(kind) {
    onchoose(kind);
  }

  function key(event) {
    if (event.key === 'Escape') { event.preventDefault(); onclose(); return; }
    if (/^[1-9]$/.test(event.key) && !filter) { const pick = flat[+event.key - 1]; if (pick) choose(pick[0]); return; }
    if (event.key === 'Backspace') { filter = filter.slice(0, -1); return; }
    if (event.key.length === 1 && /\S/.test(event.key)) filter += event.key;
  }
</script>

<svelte:window onkeydown={key} />

<div class="scrim" role="presentation" onclick={onclose}>
  <div class="card glass" role="dialog" aria-modal="true" aria-label="New item" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
    <h2>New item</h2>
    <p class="hint">{filter ? `Showing kinds matching "${filter}". Backspace to clear, Esc to close.` : 'Press a number key, or start typing a name.'}</p>
    {#if visible}
      <div class="grid">{#each visible as [kind, label] (kind)}<button onclick={() => choose(kind)}>{label}</button>{/each}</div>
    {:else}
      {#each GROUPS as [name, kinds] (name)}
        <div class="section-label">{name}</div>
        <div class="grid">{#each kinds as [kind, label] (kind)}<button class="ready" onclick={() => choose(kind)}>{label}</button>{/each}</div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; background: var(--scrim); z-index: 45; display: grid; place-items: center; }
  .card { width: min(640px, calc(100vw - 40px)); border-radius: 18px; padding: 18px 20px; }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .hint { color: var(--text-muted); margin: 4px 0 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 6px; }
  .grid button { text-align: left; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--glass-border); background: var(--group); cursor: pointer; }
  .grid button:hover { background: var(--glass-hover); }
  .grid button:not(.ready) { color: var(--text-muted); }
</style>
