<script>
  /** Right-click / Shift+F10 menu for one item; entries mirror shell/item_menu.py. */
  let { item, at, onpick, onclose } = $props();

  const entries = $derived.by(() => {
    const login = item.ref.source === 'credential';
    const rows = [];
    if (login) {
      rows.push(['Edit', 'edit'], null, ['Copy username', 'copy-username'], ['Copy password', 'copy-password'],
        ['Copy 2FA code', 'copy-totp']);
      if (item.ref.kind === 'web' && item.target) rows.push(['Open website', 'open-website']);
    } else {
      rows.push(['Open', 'open']);
    }
    rows.push(null, [item.favorite ? 'Remove from favorites' : 'Add to favorites', 'favorite'], null,
      ['Move to trash…', 'trash']);
    return rows;
  });

  let menu = $state();
  $effect(() => { menu?.querySelector('button')?.focus(); });

  function key(event) {
    const buttons = [...menu.querySelectorAll('button')];
    const at = buttons.indexOf(document.activeElement);
    if (event.key === 'Escape') { event.preventDefault(); onclose(); }
    if (event.key === 'ArrowDown') { event.preventDefault(); buttons[(at + 1) % buttons.length]?.focus(); }
    if (event.key === 'ArrowUp') { event.preventDefault(); buttons[(at - 1 + buttons.length) % buttons.length]?.focus(); }
  }
</script>

<svelte:window onclick={onclose} />

<div class="menu glass" role="menu" tabindex="-1" bind:this={menu} style:left="{at.x}px" style:top="{at.y}px"
  onkeydown={key} onclick={(e) => e.stopPropagation()}>
  {#each entries as entry, i (i)}
    {#if entry}
      <button role="menuitem" onclick={() => { onpick(entry[1]); onclose(); }}>{entry[0]}</button>
    {:else}
      <hr />
    {/if}
  {/each}
</div>

<style>
  .menu { position: fixed; z-index: 40; min-width: 200px; border-radius: 12px; padding: 5px; display: grid; }
  button { text-align: left; background: none; border: none; padding: 7px 12px; border-radius: 7px; cursor: pointer; }
  button:hover, button:focus { background: var(--glass-hover); outline: none; }
  hr { border: none; border-top: 1px solid var(--separator); margin: 4px 6px; }
</style>
