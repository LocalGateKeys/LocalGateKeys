<script>
  /** The item list: icon tiles, title, username, type and target; arrow keys move the selection. */
  import ItemTile from './ItemTile.svelte';

  let { items = [], selected = null, empty = null, onselect, onopen, onmenu, onemptyaction, ontrash, oncopy } = $props();

  let list = $state();
  const index = $derived(items.findIndex((i) => selected && i.ref.id === selected.id && i.ref.source === selected.source));

  /** Keys for the list. Home also forwards them here when focus is on the page or the search box,
   *  so arrows, Enter and Ctrl+C work without clicking the list first. Returns whether it used the key. */
  export function key(event) {
    if (!items.length) return false;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      list?.focus({ preventScroll: true });
      const step = event.key === 'ArrowDown' ? 1 : -1;
      const next = index < 0 ? (step > 0 ? 0 : items.length - 1) : Math.min(items.length - 1, Math.max(0, index + step));
      onselect(items[next].ref);
      list?.querySelectorAll('[role="option"]')[next]?.scrollIntoView?.({ block: 'nearest' });
    } else if (event.key === 'Enter' && index >= 0) {
      event.preventDefault();
      onopen(items[index].ref);
    } else if (event.key === 'Delete' && index >= 0) {
      ontrash?.(items[index].ref);
    } else if ((event.key === 'c' || event.key === 'C') && event.ctrlKey && !event.shiftKey && !event.altKey && index >= 0) {
      if (window.getSelection?.()?.toString()) return false; // copying selected text wins
      event.preventDefault();
      oncopy?.(items[index].ref);
    } else if ((event.key === 'F10' && event.shiftKey) || event.key === 'ContextMenu') {
      if (index >= 0) {
        event.preventDefault();
        const row = list?.querySelectorAll('[role="option"]')[index]?.getBoundingClientRect();
        onmenu(items[index], row ? { x: row.left + 40, y: row.bottom } : { x: 200, y: 200 });
      }
    } else return false;
    return true;
  }

  const FLAG = { breached: 'Breached', weak: 'Weak', reused: 'Reused' };
</script>

{#if !items.length && empty}
  <div class="empty">
    <h2>{empty.title}</h2>
    <p>{empty.text}</p>
    {#if empty.action}<button class="link" onclick={() => onemptyaction(empty.action)}>{empty.action}</button>{/if}
  </div>
{:else}
  <div class="list group" role="listbox" tabindex="0" aria-label="Items" bind:this={list} onkeydown={key}>
    {#each items as item (item.ref.source + item.ref.id)}
      <div
        class="row"
        role="option"
        tabindex="-1"
        aria-selected={selected?.id === item.ref.id}
        onclick={() => onselect(item.ref)}
        ondblclick={() => onopen(item.ref)}
        oncontextmenu={(e) => { e.preventDefault(); onselect(item.ref); onmenu(item, { x: e.clientX, y: e.clientY }); }}
        onkeydown={() => {}}
      >
        <ItemTile kind={item.ref.kind} origin={item.origin} icon={item.icon} />
        <span class="text">
          <span class="title">{item.favorite ? '★ ' : ''}{item.title}</span>
          <span class="sub">{item.username || item.kind_label}</span>
        </span>
        <span class="meta">
          {#if item.flag}<span class="flag {item.flag}">{FLAG[item.flag]}</span>{/if}
          <span class="target">{item.target}</span>
        </span>
      </div>
    {/each}
  </div>
{/if}

<style>
  .list { margin: 0 14px; overflow-y: auto; min-height: 0; outline: none; }
  .list:focus-visible { box-shadow: 0 0 0 2px var(--link); }
  .row {
    display: flex; align-items: center; gap: 10px; padding: 8px 12px; cursor: pointer;
    border-top: 1px solid var(--separator);
  }
  .row:first-child { border-top: none; }
  .row:hover { background: var(--glass); }
  .row[aria-selected="true"] { background: var(--glass-hover); }
  .text { flex: 1; min-width: 0; display: grid; }
  .title, .sub, .target { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub { color: var(--text-muted); font-size: 12.5px; }
  .meta { display: grid; justify-items: end; max-width: 40%; font-size: 12px; color: var(--text-faint); }
  .flag { font-size: 11px; padding: 1px 7px; border-radius: 9px; background: rgba(255, 120, 100, 0.16); color: var(--danger); }
  .empty { padding: 48px 24px; text-align: center; color: var(--text-muted); }
  .empty h2 { margin: 0 0 6px; color: var(--text); font: 600 17px var(--font-display); }
  .link { background: none; border: none; color: var(--link); cursor: pointer; padding: 6px; }
</style>
