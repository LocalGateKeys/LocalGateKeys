<script>
  /** Notes formatting: renders parseMarkdown nodes as elements. Never injects HTML; links are plain text. */
  let { nodes = [] } = $props();
</script>

{#snippet inline(list)}
  {#each list as n}{#if n.t === 'text'}{n.v}{:else if n.t === 'b'}<strong>{@render inline(n.c)}</strong>{:else if n.t === 'i'}<em>{@render inline(n.c)}</em>{:else if n.t === 'code'}<code>{n.v}</code>{:else if n.t === 'link'}<span class="link">{n.text} ({n.url})</span>{/if}{/each}
{/snippet}

<div class="md">
  {#each nodes as n}
    {#if n.t === 'h'}
      <svelte:element this={'h' + n.level} class="h" data-level={n.level}>{@render inline(n.c)}</svelte:element>
    {:else if n.t === 'p'}
      <p>{@render inline(n.c)}</p>
    {:else if n.t === 'ul'}
      <ul>{#each n.items as item}<li>{@render inline(item)}</li>{/each}</ul>
    {:else if n.t === 'ol'}
      <ol>{#each n.items as item}<li>{@render inline(item)}</li>{/each}</ol>
    {:else if n.t === 'todo'}
      <ul class="todo">{#each n.items as item}<li><label><input type="checkbox" disabled checked={item.done} /> <span>{@render inline(item.c)}</span></label></li>{/each}</ul>
    {:else if n.t === 'code'}
      <pre>{n.text}</pre>
    {:else if n.t === 'hr'}
      <hr />
    {/if}
  {/each}
</div>

<style>
  .md { overflow-wrap: anywhere; }
  p, pre { margin: 0 0 8px; white-space: pre-wrap; }
  .md > :last-child { margin-bottom: 0; }
  .h { margin: 8px 0 4px; font: 600 15px var(--font-display); }
  .h[data-level='1'] { font-size: 18px; }
  .h[data-level='3'] { font-size: 14px; }
  ul, ol { margin: 0 0 8px; padding-left: 22px; }
  .todo { list-style: none; padding-left: 4px; }
  code, pre { font-family: var(--font-mono); font-size: 0.92em; background: var(--glass); border-radius: 4px; }
  code { padding: 0 4px; }
  pre { padding: 8px 10px; }
  hr { border: none; border-top: 1px solid var(--separator); margin: 10px 0; }
  .link { color: var(--link); }
</style>
