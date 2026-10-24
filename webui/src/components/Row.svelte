<script>
  /** One row in a Group: leading slot, title/subtitle, trailing slot. Clickable when onclick is set. */
  let { title, subtitle = '', leading, trailing, onclick = undefined, selected = false } = $props();
</script>

{#if onclick}
  <button class="row" class:selected {onclick}>
    {@render leading?.()}
    <span class="text"><span class="title">{title}</span>{#if subtitle}<span class="sub">{subtitle}</span>{/if}</span>
    {@render trailing?.()}
  </button>
{:else}
  <div class="row">
    {@render leading?.()}
    <span class="text"><span class="title">{title}</span>{#if subtitle}<span class="sub">{subtitle}</span>{/if}</span>
    {@render trailing?.()}
  </div>
{/if}

<style>
  .row {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
    min-height: 44px;
    padding: var(--row-pad);
    background: none;
    border: none;
    text-align: left;
  }
  button.row { cursor: pointer; }
  button.row:hover { background: var(--glass); }
  .selected { background: var(--glass-hover); }
  .text { display: grid; min-width: 0; flex: 1; }
  .title, .sub { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub { color: var(--text-muted); font-size: 12.5px; }
</style>
