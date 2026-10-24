<script>
  /** Quiet tinted surface for content rows, with an optional section label. */
  let { label = '', children } = $props();
</script>

{#if label}<div class="section-label">{label}</div>{/if}
<div class="group">{@render children?.()}</div>

<style>
  .group :global(> * + *) { border-top: 1px solid var(--separator); }
</style>
