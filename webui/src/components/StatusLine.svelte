<script>
  import { t } from '../lib/i18n.svelte.js';
  let { status = null } = $props();
</script>

<footer class="status">
  <span><span class="dot" aria-hidden="true">●</span> {status?.encrypted ?? t('statusLine.encrypted')}</span>
  {#if status?.autolock}<span>{status.autolock}</span>{/if}
  {#if status?.clipboard}<span>{status.clipboard}</span>{/if}
  <span class="hint">{status?.hint ?? ''}</span>
</footer>

<style>
  .status {
    display: flex; gap: 16px; align-items: center; padding: 6px 16px 8px;
    font-size: 12px; color: var(--text-faint);
  }
  .dot { color: var(--success); }
  .hint { margin-left: auto; }
</style>
