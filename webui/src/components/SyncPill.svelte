<script>
  /** "Synced 2 min ago · 3 devices" at the bottom of the sidebar; the dot is green, orange or red. Opens Sync status. */
  import { t } from '../lib/i18n.svelte.js';
  import { call, on } from '../lib/api.js';

  let { onopen } = $props();
  let status = $state(null);

  async function load() {
    const result = await call('sync_status');
    status = result.ok && result.state !== 'off' ? result : null;
  }
  $effect(() => {
    load();
    const offs = [on('sync.status', load)];
    const timer = setInterval(load, 60000); // keeps "2 min ago" current
    return () => { offs.forEach((off) => off()); clearInterval(timer); };
  });
  const words = { green: 'syncPill.green', orange: 'syncPill.orange', red: 'syncPill.red' };
</script>

{#if status}
  <button type="button" class="pill" onclick={onopen} title={status.text}
    aria-label={t('syncPill.aria', { text: status.text, state: words[status.colour] ? t(words[status.colour]) : '' })}>
    <span class="dot {status.colour}" aria-hidden="true"></span>
    <span class="text">{status.text}</span>
  </button>
{/if}

<style>
  .pill { display: flex; align-items: center; gap: 8px; width: 100%; margin-top: 6px; padding: 7px 10px;
    border: 1px solid var(--separator); border-radius: 999px; background: var(--glass); color: var(--text-muted);
    font-size: 12px; text-align: left; cursor: pointer; }
  .pill:hover { background: var(--glass-hover); color: var(--text); }
  .dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--text-faint); }
  .dot.green { background: var(--success); }
  .dot.orange { background: var(--warning, #d98a00); }
  .dot.red { background: var(--danger); }
  .text { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  @media (max-width: 720px) {
    .pill { justify-content: center; padding: 8px 0; }
    .text { display: none; }
  }
</style>
