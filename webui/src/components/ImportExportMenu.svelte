<script>
  /** The sidebar's Import & export entry: import, export, transfer and incoming shared items.
   * Restore phone backup stays hidden until a phone app writes backups (phoneBackup). */
  import { t } from '../lib/i18n.svelte.js';

  let { onpick, onclose, phoneBackup = false, page = false } = $props();
  const ALL_CHOICES = [
    { route: 'import', label: 'importExportMenu.importLabel', detail: 'importExportMenu.importDetail' },
    { route: 'export', label: 'importExportMenu.exportLabel', detail: 'importExportMenu.exportDetail' },
    { route: 'transfer', label: 'importExportMenu.transferLabel', detail: 'importExportMenu.transferDetail' },
    { route: 'incoming', label: 'importExportMenu.incomingLabel', detail: 'importExportMenu.incomingDetail' },
    { route: 'phone-backup', label: 'importExportMenu.phoneLabel', detail: 'importExportMenu.phoneDetail' },
  ];
  const CHOICES = $derived(ALL_CHOICES.filter((c) => phoneBackup || c.route !== 'phone-backup'));
</script>

{#if page}
<div class="sheet glass" role="region" aria-label={t('importExportMenu.page')}>
  <header><h2>{t('importExportMenu.title')}</h2><button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button></header>
  <div class="menu page-menu" role="menu" aria-label={t('importExportMenu.title')} tabindex="-1">
    {#each CHOICES as c (c.route)}
      <button role="menuitem" onclick={() => onpick(c.route)}><strong>{t(c.label)}</strong><span>{t(c.detail)}</span></button>
    {/each}
  </div>
</div>
{:else}
<div class="scrim" role="presentation" onclick={onclose}>
  <div class="menu glass" role="menu" aria-label={t('importExportMenu.title')} tabindex="-1" onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => { if (e.key === 'Escape') onclose(); }}>
    {#each CHOICES as c (c.route)}
      <button role="menuitem" onclick={() => onpick(c.route)}><strong>{t(c.label)}</strong><span>{t(c.detail)}</span></button>
    {/each}
  </div>
</div>
{/if}

<style>
  .sheet { position: absolute; inset: 10px; z-index: 30; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    display: flex; flex-direction: column; gap: 8px; background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .page-menu { width: auto; background: none; padding: 0; }
  .scrim { position: fixed; inset: 0; z-index: 40; background: var(--scrim); display: grid; place-items: center; }
  .menu { width: min(420px, calc(100% - 32px)); border-radius: 16px; padding: 8px; display: grid; gap: 2px;
    background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  button { display: grid; text-align: left; gap: 2px; background: none; border: none; color: inherit; padding: 10px 12px; border-radius: 10px; cursor: pointer; }
  button:hover, button:focus-visible { background: var(--group); }
  span { color: var(--text-muted); font-size: 12px; }
</style>
