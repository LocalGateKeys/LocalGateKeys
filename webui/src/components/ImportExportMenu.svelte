<script>
  /** The sidebar's Import & export entry: three choices, like the classic pop-up menu.
   * Restore phone backup stays hidden until a phone app writes backups (phoneBackup). */
  let { onpick, onclose, phoneBackup = false } = $props();
  const ALL_CHOICES = [
    { route: 'import', label: 'Import passwords & items…', detail: 'From another password manager, a browser or a CSV file' },
    { route: 'export', label: 'Export…', detail: 'Write a copy of this profile to a file you choose' },
    { route: 'transfer', label: 'Encrypted transfer…', detail: 'Move items to another LocalGateKeys profile or PC' },
    { route: 'phone-backup', label: 'Restore phone backup…', detail: 'Bring back items from an Android or iPhone backup file' },
  ];
  const CHOICES = $derived(ALL_CHOICES.filter((c) => phoneBackup || c.route !== 'phone-backup'));
</script>

<div class="scrim" role="presentation" onclick={onclose}>
  <div class="menu glass" role="menu" aria-label="Import & export" tabindex="-1" onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => { if (e.key === 'Escape') onclose(); }}>
    {#each CHOICES as c (c.route)}
      <button role="menuitem" onclick={() => onpick(c.route)}><strong>{c.label}</strong><span>{c.detail}</span></button>
    {/each}
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 40; background: var(--scrim); display: grid; place-items: center; }
  .menu { width: min(420px, calc(100% - 32px)); border-radius: 16px; padding: 8px; display: grid; gap: 2px;
    background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  button { display: grid; text-align: left; gap: 2px; background: none; border: none; color: inherit; padding: 10px 12px; border-radius: 10px; cursor: pointer; }
  button:hover, button:focus-visible { background: var(--group); }
  span { color: var(--text-muted); font-size: 12px; }
</style>
