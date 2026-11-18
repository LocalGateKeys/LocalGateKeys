<script>
  /** Item history (kept on this device only): earlier versions, a field-level diff against now, restore one field. */
  import { dialog } from '../lib/dialog.js';
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { historyError, historyFieldLabel, historyLabel } from '../lib/featurePack.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { selected, onclose, onrestored = undefined } = $props();
  let data = $state(null);
  let open = $state(null); // snapshot_id whose diff is showing
  let fields = $state(null);
  let confirming = $state(null); // field name waiting for "Restore {field} from this version?"
  const titleId = `h-${Math.random().toString(36).slice(2, 9)}`;
  const PROTECTED = '[protected]';

  async function load() {
    const result = await call('item_history_list', selected);
    if (okOrToast(result)) data = result; else onclose();
  }
  $effect(() => { load(); });

  async function showDiff(row, reveal = false) {
    const result = await call('item_history_diff', selected, row.snapshot_id, reveal);
    if (!okOrToast(result)) return;
    open = row.snapshot_id;
    fields = result.fields;
    confirming = null;
  }

  async function restore(field) {
    const snapshot = open;
    const result = await call('item_history_restore_field', selected, snapshot, field);
    confirming = null;
    if (!result.ok) {
      if (result.error?.code !== 'cancelled') toast(historyError(result.error), '', 'error');
      return;
    }
    toast(t('history.restored', { field: historyFieldLabel(field) }));
    onrestored?.();
    await load();
    const row = data?.rows.find((r) => r.snapshot_id === snapshot);
    if (row) await showDiff(row); else { open = null; fields = null; }
  }

  const shown = (value) => (value === PROTECTED ? t('history.protected') : (value ?? '—'));
</script>

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-labelledby={titleId} use:dialog={{ onescape: onclose }}>
    <header>
      <h2 id={titleId}>{t('history.title')}</h2>
      <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
    </header>
    <p class="hint">{t('history.deviceOnly')}</p>
    {#if data && !data.pro}<p class="hint">{t('history.freeWindow')}</p>{/if}
    {#if data}
      {#if !data.rows.length}
        <p class="muted">{t('history.empty')}</p>
      {:else}
        <div class="group list">
          {#each data.rows as row (row.snapshot_id)}
            <button class="row" class:on={open === row.snapshot_id} aria-expanded={open === row.snapshot_id}
              onclick={() => showDiff(row)}>{historyLabel(row)}</button>
            {#if open === row.snapshot_id && fields}
              <table class="diff">
                <thead><tr><th>{t('history.field')}</th><th>{t('history.before')}</th><th>{t('history.after')}</th><th></th></tr></thead>
                <tbody>
                  {#each fields as f (f.field)}
                    <tr>
                      <td>{historyFieldLabel(f.field)}</td>
                      <td class="v">{shown(f.before)}</td>
                      <td class="v">{shown(f.after)}</td>
                      <td class="acts">
                        {#if f.secret && (f.before === PROTECTED || f.after === PROTECTED)}
                          <button class="text-btn" onclick={() => showDiff(row, true)}>{t('history.reveal')}</button>
                        {/if}
                        {#if f.restorable}
                          {#if confirming === f.field}
                            <span class="confirm">{t('history.restoreConfirm', { field: historyFieldLabel(f.field) })}</span>
                            <Button label={t('history.restoreField')} variant="primary" onclick={() => restore(f.field)} />
                            <button class="text-btn" onclick={() => (confirming = null)}>{t('common.cancel')}</button>
                          {:else}
                            <button class="text-btn" onclick={() => (confirming = f.field)}>{t('history.restoreField')}</button>
                          {/if}
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          {/each}
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; display: grid; place-items: center; background: var(--scrim); z-index: 50; }
  .card { width: min(720px, calc(100vw - 48px)); max-height: calc(100vh - 64px); overflow-y: auto; border-radius: var(--radius-card); padding: 18px 20px; }
  header { display: flex; align-items: center; gap: 8px; }
  h2 { margin: 0; flex: 1; font: 600 17px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .hint { color: var(--text-faint); font-size: 12px; margin: 6px 0 0; }
  .muted { color: var(--text-muted); }
  .list { margin-top: 10px; }
  .row { display: block; width: 100%; text-align: left; background: none; border: none; color: inherit; padding: 9px 14px; cursor: pointer; font: inherit; }
  .row + .row, .diff + .row { border-top: 1px solid var(--separator); }
  .row.on { font-weight: 600; }
  .diff { width: 100%; border-collapse: collapse; font-size: 12.5px; margin: 0 0 8px; }
  .diff th { text-align: left; color: var(--text-muted); font-weight: 500; padding: 4px 14px; }
  .diff td { padding: 6px 14px; border-top: 1px solid var(--separator); vertical-align: top; }
  .v { overflow-wrap: anywhere; user-select: text; }
  .acts { white-space: nowrap; }
  .confirm { display: block; white-space: normal; margin-bottom: 4px; }
  .text-btn { background: none; border: none; color: var(--link); cursor: pointer; font-size: 12.5px; }
</style>
