<script>
  /** After an import: what landed per kind (counted in the vault), passkeys, fields, duplicates, what was not
      brought over by name with a "mark as checked" list, and Undo of the whole import. */
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { call } from '../lib/api.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { report, ondone } = $props();
  let checked = $state(new Set());
  let busy = $state(false);
  let undone = $state(false);
  let error = $state('');

  function toggle(key) {
    const next = new Set(checked);
    if (next.has(key)) next.delete(key); else next.add(key);
    checked = next;
  }
  async function undo() {
    if (busy || !report.undo) return;
    busy = true; error = '';
    const r = await call('import_undo', report.undo);
    busy = false;
    if (r.ok) { undone = true; toast(r.message); return; }
    if (r.error.code !== 'cancelled') error = r.error.message;
  }
  const n = (value) => formatNumber(value ?? 0);
</script>

<section class="report" aria-label={t('switchReport.title')}>
  <p class="summary">{report.toast}</p>
  <div class="group" role="list" aria-label={t('switchReport.kinds')}>
    {#each report.kinds as row (row.kind)}
      <div class="row" role="listitem"><span>{row.label}</span><b>{n(row.count)}</b></div>
    {:else}
      <div class="row muted" role="listitem">{t('switchReport.nothingAdded')}</div>
    {/each}
    {#if report.updated}<div class="row" role="listitem"><span>{t('switchReport.updated')}</span><b>{n(report.updated)}</b></div>{/if}
  </div>
  <div class="group">
    <div class="row"><span>{t('switchReport.passkeys')}</span><b>{t('switchReport.passkeysCounts', { imported: n(report.passkeys.imported), skipped: n(report.passkeys.skipped) })}</b></div>
    <div class="row"><span>{t('switchReport.attachments')}</span><b>{n(report.attachments)}</b></div>
    <div class="row"><span>{t('switchReport.fields')}</span><b>{t('switchReport.fieldsCounts', { kept: n(report.fields.kept), split: n(report.fields.split), moved: n(report.fields.moved), dropped: n(report.fields.dropped) })}</b></div>
    <div class="row"><span>{t('switchReport.duplicates')}</span><b>{n(report.duplicates)}</b></div>
  </div>
  {#if report.not_carried.length || report.notes.length}
    <div class="section-label">{t('switchReport.check')}</div>
    <div class="group checks" role="group" aria-label={t('switchReport.check')}>
      {#each report.not_carried as row (row.row)}
        <label class="row" class:done={checked.has(`r${row.row}`)}><input type="checkbox" checked={checked.has(`r${row.row}`)} onchange={() => toggle(`r${row.row}`)} />
          <span>{row.name}</span><em>{row.reason}</em></label>
      {/each}
      {#each report.notes as note, i (i)}
        <label class="row" class:done={checked.has(`n${i}`)}><input type="checkbox" checked={checked.has(`n${i}`)} onchange={() => toggle(`n${i}`)} /><span>{note}</span></label>
      {/each}
    </div>
    <p class="muted">{t('switchReport.markHint')}</p>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <footer>
    {#if report.undo && !undone}<Button label={t('switchReport.undo')} busy={busy} busyLabel={t('switchReport.undoing')} onclick={undo} />{/if}
    <Button label={t('switchReport.done')} variant="primary" onclick={ondone} />
  </footer>
</section>

<style>
  .report { display: flex; flex-direction: column; gap: 8px; }
  .summary { margin: 0; font-weight: 600; }
  .row { display: flex; align-items: center; gap: 10px; padding: 8px 14px; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row span { flex: 1; }
  .row em { color: var(--text-muted); font-style: normal; font-size: 12px; }
  .row.done span { text-decoration: line-through; color: var(--text-muted); }
  .checks { max-height: 260px; overflow-y: auto; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
