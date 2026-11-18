<script>
  /** Export to a file: format, optional 2FA secrets, the classic warnings; KDBX needs its own password.
      CXF writes only the items ticked here (logins, notes, passkeys). */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let info = $state(null);
  let fmt = $state('kdbx');
  let totp = $state(false);
  let pw = $state('');
  let pw2 = $state('');
  let error = $state('');
  let busy = $state(false);
  let items = $state(null);
  let picked = $state(new Set());
  let coverage = $state([]);

  async function load() {
    const r = await call('export_formats', fmt, totp);
    if (okOrToast(r, t('exportSheet.couldNotOpen'))) info = r;
  }
  $effect(() => { fmt; totp; load(); });
  // Per item kind: what an export of the whole vault leaves out or carries without its file (shown before exporting).
  async function loadCoverage() {
    const r = await call('export_coverage');
    if (r && r.ok) coverage = r.lines || [];
  }
  loadCoverage();
  $effect(() => { if (fmt === 'cxf' && items === null) loadItems(); });

  async function loadItems() {
    items = [];
    const r = await call('export_items');
    if (okOrToast(r, t('exportSheet.couldNotOpen'))) items = r.items;
  }
  function toggle(id) {
    const next = new Set(picked);
    if (next.has(id)) next.delete(id); else next.add(id);
    picked = next;
  }
  function toggleAll() {
    picked = picked.size === items.length ? new Set() : new Set(items.map((i) => i.id));
  }
  $effect(() => () => { pw = ''; pw2 = ''; });

  async function run() {
    if (busy) return;
    busy = true; error = '';
    const r = fmt === 'cxf' ? await call('export_run', fmt, totp, '', '', [...picked])
      : await call('export_run', fmt, totp, pw, pw2);
    busy = false;
    pw = ''; pw2 = '';
    if (r.ok) { toast(r.title, r.message); onclose(); return; }
    if (r.error.code !== 'cancelled') error = r.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('exportSheet.export')}>
  <header>
    <h2>{t('exportSheet.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if info}
    <p class="muted">{info.intro}</p>
    <div class="group">
      <label class="row"><span>{t('exportSheet.format')}</span>
        <select aria-label={t('exportSheet.format')} bind:value={fmt}>{#each info.formats as f (f.key)}<option value={f.key}>{f.label}</option>{/each}</select>
      </label>
      <label class="row"><input type="checkbox" bind:checked={totp} /> {t('exportSheet.includeTotp')}</label>
    </div>
    {#if fmt === 'cxf' && items}
      <div class="group picks" role="group" aria-label={t('exportSheet.items')}>
        {#if items.length}
          <label class="row"><input type="checkbox" checked={picked.size === items.length} onchange={toggleAll} /> {t('exportSheet.selectAll')}</label>
          {#each items as item (item.id)}
            <label class="row"><input type="checkbox" checked={picked.has(item.id)} onchange={() => toggle(item.id)} /> {item.title} <em>{item.kind}</em></label>
          {/each}
        {:else}
          <p class="muted row">{t('exportSheet.noItems')}</p>
        {/if}
      </div>
    {/if}
    {#each info.warnings as w (w)}<p class="warn">{w}</p>{/each}
    {#if fmt !== 'cxf' && coverage.length}
      <div class="group coverage" role="group" aria-label={t('exportSheet.coverageHeading')}>
        <p class="row"><strong>{t('exportSheet.coverageHeading')}</strong></p>
        {#each coverage as line (line)}<p class="row">{line}</p>{/each}
      </div>
    {/if}
    {#if fmt === 'kdbx'}
      <div class="group">
        <Field label={t('exportSheet.kdbxPassword', { min: formatNumber(info.min_password) })} type="password" bind:value={pw} autocomplete="new-password" />
        <Field label={t('exportSheet.kdbxRepeat')} type="password" bind:value={pw2} autocomplete="new-password" />
      </div>
    {/if}
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label={t('common.cancel')} onclick={onclose} />
      <Button label={t('exportSheet.export')} variant="primary" busy={busy} busyLabel={t('exportSheet.exporting')} onclick={run}
        disabled={fmt === 'cxf' && picked.size === 0} />
    </footer>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row span { width: 80px; color: var(--text-muted); }
  select { flex: 1; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px; }
  .picks { max-height: 220px; overflow-y: auto; }
  .row em { margin-left: auto; color: var(--text-muted); font-style: normal; font-size: 12px; }
  .coverage p { margin: 0; }
  .warn { margin: 0; color: var(--warning); font-size: 12.5px; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
