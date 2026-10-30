<script>
  /** Import from another password manager: file (Python dialog) → password → columns → review → apply. */
  import { t } from '../lib/i18n.svelte.js';
  import { call, on } from '../lib/api.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let step = $state('start'); // start | password | mapping | review
  let opened = $state(null);
  let password = $state('');
  let mapping = $state({});
  let review = $state(null);
  let picked = $state([]);
  let error = $state('');
  let busy = $state(false);
  let progress = $state('');

  $effect(() => {
    const off = on('import.progress', (d) => { if (d.handle === opened?.handle) progress = d.text; });
    return () => { off(); password = ''; if (opened) call('import_close', opened.handle); };
  });

  async function start() {
    error = '';
    const r = await call('import_open');
    if (!r.ok) { if (r.error.code !== 'cancelled') error = r.error.message; return; }
    opened = r;
    mapping = Object.fromEntries((r.mapping?.targets ?? []).map((target) => [target.key, target.value]));
    step = r.needs_password ? 'password' : r.mapping ? 'mapping' : 'build';
    if (step === 'build') build();
  }

  async function build() {
    busy = true; error = '';
    const r = await call('import_plan', opened.handle, opened.needs_password ? password : null, opened.mapping ? { ...mapping } : null);
    busy = false;
    password = '';
    if (r.ok) { review = r; step = 'review'; picked = []; return; }
    error = r.error.message;
    if (r.error.code === 'wrong_password' || r.error.code === 'password_required') step = 'password';
  }

  function next(event) {
    event.preventDefault();
    if (step === 'password' && opened.mapping) { step = 'mapping'; return; }
    build();
  }

  async function decide(mode) {
    const r = await call('import_decide', opened.handle, picked, mode);
    if (r.ok) review = r; else error = r.error.message;
  }
  async function decideAll(action) {
    const r = await call('import_decide_all', opened.handle, action);
    if (r.ok) review = r; else error = r.error.message;
  }

  async function apply() {
    busy = true; error = '';
    const r = await call('import_apply', opened.handle);
    busy = false; progress = '';
    if (r.ok) { toast(r.title, r.message); opened = null; onclose(); return; }
    if (r.error.code === 'import_cancelled') { toast(r.error.message); opened = null; onclose(); return; }
    if (r.error.code !== 'cancelled') error = r.error.message;
  }

  function toggle(row) { picked = picked.includes(row) ? picked.filter((x) => x !== row) : [...picked, row]; }
  function cancel() { if (busy && step === 'review') call('import_cancel', opened.handle); else onclose(); }
</script>

<div class="sheet glass" role="dialog" aria-label={t('importSheet.dialog')}>
  <header>
    <h2>{step === 'review' ? t('importSheet.titleReview') : step === 'mapping' ? t('importSheet.titleColumns') : t('importSheet.titleStart')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if step === 'start'}
    <p class="muted">{t('importSheet.intro')}</p>
    <footer><Button label={t('common.chooseFile')} variant="primary" onclick={start} /></footer>
  {:else if step === 'password'}
    <form onsubmit={next}>
      <p class="muted pre">{opened.password_text}</p>
      <div class="group"><Field label={t('importSheet.password')} type="password" bind:value={password} autofocus /></div>
      <footer><Button label={t('common.cancel')} onclick={onclose} /><Button type="submit" variant="primary" label={t('common.continue')} busy={busy} busyLabel={t('importSheet.opening')} disabled={!password} /></footer>
    </form>
  {:else if step === 'mapping'}
    <form onsubmit={next}>
      <p class="muted">{opened.mapping.subtitle}</p>
      <div class="group">
        {#each opened.mapping.targets as target (target.key)}
          <label class="map"><span>{target.label}</span>
            <select aria-label={target.label} bind:value={mapping[target.key]}>
              <option value="">{opened.mapping.none}</option>
              {#each opened.mapping.columns as c (c)}<option value={c}>{c}</option>{/each}
            </select>
          </label>
        {/each}
      </div>
      <p class="muted">{opened.mapping.unmapped}</p>
      <footer><Button label={t('common.cancel')} onclick={onclose} /><Button type="submit" variant="primary" label={t('common.continue')} busy={busy} busyLabel={t('importSheet.reading')} /></footer>
    </form>
  {:else if step === 'review' && review}
    <p class="muted">{review.subtitle}</p>
    <p class="summary">{review.summary}</p>
    <div class="group table" role="table" aria-label={t('importSheet.rows')}>
      <div class="tr head" role="row"><span></span><span>{t('importSheet.colName')}</span><span>{t('importSheet.colWebsite')}</span><span>{t('importSheet.colUsername')}</span><span>{t('importSheet.colKind')}</span><span>{t('importSheet.colStatus')}</span><span>{t('importSheet.colDecision')}</span></div>
      {#each review.rows as r (r.row)}
        <div class="tr" role="row">
          <input type="checkbox" aria-label={t('importSheet.select', { name: r.name })} checked={picked.includes(r.row)} onchange={() => toggle(r.row)} />
          <span>{r.name}</span><span>{r.website}</span><span>{r.username}</span><span>{r.kind}</span><span>{r.status}</span><span>{r.decision}</span>
        </div>
      {/each}
    </div>
    <div class="bar">
      <Button label={t('importSheet.skipSelected')} disabled={!picked.length} onclick={() => decide('skip')} />
      <Button label={t('importSheet.applySelected')} disabled={!picked.length} onclick={() => decide('apply')} />
      <Button label={t('importSheet.mergeSelected')} disabled={!picked.length} onclick={() => decide('merge')} />
      <Button label={t('importSheet.keepBothSelected')} disabled={!picked.length} onclick={() => decide('keep_both')} />
    </div>
    <div class="bar">
      <Button label={t('importSheet.addAllNew')} onclick={() => decideAll('add-new')} />
      <Button label={t('importSheet.replaceConflicts')} onclick={() => decideAll('replace-conflicts')} />
      <Button label={t('importSheet.skipAll')} onclick={() => decideAll('skip-all')} />
    </div>
    {#if review.diagnostics.length}
      <div class="section-label">{t('importSheet.diagnostics')}</div>
      <pre class="group diag">{review.diagnostics.join('\n')}</pre>
    {/if}
    {#if progress}<p class="muted" role="status">{progress}</p>{/if}
    <footer><Button label={t('common.cancel')} onclick={cancel} /><Button label={t('importSheet.import')} variant="primary" busy={busy} busyLabel={t('importSheet.importing')} onclick={apply} /></footer>
  {/if}
  {#if error}<p class="error pre" role="alert">{error}</p>{/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .pre { white-space: pre-line; }
  .summary { font-weight: 600; margin: 0; }
  .map { display: flex; align-items: center; gap: 10px; padding: 7px 14px; }
  .map + .map { border-top: 1px solid var(--separator); }
  .map span { width: 170px; color: var(--text-muted); font-size: 13px; }
  select { flex: 1; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px; }
  .table { overflow: auto; max-height: 46vh; }
  .tr { display: grid; grid-template-columns: 26px 1.4fr 1.4fr 1fr 90px 90px 90px; gap: 8px; padding: 6px 12px; align-items: center; font-size: 12.5px; }
  .tr + .tr { border-top: 1px solid var(--separator); }
  .tr.head { font-weight: 600; color: var(--text-muted); }
  .bar { display: flex; flex-wrap: wrap; gap: 6px; }
  .diag { padding: 10px; font: 11.5px ui-monospace, monospace; white-space: pre-wrap; max-height: 120px; overflow: auto; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 6px; }
</style>
