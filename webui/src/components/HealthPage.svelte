<script>
  /** Password health: local findings per login and opt-in HIBP checks with live progress. */
  import { untrack } from 'svelte';
  import { call, on } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { fixActions, okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import { recall, remember } from '../lib/remember.js';

  let { filter = null, scanAll = false, onclose, onopen, onroute = null, onchangepassword = null } = $props();
  // A link that asks for a filter wins; otherwise reopen on the last one used.
  let current = $state(untrack(() => filter ?? recall('health.filter', null)));
  let data = $state(null);
  let picked = $state(null);
  let progress = $state('');
  let blocked = $state(null); // a setting stops the scan: {message, actions} to turn it on or open it
  let started = false;

  async function load() {
    const result = await call('health_report', current);
    if (okOrToast(result, t('healthPage.couldNotOpen'))) data = result;
  }

  async function scan(ids) {
    const result = await call('health_scan', ids);
    blocked = null;
    if (result.ok || result.error.code === 'cancelled') return;
    const { fix } = result.error;
    if (!fix) { toast(result.error.message, '', 'error'); return; }
    const actions = fixActions(result.error, () => { load(); scan(ids); });
    // Settings opens on top of this page; reload when it closes, since the setting may have changed.
    if (onroute) actions.at(-1).run = () => onroute('settings', { section: fix.section }, load);
    blocked = { message: result.error.message, actions };
  }

  $effect(() => {
    load();
    const offs = [
      on('job.progress', (d) => { if (d.job === 'health') progress = d.text; }),
      on('job.done', (d) => { if (d.job === 'health') { progress = d.message; load(); } }),
    ];
    if (scanAll && !started) { started = true; scan(null); }
    return () => { offs.forEach((off) => off()); call('health_cancel'); };
  });

  function choose(key) { current = key; remember('health.filter', key); load(); }
  const pickedRow = $derived(data?.rows.find((r) => r.id === picked));
</script>

<div class="sheet glass" role="dialog" aria-label={t('healthPage.title')}>
  <header>
    <h2>{t('healthPage.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if data}
    <p class="note">{data.subtitle}</p>
    <div class="bar">
      <strong>{data.summary}</strong>
      <span class="progress" role="status">{progress}</span>
    </div>
    {#if blocked}
      <div class="blocked" role="alert">
        <span>{blocked.message}</span>
        {#each blocked.actions as a (a.label)}
          <Button label={a.label} variant={a.primary ? 'primary' : 'glass'} onclick={() => { blocked = null; a.run(); }} />
        {/each}
      </div>
    {/if}
    <div class="filters" role="tablist">
      {#each data.filters as f (f.label)}
        <button role="tab" aria-selected={current === f.key} class:on={current === f.key} onclick={() => choose(f.key)}>{f.label}</button>
      {/each}
    </div>
    <div class="group rows">
      {#each data.rows as row (row.id)}
        <button class="row" class:picked={picked === row.id} onclick={() => (picked = row.id)} ondblclick={() => onopen(row.id)}>
          <span class="name">{row.label}</span>
          <span class="muted">{row.username}</span>
          <span class="score">{row.score}/4</span>
          <span class="muted find">{row.findings}</span>
          <span class="breach" class:bad={row.breach_state === 'found'}>{row.breach}</span>
        </button>
      {:else}
        <p class="empty">{t('healthPage.noMatch')}
          {#if current}<Button label={t('healthPage.showAll')} variant="link" onclick={() => choose(null)} />{/if}</p>
      {/each}
    </div>
    <footer>
      <span class="muted">{data.footer}</span>
      <Button label={t('healthPage.openEntry')} disabled={!picked} onclick={() => onopen(picked)} />
      {#if onchangepassword}
        <Button label={t('healthPage.changePassword')} disabled={!picked} variant={pickedRow?.breach_state === 'found' ? 'danger' : 'glass'}
          onclick={() => onchangepassword(picked)} />
      {/if}
      <Button label={t('healthPage.checkSelected')} disabled={!picked} onclick={() => scan([picked])} />
      <Button label={t('healthPage.scanAll')} variant="primary" onclick={() => scan(null)} />
    </footer>
  {/if}
</div>

<style>
  .sheet {
    position: absolute; inset: 10px; z-index: 31; border-radius: 18px; padding: 16px 18px;
    display: flex; flex-direction: column; background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent);
  }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .note, .muted { color: var(--text-muted); font-size: 12.5px; }
  .blocked {
    display: flex; gap: 12px; align-items: center; margin-top: 10px; padding: 8px 12px; border-radius: 10px;
    background: color-mix(in srgb, var(--warning) 14%, transparent); font-size: 13px;
  }
  .blocked span { flex: 1; }
  .bar { display: flex; gap: 12px; align-items: baseline; }
  .progress { margin-left: auto; color: var(--text-muted); font-size: 12.5px; }
  .filters { display: flex; gap: 6px; margin: 10px 0; }
  .filters button { background: var(--group); border: 1px solid var(--separator); border-radius: 999px; padding: 4px 10px; cursor: pointer; color: inherit; }
  .filters button.on { background: var(--accent); color: #fff; }
  .rows { overflow-y: auto; flex: 1; min-height: 0; }
  .row { display: grid; grid-template-columns: 1.4fr 1fr 50px 1.4fr 170px; gap: 10px; width: 100%; text-align: left; padding: 8px 14px; background: none; border: none; border-top: 1px solid var(--separator); color: inherit; cursor: pointer; }
  .row.picked { background: color-mix(in srgb, var(--accent) 18%, transparent); }
  .breach.bad { color: var(--danger); }
  .empty { color: var(--text-muted); text-align: center; }
  footer { display: flex; align-items: center; gap: 8px; margin-top: 12px; }
  footer .muted { margin-right: auto; }
</style>
