<script>
  /** Plain-secrets scan: find SSH keys and .env files stored as plain text, import them, use references. */
  import { dialog } from '../lib/dialog.js';
  import { call, on } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, cliEnabled = false } = $props();
  const JOB = 'secret_scan';
  let folders = $state([]); // empty means the user folder
  let rows = $state(null); // null until a scan finished
  let picked = $state({});
  let running = $state(false);
  let progress = $state('');
  let busy = $state(false);
  let preview = $state(null); // { id, token, path, rows, ... } while a rewrite is being reviewed
  let cliOff = $state(false);

  $effect(() => {
    const offs = [
      on('job.progress', (d) => { if (d.job === JOB) progress = d.text; }),
      on('job.done', (d) => {
        if (d.job !== JOB) return;
        running = false;
        progress = d.message;
        if (d.ok) { rows = d.rows; picked = {}; }
      }),
    ];
    return () => { offs.forEach((off) => off()); call('secret_scan_cancel'); };
  });

  async function addFolder() {
    const result = await call('secret_scan_choose_folder');
    if (result.ok) { if (!folders.includes(result.folder)) folders = [...folders, result.folder]; }
    else if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error');
  }

  async function start() {
    running = true;
    progress = t('secret_scan.starting');
    const result = await call('secret_scan_start', folders.length ? folders : null);
    if (!result.ok) { running = false; progress = ''; toast(result.error.message, '', 'error'); }
  }

  const chosen = $derived((rows ?? []).filter((r) => picked[r.id] && !r.imported).map((r) => r.id));

  async function importChosen() {
    busy = true;
    const result = await call('secret_scan_import', chosen);
    busy = false;
    if (result.ok) { rows = result.rows; picked = {}; toast(result.message); }
    else toast(result.error.message, '', 'error');
  }

  async function review(row) {
    const result = await call('secret_scan_rewrite_preview', row.id);
    if (result.ok) preview = { id: row.id, ...result };
    else toast(result.error.message, '', 'error');
  }

  async function applyRewrite() {
    const { id, token } = preview;
    busy = true;
    const result = await call('secret_scan_rewrite_apply', id, token);
    busy = false;
    preview = null;
    if (result.ok) { rows = result.rows; cliOff = !result.cli_enabled; toast(result.message); }
    else toast(result.error.message, '', 'error');
  }

  const kindLabel = (kind) => (kind === 'ssh_private_key' ? t('secret_scan.kind.ssh') : t('secret_scan.kind.env'));
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') { e.preventDefault(); if (preview) preview = null; else onclose(); } }} />

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" use:dialog aria-label={t('secret_scan.title')}>
    <header>
      <h2>{t('secret_scan.title')}</h2>
      <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
    </header>
    <p class="muted">{t('secret_scan.intro')}</p>

    <div class="section-label">{t('secret_scan.folders.title')}</div>
    <div class="folders">
      {#each folders as folder (folder)}
        <span class="chip mono">{folder}
          <button aria-label={`${t('secret_scan.folders.remove')}: ${folder}`}
            onclick={() => (folders = folders.filter((f) => f !== folder))}>✕</button></span>
      {:else}
        <span class="chip">{t('secret_scan.folders.default')}</span>
      {/each}
      <Button label={t('secret_scan.folders.add')} disabled={running} onclick={addFolder} />
    </div>
    <div class="bar">
      <Button label={t('secret_scan.scan')} variant="primary" disabled={running} onclick={start} />
      {#if running}<Button label={t('secret_scan.cancel')} onclick={() => call('secret_scan_cancel')} />{/if}
      <span class="progress" role="status">{progress}</span>
    </div>

    {#if rows}
      {#if rows.length}
        <div class="group">
          {#each rows as row (row.id)}
            <div class="row">
              <input type="checkbox" aria-label={t('secret_scan.select', { name: row.path })} disabled={row.imported}
                checked={!!picked[row.id]} onchange={(e) => (picked = { ...picked, [row.id]: e.currentTarget.checked })} />
              <div class="text">
                <div class="title">{row.name}</div>
                <div class="desc mono">{row.folder}</div>
                <div class="desc">{kindLabel(row.kind)}{#if row.kind === 'env_file'} · {t('secret_scan.vars', { count: row.var_count })}{/if}</div>
              </div>
              {#if row.imported}<span class="badge">{t('secret_scan.inVault')}</span>{/if}
              {#if row.imported && row.kind === 'env_file' && row.var_count > 0}
                <Button label={t('secret_scan.rewrite.button')} onclick={() => review(row)} />
              {/if}
            </div>
          {/each}
        </div>
        <p class="muted">{t('secret_scan.never')}</p>
        <div class="bar">
          <Button label={t('secret_scan.import')} variant="primary" {busy} disabled={!chosen.length} onclick={importChosen} />
        </div>
        {#if cliOff}<p class="muted warn" role="note">{t('secret_scan.rewrite.cliOff')}</p>
        {:else if !cliEnabled}<p class="muted" role="note">{t('secret_scan.rewrite.cliHint')}</p>{/if}
      {:else}
        <p class="muted">{t('secret_scan.none')}</p>
      {/if}
    {/if}
  </div>
</div>

{#if preview}
  <div class="scrim over">
    <div class="card glass" role="dialog" aria-modal="true" use:dialog aria-label={t('secret_scan.rewrite.title')}>
      <h2>{t('secret_scan.rewrite.title')}</h2>
      <p class="muted">{t('secret_scan.rewrite.intro', { path: preview.path })}</p>
      <table>
        <thead><tr><th>{t('secret_scan.rewrite.line')}</th><th>{t('secret_scan.rewrite.name')}</th><th>{t('secret_scan.rewrite.new')}</th></tr></thead>
        <tbody>
          {#each preview.rows as row, i (i)}
            <tr>
              <td>{row.line}</td><td class="mono">{row.name}</td>
              <td class="mono">{#if row.action === 'rewrite'}{row.after}{:else}<span class="muted">{t(`secret_scan.rewrite.skip.${row.reason}`)}</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <div class="actions">
        <Button label={t('common.cancel')} onclick={() => (preview = null)} />
        <Button label={t('secret_scan.rewrite.apply')} variant="primary" {busy} onclick={applyRewrite} />
      </div>
    </div>
  </div>
{/if}

<style>
  .scrim { position: fixed; inset: 0; display: grid; place-items: center; background: var(--scrim); z-index: 50; }
  .scrim.over { z-index: 60; }
  .card { width: min(680px, calc(100vw - 48px)); max-height: calc(100vh - 48px); overflow-y: auto; border-radius: var(--radius-card);
    padding: 20px 22px 18px; background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0 0 8px; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; }
  .warn { color: var(--warning); }
  .section-label { margin: 10px 0 4px; font-size: 12px; font-weight: 600; color: var(--text-muted); }
  .folders { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  .chip { background: var(--group); border-radius: 999px; padding: 3px 10px; font-size: 12.5px; }
  .chip button { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .bar { display: flex; align-items: center; gap: 10px; margin: 10px 0; }
  .progress { color: var(--text-muted); font-size: 12.5px; }
  .row { display: flex; align-items: center; gap: 12px; padding: 8px 12px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; }
  .title { font-size: 13.5px; }
  .desc { color: var(--text-muted); font-size: 12px; }
  .badge { font-size: 12px; color: var(--text-muted); }
  .mono { font: 11.5px ui-monospace, monospace; user-select: text; overflow-wrap: anywhere; }
  input[type="checkbox"] { width: 18px; height: 18px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; color: var(--text-muted); font-weight: 600; padding: 4px 6px; }
  td { padding: 4px 6px; border-top: 1px solid var(--separator); vertical-align: top; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
</style>
