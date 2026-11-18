<script>
  /** Security center: backup restore test ("Test now") and the printable vault health report (sub-plan 12). */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let status = $state(null);
  let picked = $state(null); // {path, name}
  let backupPassword = $state('');
  let vaultPassword = $state('');
  let busy = $state(false);

  async function load() {
    const r = await call('restore_test_status');
    if (r.ok) status = r;
  }
  $effect(() => { load(); });

  async function pick() {
    const r = await call('restore_test_pick');
    if (r.ok) picked = r; else if (r.error.code !== 'cancelled') toast(r.error.message, '', 'error');
  }

  async function run() {
    busy = true;
    const pending = call('restore_test_run', picked.path, backupPassword, vaultPassword || null);
    backupPassword = ''; vaultPassword = ''; // the passwords leave the page once the call is sent
    const r = await pending;
    busy = false;
    if (okOrToast(r, t('restoreTest.failedToRun'))) {
      status = r; picked = null;
      toast(r.text, '', r.passed ? 'info' : 'error');
    }
  }

  async function print(page) {
    const r = await call('health_report_print', page);
    if (r.ok) toast(r.message); else if (r.error.code !== 'cancelled') toast(r.error.message, '', 'error');
  }
</script>

<div class="section-label">{t('restoreTest.section')}</div>
<div class="group">
  <div class="row">
    <div class="text">
      <div>{status?.text ?? ''}</div>
      {#if status?.due}<div class="meta warning">{t('restoreTest.due')}</div>{/if}
    </div>
    <Button label={t('restoreTest.testNow')} onclick={pick} />
  </div>
  {#if picked}
    <form class="row form" onsubmit={(e) => { e.preventDefault(); run(); }}>
      <span class="meta">{picked.name}</span>
      <input type="password" autocomplete="off" placeholder={t('restoreTest.backupPassword')} bind:value={backupPassword} />
      <input type="password" autocomplete="off" placeholder={t('restoreTest.vaultPasswordOptional')} bind:value={vaultPassword} />
      <Button label={t('common.cancel')} onclick={() => { picked = null; backupPassword = ''; vaultPassword = ''; }} />
      <Button label={t('restoreTest.run')} variant="primary" {busy} disabled={!backupPassword} type="submit" />
    </form>
  {/if}
  <div class="row">
    <div class="text"><div>{t('healthReport.title')}</div><div class="meta">{t('healthReport.noSecrets')}</div></div>
    <Button label={t('healthReport.printA4')} onclick={() => print('a4')} />
    <Button label={t('healthReport.printLetter')} onclick={() => print('letter')} />
  </div>
</div>

<style>
  .section-label { margin: 14px 0 6px; font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; }
  .meta { color: var(--text-muted); font-size: 12.5px; }
  .meta.warning { color: var(--warning, #c58a00); }
  .form input { flex: 1; min-width: 0; }
</style>
