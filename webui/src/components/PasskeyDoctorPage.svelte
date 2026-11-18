<script>
  /** Passkey doctor: read-only checks (Windows passkey provider, passkeys on, native host, extension, browsers)
      and a button that opens the Windows passkeys settings page. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();
  let data = $state(null);

  async function load() {
    const result = await call('passkey_doctor_view');
    if (okOrToast(result, t('passkeyDoctor.openFailed'))) data = result;
  }
  $effect(() => { load(); });

  async function openSettings() {
    okOrToast(await call('passkey_doctor_open_settings'));
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('passkeyDoctor.title')}>
  <header>
    <h2>{t('passkeyDoctor.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if data}
    <div class="group card">
      <p class="status" class:ok={data.provider.code === 'active'} role="status">● {data.provider.text}</p>
    </div>
    <div class="section-label">{t('passkeyDoctor.checks')}</div>
    <div class="group" role="list">
      {#each data.checks as c (c.key)}
        <div class="row" role="listitem"><span>{c.label}</span><span class="state" class:ok={c.ok}>{c.ok ? '✓' : '!'} {c.detail}</span></div>
      {/each}
    </div>
    <div class="section-label">{t('passkeyDoctor.browsers')}</div>
    <div class="group" role="list">
      {#each data.browsers as b (b.browser)}
        <div class="row" role="listitem"><span>{b.browser}</span><span class="state" class:ok={b.ok}>{b.state}</span></div>
      {/each}
    </div>
    <footer>
      <Button label={t('passkeyDoctor.refresh')} onclick={load} />
      <Button label={t('passkeyDoctor.openWindows')} variant="primary" onclick={openSettings} />
    </footer>
    <p class="muted">{data.note}</p>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; }
  .card { padding: 14px; }
  .status { margin: 0; font-weight: 600; color: var(--warning); }
  .status.ok { color: var(--success); }
  .row { display: flex; justify-content: space-between; gap: 12px; padding: 10px 14px; margin: 0; }
  .row + .row { border-top: 1px solid var(--separator); }
  .state { color: var(--warning); font-weight: 600; font-size: 12.5px; text-align: right; }
  .state.ok { color: var(--success); }
  footer { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
</style>
