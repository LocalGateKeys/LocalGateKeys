<script>
  /** Settings › Autofill: auto-type into the last window (off by default) and whether to ask first. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';

  let data = $state(null);
  $effect(() => { call('autotype_settings_get').then((r) => { if (r.ok) data = r; }); });

  async function set(enabled, confirm, control) {
    const result = await call('autotype_settings_set', enabled, confirm);
    if (okOrToast(result)) data = result;
    else if (control) control.checked = !control.checked;
  }
</script>

{#if data}
  <h3 class="title">{t('autoType.title')}</h3>
  <div class="group" data-testid="autotype">
    <label class="row">
      <span class="text"><span>{t('autoType.enable')}</span><span class="desc">{t('autoType.enableHint')}</span></span>
      <input type="checkbox" role="switch" aria-label={t('autoType.enable')} checked={data.enabled}
        onchange={(e) => set(e.currentTarget.checked, data.confirm, e.currentTarget)} />
    </label>
    <label class="row">
      <span class="text">{t('autoType.confirm')}</span>
      <input type="checkbox" role="switch" aria-label={t('autoType.confirm')} checked={data.confirm} disabled={!data.enabled}
        onchange={(e) => set(data.enabled, e.currentTarget.checked, e.currentTarget)} />
    </label>
  </div>
{/if}

<style>
  .title { margin: 16px 0 8px; font: 600 15px var(--font-display); }
  .row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; display: grid; gap: 2px; font-size: 13.5px; }
  .desc { color: var(--text-muted); font-size: 12px; }
  input[type="checkbox"] { width: 18px; height: 18px; }
</style>
