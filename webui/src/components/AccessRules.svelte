<script>
  /** A login's access rules (Pro to tighten): confirm every time, never autofill, copy once, view only on phones,
   *  lock after a date. The backend asks for re-auth and refuses tightening on Free with pro_required. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';

  // onchanged(view): after a save, so the login's other sections follow the new rules.
  let { selected, onchanged = () => {} } = $props();
  let data = $state(null);

  $effect(() => {
    const ref = selected;
    data = null;
    call('access_get', ref).then((r) => { if (ref === selected && r.ok) data = r; });
  });

  async function save(changes, control) {
    const ref = selected;
    const result = await call('access_save', ref, changes);
    if (ref !== selected) return;
    if (!okOrToast(result, t('loginMore.ruleNotSaved'))) {
      // Cancelled or refused: put the control back to the saved rule.
      if (control) {
        if (control.type === 'checkbox') control.checked = !control.checked;
        else control.value = data?.access?.expires ?? '';
      }
      return;
    }
    data = result;
    toast(result.message || t('access.saved'));
    onchanged(result);
  }
</script>

{#if data}
  <div class="section-label">{t('access.title')}{#if !data.pro}<span class="pro"> · {t('access.needsPro')}</span>{/if}</div>
  <div class="group" data-testid="access-rules">
    {#if data.unknown}<p class="line warn" role="status">{t('access.unknownRule')}</p>{/if}
    <label class="line"><span class="k">{t('access.reauth')}</span>
      <input type="checkbox" role="switch" checked={data.reauth} onchange={(e) => save({ reauth: e.currentTarget.checked }, e.currentTarget)} /></label>
    <label class="line"><span class="k">{t('access.neverFill')}</span>
      <input type="checkbox" role="switch" checked={data.never_fill} onchange={(e) => save({ never_fill: e.currentTarget.checked }, e.currentTarget)} /></label>
    <label class="line"><span class="k">{t('access.copyOnce')}</span>
      <input type="checkbox" role="switch" checked={data.access?.copy === 'once'}
        onchange={(e) => save({ copy: e.currentTarget.checked ? 'once' : 'normal' }, e.currentTarget)} /></label>
    <label class="line"><span class="k">{t('access.phonesView')}</span>
      <input type="checkbox" role="switch" checked={data.access?.phones === 'view'}
        onchange={(e) => save({ phones: e.currentTarget.checked ? 'view' : 'full' }, e.currentTarget)} /></label>
    <label class="line"><span class="k">{t('access.expires')}</span>
      <input type="date" aria-label={t('access.expires')} value={data.access?.expires ?? ''}
        onchange={(e) => save({ expires: e.currentTarget.value || '' }, e.currentTarget)} /></label>
    {#if data.expired}<p class="line warn" role="status">{t('access.expired', { date: data.access?.expires ?? '' })}</p>{/if}
    <p class="hint">{t('access.olderDevices')}</p>
  </div>
{/if}

<style>
  .line { display: flex; align-items: center; gap: 8px; padding: 9px 14px; min-height: 40px; margin: 0; }
  .line + .line { border-top: 1px solid var(--separator); }
  .k { flex: 1; color: var(--text-muted); }
  .warn { color: var(--warning, #c58a00); font-size: 12.5px; }
  .pro { text-transform: none; color: var(--text-faint); }
  .hint { color: var(--text-faint); font-size: 12px; padding: 0 14px 10px; margin: 0; }
  input[type="date"] { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 6px; padding: 3px 6px; }
</style>
