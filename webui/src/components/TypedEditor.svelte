<script>
  /** Schema-driven editor for every typed item kind. Protected fields are write-only. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { kind, ref = null, onclose } = $props();

  let schema = $state(null);
  let title = $state('');
  let tags = $state('');
  let favorite = $state(false);
  let values = $state({});
  let secrets = $state({});
  let present = $state({});
  let cleared = $state([]);
  let revision = $state(null);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    (async () => {
      const result = await call('typed_schema');
      if (!okOrToast(result, t('typedEditor.couldNotOpenEditor'))) { onclose(null); return; }
      schema = result.kinds.find((k) => k.kind === kind) ?? null;
      if (!schema) { onclose(null); return; }
      if (ref) {
        const item = await call('typed_open', ref);
        if (!okOrToast(item, t('typedEditor.couldNotOpenItem'))) { onclose(null); return; }
        title = item.title;
        tags = (item.tags ?? []).join(', ');
        favorite = item.favorite;
        values = { ...item.values };
        present = { ...item.protected_present };
        revision = item.revision;
      }
    })();
  });

  const tagList = () => tags.split(',').map((t) => t.trim()).filter(Boolean);

  async function save() {
    if (busy) return;
    busy = true;
    error = '';
    let result;
    if (kind === 'document' && !ref) {
      result = await call('doc_create', title, values.description ?? '');
    } else {
      const protectedValues = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v));
      result = await call('typed_save', ref, kind, {
        title, tags: tagList(), favorite, values: { ...values }, protected: protectedValues, clear: cleared, revision,
      });
    }
    busy = false;
    // Typed secrets stay in the form after a failed save so they need not be retyped.
    if (result.ok) { secrets = {}; toast(t('typedEditor.saved', { kind: schema.label })); onclose(result.ref); return; }
    if (result.error.code !== 'cancelled') error = result.error.message;
  }

  function keys(event) {
    if (event.key === 's' && event.ctrlKey) { event.preventDefault(); save(); }
    if (event.key === 'Escape') { event.preventDefault(); secrets = {}; onclose(null); }
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label={ref ? t('typedEditor.editItem') : t('typedEditor.newItem')} tabindex="-1" onkeydown={keys}>
  {#if schema}
    <header><h2>{(ref ? schema.edit_title : schema.new_title) ?? t(ref ? 'typedEditor.editTitle' : 'typedEditor.newTitle', { kind: schema.label })}</h2></header>
    {#if schema.note}<p class="note">{schema.note}</p>{/if}
    <div class="group">
      <label class="field"><span class="k">{t('typedEditor.title')}</span><input bind:value={title} /></label>
      <label class="field"><span class="k">{t('typedEditor.tags')}</span><input bind:value={tags} placeholder={t('typedEditor.tagsPlaceholder')} /></label>
      <label class="field"><span class="k">{t('typedEditor.favorite')}</span><input type="checkbox" bind:checked={favorite} /></label>
    </div>
    <div class="section-label">{t('typedEditor.details')}</div>
    <div class="group">
      {#each schema.fields as field (field.name)}
        <label class="field" class:tall={field.type === 'multiline'}>
          <span class="k">{field.label}</span>
          {#if field.protected}
            <input type="password" autocomplete="off" bind:value={secrets[field.name]}
              placeholder={present[field.name] && !cleared.includes(field.name) ? t('typedEditor.savedReplace') : ''} />
            {#if present[field.name] && !cleared.includes(field.name)}
              <button type="button" class="text-btn" onclick={() => (cleared = [...cleared, field.name])}>{t('typedEditor.clear')}</button>
            {/if}
          {:else if field.type === 'multiline'}
            <textarea bind:value={values[field.name]}></textarea>
          {:else if field.type === 'checkbox'}
            <input type="checkbox" bind:checked={values[field.name]} />
          {:else if field.type === 'select'}
            <select bind:value={values[field.name]}>
              {#each field.options as option (option)}<option value={option}>{option || '—'}</option>{/each}
            </select>
          {:else}
            <input bind:value={values[field.name]} placeholder={field.type === 'date' ? t('typedEditor.dateFormat') : ''} />
          {/if}
        </label>
      {/each}
    </div>
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label={t('common.cancel')} onclick={() => { secrets = {}; onclose(null); }} />
      <Button label={kind === 'document' && !ref ? t('typedEditor.chooseSave') : t('typedEditor.save')} variant="primary" busy={busy} busyLabel={t('typedEditor.saving')} onclick={save} />
    </footer>
  {/if}
</div>

<style>
  .sheet {
    position: absolute; inset: 10px 10px 10px auto; width: min(560px, calc(100% - 20px)); z-index: 30;
    border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 86%, transparent);
  }
  h2 { margin: 0 0 6px; font: 600 17px var(--font-display); }
  .note { color: var(--text-muted); margin: 0 0 8px; font-size: 12.5px; }
  .field { display: flex; align-items: center; gap: 10px; padding: 9px 14px; min-height: 42px; }
  .field + .field { border-top: 1px solid var(--separator); }
  .field.tall { align-items: flex-start; }
  .k { width: 150px; flex-shrink: 0; color: var(--text-muted); font-size: 13px; }
  input:not([type="checkbox"]), textarea, select { flex: 1; min-width: 0; background: none; border: none; outline: none; user-select: text; }
  select { background: var(--group); border-radius: 6px; padding: 4px; }
  input::placeholder { color: var(--text-faint); }
  textarea { min-height: 90px; resize: vertical; }
  .text-btn { background: none; border: none; color: var(--link); cursor: pointer; }
  .error { color: var(--danger); margin: 8px 2px 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
</style>
