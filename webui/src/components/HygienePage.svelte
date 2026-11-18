<script>
  /** Clean up (from the Security center): duplicates, logins not changed in 2 years, expired items. Merges are always
   *  reviewed first; bulk delete and "merge all" are Pro and can be undone. Computed on demand, nothing stored. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { MERGEABLE, hygieneLabel, mergePair, refKey, whenSeconds } from '../lib/featurePack.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, onopen } = $props();
  let data = $state(null);
  let picked = $state(new Set()); // refKeys chosen for a bulk delete
  let keepers = $state({}); // group index -> refKey of the item to keep
  let review = $state(null); // {group, keeper, other, fields}
  let canUndo = $state(false);

  async function load() {
    const result = await call('hygiene_scan');
    if (!okOrToast(result)) return;
    data = result;
    canUndo = !!result.can_undo;
    picked = new Set();
    review = null;
  }
  $effect(() => { load(); });

  const allItems = $derived(data ? data.groups.flatMap((g) => g.items) : []);
  const pickedRefs = $derived(allItems.filter((i) => picked.has(refKey(i.ref))).map((i) => i.ref)
    .filter((ref, n, all) => all.findIndex((r) => refKey(r) === refKey(ref)) === n));

  function pick(ref, on) {
    const next = new Set(picked);
    if (on) next.add(refKey(ref)); else next.delete(refKey(ref));
    picked = next;
  }

  async function preview(group, index) {
    const pair = mergePair(group.items, keepers[index]);
    if (!pair) return;
    const result = await call('hygiene_merge_preview', pair.keeper, pair.other);
    if (!okOrToast(result)) return;
    review = { index, ...pair, fields: result.fields };
  }

  async function merge() {
    const result = await call('hygiene_merge', review.keeper, review.other);
    if (!okOrToast(result)) return;
    toast(result.message || t('hygiene.merged'));
    await load();
  }

  async function remove(refs) {
    const result = await call('hygiene_delete', refs);
    if (!okOrToast(result)) return;
    toast(result.message || t('hygiene.deleted', { count: refs.length }));
    await load();
    if (refs.length > 1) canUndo = true;
  }

  async function mergeAll() {
    const result = await call('hygiene_merge_all');
    if (!okOrToast(result)) return;
    toast(result.message || t('hygiene.mergedCount', { count: result.count ?? 0 }));
    await load();
    canUndo = true;
  }

  async function undo() {
    const result = await call('hygiene_undo');
    if (!okOrToast(result)) return;
    toast(result.message || t('hygiene.undone'));
    await load();
  }

  const hasSameLogin = $derived(!!data?.groups.some((g) => g.type === 'same_login'));
</script>

<div class="sheet glass" role="dialog" aria-label={t('hygiene.title')}>
  <header>
    <h2>{t('hygiene.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if data}
    <div class="body">
      <p class="summary" role="status">{t('hygiene.summary', { dupes: data.summary?.dupes ?? 0, old: data.summary?.old ?? 0, expired: data.summary?.expired ?? 0 })}</p>
      <div class="bulk">
        <Button label={t('hygiene.deleteSelected', { count: pickedRefs.length })} variant="danger"
          disabled={!data.pro || pickedRefs.length < 2} onclick={() => remove(pickedRefs)} />
        {#if hasSameLogin}<Button label={t('hygiene.mergeAll')} disabled={!data.pro} onclick={mergeAll} />{/if}
        {#if canUndo}<Button label={t('hygiene.undo')} onclick={undo} />{/if}
        {#if !data.pro}<span class="meta">{t('hygiene.bulkNeedsPro')}</span>{/if}
      </div>
      {#each data.groups as group, gi (gi)}
        <div class="section-label">{hygieneLabel(group.type)}</div>
        <div class="group" data-testid="hygiene-group">
          {#each group.items as item, ii (refKey(item.ref) + ii)}
            <div class="row">
              <input type="checkbox" aria-label={item.title} checked={picked.has(refKey(item.ref))} disabled={!data.pro}
                onchange={(e) => pick(item.ref, e.currentTarget.checked)} />
              {#if MERGEABLE.has(group.type) && group.items.length > 1}
                <input type="radio" name={`keep-${gi}`} aria-label={t('hygiene.keep')} title={t('hygiene.keep')}
                  checked={(keepers[gi] ?? refKey(group.items[0].ref)) === refKey(item.ref)}
                  onchange={() => { keepers = { ...keepers, [gi]: refKey(item.ref) }; if (review?.index === gi) review = null; }} />
              {/if}
              <button class="open" onclick={() => onopen?.(item.ref)}>
                <span>{item.title}</span>
                <span class="meta">{item.subtitle}{item.updated_at ? ` · ${whenSeconds(item.updated_at)}` : ''}</span>
              </button>
              <button class="text-btn danger" onclick={() => remove([item.ref])}>{t('hygiene.delete')}</button>
            </div>
          {/each}
          {#if MERGEABLE.has(group.type) && group.items.length > 1}
            <div class="row end"><Button label={t('hygiene.merge')} onclick={() => preview(group, gi)} /></div>
          {/if}
          {#if review?.index === gi}
            <div class="review">
              <p class="meta">{t('hygiene.mergeReview')}</p>
              <table>
                <thead><tr><th>{t('history.field')}</th><th>{t('hygiene.keep')}</th><th>{t('history.after')}</th></tr></thead>
                <tbody>
                  {#each review.fields as f (f.field)}
                    <tr class:changed={f.before !== f.after}><td>{f.field}</td>
                      <td class="v">{f.before === '[protected]' ? t('history.protected') : (f.before ?? '—')}</td>
                      <td class="v">{f.after === '[protected]' ? t('history.protected') : (f.after ?? '—')}</td></tr>
                  {/each}
                </tbody>
              </table>
              <div class="row end">
                <button class="text-btn" onclick={() => (review = null)}>{t('common.cancel')}</button>
                <Button label={t('hygiene.merge')} variant="primary" onclick={merge} />
              </div>
            </div>
          {/if}
        </div>
      {:else}
        <p class="meta">{t('hygiene.none')}</p>
      {/each}
    </div>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 30; border-radius: 18px; padding: 16px 18px; display: flex; flex-direction: column;
    background: color-mix(in srgb, var(--wash-base-opaque) 90%, transparent); }
  header { display: flex; align-items: center; gap: 8px; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .body { overflow-y: auto; flex: 1; min-height: 0; padding-top: 10px; }
  .summary { margin: 0 0 8px; font-weight: 600; }
  .bulk { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .section-label { margin: 14px 0 6px; font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; }
  .row { display: flex; align-items: center; gap: 10px; padding: 8px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row.end { justify-content: flex-end; }
  .open { flex: 1; min-width: 0; display: grid; text-align: left; background: none; border: none; color: inherit; cursor: pointer; font: inherit; }
  .meta { color: var(--text-muted); font-size: 12.5px; }
  .text-btn { background: none; border: none; color: var(--link); cursor: pointer; font-size: 12.5px; }
  .danger { color: var(--danger); }
  .review { border-top: 1px solid var(--separator); padding: 8px 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; color: var(--text-muted); font-weight: 500; padding: 4px 6px; }
  td { padding: 5px 6px; border-top: 1px solid var(--separator); vertical-align: top; }
  tr.changed td { font-weight: 600; }
  .v { overflow-wrap: anywhere; user-select: text; }
</style>
