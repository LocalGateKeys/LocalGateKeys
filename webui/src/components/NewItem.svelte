<script>
  /** New item chooser (groups and order from shell/new_item.py). */
  import { t } from '../lib/i18n.svelte.js';

  let { onchoose, onclose } = $props();

  const GROUPS = [
    ['newItem.groupSignIns', [['web', 'newItem.web'], ['desktop', 'newItem.desktop'], ['passkey', 'newItem.passkey']]],
    ['newItem.groupMoney', [['card', 'newItem.card'], ['bank_account', 'newItem.bank_account']]],
    ['newItem.groupPersonal', [['identity', 'newItem.identity'], ['note', 'newItem.note'], ['document', 'newItem.document']]],
    ['newItem.groupTech', [['ssh_key', 'newItem.ssh_key'], ['api_key', 'newItem.api_key'], ['wifi', 'newItem.wifi'], ['bookmark', 'newItem.bookmark']]],
    ['newItem.groupOwn', [['license', 'newItem.license'], ['subscription', 'newItem.subscription'], ['warranty', 'newItem.warranty'], ['purchase', 'newItem.purchase']]],
  ];  // Labels are catalog keys, translated where they are shown.
  let filter = $state('');
  const flat = GROUPS.flatMap(([, kinds]) => kinds);
  const visible = $derived(filter ? flat.filter(([, label]) => t(label).toLowerCase().includes(filter.toLowerCase())) : null);

  function choose(kind) {
    onchoose(kind);
  }

  function key(event) {
    if (event.key === 'Escape') { event.preventDefault(); onclose(); return; }
    if (/^[1-9]$/.test(event.key) && !filter) { const pick = flat[+event.key - 1]; if (pick) choose(pick[0]); return; }
    if (event.key === 'Backspace') { filter = filter.slice(0, -1); return; }
    if (event.key.length === 1 && /\S/.test(event.key)) filter += event.key;
  }
</script>

<svelte:window onkeydown={key} />

<div class="scrim" role="presentation" onclick={onclose}>
  <div class="card glass" role="dialog" aria-modal="true" aria-label={t('newItem.title')} tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
    <h2>{t('newItem.title')}</h2>
    <button class="scan" onclick={() => choose('scan-qr')}>{t('newItem.scan')}<span>{t('newItem.scanHint')}</span></button>
    <p class="hint">{filter ? t('newItem.hintFilter', { filter }) : t('newItem.hintDefault')}</p>
    {#if visible}
      <div class="grid">{#each visible as [kind, label] (kind)}<button onclick={() => choose(kind)}>{t(label)}</button>{/each}</div>
    {:else}
      {#each GROUPS as [name, kinds] (name)}
        <div class="section-label">{t(name)}</div>
        <div class="grid">{#each kinds as [kind, label] (kind)}<button class="ready" onclick={() => choose(kind)}>{t(label)}</button>{/each}</div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; background: var(--scrim); z-index: 45; display: grid; place-items: center; }
  .card { width: min(640px, calc(100vw - 40px)); border-radius: 18px; padding: 18px 20px; }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .hint { color: var(--text-muted); margin: 4px 0 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 6px; }
  .grid button { text-align: left; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--glass-border); background: var(--group); cursor: pointer; }
  .grid button:hover { background: var(--glass-hover); }
  .scan { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; width: 100%; margin: 10px 0 2px; padding: 10px 12px;
    border-radius: 10px; border: 1px solid var(--glass-border); background: var(--group); cursor: pointer; text-align: left; }
  .scan:hover { background: var(--glass-hover); }
  .scan span { color: var(--text-muted); font-size: 12px; }
  .grid button:not(.ready) { color: var(--text-muted); }
</style>
