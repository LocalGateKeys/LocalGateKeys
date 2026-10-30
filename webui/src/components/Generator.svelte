<script>
  /** Password generator sheet. Settings persist in Python on every Generate. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();

  let options = $state(null);
  let value = $state('');
  let health = $state('');

  async function generate(changes = {}) {
    const result = await call('generator_generate', { ...(options ?? {}), ...changes });
    if (!okOrToast(result, t('generator.couldNotGenerate'))) return;
    value = result.value;
    health = result.health;
    if (result.options && Object.keys(result.options).length) options = result.options;
  }

  $effect(() => {
    (async () => {
      const result = await call('generator_get');
      if (result.ok) options = result.options;
      generate();
    })();
  });

  async function copy() {
    const result = await call('generator_copy', value);
    if (okOrToast(result, t('home.notCopied'))) notice(result);
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label={t('generator.title')}>
  <header><h2>{t('generator.title')}</h2><button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button></header>
  <div class="group output">
    <span class="mono">{value}</span>
    <span class="health">{health}</span>
  </div>
  {#if options}
    <div class="section-label">{t('generator.options')}</div>
    <div class="group">
      <div class="field">
        <span class="k">{t('generator.type')}</span>
        <button class="seg" class:on={options.mode === 'password'} onclick={() => generate({ mode: 'password' })}>{t('generator.random')}</button>
        <button class="seg" class:on={options.mode === 'passphrase'} onclick={() => generate({ mode: 'passphrase' })}>{t('generator.passphrase')}</button>
      </div>
      {#if options.mode === 'passphrase'}
        <label class="field"><span class="k">{t('generator.words')}</span>
          <input type="range" min="3" max="16" value={options.words} onchange={(e) => generate({ words: +e.currentTarget.value })} />
          <span class="n">{options.words}</span>
        </label>
      {:else}
        <label class="field"><span class="k">{t('generator.length')}</span>
          <input type="range" min="8" max="64" value={options.length} onchange={(e) => generate({ length: +e.currentTarget.value })} />
          <span class="n">{options.length}</span>
        </label>
        {#each [['uppercase', 'A–Z'], ['lowercase', 'a–z'], ['digits', '0–9'], ['symbols', t('generator.symbols')]] as [key, label] (key)}
          <label class="field"><span class="k">{label}</span>
            <input type="checkbox" checked={options[key]} onchange={(e) => generate({ [key]: e.currentTarget.checked })} />
          </label>
        {/each}
      {/if}
    </div>
  {/if}
  <footer>
    <Button label={t('generator.again')} onclick={() => generate()} />
    <Button label={t('generator.copy')} variant="primary" onclick={copy} />
  </footer>
</div>

<style>
  .sheet {
    position: absolute; inset: 10px 10px 10px auto; width: min(460px, calc(100% - 20px)); z-index: 30;
    border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 86%, transparent);
  }
  header { display: flex; align-items: center; margin-bottom: 10px; }
  h2 { margin: 0; font: 600 17px var(--font-display); flex: 1; }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 14px; }
  .output { padding: 16px; display: grid; gap: 8px; text-align: center; }
  .mono { font-family: var(--font-mono); font-size: 16px; letter-spacing: 0.5px; overflow-wrap: anywhere; user-select: text; }
  .health { color: var(--text-muted); font-size: 12.5px; }
  .field { display: flex; align-items: center; gap: 10px; padding: 9px 14px; min-height: 42px; }
  .field + .field { border-top: 1px solid var(--separator); }
  .k { width: 96px; color: var(--text-muted); }
  .n { width: 28px; text-align: right; }
  input[type="range"] { flex: 1; }
  .seg { height: 26px; padding: 0 12px; border-radius: 13px; border: 1px solid var(--glass-border); background: var(--glass); cursor: pointer; }
  .seg.on { background: var(--accent); color: var(--on-accent); border-color: transparent; }
  footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }
</style>
