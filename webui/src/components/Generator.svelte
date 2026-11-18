<script>
  /** Password generator sheet. Settings persist in Python on every Generate. */
  import { dialog } from '../lib/dialog.js';
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  // onuse: set when the editor opened the generator for its password field; the value goes back to it.
  let { onclose, onuse = undefined } = $props();

  let options = $state(null);
  let value = $state('');
  let health = $state('');
  let seq = 0;

  async function generate(changes = {}) {
    const mine = ++seq;
    if (options) options = { ...options, ...changes }; // the controls follow the click at once
    const result = await call('generator_generate', { ...(options ?? {}), ...changes });
    if (mine !== seq) return; // a newer request is on its way; an older reply must not win
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
    if (!okOrToast(result, t('home.notCopied'))) return;
    notice(result);
    startCountdown(Number(result.clear_seconds) || 0);
  }

  // C3: a live "clipboard clears in N s" line after a copy (the app clears it; this only shows the time left).
  let clearsIn = $state(0);
  let timer = null;
  function startCountdown(seconds) {
    clearInterval(timer);
    clearsIn = seconds;
    if (seconds > 0) timer = setInterval(() => { clearsIn -= 1; if (clearsIn <= 0) clearInterval(timer); }, 1000);
  }
  $effect(() => () => clearInterval(timer));
</script>

<div class="sheet glass" class:nested={!!onuse} role="dialog" aria-modal="true" use:dialog={{ onescape: onclose }} aria-label={t('generator.title')}>
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
        <button class="seg" class:on={options.mode === 'answer'} onclick={() => generate({ mode: 'answer' })}>{t('generator.mode.answer')}</button>
      </div>
      {#if options.mode === 'passphrase'}
        <label class="field"><span class="k">{t('generator.words')}</span>
          <input type="range" min="3" max="16" value={options.words} oninput={(e) => generate({ words: +e.currentTarget.value })} />
          <span class="n">{options.words}</span>
        </label>
      {:else if options.mode === 'answer'}
        <div class="field"><span class="k">{t('generator.answer.words')}</span>
          <button class="seg" aria-label={t('generator.answer.fewer')} disabled={options.answer_words <= 2} onclick={() => generate({ answer_words: options.answer_words - 1 })}>−</button>
          <span class="n" aria-live="polite">{options.answer_words}</span>
          <button class="seg" aria-label={t('generator.answer.more')} disabled={options.answer_words >= 6} onclick={() => generate({ answer_words: options.answer_words + 1 })}>+</button>
        </div>
      {:else}
        <label class="field"><span class="k">{t('generator.length')}</span>
          <input type="range" min="8" max="64" value={options.length} oninput={(e) => generate({ length: +e.currentTarget.value })} />
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
  {#if clearsIn > 0}
    <p class="health" role="status">{t('generator.clipboardClearsIn', { count: clearsIn })}</p>
  {/if}
  <footer>
    <Button label={t('generator.again')} onclick={() => generate()} />
    {#if onuse}
      <Button label={t('generator.copy')} onclick={copy} />
      <Button label={t('generator.useThis')} variant="primary" disabled={!value} onclick={() => { onuse(value); onclose(); }} />
    {:else}
      <Button label={t('generator.copy')} variant="primary" onclick={copy} />
    {/if}
  </footer>
</div>

<style>
  .sheet {
    position: absolute; inset: 10px 10px 10px auto; width: min(460px, calc(100% - 20px)); z-index: 30;
    border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 86%, transparent);
  }
  .sheet.nested { z-index: 60; }
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
