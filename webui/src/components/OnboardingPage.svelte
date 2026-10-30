<script>
  /** Set up LocalGateKeys: five skippable steps (vault, Windows Hello, import, recovery phrase, browser).
   *  Opening the guide offers skipped steps again; steps done on another page are picked up when it reloads. */
  import { call, on } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose, onroute } = $props();
  let view = $state(null);
  let busy = $state(false);

  async function load(again = false) {
    const r = await call(again ? 'onboarding_show' : 'onboarding_state');
    if (okOrToast(r, t('onboardingPage.openFailed'))) view = r;
  }
  $effect(() => {
    load(true);
    const off = on('items.changed', () => load());
    return off;
  });

  const current = $derived(view?.steps.find((s) => s.key === view.current) ?? null);
  const first = $derived(!!view && view.steps.every((s) => s.state !== 'skipped') && view.done <= 1);

  async function perform(step) {
    if (busy) return;
    busy = true;
    try {
      // The connection test can take seconds: it runs as its own call, outside the vault lock.
      if (step === 'browser') await call('onboarding_test_connection');
      const r = await call('onboarding_perform', step);
      if (!okOrToast(r)) return;
      view = r;
      if (r.open) onroute(r.open.route, r.open.params ?? {}, () => load());
    } finally { busy = false; }
  }

  async function skip(step) {
    const r = await call('onboarding_skip', step);
    if (okOrToast(r)) view = r;
  }

  async function skipAll() {
    const r = await call('onboarding_skip_all');
    if (okOrToast(r)) onclose();
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('onboardingPage.title')}>
  <header>
    <h2>{view?.title ?? t('onboardingPage.title')}</h2>
    <button class="close" aria-label={t('onboardingPage.closeSetup')} onclick={onclose}>✕</button>
  </header>
  {#if view}
    <p class="muted">{view.subtitle}</p>
    <p class="progress" aria-live="polite">{t('onboardingPage.progress', { progress: view.progress })}</p>
    <ol class="steps">
      {#each view.steps as s, i (s.key)}
        <li class={s.state} aria-current={s.state === 'current' ? 'step' : undefined}>
          <span class="n" aria-hidden="true">{s.state === 'done' ? '✓' : i + 1}</span>
          <div class="body">
            <h3>{s.label}<span class="sr">{s.state === 'done' ? t('onboardingPage.stepDone') : s.state === 'skipped' ? t('onboardingPage.stepSkippedSr') : ''}</span></h3>
            {#if s.state === 'current' || s.state === 'skipped'}
              <p class="muted">{s.text}</p>
              {#if s.state === 'current' && view.message}<p class="status" role="status">{view.message}</p>{/if}
              <div class="actions">
                {#if s.state === 'current'}<Button label={t('onboardingPage.skip')} onclick={() => skip(s.key)} />{/if}
                <Button label={s.primary} variant={s.state === 'current' ? 'primary' : undefined} disabled={busy}
                  onclick={() => perform(s.key)} />
              </div>
            {:else if s.state === 'skipped'}
              <p class="muted">{t('onboardingPage.skipped')}</p>
            {/if}
          </div>
        </li>
      {/each}
    </ol>
    <footer>
      {#if first && current}
        <button type="button" class="link" onclick={skipAll}>{t('onboardingPage.skipSetup')}</button>
      {/if}
      <Button label={view.complete ? t('common.done') : t('onboardingPage.finishLater')} variant={view.complete ? 'primary' : undefined} onclick={onclose} />
    </footer>
    {#if !current && !view.complete}
      <p class="muted">{t('onboardingPage.skippedStay')}</p>
    {/if}
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0; font: 600 14px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .progress { margin: 0; font-weight: 600; font-size: 12.5px; color: var(--text-muted); }
  .steps { list-style: none; padding: 0; margin: 4px 0; display: grid; gap: 8px; }
  .steps li { display: flex; gap: 12px; padding: 12px 14px; border-radius: 12px; background: var(--group); }
  .steps li.current { outline: 2px solid var(--accent); outline-offset: -2px; }
  .n { flex: none; width: 24px; height: 24px; border-radius: 50%; display: grid; place-items: center;
    font: 600 12px var(--font-display); background: var(--wash-base); color: var(--text-muted); }
  .done .n { background: var(--success); color: #fff; }
  .current .n { background: var(--accent); color: #fff; }
  .body { flex: 1; display: grid; gap: 6px; }
  .status { margin: 0; font-weight: 600; font-size: 12.5px; }
  .actions { display: flex; gap: 8px; justify-content: flex-end; }
  footer { display: flex; justify-content: flex-end; align-items: center; gap: 8px; }
  .link { margin-right: auto; background: none; border: none; color: var(--accent-text, var(--accent)); cursor: pointer;
    font-size: 13px; text-decoration: underline; padding: 4px 0; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
