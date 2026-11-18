<script>
  /** "Exposed to an AI agent": an agent received this login's password or this secret, and it has not changed
   * since. Python works it out from the device's logs; the page gets the agent's name and date, never a value. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { id, onchangepassword = null } = $props();
  let seen = $state(null);

  $effect(() => {
    const mine = id;
    seen = null;
    if (!mine) return;
    call('agent_exposure_get', mine).then((result) => {
      if (mine === id && result.ok && result.exposed) seen = result;
    });
  });

  async function dismiss() {
    const result = await call('agent_exposure_dismiss', id);
    if (okOrToast(result, t('settings.error.notSaved'))) seen = null;
  }
</script>

{#if seen}
  <div class="notice" role="status">
    <div class="text">
      <strong>{t('healthPage.agentTitle')}</strong>
      <span>{seen.text}</span>
    </div>
    {#if onchangepassword && seen.kind === 'login'}
      <Button label={t('healthPage.changePassword')} onclick={() => onchangepassword(id)} />
    {/if}
    <Button label={t('healthPage.agentDismiss')} variant="glass" onclick={dismiss} />
  </div>
{/if}

<style>
  .notice {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 8px 0; padding: 8px 12px; border-radius: 10px;
    background: color-mix(in srgb, var(--warning) 14%, transparent); font-size: 13px;
  }
  .text { flex: 1 1 200px; min-width: 0; overflow-wrap: anywhere; display: flex; flex-direction: column; gap: 2px; }
</style>
