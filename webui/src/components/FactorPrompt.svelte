<script>
  /** Key file / YubiKey on the unlock screen: the key-file row (picker, remembered name, "remember"),
   *  the YubiKey note, and "Touch your YubiKey" with Cancel while a YubiKey waits (factors.touch events).
   *  Only the picked file's name lives here; Python keeps its path and reads the file at unlock. */
  import { call, on } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';

  let { factors = [], keyfileName = null, remember = true, picked = $bindable(null), disabled = false,
        onerror = undefined } = $props();
  const needsKeyfile = $derived(factors.some((f) => f.kind === 'keyfile'));
  const yubikey = $derived(factors.find((f) => f.kind === 'yubikey-hmac'));
  let touching = $state(false);
  let again = $state(false);
  let keep = $state(true);

  $effect(() => { keep = remember !== false; });

  $effect(() => {
    const offs = [
      on('factors.touch', (d) => { touching = !!d.waiting; if (!d.waiting) again = false; }),
      on('factors.touch_again', () => { again = true; }),
    ];
    return () => offs.forEach((off) => off());
  });

  async function choose() {
    const result = await call('factors_pick_keyfile');
    if (result.ok) picked = { name: result.name };
    else if (result.error.code !== 'cancelled') onerror?.(result.error.message);
  }

  async function setRemember(event) {
    const value = event.currentTarget.checked;
    const result = await call('factors_set_remember', value);
    if (result.ok) keep = result.remember !== false;
    else { keep = !value; onerror?.(result.error.message); }
  }

  function cancel() { call('factors_cancel'); }

  const shown = $derived(picked?.name ?? keyfileName);
</script>

{#if needsKeyfile}
  <div class="factor" role="group" aria-label={t('factors.keyFile')}>
    <span class="name">{shown ? t('factors.prompt.chosen', { name: shown }) : t('factors.prompt.noneChosen')}</span>
    <Button label={t('factors.prompt.choose')} onclick={choose} {disabled} />
    <label class="toggle"><input type="checkbox" checked={keep} onchange={setRemember} {disabled} /> {t('factors.prompt.remember')}</label>
  </div>
{/if}
{#if touching}
  <div class="touch" role="status">
    <span>{again ? t('factors.prompt.touchAgain') : t('factors.prompt.touch')}</span>
    <Button label={t('common.cancel')} onclick={cancel} />
  </div>
{:else if yubikey}
  <p class="note">{t('factors.prompt.yubikeyNeeded', { slot: yubikey.slot ?? 2 })}</p>
{/if}

<style>
  .factor { width: 100%; display: grid; grid-template-columns: 1fr auto; gap: 6px 8px; align-items: center; }
  .name { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .toggle { grid-column: 1 / -1; display: flex; gap: 8px; align-items: center; font-size: 12.5px; color: var(--text-muted); }
  .touch { width: 100%; display: flex; gap: 8px; align-items: center; justify-content: space-between; padding: 8px 12px;
    border-radius: 10px; background: color-mix(in srgb, var(--accent) 14%, transparent); font-weight: 600; }
  .note { margin: 0; font-size: 12.5px; color: var(--text-muted); text-align: center; }
</style>
