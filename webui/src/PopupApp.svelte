<script>
  /** The small popup window: unlock (profile chips, password, Hello, camera) and the questions a fill asks
   * when it was started outside the app (field button, Ctrl+Shift+Space, browser). Python shows and hides it. */
  import { t } from './lib/i18n.svelte.js';
  import Modal from './components/Modal.svelte';
  import PasswordModal from './components/PasswordModal.svelte';
  import PasskeyModal from './components/PasskeyModal.svelte';
  import ChoiceModal from './components/ChoiceModal.svelte';
  import { call, on } from './lib/api.js';
  import ProfileChooser from './screens/ProfileChooser.svelte';
  import Unlock from './screens/Unlock.svelte';

  // The popup appears on top of whatever the user is typing in: approvals stay inert this long.
  const GUARD_MS = 500;
  const SUPPORTED = new Set(['confirm', 'password', 'upgrade', 'passkey', 'choose', 'confirm_remember']);
  let vault = $state(null);
  let modals = $state([]);
  let choosingProfile = $state(false);

  $effect(() => {
    if (vault?.appearance === 'light' || vault?.appearance === 'dark') document.documentElement.dataset.theme = vault.appearance;
    else delete document.documentElement.dataset.theme;
  });

  $effect(() => {
    call('vault_state').then((result) => { if (result.ok) vault = result; });
    const offs = [
      on('vault.state', (detail) => { vault = detail; if (detail.state === 'unlocked') choosingProfile = false; }),
      on('modal.request', (detail) => {
        if (detail.surface !== 'popup') return; // the main window's own questions
        if (!SUPPORTED.has(detail.kind)) { call('modal_answer', detail.id, { choice: 'cancel' }); return; }
        modals.push(detail);
      }),
      on('modal.cancel', (detail) => {
        const ids = new Set(detail.ids ?? []);
        modals = modals.filter((m) => !ids.has(m.id));
      }),
    ];
    return () => offs.forEach((off) => off());
  });

  function answer(id, value) {
    modals = modals.filter((m) => m.id !== id);
    call('modal_answer', id, value);
  }
</script>

<div class="wash" aria-hidden="true"></div>
<main class="popup">
  {#if modals.length}
    {@const modal = modals[0]}
    {#key modal.id}
      {#if modal.kind === 'password'}
        <PasswordModal title={modal.title} message={modal.message} onanswer={(value) => answer(modal.id, value)} />
      {:else if modal.kind === 'passkey'}
        <PasskeyModal request={modal} guardMs={GUARD_MS} onanswer={(value) => answer(modal.id, value)} />
      {:else if modal.kind === 'choose' || modal.kind === 'confirm_remember'}
        <ChoiceModal request={modal} guardMs={GUARD_MS} onanswer={(value) => answer(modal.id, value)} />
      {:else if modal.kind === 'upgrade'}
        <Modal title="LocalGateKeys Pro" message={modal.message} allowLabel={t('app.enterLicence')} denyLabel={t('common.notNow')} guardMs={GUARD_MS}
          extraLabel={modal.purchase_url ? t('app.buyPro') : ''}
          onextra={() => { call('system_open_url', modal.purchase_url); answer(modal.id, 'cancel'); }}
          onanswer={(yes) => answer(modal.id, yes ? 'enter' : 'cancel')} />
      {:else}
        <Modal title={modal.title} message={modal.message} guardMs={GUARD_MS} onanswer={(value) => answer(modal.id, value)} />
      {/if}
    {/key}
  {:else if vault && vault.state !== 'unlocked'}
    {#if choosingProfile || vault.state === 'no_profile'}
      <ProfileChooser onchosen={(state) => { vault = state; choosingProfile = false; }} />
    {:else}
      <Unlock {vault} brand={false} onswitchprofile={() => (choosingProfile = true)} />
    {/if}
  {:else}
    <p class="done" role="status">{t('popup.unlocked')}</p>
  {/if}
</main>

<style>
  .popup { height: 100%; overflow: auto; }
  .done { text-align: center; color: var(--text-muted); margin-top: 40vh; }
</style>
