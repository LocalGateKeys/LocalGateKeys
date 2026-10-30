<script>
  import { t } from './lib/i18n.svelte.js';
  import Modal from './components/Modal.svelte';
  import Toast from './components/Toast.svelte';
  import { call, on } from './lib/api.js';
  import ProfileChooser from './screens/ProfileChooser.svelte';
  import Unlock from './screens/Unlock.svelte';
  import Home from './screens/Home.svelte';
  import PasswordModal from './components/PasswordModal.svelte';
  import LegacyScreen from './screens/LegacyScreen.svelte';
  import PasskeyModal from './components/PasskeyModal.svelte';
  import ChoiceModal from './components/ChoiceModal.svelte';

  // Request kinds this build can show; anything else is declined at once so
  // Python is not left waiting for the timeout.
  const SUPPORTED = new Set(['confirm', 'password', 'upgrade', 'passkey', 'choose', 'confirm_remember']);

  let vault = $state(null);
  let appearance = $state('system');

  // Theme: "system" follows Windows (CSS media query); light/dark are explicit choices.
  $effect(() => {
    const root = document.documentElement;
    if (appearance === 'light' || appearance === 'dark') root.dataset.theme = appearance;
    else delete root.dataset.theme;
  });
  $effect(() => { if (vault?.appearance) appearance = vault.appearance; });
  // With "system", follow a live Windows theme change in the title bar too.
  $effect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!media) return;
    const sync = () => { if (appearance === 'system') call('window_theme_sync'); };
    media.addEventListener?.('change', sync);
    return () => media.removeEventListener?.('change', sync);
  });
  let choosingProfile = $state(false);
  let modals = $state([]);
  let notices = 0;

  $effect(() => {
    // Re-read the real state on every load (a reload must never show stale "unlocked").
    call('vault_state').then((result) => { if (result.ok) vault = result; });
    const offs = [
      on('vault.state', (detail) => { vault = detail; }),
      on('appearance', (detail) => { appearance = detail.appearance; }),
      // Tray, hotkeys and the browser host ask for a page (quick access, updates).
      on('navigate', (detail) => window.dispatchEvent(new CustomEvent('lgk-route', { detail }))),
      on('modal.request', (detail) => {
        if (detail.surface === 'popup') return; // shown by the small popup window
        if (!SUPPORTED.has(detail.kind)) {
          call('modal_answer', detail.id, { choice: 'cancel' });
          return;
        }
        modals.push(detail);
      }),
      // A notice from Python (rollback reset): stays until dismissed; nothing waits on the answer.
      on('notice', (detail) => { modals.push({ ...detail, id: `notice-${++notices}`, kind: 'notice' }); }),
      on('modal.cancel', (detail) => {
        const ids = new Set(detail.ids ?? []);
        modals = modals.filter((m) => !ids.has(m.id));
      }),
    ];
    return () => offs.forEach((off) => off());
  });

  // Opens the checkout in the browser; the buyer comes back to Tools > Licence with the key.
  function buyPro(id, url) {
    call('system_open_url', url);
    answer(id, 'cancel');
  }

  function upgradeAnswer(id, yes) {
    answer(id, yes ? 'enter' : 'cancel');
    if (yes) window.dispatchEvent(new CustomEvent('lgk-route', { detail: { route: 'licence' } }));
  }

  function answer(id, value) {
    modals = modals.filter((m) => m.id !== id);
    call('modal_answer', id, value);
  }

  const showChooser = $derived(vault && (vault.state === 'no_profile' || ((choosingProfile || vault.choose_profile) && vault.state !== 'unlocked')));
</script>

<div class="wash" aria-hidden="true"></div>
<div class="shell">
  <main>
    {#if !vault}
      <!-- waiting for vault_state -->
    {:else if vault.state === 'legacy'}
      <LegacyScreen {vault} onchosen={(state) => { vault = state; }} />
    {:else if showChooser}
      <ProfileChooser onchosen={(state) => { vault = state; choosingProfile = false; }} />
    {:else if vault.state === 'unlocked'}
      <Home {vault} />
    {:else}
      <Unlock {vault} onswitchprofile={() => (choosingProfile = true)} />
    {/if}
  </main>
</div>

{#if modals.length}
  {@const modal = modals[0]}
  {#key modal.id}
    {#if modal.kind === 'password'}
      <PasswordModal title={modal.title} message={modal.message} onanswer={(value) => answer(modal.id, value)} />
    {:else if modal.kind === 'passkey'}
      <PasskeyModal request={modal} onanswer={(value) => answer(modal.id, value)} />
    {:else if modal.kind === 'choose' || modal.kind === 'confirm_remember'}
      <ChoiceModal request={modal} onanswer={(value) => answer(modal.id, value)} />
    {:else if modal.kind === 'notice'}
      <Modal title={modal.title} message={modal.message} allowLabel={t('common.ok')} denyLabel=""
        onanswer={() => (modals = modals.filter((m) => m.id !== modal.id))} />
    {:else if modal.kind === 'upgrade'}
      <Modal title="LocalGateKeys Pro" message={modal.message} allowLabel={t('app.enterLicence')} denyLabel={t('common.notNow')}
        extraLabel={modal.purchase_url ? t('app.buyPro') : ''} onextra={() => buyPro(modal.id, modal.purchase_url)}
        onanswer={(yes) => upgradeAnswer(modal.id, yes)} />
    {:else}
      <Modal title={modal.title} message={modal.message} onanswer={(value) => answer(modal.id, value)} />
    {/if}
  {/key}
{/if}
<Toast />

<style>
  .shell { height: 100%; display: flex; flex-direction: column; }
  main { flex: 1; min-height: 0; }
</style>
