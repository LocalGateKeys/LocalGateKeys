<script>
  /** Unlock an existing vault, or create one for a profile without a vault.
   *  Locked extras: profile chips, "Locked … ago", throttling countdown, recovery-phrase recovery, backups. */
  import ErrorLogLink from '../components/ErrorLogLink.svelte';
  import Button from '../components/Button.svelte';
  import Field from '../components/Field.svelte';
  import RecoveryPage from '../components/RecoveryPage.svelte';
  import CameraView from '../components/CameraView.svelte';
  import { call } from '../lib/api.js';
  import mark from '../../../src/localvault/assets/localgatekeys_mark.png';

  // brand: the logo and name above the card (the small fill popup leaves it out).
  let { vault, onswitchprofile = undefined, brand = true } = $props();

  let password = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state('');
  let mode = $state('unlock'); // 'unlock' | 'recover' | 'backups'
  let phrase = $state('');
  let wait = $state(0);
  const creating = $derived(!vault.vault_exists);
  let alt = $state(''); // 'hello' | 'camera' while one is running
  let altNote = $state('');
  let autoTried = false;

  async function useHello() {
    if (alt || busy) return;
    alt = 'hello'; error = '';
    altNote = 'Complete the Windows Security prompt. Cancel it to return to your master password.';
    const result = await call('vault_unlock_hello');
    alt = ''; altNote = '';
    if (!result.ok) { error = result.error.message; backToPassword(result.error.code); }
  }

  async function useCamera() {
    if (alt || busy) return;
    alt = 'camera'; error = '';
    const result = await call('vault_unlock_face');
    alt = '';
    if (!result.ok) {
      error = result.error.code === 'cancelled' ? result.error.message : (result.error.message || 'Camera verification was not accepted. Use your master password.');
      backToPassword(result.error.code);
    }
  }

  $effect(() => {
    // Auto-start once per lock screen, after the window exists to own the Windows Security prompt.
    if (vault.hello && vault.hello_auto && !creating && !autoTried && mode === 'unlock') {
      autoTried = true;
      setTimeout(useHello, 250);
    }
  });

  $effect(() => {
    wait = vault.backoff ?? 0;
    if (!wait) return;
    const timer = setInterval(() => { wait = Math.max(0, wait - 1); if (!wait) clearInterval(timer); }, 1000);
    return () => clearInterval(timer);
  });

  // Face or Hello did not work: the master password is the way in, so put the cursor there.
  function backToPassword(code) {
    if (code === 'face_setup') {
      try { window.sessionStorage.setItem('lgk.afterUnlock', JSON.stringify({ route: 'settings', params: { section: 'unlocking' } })); } catch { /* optional */ }
    }
    setTimeout(() => document.querySelector('.unlock input[type="password"]')?.focus(), 0);
  }

  function wipe() { password = ''; confirm = ''; phrase = ''; }

  async function submit(event) {
    event.preventDefault();
    if (busy || wait) return;
    busy = true;
    error = '';
    let result;
    if (mode === 'recover') result = await call('vault_recover', phrase, password, confirm);
    else if (creating) result = await call('vault_create', password, confirm);
    else result = await call('vault_unlock', password);
    busy = false;
    // Never keep the master password or phrase in the page, whatever the outcome.
    wipe();
    if (!result.ok) {
      error = result.error.message;
      if (result.error.code === 'throttled') {
        const state = await call('vault_state');
        if (state.ok) wait = state.backoff ?? 0;
      }
    }
    // On success Python emits vault.state and App switches screens.
  }

  async function pick(chip) {
    if (chip.active) return;
    const result = await call('profiles_select', chip.id);
    if (!result.ok) error = result.error.message;
  }
</script>

{#if alt === 'camera'}<CameraView title="Camera verification" mode="verify" />{/if}
{#if mode === 'backups'}
  <RecoveryPage onclose={() => (mode = 'unlock')} />
{/if}

<section class="unlock">
  {#if brand}
    <header class="brand">
      <img src={mark} alt="" width="64" height="64" />
      <p class="name">Local<span>Gate</span>Keys</p>
      <p class="tagline">Your keys. Your control.</p>
    </header>
  {/if}
  <form class="card glass" onsubmit={submit}>
    {#if vault.chips?.length > 1}
      <div class="chips" role="list" aria-label="Profiles">
        {#each vault.chips as chip (chip.id)}
          <span role="listitem"><button type="button" class="chip" class:on={chip.active} aria-pressed={chip.active}
                  title={chip.name} aria-label={chip.name} onclick={() => pick(chip)}>{chip.initial}</button></span>
        {/each}
      </div>
    {/if}
    <div class="avatar" style:background={vault.profile?.color} aria-hidden="true">
      {(vault.profile?.name ?? '?').slice(0, 1).toUpperCase()}
    </div>
    <h1>{vault.profile?.name ?? 'LocalGateKeys'}</h1>
    {#if creating}
      <p class="hint">Choose a master password (at least 12 characters). Keep it for recovery; optional camera verification or Windows Hello can be set up later.</p>
    {:else if mode === 'recover'}
      <p class="hint">Enter your 24-word recovery phrase, separated by spaces, then choose a new master password. The vault is re-encrypted with a new key; your recovery phrase keeps working, and Windows Hello and camera verification need to be set up again.</p>
    {:else}
      <p class="hint">{vault.subtitle ?? 'Vault locked'}</p>
    {/if}
    {#if vault.status}<p class="status" role="status">{vault.status}</p>{/if}

    <div class="group fields">
      {#if mode === 'recover'}
        <Field label="Recovery phrase" type="password" bind:value={phrase} autofocus />
        <Field label="New master password (at least 12 characters)" type="password" bind:value={password} autocomplete="new-password" />
        <Field label="Enter the new master password again" type="password" bind:value={confirm} autocomplete="new-password" />
      {:else}
        <Field label="Master password" type="password" bind:value={password} autofocus autocomplete={creating ? 'new-password' : 'current-password'} invalid={!!error} />
        {#if creating}
          <Field label="Confirm password" type="password" bind:value={confirm} autocomplete="new-password" />
        {/if}
      {/if}
    </div>

    {#if altNote}<p class="status" role="status">{altNote}</p>{/if}
    {#if wait}<p class="error" role="alert">Too many incorrect attempts. Try again in {wait} s.</p>
    {:else if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}

    <div class="actions">
      <Button type="submit" variant="primary" disabled={!!wait}
              label={mode === 'recover' ? 'Recover vault' : creating ? 'Create vault' : 'Unlock'}
              busy={busy} busyLabel={creating ? 'Creating…' : 'Unlocking…'} />
    </div>
    {#if mode === 'unlock' && !creating && vault.hello}
      <div class="actions"><Button label="Unlock with Windows Hello" onclick={useHello} busy={alt === 'hello'} busyLabel="Waiting for Windows…" disabled={!!wait} /></div>
      <p class="or">or use your master password</p>
    {/if}
    <div class="links">
      {#if mode === 'unlock' && !creating && vault.camera}
        <Button variant="link" label="Use camera instead" onclick={useCamera} disabled={!!alt || !!wait} />
      {/if}
      {#if mode === 'recover'}
        <Button variant="link" label="Back to unlock" onclick={() => { mode = 'unlock'; wipe(); error = ''; }} />
      {:else if !creating && vault.recovery_phrase}
        <Button variant="link" label="Forgot it? Use recovery phrase" onclick={() => { mode = 'recover'; wipe(); error = ''; }} />
      {/if}
      {#if !creating}<Button variant="link" label="Backup & restore" onclick={() => (mode = 'backups')} />{/if}
      {#if onswitchprofile}<Button variant="link" label="Use another profile" onclick={onswitchprofile} />{/if}
    </div>
  </form>
</section>

<style>
  /* The card stays centred in the window; the brand sits centred in the space above it. */
  .unlock { height: 100%; display: grid; grid-template-rows: 1fr auto minmax(24px, 1fr); justify-items: center; padding: 0 24px; overflow-y: auto; }
  .unlock > .card { grid-row: 2; }
  .brand { grid-row: 1; align-self: center; display: grid; justify-items: center; gap: 4px; padding: 12px 0; text-align: center; }
  .brand img { width: 64px; height: 64px; border-radius: 16px; margin-bottom: 6px; }
  .brand .name { margin: 0; font: 700 26px var(--font-display); letter-spacing: -0.01em; }
  .brand .name span { color: var(--brand-text); }
  .brand .tagline { margin: 0; font-size: 11.5px; letter-spacing: 0.18em; text-transform: uppercase; color: var(--text-muted); }
  .card {
    width: min(420px, 100%);
    border-radius: var(--radius-card);
    padding: 28px 24px 20px;
    display: grid;
    justify-items: center;
    gap: 10px;
  }
  .chips { display: flex; gap: 6px; }
  .chip { width: 30px; height: 30px; border-radius: 50%; border: 1px solid var(--separator); background: var(--group); color: inherit; cursor: pointer; }
  .chip.on { background: var(--accent); color: #fff; }
  .avatar {
    width: 56px; height: 56px; border-radius: 16px;
    display: grid; place-items: center;
    font: 600 24px var(--font-display); color: #fff;
  }
  h1 { margin: 6px 0 0; font: 600 20px var(--font-display); }
  .hint { margin: 0 0 6px; color: var(--text-muted); text-align: center; }
  .status { margin: 0; font-size: 12.5px; color: var(--text-muted); text-align: center; }
  .fields { width: 100%; }
  .error { margin: 2px 0 0; color: var(--danger); text-align: center; }
  .actions { width: 100%; display: grid; margin-top: 6px; }
  .actions :global(.btn) { height: 38px; }
  .or { margin: 0; color: var(--text-faint); font-size: 12px; }
  .links { display: flex; flex-wrap: wrap; justify-content: center; gap: 4px 12px; }
</style>
