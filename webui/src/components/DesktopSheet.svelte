<script>
  /** Desktop app logins: bind an app (map its fields), refresh a binding, or fill a saved login now. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { call } from '../lib/api.js';
  import { notice, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { token = null, entryId = null, onclose } = $props();
  let form = $state(null);
  let countdown = $state(0);
  let userIndex = $state('');
  let passwordIndex = $state('');
  let label = $state('');
  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);
  let signIn = $state(null); // {token, app, title, current, buttons}

  async function mapSignIn() {
    error = '';
    const r = await call('desktop_signin_scan', entryId);
    if (r.ok) signIn = r; else if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function chooseButton(index) {
    error = '';
    const r = await call('desktop_signin_save', signIn.token, index);
    if (r.ok) { notice(r); signIn = null; return; }
    if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function warnAgain() {
    const r = await call('desktop_web_warning_reset', entryId);
    if (r.ok) toast(r.message); else error = r.error.message;
  }

  function use(r) {
    form = r;
    userIndex = r.user_index ?? '';
    passwordIndex = r.password_index ?? '';
    label = r.label ?? '';
  }

  async function countdownThen(method, ...args) {
    error = '';
    countdown = 3;
    const tick = setInterval(() => { countdown = Math.max(0, countdown - 1); }, 1000);
    const r = await call(method, ...args);
    clearInterval(tick);
    countdown = 0;
    return r;
  }

  async function inspect() {
    const r = await countdownThen('desktop_bind_scan', entryId);
    if (r.ok) use(r); else error = r.error.message;
  }

  async function fillNow() {
    const r = await countdownThen('desktop_fill', entryId);
    if (!r.ok && r.error.code !== 'cancelled') error = r.error.message;
  }

  $effect(() => {
    if (token) call('desktop_bind_form', token).then((r) => { if (r.ok) use(r); else error = r.error.message; });
    return () => { password = ''; };
  });

  async function save(event) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    const r = await call('desktop_bind_save', form.token, userIndex === '' ? null : Number(userIndex),
      Number(passwordIndex), label, username, password);
    busy = false;
    password = '';
    if (r.ok) { toast(r.message); onclose(); return; }
    if (r.error.code !== 'cancelled') error = r.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-label={t('desktopSheet.title')}>
  <header>
    <h2>{form ? (form.rebind ? t('desktopSheet.refreshTitle') : t('desktopSheet.mapTitle')) : t('desktopSheet.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if countdown}
    <p class="big" role="status">{t('desktopSheet.countdown', { count: countdown, number: formatNumber(countdown) })}</p>
  {:else if signIn}
    <p class="muted pre">{t('desktopSheet.signInInfo', { app: signIn.app, window: signIn.title, current: signIn.current })}</p>
    <p class="muted">{t('desktopSheet.chooseOnly')}</p>
    <div class="group buttons" role="group" aria-label={t('desktopSheet.buttonsInApp')}>
      {#each signIn.buttons as b (b.index)}<button class="choice" onclick={() => chooseButton(b.index)}>{b.name}</button>{/each}
    </div>
    <footer><Button label={t('common.back')} onclick={() => (signIn = null)} /></footer>
  {:else if !form}
    <p class="muted">{t('desktopSheet.explain')}</p>
    <footer>
      {#if entryId}<Button label={t('desktopSheet.fillNow')} variant="primary" onclick={fillNow} />{/if}
      <Button label={entryId ? t('desktopSheet.refreshBinding') : t('desktopSheet.inspect')} variant={entryId ? undefined : 'primary'} onclick={inspect} />
    </footer>
    {#if entryId}
      <footer>
        <Button label={t('desktopSheet.mapSignIn')} onclick={mapSignIn} />
        <Button label={t('desktopSheet.warnAgain')} onclick={warnAgain} />
      </footer>
      <p class="muted">{t('desktopSheet.refreshNote')}</p>
    {/if}
    <p class="muted">{t('desktopSheet.tip')}</p>
  {:else}
    <form onsubmit={save}>
      <p class="muted pre">{form.title}{'\n'}{form.app}{'\n'}{form.intro}</p>
      <div class="group">
        <label class="row"><span>{t('desktopSheet.usernameField')}</span>
          <select aria-label={t('desktopSheet.usernameField')} bind:value={userIndex}>
            <option value="">{t('desktopSheet.none')}</option>
            {#each form.controls as c (c.index)}<option value={c.index}>{c.label}</option>{/each}
          </select>
        </label>
        <label class="row"><span>{t('desktopSheet.passwordField')}</span>
          <select aria-label={t('desktopSheet.passwordField')} bind:value={passwordIndex}>
            {#each form.controls as c (c.index)}<option value={c.index}>{c.label}</option>{/each}
          </select>
        </label>
      </div>
      {#if !form.rebind}
        <div class="group">
          <Field label={t('desktopSheet.label')} bind:value={label} />
          <Field label={t('desktopSheet.usernameOrEmail')} bind:value={username} />
          <Field label={t('desktopSheet.passwordTyped')} type="password" bind:value={password} autocomplete="new-password" />
        </div>
      {/if}
      <footer>
        <Button label={t('common.cancel')} onclick={onclose} />
        <Button type="submit" variant="primary" label={form.rebind ? t('desktopSheet.saveBinding') : t('desktopSheet.saveLogin')} busy={busy} busyLabel={t('common.saving')} disabled={passwordIndex === ''} />
      </footer>
    </form>
  {/if}
  {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 33; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 10px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .pre { white-space: pre-line; word-break: break-all; }
  .big { font: 600 16px var(--font-display); text-align: center; padding: 30px 0; }
  .row { display: flex; align-items: center; gap: 10px; padding: 8px 14px; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row span { width: 130px; color: var(--text-muted); }
  select { flex: 1; min-width: 0; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px; }
  form { display: grid; gap: 10px; }
  .error { color: var(--danger); margin: 0; }
  .buttons { display: grid; }
  .choice { text-align: left; padding: 9px 14px; background: none; border: none; color: inherit; cursor: pointer; }
  .choice + .choice { border-top: 1px solid var(--separator); }
  .choice:hover { background: var(--group); }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
