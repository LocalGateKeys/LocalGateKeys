<script>
  /** Device sync: Wi-Fi and cloud-folder cards. Every action is one Python call; forms clear their passwords after it. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call, on } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose, onlicence } = $props();
  let view = $state(null);
  let form = $state(null); // {kind, title, intro, folder, twice, ...}
  let folder = $state(null); // {token, path}
  let pw = $state('');
  let pw2 = $state('');
  let strength = $state(null);
  let text = $state('');
  let picked = $state([]);
  let error = $state('');
  let working = $state(false);
  let qr = $state(null);
  let qrProblem = $state(''); // the listener is not running: no QR, only the reason and the address
  let paired = $state(null); // {id, name, fingerprint, message}: who just paired by QR, with Undo
  let confirm = $state(null); // {id, name, code, fingerprint, seconds, message, adding}: a device waits for Accept
  let firewall = $state(null); // {supported, allowed, profile, advice}
  let firewallBusy = $state(false);
  let qrTimer = null;
  let viewportWidth = $state(typeof window === 'undefined' ? 1024 : window.innerWidth);
  // Whole CSS pixels per module: at most the size Python chose (≤ 260px) and about 60% of a narrow window.
  const qrPx = $derived.by(() => {
    const size = qr?.size ?? 240;
    const modules = qr?.modules || 0;
    if (!modules) return Math.min(size, 260);
    const fit = Math.min(size, 260, Math.floor(viewportWidth * 0.6));
    return modules * Math.max(1, Math.floor(fit / modules));
  });

  async function load(method = 'sync_view') {
    const result = await call(method);
    if (result.ok) view = result;
    else if (method === 'sync_refresh') load('sync_view'); // busy: show the current view instead
    else okOrToast(result, t('syncPage.openFailed'));
  }

  $effect(() => {
    load('sync_refresh');
    const off = on('sync.status', () => load());
    // Leaving the page disarms an open pairing code, as closing the classic QR window did.
    return () => { off(); if (qr) closeQr(); stopQr(); wipe(); };
  });

  function wipe() { pw = ''; pw2 = ''; text = ''; strength = null; }
  function closeForm() { form = null; folder = null; picked = []; error = ''; wipe(); }

  async function check() {
    if (!form?.twice || !pw) { strength = null; return; }
    const result = await call('sync_password_check', pw, pw2);
    if (result.ok) strength = result;
  }

  function done(result) {
    working = false;
    wipe();
    if (!result.ok) { if (result.error.code !== 'cancelled') error = result.error.message; return false; }
    closeForm();
    if (result.message) toast(result.message);
    if (result.cards) view = result;
    return true;
  }

  async function act(action, card) {
    error = '';
    if (action === 'sync-now') { await call('sync_now'); return; }
    if (action === 'create-group') {
      form = { kind: 'create', title: t('syncPage.createTitle'), folder: true, twice: true,
        intro: t('syncPage.createIntro') };
    } else if (action === 'join-folder') {
      form = { kind: 'join', title: t('syncPage.joinFolderTitle'), folder: true, twice: false,
        intro: t('syncPage.joinFolderIntro') };
    } else if (action === 'add-folder' || action === 'use-folder') {
      const setup = await call('sync_setup_text', action);
      if (okOrToast(setup)) form = { kind: 'setup', action, title: setup.title, intro: setup.intro, folder: true, twice: setup.confirm_twice };
    } else if (action === 'change-password') {
      const r = await call('sync_rotation_text');
      if (okOrToast(r)) form = { kind: 'rotate', title: r.title, intro: r.intro, folder: false, twice: true };
    } else if (action === 'remove-device') {
      const info = await call('sync_remove_info', card);
      if (okOrToast(info)) form = { kind: 'remove', card, title: t('syncPage.removeTitle'), devices: info.devices,
        twice: info.needs_password, folder: false, intro: info.needs_password ? t('syncPage.removeNeedsPassword') : '' };
    } else if (action === 'show-orphans') {
      const r = await call('sync_orphans');
      if (!okOrToast(r)) return;
      if (!r.devices.length) { toast(r.message); return; }
      form = { kind: 'orphans', title: t('syncPage.removeDevicesTitle'), devices: r.devices, twice: true, folder: false, intro: r.intro };
    } else if (action === 'ack-members') {
      done(await call('sync_acknowledge_members'));
    } else if (action === 'leave') {
      done(await call('sync_leave'));
    } else if (action === 'reset') {
      done(await call('sync_reset'));
    } else if (action === 'show-qr') {
      await showQr();
    } else if (action === 'find-again') {
      form = { kind: 'refind', title: t('syncPage.findTitle'), intro: t('syncPage.findIntro') };
    } else if (action === 'join-qr') {
      form = { kind: 'qrtext', title: t('syncPage.joinQrTitle'), intro: t('syncPage.joinQrIntro') };
    } else if (action === 'wifi-enable') {
      const r = await call('sync_wifi_suggest');
      if (okOrToast(r)) { text = r.value; form = { kind: 'wifi', title: t('syncPage.wifiTitle'), intro: r.intro, choices: r.choices ?? [] }; }
    } else if (action === 'wifi-disable') {
      const r = await call('sync_wifi_disable');
      if (okOrToast(r)) view = r;
    }
  }

  async function chooseFolder() {
    const r = await call('sync_choose_folder');
    if (r.ok) folder = r;
    else if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function submit(event) {
    event.preventDefault();
    if (working) return;
    working = true; error = '';
    const f = form;
    let result;
    if (f.kind === 'create') result = await call('sync_create', folder?.token ?? '', pw, pw2);
    else if (f.kind === 'join') result = await call('sync_join', folder?.token ?? '', pw);
    else if (f.kind === 'setup') result = await call('sync_folder_setup', f.action, folder?.token ?? '', pw, pw2);
    else if (f.kind === 'rotate') result = await call('sync_change_password', pw, pw2);
    else if (f.kind === 'remove') result = await call('sync_remove_device', f.card, picked[0] ?? '', pw, pw2);
    else if (f.kind === 'orphans') result = await call('sync_remove_orphans', picked, pw, pw2);
    else if (f.kind === 'qrtext') result = await call('sync_join_qr', text);
    else if (f.kind === 'refind') result = await call('sync_find_again_qr', text);
    else if (f.kind === 'wifi') result = await call('sync_wifi_enable', text);
    else if (f.kind === 'pick') result = await call('sync_wifi_enable', picked[0] ?? '');
    if (done(result) && f.folder) folder = null;
    if (f.kind === 'pick' && result?.ok) await showQr(); // the chosen address is saved: show the code now
  }

  async function showQr() {
    qrProblem = '';
    const r = await call('sync_qr_show');
    if (!r.ok && r.error?.code === 'listen_failed') { qrProblem = r.error.message; return; }
    if (!okOrToast(r, t('syncPage.noPairingCode'))) return;
    if (r.choose_address) {
      const keep = r.addresses.find((a) => a.value === r.current);
      picked = keep ? [keep.value] : r.addresses.length ? [r.addresses[0].value] : [];
      form = { kind: 'pick', title: t('syncPage.chooseAddressTitle'), intro: r.message, devices: r.addresses.map((a) => ({ id: a.value, name: a.label, detail: '' })) };
      return;
    }
    qr = r; startQr();
    if (r.notice) toast(r.notice);
    loadFirewall();
  }

  async function loadFirewall() {
    firewall = null;
    const r = await call('sync_firewall_status');
    if (r.ok && r.supported) firewall = r;
  }
  async function allowFirewall() {
    if (firewallBusy) return;
    firewallBusy = true;
    const r = await call('sync_firewall_allow');
    firewallBusy = false;
    if (r.ok) { firewall = r; toast(r.message); } else if (r.error.code !== 'cancelled') okOrToast(r, t('syncPage.firewallNotChanged'));
  }

  function startQr() {
    stopQr();
    qrTimer = setInterval(async () => {
      if (!qr) return;
      const r = await call('sync_qr_poll', qr.offer_id);
      showQrState(r);
    }, 1000);
  }
  function showQrState(r) {
    if (!r.ok || r.state === 'closed' || r.state === 'expired') { stopQr(); qr = null; confirm = null; return; }
    if (r.state === 'paired') {
      stopQr(); qr = null; confirm = null; firewall = null;
      paired = r.device ? { ...r.device, message: r.message } : null;
      if (!paired) toast(r.message);
      load('sync_refresh');
      return;
    }
    if (r.state === 'declined') { stopQr(); qr = null; confirm = null; firewall = null; toast(r.message); return; }
    if (r.state === 'confirm') { confirm = { ...r.device, seconds: r.seconds_left, message: r.message }; return; }
    if (r.state === 'adding') { confirm = confirm ? { ...confirm, adding: true, message: r.message } : null; return; }
    confirm = null;
    qr = { ...qr, countdown: r.countdown };
  }
  // Accept admits the device only if both screens show the same code; Decline (or no answer) refuses it.
  async function decide(accept) {
    if (!qr || !confirm || confirm.adding) return;
    const id = qr.offer_id;
    if (accept) confirm = { ...confirm, adding: true };
    const r = await call('sync_qr_poll', id, accept ? 'accept' : 'decline');
    if (!r.ok) { okOrToast(r); confirm = null; return; }
    if (qr?.offer_id === id) showQrState(r);
  }
  function stopQr() { clearInterval(qrTimer); qrTimer = null; }
  async function closeQr() {
    const id = qr?.offer_id;
    stopQr(); qr = null; confirm = null; firewall = null;
    if (id) await call('sync_qr_close', id);
  }
  async function copyQr() {
    const r = await call('sync_qr_copy', qr.offer_id);
    if (okOrToast(r)) toast(r.message);
  }

  async function undoPairing() {
    // Undo = Remove a device on the Wi-Fi card with the new device chosen (a cloud-folder group also changes the
    // sync password there, because the new device already received the group key).
    const id = paired?.id;
    paired = null;
    await load('sync_refresh');
    await act('remove-device', 'wifi');
    if (form?.kind === 'remove' && form.devices.some((d) => d.id === id)) picked = [id];
  }

  // Rollback witnesses: "This was me" asks and re-authenticates in Python; Dismiss accepts a peer's older copy.
  async function keepThisCopy() {
    if (working) return;
    working = true;
    done(await call('sync_acknowledge_rollback'));
  }
  async function dismissPeer(id) {
    if (working) return;
    working = true;
    done(await call('sync_dismiss_peer_rollback', id));
  }

  function toggle(id) { picked = picked.includes(id) ? picked.filter((x) => x !== id) : [...picked, id]; }
  const needsPick = $derived(form && (form.kind === 'remove' || form.kind === 'orphans' || form.kind === 'pick'));
  const canSubmit = $derived(form && (!form.folder || folder) && (!needsPick || picked.length)
    && (['qrtext', 'refind', 'wifi'].includes(form.kind) ? text.trim() : (form.kind === 'remove' && !form.twice) || form.kind === 'pick' || pw));
</script>

<svelte:window bind:innerWidth={viewportWidth} />

<div class="sheet glass" role="dialog" aria-label={t('syncPage.title')}>
  <header>
    <h2>{t('syncPage.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  {#if view && view.pro === false}
    <section class="group card" aria-label="LocalGateKeys Pro">
      <h3>LocalGateKeys Pro</h3>
      <p class="muted">{view.pro_text}</p>
      <div class="actions">
        <Button label={t('syncPage.enterLicence')} variant="primary" onclick={() => onlicence?.()} />
      </div>
    </section>
  {/if}
  <!-- Free plan with a licence-only service: pairing and Sync now stay available, so a licence bought on a phone can arrive. -->
  {#if view && (view.pro !== false || view.licence_only)}
    <p class="muted">{view.intro}</p>
    {#if view.status_line}<p class="status" role="status">{view.status_line}<ErrorLogLink text={view.status_line} /></p>{/if}
    {#if view.rollback?.own}
      <div class="banner {view.rollback.own.severity}" role="alert" aria-label={view.rollback.own.title}>
        <strong>{view.rollback.own.title}</strong>
        <p>{view.rollback.own.text}</p>
        <div class="actions">
          <Button label={view.rollback.own.action} variant="primary" disabled={view.busy || working} onclick={keepThisCopy} />
        </div>
      </div>
    {/if}
    {#each view.rollback?.peers ?? [] as p (p.id)}
      <div class="banner {p.severity}" role="status">
        <p>{p.text}</p>
        <div class="actions">
          <Button label={p.action} disabled={view.busy || working} onclick={() => dismissPeer(p.id)} />
        </div>
      </div>
    {/each}
    {#if view.banner}<p class="banner {view.banner.severity}">{view.banner.text}</p>{/if}
    {#if !view.available}<p class="banner warning">{t('syncPage.needsUnlock')}</p>{/if}
    {#each view.cards as c (c.key)}
      <section class="group card" aria-label={c.title}>
        <h3>{c.title}</h3>
        <p class="muted">{c.state_text}</p>
        {#if c.last_sync_text}<p class="muted small">{c.last_sync_text}</p>{/if}
        {#if c.banner}<p class="banner {c.banner.severity}">{c.banner.text}</p>{/if}
        {#if c.members.length}
          <div class="label">{c.members_heading}</div>
          {#each c.members as m (m.id)}<div class="member">{m.name}{m.detail ? `  ·  ${m.detail}` : ''}</div>{/each}
        {/if}
        {#if c.key !== 'folder' && [c.banner, ...c.issues].some((i) => i?.kind === 'unreachable')}
          <div class="refind" role="status"><strong>{t('syncPage.cantFindPc')}</strong>
            <Button label={t('syncPage.findAgain')} disabled={view.busy || working} onclick={() => act('find-again', c.key)} /></div>
        {/if}
        {#each c.issues as i, n (n)}<p class="issue {i.severity}">• {i.text}<ErrorLogLink text={i.text} /></p>{/each}
        {#if c.hint}<p class="muted small">{c.hint}</p>{/if}
        <div class="actions">
          {#each c.actions as a (a.id)}
            <Button label={a.label} variant={a.primary ? 'primary' : undefined} disabled={view.busy || working} onclick={() => act(a.id, c.key)} />
          {/each}
        </div>
      </section>
    {/each}
    {#each view.skipped as line (line)}<p class="muted small">{line}</p>{/each}
  {/if}
</div>

{#if form}
  <div class="scrim" role="dialog" aria-modal="true" aria-label={form.title}>
    <form class="sheet-form glass" onsubmit={submit}>
      <h2>{form.title}</h2>
      {#if form.intro}<p class="muted pre">{form.intro}</p>{/if}
      {#if form.folder}
        <div class="row">
          <span class="path">{folder?.path ?? t('syncPage.noFolder')}</span>
          <Button label={t('syncPage.browse')} onclick={chooseFolder} />
        </div>
      {/if}
      {#if needsPick}
        <div class="group picks">
          {#each form.devices as d (d.id)}
            <label><input type={form.kind === 'orphans' ? 'checkbox' : 'radio'} name="device" checked={picked.includes(d.id)}
              onchange={() => (form.kind === 'orphans' ? toggle(d.id) : (picked = [d.id]))} /> {d.name}{d.detail ? ` · ${d.detail}` : ''}</label>
          {/each}
        </div>
      {/if}
      {#if form.kind === 'qrtext' || form.kind === 'refind'}
        <textarea aria-label={t('syncPage.codeText')} bind:value={text} spellcheck="false"></textarea>
      {:else if form.kind === 'wifi'}
        <div class="group"><Field label={t('syncPage.addressAndPort')} bind:value={text} /></div>
        {#if form.choices?.length > 1}
          <div class="choices" aria-label={t('syncPage.thisPcAddresses')}>
            {#each form.choices as c (c.value)}<button type="button" class="chip" class:on={text === c.value} onclick={() => (text = c.value)}>{c.label}</button>{/each}
          </div>
        {/if}
      {:else if form.kind === 'pick'}
        <!-- the address list above is the whole form -->
      {:else if form.kind !== 'remove' || form.twice}
        <div class="group">
          <Field label={t('syncPage.syncPassword')} type="password" bind:value={pw} autocomplete="new-password" oninput={check} />
          {#if form.twice}<Field label={t('syncPage.enterAgain')} type="password" bind:value={pw2} autocomplete="new-password" oninput={check} />{/if}
        </div>
        {#if form.twice}
          <p class="muted small">{strength ? `${strength.label} · ${strength.message}` : t('syncPage.passwordRule')}</p>
          <p class="muted small">{view?.advice}</p>
        {/if}
      {/if}
      {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
      <footer>
        <Button label={t('common.cancel')} onclick={closeForm} />
        <Button type="submit" variant="primary" label={t('common.continue')} busy={working} busyLabel={t('syncPage.working')} disabled={!canSubmit} />
      </footer>
    </form>
  </div>
{/if}

{#if qr}
  <div class="scrim" role="dialog" aria-modal="true" aria-label={t('syncPage.pairTitle')}>
    <div class="sheet-form glass qr">
      <h2>{t('syncPage.scanInstruction')}</h2>
      <div class="qr-row">
        <!-- Whole CSS pixels per module (Python picks the PNG scale), capped at min(260px, 60vw); the quiet zone is in the image. -->
        <img class="qr-image" src={qr.image} alt={t('syncPage.qrAlt')} width={qrPx} height={qrPx}
          style:width="{qrPx}px" style:height="{qrPx}px" />
        <div class="where" aria-label={t('syncPage.whereToConnect')}>
          {#if qr.address}
            <span class="muted small">{t('syncPage.thisPc')}</span>
            <span class="address" aria-label={t('syncPage.thisPcAddress')}>{qr.address}</span>
          {/if}
          <p class="code">{t('syncPage.code', { code: qr.code })}</p>
          {#if qr.hint}<p class="muted small">{qr.hint}</p>{/if}
        </div>
      </div>
      {#if firewall}
        <div class="firewall">
          {#if firewall.profile}<p class="muted small">{t('syncPage.networkProfile', { profile: firewall.profile })}</p>{/if}
          {#if firewall.advice}<p class="banner warning small">{firewall.advice}</p>{/if}
          {#if firewall.allowed}
            <p class="muted small">{t('syncPage.firewallAllows')}</p>
          {:else if firewall.can_allow}
            <Button label={t('syncPage.allowFirewall')} busy={firewallBusy} busyLabel={t('syncPage.waitingWindows')} onclick={allowFirewall} />
          {/if}
        </div>
      {/if}
      <p class="muted small">{t('syncPage.joinByQrHint')}</p>
      <p class="muted" role="status">{qr.countdown}</p>
      <footer>
        <Button label={t('syncPage.copyCode')} onclick={copyQr} />
        <Button label={t('common.close')} onclick={closeQr} />
      </footer>
    </div>
  </div>
{/if}

{#if qr && confirm}
  <div class="scrim" role="alertdialog" aria-modal="true" aria-label={t('syncPage.acceptTitle')}>
    <div class="sheet-form glass">
      <h2>{t('syncPage.addDevice', { name: confirm.name })}</h2>
      <p class="muted">{confirm.message}</p>
      <p class="code verify" aria-label={t('syncPage.verificationCode')}>{confirm.code}</p>
      <p class="muted small">{t('syncPage.acceptHint')}</p>
      {#if confirm.fingerprint}<p class="muted small">{t('syncPage.fingerprint', { fingerprint: confirm.fingerprint })}</p>{/if}
      {#if !confirm.adding && confirm.seconds != null}<p class="muted small" role="status">{t('syncPage.declinesIn', { seconds: formatNumber(confirm.seconds) })}</p>{/if}
      <footer>
        <Button label={t('syncPage.decline')} disabled={confirm.adding} onclick={() => decide(false)} />
        <Button label={t('syncPage.accept')} variant="primary" busy={confirm.adding} busyLabel={t('syncPage.adding')} onclick={() => decide(true)} />
      </footer>
    </div>
  </div>
{/if}

{#if paired}
  <div class="scrim" role="dialog" aria-modal="true" aria-label={t('syncPage.pairedTitle')}>
    <div class="sheet-form glass">
      <h2>{t('syncPage.paired', { name: paired.name })}</h2>
      <p class="muted">{paired.message}</p>
      {#if paired.fingerprint}<p class="muted small">{t('syncPage.fingerprint', { fingerprint: paired.fingerprint })}</p>{/if}
      <footer>
        <Button label={t('syncPage.undo')} onclick={undoPairing} />
        <Button label={t('syncPage.keep')} variant="primary" onclick={() => (paired = null)} />
      </footer>
    </div>
  </div>
{/if}

{#if qrProblem}
  <div class="scrim" role="dialog" aria-modal="true" aria-label={t('syncPage.notListening')}>
    <div class="sheet-form glass">
      <h2>{t('syncPage.noPairingCode')}</h2>
      <p class="error" role="alert">{qrProblem}<ErrorLogLink text={qrProblem} /></p>
      <footer><Button label={t('common.close')} onclick={() => (qrProblem = '')} /></footer>
    </div>
  </div>
{/if}

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0 0 4px; font: 600 16px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 2px 0; }
  .small { font-size: 12px; }
  .pre { white-space: pre-line; }
  .status { font-size: 12.5px; }
  .banner { padding: 8px 12px; border-radius: 10px; margin: 8px 0; background: var(--group); }
  .banner.error { color: var(--danger); font-weight: 600; }
  .banner.warning { color: var(--warning); }
  .card { padding: 14px; margin: 10px 0; }
  .label { font-weight: 600; margin-top: 8px; font-size: 13px; }
  .member { padding: 2px 10px; font-size: 13px; }
  .refind { display: flex; align-items: center; gap: 10px; margin: 6px 10px; }
  .issue { margin: 2px 10px; font-size: 12px; color: var(--warning); }
  .issue.notice { color: var(--text-muted); }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .scrim { position: fixed; inset: 0; z-index: 50; background: var(--scrim); display: grid; place-items: center; }
  .sheet-form { width: min(520px, calc(100% - 32px)); border-radius: 18px; padding: 18px; display: grid; gap: 10px;
    background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  .row { display: flex; gap: 8px; align-items: center; }
  .path { flex: 1; font-size: 12.5px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .picks { padding: 8px 12px; display: grid; gap: 6px; }
  textarea { min-height: 90px; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 10px; padding: 8px;
    font: 12px ui-monospace, monospace; user-select: text; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
  .qr { justify-items: center; text-align: center; }
  .qr h2 { font-size: 15px; }
  /* Never blurred: nearest-neighbour scaling only; white behind the image's own quiet zone. */
  .qr-image { flex: 0 0 auto; max-width: none; aspect-ratio: 1; background: #fff; border-radius: 6px; image-rendering: crisp-edges; image-rendering: pixelated; }
  .code { font: 600 18px var(--font-display); margin: 0; }
  .code.verify { font-size: 30px; letter-spacing: 0.08em; text-align: center; font-variant-numeric: tabular-nums; }
  /* Wide: QR beside the address and hint. Narrow: stacked and centred. */
  .qr-row { display: flex; flex-wrap: wrap; gap: 18px; align-items: center; justify-content: center; width: 100%; }
  .where { flex: 1 1 200px; min-width: 0; display: grid; gap: 4px; text-align: left; }
  @media (max-width: 560px) {
    .qr-row { flex-direction: column; }
    .where { flex-basis: auto; text-align: center; justify-items: center; }
  }
  .address { font: 700 26px ui-monospace, monospace; user-select: text; overflow-wrap: anywhere; }
  .firewall { display: grid; gap: 6px; justify-items: center; }
  .choices { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 999px; padding: 4px 10px; font-size: 12px; cursor: pointer; }
  .chip.on { border-color: var(--accent, var(--text)); font-weight: 600; }
</style>
