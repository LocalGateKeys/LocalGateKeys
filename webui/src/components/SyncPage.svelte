<script>
  /** Device sync: Wi-Fi and cloud-folder cards. Every action is one Python call; forms clear their passwords after it. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call, on } from '../lib/api.js';
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
    else okOrToast(result, 'Could not open Sync');
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
      form = { kind: 'create', title: 'Create sync group', folder: true, twice: true,
        intro: 'Choose the folder your cloud app syncs (for example OneDrive), then a sync password. Your other devices join with this password.' };
    } else if (action === 'join-folder') {
      form = { kind: 'join', title: 'Join a folder', folder: true, twice: false,
        intro: 'Choose the sync folder your other device created (the folder that contains “LocalGateKeys Sync”), then enter its sync password.' };
    } else if (action === 'add-folder' || action === 'use-folder') {
      const setup = await call('sync_setup_text', action);
      if (okOrToast(setup)) form = { kind: 'setup', action, title: setup.title, intro: setup.intro, folder: true, twice: setup.confirm_twice };
    } else if (action === 'change-password') {
      const r = await call('sync_rotation_text');
      if (okOrToast(r)) form = { kind: 'rotate', title: r.title, intro: r.intro, folder: false, twice: true };
    } else if (action === 'remove-device') {
      const info = await call('sync_remove_info', card);
      if (okOrToast(info)) form = { kind: 'remove', card, title: 'Remove a device', devices: info.devices,
        twice: info.needs_password, folder: false, intro: info.needs_password ? 'Removing a device needs a NEW sync password.' : '' };
    } else if (action === 'show-orphans') {
      const r = await call('sync_orphans');
      if (!okOrToast(r)) return;
      if (!r.devices.length) { toast(r.message); return; }
      form = { kind: 'orphans', title: 'Remove devices', devices: r.devices, twice: true, folder: false, intro: r.intro };
    } else if (action === 'ack-members') {
      done(await call('sync_acknowledge_members'));
    } else if (action === 'leave') {
      done(await call('sync_leave'));
    } else if (action === 'reset') {
      done(await call('sync_reset'));
    } else if (action === 'show-qr') {
      await showQr();
    } else if (action === 'join-qr') {
      form = { kind: 'qrtext', title: 'Join by QR text', intro: 'Paste the code text shown on the other device.' };
    } else if (action === 'wifi-enable') {
      const r = await call('sync_wifi_suggest');
      if (okOrToast(r)) { text = r.value; form = { kind: 'wifi', title: 'Wi-Fi sync', intro: r.intro, choices: r.choices ?? [] }; }
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
    else if (f.kind === 'wifi') result = await call('sync_wifi_enable', text);
    else if (f.kind === 'pick') result = await call('sync_wifi_enable', picked[0] ?? '');
    if (done(result) && f.folder) folder = null;
    if (f.kind === 'pick' && result?.ok) await showQr(); // the chosen address is saved: show the code now
  }

  async function showQr() {
    qrProblem = '';
    const r = await call('sync_qr_show');
    if (!r.ok && r.error?.code === 'listen_failed') { qrProblem = r.error.message; return; }
    if (!okOrToast(r, 'No pairing code')) return;
    if (r.choose_address) {
      const keep = r.addresses.find((a) => a.value === r.current);
      picked = keep ? [keep.value] : r.addresses.length ? [r.addresses[0].value] : [];
      form = { kind: 'pick', title: 'Choose this PC’s address', intro: r.message, devices: r.addresses.map((a) => ({ id: a.value, name: a.label, detail: '' })) };
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
    if (r.ok) { firewall = r; toast(r.message); } else if (r.error.code !== 'cancelled') okOrToast(r, 'Windows Firewall was not changed');
  }

  function startQr() {
    stopQr();
    qrTimer = setInterval(async () => {
      if (!qr) return;
      const r = await call('sync_qr_poll', qr.offer_id);
      if (!r.ok || r.state === 'closed' || r.state === 'expired') { stopQr(); qr = null; return; }
      if (r.state === 'paired') {
        stopQr(); qr = null; firewall = null;
        paired = r.device ? { ...r.device, message: r.message } : null;
        if (!paired) toast(r.message);
        load('sync_refresh');
        return;
      }
      qr = { ...qr, countdown: r.countdown };
    }, 1000);
  }
  function stopQr() { clearInterval(qrTimer); qrTimer = null; }
  async function closeQr() {
    const id = qr?.offer_id;
    stopQr(); qr = null; firewall = null;
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

  function toggle(id) { picked = picked.includes(id) ? picked.filter((x) => x !== id) : [...picked, id]; }
  const needsPick = $derived(form && (form.kind === 'remove' || form.kind === 'orphans' || form.kind === 'pick'));
  const canSubmit = $derived(form && (!form.folder || folder) && (!needsPick || picked.length)
    && (['qrtext', 'wifi'].includes(form.kind) ? text.trim() : (form.kind === 'remove' && !form.twice) || form.kind === 'pick' || pw));
</script>

<svelte:window bind:innerWidth={viewportWidth} />

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Sync">
  <header>
    <h2>Sync</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if view && view.pro === false}
    <section class="group card" aria-label="LocalGateKeys Pro">
      <h3>LocalGateKeys Pro</h3>
      <p class="muted">{view.pro_text}</p>
      <div class="actions">
        <Button label="Enter licence" variant="primary" onclick={() => onlicence?.()} />
      </div>
    </section>
  {:else if view}
    <p class="muted">{view.intro}</p>
    {#if view.status_line}<p class="status" role="status">{view.status_line}<ErrorLogLink text={view.status_line} /></p>{/if}
    {#if view.banner}<p class="banner {view.banner.severity}">{view.banner.text}</p>{/if}
    {#if !view.available}<p class="banner warning">Sync runs while the vault is unlocked on this PC. Unlock and try again.</p>{/if}
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
          <span class="path">{folder?.path ?? 'No folder chosen'}</span>
          <Button label="Browse…" onclick={chooseFolder} />
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
      {#if form.kind === 'qrtext'}
        <textarea aria-label="Code text" bind:value={text} spellcheck="false"></textarea>
      {:else if form.kind === 'wifi'}
        <div class="group"><Field label="Address and port" bind:value={text} /></div>
        {#if form.choices?.length > 1}
          <div class="choices" aria-label="This PC's addresses">
            {#each form.choices as c (c.value)}<button type="button" class="chip" class:on={text === c.value} onclick={() => (text = c.value)}>{c.label}</button>{/each}
          </div>
        {/if}
      {:else if form.kind === 'pick'}
        <!-- the address list above is the whole form -->
      {:else if form.kind !== 'remove' || form.twice}
        <div class="group">
          <Field label="Sync password" type="password" bind:value={pw} autocomplete="new-password" oninput={check} />
          {#if form.twice}<Field label="Enter it again" type="password" bind:value={pw2} autocomplete="new-password" oninput={check} />{/if}
        </div>
        {#if form.twice}
          <p class="muted small">{strength ? `${strength.label} · ${strength.message}` : 'At least 12 characters, rated Strong or better.'}</p>
          <p class="muted small">{view?.advice}</p>
        {/if}
      {/if}
      {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
      <footer>
        <Button label="Cancel" onclick={closeForm} />
        <Button type="submit" variant="primary" label="Continue" busy={working} busyLabel="Working…" disabled={!canSubmit} />
      </footer>
    </form>
  </div>
{/if}

{#if qr}
  <div class="scrim" role="dialog" aria-modal="true" aria-label="Pair a device">
    <div class="sheet-form glass qr">
      <h2>Scan this code with LocalGateKeys on the other device</h2>
      <div class="qr-row">
        <!-- Whole CSS pixels per module (Python picks the PNG scale), capped at min(260px, 60vw); the quiet zone is in the image. -->
        <img class="qr-image" src={qr.image} alt="Pairing QR code" width={qrPx} height={qrPx}
          style:width="{qrPx}px" style:height="{qrPx}px" />
        <div class="where" aria-label="Where to connect">
          {#if qr.address}
            <span class="muted small">This PC</span>
            <span class="address" aria-label="This PC's address">{qr.address}</span>
          {/if}
          <p class="code">Code: {qr.code}</p>
          {#if qr.hint}<p class="muted small">{qr.hint}</p>{/if}
        </div>
      </div>
      {#if firewall}
        <div class="firewall">
          {#if firewall.profile}<p class="muted small">Network profile: {firewall.profile}</p>{/if}
          {#if firewall.advice}<p class="banner warning small">{firewall.advice}</p>{/if}
          {#if firewall.allowed}
            <p class="muted small">Windows Firewall allows LocalGateKeys on this network.</p>
          {:else if firewall.can_allow}
            <Button label="Allow through Windows Firewall" busy={firewallBusy} busyLabel="Waiting for Windows…" onclick={allowFirewall} />
          {/if}
        </div>
      {/if}
      <p class="muted small">On another PC, use Join by QR text and paste the code text instead.</p>
      <p class="muted" role="status">{qr.countdown}</p>
      <footer>
        <Button label="Copy code text" onclick={copyQr} />
        <Button label="Close" onclick={closeQr} />
      </footer>
    </div>
  </div>
{/if}

{#if paired}
  <div class="scrim" role="dialog" aria-modal="true" aria-label="Device paired">
    <div class="sheet-form glass">
      <h2>Paired: {paired.name}</h2>
      <p class="muted">{paired.message}</p>
      {#if paired.fingerprint}<p class="muted small">Key fingerprint: {paired.fingerprint}</p>{/if}
      <footer>
        <Button label="Undo" onclick={undoPairing} />
        <Button label="Keep" variant="primary" onclick={() => (paired = null)} />
      </footer>
    </div>
  </div>
{/if}

{#if qrProblem}
  <div class="scrim" role="dialog" aria-modal="true" aria-label="Wi-Fi sync is not listening">
    <div class="sheet-form glass">
      <h2>No pairing code</h2>
      <p class="error" role="alert">{qrProblem}<ErrorLogLink text={qrProblem} /></p>
      <footer><Button label="Close" onclick={() => (qrProblem = '')} /></footer>
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
