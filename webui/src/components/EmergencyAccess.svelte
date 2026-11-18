<script>
  /** Emergency access (sub-plan 08). mode "owner": the plan editor (with the collusion warning), the shard
   *  sheets / files right after a plan is made, and access requests with Deny / Grant now. mode "heir":
   *  "I was given access": add shards (file, dropped file or pasted QR text), pick the shared folder, ask for
   *  access, then restore the owner's backup as a new profile. Phrases and passwords are cleared after each call. */
  import { call } from '../lib/api.js';
  import { formatDate, formatNumber, t } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import HeirSheet from './HeirSheet.svelte';

  let { mode = 'owner', onclose } = $props();

  let view = $state(null);
  let message = $state('');
  let error = $state('');
  let busy = $state(false);

  // ------------------------------------------------------------------ owner
  let editing = $state(false);
  let form = $state({ k: 2, holders: ['', '', ''], wait: 7, owner: '', folder: '', phrase: '' });
  let issued = $state(null); // { handle }
  let sheet = $state(null);
  let granting = $state(null); // request id
  let grantPhrase = $state('');

  // ------------------------------------------------------------------- heir
  let pasted = $state('');
  let restoreForm = $state({ name: '', password: '', confirm: '' });

  const day = (iso) => (iso ? formatDate(new Date(`${iso}T12:00:00`), { dateStyle: 'medium' }) : '');

  async function load() {
    const result = await call(mode === 'owner' ? 'heir_plan_list' : 'heir_receive_view');
    if (result.ok) {
      view = result;
      if (mode === 'owner' && !result.plan && !issued) editing = true;
    } else error = result.error.message;
  }
  $effect(() => { load(); });

  function show(result, after) {
    if (result.ok) { message = result.message ?? ''; error = ''; after?.(result); }
    else if (result.error.code !== 'cancelled') error = result.error.message;
    return result.ok;
  }

  async function run(fn) {
    if (busy) return null;
    busy = true;
    try { return await fn(); } finally { busy = false; }
  }

  async function chooseFolder() {
    const result = await call('heir_plan_choose_folder');
    if (result.ok) form.folder = result.folder;
    else if (result.error.code !== 'cancelled') error = result.error.message;
  }
  function addHolder() { if (form.holders.length < 5) form.holders = [...form.holders, '']; }
  function removeHolder(i) {
    if (form.holders.length > 2) form.holders = form.holders.filter((_, j) => j !== i);
    if (form.k > form.holders.length) form.k = form.holders.length;
  }

  async function create(event) {
    event.preventDefault();
    if (busy) return;
    const pending = call('heir_plan_create', Number(form.k), form.holders.map((h) => h.trim()),
      Number(form.wait), form.folder, form.owner.trim(), form.phrase);
    form.phrase = '';
    const result = await run(() => pending);
    if (result && show(result)) {
      issued = { handle: result.handle };
      editing = false;
      load();
    }
  }

  async function printSheets() {
    const result = await call('heir_plan_sheet', issued.handle);
    if (result.ok) sheet = result;
    else error = result.error.message;
  }
  async function saveFiles() { show(await call('heir_plan_save', issued.handle)); }
  async function finishIssue() {
    await call('heir_plan_done', issued.handle);
    issued = null; sheet = null; message = '';
  }

  async function denyRequest(id) {
    const result = await run(() => call('heir_plan_deny', id));
    if (result && show(result)) load();
  }
  async function grantRequest(event) {
    event.preventDefault();
    if (busy) return;
    const pending = call('heir_plan_grant', granting, grantPhrase);
    grantPhrase = '';
    const result = await run(() => pending);
    if (result && show(result)) { granting = null; load(); }
  }
  async function backupNow() { show(await call('heir_backup_now')); }
  async function setFolder() {
    const result = await call('heir_plan_set_folder');
    if (show(result)) load();
  }

  // ------------------------------------------------------------------- heir
  async function addFile() {
    const result = await call('heir_shard_add_file');
    if (show(result)) load();
  }
  async function addText(text) {
    const value = String(text ?? '').trim();
    if (!value) return;
    if (show(await call('heir_shard_add_text', value))) { pasted = ''; load(); }
  }
  async function dropped(event) {
    event.preventDefault();
    for (const file of event.dataTransfer?.files ?? []) {
      if (file.size > 8192) { error = t('heir.err.malformed'); continue; }
      await addText(await file.text());
    }
  }
  async function clearShards() { await call('heir_shards_clear'); message = ''; load(); }
  async function chooseShared() {
    const result = await call('heir_receive_folder');
    if (result.ok) load();
    else if (result.error.code !== 'cancelled') error = result.error.message;
  }
  async function requestAccess() {
    const result = await run(() => call('heir_request_create'));
    if (result && show(result)) load();
  }
  async function restore(event) {
    event.preventDefault();
    if (busy) return;
    // Sent, then cleared: no copy of the new master password stays in the page while Python works.
    const pending = call('heir_restore', restoreForm.name.trim(), restoreForm.password, restoreForm.confirm);
    restoreForm = { name: restoreForm.name, password: '', confirm: '' };
    const result = await run(() => pending);
    if (result && show(result)) load();
  }

  const STATE_TEXT = {
    none: () => t('heirUi.stateNone'),
    denied: () => t('heirUi.stateDenied'),
    'need-more': (s) => t('heir.err.needMore', { count: s.missing }),
    waiting: (s) => t('heir.err.waiting', { count: s.days_left }),
    'no-backup': () => t('heir.err.noBackup'),
    ready: () => t('heirUi.stateReady'),
  };
  const stateText = $derived(view?.status ? (view.status.message ?? STATE_TEXT[view.status.state]?.(view.status) ?? '') : '');
</script>

<section class="heir" aria-label={t('heirUi.title')}>
  <header>
    <h3>{mode === 'owner' ? t('heirUi.title') : t('heirUi.receive')}</h3>
    <Button label={t('heirUi.back')} onclick={onclose} />
  </header>
  {#if message}<p class="summary" role="status">{message}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if view && mode === 'owner'}
    {#if issued}
      <div class="group pad" data-testid="heir-issued">
        <strong>{t('heirUi.issued')}</strong>
        <p class="note">{t('heir.planMade')}</p>
        <div class="buttons">
          <Button label={t('heirUi.print')} onclick={printSheets} />
          <Button label={t('heirUi.saveFiles')} onclick={saveFiles} />
          <Button variant="primary" label={t('heirUi.done')} onclick={finishIssue} />
        </div>
      </div>
    {:else if editing}
      <form class="group pad form" onsubmit={create} aria-label={t('heirUi.newPlan')}>
        {#if view.plan}<p class="note">{t('heirUi.replaceNote')}</p>{/if}
        {#if !view.pro}<p class="note warn">{t('heirUi.proOnly')}</p>{/if}
        {#if !view.has_phrase}<p class="note warn">{t('heirUi.needPhrase')}</p>{/if}
        <strong>{t('heirUi.holders')}</strong>
        {#each form.holders as _, i (i)}
          <div class="holder">
            <Field label={t('heir.holder') + ' ' + formatNumber(i + 1)} bind:value={form.holders[i]} />
            {#if form.holders.length > 2}<Button variant="link" label={t('heirUi.removeHolder')} onclick={() => removeHolder(i)} />{/if}
          </div>
        {/each}
        {#if form.holders.length < 5}<div><Button variant="link" label={t('heirUi.addHolder')} onclick={addHolder} /></div>{/if}
        <label class="num">{t('heirUi.needed')}
          <input type="number" min="2" max={form.holders.length} bind:value={form.k} /></label>
        <label class="num">{t('heirUi.waitDays')}
          <input type="number" min="1" max="30" bind:value={form.wait} /></label>
        <Field label={t('heirUi.ownerName')} bind:value={form.owner} />
        <div class="row-inline">
          <span>{t('heirUi.folder')}: {form.folder || t('heirUi.noFolder')}</span>
          <Button label={t('heirUi.chooseFolder')} onclick={chooseFolder} />
        </div>
        <Field label={t('heirUi.phrase')} type="password" bind:value={form.phrase} />
        <p class="note">{t('heirUi.phraseNote')}</p>
        <p class="warning" data-testid="heir-collusion">{view.collusion}</p>
        <footer>
          {#if view.plan}<Button label={t('common.cancel')} onclick={() => { editing = false; form.phrase = ''; }} />{/if}
          <Button type="submit" variant="primary" label={t('heirUi.create')} busy={busy} busyLabel={t('heirUi.working')} />
        </footer>
      </form>
    {:else if view.plan}
      <div class="group pad">
        <p>{t('heirUi.planLine', { k: formatNumber(view.plan.k), n: formatNumber(view.plan.n),
          days: formatNumber(view.plan.wait_days), date: day(view.plan.created) })}</p>
        <p class="note">{view.plan.holders.join(', ')}</p>
        <div class="row-inline">
          <span class="note">{t('heirUi.folder')}: {view.plan.folder || t('heirUi.noFolder')}</span>
          <Button variant="link" label={t('heirUi.chooseFolder')} onclick={setFolder} />
        </div>
        {#if !view.plan.home}<p class="note" data-testid="heir-not-home">{t('heirUi.notHome')}</p>{/if}
        {#if view.plan.stale}<p class="note warn" role="alert">{t('heirUi.stale')}</p>{/if}
        {#if view.plan.folder && view.folder_reachable === false}<p class="error" role="alert" data-testid="heir-folder-unreachable">{t('heirUi.folderUnreachable')}</p>{/if}
        <p class="warning">{view.collusion}</p>
        {#if view.backup_error}<p class="error">{view.backup_error}</p>{/if}
        <div class="buttons">
          <Button label={t('heirUi.newPlan')} onclick={() => { editing = true; }} />
          {#if view.plan.folder && !view.plan.stale && view.plan.home}<Button label={t('heirUi.backupNow')} onclick={backupNow} />{/if}
        </div>
        {#if view.plan.home}<p class="note">{t('heirUi.backupMeta')}</p>{/if}
      </div>
      <div class="section-label">{t('heirUi.requests')}</div>
      <div class="group">
        {#each view.requests as request (request.id)}
          <div class="row" data-testid="heir-request">
            <div class="text">{t('heirUi.requestLine', { holder: request.holder, date: day(request.created),
              days: formatNumber(request.days_left) })}
              {#if request.granted}<div class="meta">{t('heirUi.grantedLine')}</div>{/if}</div>
            <Button variant="danger" label={t('heirUi.deny')} onclick={() => denyRequest(request.id)} />
            {#if !request.granted}<Button label={t('heirUi.grant')} onclick={() => { granting = request.id; grantPhrase = ''; }} />{/if}
          </div>
          {#if granting === request.id}
            <form class="pad form" onsubmit={grantRequest} aria-label={t('heirUi.grant')}>
              <Field label={t('heirUi.grantPhrase')} type="password" bind:value={grantPhrase} autofocus />
              <footer>
                <Button label={t('common.cancel')} onclick={() => { granting = null; grantPhrase = ''; }} />
                <Button type="submit" variant="primary" label={t('heirUi.grant')} busy={busy} busyLabel={t('heirUi.working')} />
              </footer>
            </form>
          {/if}
        {:else}
          <div class="row"><div class="text meta">{t('heirUi.noRequests')}</div></div>
        {/each}
      </div>
    {/if}
  {:else if view && mode === 'heir'}
    <div class="group pad">
      <strong>{t('heirUi.shards')}</strong>
      {#if view.plan}<p class="note">{t('heirUi.planOf', { owner: view.plan.owner || '–', k: formatNumber(view.plan.k) })}</p>{/if}
      {#each view.shards as shard (shard.index)}
        <div data-testid="heir-shard">{t('heirUi.shardLine', { index: formatNumber(shard.index), holder: shard.holder })}</div>
      {:else}
        <p class="note">{t('heirUi.noShards')}</p>
      {/each}
      <div class="buttons">
        <Button label={t('heirUi.addFile')} onclick={addFile} />
        {#if view.shards.length}<Button variant="link" label={t('heirUi.clear')} onclick={clearShards} />{/if}
      </div>
      <div class="drop" role="region" aria-label={t('heirUi.paste')} ondragover={(e) => e.preventDefault()} ondrop={dropped}>
        <label for="heir-paste">{t('heirUi.paste')}</label>
        <textarea id="heir-paste" rows="2" bind:value={pasted}></textarea>
        <Button label={t('heirUi.addText')} onclick={() => addText(pasted)} />
      </div>
      <div class="row-inline">
        <span>{t('heirUi.folder')}: {view.folder || t('heirUi.noFolder')}</span>
        <Button label={t('heirUi.chooseFolder')} onclick={chooseShared} />
      </div>
      {#if stateText}<p class="state" role="status" data-testid="heir-state">{stateText}</p>{/if}
      <div class="buttons">
        <Button label={t('heirUi.request')} disabled={!view.shards.length || !view.folder} busy={busy}
                busyLabel={t('heirUi.working')} onclick={requestAccess} />
        {#if view.status}<Button variant="link" label={t('heirUi.refresh')} onclick={load} />{/if}
      </div>
    </div>
    {#if view.status?.state === 'ready'}
      <form class="group pad form" onsubmit={restore} aria-label={t('heirUi.restoreTitle')}>
        <strong>{t('heirUi.restoreTitle')}</strong>
        <Field label={t('heirUi.profileName')} bind:value={restoreForm.name} />
        <Field label={t('heirUi.newPassword')} type="password" bind:value={restoreForm.password} />
        <Field label={t('heirUi.confirmPassword')} type="password" bind:value={restoreForm.confirm} />
        <footer>
          <Button type="submit" variant="primary" label={t('heirUi.restore')} busy={busy} busyLabel={t('heirUi.working')} />
        </footer>
      </form>
    {/if}
  {/if}
</section>
{#if sheet}<HeirSheet {sheet} ondone={() => { sheet = null; }} />{/if}

<style>
  .heir { display: grid; gap: 8px; }
  header { display: flex; align-items: center; gap: 8px; }
  h3 { margin: 0; flex: 1; font: 600 15px var(--font-display); }
  .pad { padding: 12px 14px; display: grid; gap: 8px; }
  .form footer, .buttons { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
  .buttons { justify-content: flex-start; }
  .note, .meta { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .warn { color: var(--warning); }
  .warning { margin: 0; padding: 8px 12px; border-radius: 10px; font-size: 12.5px; font-weight: 600;
    background: color-mix(in srgb, var(--warning) 14%, transparent); }
  .summary { margin: 0; padding: 8px 12px; border-radius: 10px; background: color-mix(in srgb, var(--accent) 14%, transparent); }
  .error { color: var(--danger); margin: 0; }
  .state { margin: 0; font-weight: 600; }
  .holder, .row-inline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .holder :global(.field) { flex: 1; }
  .num { display: flex; align-items: center; gap: 10px; font-size: 13px; }
  .num input { width: 64px; }
  .row { display: flex; align-items: center; gap: 10px; padding: 9px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; }
  .drop { display: grid; gap: 6px; padding: 8px; border: 1px dashed var(--separator); border-radius: 10px; }
  .drop label { font-size: 12.5px; color: var(--text-muted); }
  textarea { font: 12px ui-monospace, Consolas, monospace; resize: vertical; }
</style>
