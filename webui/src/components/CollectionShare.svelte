<script>
  /**
   * The Share section of a collection (sub-plan 07): share it through a folder, join one, see who is in,
   * let waiting people in by name, remove someone with a new share password, leave or stop sharing.
   * Without collectionId it is the "Join a shared collection" sheet. Passwords live only in the inputs and
   * are cleared after every call; Python never sends a password, key or keyring back.
   */
  import { untrack } from 'svelte';
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { collectionId = null, collectionName = '', onclose, onchanged = () => {} } = $props();

  // The sheet keeps its own collection: joining turns the join sheet into that collection's Share section.
  let id = $state(untrack(() => collectionId));
  let view = $state(null);
  let folder = $state(null);
  let name = $state('');
  let password = $state('');
  let confirm = $state('');
  let canEdit = $state(false);
  let busy = $state(false);
  let removing = $state(null);
  let chosen = $state([]);

  const title = $derived(id ? t('collectionShare.shareTitle', { name: view?.collection?.name ?? collectionName })
    : t('collectionShare.joinTitle'));

  async function load() {
    const r = await call('collection_share_members', id);
    if (okOrToast(r, t('workspacePages.openFailed', { title: t('collectionShare.share') }))) view = r;
  }
  $effect(() => { if (id) load(); });

  function clearSecrets() { password = ''; confirm = ''; }

  async function run(method, ...args) {
    busy = true;
    try {
      const r = await call(method, ...args);
      clearSecrets();
      if (!okOrToast(r)) return null;
      view = r;
      removing = null;
      chosen = [];
      if (r.message) toast(r.message);
      onchanged();
      return r;
    } finally {
      clearSecrets();
      busy = false;
    }
  }

  async function pickFolder() {
    const r = await call('collection_share_choose_folder');
    if (r?.ok) folder = { token: r.token, path: r.path };
    else if (r?.error?.code !== 'cancelled') okOrToast(r);
  }

  async function share() {
    if (await run('collection_share_create', id, folder.token, password, confirm, canEdit, name.trim())) folder = null;
  }

  async function join() {
    const r = await run('collection_share_join', folder.token, password, name.trim());
    if (r) { folder = null; id = r.collection_id; }
  }

  function toggle(memberId, on) {
    chosen = on ? [...chosen, memberId] : chosen.filter((x) => x !== memberId);
  }
</script>

<div class="sheet glass" role="dialog" aria-label={title}>
  <header>
    <h2>{title}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>

  {#if !id}
    <p class="muted">{t('collectionShare.joinIntro')}</p>
    <form class="form" onsubmit={(e) => { e.preventDefault(); join(); }}>
      <div class="line">
        <span class="grow">{folder ? folder.path : t('collectionShare.noFolder')}</span>
        <Button label={t('collectionShare.chooseFolderButton')} onclick={pickFolder} />
      </div>
      <label>{t('collectionShare.yourName')}<input bind:value={name} placeholder={t('collectionShare.namePlaceholder')} maxlength="40" /></label>
      <label>{t('collectionShare.password')}<input type="password" autocomplete="off" bind:value={password} /></label>
      <footer><Button type="submit" variant="primary" label={t('collectionShare.joinButton')} {busy} disabled={!folder || !password} /></footer>
    </form>
  {:else if view}
    {#if view.twice}
      <p class="banner warning" role="alert">{view.twice}</p>
    {/if}
    {#if view.status}
      <p class="banner {view.status.severity}" role={view.status.severity === 'info' ? 'status' : 'alert'}>{view.status.text}</p>
      {#if view.status.action === 'rejoin'}
        <form class="form" onsubmit={(e) => { e.preventDefault(); run('collection_share_rejoin', id, password, name.trim()); }}>
          <label>{t('collectionShare.password')}<input type="password" autocomplete="off" bind:value={password} /></label>
          <footer><Button type="submit" variant="primary" label={t('collectionShare.joinAgain')} {busy} disabled={!password} /></footer>
        </form>
      {/if}
    {/if}

    {#if !view.shared && view.linked}
      <p class="muted">{view.linked.text}</p>
      <p class="muted">{view.linked.forget_hint}</p>
      <footer>
        <Button label={t('collectionShare.forgetLink')} variant="danger" {busy}
          onclick={() => run('collection_share_forget_link', id)} />
      </footer>
    {:else if !view.shared}
      <p class="muted">{view.intro}</p>
      {#if !view.pro}<p class="muted">{view.pro_text}</p>{/if}
      <form class="form" onsubmit={(e) => { e.preventDefault(); share(); }}>
        <div class="line">
          <span class="grow">{folder ? folder.path : t('collectionShare.noFolder')}</span>
          <Button label={t('collectionShare.chooseFolderButton')} onclick={pickFolder} />
        </div>
        <label>{t('collectionShare.yourName')}<input bind:value={name} placeholder={t('collectionShare.namePlaceholder')} maxlength="40" /></label>
        <label>{t('collectionShare.password')}<input type="password" autocomplete="new-password" bind:value={password} /></label>
        <label>{t('collectionShare.confirmPassword')}<input type="password" autocomplete="new-password" bind:value={confirm} /></label>
        <label class="check"><input type="checkbox" bind:checked={canEdit} />{t('collectionShare.canEdit')}</label>
        <p class="muted">{view.mode_hint}</p>
        <footer><Button type="submit" variant="primary" label={t('collectionShare.shareButton')} {busy} disabled={!folder || !password || !confirm} /></footer>
      </form>
    {:else}
      <p class="mode"><strong>{view.mode_text}</strong> <span class="muted">{view.mode_hint}</span></p>
      {#if view.folder}<p class="muted">{t('collectionShare.folderLabel', { path: view.folder })}</p>{/if}

      {#if view.upgrade && !removing}
        <form class="form panel" aria-label={view.upgrade.title}
          onsubmit={(e) => { e.preventDefault(); run('collection_share_upgrade', id, password, confirm); }}>
          <strong>{view.upgrade.title}</strong>
          <p class="muted">{view.upgrade.text}</p>
          <label>{t('collectionShare.password')}<input type="password" autocomplete="new-password" bind:value={password} /></label>
          <label>{t('collectionShare.confirmPassword')}<input type="password" autocomplete="new-password" bind:value={confirm} /></label>
          <footer><Button type="submit" variant="primary" label={t('collectionShare.upgradeButton')} {busy} disabled={!password || !confirm} /></footer>
        </form>
      {/if}

      <div class="section-label">{t('collectionShare.people')}</div>
      <div class="group rows" role="list" aria-label={t('collectionShare.people')}>
        {#each view.members as m (m.id)}
          <div class="row" role="listitem">
            <span class="grow">{m.name}{#if m.is_self}<span class="muted"> ({t('collectionShare.you')})</span>{/if}</span>
            <span class="tag {m.state}">{m.state_text}</span>
            {#if m.removable}<Button label={t('collectionShare.remove')} variant="danger" onclick={() => { removing = m; clearSecrets(); }} />{/if}
          </div>
        {/each}
      </div>

      {#if removing}
        <form class="form panel" aria-label={t('collectionShare.removeHeading', { person: removing.name })}
          onsubmit={(e) => { e.preventDefault(); run('collection_share_remove_member', id, removing.id, password, confirm); }}>
          <strong>{t('collectionShare.removeHeading', { person: removing.name })}</strong>
          <p class="muted">{t('collectionShare.removeHint', { person: removing.name })}</p>
          <label>{t('collectionShare.newPassword')}<input type="password" autocomplete="new-password" bind:value={password} /></label>
          <label>{t('collectionShare.newPasswordAgain')}<input type="password" autocomplete="new-password" bind:value={confirm} /></label>
          <footer>
            <Button label={t('common.cancel')} onclick={() => { removing = null; clearSecrets(); }} />
            <Button type="submit" variant="danger" label={t('collectionShare.removeButton', { person: removing.name })} {busy} disabled={!password || !confirm} />
          </footer>
        </form>
      {/if}

      {#if view.pending.length}
        <div class="section-label">{t('collectionShare.waiting')}</div>
        <p class="muted">{t('collectionShare.waitingHint')}</p>
        <div class="group rows">
          {#each view.pending as p (p.id)}
            <label class="row check"><input type="checkbox" checked={chosen.includes(p.id)} onchange={(e) => toggle(p.id, e.currentTarget.checked)} />{p.name}</label>
          {/each}
        </div>
        <footer><Button variant="primary" label={t('collectionShare.letIn')} {busy} disabled={!chosen.length} onclick={() => run('collection_share_approve', id, [...chosen])} /></footer>
      {/if}

      {#if view.removed.length}
        <div class="section-label">{t('collectionShare.removedHeading')}</div>
        <div class="group rows">
          {#each view.removed as r, i (i)}<div class="row"><span class="grow">{r.name}</span></div>{/each}
        </div>
      {/if}

      <footer>
        <Button label={view.is_owner ? t('collectionShare.stopSharing') : t('collectionShare.leave')} {busy}
          onclick={() => run('collection_share_leave', id)} />
      </footer>
    {/if}
    <p class="muted help">{view.help} {view.owner_loss}</p>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 33; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .form { display: flex; flex-direction: column; gap: 8px; }
  .panel { padding: 10px 12px; border-radius: 12px; background: var(--group); }
  .line { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 12.5px; }
  label.check { flex-direction: row; align-items: center; gap: 8px; }
  .grow { flex: 1; overflow-wrap: anywhere; }
  .rows { overflow: auto; }
  .row { display: flex; gap: 12px; align-items: center; padding: 9px 14px; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .tag { font-size: 11.5px; padding: 2px 8px; border-radius: 999px; background: var(--group); }
  .tag.pending { background: color-mix(in srgb, var(--accent) 22%, transparent); }
  .banner { margin: 0; padding: 8px 12px; border-radius: 10px; font-size: 13px; background: var(--group); }
  .banner.warning { background: color-mix(in srgb, var(--warning) 22%, transparent); }
  .banner.error { background: color-mix(in srgb, var(--danger) 22%, transparent); }
  .mode { margin: 0; font-size: 13px; }
  .help { margin-top: 6px; }
  input:not([type='checkbox']) { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 6px 8px; user-select: text; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
