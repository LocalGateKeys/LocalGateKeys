<script>
  /** Details of the selected item: label above value with a Copy button per field, one primary Open website,
   *  live 2FA. Share, Password history and Move to trash sit in the More menu next to Edit. */
  import { dialog } from '../lib/dialog.js';
  import { call, on } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import ItemHistorySheet from './ItemHistorySheet.svelte';
  import ItemTile from './ItemTile.svelte';
  import LoginMore from './LoginMore.svelte';
  import MarkdownView from './MarkdownView.svelte';
  import { parseMarkdown } from '../lib/markdown.js';

  // icon: the list row's own icon (site or app), so the header matches the list.
  let { selected = null, icon = null, onedit = undefined, onchanged = undefined, onshare = undefined } = $props();

  const MASK = '•'.repeat(12);
  let detail = $state(null);
  let error = $state('');
  let revealed = $state(null);
  let typedRevealed = $state({});
  // Read-only decode of a revealed API-key value that is a JWT, by field; cleared with the revealed value.
  let typedTokens = $state({});
  // The Wi-Fi QR image holds the password: it lives only while its dialog is open.
  let wifiQr = $state(null);
  let preview = $state(null);
  let code = $state(null);
  let maskTimer = null;
  let maskTick = null;
  let maskLeft = $state(0); // seconds until a revealed value hides again
  let codeTimer = null;
  let loadedFor = null;
  let moreOpen = $state(false);
  let showHistory = $state(false);
  let itemHistory = $state(false);
  let loginMore = $state();
  // This device's "Show formatting" switch for note bodies and login notes (default on).
  let formatting = $state(true);
  call('notes_formatting_get').then((r) => { if (r?.ok) formatting = r.enabled !== false; });

  // Parsed once per note, not on every render.
  const loginNodes = $derived(detail?.notes ? parseMarkdown(detail.notes) : []);
  const wifiSecurity = $derived(detail?.kind === 'wifi' ? String(detail.fields?.find((f) => f.name === 'security')?.value ?? '') : '');
  const typedNodes = $derived(detail?.kind === 'note'
    ? Object.fromEntries(Object.entries(typedRevealed).map(([name, value]) => [name, parseMarkdown(value)])) : {});

  async function setFormatting(enabled) {
    formatting = enabled;
    const r = await call('notes_formatting_set', enabled);
    if (!r.ok) { formatting = !enabled; toast(r.error.message); }
  }

  function startMask(seconds) {
    clearTimeout(maskTimer); clearInterval(maskTick);
    const end = Date.now() + seconds * 1000;
    maskLeft = Math.max(0, Math.ceil(seconds));
    maskTimer = setTimeout(hide, seconds * 1000);
    maskTick = setInterval(() => { maskLeft = Math.max(0, Math.ceil((end - Date.now()) / 1000)); }, 1000);
  }

  function stopTimers() {
    clearTimeout(maskTimer); clearInterval(maskTick); maskTick = null;
    clearTimeout(codeTimer);
    maskTimer = codeTimer = null;
  }

  function hide() {
    revealed = null;
    typedRevealed = {};
    typedTokens = {};
    clearTimeout(maskTimer); clearInterval(maskTick); maskTick = null;
  }

  async function load(ref) {
    stopTimers();
    revealed = null;
    typedRevealed = {};
    typedTokens = {};
    wifiQr = null;
    preview = null;
    code = null;
    error = '';
    if (!ref) { detail = null; return; }
    loadedFor = ref;
    moreOpen = false;
    showHistory = false;
    itemHistory = false;
    const result = await call(ref.source === 'typed' ? 'typed_detail' : 'item_detail', ref);
    if (loadedFor !== ref) return;
    if (!result.ok) { detail = null; error = result.error.message; return; }
    detail = result;
    if (result.has_totp && !result.strict) refreshCode(ref);
  }

  async function refreshCode(ref) {
    const result = await call('item_totp', ref);
    if (loadedFor !== ref) return;
    if (!result.ok) { code = { error: result.error.message }; return; }
    code = result;
    codeTimer = setTimeout(() => refreshCode(ref), Math.max(1, result.remaining) * 1000 + 50);
  }

  $effect(() => { load(selected); return stopTimers; });
  $effect(() => on('vault.state', (state) => { if (state.state !== 'unlocked') { hide(); detail = null; stopTimers(); } }));

  async function reveal() {
    if (revealed !== null) { hide(); return; }
    const ref = selected;
    const result = await call('item_reveal', ref);
    if (loadedFor !== ref || selected !== ref) return; // the user moved to another item meanwhile
    if (!okOrToast(result, t('detailPane.notRevealed'))) return;
    revealed = result.password;
    startMask(result.mask_after ?? 30);
  }

  async function copy(field) {
    const result = await call('item_copy', selected, field);
    if (okOrToast(result, t('home.notCopied'))) notice(result);
  }

  async function favorite() {
    const ref = selected;
    const result = await call('item_favorite', ref, !detail.favorite);
    if (loadedFor !== ref) { if (result.ok) onchanged?.(); return; }
    if (okOrToast(result)) { detail.favorite = !detail.favorite; toast(result.message); onchanged?.(); }
  }

  async function trash() {
    const result = await call('item_trash', selected);
    if (okOrToast(result, t('home.notTrashed'))) { notice(result); onchanged?.(); }
  }

  // Not secret (website, plain typed fields): straight to the clipboard, no clearing needed.
  async function copyPlain(text) {
    try { await navigator.clipboard.writeText(String(text ?? '')); toast(t('detailPane.copied')); }
    catch { toast(t('home.notCopied'), '', 'error'); }
  }

  async function pickMore(action) {
    moreOpen = false;
    if (action === 'share') onshare?.(selected);
    else if (action === 'trash') trash();
    else if (action === 'item-history') itemHistory = true;
    else if (action === 'history') { showHistory = true; await Promise.resolve(); loginMore?.openHistory(); }
  }

  async function autoType() {
    const result = await call('autotype_run', selected);
    if (okOrToast(result, t('autoType.title')) && result.message) toast(result.message);
  }

  async function afterRestore() {
    const ref = selected;
    const fresh = await call(ref.source === 'typed' ? 'typed_detail' : 'item_detail', ref);
    if (fresh.ok && ref === selected) detail = fresh;
    onchanged?.();
  }

  async function openWebsite() {
    okOrToast(await call('item_open_website', selected), t('home.websiteNotOpened'));
  }

  async function revealTyped(field) {
    if (typedRevealed[field] !== undefined) {
      const next = { ...typedRevealed }; delete next[field]; typedRevealed = next;
      const tokens = { ...typedTokens }; delete tokens[field]; typedTokens = tokens;
      return;
    }
    const ref = selected;
    const result = await call('typed_reveal', ref, field);
    if (loadedFor !== ref || selected !== ref) return;
    if (!okOrToast(result, t('detailPane.notRevealed'))) return;
    typedRevealed = { ...typedRevealed, [field]: result.value };
    if (result.token) typedTokens = { ...typedTokens, [field]: result.token };
    startMask(result.mask_after ?? 30);
  }

  // Writes the token's expiry date through the normal edit and save path, so reminders pick it up.
  async function setExpiryFromToken(date) {
    const opened = await call('typed_open', selected);
    if (!okOrToast(opened, t('typedEditor.couldNotOpenItem'))) return;
    const saved = await call('typed_save', selected, 'api_key', {
      title: opened.title, tags: opened.tags, favorite: opened.favorite, values: { ...opened.values, expires: date },
      protected: {}, clear: [], revision: opened.revision,
    });
    if (!okOrToast(saved, t('jwt.notSaved'))) return;
    toast(t('jwt.expirySet', { date }));
    typedTokens = Object.fromEntries(Object.entries(typedTokens).map(([name, token]) => [name, { ...token, set_expiry_date: '' }]));
    const fresh = await call('typed_detail', selected);
    if (fresh.ok) detail = fresh;
    onchanged?.();
  }

  async function showWifiQr() {
    const result = await call('typed_wifi_qr', selected);
    if (!okOrToast(result, t('detailPane.notRevealed'))) return;
    wifiQr = { image: result.png_data_url, ssid: result.ssid };
  }

  async function copyTyped(field) {
    const result = await call('typed_copy', selected, field);
    if (okOrToast(result, t('home.notCopied'))) notice(result);
  }

  async function documentAction(method) {
    const result = await call(method, selected);
    if (!okOrToast(result, t('detailPane.documentStopped'), () => documentAction(method))) return;
    if (method === 'doc_preview') preview = result;
    else if (result.message) toast(result.message);
  }

  const ring = $derived(code && !code.error ? (code.remaining / (code.period || 30)) * 56.5 : 0);
</script>

{#snippet formatSwitch()}
  <label class="fmt"><input type="checkbox" checked={formatting} onchange={(e) => setFormatting(e.currentTarget.checked)} />{t('detailPane.showFormatting')}</label>
{/snippet}

<section class="detail" aria-label={t('detailPane.details')}>
  {#if !selected}
    <p class="empty">{t('detailPane.selectItem')}</p>
  {:else if error}
    <p class="empty">{error}</p>
  {:else if detail}
    <header>
      <ItemTile kind={detail.kind} origin={detail.origin} {icon} size={38} />
      <div class="heading">
        <h2>{detail.title}</h2>
        <p class="sub">{detail.subtitle}</p>
      </div>
      <button class="star" aria-label={detail.favorite ? t('detailPane.removeFavorite') : t('detailPane.addFavorite')} onclick={favorite}>{detail.favorite ? '★' : '☆'}</button>
      {#if (detail.actions?.includes('edit') || selected.source === 'typed') && onedit}<Button label={t('detailPane.edit')} onclick={() => onedit(selected)} />{/if}
      <div class="more-wrap">
        <button class="more" aria-label={t('detailPane.more')} title={t('detailPane.more')} aria-haspopup="menu" aria-expanded={moreOpen}
          onclick={() => (moreOpen = !moreOpen)}>⋯</button>
        {#if moreOpen}
          <div class="more-menu glass" role="menu" aria-label={t('detailPane.more')}>
            {#if onshare && !['passkey', 'document'].includes(selected.kind)}<button role="menuitem" onclick={() => pickMore('share')}>{t('detailPane.share')}</button>{/if}
            <button role="menuitem" onclick={() => pickMore('item-history')}>{t('history.title')}</button>
            {#if selected.source !== 'typed'}<button role="menuitem" onclick={() => pickMore('history')}>{t('loginMore.passwordHistory')}</button>{/if}
            <button role="menuitem" class="danger" onclick={() => pickMore('trash')}>{t('detailPane.moveToTrash')}</button>
          </div>
        {/if}
      </div>
    </header>
    {#if detail.access?.expired}
      <p class="banner" role="alert">{t('access.expired', { date: detail.access.expired_on ?? '' })}</p>
    {:else if detail.access?.unknown}
      <p class="banner" role="status">{t('access.unknownRule')}</p>
    {/if}
    {#if detail.actions?.includes('autotype')}
      <div class="open"><Button label={t('autoType.run')} onclick={autoType} /></div>
    {/if}
    {#if detail.actions?.includes('open_website')}
      <div class="open"><Button label={t('detailPane.openWebsite')} variant="primary" onclick={openWebsite} /></div>
    {/if}

    {#if selected.source !== 'typed' && detail.has_totp}
      <!-- The live code sits first, under the header, like the iPhone app. -->
      <div class="section-label">{t('detailPane.oneTimeCode')}</div>
      <div class="group">
        <div class="field top-code">
          {#if detail.strict}
            <button class="v muted text-left" onclick={() => copy('totp')}>{t('detailPane.hiddenClick')}</button>
          {:else if code?.error}
            <span class="v muted">{code.error}</span>
          {:else if code}
            <svg class="ring" width="24" height="24" viewBox="0 0 20 20" aria-label={t('detailPane.refreshesIn', { seconds: formatNumber(code.remaining) })}>
              <circle cx="10" cy="10" r="9" fill="none" stroke="var(--separator)" stroke-width="2" />
              <circle cx="10" cy="10" r="9" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round"
                stroke-dasharray="56.5" stroke-dashoffset={56.5 - ring} transform="rotate(-90 10 10)" />
            </svg>
            <span class="v mono code">{code.code}</span>
            <Button label={t('detailPane.copy')} ariaLabel={t('detailPane.copyCode')} onclick={() => copy('totp')} />
          {/if}
        </div>
      </div>
    {/if}

    {#if selected.source === 'typed'}
      <div class="section-label">{t('detailPane.detailsLabel')}</div>
      <div class="group">
        {#each detail.fields as field (field.name)}
          <div class="field">
            <div class="kv">
            <span class="k">{field.label}</span>
            {#if field.protected}
              <!-- A revealed note body is text, not a code: keep its line breaks. -->
              {#if formatting && typedRevealed[field.name] !== undefined && detail.kind === 'note'}
                <div class="v md"><MarkdownView nodes={typedNodes[field.name] ?? []} /></div>
              {:else}
                <span class="v" class:mono={typedRevealed[field.name] === undefined || detail.kind !== 'note'}
                  class:notes={typedRevealed[field.name] !== undefined && detail.kind === 'note'}>{typedRevealed[field.name] ?? (field.present ? MASK : '—')}</span>
              {/if}
              {#if typedRevealed[field.name] !== undefined && detail.kind === 'note'}{@render formatSwitch()}{/if}
            {:else}
              <span class="v notes">{field.value === true ? t('detailPane.yes') : field.value === false ? t('detailPane.no') : field.value}</span>
            {/if}
            </div>
            {#if field.protected && field.present}
              <button class="text-btn" aria-label={t(typedRevealed[field.name] !== undefined ? 'detailPane.hideField' : 'detailPane.revealField', { name: field.name })} onclick={() => revealTyped(field.name)}>{typedRevealed[field.name] !== undefined ? t('detailPane.hide') : t('detailPane.show')}</button>
              {#if typedRevealed[field.name] !== undefined && maskLeft}<span class="hides-in" aria-hidden="true">{t('detailPane.hidesIn', { seconds: maskLeft })}</span>{/if}
              <Button label={t('detailPane.copy')} ariaLabel={t('detailPane.copyField', { name: field.name })} onclick={() => copyTyped(field.name)} />
            {:else if !field.protected && typeof field.value === 'string' && field.value}
              <Button label={t('detailPane.copy')} ariaLabel={t('detailPane.copyField', { name: field.label })} onclick={() => copyPlain(field.value)} />
            {/if}
          </div>
        {:else}
          <div class="field"><span class="v muted">{t('detailPane.noDetails')}</span></div>
        {/each}
      </div>
      {#each Object.entries(typedTokens) as [name, token] (name)}
        <div class="section-label">{Object.keys(typedTokens).length > 1 ? `${t('jwt.title')} · ${detail.fields.find((f) => f.name === name)?.label ?? name}` : t('jwt.title')}</div>
        <div class="group">
          <div class="field"><span class="k">{t('jwt.alg')}</span><span class="v mono">{token.alg || '—'}{token.typ ? ` · ${token.typ}` : ''}</span></div>
          {#if token.iss}<div class="field"><span class="k">{t('jwt.iss')}</span><span class="v notes">{token.iss}</span></div>{/if}
          {#if token.sub}<div class="field"><span class="k">{t('jwt.sub')}</span><span class="v notes">{token.sub}</span></div>{/if}
          {#if token.aud?.length}<div class="field"><span class="k">{t('jwt.aud')}</span><span class="v notes">{token.aud.join(', ')}</span></div>{/if}
          {#if token.iat}<div class="field"><span class="k">{t('jwt.iat')}</span><span class="v">{token.iat}</span></div>{/if}
          {#if token.nbf}<div class="field"><span class="k">{t('jwt.nbf')}</span><span class="v">{token.nbf}</span></div>{/if}
          {#if token.exp}
            <div class="field">
              <span class="k">{t('jwt.exp')}</span><span class="v">{token.exp}</span>
              {#if token.expired}<span class="tag expired">{t('jwt.expired')}</span>{/if}
            </div>
          {/if}
          <div class="field"><span class="v muted">{t('jwt.unchecked')}</span></div>
          {#if token.set_expiry_date}
            <div class="field"><Button label={t('jwt.setExpiry')} onclick={() => setExpiryFromToken(token.set_expiry_date)} /></div>
          {/if}
        </div>
      {/each}
      {#if detail.kind === 'wifi'}
        <div class="group"><div class="field">
          {#if wifiSecurity.endsWith('enterprise')}
            <span class="v muted">{t('detail.wifi.enterprise_no_qr')}</span>
          {:else}
            <Button label={t('detail.wifi.show_qr')} onclick={showWifiQr} />
          {/if}
        </div></div>
      {/if}
      {#if detail.document}
        <div class="section-label">{t('detailPane.document')}</div>
        <div class="group">
          <div class="field"><span class="v">{detail.document.error ?? t('detailPane.documentInfo', { name: detail.document.name, mime: detail.document.mime, size: t('detailPane.bytes', { count: detail.document.size ?? 0, number: formatNumber(detail.document.size ?? 0) }) })}</span></div>
          <div class="field doc-actions">
            <Button label={t('detailPane.safePreview')} onclick={() => documentAction('doc_preview')} />
            <Button label={t('detailPane.openFile')} onclick={() => documentAction('doc_open')} />
            <Button label={t('detailPane.saveCopy')} onclick={() => documentAction('doc_save_copy')} />
            <Button label={t('detailPane.replaceFile')} onclick={() => documentAction('doc_replace')} />
          </div>
          {#if preview}
            <div class="field"><span class="v notes">{preview.kind === 'text' ? preview.content : t('detailPane.metadataPreview', { reason: preview.reason })}</span></div>
          {/if}
        </div>
      {/if}
    {:else}
      <div class="section-label">{t('detailPane.signIn')}</div>
      <div class="group">
        <div class="field">
          <div class="kv"><span class="k">{t('detailPane.username')}</span><span class="v">{detail.username || '—'}</span></div>
          {#if detail.username}<Button label={t('detailPane.copy')} ariaLabel={t('detailPane.copyUsername')} onclick={() => copy('username')} />{/if}
        </div>
        <div class="field">
          <div class="kv"><span class="k">{t('detailPane.password')}</span><span class="v mono">{revealed ?? MASK}</span></div>
          <button class="text-btn" onclick={reveal}>{revealed !== null ? t('detailPane.hide') : t('detailPane.show')}</button>
          {#if revealed !== null && maskLeft}<span class="hides-in" aria-hidden="true">{t('detailPane.hidesIn', { seconds: maskLeft })}</span>{/if}
          <Button label={t('detailPane.copy')} ariaLabel={t('detailPane.copyPassword')} onclick={() => copy('password')} />
        </div>
        {#if detail.target}
          <div class="field">
            <div class="kv"><span class="k">{t('detailPane.website')}</span><span class="v link">{detail.target}</span></div>
            <Button label={t('detailPane.copy')} ariaLabel={t('detailPane.copyField', { name: t('detailPane.website') })} onclick={() => copyPlain(detail.target)} />
          </div>
        {/if}
      </div>
      {#if detail.notes !== null}
        <div class="section-label">{t('detailPane.notes')}</div>
        <div class="group"><div class="field">
          {#if detail.notes && formatting}
            <div class="v md"><MarkdownView nodes={loginNodes} /></div>
          {:else}
            <span class="v notes">{detail.notes || t('detailPane.noNotes')}</span>
          {/if}
          {#if detail.notes}{@render formatSwitch()}{/if}
        </div></div>
      {/if}
      <LoginMore bind:this={loginMore} {selected} withHistory={showHistory} />
    {/if}

    {#if detail.tags?.length}
      <div class="tags">{#each detail.tags as tag (tag)}<span class="tag">{tag}</span>{/each}</div>
    {/if}
  {/if}
</section>

{#if itemHistory && selected}
  <ItemHistorySheet {selected} onclose={() => (itemHistory = false)} onrestored={afterRestore} />
{/if}

<svelte:window onkeydown={(e) => { if (e.key === 'Escape' && wifiQr) wifiQr = null; else if (e.key === 'Escape' && moreOpen) { e.preventDefault(); moreOpen = false; } }}
  onclick={(e) => { if (moreOpen && !e.target?.closest?.('.more-wrap')) moreOpen = false; }} />
{#if wifiQr}
  <div class="qr-scrim" role="dialog" aria-modal="true" use:dialog aria-label={wifiQr.ssid}>
    <div class="qr-card glass">
      <h2>{wifiQr.ssid}</h2>
      <img src={wifiQr.image} alt={t('detail.wifi.show_qr')} />
      <p class="muted">{t('detail.wifi.qr_hint')}</p>
      <p class="muted">{t('detail.wifi.qr_no_expiry')}</p>
      <Button label={t('common.close')} variant="primary" onclick={() => { wifiQr = null; }} />
    </div>
  </div>
{/if}

<style>
  .qr-scrim { position: fixed; inset: 0; display: grid; place-items: center; background: var(--scrim); z-index: 55; }
  .qr-card { width: min(340px, calc(100vw - 48px)); border-radius: var(--radius-card); padding: 20px; display: grid; gap: 10px; justify-items: center; text-align: center; }
  .qr-card h2 { margin: 0; font: 600 17px var(--font-display); overflow-wrap: anywhere; }
  .qr-card img { width: 100%; image-rendering: pixelated; background: #fff; border-radius: 8px; }
  .qr-card p { margin: 0; font-size: 12.5px; }
  .detail { padding: 6px 18px 12px; overflow-y: auto; min-height: 0; }
  .empty { color: var(--text-muted); text-align: center; margin-top: 64px; }
  header { display: flex; align-items: center; gap: 10px; padding: 8px 0 4px; }
  .heading { flex: 1; min-width: 0; }
  h2 { margin: 0; font: 600 17px var(--font-display); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub { margin: 0; color: var(--text-muted); font-size: 12.5px; }
  .star { background: none; border: none; color: var(--warning); font-size: 18px; cursor: pointer; }
  .field { display: flex; align-items: center; gap: 8px; padding: 8px 14px; min-height: 42px; }
  .field :global(.btn) { height: 26px; padding: 0 10px; font-size: 12px; flex-shrink: 0; }
  .kv { flex: 1; min-width: 0; display: grid; gap: 2px; }
  .k { color: var(--text-muted); font-size: 11.5px; }
  .open { display: grid; padding: 4px 0 8px; }
  .more-wrap { position: relative; }
  .more { width: 32px; height: 32px; border-radius: 999px; border: 1px solid var(--glass-border); background: var(--glass);
    color: var(--text); cursor: pointer; font-size: 16px; line-height: 1; }
  .more:hover { background: var(--glass-hover); }
  .more-menu { position: absolute; right: 0; top: calc(100% + 4px); z-index: 20; min-width: 180px; padding: 6px; border-radius: 12px;
    display: grid; gap: 2px; background: color-mix(in srgb, var(--wash-base-opaque) 94%, transparent); }
  .more-menu button { background: none; border: none; color: inherit; text-align: left; padding: 8px 10px; border-radius: 8px; cursor: pointer; font: inherit; }
  .more-menu button:hover, .more-menu button:focus-visible { background: var(--group); }
  .more-menu .danger { color: var(--danger); }
  .v { flex: 1; min-width: 0; overflow-wrap: anywhere; user-select: text; }
  .mono { font-family: var(--font-mono); letter-spacing: 0.5px; }
  .code { font-size: 22px; letter-spacing: 2px; }
  .top-code { gap: 14px; min-height: 52px; }
  .muted { color: var(--text-muted); }
  .link { color: var(--link); }
  .notes { white-space: pre-wrap; }
  .fmt { display: inline-flex; align-items: center; gap: 4px; color: var(--text-muted); font-size: 12px; white-space: nowrap; cursor: pointer; }
  .text-left { text-align: left; background: none; border: none; cursor: pointer; padding: 0; }
  .text-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 4px; font-size: 14px; }
  .text-btn { color: var(--link); font-size: 13px; }
  .banner { margin: 4px 0 8px; padding: 8px 12px; border-radius: 10px; font-size: 12.5px;
    background: color-mix(in srgb, var(--warning) 16%, transparent); }
  .tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 12px; }
  .tag { padding: 2px 10px; border-radius: 10px; background: var(--glass); font-size: 12px; }
  .tag.expired { background: var(--danger); color: #fff; }
  .doc-actions { flex-wrap: wrap; gap: 6px; }
  .hides-in { font-size: 12px; color: var(--text-muted); white-space: nowrap; }
</style>
