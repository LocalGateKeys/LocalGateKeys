<script>
  /** Details of the selected item: reveal (auto-masked), copy, live 2FA, actions. */
  import { call, on } from '../lib/api.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import ItemTile from './ItemTile.svelte';
  import LoginMore from './LoginMore.svelte';

  // icon: the list row's own icon (site or app), so the header matches the list.
  let { selected = null, icon = null, onedit = undefined, onchanged = undefined } = $props();

  const MASK = '•'.repeat(12);
  let detail = $state(null);
  let error = $state('');
  let revealed = $state(null);
  let typedRevealed = $state({});
  let preview = $state(null);
  let code = $state(null);
  let maskTimer = null;
  let codeTimer = null;
  let loadedFor = null;

  function stopTimers() {
    clearTimeout(maskTimer);
    clearTimeout(codeTimer);
    maskTimer = codeTimer = null;
  }

  function hide() {
    revealed = null;
    typedRevealed = {};
    clearTimeout(maskTimer);
  }

  async function load(ref) {
    stopTimers();
    revealed = null;
    typedRevealed = {};
    preview = null;
    code = null;
    error = '';
    if (!ref) { detail = null; return; }
    loadedFor = ref;
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
    const result = await call('item_reveal', selected);
    if (!okOrToast(result, 'Not revealed')) return;
    revealed = result.password;
    maskTimer = setTimeout(hide, (result.mask_after ?? 30) * 1000);
  }

  async function copy(field) {
    const result = await call('item_copy', selected, field);
    if (okOrToast(result, 'Not copied')) notice(result);
  }

  async function favorite() {
    const result = await call('item_favorite', selected, !detail.favorite);
    if (okOrToast(result)) { detail.favorite = !detail.favorite; toast(result.message); onchanged?.(); }
  }

  async function trash() {
    const result = await call('item_trash', selected);
    if (okOrToast(result, 'Not moved to trash')) { notice(result); onchanged?.(); }
  }

  async function openWebsite() {
    okOrToast(await call('item_open_website', selected), 'Website not opened');
  }

  async function revealTyped(field) {
    if (typedRevealed[field] !== undefined) { const next = { ...typedRevealed }; delete next[field]; typedRevealed = next; return; }
    const result = await call('typed_reveal', selected, field);
    if (!okOrToast(result, 'Not revealed')) return;
    typedRevealed = { ...typedRevealed, [field]: result.value };
    clearTimeout(maskTimer);
    maskTimer = setTimeout(hide, (result.mask_after ?? 30) * 1000);
  }

  async function copyTyped(field) {
    const result = await call('typed_copy', selected, field);
    if (okOrToast(result, 'Not copied')) notice(result);
  }

  async function documentAction(method) {
    const result = await call(method, selected);
    if (!okOrToast(result, 'Document action stopped', () => documentAction(method))) return;
    if (method === 'doc_preview') preview = result;
    else if (result.message) toast(result.message);
  }

  const ring = $derived(code && !code.error ? (code.remaining / (code.period || 30)) * 56.5 : 0);
</script>

<section class="detail" aria-label="Item details">
  {#if !selected}
    <p class="empty">Select an item to see its details</p>
  {:else if error}
    <p class="empty">{error}</p>
  {:else if detail}
    <header>
      <ItemTile kind={detail.kind} origin={detail.origin} {icon} size={38} />
      <div class="heading">
        <h2>{detail.title}</h2>
        <p class="sub">{detail.subtitle}</p>
      </div>
      <button class="star" aria-label={detail.favorite ? 'Remove from favorites' : 'Add to favorites'} onclick={favorite}>{detail.favorite ? '★' : '☆'}</button>
      {#if (detail.actions?.includes('edit') || selected.source === 'typed') && onedit}<Button label="Edit" onclick={() => onedit(selected)} />{/if}
      {#if detail.actions?.includes('open_website')}<Button label="Open website" variant="primary" onclick={openWebsite} />{/if}
    </header>

    {#if selected.source !== 'typed' && detail.has_totp}
      <!-- The live code sits first, under the header, like the iPhone app. -->
      <div class="section-label">One-time code</div>
      <div class="group">
        <div class="field top-code">
          {#if detail.strict}
            <button class="v muted text-left" onclick={() => copy('totp')}>Hidden · click to show</button>
          {:else if code?.error}
            <span class="v muted">{code.error}</span>
          {:else if code}
            <svg class="ring" width="24" height="24" viewBox="0 0 20 20" aria-label={`Refreshes in ${code.remaining} s`}>
              <circle cx="10" cy="10" r="9" fill="none" stroke="var(--separator)" stroke-width="2" />
              <circle cx="10" cy="10" r="9" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round"
                stroke-dasharray="56.5" stroke-dashoffset={56.5 - ring} transform="rotate(-90 10 10)" />
            </svg>
            <span class="v mono code">{code.code}</span>
            <button class="icon accent" aria-label="Copy 2FA code" onclick={() => copy('totp')}>⧉</button>
          {/if}
        </div>
      </div>
    {/if}

    {#if selected.source === 'typed'}
      <div class="section-label">Details</div>
      <div class="group">
        {#each detail.fields as field (field.name)}
          <div class="field">
            <span class="k">{field.label}</span>
            {#if field.protected}
              <!-- A revealed note body is text, not a code: keep its line breaks. -->
              <span class="v" class:mono={typedRevealed[field.name] === undefined || detail.kind !== 'note'}
                class:notes={typedRevealed[field.name] !== undefined && detail.kind === 'note'}>{typedRevealed[field.name] ?? (field.present ? MASK : '—')}</span>
              {#if field.present}
                <button class="text-btn" aria-label={`${typedRevealed[field.name] !== undefined ? 'Hide' : 'Reveal'} ${field.name}`} onclick={() => revealTyped(field.name)}>{typedRevealed[field.name] !== undefined ? 'Hide' : 'Show'}</button>
                <button class="icon accent" aria-label={`Copy ${field.name}`} onclick={() => copyTyped(field.name)}>⧉</button>
              {/if}
            {:else}
              <span class="v notes">{field.value === true ? 'Yes' : field.value === false ? 'No' : field.value}</span>
            {/if}
          </div>
        {:else}
          <div class="field"><span class="v muted">No details saved.</span></div>
        {/each}
      </div>
      {#if detail.document}
        <div class="section-label">Document</div>
        <div class="group">
          <div class="field"><span class="v">{detail.document.error ?? `${detail.document.name} · ${detail.document.mime} · ${(detail.document.size ?? 0).toLocaleString()} bytes`}</span></div>
          <div class="field doc-actions">
            <Button label="Safe preview" onclick={() => documentAction('doc_preview')} />
            <Button label="Open file" onclick={() => documentAction('doc_open')} />
            <Button label="Save a copy…" onclick={() => documentAction('doc_save_copy')} />
            <Button label="Replace file…" onclick={() => documentAction('doc_replace')} />
          </div>
          {#if preview}
            <div class="field"><span class="v notes">{preview.kind === 'text' ? preview.content : `Metadata-only preview · ${preview.reason}`}</span></div>
          {/if}
        </div>
      {/if}
    {:else}
      <div class="section-label">Sign-in</div>
      <div class="group">
        <div class="field">
          <span class="k">Username</span><span class="v">{detail.username || '—'}</span>
          {#if detail.username}<button class="icon" aria-label="Copy username" onclick={() => copy('username')}>⧉</button>{/if}
        </div>
        <div class="field">
          <span class="k">Password</span>
          <span class="v mono">{revealed ?? MASK}</span>
          <button class="text-btn" onclick={reveal}>{revealed !== null ? 'Hide' : 'Show'}</button>
          <button class="icon accent" aria-label="Copy password" onclick={() => copy('password')}>⧉</button>
        </div>
      </div>
      {#if detail.target}
        <div class="section-label">Website</div>
        <div class="group"><div class="field"><span class="v link">{detail.target}</span></div></div>
      {/if}
      {#if detail.notes !== null}
        <div class="section-label">Notes</div>
        <div class="group"><div class="field"><span class="v notes">{detail.notes || 'No notes'}</span></div></div>
      {/if}
      <LoginMore {selected} />
    {/if}

    {#if detail.tags?.length}
      <div class="tags">{#each detail.tags as tag (tag)}<span class="tag">{tag}</span>{/each}</div>
    {/if}
    <div class="footer"><Button label="Move to trash" variant="danger" onclick={trash} /></div>
  {/if}
</section>

<style>
  .detail { padding: 6px 18px 12px; overflow-y: auto; min-height: 0; }
  .empty { color: var(--text-muted); text-align: center; margin-top: 64px; }
  header { display: flex; align-items: center; gap: 10px; padding: 8px 0 4px; }
  .heading { flex: 1; min-width: 0; }
  h2 { margin: 0; font: 600 17px var(--font-display); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub { margin: 0; color: var(--text-muted); font-size: 12.5px; }
  .star { background: none; border: none; color: var(--warning); font-size: 18px; cursor: pointer; }
  .field { display: flex; align-items: center; gap: 10px; padding: 10px 14px; min-height: 42px; }
  .k { width: 110px; flex-shrink: 0; color: var(--text-muted); }
  .v { flex: 1; min-width: 0; overflow-wrap: anywhere; user-select: text; }
  .mono { font-family: var(--font-mono); letter-spacing: 0.5px; }
  .code { font-size: 22px; letter-spacing: 2px; }
  .top-code { gap: 14px; min-height: 52px; }
  .muted { color: var(--text-muted); }
  .link { color: var(--link); }
  .notes { white-space: pre-wrap; }
  .text-left { text-align: left; background: none; border: none; cursor: pointer; padding: 0; }
  .icon, .text-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 4px; font-size: 14px; }
  .text-btn { color: var(--link); font-size: 13px; }
  .accent { color: var(--link); }
  .tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 12px; }
  .tag { padding: 2px 10px; border-radius: 10px; background: var(--glass); font-size: 12px; }
  .footer { margin-top: 18px; }
  .doc-actions { flex-wrap: wrap; gap: 6px; }
</style>
