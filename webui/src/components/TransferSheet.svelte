<script>
  /** Encrypted transfer packages: choose scope or package, preview, then commit explicitly. */
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let { onclose } = $props();
  let info = $state(null);
  let mode = $state('export');
  let pkg = $state(null);
  let pw = $state('');
  let pw2 = $state('');
  let scope = $state({ ids: '', kinds: '', tags: '', favorite: false, include_attachments: true });
  let policy = $state('skip');
  let allowReplace = $state(false);
  let preview = $state(null);
  let lines = $state([]);
  let status = $state('');
  let error = $state('');
  let busy = $state(false);

  $effect(() => { call('transfer_info').then((r) => { if (okOrToast(r)) { info = r; status = r.status; } }); });
  $effect(() => () => { pw = ''; pw2 = ''; call('transfer_cancel'); });

  function reset() { pkg = null; preview = null; lines = []; error = ''; }
  function invalidate() { preview = null; }

  async function choose() {
    const r = await call('transfer_choose', mode);
    if (r.ok) { pkg = r; invalidate(); } else if (r.error.code !== 'cancelled') error = r.error.message;
  }

  async function inspect() {
    const r = await call('transfer_inspect', pkg?.handle ?? '');
    if (r.ok) { lines = r.lines; status = r.status; } else error = r.error.message;
  }

  async function doPreview() {
    busy = true; error = '';
    const r = await call('transfer_preview', mode, pkg?.handle ?? '', pw, { ...scope }, policy, allowReplace);
    busy = false;
    if (r.ok) { preview = r.token; lines = r.lines; status = r.status; } else { preview = null; error = r.error.message; }
  }

  async function commit() {
    busy = true; error = '';
    const r = await call('transfer_commit', preview, mode, pkg?.handle ?? '', pw, pw2, { ...scope }, policy, allowReplace);
    busy = false;
    preview = null;
    pw = ''; pw2 = ''; // never kept after a commit attempt, whatever the outcome
    if (r.ok) { lines = r.lines; status = r.status; pkg = null; toast(r.status); return; }
    pkg = null; // the package must be chosen again after a failed commit
    if (r.error.code !== 'cancelled') error = r.error.message; else status = r.error.message;
  }
</script>

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Encrypted transfer">
  <header>
    <h2>{info?.title ?? 'Encrypted transfer'}</h2>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if info}
    <p class="muted">{info.intro}</p>
    <div class="seg" role="radiogroup" aria-label="Direction">
      <button role="radio" aria-checked={mode === 'export'} class:on={mode === 'export'} onclick={() => { mode = 'export'; reset(); }}>Export a package</button>
      <button role="radio" aria-checked={mode === 'import'} class:on={mode === 'import'} onclick={() => { mode = 'import'; reset(); }}>Import a package</button>
    </div>
    {#if mode === 'export'}
      <p class="muted">{info.scope_note}</p>
      <div class="group">
        <label class="row"><span>Item or credential IDs</span><input bind:value={scope.ids} oninput={invalidate} /></label>
        <label class="row"><span>Kinds (for example web, note)</span><input bind:value={scope.kinds} oninput={invalidate} /></label>
        <label class="row"><span>Tags</span><input bind:value={scope.tags} oninput={invalidate} /></label>
        <label class="row"><input type="checkbox" bind:checked={scope.favorite} onchange={invalidate} /> Favorites only</label>
        <label class="row"><input type="checkbox" bind:checked={scope.include_attachments} onchange={invalidate} /> Include attachments and dependencies</label>
      </div>
    {:else}
      <div class="group">
        <label class="row"><span>Conflicts</span>
          <select aria-label="Conflicts" bind:value={policy} onchange={invalidate}>{#each info.policies as p (p)}<option value={p}>{p}</option>{/each}</select>
        </label>
        <label class="row"><input type="checkbox" bind:checked={allowReplace} onchange={invalidate} /> Allow replace</label>
      </div>
    {/if}
    <div class="pathrow">
      <span class="path">{pkg?.path ?? 'No package chosen'}</span>
      <Button label="Choose…" onclick={choose} />
      {#if mode === 'import'}<Button label="Inspect" disabled={!pkg} onclick={inspect} />{/if}
    </div>
    <div class="group">
      <Field label="Transfer password" type="password" bind:value={pw} oninput={invalidate} autocomplete="new-password" />
      {#if mode === 'export'}<Field label="Confirm password (export)" type="password" bind:value={pw2} autocomplete="new-password" />{/if}
    </div>
    {#if lines.length}<pre class="group summary" aria-label="Preview">{lines.join('\n')}</pre>{/if}
    <p class="muted" role="status">{status}</p>
    {#if error}<p class="error" role="alert">{error}<ErrorLogLink text={error} /></p>{/if}
    <footer>
      <Button label="Cancel" onclick={() => { call('transfer_cancel'); invalidate(); pw = ''; pw2 = ''; status = 'The pending transfer was cancelled before commit.'; }} />
      <Button label="Preview" busy={busy && !preview} disabled={!pkg || !pw} onclick={doPreview} />
      <Button label={mode === 'export' ? 'Write package' : 'Import package'} variant="primary" busy={busy && !!preview} busyLabel="Committing…" disabled={!preview} onclick={commit} />
    </footer>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); display: flex; flex-direction: column; gap: 8px; }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; margin: 0; }
  .seg { display: flex; border: 1px solid var(--separator); border-radius: 9px; overflow: hidden; align-self: flex-start; }
  .seg button { background: none; border: none; color: inherit; padding: 6px 14px; cursor: pointer; }
  .seg button.on { background: var(--accent); color: #fff; }
  .row { display: flex; align-items: center; gap: 10px; padding: 8px 14px; font-size: 13px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .row span { width: 210px; color: var(--text-muted); }
  .row input:not([type="checkbox"]), select { flex: 1; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px; user-select: text; }
  .pathrow { display: flex; gap: 8px; align-items: center; }
  .path { flex: 1; font-size: 12.5px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .summary { padding: 10px 12px; font: 12px ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
