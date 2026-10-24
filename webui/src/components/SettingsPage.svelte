<script>
  /** Settings: the classic sections and rows, saved as you change them. Buttons open the matching page. */
  import { untrack } from 'svelte';
  import { call, on } from '../lib/api.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { recall, remember } from '../lib/remember.js';

  let { section = null, onclose, onroute } = $props();
  let data = $state(null);
  // A link to a section wins; otherwise reopen where the user left off.
  let active = $state(untrack(() => section ?? recall('settings.section', null)));
  let saved = $state(false);
  let errors = $state({});
  let drafts = $state({});
  let savedTimer = null;

  async function load() {
    const result = await call('settings_page');
    if (!okOrToast(result, 'Could not open Settings')) { onclose(); return; }
    data = result;
    if (!active || !result.sections.some((s) => s.key === active)) active = result.sections[0]?.key;
  }
  $effect(() => {
    load();
    const off = on('settings.changed', () => load());
    return off;
  });

  function flashSaved() {
    saved = true;
    clearTimeout(savedTimer);
    savedTimer = setTimeout(() => (saved = false), 1500);
  }

  async function set(row, value) {
    errors = { ...errors, [row.key]: '' };
    const result = await call('settings_set', row.key, value);
    if (result.ok) { flashSaved(); await load(); return; }
    if (result.error.code !== 'cancelled') errors = { ...errors, [row.key]: result.error.message || 'That value cannot be used.' };
    await load(); // revert the control to the saved value
  }

  function pickValue(row, raw) {
    const option = row.options.find((o) => String(o.value) === raw);
    return option ? option.value : raw;
  }

  async function chooseFolder(row) {
    const result = await call('settings_choose_folder', row.key);
    if (result.ok) { flashSaved(); load(); }
    else if (result.error.code !== 'cancelled') errors = { ...errors, [row.key]: result.error.message };
  }

  function press(row) {
    if (row.route === 'errorlog') { call('errorlog_open'); return; }
    onroute(row.route, row.params ?? {}, load);
  }

  const current = $derived(data?.sections.find((s) => s.key === active));

  // Search: every word must appear in the row, its section's title or the section's keywords
  // (the same keywords the command palette uses), so "lock", "hibp" or "clipboard" find the right switch.
  let query = $state('');
  let searchBox = $state();
  let sheetEl = $state();
  const norm = (text) => String(text ?? '').toLowerCase();
  const results = $derived.by(() => {
    const words = norm(query).split(/\s+/).filter(Boolean);
    if (!words.length || !data) return null;
    return data.sections.map((section) => {
      const around = norm(`${section.title} ${(section.keywords ?? []).join(' ')}`);
      const rows = section.rows.filter((row) => {
        const text = `${around} ${norm(row.title)} ${norm(row.description)} ${norm(row.text)} ${norm(row.label)}`;
        return words.every((w) => text.includes(w));
      });
      return { ...section, rows };
    }).filter((section) => section.rows.length);
  });

  function searchKeys(event) {
    // Ctrl+F searches Settings while this page is the one showing.
    if (!sheetEl?.offsetParent) return;
    if (event.ctrlKey && (event.key === 'f' || event.key === 'F')) {
      event.preventDefault(); event.stopImmediatePropagation(); searchBox?.focus(); searchBox?.select();
    } else if (event.key === 'Escape' && query && document.activeElement === searchBox) {
      event.preventDefault(); event.stopImmediatePropagation(); query = '';
    }
  }

  function showSection(key) { query = ''; active = key; remember('settings.section', key); }
</script>

{#snippet rowView(row)}
    {#if row.type === 'note'}
      <p class="note row">{row.text}</p>
    {:else}
      <div class="row">
        <div class="text">
          <div class="title">{row.title}</div>
          {#if row.description}<div class="desc">{row.description}</div>{/if}
          {#if row.key && errors[row.key]}<div class="error" role="alert">{errors[row.key]}</div>{/if}
        </div>
        {#if row.type === 'switch'}
          <input type="checkbox" role="switch" aria-label={row.title} checked={row.value} onchange={(e) => set(row, e.currentTarget.checked)} />
        {:else if row.type === 'choice'}
          <select aria-label={row.title} value={String(row.value)} onchange={(e) => set(row, pickValue(row, e.currentTarget.value))}>
            {#each row.options as o (o.label)}<option value={String(o.value)}>{o.label}</option>{/each}
          </select>
        {:else if row.type === 'segmented'}
          <div class="seg" role="radiogroup" aria-label={row.title}>
            {#each row.options as o (o.label)}
              <button role="radio" aria-checked={o.value === row.value} class:on={o.value === row.value} onclick={() => set(row, o.value)}>{o.label}</button>
            {/each}
          </div>
        {:else if row.type === 'text'}
          <input class="textbox" aria-label={row.title} value={drafts[row.key] ?? row.value}
            oninput={(e) => (drafts = { ...drafts, [row.key]: e.currentTarget.value })}
            onchange={(e) => { const v = e.currentTarget.value; drafts = { ...drafts, [row.key]: undefined }; set(row, v); }} />
        {:else if row.type === 'folder'}
          <span class="desc path">{row.value || 'Not set'}</span>
          {#if row.value}<Button label="Clear" onclick={() => set(row, '')} />{/if}
          <Button label="Choose…" onclick={() => chooseFolder(row)} />
        {:else if row.type === 'shortcut'}
          <kbd>{row.keys}</kbd>
        {:else if row.type === 'link'}
          <Button label={row.label} onclick={() => call('system_open_url', row.url)} />
        {:else if row.type === 'button'}
          <Button label={row.label} variant={row.primary ? 'primary' : undefined} onclick={() => press(row)} />
        {/if}
      </div>
    {/if}
{/snippet}

<svelte:window onkeydowncapture={searchKeys} />

<div class="sheet glass" role="dialog" aria-modal="true" aria-label="Settings" bind:this={sheetEl}>
  <header>
    <h2>Settings</h2>
    <input class="search" type="search" placeholder="Search settings" aria-label="Search settings"
      bind:this={searchBox} bind:value={query} />
    <span class="pill" class:on={saved} role="status">{saved ? 'Saved' : data?.saved_text ?? ''}</span>
    <button class="close" aria-label="Close" onclick={onclose}>✕</button>
  </header>
  {#if data}
    <div class="body">
      <nav aria-label="Settings sections">
        {#each data.sections as s (s.key)}
          <button class:on={!results && s.key === active} aria-current={s.key === active ? 'page' : undefined} onclick={() => showSection(s.key)}>{s.title}</button>
        {/each}
      </nav>
      {#if results}
        <section class="rows" aria-label="Search results">
          {#each results as section (section.key)}
            <h3 class="hit"><button class="section-link" onclick={() => showSection(section.key)}>{section.title}</button></h3>
            <div class="group">{#each section.rows as row, i (row.key ?? row.title ?? i)}{@render rowView(row)}{/each}</div>
          {:else}
            <p class="note">No settings match “{query}”.</p>
          {/each}
        </section>
      {:else if current}
        <section class="rows" aria-label={current.title}>
          <h3>{current.title}</h3>
          {#if current.error}<p class="error">{current.error}<ErrorLogLink text={current.error} /></p>{/if}
          <div class="group">
            {#each current.rows as row, i (row.key ?? row.title ?? i)}{@render rowView(row)}{/each}
          </div>
        </section>
      {/if}
    </div>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 30; border-radius: 18px; padding: 16px 18px; display: flex; flex-direction: column;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; gap: 10px; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  h3 { margin: 0 0 8px; font: 600 15px var(--font-display); }
  .pill { font-size: 12px; color: var(--text-muted); padding: 2px 10px; border-radius: 999px; }
  .pill.on { background: color-mix(in srgb, var(--success) 22%, transparent); color: var(--success); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .search {
    width: 220px; font: inherit; font-size: 13px; padding: 5px 10px; border-radius: 8px; color: inherit;
    border: 1px solid color-mix(in srgb, currentColor 18%, transparent); background: var(--group);
  }
  .hit { margin-top: 14px; }
  .hit:first-child { margin-top: 0; }
  .section-link { border: 0; background: none; padding: 0; font: inherit; color: var(--link); cursor: pointer; }
  .body { flex: 1; min-height: 0; display: grid; grid-template-columns: 190px 1fr; gap: 14px; margin-top: 12px; }
  nav { display: flex; flex-direction: column; gap: 2px; }
  nav button { text-align: left; background: none; border: none; color: inherit; padding: 7px 10px; border-radius: 8px; cursor: pointer; }
  nav button.on { background: var(--group); font-weight: 600; }
  .rows { overflow-y: auto; min-height: 0; }
  .row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; margin: 0; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; }
  .title { font-size: 13.5px; }
  .desc, .note { color: var(--text-muted); font-size: 12px; }
  .path { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .error { color: var(--danger); font-size: 12px; }
  select, .textbox { background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px 8px; }
  .textbox { width: 150px; user-select: text; }
  .seg { display: flex; border: 1px solid var(--separator); border-radius: 9px; overflow: hidden; }
  .seg button { background: none; border: none; color: inherit; padding: 5px 12px; cursor: pointer; }
  .seg button.on { background: var(--accent); color: #fff; }
  kbd { font: 12px ui-monospace, monospace; padding: 3px 8px; border-radius: 6px; background: var(--group); border: 1px solid var(--separator); }
  input[type="checkbox"] { width: 18px; height: 18px; }
</style>
