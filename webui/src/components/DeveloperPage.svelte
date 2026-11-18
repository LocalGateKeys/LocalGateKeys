<script>
  /** Developer: the SSH agent switch, the vault's SSH keys, and the SSH_AUTH_SOCK / Git signing setup. */
  import { dialog } from '../lib/dialog.js';
  import { call, on } from '../lib/api.js';
  import { t, formatDate } from '../lib/i18n.svelte.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import SecretScanSheet from './SecretScanSheet.svelte';

  let { onclose } = $props();
  let data = $state(null);
  let keyName = $state('');
  let preview = $state(null); // { id, rows } while the Git change is being reviewed
  let busy = $state(false);
  let scanning = $state(false);

  async function load() {
    const result = await call('developer_status');
    if (okOrToast(result, t('developer.openFailed'))) data = result;
  }
  $effect(() => {
    load();
    const off = on('developer.changed', () => load());
    return off;
  });

  async function act(method, ...args) {
    busy = true;
    const result = await call(method, ...args);
    busy = false;
    if (result.ok) { if (result.message) toast(result.message); await load(); }
    else if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error');
    return result;
  }

  async function setAgent(enabled) {
    const result = await call('developer_set', 'ssh_agent', enabled);
    if (!result.ok) toast(result.error.message, '', 'error');
    await load();
  }

  async function toggle(key, on) {
    const result = await call('developer_key_toggle', key.id, on);
    if (!result.ok) toast(result.error.message, '', 'error');
    await load(); // puts the switch back when the key was refused
  }

  async function setCli(enabled) {
    const result = await call('developer_cli_set', enabled);
    if (!result.ok) toast(result.error.message, '', 'error');
    await load();
  }

  async function setAgents(key, enabled) {
    const result = await call('developer_agents_set', key, enabled);
    if (!result.ok) toast(result.error.message, '', 'error');
    await load(); // puts the switch back when it was refused (no Pro)
  }

  /** The last stage of one run_with_secrets run, in words (the log keeps no values). */
  function runOutcome(run) {
    if (run.stage === 'finished') {
      if (run.timed_out) return t('agents.runs.timedOut');
      if (run.started === false) return t('agents.runs.failed');
      return t('agents.runs.finished', { code: run.exit_code ?? '?' });
    }
    const key = { refused: 'refused', denied: 'denied', approved: 'approved', released: 'released' }[run.stage];
    return key ? t(`agents.runs.${key}`) : run.stage;
  }

  async function toggleCliItem(item, on) {
    const result = await call('developer_cli_item_toggle', item.id, on);
    if (!result.ok) toast(result.error.message, '', 'error');
    await load(); // puts the switch back when the item was refused
  }

  async function generate() {
    const result = await act('developer_generate_key', keyName.trim());
    if (result.ok) keyName = '';
  }

  async function review(key) {
    const result = await call('developer_git_plan', key.id);
    if (result.ok) preview = { id: key.id, rows: result.rows };
    else toast(result.error.message, '', 'error');
  }

  async function applyGit() {
    const id = preview.id;
    preview = null;
    await act('developer_git_apply', id);
  }

  const agentText = $derived(data ? t(`developer.agent.status.${data.agent.status}`) : '');
  const unset = () => t('developer.preview.unset');
</script>

<div class="sheet glass" role="dialog" aria-label={t('developer.title')}>
  <header>
    <h2>{t('developer.title')}</h2>
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  <p class="muted">{t('developer.intro')}</p>
  {#if data}
    <div class="group">
      <div class="row">
        <div class="text">
          <div class="title">{t('developer.agent.title')}</div>
          <div class="desc">{t('developer.agent.desc')}</div>
          <div class="desc status" class:bad={data.agent.status === 'unavailable' || data.agent.status === 'taken'} role="status">{agentText}</div>
        </div>
        <input type="checkbox" role="switch" aria-label={t('developer.agent.title')} checked={data.agent.enabled}
          onchange={(e) => setAgent(e.currentTarget.checked)} />
      </div>
    </div>

    <div class="group">
      <div class="row">
        <div class="text">
          <div class="title">{t('developer.cli.title')}</div>
          <div class="desc">{t('developer.cli.desc')}</div>
        </div>
        {#if data.cli.available !== false}
          <input type="checkbox" role="switch" aria-label={t('developer.cli.title')} checked={data.cli.enabled}
            onchange={(e) => setCli(e.currentTarget.checked)} />
        {/if}
      </div>
      {#if data.cli.available === false}<p class="row muted">{t('developer.cli.storeUnavailable')}</p>{/if}
      {#if data.cli.packaged}<p class="row muted">{t('developer.cli.storeCommand')}</p>{/if}
    </div>
    {#if data.agents}
      <div class="group agents">
        <div class="row">
          <div class="text">
            <div class="title">{t('agents.settings.title')}</div>
            <div class="desc">{t('agents.settings.desc')}</div>
            {#if !data.agents.pro}<div class="desc warn">{t('agents.settings.proOnly')}</div>{/if}
          </div>
          <input type="checkbox" role="switch" aria-label={t('agents.settings.title')} checked={data.agents.enabled}
            disabled={!data.agents.pro && !data.agents.enabled} onchange={(e) => setAgents('enabled', e.currentTarget.checked)} />
        </div>
        {#if data.agents.enabled}
          <div class="row">
            <div class="text">
              <div class="title">{t('agents.settings.hello')}</div>
              <div class="desc">{t('agents.settings.helloDesc')}</div>
            </div>
            <input type="checkbox" role="switch" aria-label={t('agents.settings.hello')} checked={data.agents.hello}
              onchange={(e) => setAgents('hello', e.currentTarget.checked)} />
          </div>
          {#if data.agents.packaged}<p class="row muted">{t('agents.settings.storeHowTo')}</p>
          {:else}<p class="row muted">{t('agents.settings.howTo')}</p>{/if}
          {#if data.agents.available === false}<p class="row muted">{t('developer.cli.storeUnavailable')}</p>{/if}
        {/if}
      </div>
      {#if data.agents.runs && (data.agents.enabled || data.agents.runs.length)}
        <div class="section-label">{t('agents.runs.title')}</div>
        <div class="group agent-runs">
          {#each data.agents.runs as run, index (index)}
            <div class="row run">
              <div class="text">
                <div class="title">{run.agent} · {runOutcome(run)}</div>
                <div class="mono">{run.command}</div>
                {#each run.items ?? [] as item, i (i)}
                  <div class="desc">{`${item.variable} = ${item.title || '?'}: ${item.field}`}</div>
                {/each}
                {#if run.at}<div class="desc">{formatDate(new Date(run.at * 1000), { dateStyle: 'medium', timeStyle: 'short' })}</div>{/if}
              </div>
            </div>
          {:else}
            <p class="row muted">{t('agents.runs.empty')}</p>
          {/each}
        </div>
      {/if}
    {/if}
    {#if data.cli.enabled || data.agents?.enabled}
      <div class="section-label">{t('developer.cli.items')}</div>
      <div class="group cli-items">
        {#each data.cli.items as item (item.id)}
          <div class="row">
            <div class="text">
              <div class="title">{item.title}</div>
              {#if item.strict}<div class="desc warn">{t('developer.cli.strictShort')}</div>{/if}
            </div>
            <label class="offer">
              <input type="checkbox" role="switch" aria-label={`${t('developer.cli.allow')}: ${item.title}`}
                checked={item.listed} disabled={item.strict && !item.listed} title={item.strict ? t('developer.cli.strictReason') : ''}
                onchange={(e) => toggleCliItem(item, e.currentTarget.checked)} />
              <span>{t('developer.cli.allow')}</span>
            </label>
          </div>
        {:else}
          <p class="row muted">{t('developer.cli.empty')}</p>
        {/each}
      </div>
    {/if}

    <div class="section-label">{t('developer.keys.title')}</div>
    <div class="group">
      {#each data.keys as key (key.id)}
        <div class="row key">
          <div class="text">
            <div class="title">{key.title}</div>
            {#if key.fingerprint}<div class="desc mono">{key.fingerprint}</div>{/if}
            {#if key.state === 'needs_passphrase'}
              <div class="desc warn">{t('developer.keys.needsPassphrase')}. {t('developer.keys.needsPassphraseHint')}</div>
            {:else if key.state === 'unsupported'}
              <div class="desc warn">{t('developer.keys.notSupported')}: {key.reason}</div>
            {/if}
          </div>
          {#if key.state === 'ok'}
            <Button label={t('developer.keys.copy')} onclick={() => act('developer_copy_public_key', key.id)} />
            {#if key.offered && data.git.available && data.git.signing_ok}
              <Button label={t('developer.keys.git')} onclick={() => review(key)} />
            {/if}
          {/if}
          <label class="offer">
            <input type="checkbox" role="switch" aria-label={`${t('developer.keys.offer')}: ${key.title}`}
              checked={key.offered} disabled={key.state !== 'ok'} onchange={(e) => toggle(key, e.currentTarget.checked)} />
            <span>{t('developer.keys.offer')}</span>
          </label>
        </div>
      {:else}
        <p class="row muted">{t('developer.keys.empty')}</p>
      {/each}
      <div class="row">
        <div class="text">
          <div class="title">{t('developer.generate.title')}</div>
          <div class="desc">{t('developer.generate.desc')}</div>
        </div>
        <input class="textbox" aria-label={t('developer.generate.name')} placeholder={t('developer.generate.name')}
          maxlength="64" bind:value={keyName} />
        <Button label={t('developer.generate.button')} variant="primary" {busy} onclick={generate} />
      </div>
    </div>

    <div class="section-label">{t('developer.scan.title')}</div>
    <div class="group">
      <div class="row">
        <div class="text">
          <div class="title">{t('developer.scan.rowTitle')}</div>
          <div class="desc">{t('developer.scan.desc')}</div>
        </div>
        <Button label={t('developer.scan.button')} onclick={() => (scanning = true)} />
      </div>
    </div>

    <div class="section-label">{t('developer.setup.title')}</div>
    <p class="muted forwarding" role="note">{t('developer.setup.forwarding')}</p>
    <div class="group">
      <div class="row">
        <div class="text">
          <div class="title">{t('developer.env.title')}</div>
          <div class="desc">{t('developer.env.desc')}</div>
          <div class="desc mono">{t('developer.env.current', { value: data.env.current || t('developer.env.notSet') })}</div>
        </div>
        {#if data.env.applied}<Button label={t('developer.env.undo')} onclick={() => act('developer_env_undo')} />{/if}
        <Button label={t('developer.env.apply')} variant="primary" disabled={data.env.current === data.env.pipe}
          onclick={() => act('developer_env_apply')} />
      </div>
      <div class="row">
        <div class="text">
          <div class="title">{t('developer.git.title')}</div>
          <div class="desc">{t('developer.git.desc')}</div>
          {#if !data.git.available}<div class="desc warn">{t('developer.git.unavailable')}</div>
          {:else if !data.git.signing_ok}<div class="desc warn">{t('developer.git.tooOld', { version: data.git.version })}</div>
          {:else if !data.keys.some((k) => k.offered)}<div class="desc">{t('developer.git.noKey')}</div>{/if}
        </div>
        {#if data.git.applied}<Button label={t('developer.git.undo')} onclick={() => act('developer_git_undo')} />{/if}
      </div>
    </div>
  {/if}
</div>

{#if scanning}
  <SecretScanSheet cliEnabled={data?.cli.enabled} onclose={() => { scanning = false; load(); }} />
{/if}

{#if preview}
  <div class="scrim">
    <div class="card glass" role="dialog" aria-modal="true" use:dialog={{ onescape: () => (preview = null) }} aria-label={t('developer.preview.title')}>
      <h2>{t('developer.preview.title')}</h2>
      <table>
        <thead><tr><th>{t('developer.preview.setting')}</th><th>{t('developer.preview.current')}</th><th>{t('developer.preview.new')}</th></tr></thead>
        <tbody>
          {#each preview.rows as row (row.key)}
            <tr><td class="mono">{row.key}</td><td class="mono">{row.current ?? unset()}</td><td class="mono">{row.new}</td></tr>
          {/each}
        </tbody>
      </table>
      <div class="actions">
        <Button label={t('common.cancel')} onclick={() => (preview = null)} />
        <Button label={t('developer.preview.apply')} variant="primary" onclick={applyGit} />
      </div>
    </div>
  </div>
{/if}

<style>
  .sheet { position: absolute; inset: 10px; z-index: 32; border-radius: 18px; padding: 16px 18px; overflow-y: auto;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  header { display: flex; align-items: center; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .muted { color: var(--text-muted); font-size: 12.5px; }
  .forwarding { margin: 4px 0 8px; overflow-wrap: anywhere; min-width: 0; }
  .sheet, .sheet :global(.group) { min-width: 0; overflow-wrap: anywhere; overflow-x: hidden; }
  header { min-width: 0; }
  h2 { min-width: 0; overflow-wrap: anywhere; }
  .offer { flex-wrap: wrap; min-width: 0; }
  .textbox { max-width: 100%; min-width: 0; }
  table { table-layout: fixed; }
  td, th { overflow-wrap: anywhere; }
  .row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; margin: 0; }
  /* Hint paragraphs hold bare text: a flex row would keep it on one unshrinkable line. */
  p.row { display: block; overflow-wrap: anywhere; min-width: 0; }
  .text { overflow-wrap: anywhere; }
  .row + .row { border-top: 1px solid var(--separator); }
  .text { flex: 1; min-width: 0; }
  .title { font-size: 13.5px; }
  .desc { color: var(--text-muted); font-size: 12px; }
  .status { font-weight: 600; }
  .status.bad, .warn { color: var(--warning); }
  .mono { font: 11.5px ui-monospace, monospace; user-select: text; overflow-wrap: anywhere; }
  .offer { display: flex; align-items: center; gap: 6px; font-size: 12.5px; }
  .textbox { width: 160px; background: var(--group); color: var(--text); border: 1px solid var(--separator); border-radius: 8px; padding: 5px 8px; }
  input[type="checkbox"] { width: 18px; height: 18px; }
  .scrim { position: fixed; inset: 0; display: grid; place-items: center; background: var(--scrim); z-index: 50; }
  .card { width: min(640px, calc(100vw - 48px)); border-radius: var(--radius-card); padding: 22px 22px 18px; }
  .card h2 { margin: 0 0 12px; flex: none; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; color: var(--text-muted); font-weight: 600; padding: 4px 6px; }
  td { padding: 4px 6px; border-top: 1px solid var(--separator); vertical-align: top; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
</style>
