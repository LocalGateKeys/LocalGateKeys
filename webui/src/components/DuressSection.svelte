<script>
  /** Settings › Unlocking › Duress password (Pro): a second master password that opens a separate vault and
   *  makes this vault refuse its own master password for some hours. The page is the same in every session. */
  import { call } from '../lib/api.js';
  import { t } from '../lib/i18n.svelte.js';
  import { toast } from '../lib/toast.js';
  import Button from './Button.svelte';
  import Field from './Field.svelte';

  let view = $state(null);
  let busy = $state(false);
  let message = $state('');
  let current = $state('');
  let password = $state('');
  let confirm = $state('');
  let hours = $state(24);
  let picked = $state([]);
  const full = $derived(!!view && picked.length >= view.max_items);

  async function load() {
    const result = await call('duress_status');
    if (result.ok) {
      view = result;
      hours = result.lock_hours;
    }
  }

  $effect(() => { load(); });

  function toggle(id, on) {
    picked = on ? [...picked, id] : picked.filter((value) => value !== id);
  }

  function clear() {
    current = '';
    password = '';
    confirm = '';
  }

  async function setUp() {
    if (busy) return;
    busy = true;
    message = '';
    const pending = call('duress_setup', current, password, confirm, Number(hours), picked);
    clear(); // the passwords leave the page once the call is sent
    const result = await pending;
    busy = false;
    if (result.ok) {
      view = result;
      picked = [];
      message = result.message;
    } else toast(result.error.message, '', 'error');
  }

  async function remove() {
    if (busy) return;
    busy = true;
    message = '';
    const result = await call('duress_remove');
    busy = false;
    if (result.ok) {
      view = result;
      message = result.message;
    } else if (result.error.code !== 'cancelled') toast(result.error.message, '', 'error');
  }
</script>

{#if view}
  <div class="section-label">{t('duress.ui.section')}</div>
  <div class="group card" data-testid="duress">
    <p class="note">{t('duress.ui.note')}</p>
    {#if message}<p class="status success" role="status">{message}</p>{/if}
    {#if view.configured}
      <p class="status success">{t('duress.ui.statusOn', { count: view.lock_hours })}</p>
      <footer><Button label={t('unlockingPage.remove')} variant="danger" onclick={remove} disabled={busy} /></footer>
    {:else if !view.pro}
      <p class="status">{t('duress.ui.statusOff')}</p>
      <p class="note warn">{t('duress.ui.proOnly')}</p>
    {:else}
      <p class="status">{t('duress.ui.statusOff')}</p>
      <Field label={t('duress.ui.current')} type="password" bind:value={current} autocomplete="current-password" />
      <Field label={t('duress.ui.password')} type="password" bind:value={password} autocomplete="new-password" />
      <Field label={t('duress.ui.confirm')} type="password" bind:value={confirm} autocomplete="new-password" />
      <label class="hours">{t('duress.ui.hours')}
        <input type="number" min={view.min_hours} max={view.max_hours} bind:value={hours} disabled={busy} />
      </label>
      {#if view.items.length}
        <details>
          <summary>{t('duress.ui.items', { count: view.max_items })}</summary>
          <ul class="items">
            {#each view.items as item (item.id)}
              {@const on = picked.includes(item.id)}
              <li><label><input type="checkbox" checked={on} disabled={busy || (full && !on)}
                onchange={(e) => toggle(item.id, e.currentTarget.checked)} /> {item.title}</label></li>
            {/each}
          </ul>
        </details>
      {/if}
      <p class="note">{t('duress.ui.itemsNote')}</p>
      <p class="note">{view.folder ? t('duress.ui.folderNote') : t('duress.ui.noFolderNote')}</p>
      <footer>
        <Button label={t('duress.ui.setUp')} variant="primary" onclick={setUp} busy={busy}
          disabled={!current || !password || !confirm} />
      </footer>
    {/if}
  </div>
{/if}

<style>
  .card { padding: 14px; display: grid; gap: 8px; }
  .status { margin: 0; font-weight: 600; }
  .status.success { color: #34C759; }
  .note { margin: 0; color: var(--text-muted); font-size: 12.5px; white-space: pre-line; }
  .note.warn { color: var(--warning); }
  .hours { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  .hours input { width: 5em; }
  .items { list-style: none; margin: 6px 0 0; padding: 0; max-height: 180px; overflow-y: auto; display: grid; gap: 4px;
    font-size: 13px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
