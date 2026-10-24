<script>
  /** A login's extra content: password history, recovery codes, custom fields, autofill rules. */
  import { call } from '../lib/api.js';
  import { notice, okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { selected } = $props();

  let codesInfo = $state(null);
  let codes = $state(null);
  let history = $state(null);
  let fields = $state(null);
  // The field editor (Add, Save) shows only for rows from a successful fields_get: a save replaces the whole
  // list, so saving rows the page never loaded would delete the stored fields.
  let fieldsLoaded = $state(false);
  let fieldsError = $state('');
  let removed = $state([]); // stored row indexes the user removed; the save must account for every stored row
  let policy = $state(null);
  // "Always ask for the master password": fields stay locked until the user asks, so selecting never prompts.
  const strict = $derived(Boolean(policy?.require_master_password));

  $effect(() => {
    const ref = selected;
    codes = null; history = null; codesInfo = null; policy = null;
    dropFields();
    (async () => {
      const [count, p] = await Promise.all([call('recovery_count', ref), call('policy_get', ref)]);
      if (ref !== selected) return;
      if (count.ok) codesInfo = count;
      if (!p.ok) { fieldsError = p.error?.message || FIELDS_ERROR; return; }
      policy = p.policy;
      if (!p.policy.require_master_password) await loadFields(ref);
    })();
  });

  const FIELDS_ERROR = 'Custom fields could not be loaded.';

  function dropFields() { fields = null; fieldsLoaded = false; fieldsError = ''; removed = []; }
  function showFields(rows) { fields = rows; removed = []; fieldsLoaded = true; fieldsError = ''; }

  async function loadFields(ref) {
    const f = await call('fields_get', ref, false);
    if (ref !== selected) return;
    if (f.ok) showFields(f.fields); else fieldsError = f.error?.message || FIELDS_ERROR;
  }

  async function retryFields() {
    const ref = selected;
    fieldsError = '';
    if (policy === null) {
      const p = await call('policy_get', ref);
      if (ref !== selected) return;
      if (!p.ok) { fieldsError = p.error?.message || FIELDS_ERROR; return; }
      policy = p.policy;
    }
    if (!policy.require_master_password) await loadFields(ref);
  }

  async function openHistory() {
    const result = await call('history_list', selected);
    if (okOrToast(result, 'History not opened')) history = result.rows;
  }
  async function copyPrevious(row) {
    const result = await call('history_copy', selected, row.index, row.changed_at);
    if (okOrToast(result, 'Not copied')) notice(result);
  }
  async function revealCodes() {
    const result = await call('recovery_get', selected);
    if (okOrToast(result, 'Codes not revealed')) codes = result.codes.join('\n');
  }
  async function saveCodes() {
    const result = await call('recovery_save', selected, codes.split('\n').map((c) => c.trim()).filter(Boolean));
    if (okOrToast(result)) { toast(result.message); codes = null; codesInfo = (await call('recovery_count', selected)); }
  }
  async function useNext() {
    const result = await call('recovery_use_next', selected);
    if (okOrToast(result, 'No code used')) { toast(result.message); codesInfo = (await call('recovery_count', selected)); }
  }
  async function revealFields() {
    const result = await call('fields_get', selected, true);
    if (okOrToast(result, 'Fields not revealed')) showFields(result.fields);
  }
  function removeField(i) {
    const index = fields[i]?.index;
    if (Number.isInteger(index)) removed = [...removed, index];
    fields = fields.filter((_, j) => j !== i);
  }
  async function saveFields() {
    if (!fieldsLoaded || fields === null) return;
    const ref = selected;
    const result = await call('fields_save', ref, fields, removed);
    if (!okOrToast(result)) return;
    toast(result.message);
    // Stored row indexes changed: load the saved rows again (a strict login locks them again instead).
    dropFields();
    if (ref === selected && !strict) await loadFields(ref);
  }
  async function setPolicy(key, value, control) {
    const ref = selected;
    const result = await call('policy_save', ref, { [key]: value });
    if (!okOrToast(result, 'Rule not saved')) {
      // Cancelled or refused: put the control back to the saved rule.
      if (control) control[control.type === 'checkbox' ? 'checked' : 'value'] = policy[key];
      return;
    }
    policy = { ...policy, [key]: value };
    toast(result.message);
    if (key === 'require_master_password') {
      codes = null; history = null;
      dropFields();
      const count = await call('recovery_count', ref);
      if (ref === selected && count.ok) codesInfo = count;
      if (!value) await loadFields(ref);
    }
  }
  const when = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 16).replace('T', ' ');
</script>

<div class="more">
  <div class="section-label">Recovery codes</div>
  <div class="group">
    {#if codes !== null}
      <textarea aria-label="Recovery codes" bind:value={codes}></textarea>
      <div class="actions"><span class="hint">One code per line. Using a code copies it and removes it from this list.</span>
        <Button label="Save codes" onclick={saveCodes} /></div>
    {:else}
      <div class="line"><span class="muted">{codesInfo?.text ?? ''}</span>
        <Button label="Reveal" onclick={revealCodes} />
        {#if codesInfo?.count || codesInfo?.locked}<Button label="Copy and use next code" onclick={useNext} />{/if}</div>
    {/if}
  </div>

  <div class="section-label">Custom fields</div>
  <div class="group">
    {#if strict && !fieldsLoaded}
      <div class="line"><span class="muted grow">Locked · this login always asks for the master password.</span>
        <Button label="Show fields" onclick={revealFields} /></div>
    {:else if !fieldsLoaded}
      <div class="line"><span class="muted grow">{fieldsError || 'Loading custom fields…'}</span>
        {#if fieldsError}<Button label="Try again" onclick={retryFields} />{/if}</div>
    {:else}
    {#each fields ?? [] as field, i (i)}
      <div class="line">
        <input class="name" aria-label="Field name" bind:value={field.name} />
        {#if field.value === null}<span class="muted grow">Hidden</span>
        {:else}<input class="grow" aria-label={`Value of ${field.name}`} type={field.hidden ? 'password' : 'text'} bind:value={field.value} />{/if}
        <label class="muted"><input type="checkbox" bind:checked={field.hidden} /> Hidden</label>
        <button class="text-btn" onclick={() => removeField(i)}>Remove</button>
      </div>
    {/each}
    <div class="actions">
      <span class="hint">Hidden fields are masked on screen and treated like passwords when exported.</span>
      <button class="text-btn" onclick={() => (fields = [...(fields ?? []), { name: '', value: '', hidden: true }])}>Add field</button>
      {#if fields?.some((f) => f.value === null)}<button class="text-btn" onclick={revealFields}>Reveal hidden</button>{/if}
      <Button label="Save fields" onclick={saveFields} />
    </div>
    {/if}
  </div>

  {#if policy}
    <div class="section-label">Autofill rules</div>
    <div class="group">
      <label class="line"><span class="k">Filling</span>
        <select aria-label="Filling" value={policy.fill} onchange={(e) => setPolicy('fill', e.currentTarget.value, e.currentTarget)}>
          <option value="click">On click</option><option value="never">Off</option></select></label>
      <label class="line"><span class="k">Sign in after filling</span>
        <select aria-label="Sign in after filling" value={policy.sign_in} onchange={(e) => setPolicy('sign_in', e.currentTarget.value, e.currentTarget)}>
          <option value="inherit">Default</option><option value="never">Never</option><option value="enabled">Always</option></select></label>
      <label class="line"><span class="k">Always ask for the master password</span>
        <input type="checkbox" checked={policy.require_master_password} onchange={(e) => setPolicy('require_master_password', e.currentTarget.checked, e.currentTarget)} /></label>
      <label class="line"><span class="k">Offer to save changes from the browser</span>
        <input type="checkbox" checked={policy.save_prompts} onchange={(e) => setPolicy('save_prompts', e.currentTarget.checked, e.currentTarget)} /></label>
      <p class="hint pad">Filling and sign-in only ever happen after your click, never when a page loads.</p>
    </div>
  {/if}

  <div class="section-label">Password history</div>
  <div class="group">
    {#if history === null}
      <div class="line"><span class="muted grow">The last five replaced passwords are kept encrypted.</span>
        <Button label="Password history" onclick={openHistory} /></div>
    {:else if history.length === 0}
      <div class="line muted">No previous passwords.</div>
    {:else}
      {#each history as row (row.index)}
        <div class="line"><span class="grow">{when(row.changed_at)}</span>
          <button class="text-btn" onclick={() => copyPrevious(row)}>Copy previous password</button></div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .line { display: flex; align-items: center; gap: 8px; padding: 9px 14px; min-height: 40px; }
  .line + .line { border-top: 1px solid var(--separator); }
  .k { flex: 1; color: var(--text-muted); }
  .grow { flex: 1; min-width: 0; }
  .name { width: 110px; }
  input:not([type="checkbox"]), textarea { background: none; border: none; outline: none; user-select: text; }
  textarea { width: 100%; min-height: 90px; padding: 10px 14px; resize: vertical; }
  select { background: var(--group); border: 1px solid var(--glass-border); border-radius: 6px; padding: 3px 6px; }
  .muted { color: var(--text-muted); }
  .hint { color: var(--text-faint); font-size: 12px; flex: 1; }
  .pad { padding: 0 14px 10px; margin: 0; }
  .actions { display: flex; align-items: center; gap: 8px; padding: 8px 14px; border-top: 1px solid var(--separator); }
  .text-btn { background: none; border: none; color: var(--link); cursor: pointer; }
</style>
