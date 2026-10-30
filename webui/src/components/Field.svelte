<script>
  /** Label-left field row. type="password" gets a Show/Hide toggle. */
  import { t } from '../lib/i18n.svelte.js';

  let {
    label,
    value = $bindable(''),
    type = 'text',
    placeholder = '',
    autocomplete = 'off',
    autofocus = false,
    invalid = false,
    oninput = undefined,
    disabled = false,
  } = $props();

  const id = `f-${Math.random().toString(36).slice(2, 9)}`;
  let revealed = $state(false);
  let input = $state();
  const inputType = $derived(type === 'password' && !revealed ? 'password' : type === 'password' ? 'text' : type);

  $effect(() => {
    if (autofocus && input) input.focus();
  });
</script>

<div class="field" class:invalid>
  <label for={id}>{label}</label>
  <input
    bind:this={input}
    {id}
    type={inputType}
    bind:value
    {placeholder}
    {autocomplete}
    spellcheck="false"
    aria-invalid={invalid}
    {oninput}
    {disabled}
  />
  {#if type === 'password'}
    <button type="button" class="reveal" onclick={() => (revealed = !revealed)}>
      {revealed ? t('field.hide') : t('field.show')}
    </button>
  {/if}
</div>

<style>
  .field {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: var(--row-pad);
    min-height: 44px;
  }
  label { width: 128px; flex-shrink: 0; color: var(--text-muted); }
  input {
    flex: 1;
    min-width: 0;
    background: none;
    border: none;
    outline: none;
    padding: 4px 0;
    user-select: text;
  }
  input::placeholder { color: var(--text-faint); }
  .invalid label { color: var(--danger); }
  .reveal {
    background: none;
    border: none;
    color: var(--link);
    cursor: pointer;
    padding: 2px 4px;
  }
</style>
