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
  let capsOn = $state(false); // Caps Lock warning, password fields only
  function caps(event) { if (type === 'password') capsOn = !!event.getModifierState?.('CapsLock'); }
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
    onkeydown={caps}
    onkeyup={caps}
    onblur={() => (capsOn = false)}
    aria-describedby={capsOn ? `${id}-caps` : undefined}
  />
  {#if capsOn}<span class="caps" id="{id}-caps" role="status">{t('field.capsLock')}</span>{/if}
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
  .caps { color: var(--danger); font-size: 12px; white-space: nowrap; }
  .reveal {
    background: none;
    border: none;
    color: var(--link);
    cursor: pointer;
    padding: 2px 4px;
  }
</style>
