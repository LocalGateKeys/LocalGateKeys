<script>
  /** Pill button. variant: primary | glass | danger | link */
  let {
    label,
    variant = 'glass',
    type = 'button',
    busy = false,
    busyLabel = '',
    disabled = false,
    icon = '',
    onclick = undefined,
  } = $props();
</script>

<button
  class="btn {variant}"
  {type}
  disabled={disabled || busy}
  aria-busy={busy}
  onclick={onclick}
>
  {#if icon}<span class="icon" aria-hidden="true">{icon}</span>{/if}
  {busy && busyLabel ? busyLabel : label}
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    height: 32px;
    padding: 0 16px;
    border-radius: 999px;
    border: 1px solid transparent;
    cursor: pointer;
    white-space: nowrap;
    transition: background-color 120ms ease, transform 80ms ease;
  }
  .btn:active:not(:disabled) { transform: scale(0.98); }
  .btn:disabled { opacity: 0.55; cursor: default; }
  .primary { background: var(--accent); color: var(--on-accent); font-weight: 600; }
  .primary:hover:not(:disabled) { background: var(--accent-hover); }
  .glass {
    background: var(--glass);
    border-color: var(--glass-border);
    box-shadow: inset 0 1px 0 var(--glass-highlight);
    backdrop-filter: blur(var(--glass-blur)) saturate(170%);
  }
  .glass:hover:not(:disabled) { background: var(--glass-hover); }
  .danger { background: transparent; border-color: var(--danger); color: var(--danger); }
  .link { background: none; color: var(--link); padding: 0 4px; height: auto; }
  .icon { font-size: 15px; line-height: 1; }
</style>
