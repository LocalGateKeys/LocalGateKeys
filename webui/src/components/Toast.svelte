<script>
  /** Notifications pushed by Python ("toast" events). Closable; the timer pauses while the pointer is over one. */
  import { t } from '../lib/i18n.svelte.js';
  import { on } from '../lib/api.js';
  import { errorLogAction, mentionsErrorLog, routeAction } from '../lib/toast.js';

  let toasts = $state([]);
  let next = 0;
  const timers = new Map(); // id -> { left, started, handle }

  $effect(() => on('toast', (detail) => {
    const id = next++;
    // Python sends one {label, route, params} action; the page sends {label, run} actions.
    const actions = detail.action ? [routeAction(detail.action)] : [...(detail.actions ?? [])];
    if ((detail.error_log === true || mentionsErrorLog(`${detail.title ?? ''} ${detail.message ?? ''}`)) && !actions.some((a) => a.id === 'errorlog')) {
      actions.push(errorLogAction());
    }
    toasts.push({ id, kind: detail.kind === 'error' ? 'error' : 'info', title: detail.title ?? '', message: detail.message ?? '', actions });
    timers.set(id, { left: actions.length ? 15000 : 6000 }); // longer when there is something to click
    resume(id);
  }));

  function resume(id) {
    const t = timers.get(id);
    if (!t || t.handle) return;
    t.started = Date.now();
    t.handle = setTimeout(() => dismiss(id), t.left);
  }

  function pause(id) {
    const t = timers.get(id);
    if (!t?.handle) return;
    clearTimeout(t.handle);
    t.handle = null;
    t.left = Math.max(1500, t.left - (Date.now() - t.started));
  }

  function dismiss(id) {
    clearTimeout(timers.get(id)?.handle);
    timers.delete(id);
    toasts = toasts.filter((t) => t.id !== id);
  }
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each toasts as toast (toast.id)}
    <div class="toast glass {toast.kind}" role="group" aria-label={toast.title}
         onmouseenter={() => pause(toast.id)} onmouseleave={() => resume(toast.id)}
         onfocusin={() => pause(toast.id)} onfocusout={() => resume(toast.id)}>
      <div class="head">
        <strong>{toast.title}</strong>
        <button class="close" aria-label={t('toast.dismiss')} onclick={() => dismiss(toast.id)}>✕</button>
      </div>
      {#if toast.message}<span>{toast.message}</span>{/if}
      {#if toast.actions.length}
        <div class="actions">
          {#each toast.actions as a (a.label)}
            <button class:primary={a.primary} onclick={() => { dismiss(toast.id); a.run(); }}>{a.label}</button>
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .toasts { position: fixed; right: 18px; bottom: 18px; display: grid; gap: 8px; z-index: 60; }
  .toast { border-radius: 14px; padding: 10px 14px; display: grid; gap: 2px; max-width: 360px; }
  .toast span { color: var(--text-muted); }
  .head { display: flex; gap: 10px; align-items: flex-start; }
  .head strong { flex: 1; }
  .close {
    border: 0; background: transparent; color: var(--text-muted); cursor: pointer; font-size: 12px;
    padding: 2px 4px; margin: -2px -6px 0 0; border-radius: 6px;
  }
  .close:hover { color: inherit; }
  .error strong { color: var(--danger); }
  .actions { display: flex; gap: 6px; margin-top: 6px; }
  .actions button {
    font: inherit; font-size: 12.5px; padding: 4px 10px; border-radius: 8px; cursor: pointer;
    border: 1px solid color-mix(in srgb, currentColor 22%, transparent); background: transparent; color: inherit;
  }
  .actions button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
</style>
