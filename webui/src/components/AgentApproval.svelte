<script>
  /** An AI agent asks to sign in to a site, read one allow-listed value, or run one command with secrets
   * (agent_gate). Everything the agent sent is shown as text: the purpose and the command line sit in monospace
   * blocks and are never rendered as markup. "Approve once" is the only yes (no "always"); Deny, Escape, closing
   * the palette or the timeout are a no. The approve button arms after guardMs so a keystroke aimed at another app
   * never approves. */
  import { dialog } from '../lib/dialog.js';
  import { t } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';

  let { request, onanswer, guardMs = 0 } = $props();

  const titleId = `a-${Math.random().toString(36).slice(2, 9)}`;
  const run = $derived(request.action === 'run');
  const title = $derived(run ? t('agents.view.runTitle')
    : request.action === 'read' ? t('agents.view.readTitle') : t('agents.view.signInTitle'));
  const secrets = $derived(Array.isArray(request.secrets) ? request.secrets : []);
  // A sign-in either uses the site's passkey or fills the password; anything else is shown as the password case.
  const passkey = $derived(request.method === 'passkey');
  let armed = $state(false);
  const ready = $derived(!guardMs || armed);
  let denyButton = $state();

  $effect(() => {
    if (!guardMs) return undefined;
    const timer = setTimeout(() => { armed = true; }, guardMs);
    return () => clearTimeout(timer);
  });
  // Focus Deny without scrolling: a long request must open at its top (agent, folder, command), not at the buttons.
  $effect(() => { denyButton?.querySelector('button')?.focus({ preventScroll: true }); });

  function onkeydown(event) {
    if (event.key === 'Escape') { event.preventDefault(); onanswer({ approved: false }); }
  }
</script>

<svelte:window {onkeydown} />

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" use:dialog aria-labelledby={titleId}>
    <h2 id={titleId}>{title}</h2>
    <dl>
      <dt>{t('agents.view.agent')}</dt><dd data-testid="agent-name">{request.agent}{#if request.process} ({request.process}){/if}</dd>
      {#if run}
        <dt>{t('agents.view.folder')}</dt><dd data-testid="agent-cwd">{request.cwd}</dd>
        <dt>{t('agents.view.timeLimit')}</dt><dd data-testid="agent-timeout">{t('agents.view.seconds', { seconds: request.timeout })}</dd>
      {:else}
        <dt>{request.action === 'read' ? t('agents.view.item') : t('agents.view.site')}</dt><dd data-testid="agent-site">{request.site}</dd>
        {#if request.action !== 'read'}<dt>{t('agents.view.method')}</dt><dd data-testid="agent-method">{passkey ? t('agents.view.methodPasskey') : t('agents.view.methodPassword')}</dd>{/if}
      {/if}
    </dl>
    {#if run}
      <p class="label">{t('agents.view.command')}</p>
      <pre class="purpose" data-testid="agent-command">{request.command}</pre>
      <p class="label">{t('agents.view.secrets')}</p>
      <ul class="secrets" data-testid="agent-secrets">
        {#each secrets as secret, index (index)}
          <li>{t('agents.approve.runValue', { variable: secret.variable, item: secret.item, field: secret.field })}</li>
        {/each}
      </ul>
    {/if}
    <p class="label">{t('agents.view.purpose')}</p>
    <pre class="purpose" data-testid="agent-purpose">{request.purpose || '-'}</pre>
    <p class="note" class:warn={run}>{run ? t('agents.view.runNote') : request.action === 'read' ? t('agents.view.readNote') : passkey ? t('agents.view.signInPasskeyNote') : t('agents.view.signInNote')}</p>
    {#if request.hello}<p class="note">{t('agents.view.hello')}</p>{/if}
    <div class="actions">
      <span bind:this={denyButton}><Button label={t('modal.deny')} onclick={() => onanswer({ approved: false })} /></span>
      <Button label={t('agents.view.approveOnce')} variant="primary" disabled={!ready}
        onclick={() => { if (ready) onanswer({ approved: true }); }} />
    </div>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; display: grid; place-items: center; background: var(--scrim); z-index: 50; }
  .card { width: min(460px, calc(100vw - 32px)); border-radius: var(--radius-card); padding: 18px 20px 16px;
    max-height: calc(100vh - 24px); overflow: auto; box-sizing: border-box; }
  h2 { margin: 0 0 8px; font: 600 16px/1.3 var(--font-display); }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 4px 10px; margin: 0 0 8px; font-size: 13px; }
  dt { color: var(--text-muted); }
  dd { margin: 0; overflow-wrap: anywhere; }
  .label { margin: 0 0 4px; color: var(--text-muted); font-size: 12.5px; }
  .purpose { margin: 0; padding: 8px 10px; border-radius: 8px; background: var(--group); border: 1px solid var(--separator);
    font: 12.5px/1.4 ui-monospace, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere;
    max-height: 120px; overflow: auto; user-select: text; }
  .note { margin: 8px 0 0; color: var(--text-muted); font-size: 12.5px; }
  .note.warn { color: var(--text); }
  .secrets { margin: 0 0 8px; padding: 6px 10px 6px 26px; border-radius: 8px; background: var(--group);
    border: 1px solid var(--separator); font: 12.5px/1.45 ui-monospace, Consolas, monospace; overflow-wrap: anywhere;
    max-height: 120px; overflow: auto; }
  .purpose + .label { margin-top: 8px; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }
</style>
