<script>
  /** The printable emergency kit. Mounting it renders the page, opens the system print dialog (which offers
   *  "Microsoft Print to PDF"), then reports `ondone` (on `afterprint`, or a long fallback timer) so the parent unmounts it and the page is gone again.
   *  `words` is the recovery phrase the screen that just showed it still holds, or null for 24 blank boxes;
   *  it is only ever drawn here, never sent back to Python, stored or logged. */
  import { onMount, untrack } from 'svelte';
  import { formatDate, formatNumber, t } from '../lib/i18n.svelte.js';
  import { portal, printWhenPainted } from '../lib/printPage.js';

  let { facts, words = null, ondone } = $props();

  // The words are held here only while the kit exists; the cleanup below blanks them.
  let held = $state.raw(untrack(() => words));
  const boxes = $derived(Array.from({ length: 24 }, (_, i) => (Array.isArray(held) ? String(held[i] ?? '') : '')));
  const date = $derived(formatDate(new Date(`${facts.created}T12:00:00`), { dateStyle: 'long' }));
  const steps = ['kit.step1', 'kit.step2', 'kit.step3', 'kit.step4', 'kit.step5'];

  onMount(() => {
    const stop = printWhenPainted(ondone);
    return () => {
      stop();
      held = null;
    };
  });
</script>

<div class="kit-portal print-portal" use:portal aria-hidden="true">
  <article class="kit">
    <h1>{t('kit.title')}</h1>
    <p class="intro">{t('kit.intro')}</p>
    <dl class="facts">
      <dt>{t('kit.profile')}</dt><dd>{facts.profile}</dd>
      <dt>{t('kit.date')}</dt><dd>{date}</dd>
      <dt>{t('kit.version')}</dt><dd>{facts.app_version}</dd>
      <dt>{t('kit.vaultPath')}</dt><dd class="path">{facts.vault_path}</dd>
      <dt>{t('kit.backupFolders')}</dt>
      <dd class="path">{#each facts.backup_folders as folder, i (i)}<div>{folder}</div>{/each}</dd>
    </dl>
    <p class="master"><span>{t('kit.master')}</span><span class="line"></span></p>
    <h2>{t('kit.phraseHeading')}</h2>
    <ol class="boxes">
      {#each boxes as word, i (i)}
        <li class="box" data-testid="kit-box"><span class="n">{formatNumber(i + 1)}</span><span class="w" data-word>{word}</span></li>
      {/each}
    </ol>
    <h2>{t('kit.stepsHeading')}</h2>
    <ol class="steps">
      {#each steps as key (key)}<li>{t(key)}</li>{/each}
    </ol>
    <p class="warning">{t('kit.warning')}</p>
  </article>
  {#if Array.isArray(facts.heir_holders) && facts.heir_holders.length}
    <!-- Emergency access: who holds a shard, by nickname only (never the shards themselves). -->
    <article class="kit holders" data-testid="kit-holders">
      <h1>{t('kit.heirHeading')}</h1>
      <p class="intro">{t('kit.heirIntro')}</p>
      <ol class="steps">
        {#each facts.heir_holders as name, i (i)}<li>{name}</li>{/each}
      </ol>
    </article>
  {/if}
</div>

<style>
  .kit-portal { display: none; }
  @media print {
    :global(body > :not(.print-portal)) { display: none !important; }
    :global(html), :global(body) { background: #fff !important; margin: 0; }
    .kit-portal { display: block !important; }
    .kit { color: #000; background: #fff; font: 11pt/1.4 system-ui, 'Segoe UI', sans-serif; padding: 0; overflow-wrap: anywhere; }
    h1 { font-size: 20pt; margin: 0 0 4pt; }
    h2 { font-size: 13pt; margin: 14pt 0 6pt; break-after: avoid; }
    .intro { margin: 0 0 10pt; }
    .facts { display: grid; grid-template-columns: max-content 1fr; gap: 3pt 12pt; margin: 0; }
    .facts dt { font-weight: 600; }
    .facts dd { margin: 0; }
    .path { font: 10pt ui-monospace, Consolas, monospace; }
    .master { display: flex; gap: 10pt; align-items: flex-end; margin: 14pt 0 0; }
    .line { flex: 1; min-width: 60pt; border-bottom: 1pt solid #000; height: 16pt; }
    .boxes { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(4, 1fr); gap: 5pt; break-inside: avoid; }
    .box { border: 1pt solid #000; border-radius: 3pt; min-height: 24pt; padding: 3pt 5pt; display: flex; gap: 5pt; align-items: baseline; }
    .n { font-size: 8pt; min-width: 14pt; }
    .w { font: 11pt ui-monospace, Consolas, monospace; }
    .steps { margin: 0; padding-left: 18pt; }
    .steps li { margin: 0 0 3pt; }
    .holders { break-before: page; }
    .warning { margin: 12pt 0 0; padding: 6pt 8pt; border: 1.5pt solid #000; font-weight: 600; }
    @page { margin: 14mm; }
  }
</style>
