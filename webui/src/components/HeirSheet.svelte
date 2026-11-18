<script>
  /** The printable emergency-access shard sheet, one page per holder (`heir.sheet_facts`). It prints like the
   *  emergency kit: HTML drawn by the browser with system fonts, so Greek and every other script print as typed.
   *  The QR code is SVG path data from Python (no markup is injected). Mounting prints; `ondone` reports the end. */
  import { onMount } from 'svelte';
  import { formatDate, formatNumber, t } from '../lib/i18n.svelte.js';
  import { portal, printWhenPainted } from '../lib/printPage.js';

  let { sheet, ondone } = $props();

  const date = $derived(formatDate(new Date(`${sheet.created}T12:00:00`), { dateStyle: 'long' }));
  const steps = ['heirSheet.step1', 'heirSheet.step2', 'heirSheet.step3', 'heirSheet.step4'];

  onMount(() => printWhenPainted(ondone));
</script>

<div class="sheet-portal print-portal" use:portal aria-hidden="true">
  {#each sheet.pages as page (page.index)}
    <article class="sheet" data-testid="heir-page">
      <h1>{t('heirSheet.title')}</h1>
      <p class="for"><span>{t('heirSheet.for')}</span> <strong data-testid="heir-holder">{page.holder}</strong></p>
      <dl class="facts">
        <dt>{t('heirSheet.shard')}</dt><dd>{formatNumber(page.index)} / {formatNumber(sheet.n)}</dd>
        <dt>{t('heirSheet.needed')}</dt><dd>{formatNumber(sheet.k)}</dd>
        <dt>{t('heirSheet.waitDays')}</dt><dd>{formatNumber(sheet.wait_days)}</dd>
        <dt>{t('heirSheet.owner')}</dt><dd>{sheet.owner || '–'}</dd>
        <dt>{t('heirSheet.plan')}</dt><dd class="id">{sheet.plan_id}</dd>
        <dt>{t('heirSheet.created')}</dt><dd>{date}</dd>
      </dl>
      <svg class="qr" viewBox="0 0 {page.qr_size} {page.qr_size}" shape-rendering="crispEdges" role="img"
           aria-label={t('heirSheet.title')}>
        <rect width={page.qr_size} height={page.qr_size} fill="#fff" />
        <path d={page.qr_path} fill="#000" />
      </svg>
      <ol class="steps">
        {#each steps as key (key)}<li>{t(key)}</li>{/each}
      </ol>
      <p class="warning">{t('heir.collusionWarning')}</p>
      <p class="id small">{page.package_id}</p>
    </article>
  {/each}
</div>

<style>
  .sheet-portal { display: none; }
  @media print {
    :global(body > :not(.print-portal)) { display: none !important; }
    :global(html), :global(body) { background: #fff !important; margin: 0; }
    .sheet-portal { display: block !important; }
    .sheet { color: #000; background: #fff; font: 11pt/1.4 system-ui, 'Segoe UI', sans-serif; overflow-wrap: anywhere; }
    .sheet + .sheet { break-before: page; }
    h1 { font-size: 18pt; margin: 0 0 8pt; }
    .for { font-size: 13pt; margin: 0 0 8pt; }
    .for strong { font-size: 16pt; }
    .facts { display: grid; grid-template-columns: max-content 1fr; gap: 3pt 12pt; margin: 0; }
    .facts dt { font-weight: 600; }
    .facts dd { margin: 0; }
    .id { font: 9pt ui-monospace, Consolas, monospace; }
    .qr { display: block; width: 95mm; height: 95mm; margin: 10pt auto; }
    .steps { margin: 0; padding-left: 18pt; }
    .steps li { margin: 0 0 3pt; }
    .warning { margin: 10pt 0 0; padding: 6pt 8pt; border: 1.5pt solid #000; font-weight: 600; }
    .small { margin: 8pt 0 0; font-size: 7pt; }
    @page { margin: 14mm; }
  }
</style>
