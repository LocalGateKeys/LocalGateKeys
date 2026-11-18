<script>
  /** Privacy proof: facts read from this device, the claims that have a guard test, the measured connections, and an
   *  export signed with the sync device key (unsigned while sync is off). */
  import { call } from '../lib/api.js';
  import { formatDate, t } from '../lib/i18n.svelte.js';
  import { privacyFacts } from '../lib/featurePack.js';
  import { okOrToast, toast } from '../lib/toast.js';
  import Button from './Button.svelte';

  let { onclose } = $props();
  let data = $state(null);
  let exported = $state(null);

  async function load() {
    const result = await call('privacy_proof_get');
    if (okOrToast(result)) data = result;
  }
  $effect(() => { load(); });

  async function exportProof() {
    const result = await call('privacy_proof_export');
    if (!okOrToast(result)) return;
    exported = result;
    toast(t('privacy.exported', { file: result.file_name }));
  }

  const network = $derived(data?.document?.network ?? null);
  const facts = $derived(privacyFacts(data?.document?.facts));
  function when(at) {
    const date = new Date(at);
    return Number.isNaN(date.getTime()) ? at : formatDate(date, { dateStyle: 'medium', timeStyle: 'short' });
  }
  const PURPOSES = ['update_check', 'revocation_list', 'breach_range', 'website_icon', 'lan_sync'];
  const purpose = (id) => (PURPOSES.includes(id) ? t(`securityPage.network.purpose.${id}`) : id);
</script>

<div class="sheet glass" role="dialog" aria-label={t('privacy.title')}>
  <header>
    <h2>{t('privacy.title')}</h2>
    <Button label={t('privacy.export')} variant="primary" onclick={exportProof} />
    <button class="close" aria-label={t('common.close')} onclick={onclose}>✕</button>
  </header>
  <p class="meta">{t('privacy.intro')}</p>
  {#if data}
    <div class="body">
      {#if exported}<p class="note" role="status">{t('privacy.verifyHint', { file: exported.file_name })}</p>{/if}

      <div class="section-label">{t('privacy.facts')}</div>
      <div class="group">
        {#each facts as fact (fact.label)}
          <div class="row"><span class="k">{fact.label}</span><span>{fact.value}</span></div>
        {/each}
      </div>

      {#if data.claims?.length}
        <div class="section-label">{t('privacy.claims')}</div>
        <ul class="group claims">
          {#each data.claims as claim (claim.id)}<li>{claim.text}</li>{/each}
        </ul>
      {/if}

      <div class="section-label">{t('privacy.network')}</div>
      <div class="group">
        {#if !network?.available}
          <div class="row"><span class="meta">{t('privacy.noListYet')}</span></div>
        {:else}
          {#each network.entries ?? [] as entry, i (i)}
            <div class="row entry" data-testid="proof-entry">
              <span class="meta when">{when(entry.at)}</span>
              <span class="what">{purpose(entry.purpose)}</span>
              <span class="host">{entry.host}</span>
              <span class="meta">{entry.result}</span>
            </div>
          {/each}
          {#each Object.entries(network.counts ?? {}) as [id, count] (id)}
            <div class="row"><span class="meta">{t('privacy.counts', { count, purpose: purpose(id) })}</span></div>
          {/each}
        {/if}
      </div>

      <div class="section-label">{data.signed ? t('privacy.signedBy', { fingerprint: data.fingerprint ?? '' }) : t('privacy.unsigned')}</div>
      <p class="meta">{t('privacy.signatureMeans')}</p>
    </div>
  {/if}
</div>

<style>
  .sheet { position: absolute; inset: 10px; z-index: 30; border-radius: 18px; padding: 16px 18px; display: flex; flex-direction: column;
    background: color-mix(in srgb, var(--wash-base-opaque) 90%, transparent); }
  header { display: flex; align-items: center; gap: 8px; }
  h2 { margin: 0; flex: 1; font: 600 18px var(--font-display); }
  .close { background: none; border: none; color: var(--text-muted); cursor: pointer; }
  .body { overflow-y: auto; flex: 1; min-height: 0; }
  .section-label { margin: 14px 0 6px; font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; overflow-wrap: anywhere; }
  .row { display: flex; align-items: center; gap: 10px; padding: 8px 14px; }
  .row + .row { border-top: 1px solid var(--separator); }
  .k { flex: 1; color: var(--text-muted); }
  .meta { color: var(--text-muted); font-size: 12.5px; }
  .note { margin: 8px 0 0; user-select: text; font-family: var(--font-mono); font-size: 12px; }
  .claims { margin: 0; padding: 8px 14px 8px 32px; display: grid; gap: 4px; }
  .entry { font-size: 13px; }
  .when { flex: 0 0 160px; }
  .what { flex: 0 0 170px; }
  .host { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
