<script>
  /** The show-once recovery phrase card: the 24 words, then three of them retyped to confirm.
   *  Used after creating or replacing a phrase, and after removing camera verification replaced it. */
  import { untrack } from 'svelte';
  import ErrorLogLink from './ErrorLogLink.svelte';
  import { call } from '../lib/api.js';
  import { formatNumber, t } from '../lib/i18n.svelte.js';
  import Button from './Button.svelte';

  let { card, ondone } = $props();
  // The parent keys this component by card.token, so the first card is the only one it sees.
  let answers = $state(untrack(() => card.positions.map(() => '')));
  let cardError = $state('');

  async function confirmPhrase() {
    const result = await call('phrase_confirm', card.token, answers);
    if (!result.ok) { cardError = result.error.message; return; }
    if (!result.confirmed) { cardError = result.message; return; }
    answers = [];
    ondone(result.message);
  }

  async function closeCard() {
    const result = await call('phrase_close', card.token);
    answers = [];
    ondone(result.ok ? result.message : '');
  }
</script>

<section class="card group" aria-label={t('phraseCard.title')}>
  <h3>{t('phraseCard.title')}</h3>
  <p class="note">{card.intro}</p>
  <ol class="words">
    {#each card.words as word, i (i)}<li><span class="n">{String(i + 1).padStart(2, '0')}.</span> {word}</li>{/each}
  </ol>
  <p class="note">{t('phraseCard.confirmPrompt')}</p>
  <div class="challenge">
    {#each card.positions as pos, i (pos)}
      <label>{t('phraseCard.word', { number: formatNumber(pos) })}<input autocomplete="off" spellcheck="false" bind:value={answers[i]} /></label>
    {/each}
  </div>
  {#if cardError}<p class="error" role="alert">{cardError}<ErrorLogLink text={cardError} /></p>{/if}
  <footer>
    <Button label={t('phraseCard.closeWithout')} onclick={closeCard} />
    <Button label={t('common.confirm')} variant="primary" onclick={confirmPhrase} />
  </footer>
</section>

<style>
  h3 { margin: 0 0 4px; font: 600 15px var(--font-display); }
  .note { color: var(--text-muted); font-size: 12.5px; }
  .card { padding: 14px; display: grid; gap: 8px; }
  .words { columns: 3; list-style: none; padding: 0; margin: 4px 0; font: 500 14px ui-monospace, monospace; user-select: text; }
  .words li { padding: 3px 0; }
  .n { color: var(--text-faint); }
  .challenge { display: flex; gap: 10px; }
  .challenge label { display: grid; gap: 4px; font-size: 12.5px; color: var(--text-muted); }
  .challenge input { background: var(--group); border: 1px solid var(--separator); border-radius: 8px; padding: 6px 8px; color: var(--text); }
  .error { color: var(--danger); margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: 8px; }
</style>
