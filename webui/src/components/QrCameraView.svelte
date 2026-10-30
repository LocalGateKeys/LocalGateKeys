<script>
  /** Live camera preview while a 2FA QR code is read, driven by qr.status / qr.frame events.
   *  Frames exist only in this page's memory; nothing is saved. */
  import { t } from '../lib/i18n.svelte.js';
  import { call, on } from '../lib/api.js';
  import Button from './Button.svelte';

  let image = $state('');
  let status = $state(t('cameraView.starting'));
  let detail = $state(t('cameraView.noUpload'));
  let phase = $state('running');

  $effect(() => {
    const offs = [
      on('qr.status', (d) => { status = d.status; detail = d.detail; phase = d.state; }),
      on('qr.frame', (d) => { image = d.image; }),
    ];
    return () => { offs.forEach((off) => off()); image = ''; };
  });
</script>

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-label={t('cameraView.qrTitle')}>
    <h2>{t('cameraView.qrTitle')}</h2>
    <div class="preview">
      {#if image}<img src={image} alt="" />{/if}
      <span class="frame" aria-hidden="true"></span>
    </div>
    <p class="status" role="status">{status}</p>
    <p class="detail">{detail}</p>
    <footer>
      <Button label={t('cameraView.tryAnother')} onclick={() => call('qr_switch_camera')} disabled={phase !== 'running'} />
      <Button label={t('common.cancel')} onclick={() => call('qr_cancel')} />
    </footer>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 60; background: var(--scrim); display: grid; place-items: center; }
  .card { width: min(440px, calc(100% - 32px)); border-radius: 20px; padding: 20px; display: grid; justify-items: center; gap: 6px;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .preview { position: relative; width: 360px; max-width: 100%; aspect-ratio: 16 / 9; margin: 8px 0; border-radius: 14px;
    overflow: hidden; background: #0B0F14; }
  img { width: 100%; height: 100%; object-fit: cover; }
  .frame { position: absolute; inset: 14% 30%; border: 3px solid #34C759; border-radius: 12px; }
  .status { margin: 4px 0 0; font-weight: 600; text-align: center; }
  .detail { margin: 0; color: var(--text-muted); text-align: center; font-size: 12.5px; }
  footer { display: flex; justify-content: space-between; width: 100%; margin-top: 8px; }
</style>
