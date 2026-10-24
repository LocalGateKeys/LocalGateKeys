<script>
  /** Live camera check: a round preview with a progress ring, driven by face.status / face.frame events.
   *  Frames exist only in this page's memory; nothing is saved. */
  import { call, on } from '../lib/api.js';
  import Button from './Button.svelte';

  let { title = 'Camera verification', mode = 'verify' } = $props();
  let image = $state('');
  let status = $state('Starting camera…');
  let detail = $state('Nothing is uploaded. No photo or video is saved.');
  let progress = $state(0);
  let phase = $state('running');

  const R = 132;
  const C = 2 * Math.PI * R;

  $effect(() => {
    const offs = [
      on('face.status', (d) => { status = d.status; detail = d.detail; progress = d.progress; phase = d.state; }),
      on('face.frame', (d) => { image = d.image; progress = d.progress; }),
    ];
    return () => { offs.forEach((off) => off()); image = ''; };
  });
</script>

<div class="scrim">
  <div class="card glass" role="dialog" aria-modal="true" aria-label={title}>
    <h2>{title}</h2>
    <p class="hint">{mode === 'verify' ? 'Look at the camera.' : 'Look at the camera and slowly move your head a little in a circle.'}</p>
    <div class="preview">
      <svg viewBox="0 0 280 280" aria-hidden="true">
        <circle cx="140" cy="140" r={R} class="track" />
        <circle cx="140" cy="140" r={R} class="ring" class:done={phase === 'success'}
          stroke-dasharray={C} stroke-dashoffset={C * (1 - (phase === 'success' ? 1 : progress))} />
      </svg>
      {#if image}<img src={image} alt="" />{/if}
    </div>
    <p class="status" role="status">{status}</p>
    <p class="detail">{detail}</p>
    <footer>
      <Button label="Try another camera" onclick={() => call('face_switch_camera')} disabled={phase !== 'running'} />
      <Button label="Cancel" onclick={() => call('face_cancel')} />
    </footer>
  </div>
</div>

<style>
  .scrim { position: fixed; inset: 0; z-index: 60; background: var(--scrim); display: grid; place-items: center; }
  .card { width: min(440px, calc(100% - 32px)); border-radius: 20px; padding: 20px; display: grid; justify-items: center; gap: 6px;
    background: color-mix(in srgb, var(--wash-base-opaque) 92%, transparent); }
  h2 { margin: 0; font: 600 18px var(--font-display); }
  .hint, .detail { margin: 0; color: var(--text-muted); text-align: center; font-size: 12.5px; }
  .preview { position: relative; width: 280px; height: 280px; margin: 8px 0; }
  svg { position: absolute; inset: 0; transform: rotate(-90deg); }
  .track { fill: none; stroke: #3A4656; stroke-width: 8; }
  .ring { fill: none; stroke: #34C759; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 0.2s; }
  img { position: absolute; inset: 14px; width: 252px; height: 252px; border-radius: 50%; object-fit: cover; }
  .status { margin: 4px 0 0; font-weight: 600; text-align: center; }
  footer { display: flex; justify-content: space-between; width: 100%; margin-top: 8px; }
</style>
