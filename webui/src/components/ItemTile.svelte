<script>
  /** An item's tile: its own icon (captured site icon, desktop app icon), else the bundled site logo for
   *  its origin, else a glyph for its kind. */
  import { logoFor, glyphFor } from '../lib/siteLogos.js';

  let { kind, origin = null, icon = null, size = 26 } = $props();

  const logo = $derived(icon || !origin ? null : logoFor(origin));
  const glyph = $derived(glyphFor(kind));
</script>

{#if icon}
  <img class="tile" src={icon} alt="" style:--size="{size}px" />
{:else if logo}
  <span class="tile" style:--size="{size}px" style:background={logo.hex} title={logo.title} aria-hidden="true" data-logo={logo.slug}>
    <svg viewBox="0 0 24 24"><path d={logo.path} fill={logo.light ? '#111' : '#fff'} /></svg>
  </span>
{:else}
  <span class="tile glyph tint-{glyph.tint}" style:--size="{size}px" aria-hidden="true" data-kind={kind}>
    <svg viewBox="0 0 24 24"><path d={glyph.path} /></svg>
  </span>
{/if}

<style>
  .tile {
    width: var(--size); height: var(--size); border-radius: calc(var(--size) * 0.27); flex-shrink: 0;
    display: grid; place-items: center; object-fit: cover; box-sizing: border-box;
  }
  .tile svg { width: 60%; height: 60%; display: block; }
  .glyph { color: var(--tint); background: color-mix(in srgb, var(--tint) 16%, transparent); }
  .glyph svg { width: 66%; height: 66%; }
  .glyph path { fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
  .tint-link { --tint: var(--link); }
  .tint-success { --tint: var(--success); }
  .tint-warning { --tint: var(--warning); }
  .tint-identity { --tint: #b9a2ff; }
  /* Same rule as tokens.css: the Windows theme unless the app forces one. */
  @media (prefers-color-scheme: light) { :global(:root:not([data-theme="dark"])) .tint-identity { --tint: #6d4aff; } }
  :global(:root[data-theme="light"]) .tint-identity { --tint: #6d4aff; }
</style>
