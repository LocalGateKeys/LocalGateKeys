import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import { logoFor, glyphFor, isLight } from './siteLogos.js';
import ItemTile from '../components/ItemTile.svelte';

describe('logoFor', () => {
  it('matches a listed domain and its subdomains', () => {
    expect(logoFor('https://github.com')?.slug).toBe('github');
    expect(logoFor('https://accounts.google.com')?.slug).toBe('google');
    expect(logoFor('https://www.netflix.com:443/')?.slug).toBe('netflix');
  });

  it('prefers the most specific listed domain', () => {
    expect(logoFor('https://mail.google.com')?.slug).toBe('gmail');
  });

  it('never gives a lookalike host the brand logo', () => {
    expect(logoFor('https://google.com.example.net')).toBeNull();
    expect(logoFor('https://evilgoogle.com')).toBeNull();
    expect(logoFor('https://192.168.1.1')).toBeNull();
    expect(logoFor('not a url')).toBeNull();
    expect(logoFor('')).toBeNull();
  });

  it('flags light brand colours for a dark glyph', () => {
    expect(isLight('#FFFC00')).toBe(true);
    expect(isLight('#181717')).toBe(false);
  });
});

describe('ItemTile', () => {
  it('draws the bundled logo for a known site', () => {
    const { container } = render(ItemTile, { kind: 'web', origin: 'https://github.com' });
    expect(container.querySelector('[data-logo="github"] path')).not.toBeNull();
  });

  it('prefers the item\'s own icon over the logo', () => {
    const { container } = render(ItemTile, { kind: 'web', origin: 'https://github.com', icon: 'data:image/png;base64,AA==' });
    expect(container.querySelector('img')).not.toBeNull();
    expect(container.querySelector('[data-logo]')).toBeNull();
  });

  it('falls back to the kind glyph, never a letter', () => {
    const { container } = render(ItemTile, { kind: 'wifi', origin: null });
    const tile = container.querySelector('[data-kind="wifi"]');
    expect(tile.querySelector('path').getAttribute('d')).toBe(glyphFor('wifi').path);
    expect(tile.textContent.trim()).toBe('');
  });

  it('has a glyph for unknown kinds', () => {
    expect(glyphFor('something_new').path).toBe(glyphFor('document').path);
  });
});
