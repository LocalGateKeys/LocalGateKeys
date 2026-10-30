// UX plan workstream 13: an automated accessibility audit (axe-core) of the main screens, and text
// contrast of the colour tokens in both themes (4.5:1), measured over the opaque wash the glass sits on.
import { afterEach, describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import { readFileSync } from 'node:fs';
import axe from 'axe-core';
import Home from './Home.svelte';
import Unlock from './Unlock.svelte';
import { LOCKED, UNLOCKED, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

// jsdom has no layout or colours: contrast is checked from the tokens below instead.
const OPTIONS = { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } };

async function audit(container) {
  const result = await axe.run(container, OPTIONS);
  return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
}

describe('axe audit', () => {
  it('home screen has no violations', async () => {
    fakeApi({ sync_status: async () => ({ ok: true, state: 'ok', colour: 'green', text: 'Synced just now · 2 devices', devices: [] }) });
    const { container } = render(Home, { vault: UNLOCKED });
    await screen.findByText('Alpha');
    await screen.findByRole('button', { name: /Sync status/ });
    expect(await audit(container)).toEqual([]);
  });

  it('unlock screen has no violations', async () => {
    fakeApi();
    const { container } = render(Unlock, { vault: LOCKED });
    await new Promise((r) => setTimeout(r, 0));
    expect(await audit(container)).toEqual([]);
  });
});

// ----------------------------------------------------------------- contrast
const css = readFileSync('src/styles/tokens.css', 'utf8'); // vitest runs from webui/

function block(selector) {
  const start = css.indexOf(selector);
  const open = css.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === '{') depth++;
    if (css[i] === '}' && --depth === 0) return css.slice(open + 1, i);
  }
  return '';
}
function tokens(text) {
  const out = {};
  for (const m of text.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}
function rgba(value) {
  if (value.startsWith('#')) return [1, 3, 5].map((i) => parseInt(value.slice(i, i + 2), 16)).concat(1);
  const m = value.match(/rgba?\(([^)]+)\)/);
  const parts = m[1].split(',').map((p) => parseFloat(p));
  return [parts[0], parts[1], parts[2], parts[3] ?? 1];
}
function over([r, g, b, a], [br, bg, bb]) { return [r * a + br * (1 - a), g * a + bg * (1 - a), b * a + bb * (1 - a)]; }
function luminance(rgb) {
  const [r, g, b] = rgb.map((v) => { const c = v / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a, b) { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); }

const dark = tokens(block(':root {'));
const light = { ...dark, ...tokens(block(':root[data-theme="light"]')) };
const TEXT = ['text', 'text-muted', 'text-faint', 'link', 'danger', 'success', 'warning'];

describe('token contrast', () => {
  for (const [name, theme] of [['dark', dark], ['light', light]]) {
    it(`${name}: text tokens reach 4.5:1 on the window background`, () => {
      const bg = rgba(theme['wash-base-opaque']).slice(0, 3);
      const low = TEXT.map((t) => [t, ratio(over(rgba(theme[t]), bg), bg)]).filter(([, r]) => r < 4.5)
        .map(([t, r]) => `${t} ${r.toFixed(2)}`);
      expect(low).toEqual([]);
    });
    it(`${name}: white on the accent reaches 4.5:1`, () => {
      expect(ratio([255, 255, 255], rgba(theme.accent).slice(0, 3))).toBeGreaterThanOrEqual(4.5);
    });
  }
});
