import { describe, expect, it } from 'vitest';
import overviewSource from './Overview.svelte?raw';
import networkSource from './NetworkActivityPanel.svelte?raw';
import homeSource from '../screens/Home.svelte?raw';

// Found 2026-11-14 in the screenshot harness at the 900x600 minimum window in en-XA (jsdom has no layout,
// so these pin the CSS that keeps long words inside their box).
const rule = (source, selector) => source.match(new RegExp(`\\n\\s*${selector.replace('.', '\\.')} \\{([^}]*)\\}`))?.[1] ?? '';

describe('narrow window text wrapping', () => {
  it('overview boxes give their one column a zero minimum so a long title cannot widen it past the box', () => {
    expect(rule(overviewSource, '.card')).toMatch(/grid-template-columns:\s*minmax\(0,\s*1fr\)/);
  });

  it('the Network activity intro breaks long words instead of running out of the panel', () => {
    expect(rule(networkSource, '.text')).toMatch(/overflow-wrap:\s*anywhere/);
  });

  it('the three home columns fit the page of a 900 px minimum window (about 884 px inside the frame)', () => {
    const home = rule(homeSource, '.home');
    const columns = home.match(/grid-template-columns:\s*([^;]+);/)[1];
    const mins = [...columns.matchAll(/(?:minmax\()?(\d+)px/g)].map((m) => Number(m[1]));
    const gap = Number(home.match(/gap:\s*(\d+)px/)[1]);
    const pad = Number(home.match(/padding:\s*\d+px\s+(\d+)px/)[1]);
    expect(mins).toHaveLength(3);
    expect(mins.reduce((a, b) => a + b, 0) + 2 * gap + 2 * pad).toBeLessThanOrEqual(884);
  });
});
