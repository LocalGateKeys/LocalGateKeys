import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import { tick } from 'svelte';
import EmergencyKit from './EmergencyKit.svelte';
import HeirSheet from './HeirSheet.svelte';
import kitSource from './EmergencyKit.svelte?raw';
import sheetSource from './HeirSheet.svelte?raw';
import { PRINT_PORTAL_CLASS } from '../lib/printPage.js';

// Sub-plan 08 review R1: component CSS is bundled whether or not the component is mounted, so each printable
// page's "hide everything else" rule must spare every print portal, or the kit and the shard sheet blank
// each other once both are in the app.
const FACTS = { profile: 'Alex', vault_path: 'C:\\v.json', backup_folders: [], created: '2026-11-03', app_version: '1' };
const SHEET = { owner: '', plan_id: 'p', k: 2, n: 2, wait_days: 7, created: '2026-11-03',
  pages: [{ holder: 'A', index: 1, package_id: 'a', qr_size: 3, qr_path: 'M0 0h1v1h-1z' },
    { holder: 'B', index: 2, package_id: 'b', qr_size: 3, qr_path: 'M0 0h1v1h-1z' }] };

const hideRules = (source) => [...source.matchAll(/:global\((body > :not\([^)]*\))\)\s*\{\s*display:\s*none/g)]
  .map((m) => m[1]);
const frames = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())));

afterEach(() => {
  vi.restoreAllMocks();
  document.querySelectorAll(`.${PRINT_PORTAL_CLASS}`).forEach((n) => n.remove());
});

describe('print portals', () => {
  it('neither page\'s print rule hides the other page', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => {});
    render(EmergencyKit, { facts: FACTS, words: null, ondone: () => {} });
    render(HeirSheet, { sheet: SHEET, ondone: () => {} });
    await tick(); await frames(); await tick();
    const kit = document.querySelector('.kit-portal');
    const sheet = document.querySelector('.sheet-portal');
    expect(kit.parentElement).toBe(document.body);
    expect(sheet.parentElement).toBe(document.body);
    const rules = [...hideRules(kitSource), ...hideRules(sheetSource)];
    expect(rules).toHaveLength(2);
    for (const selector of rules) {
      const hidden = [...document.querySelectorAll(selector)];
      expect(hidden).not.toContain(kit);
      expect(hidden).not.toContain(sheet);
      expect(hidden.length).toBeGreaterThan(0); // the app itself is still hidden
    }
  });
});
