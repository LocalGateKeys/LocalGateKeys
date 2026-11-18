import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Run from webui/ (vitest's root); CSS imports are stubbed in tests, so read the file itself.
const css = readFileSync(resolve(process.cwd(), 'src/styles/tokens.css'), 'utf8');

describe('tokens.css', () => {
  it('keeps the open <select> list readable in the dark theme (regressed twice)', () => {
    expect(css).toMatch(/:root\s*\{[^}]*color-scheme:\s*dark/);
    expect(css).toMatch(/select option[^{]*\{[^}]*color:\s*var\(--text\)[^}]*background-color:\s*var\(--wash-base-opaque\)/);
  });
});
