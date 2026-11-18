import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import cases from '../../../tests/vectors/markdown/cases.json';
import { parseMarkdown } from './markdown.js';
import MarkdownView from '../components/MarkdownView.svelte';
import DetailPane from '../components/DetailPane.svelte';
import { ALPHA, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

describe('parseMarkdown vectors', () => {
  it('has the documented cases', () => {
    const names = cases.map((c) => c.name);
    for (const name of ['heading_levels', 'bold_italic_nested', 'inline_code_keeps_stars', 'fenced_block_verbatim',
      'bullets_and_numbers', 'checklist', 'rule', 'blank_lines_split_paragraphs', 'html_is_text',
      'javascript_link_is_text', 'unclosed_bold_is_text', 'crlf_input', 'max_20000_chars']) {
      expect(names).toContain(name);
    }
  });

  for (const c of cases) {
    it(c.name, () => expect(parseMarkdown(c.input)).toEqual(c.nodes));
  }

  it('stays fast on pathological input', () => {
    const inputs = ['*a '.repeat(6666), '**a '.repeat(5000), '*a\n'.repeat(6666), '*[a](b '.repeat(2857),
      '*a '.repeat(6600) + 'a*', '[a]('.repeat(5000), '['.repeat(19999), '[a**'.repeat(4000)];
    for (const input of inputs) {
      const started = performance.now();
      parseMarkdown(input);
      expect(performance.now() - started).toBeLessThan(100);
    }
  });
});

describe('MarkdownView', () => {
  it('renders markup as text, never as elements', () => {
    const text = '<script>window.hacked = 1</script> **b**\n\n[x](javascript:alert(1))';
    const { container } = render(MarkdownView, { nodes: parseMarkdown(text) });
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('a')).toBeNull();
    expect(container.textContent).toContain('<script>window.hacked = 1</script>');
    expect(container.textContent).toContain('x (javascript:alert(1))');
    expect(container.querySelector('strong').textContent).toBe('b');
  });

  it('renders every block type', () => {
    const text = '# T\n\n- a\n\n1. b\n\n- [x] c\n\n```\ncode\n```\n\n---\n\n*i* `k`';
    const { container } = render(MarkdownView, { nodes: parseMarkdown(text) });
    expect(container.querySelector('h1').textContent).toBe('T');
    expect(container.querySelector('ul li').textContent).toContain('a');
    expect(container.querySelector('ol li').textContent).toContain('b');
    expect(container.querySelector('input[type=checkbox]').checked).toBe(true);
    expect(container.querySelector('pre').textContent).toBe('code');
    expect(container.querySelector('hr')).not.toBeNull();
    expect(container.querySelector('em').textContent).toBe('i');
    expect(container.querySelector('code').textContent).toBe('k');
  });
});

describe('DetailPane formatting switch', () => {
  const detail = (notes) => ({ ok: true, kind: 'web', title: 'Alpha', subtitle: '', username: 'ann', has_password: true,
    has_totp: false, strict: false, notes, tags: [], target: '', origin: null, favorite: false, actions: ['edit'] });

  it('formats login notes, and the switch shows the raw pre-wrap text', async () => {
    const api = fakeApi({ item_detail: vi.fn().mockResolvedValue(detail('# Title\n**bold** <script>x</script>')) });
    const { container } = render(DetailPane, { selected: ALPHA.ref });
    expect(await screen.findByRole('heading', { name: 'Title' })).toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull();
    await fireEvent.click(screen.getByRole('checkbox', { name: 'Show formatting' }));
    await waitFor(() => expect(api.notes_formatting_set).toHaveBeenCalledWith(false));
    const raw = await screen.findByText(/# Title/);
    expect(raw).toHaveClass('notes');
    expect(raw.textContent).toBe('# Title\n**bold** <script>x</script>');
    expect(container.querySelector('h1')).toBeNull();
  });

  it('starts raw when the device setting is off', async () => {
    fakeApi({ item_detail: vi.fn().mockResolvedValue(detail('**bold**')), notes_formatting_get: vi.fn().mockResolvedValue({ ok: true, enabled: false }) });
    const { container } = render(DetailPane, { selected: ALPHA.ref });
    expect(await screen.findByText('**bold**')).toHaveClass('notes');
    await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Show formatting' }).checked).toBe(false));
    expect(container.querySelector('strong')).toBeNull();
  });

  it('formats a note body only after reveal', async () => {
    fakeApi({ typed_detail: vi.fn().mockResolvedValue({ ok: true, kind: 'note', title: 'Router', subtitle: 'Secure note',
      fields: [{ name: 'body', label: 'Note body', value: null, protected: true, present: true }], tags: [], favorite: false }),
      typed_reveal: vi.fn().mockResolvedValue({ ok: true, value: '## Wifi\n- one', mask_after: 30 }) });
    const { container } = render(DetailPane, { selected: { source: 'typed', id: 'n1', kind: 'note' } });
    expect(await screen.findByText('••••••••••••')).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'Show formatting' })).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Reveal body' }));
    expect(await screen.findByRole('heading', { name: 'Wifi' })).toBeInTheDocument();
    expect(container.querySelector('ul li').textContent).toContain('one');
  });
});
