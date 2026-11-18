// Desktop UI review 2026-11-15: races, shortcuts over the editor, focus handling, Caps Lock, live generator.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import Home from './Home.svelte';
import DetailPane from '../components/DetailPane.svelte';
import Generator from '../components/Generator.svelte';
import Field from '../components/Field.svelte';
import PasswordModal from '../components/PasswordModal.svelte';
import { ALPHA, UNLOCKED, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; vi.useRealTimers(); });

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

describe('DetailPane reveal race', () => {
  it('drops a reveal reply that arrives after the selection moved on', async () => {
    const pending = deferred();
    const other = { source: 'credential', id: 'b2', kind: 'web' };
    fakeApi({ item_reveal: vi.fn().mockReturnValue(pending.promise) });
    const view = render(DetailPane, { selected: ALPHA.ref });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show' }));
    await view.rerender({ selected: other });
    pending.resolve({ ok: true, password: 'pw-alpha-1234567', mask_after: 30 });
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText('pw-alpha-1234567')).toBeNull();
  });

  it('shows when a revealed password hides again', async () => {
    fakeApi({ item_reveal: vi.fn().mockResolvedValue({ ok: true, password: 'pw-alpha-1234567', mask_after: 30 }) });
    render(DetailPane, { selected: ALPHA.ref });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show' }));
    expect(await screen.findByText('Hides in 30 s')).toBeInTheDocument();
  });
});

describe('Generator', () => {
  it('ignores an older reply that arrives last', async () => {
    const first = deferred();
    const replies = [first.promise];
    fakeApi({
      generator_get: vi.fn().mockResolvedValue({ ok: true, options: { mode: 'password', length: 20, uppercase: true, lowercase: true, digits: true, symbols: true } }),
      generator_generate: vi.fn().mockImplementation(() => replies.shift() ?? Promise.resolve({ ok: true, value: 'x', health: '', options: {} })),
    });
    render(Generator, { onclose: () => {} });
    await waitFor(() => expect(window.pywebview.api.generator_generate).toHaveBeenCalledTimes(1));
    first.resolve({ ok: true, value: 'initial-value', health: '', options: {} });
    await screen.findByText('initial-value');
    // Two quick changes: the older reply comes back last and must not win.
    const a = deferred();
    const b = deferred();
    replies.push(a.promise, b.promise);
    const slider = screen.getByRole('slider');
    await fireEvent.input(slider, { target: { value: '30' } });
    expect(screen.getByText('30')).toBeInTheDocument(); // the label follows the slider at once
    await fireEvent.input(slider, { target: { value: '40' } });
    b.resolve({ ok: true, value: 'newest-value', health: '', options: {} });
    await screen.findByText('newest-value');
    a.resolve({ ok: true, value: 'stale-value', health: '', options: {} });
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText('stale-value')).toBeNull();
    expect(screen.getByText('newest-value')).toBeInTheDocument();
  });
});

describe('Caps Lock warning', () => {
  it('appears on a password field while Caps Lock is on', async () => {
    render(Field, { label: 'Master password', type: 'password' });
    const input = screen.getByLabelText('Master password');
    await fireEvent.keyDown(input, { key: 'A', getModifierState: () => true });
    const event = new KeyboardEvent('keyup', { key: 'A', bubbles: true });
    event.getModifierState = (k) => k === 'CapsLock';
    input.dispatchEvent(event);
    expect(await screen.findByText('Caps Lock is on')).toBeInTheDocument();
    const off = new KeyboardEvent('keyup', { key: 'a', bubbles: true });
    off.getModifierState = () => false;
    input.dispatchEvent(off);
    await waitFor(() => expect(screen.queryByText('Caps Lock is on')).toBeNull());
  });

  it('appears in the re-authentication prompt too', async () => {
    render(PasswordModal, { title: 'Confirm', onanswer: () => {} });
    const input = screen.getByLabelText('Master password');
    const event = new KeyboardEvent('keydown', { key: 'A', bubbles: true });
    event.getModifierState = (k) => k === 'CapsLock';
    input.dispatchEvent(event);
    expect(await screen.findByText('Caps Lock is on')).toBeInTheDocument();
  });
});

describe('Dialog focus', () => {
  it('keeps Tab inside a modal and returns focus to the opener', async () => {
    const opener = document.createElement('button');
    opener.textContent = 'opener';
    document.body.appendChild(opener);
    opener.focus();
    const view = render(PasswordModal, { title: 'Confirm', onanswer: () => {} });
    const input = screen.getByLabelText('Master password');
    await waitFor(() => expect(document.activeElement).toBe(input));
    const confirm = screen.getByRole('button', { name: 'Confirm' });
    confirm.focus();
    await fireEvent.keyDown(document, { key: 'Tab' });
    expect(document.activeElement).toBe(input); // wrapped from the last control to the first
    await fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(confirm);
    view.unmount();
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });
});

describe('Shortcuts over the editor', () => {
  it('Ctrl+N and Ctrl+K do not replace an open editor', async () => {
    fakeApi();
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    await fireEvent.keyDown(window, { key: 'n', ctrlKey: true });
    await fireEvent.click(await screen.findByRole('button', { name: /Website login/ }));
    const editor = await screen.findByRole('dialog', { name: /login/i });
    await fireEvent.keyDown(window, { key: 'n', ctrlKey: true });
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(editor).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Search' })).toBeNull();
  });

  it('Enter in the search box opens the top hit, Esc clears the query', async () => {
    const api = fakeApi();
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    const search = screen.getByRole('searchbox');
    await fireEvent.input(search, { target: { value: 'r' } });
    await fireEvent.keyDown(search, { key: 'Escape' });
    expect(search.value).toBe('');
    expect(api.items_list).toHaveBeenCalled();
  });
});
