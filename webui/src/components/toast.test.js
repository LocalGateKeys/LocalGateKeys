import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import Toast from './Toast.svelte';
import { notice, toast } from '../lib/toast.js';
import ErrorLogLink from './ErrorLogLink.svelte';
import ItemList from './ItemList.svelte';
import { fakeApi } from '../test/fakeApi.js';

describe('Toast', () => {
  it('can be dismissed by hand', async () => {
    render(Toast);
    toast('Saved.');
    await tick();
    await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText('Saved.')).toBeNull();
  });

  it('stays while the pointer is over it', async () => {
    vi.useFakeTimers();
    try {
      render(Toast);
      toast('Hold me');
      await tick();
      await fireEvent.mouseEnter(screen.getByRole('group', { name: 'Hold me' }));
      vi.advanceTimersByTime(20000);
      await tick();
      expect(screen.getByText('Hold me')).toBeTruthy();
      await fireEvent.mouseLeave(screen.getByRole('group', { name: 'Hold me' }));
      vi.advanceTimersByTime(7000);
      await tick();
      expect(screen.queryByText('Hold me')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('turns undo and route actions into buttons', async () => {
    const routed = vi.fn();
    window.addEventListener('lgk-route', (e) => routed(e.detail));
    render(Toast);
    notice({ message: 'Moved Alpha to Trash.', undo: { ids: ['a1'] },
      action: { label: 'Open Privacy settings', route: 'settings', params: { section: 'privacy' } } });
    await tick();
    expect(screen.getByRole('button', { name: 'Undo' })).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Open Privacy settings' }));
    expect(routed).toHaveBeenCalledWith({ route: 'settings', params: { section: 'privacy' } });
  });
});

describe('Open error log', () => {
  it('is offered on notices and inline text that mention the error log', async () => {
    const api = fakeApi({ errorlog_open: vi.fn().mockResolvedValue({ ok: true }) });
    render(Toast);
    toast('Something went wrong. Details are in the error log.', '', 'error');
    await tick();
    await fireEvent.click(screen.getByRole('button', { name: 'Open error log' }));
    expect(api.errorlog_open).toHaveBeenCalled();
  });

  it('stays away from other text', () => {
    render(ErrorLogLink, { text: 'Wrong password.' });
    expect(screen.queryByRole('button', { name: 'Open error log' })).toBeNull();
  });
});

describe('ItemList keys from outside the list', () => {
  const items = [
    { ref: { source: 'credential', id: 'a', kind: 'web' }, title: 'Alpha', subtitle: '', kind_label: 'Login', flags: [] },
    { ref: { source: 'credential', id: 'b', kind: 'web' }, title: 'Beta', subtitle: '', kind_label: 'Login', flags: [] },
  ];
  const press = (key, extra = {}) => new KeyboardEvent('keydown', { key, cancelable: true, ...extra });

  it('moves, opens and copies through the exported key handler', () => {
    const onselect = vi.fn(); const onopen = vi.fn(); const oncopy = vi.fn();
    const { component, rerender } = render(ItemList, { items, selected: null, onselect, onopen, oncopy, onmenu: vi.fn() });
    expect(component.key(press('ArrowDown'))).toBe(true);
    expect(onselect).toHaveBeenLastCalledWith(items[0].ref);
    return rerender({ selected: items[1].ref }).then(() => {
      expect(component.key(press('Enter'))).toBe(true);
      expect(onopen).toHaveBeenCalledWith(items[1].ref);
      expect(component.key(press('c', { ctrlKey: true }))).toBe(true);
      expect(oncopy).toHaveBeenCalledWith(items[1].ref);
      expect(component.key(press('x'))).toBe(false);
    });
  });
});
