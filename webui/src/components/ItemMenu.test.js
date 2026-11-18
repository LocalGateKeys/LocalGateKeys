import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import ItemMenu from './ItemMenu.svelte';

const item = { ref: { source: 'credential', kind: 'web', id: 'a' }, target: 'example.com', favorite: false };

describe('item menu', () => {
  it('test_copy_cli_reference_only_when_the_cli_is_on', async () => {
    const { unmount } = render(ItemMenu, { item, at: { x: 0, y: 0 }, onpick: () => {}, onclose: () => {} });
    expect(screen.queryByRole('menuitem', { name: 'Copy CLI reference' })).toBeNull();
    unmount();
    const onpick = vi.fn();
    render(ItemMenu, { item, at: { x: 0, y: 0 }, cli: true, onpick, onclose: () => {} });
    await fireEvent.click(screen.getByRole('menuitem', { name: 'Copy CLI reference' }));
    expect(onpick).toHaveBeenCalledWith('copy-cli-reference');
  });
});
