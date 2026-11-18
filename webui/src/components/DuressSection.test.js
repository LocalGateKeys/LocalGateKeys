import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import DuressSection from './DuressSection.svelte';

const OFF = { ok: true, pro: true, configured: false, lock_hours: 24, min_hours: 1, max_hours: 168, max_items: 2,
  folder: false, items: [{ id: 'a', title: 'Alpha', kind: 'login' }, { id: 'b', title: 'Beta', kind: 'note' },
    { id: 'c', title: 'Gamma', kind: 'bookmark' }] };

afterEach(() => { vi.restoreAllMocks(); delete window.pywebview; });

function install(api) {
  window.pywebview = { api };
  return api;
}

describe('duress password section', () => {
  it('sets one up with the picked items and the hours', async () => {
    const api = install({
      duress_status: vi.fn().mockResolvedValue(OFF),
      duress_setup: vi.fn().mockResolvedValue({ ...OFF, configured: true, lock_hours: 6, message: 'Set.' }),
    });
    render(DuressSection);
    await screen.findByTestId('duress');
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'real password' } });
    await fireEvent.input(screen.getByLabelText('Duress password'), { target: { value: 'second password' } });
    await fireEvent.input(screen.getByLabelText('Repeat duress password'), { target: { value: 'second password' } });
    await fireEvent.input(screen.getByLabelText(/Hours to refuse/), { target: { value: '6' } });
    await fireEvent.click(screen.getByLabelText('Alpha'));
    await fireEvent.click(screen.getByLabelText('Gamma'));
    expect(screen.getByLabelText('Beta').disabled).toBe(true); // at most max_items
    await fireEvent.click(screen.getByRole('button', { name: 'Set up' }));
    await waitFor(() => expect(api.duress_setup).toHaveBeenCalledWith('real password', 'second password',
      'second password', 6, ['a', 'c']));
    expect(await screen.findByText('Set.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument();
    expect(document.body.textContent.toLowerCase()).not.toContain('decoy');
  });

  it('shows the Pro note on the free plan and no form', async () => {
    install({ duress_status: vi.fn().mockResolvedValue({ ...OFF, pro: false }) });
    render(DuressSection);
    expect(await screen.findByText('The duress password needs LocalGateKeys Pro.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set up' })).toBeNull();
  });

  it('removes it', async () => {
    const api = install({
      duress_status: vi.fn().mockResolvedValue({ ...OFF, configured: true, lock_hours: 1 }),
      duress_remove: vi.fn().mockResolvedValue({ ...OFF, message: 'Duress password removed.' }),
    });
    render(DuressSection);
    await fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(api.duress_remove).toHaveBeenCalled());
    expect(await screen.findByText('Duress password removed.')).toBeInTheDocument();
  });
});
