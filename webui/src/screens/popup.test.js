import { afterEach, describe, expect, it } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import PopupApp from '../PopupApp.svelte';
import App from '../App.svelte';
import { LOCKED, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const CHOOSE = { id: 'p1', kind: 'choose', surface: 'popup', title: 'Choose account for this app', message: '',
  options: [{ id: 'a', label: 'ann' }, { id: 'b', label: 'bob' }] };

describe('Popup window', () => {
  it('shows the compact unlock while locked', async () => {
    fakeApi({ vault_state: () => Promise.resolve(LOCKED) });
    render(PopupApp);
    expect(await screen.findByLabelText('Master password')).toBeInTheDocument();
  });

  it('answers a fill question and ignores the main window\'s own', async () => {
    fakeApi();
    render(PopupApp);
    emit('modal.request', { id: 'm1', kind: 'confirm', title: 'Main window question', message: '' });
    emit('modal.request', CHOOSE);
    await fireEvent.click(await screen.findByLabelText('bob'));
    const use = screen.getByRole('button', { name: 'Use this account' });
    await waitFor(() => expect(use).toBeEnabled(), { timeout: 2000 });
    await fireEvent.click(use);
    expect(window.pywebview.api.modal_answer).toHaveBeenCalledWith('p1', 'b');
    expect(screen.queryByText('Main window question')).not.toBeInTheDocument();
  });

  it('a confirmation focuses Deny and ignores Allow for the first half second', async () => {
    fakeApi();
    render(PopupApp);
    emit('modal.request', { id: 'c1', kind: 'confirm', surface: 'popup', title: 'Save new login?', message: '' });
    const deny = await screen.findByRole('button', { name: 'Deny' });
    const allow = screen.getByRole('button', { name: 'Allow' });
    await waitFor(() => expect(deny).toHaveFocus());
    expect(allow).toBeDisabled();
    await fireEvent.click(allow);
    expect(window.pywebview.api.modal_answer).not.toHaveBeenCalled();
    await waitFor(() => expect(allow).toBeEnabled(), { timeout: 2000 });
    await fireEvent.click(allow);
    expect(window.pywebview.api.modal_answer).toHaveBeenCalledWith('c1', true);
  });
});

describe('Main window', () => {
  it('leaves popup questions to the popup', async () => {
    fakeApi();
    render(App);
    emit('modal.request', CHOOSE);
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText('Choose account for this app')).not.toBeInTheDocument();
    expect(window.pywebview.api.modal_answer).not.toHaveBeenCalled();
  });
});
