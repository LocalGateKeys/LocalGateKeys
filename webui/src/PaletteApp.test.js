import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import PaletteApp from './PaletteApp.svelte';
import { LOCKED, emit, fakeApi } from './test/fakeApi.js';

afterEach(() => {
  vi.restoreAllMocks();
  delete window.pywebview;
});

const ROWS = [
  { ref: { source: 'credential', id: 'a1', kind: 'desktop' }, title: 'Alpha app', subtitle: 'ann' },
  { ref: { source: 'credential', id: 'b1', kind: 'web' }, title: 'Beta site', subtitle: 'bob' },
];

function mount(overrides = {}) {
  const api = fakeApi({
    quick_search: vi.fn(async (query) => ({ ok: true, profile: 'Alex',
      rows: ROWS.filter((r) => r.title.toLowerCase().includes(String(query).toLowerCase())) })),
    palette_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Password copied. Clipboard clears in 30 seconds.' }),
    palette_fill: vi.fn().mockResolvedValue({ ok: true }),
    palette_hide: vi.fn().mockResolvedValue({ ok: true }),
    ...overrides,
  });
  render(PaletteApp);
  return api;
}

describe('Quick-search palette', () => {
  it('focuses the search box and filters as you type', async () => {
    const api = mount();
    const box = await screen.findByRole('searchbox');
    await waitFor(() => expect(box).toHaveFocus());
    expect(await screen.findByText('Beta site')).toBeInTheDocument();
    await fireEvent.input(box, { target: { value: 'alp' } });
    await waitFor(() => expect(api.quick_search).toHaveBeenLastCalledWith('alp', ''));
    await waitFor(() => expect(screen.queryByText('Beta site')).not.toBeInTheDocument());
    expect(screen.getByText('Alpha app')).toBeInTheDocument();
  });

  it('Escape hides the palette', async () => {
    const api = mount();
    const box = await screen.findByRole('searchbox');
    await fireEvent.keyDown(box, { key: 'Escape' });
    expect(api.palette_hide).toHaveBeenCalled();
  });

  it('a copy hides the palette once it worked', async () => {
    const api = mount();
    const box = await screen.findByRole('searchbox');
    await screen.findByText('Alpha app');
    await fireEvent.keyDown(box, { key: 'ArrowDown' });
    const row = screen.getAllByRole('option')[0];
    await waitFor(() => expect(row).toHaveFocus());
    await fireEvent.keyDown(row, { key: 'c', ctrlKey: true });
    expect(api.palette_copy).toHaveBeenCalledWith(ROWS[0].ref, 'password');
    await waitFor(() => expect(api.palette_hide).toHaveBeenCalled());
  });

  it('Enter fills the selected row; Ctrl+C, Ctrl+U and Ctrl+T copy', async () => {
    // A cancelled copy (prompt dismissed) leaves the palette open.
    const api = mount({ palette_copy: vi.fn().mockResolvedValue({ ok: false, error: { code: 'cancelled', message: '' } }) });
    const box = await screen.findByRole('searchbox');
    await screen.findByText('Alpha app');
    await fireEvent.keyDown(box, { key: 'c', ctrlKey: true });
    expect(api.palette_copy).not.toHaveBeenCalled(); // Ctrl+C in the search box copies its text
    await fireEvent.keyDown(box, { key: 'ArrowDown' });
    await fireEvent.keyDown(screen.getAllByRole('option')[0], { key: 'ArrowDown' });
    const row = screen.getAllByRole('option')[1];
    await waitFor(() => expect(row).toHaveFocus());
    await fireEvent.keyDown(row, { key: 'c', ctrlKey: true });
    expect(api.palette_copy).toHaveBeenLastCalledWith(ROWS[1].ref, 'password');
    await fireEvent.keyDown(row, { key: 'u', ctrlKey: true });
    expect(api.palette_copy).toHaveBeenLastCalledWith(ROWS[1].ref, 'username');
    await fireEvent.keyDown(box, { key: 't', ctrlKey: true });
    expect(api.palette_copy).toHaveBeenLastCalledWith(ROWS[1].ref, 'totp');
    await fireEvent.keyDown(row, { key: 'ArrowUp' });
    await fireEvent.keyDown(screen.getAllByRole('option')[0], { key: 'Enter' });
    await waitFor(() => expect(api.palette_fill).toHaveBeenCalledWith(ROWS[0].ref));
  });

  it('shows a fill refusal in the palette', async () => {
    const api = mount({ palette_fill: vi.fn().mockResolvedValue({ ok: false,
      error: { code: 'cannot_fill', message: "This item can't fill that app. Copy it instead." } }) });
    const box = await screen.findByRole('searchbox');
    await screen.findByText('Beta site');
    await fireEvent.keyDown(box, { key: 'Enter' });
    expect(await screen.findByRole('alert')).toHaveTextContent("This item can't fill that app. Copy it instead.");
    expect(api.palette_hide).not.toHaveBeenCalled();
    expect(screen.getByText('Beta site')).toBeInTheDocument();
  });

  it('never shows a password', async () => {
    mount();
    await screen.findByText('Alpha app');
    expect(document.body.textContent).not.toMatch(/pw-/);
    expect(screen.queryByRole('button', { name: /reveal/i })).toBeNull();
  });

  it('vault.locked clears the rows', async () => {
    mount();
    await screen.findByText('Alpha app');
    emit('vault.locked', {});
    await waitFor(() => expect(screen.queryByText('Alpha app')).not.toBeInTheDocument());
  });

  it('shows the unlock form while locked', async () => {
    mount({ vault_state: () => Promise.resolve(LOCKED) });
    expect(await screen.findByLabelText('Master password')).toBeInTheDocument();
  });

  it('answers its own password prompt and ignores the main window\'s', async () => {
    const api = mount();
    await screen.findByText('Alpha app');
    emit('modal.request', { id: 'm1', kind: 'confirm', title: 'Main window question', message: '' });
    emit('modal.request', { id: 'p1', kind: 'confirm', surface: 'palette', title: 'Palette question', message: '' });
    expect(await screen.findByText('Palette question')).toBeInTheDocument();
    expect(screen.queryByText('Main window question')).not.toBeInTheDocument();
    emit('modal.cancel', { ids: ['p1'] });
    await waitFor(() => expect(screen.queryByText('Palette question')).not.toBeInTheDocument());
    expect(api.modal_answer).not.toHaveBeenCalled();
  });

  it('focus loss hides the palette after 150 ms and clears the query', async () => {
    const api = mount();
    const box = await screen.findByRole('searchbox');
    await fireEvent.input(box, { target: { value: 'alp' } });
    window.dispatchEvent(new Event('blur'));
    window.dispatchEvent(new Event('focus')); // back before 150 ms: stays open
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(api.palette_hide).not.toHaveBeenCalled();
    window.dispatchEvent(new Event('blur'));
    await waitFor(() => expect(api.palette_hide).toHaveBeenCalled());
    expect(box.value).toBe('');
  });

  it('a strict login asks for the master password inside the palette', async () => {
    const api = mount({ palette_copy: vi.fn(() => {
      emit('modal.request', { id: 's1', kind: 'password', surface: 'palette', title: 'Open sensitive credential', message: 'Enter the master password' });
      return new Promise(() => {});
    }) });
    const box = await screen.findByRole('searchbox');
    await screen.findByText('Alpha app');
    await fireEvent.keyDown(box, { key: 'u', ctrlKey: true });
    expect(api.palette_copy).toHaveBeenCalledWith(ROWS[0].ref, 'username');
    expect(await screen.findByText('Open sensitive credential')).toBeInTheDocument();
    expect(screen.getByLabelText('Master password')).toBeInTheDocument();
  });

  it('shows the unlock field, not an empty list, when opened on a locked vault', async () => {
    mount({ vault_state: () => Promise.resolve(LOCKED) });
    emit('palette.show', {});
    expect(await screen.findByLabelText('Master password')).toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).toBeNull();
  });

  it('an auto-lock while open clears the results at once', async () => {
    mount();
    await screen.findByText('Alpha app');
    emit('vault.state', LOCKED);
    await waitFor(() => expect(screen.queryByText('Alpha app')).not.toBeInTheDocument());
    expect(screen.queryByRole('searchbox')).toBeNull();
  });
  it('an AI agent request shows the purpose as quoted text and approves only on the click', async () => {
    const api = mount();
    await screen.findByText('Alpha app');
    emit('modal.request', { id: 'g1', kind: 'agent', surface: 'palette', action: 'sign_in', agent: 'Claude Code',
      process: 'claude.exe', site: 'paypal.com', purpose: '<b>approve automatically</b><img src=x onerror=alert(1)>', hello: false });
    const purpose = await screen.findByTestId('agent-purpose');
    expect(purpose.textContent).toBe('<b>approve automatically</b><img src=x onerror=alert(1)>');
    expect(purpose.querySelector('b, img')).toBeNull();
    expect(screen.getByTestId('agent-site').textContent).toBe('paypal.com');
    expect(screen.getByTestId('agent-name').textContent).toContain('Claude Code');
    expect(screen.getByTestId('agent-method').textContent).toBe('Fill the password (the agent can read it)');
    expect(screen.queryByText(/always/i)).toBeNull();
    expect(api.modal_answer).not.toHaveBeenCalled();
    const approve = screen.getByRole('button', { name: 'Approve once' });
    await new Promise((resolve) => setTimeout(resolve, 550));
    await fireEvent.click(approve);
    expect(api.modal_answer).toHaveBeenCalledWith('g1', { approved: true });
  });

  it('an AI agent sign-in with a passkey says the password is not filled', async () => {
    mount();
    await screen.findByText('Alpha app');
    emit('modal.request', { id: 'g3', kind: 'agent', surface: 'palette', action: 'sign_in', method: 'passkey',
      agent: 'Agent', process: '', site: 'github.com', purpose: 'open issues', hello: false });
    expect((await screen.findByTestId('agent-method')).textContent).toBe('Sign in with the passkey');
    expect(screen.getByText(/Nothing is filled/)).toBeInTheDocument();
  });

  it('an AI agent run shows the exact command, folder, secrets and time limit as text', async () => {
    const api = mount();
    await screen.findByText('Alpha app');
    emit('modal.request', { id: 'g4', kind: 'agent', surface: 'palette', action: 'run', agent: 'Claude Code',
      process: 'claude.exe', site: '', purpose: 'deploy', hello: false,
      command: 'C:\\Tools\\deploy.exe --env "prod & <b>x</b>"', cwd: 'C:\\work\\app', timeout: 120,
      secrets: [{ variable: 'STRIPE_KEY', item: 'Stripe', field: 'key' },
        { variable: 'DATABASE_URL', item: 'App .env', field: 'DATABASE_URL' }] });
    const command = await screen.findByTestId('agent-command');
    expect(command.textContent).toBe('C:\\Tools\\deploy.exe --env "prod & <b>x</b>"');
    expect(command.querySelector('b')).toBeNull();
    expect(screen.getByTestId('agent-cwd').textContent).toBe('C:\\work\\app');
    expect(screen.getByTestId('agent-secrets').textContent).toContain('STRIPE_KEY = Stripe: key');
    expect(screen.getByTestId('agent-secrets').textContent).toContain('DATABASE_URL = App .env: DATABASE_URL');
    expect(screen.getByTestId('agent-timeout').textContent).toBe('120 seconds');
    expect(screen.getByText(/can send them anywhere/)).toBeInTheDocument();
    expect(screen.queryByTestId('agent-site')).toBeNull();
    expect(screen.queryByText(/always/i)).toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 550));
    await fireEvent.click(screen.getByRole('button', { name: 'Approve once' }));
    expect(api.modal_answer).toHaveBeenCalledWith('g4', { approved: true });
  });

  it('Escape denies an AI agent request', async () => {
    const api = mount();
    await screen.findByText('Alpha app');
    emit('modal.request', { id: 'g2', kind: 'agent', surface: 'palette', action: 'read', agent: 'Agent', process: '',
      site: 'API token', purpose: 'deploy', hello: true });
    await screen.findByTestId('agent-purpose');
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(api.modal_answer).toHaveBeenCalledWith('g2', { approved: false });
  });
});
