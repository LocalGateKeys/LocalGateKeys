import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import DeveloperPage from './DeveloperPage.svelte';
import { emit, fakeApi } from '../test/fakeApi.js';

const KEYS = [
  { id: 'k1', title: 'Work', fingerprint: 'SHA256:aaa', state: 'ok', reason: '', offered: true },
  { id: 'k2', title: 'Locked', fingerprint: 'SHA256:bbb', state: 'needs_passphrase', reason: '', offered: false },
  { id: 'k3', title: 'Old PuTTY', fingerprint: '', state: 'unsupported', reason: 'PuTTY (.ppk) keys are not supported by the agent', offered: false },
  { id: 'k4', title: 'Spare', fingerprint: 'SHA256:ddd', state: 'ok', reason: '', offered: false },
];
const STATUS = {
  ok: true,
  agent: { enabled: false, status: 'off' },
  keys: KEYS,
  env: { name: 'SSH_AUTH_SOCK', current: '', pipe: '\\\\.\\pipe\\lgk', applied: false },
  git: { available: true, signing_ok: true, version: '2.50', applied: false },
  cli: { enabled: false, items: [
    { id: 'l1', title: 'Plain login', kind: 'web', listed: false, strict: false },
    { id: 'l2', title: 'Bank', kind: 'web', listed: false, strict: true },
    { id: 'n1', title: 'Router', kind: 'note', listed: true, strict: false },
  ] },
};
const PLAN = { ok: true, rows: [
  { key: 'core.sshCommand', current: null, new: 'C:/Windows/System32/OpenSSH/ssh.exe' },
  { key: 'gpg.format', current: 'openpgp', new: 'ssh' },
  { key: 'gpg.ssh.program', current: null, new: 'C:/Windows/System32/OpenSSH/ssh-keygen.exe' },
  { key: 'user.signingkey', current: null, new: 'key::ssh-ed25519 AAAA' },
  { key: 'commit.gpgsign', current: null, new: 'true' },
] };

afterEach(() => {
  vi.restoreAllMocks();
  delete window.pywebview;
});

function mount(overrides = {}) {
  const api = fakeApi({
    developer_status: vi.fn().mockResolvedValue(STATUS),
    developer_set: vi.fn().mockResolvedValue({ ok: true, enabled: true, message: 'Applying…' }),
    developer_key_toggle: vi.fn().mockResolvedValue({ ok: true, offered: true }),
    developer_generate_key: vi.fn().mockResolvedValue({ ok: true, id: 'k9', message: 'SSH key created.' }),
    developer_copy_public_key: vi.fn().mockResolvedValue({ ok: true, message: 'Public key copied.' }),
    developer_env_apply: vi.fn().mockResolvedValue({ ok: true, message: 'set' }),
    developer_env_undo: vi.fn().mockResolvedValue({ ok: true, message: 'undone' }),
    developer_git_plan: vi.fn().mockResolvedValue(PLAN),
    developer_git_apply: vi.fn().mockResolvedValue({ ok: true, message: 'Git is set up to sign commits.' }),
    developer_git_undo: vi.fn().mockResolvedValue({ ok: true, message: 'undone' }),
    developer_cli_set: vi.fn().mockResolvedValue({ ok: true, enabled: true }),
    developer_cli_item_toggle: vi.fn().mockResolvedValue({ ok: true, listed: true }),
    ...overrides,
  });
  render(DeveloperPage, { onclose: () => {} });
  return api;
}

describe('developer page', () => {
  it('test_taken_agent_status_is_shown_as_a_warning', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, agent: { enabled: true, status: 'taken' } }) });
    await waitFor(() => expect(document.querySelector('.desc.status')).toHaveClass('bad'));
  });

  it('test_page_lists_keys_with_their_state', async () => {
    mount();
    expect(await screen.findByText('Work')).toBeTruthy();
    expect(screen.getByText(/Needs a passphrase/)).toBeTruthy();
    expect(screen.getByText(/PuTTY \(\.ppk\) keys are not supported/)).toBeTruthy();
    expect(screen.getByRole('switch', { name: 'Offer to SSH: Work' }).checked).toBe(true);
    expect(screen.getByRole('switch', { name: 'Offer to SSH: Locked' }).disabled).toBe(true);
    expect(screen.getByRole('switch', { name: 'Offer to SSH: Old PuTTY' }).disabled).toBe(true);
    expect(screen.getByRole('switch', { name: 'Offer to SSH: Spare' }).disabled).toBe(false);
  });

  it('test_setup_says_agent_forwarding_is_not_served', async () => {
    mount();
    const note = await screen.findByRole('note');
    expect(note.textContent).toMatch(/do not use ssh -A/);
    expect(note.textContent).toMatch(/8\.1/);
  });

  it('test_agent_switch_calls_developer_set', async () => {
    const api = mount();
    const toggle = await screen.findByRole('switch', { name: 'SSH agent' });
    await fireEvent.click(toggle);
    await waitFor(() => expect(api.developer_set).toHaveBeenCalledWith('ssh_agent', true));
    expect(screen.getByRole('status').textContent).toBe('Off');
    api.developer_status.mockResolvedValue({ ...STATUS, agent: { enabled: true, status: 'running' } });
    emit('developer.changed', {});
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('Running'));
  });

  it('test_key_switch_calls_developer_key_toggle', async () => {
    const api = mount();
    await fireEvent.click(await screen.findByRole('switch', { name: 'Offer to SSH: Spare' }));
    await waitFor(() => expect(api.developer_key_toggle).toHaveBeenCalledWith('k4', true));
  });

  it('test_generate_key_sends_the_name', async () => {
    const api = mount();
    const box = await screen.findByLabelText('Key name');
    await fireEvent.input(box, { target: { value: ' Laptop ' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Generate' }));
    await waitFor(() => expect(api.developer_generate_key).toHaveBeenCalledWith('Laptop'));
  });

  it('test_git_preview_modal_shows_current_and_new_and_applies_on_confirm', async () => {
    const api = mount();
    await fireEvent.click(await screen.findByRole('button', { name: 'Use for Git signing' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change global Git settings?' });
    expect(api.developer_git_plan).toHaveBeenCalledWith('k1');
    expect(dialog.textContent).toContain('gpg.format');
    expect(dialog.textContent).toContain('openpgp');
    expect(dialog.textContent).toContain('(not set)');
    expect(dialog.textContent).toContain('key::ssh-ed25519 AAAA');
    expect(api.developer_git_apply).not.toHaveBeenCalled(); // nothing changes before the user confirms
    await fireEvent.click(screen.getByRole('button', { name: 'Apply changes' }));
    await waitFor(() => expect(api.developer_git_apply).toHaveBeenCalledWith('k1'));
    expect(screen.queryByRole('dialog', { name: 'Change global Git settings?' })).toBeNull();
  });

  it('test_git_preview_cancel_changes_nothing', async () => {
    const api = mount();
    await fireEvent.click(await screen.findByRole('button', { name: 'Use for Git signing' }));
    await screen.findByRole('dialog', { name: 'Change global Git settings?' });
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog', { name: 'Change global Git settings?' })).toBeNull();
    expect(api.developer_git_apply).not.toHaveBeenCalled();
  });

  it('test_env_apply_and_undo_buttons', async () => {
    const api = mount();
    await fireEvent.click(await screen.findByRole('button', { name: 'Apply' }));
    await waitFor(() => expect(api.developer_env_apply).toHaveBeenCalled());
    expect(screen.queryByRole('button', { name: 'Undo' })).toBeNull();
    api.developer_status.mockResolvedValue({ ...STATUS, env: { ...STATUS.env, current: STATUS.env.pipe, applied: true },
      git: { ...STATUS.git, applied: true } });
    emit('developer.changed', {});
    const undos = await screen.findAllByRole('button', { name: 'Undo' });
    expect(undos).toHaveLength(2);
    await fireEvent.click(undos[0]);
    await waitFor(() => expect(api.developer_env_undo).toHaveBeenCalled());
    await fireEvent.click(undos[1]);
    await waitFor(() => expect(api.developer_git_undo).toHaveBeenCalled());
  });

  it('test_git_missing_says_so_and_hides_the_git_button', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, git: { available: false, signing_ok: true, version: '', applied: false } }) });
    expect(await screen.findByText('Git was not found on this PC.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Use for Git signing' })).toBeNull();
  });

  it('test_git_older_than_2_34_says_so_and_hides_the_git_button', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, git: { available: true, signing_ok: false, version: '2.33', applied: false } }) });
    expect(await screen.findByText(/Git 2\.33 is too old/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Use for Git signing' })).toBeNull();
  });

  it('test_cli_switch_calls_developer_cli_set_and_items_show_only_when_on', async () => {
    const api = mount();
    expect(await screen.findByRole('switch', { name: 'Command line access' })).toBeTruthy();
    expect(screen.queryByRole('switch', { name: 'Allow: Plain login' })).toBeNull();
    await fireEvent.click(screen.getByRole('switch', { name: 'Command line access' }));
    await waitFor(() => expect(api.developer_cli_set).toHaveBeenCalledWith(true));
  });

  it('test_agents_switch_calls_developer_agents_set_and_shows_the_allow_list', async () => {
    const api = mount({
      developer_status: vi.fn().mockResolvedValue({ ...STATUS, cli: { ...STATUS.cli, available: false },
        agents: { enabled: true, hello: false, pro: true } }),
      developer_agents_set: vi.fn().mockResolvedValue({ ok: true, enabled: false, hello: false, pro: true }),
    });
    const sw = await screen.findByRole('switch', { name: 'Allow AI agents to use LocalGateKeys' });
    expect(screen.getByRole('switch', { name: 'Allow: Plain login' })).toBeTruthy();
    await fireEvent.click(screen.getByRole('switch', { name: 'Require Windows Hello for each approval' }));
    await waitFor(() => expect(api.developer_agents_set).toHaveBeenCalledWith('hello', true));
    await fireEvent.click(sw);
    await waitFor(() => expect(api.developer_agents_set).toHaveBeenCalledWith('enabled', false));
  });

  it('test_recent_agent_runs_show_the_command_items_and_outcome', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, agents: { enabled: true, hello: false, pro: true, runs: [
      { at: 1700000200, stage: 'finished', agent: 'Claude Code', command: '"C:\\Tools\\deploy.exe" --prod', result: 'ok',
        exit_code: 0, timed_out: false, started: true, items: [{ variable: 'API_TOKEN', field: 'key', title: 'Deploy key' }] },
      { at: 1700000100, stage: 'finished', agent: 'Claude Code', command: 'slow.exe', result: 'cancelled',
        exit_code: -1, timed_out: true, started: true, items: [] },
      { at: 1700000000, stage: 'denied', agent: 'Other agent', command: 'x.exe', items: [] },
    ] } }) });
    expect(await screen.findByText('Recent AI agent runs')).toBeTruthy();
    expect(screen.getByText('"C:\\Tools\\deploy.exe" --prod')).toBeTruthy();
    expect(screen.getByText('API_TOKEN = Deploy key: key')).toBeTruthy();
    expect(screen.getByText(/Finished, exit code 0/)).toBeTruthy();
    expect(screen.getByText(/Stopped at the time limit/)).toBeTruthy();
    expect(screen.getByText(/Denied/)).toBeTruthy();
  });

  it('test_recent_agent_runs_empty_text', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, agents: { enabled: true, hello: false, pro: true, runs: [] } }) });
    expect(await screen.findByText('No AI agent has asked to run a command yet.')).toBeTruthy();
  });

  it('test_agents_switch_is_disabled_without_pro', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, agents: { enabled: false, hello: false, pro: false } }) });
    const sw = await screen.findByRole('switch', { name: 'Allow AI agents to use LocalGateKeys' });
    expect(sw.disabled).toBe(true);
  });

  it('test_store_build_shows_a_note_instead_of_the_cli_switch', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, cli: { enabled: false, available: false, items: [] } }) });
    expect(await screen.findByText(/not part of the Microsoft Store version/)).toBeTruthy();
    expect(screen.queryByRole('switch', { name: 'Command line access' })).toBeNull();
  });

  it('test_store_package_shows_the_native_host_commands', async () => {
    mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, cli: { ...STATUS.cli, available: true, packaged: true },
      agents: { enabled: true, hello: false, pro: true, available: true, packaged: true } }) });
    expect(await screen.findByText(/LocalGateKeysNativeHost\.exe lgk <command>/)).toBeTruthy();
    expect(screen.getByText(/LocalGateKeysNativeHost\.exe mcp/)).toBeTruthy();
    expect(screen.queryByText(/-- lgk mcp/)).toBeNull(); // `lgk` does not exist in the Store package
    expect(screen.getByRole('switch', { name: 'Command line access' })).toBeTruthy();
  });

  it('test_cli_item_switches_and_strict_logins_are_disabled', async () => {
    const api = mount({ developer_status: vi.fn().mockResolvedValue({ ...STATUS, cli: { ...STATUS.cli, enabled: true } }) });
    await fireEvent.click(await screen.findByRole('switch', { name: 'Allow: Plain login' }));
    await waitFor(() => expect(api.developer_cli_item_toggle).toHaveBeenCalledWith('l1', true));
    expect(screen.getByRole('switch', { name: 'Allow: Bank' }).disabled).toBe(true);
    expect(screen.getByText('Asks for the master password every time')).toBeTruthy();
    expect(screen.getByRole('switch', { name: 'Allow: Router' }).checked).toBe(true);
  });
});
