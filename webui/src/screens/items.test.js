import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import TypedEditor from '../components/TypedEditor.svelte';
import DetailPane from '../components/DetailPane.svelte';
import TrashPage from '../components/TrashPage.svelte';
import LoginMore from '../components/LoginMore.svelte';
import NewItem from '../components/NewItem.svelte';
import LoginEditor from '../components/LoginEditor.svelte';
import { ALPHA, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; vi.useRealTimers(); });
const CARD = { source: 'typed', id: 'c1', kind: 'card' };

describe('TypedEditor', () => {
  it('creates a card; protected fields are write-only', async () => {
    const api = fakeApi();
    const onclose = vi.fn();
    render(TypedEditor, { kind: 'card', ref: null, onclose });
    await fireEvent.input(await screen.findByLabelText('Title'), { target: { value: 'Visa' } });
    await fireEvent.input(screen.getByLabelText('Cardholder'), { target: { value: 'Ann' } });
    await fireEvent.input(screen.getByLabelText(/Card number/), { target: { value: '4111111111111111' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.typed_save).toHaveBeenCalled());
    const [ref, kind, data] = api.typed_save.mock.calls[0];
    expect(ref).toBeNull();
    expect(kind).toBe('card');
    expect(data.values).toEqual({ cardholder: 'Ann' });
    expect(data.protected).toEqual({ number: '4111111111111111' });
    await waitFor(() => expect(onclose).toHaveBeenCalledWith(CARD));
  });

  it('editing shows saved protected fields as saved, never their value', async () => {
    fakeApi();
    render(TypedEditor, { kind: 'card', ref: CARD, onclose: vi.fn() });
    const number = await screen.findByLabelText(/Card number/);
    expect(number).toHaveValue('');
    expect(number).toHaveAttribute('placeholder', 'Saved · enter a new value to replace');
  });

  it('a document asks Python for the file', async () => {
    const api = fakeApi();
    render(TypedEditor, { kind: 'document', ref: null, onclose: vi.fn() });
    await fireEvent.input(await screen.findByLabelText('Title'), { target: { value: 'Contract' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file and save' }));
    await waitFor(() => expect(api.doc_create).toHaveBeenCalledWith('Contract', ''));
  });
});

describe('Typed detail', () => {
  it('reveals a protected field', async () => {
    const api = fakeApi();
    render(DetailPane, { selected: CARD });
    await fireEvent.click(await screen.findByRole('button', { name: 'Reveal number' }));
    expect(await screen.findByText('4111111111111111')).toBeInTheDocument();
    expect(api.typed_reveal).toHaveBeenCalledWith(CARD, 'number');
  });
});

describe('TrashPage', () => {
  it('restores and permanently deletes the selection', async () => {
    const api = fakeApi();
    render(TrashPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByLabelText('Select Router'));
    await fireEvent.click(screen.getByRole('button', { name: 'Restore selected' }));
    await waitFor(() => expect(api.trash_restore).toHaveBeenCalledWith(['t1']));
    await fireEvent.click(await screen.findByLabelText('Select Alpha'));
    await fireEvent.click(screen.getByRole('button', { name: 'Delete selected' }));
    await waitFor(() => expect(api.trash_purge).toHaveBeenCalled());
    expect(screen.getByText('Entries stay encrypted for 30 days.')).toBeInTheDocument();
  });
});

describe('LoginMore', () => {
  it('opens history and saves an autofill rule', async () => {
    const api = fakeApi();
    render(LoginMore, { selected: ALPHA.ref });
    expect(await screen.findByText('2 saved code(s) hidden. Reveal to view or edit.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Password history' }));
    await waitFor(() => expect(api.history_list).toHaveBeenCalledWith(ALPHA.ref));
    await fireEvent.change(await screen.findByLabelText('Filling'), { target: { value: 'never' } });
    await waitFor(() => expect(api.policy_save).toHaveBeenCalledWith(ALPHA.ref, { fill: 'never' }));
  });

  it('offers no field editor until the stored fields loaded', async () => {
    const api = fakeApi({ fields_get: vi.fn()
      .mockResolvedValueOnce({ ok: false, error: { code: 'vault_error', message: 'Fields could not be read.' } })
      .mockResolvedValue({ ok: true, fields: [{ index: 0, name: 'PIN', value: null, hidden: true }] }) });
    render(LoginMore, { selected: ALPHA.ref });
    expect(await screen.findByText('Fields could not be read.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add field' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Save fields' })).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('button', { name: 'Add field' })).toBeInTheDocument();
    expect(api.fields_save).not.toHaveBeenCalled();
  });

  it('a failed policy load shows a retry line, not an empty editor', async () => {
    const api = fakeApi({ policy_get: vi.fn()
      .mockResolvedValueOnce({ ok: false, error: { code: 'locked', message: 'Unlock this profile first.' } })
      .mockResolvedValue({ ok: true, policy: { fill: 'click', sign_in: 'inherit', require_master_password: false, save_prompts: true } }) });
    render(LoginMore, { selected: ALPHA.ref });
    expect(await screen.findByText('Unlock this profile first.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add field' })).toBeNull();
    expect(api.fields_get).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('button', { name: 'Add field' })).toBeInTheDocument();
  });

  it('saving sends the removed stored rows with the list', async () => {
    const api = fakeApi();
    render(LoginMore, { selected: ALPHA.ref });
    await fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Add field' }));
    await fireEvent.input(screen.getByLabelText('Field name'), { target: { value: 'Color' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save fields' }));
    await waitFor(() => expect(api.fields_save).toHaveBeenCalledWith(
      ALPHA.ref, [{ name: 'Color', value: '', hidden: true }], [0]));
    await waitFor(() => expect(api.fields_get).toHaveBeenCalledTimes(2)); // the saved rows load again
  });
});

describe('NewItem and GA import', () => {
  it('offers every typed kind', async () => {
    const onchoose = vi.fn();
    render(NewItem, { onchoose, onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Payment card' }));
    expect(onchoose).toHaveBeenCalledWith('card');
  });

  it('a pasted Google Authenticator export in Setup key lists its accounts', async () => {
    const api = fakeApi();
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    const key = await screen.findByLabelText('Setup key');
    await fireEvent.input(key, { target: { value: 'otpauth-migration://offline?data=x' } });
    await fireEvent.change(key);
    await waitFor(() => expect(api.ga_parse).toHaveBeenCalledWith('otpauth-migration://offline?data=x', 'Untitled login', ''));
    expect(key).toHaveValue('');
    await fireEvent.click(await screen.findByRole('button', { name: 'Use for this login' }));
    await waitFor(() => expect(api.ga_apply).toHaveBeenCalledWith('d1', 'g1', 0));
  });

  it('on the free plan the two-factor key is not editable but an existing one can be removed', async () => {
    const view = { ok: true, draft_id: 'd1', kind: 'web', is_new: false, label: 'Mail', label_hint: 'Mail', urls: [{ url: 'mail.test', match: 'exact_origin' }],
      username: 'ann', password_set: true, favorite: false, tags: [], notes: '', totp_configured: true, totp_allowed: false, policy: {}, errors: [], strength: null, dirty: false };
    const api = fakeApi({ login_new: vi.fn().mockResolvedValue(view) });
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    expect(await screen.findByText('Adding or changing two-factor codes needs LocalGateKeys Pro. Codes you already saved keep working.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Setup key')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Scan with camera' })).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(api.login_update).toHaveBeenCalledWith('d1', { totp_remove: true }));
  });

  it('a pasted QR snip puts the key in the draft; a text paste is left alone', async () => {
    const view = { draft_id: 'd1', kind: 'web', is_new: true, label: '', label_hint: 'x', urls: [{ url: '', match: 'exact_origin' }],
      username: '', password_set: true, favorite: false, tags: [], notes: '', totp_configured: true, policy: {}, errors: [], strength: null, dirty: true };
    const api = fakeApi({ qr_scan_image: vi.fn().mockResolvedValue({ ok: true, found: 'key', view }) });
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    const key = await screen.findByLabelText('Setup key');
    await fireEvent.paste(key, { clipboardData: { items: [{ kind: 'string', type: 'text/plain' }] } });
    expect(api.qr_scan_image).not.toHaveBeenCalled();
    const png = new File([new Uint8Array([137, 80, 78, 71])], 'snip.png', { type: 'image/png' });
    await fireEvent.paste(key, { clipboardData: { items: [{ kind: 'file', type: 'image/png', getAsFile: () => png }] } });
    await waitFor(() => expect(api.qr_scan_image).toHaveBeenCalledWith('d1', 'data:image/png;base64,iVBORw=='));
    expect(await screen.findByText('2FA setup key read from the QR code. Save to keep it.')).toBeInTheDocument();
    expect(key).toHaveAttribute('placeholder', 'Configured — paste a new key or QR snip');
  });

  it('the camera scan shows a preview, can be cancelled, and lists export accounts', async () => {
    let finish;
    const api = fakeApi({ qr_scan_camera: vi.fn(() => new Promise((resolve) => { finish = resolve; })),
      qr_cancel: vi.fn().mockResolvedValue({ ok: true }) });
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Scan with camera' }));
    const dialog = await screen.findByRole('dialog', { name: 'Scan a 2FA QR code' });
    emit('qr.status', { status: 'Hold the QR code up to the camera', detail: '', state: 'running' });
    expect(await screen.findByText('Hold the QR code up to the camera')).toBeInTheDocument();
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(api.qr_cancel).toHaveBeenCalled();
    finish({ ok: true, found: 'accounts', token: 'g1', accounts: [{ index: 0, issuer: 'Alpha', label: 'ann' }, { index: 1, issuer: 'Beta', label: 'bob' }],
      skipped: [], best: 1, batch: { index: 0, size: 2 } });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Scan a 2FA QR code' })).toBeNull());
    expect(screen.getByRole('combobox', { name: 'Account for this login' })).toHaveValue('1');
    expect(screen.getByText(/Code 1 of 2\. 2 account\(s\) found\. Best match selected/)).toBeInTheDocument();
  });
});
