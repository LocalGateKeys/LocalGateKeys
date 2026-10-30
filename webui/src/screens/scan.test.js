import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import Home from './Home.svelte';
import ScanSheet from '../components/ScanSheet.svelte';
import NewItem from '../components/NewItem.svelte';
import LoginEditor from '../components/LoginEditor.svelte';
import { emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; vi.useRealTimers(); });

const PNG = () => new File([new Uint8Array([137, 80, 78, 71])], 'code.png', { type: 'image/png' });
const DATA_URL = 'data:image/png;base64,iVBORw==';

const KEY = {
  ok: true, token: 't1', kind: 'key', complete: true, skipped: [], batch: { size: 1, scanned: [0], missing: [] },
  accounts: [{ index: 0, issuer: 'Alpha', label: 'ann', already: null, best: 'a1',
    matches: [{ id: 'a1', label: 'Alpha', username: 'ann', website: 'https://alpha.test', has_totp: false }] }],
};
const NEW_KEY = { ...KEY, accounts: [{ index: 0, issuer: 'Gamma', label: 'gail', already: null, best: null, matches: [] }] };
const EXPORT = {
  ok: true, token: 'e1', kind: 'export', complete: true, skipped: [], batch: { size: 1, scanned: [0], missing: [] },
  accounts: [
    { index: 0, issuer: 'Alpha', label: 'ann', already: null, best: 'a1',
      matches: [{ id: 'a1', label: 'Alpha', username: 'ann', website: 'https://alpha.test', has_totp: false }] },
    { index: 1, issuer: 'beta.test', label: 'bob', already: null, best: null, matches: [] },
    { index: 2, issuer: 'Gamma', label: 'cat', already: 'Gamma', best: null, matches: [] },
  ],
};
const DRAFT = { ok: true, draft_id: 'd9', kind: 'web', is_new: false, label: 'Alpha', label_hint: 'Alpha',
  urls: [{ url: 'https://alpha.test', match: 'exact_origin' }], username: 'ann', password_set: false, favorite: false,
  tags: [], notes: '', totp_configured: true, totp_allowed: true, policy: {}, errors: [], strength: null, dirty: true };

function sheet(overrides = {}, props = {}) {
  const api = fakeApi({
    qr_sheet_scan_image: vi.fn().mockResolvedValue(KEY),
    qr_sheet_scan_camera: vi.fn().mockResolvedValue(KEY),
    qr_sheet_open: vi.fn().mockResolvedValue(DRAFT),
    qr_sheet_add: vi.fn().mockResolvedValue({ ok: true, added: 1, updated: 1, skipped: [], message: 'Added 1 new login with a 2FA code and 2FA code added to 1 login.' }),
    qr_sheet_discard: vi.fn().mockResolvedValue({ ok: true }),
    qr_cancel: vi.fn().mockResolvedValue({ ok: true }),
    ...overrides,
  });
  const handlers = { onclose: vi.fn(), onedit: vi.fn(), ondone: vi.fn(), ...props };
  render(ScanSheet, handlers);
  return { api, ...handlers };
}

describe('Scan QR code entry points', () => {
  it('the sidebar Tools entry opens the Scan page in the content pane', async () => {
    fakeApi({ nav_get: vi.fn().mockResolvedValue({ ok: true, groups: [{ name: 'Tools', entries: [
      { label: 'Scan QR code', icon: 'nav.tools', token: null, count: null, action: 'scan_qr_clicked' }] }] }) });
    const { container } = render(Home, {});
    await fireEvent.click(await screen.findByRole('button', { name: 'Scan QR code' }));
    const dialog = await screen.findByRole('dialog', { name: 'Scan QR code' });
    expect(container.querySelector('.pane').contains(dialog)).toBe(true);
    expect(document.querySelector('.trash-host')).toBeNull(); // not a full-window overlay
  });

  it('the Ctrl+K palette opens it', async () => {
    fakeApi({
      palette_query: vi.fn().mockResolvedValue({ ok: true, rows: [
        { kind: 'command', title: 'Scan QR code', subtitle: 'Add 2FA codes', group: 'Actions', command_id: 'scan-qr' }] }),
      palette_run: vi.fn().mockResolvedValue({ ok: true, navigate: 'scan-qr' }),
    });
    render(Home, {});
    await screen.findByText('All items', { selector: 'h1' });
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await fireEvent.click(await screen.findByRole('option', { name: /Scan QR code/ }));
    expect(await screen.findByRole('dialog', { name: 'Scan QR code' })).toBeInTheDocument();
  });

  it('the New item menu offers it', async () => {
    const onchoose = vi.fn();
    render(NewItem, { onchoose, onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: /Scan QR code/ }));
    expect(onchoose).toHaveBeenCalledWith('scan-qr');
  });

  it('New item > Scan QR code opens the sheet from Home', async () => {
    fakeApi();
    render(Home, {});
    await screen.findByText('All items', { selector: 'h1' });
    await fireEvent.keyDown(window, { key: 'n', ctrlKey: true });
    await fireEvent.click(await screen.findByRole('button', { name: /Scan QR code/ }));
    expect(await screen.findByRole('dialog', { name: 'Scan QR code' })).toBeInTheDocument();
  });
});

describe('Scan sheet ways in', () => {
  it('offers paste, a picture file limited to PNG, JPEG and BMP, and the webcam', async () => {
    sheet();
    expect(screen.getByText(/Win\+Shift\+S/)).toBeInTheDocument();
    const input = screen.getByLabelText('Choose image…');
    expect(input).toHaveAttribute('type', 'file');
    expect(input).toHaveAttribute('accept', 'image/png,image/jpeg,image/bmp');
    expect(screen.getByRole('button', { name: 'Use webcam' })).toBeInTheDocument();
  });

  it('a chosen picture is read to a data URL and sent to Python', async () => {
    const { api } = sheet();
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await waitFor(() => expect(api.qr_sheet_scan_image).toHaveBeenCalledWith(DATA_URL, null));
  });

  it('a picture of another type is refused before it is read', async () => {
    const { api } = sheet();
    const gif = new File([new Uint8Array([71, 73, 70])], 'x.gif', { type: 'image/gif' });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [gif] } });
    expect(await screen.findByText('Use a PNG, JPEG or BMP picture of the QR code.')).toBeInTheDocument();
    expect(api.qr_sheet_scan_image).not.toHaveBeenCalled();
  });

  it('a dropped picture is scanned', async () => {
    const { api } = sheet();
    const dialog = screen.getByRole('dialog', { name: 'Scan QR code' });
    await fireEvent.dragOver(dialog, { dataTransfer: { files: [PNG()], types: ['Files'] } });
    await fireEvent.drop(dialog, { dataTransfer: { files: [PNG()], types: ['Files'] } });
    await waitFor(() => expect(api.qr_sheet_scan_image).toHaveBeenCalledWith(DATA_URL, null));
  });

  it('a pasted screenshot is scanned; a text paste is ignored', async () => {
    const { api } = sheet();
    const dialog = screen.getByRole('dialog', { name: 'Scan QR code' });
    await fireEvent.paste(dialog, { clipboardData: { items: [{ kind: 'string', type: 'text/plain' }] } });
    expect(api.qr_sheet_scan_image).not.toHaveBeenCalled();
    await fireEvent.paste(dialog, { clipboardData: { items: [{ kind: 'file', type: 'image/png', getAsFile: PNG }] } });
    await waitFor(() => expect(api.qr_sheet_scan_image).toHaveBeenCalledWith(DATA_URL, null));
  });

  it('the webcam shows the camera view and can be cancelled', async () => {
    let finish;
    const { api } = sheet({ qr_sheet_scan_camera: vi.fn(() => new Promise((resolve) => { finish = resolve; })) });
    await fireEvent.click(screen.getByRole('button', { name: 'Use webcam' }));
    const camera = await screen.findByRole('dialog', { name: 'Scan a 2FA QR code' });
    emit('qr.status', { status: 'Hold the QR code up to the camera', detail: '', state: 'running' });
    await fireEvent.click(within(camera).getByRole('button', { name: 'Cancel' }));
    expect(api.qr_cancel).toHaveBeenCalled();
    finish({ ok: false, error: { code: 'cancelled', message: 'Cancelled.' } });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Scan a 2FA QR code' })).toBeNull());
    expect(api.qr_sheet_scan_camera).toHaveBeenCalledWith(null);
  });

  it('shows a bad image error from Python', async () => {
    sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue({ ok: false, error: { code: 'not_found', message: 'No 2FA QR code was found in the pasted image.' } }) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    expect(await screen.findByText('No 2FA QR code was found in the pasted image.')).toBeInTheDocument();
  });

  it('on the free plan says 2FA needs Pro (Python shows the upgrade screen)', async () => {
    sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue({ ok: false, error: { code: 'pro_required', message: 'Two-factor codes need LocalGateKeys Pro.' } }) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    expect(await screen.findByText('Two-factor codes need LocalGateKeys Pro.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open in editor' })).toBeNull();
  });
});

describe('Scan sheet results', () => {
  it('a single key with a matching login opens that login in the editor with the key applied', async () => {
    const { api, onedit } = sheet();
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    expect(await screen.findByText('Alpha', { selector: '.account strong' })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Alpha · ann/ })).toBeChecked();
    await fireEvent.click(screen.getByRole('button', { name: 'Open in editor' }));
    await waitFor(() => expect(api.qr_sheet_open).toHaveBeenCalledWith('t1', 0, 'a1'));
    expect(onedit).toHaveBeenCalledWith(DRAFT, { source: 'credential', id: 'a1', kind: 'web' });
  });

  it('a single key can go to a new login instead', async () => {
    const { api, onedit } = sheet();
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await fireEvent.click(await screen.findByRole('radio', { name: 'New login' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Open in editor' }));
    await waitFor(() => expect(api.qr_sheet_open).toHaveBeenCalledWith('t1', 0, null));
    expect(onedit).toHaveBeenCalledWith(DRAFT, null);
  });

  it('a single key without matches opens a prefilled new login', async () => {
    const { api } = sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue(NEW_KEY) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    expect(await screen.findByText(/No login matches/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Open in editor' }));
    await waitFor(() => expect(api.qr_sheet_open).toHaveBeenCalledWith('t1', 0, null));
  });

  it('an export lists every account with a checkbox and adds the ticked ones in one go', async () => {
    const { api, ondone } = sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue(EXPORT) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    const boxes = await screen.findAllByRole('checkbox');
    expect(boxes).toHaveLength(3);
    expect(boxes.map((b) => b.checked)).toEqual([true, true, false]); // the third is already saved
    expect(screen.getByText(/Already in Gamma/)).toBeInTheDocument();
    // A website guessed from the issuer is offered, not filled in silently.
    expect(screen.getByLabelText('Website for beta.test')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Add 2 accounts' })).toBeDisabled();
    await fireEvent.click(screen.getByRole('button', { name: 'From the QR code: beta.test — use it?' }));
    expect(screen.getByLabelText('Website for beta.test')).toHaveValue('beta.test');
    expect(screen.getByLabelText('Destination for Alpha')).toHaveValue('a1');
    await fireEvent.click(screen.getByRole('button', { name: 'Add 2 accounts' }));
    await waitFor(() => expect(api.qr_sheet_add).toHaveBeenCalledWith('e1', [
      { index: 0, target: 'a1', website: '', replace: false }, { index: 1, target: 'new', website: 'beta.test', replace: false }]));
    expect(await screen.findByText(/Added 1 new login/)).toBeInTheDocument();
    expect(ondone).toHaveBeenCalled();
  });

  it('a new login without a website keeps Add disabled until one is typed', async () => {
    const { api } = sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue(EXPORT) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    const boxes = await screen.findAllByRole('checkbox');
    await fireEvent.click(boxes[1]);
    await fireEvent.click(boxes[2]);
    const add = screen.getByRole('button', { name: 'Add 2 accounts' });
    expect(add).toBeDisabled();
    await fireEvent.input(screen.getByLabelText('Website for Gamma'), { target: { value: 'gamma.test' } });
    expect(add).toBeEnabled();
    await fireEvent.click(add);
    await waitFor(() => expect(api.qr_sheet_add).toHaveBeenCalledWith('e1', [
      { index: 0, target: 'a1', website: '', replace: false }, { index: 2, target: 'new', website: 'gamma.test', replace: false }]));
  });

  it('a multi-part export asks for the next code and sends the token with it', async () => {
    const part = { ...EXPORT, complete: false, batch: { size: 2, scanned: [0], missing: [1] } };
    const scan = vi.fn().mockResolvedValueOnce(part).mockResolvedValueOnce({ ...EXPORT, batch: { size: 2, scanned: [0, 1], missing: [] } });
    sheet({ qr_sheet_scan_image: scan });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    expect(await screen.findByText(/Code 1 of 2 scanned/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add 2 accounts' })).toBeDisabled();
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await waitFor(() => expect(scan).toHaveBeenLastCalledWith(DATA_URL, 'e1'));
    await fireEvent.click(await screen.findByRole('button', { name: 'From the QR code: beta.test — use it?' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Add 2 accounts' })).toBeEnabled());
  });

  it('closing discards the scanned accounts', async () => {
    const { api, onclose } = sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue(EXPORT) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await screen.findAllByRole('checkbox');
    await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(api.qr_sheet_discard).toHaveBeenCalledWith('e1'));
    expect(onclose).toHaveBeenCalled();
  });
});

describe('LoginEditor picture options', () => {
  it('a chosen or dropped picture goes through qr_scan_image', async () => {
    const view = { ...DRAFT, draft_id: 'd1' };
    const api = fakeApi({ qr_scan_image: vi.fn().mockResolvedValue({ ok: true, found: 'key', view }) });
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    const input = await screen.findByLabelText('Choose image…');
    expect(input).toHaveAttribute('accept', 'image/png,image/jpeg,image/bmp');
    await fireEvent.change(input, { target: { files: [PNG()] } });
    await waitFor(() => expect(api.qr_scan_image).toHaveBeenCalledWith('d1', DATA_URL));
    api.qr_scan_image.mockClear();
    const dialog = screen.getByRole('dialog');
    await fireEvent.drop(dialog, { dataTransfer: { files: [PNG()], types: ['Files'] } });
    await waitFor(() => expect(api.qr_scan_image).toHaveBeenCalledWith('d1', DATA_URL));
  });

  it('opens with a draft handed over by the Scan sheet', async () => {
    const api = fakeApi();
    render(LoginEditor, { ref: null, draft: DRAFT, onclose: vi.fn() });
    expect(await screen.findByDisplayValue('ann')).toBeInTheDocument();
    expect(api.login_new).not.toHaveBeenCalled();
    expect(api.login_open).not.toHaveBeenCalled();
  });
});

describe('Scan sheet fix round 1', () => {
  const WITH_TOTP = { ...EXPORT, accounts: [
    { index: 0, issuer: 'Alpha', label: 'ann', already: null, best: 'a1',
      matches: [{ id: 'a1', label: 'Alpha', username: 'ann', website: 'https://alpha.test', has_totp: true }] },
    { index: 1, issuer: 'Al', label: 'an', already: null, best: null,
      matches: [{ id: 'a1', label: 'Alpha', username: 'ann', website: 'https://alpha.test', has_totp: true }] },
  ] };

  it('only an unambiguous match is picked; options say they replace an existing 2FA code', async () => {
    sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue(WITH_TOTP) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await screen.findAllByRole('checkbox');
    expect(screen.getByLabelText('Destination for Alpha')).toHaveValue('a1');
    expect(screen.getByLabelText('Destination for Al')).toHaveValue('new');
    expect(within(screen.getByLabelText('Destination for Al')).getByRole('option', { name: /Alpha · ann \(replaces its 2FA code\)/ })).toBeInTheDocument();
  });

  it('replacing a 2FA code asks first and sends replace only after a yes', async () => {
    const { api } = sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue(WITH_TOTP) });
    window.confirm = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(true);
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    const boxes = await screen.findAllByRole('checkbox');
    await fireEvent.click(boxes[1]); // untick the ambiguous one
    await fireEvent.click(screen.getByRole('button', { name: 'Add 1 account' }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringMatching(/Alpha already has a 2FA code/));
    expect(api.qr_sheet_add).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Add 1 account' }));
    await waitFor(() => expect(api.qr_sheet_add).toHaveBeenCalledWith('e1', [{ index: 0, target: 'a1', website: '', replace: true }]));
  });

  it('discards the scan when the sheet unmounts and when a new scan starts', async () => {
    const api = fakeApi({ qr_sheet_scan_image: vi.fn().mockResolvedValueOnce(KEY).mockResolvedValueOnce({ ...KEY, token: 't2' }),
      qr_sheet_discard: vi.fn().mockResolvedValue({ ok: true }) });
    const view = render(ScanSheet, { onclose: vi.fn(), onedit: vi.fn() });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await screen.findByRole('button', { name: 'Open in editor' });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    await waitFor(() => expect(api.qr_sheet_discard).toHaveBeenCalledWith('t1'));
    await waitFor(() => expect(api.qr_sheet_scan_image).toHaveBeenCalledTimes(2));
    await screen.findByRole('button', { name: 'Open in editor' });
    view.unmount();
    await waitFor(() => expect(api.qr_sheet_discard).toHaveBeenCalledWith('t2'));
  });

  it('says when a picture held more than one QR code', async () => {
    sheet({ qr_sheet_scan_image: vi.fn().mockResolvedValue({ ...KEY, more_codes: 2 }) });
    await fireEvent.change(screen.getByLabelText('Choose image…'), { target: { files: [PNG()] } });
    expect(await screen.findByText(/held 3 QR codes; only the first was read/)).toBeInTheDocument();
  });
});
