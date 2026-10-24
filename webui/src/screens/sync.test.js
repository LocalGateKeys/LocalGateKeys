import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import SyncPage from '../components/SyncPage.svelte';
import { emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; vi.useRealTimers(); });

const card = (key, title, actions) => ({ key, title, state: 'off', state_text: 'Not set up', last_sync_text: '', banner: null,
  hint: '', members_heading: 'Devices', members: [], issues: [], actions });
const VIEW = { ok: true, intro: 'Keep this vault in step.', status_line: '', banner: null, skipped: [], available: true, busy: false,
  advice: 'Write this password down. Never reuse an earlier sync password.',
  cards: [card('wifi', 'Wi-Fi sync', [{ id: 'wifi-enable', label: 'Turn on Wi-Fi sync', primary: true }, { id: 'show-qr', label: 'Show pairing code', primary: false }]),
    card('folder', 'Cloud folder', [{ id: 'create-group', label: 'Create sync group', primary: true }, { id: 'leave', label: 'Leave sync', primary: false }])] };

function api(overrides = {}) {
  return fakeApi({ sync_view: vi.fn().mockResolvedValue(VIEW), sync_refresh: vi.fn().mockResolvedValue(VIEW), ...overrides });
}

describe('SyncPage', () => {
  it('creates a group with a folder from Python and clears the passwords', async () => {
    const a = api({
      sync_choose_folder: vi.fn().mockResolvedValue({ ok: true, token: 't1', path: 'C:\\Cloud' }),
      sync_password_check: vi.fn().mockResolvedValue({ ok: true, label: 'Strong', message: 'Good.' }),
      sync_create: vi.fn().mockResolvedValue({ ...VIEW, message: 'Sync group created.' }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Create sync group' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Browse…' }));
    expect(await screen.findByText('C:\\Cloud')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Sync password'), { target: { value: 'violet-orbit-cactus-91' } });
    await fireEvent.input(screen.getByLabelText('Enter it again'), { target: { value: 'violet-orbit-cactus-91' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(a.sync_create).toHaveBeenCalledWith('t1', 'violet-orbit-cactus-91', 'violet-orbit-cactus-91'));
    await waitFor(() => expect(screen.queryByLabelText('Sync password')).not.toBeInTheDocument());
  });

  it('on the free plan shows the Pro card instead of the setup cards', async () => {
    const free = { ...VIEW, pro: false, pro_text: 'Device sync is part of LocalGateKeys Pro.' };
    api({ sync_view: vi.fn().mockResolvedValue(free), sync_refresh: vi.fn().mockResolvedValue(free) });
    const onlicence = vi.fn();
    render(SyncPage, { onclose: vi.fn(), onlicence });
    expect(await screen.findByText('Device sync is part of LocalGateKeys Pro.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create sync group' })).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Enter licence' }));
    expect(onlicence).toHaveBeenCalled();
  });

  it('shows the pairing code and cancels the offer on close', async () => {
    const a = api({
      sync_qr_show: vi.fn().mockResolvedValue({ ok: true, offer_id: 'o1', code: '123-456', image: 'data:image/png;base64,AA', countdown: '2:00' }),
      sync_qr_close: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    expect(await screen.findByText('Code: 123-456')).toBeInTheDocument();
    await fireEvent.click(within(screen.getByRole('dialog', { name: 'Pair a device' })).getByRole('button', { name: 'Close' }));
    expect(a.sync_qr_close).toHaveBeenCalledWith('o1');
  });

  it('re-reads the view when sync publishes a status', async () => {
    const a = api();
    render(SyncPage, { onclose: vi.fn() });
    await screen.findByText('Wi-Fi sync');
    emit('sync.status', {});
    await waitFor(() => expect(a.sync_view).toHaveBeenCalled());
  });

  it('shows a refused leave as an error-free cancel', async () => {
    const a = api({ sync_leave: vi.fn().mockResolvedValue({ ok: false, error: { code: 'cancelled', message: 'Cancelled.' } }) });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Leave sync' }));
    expect(a.sync_leave).toHaveBeenCalled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('SyncPage Wi-Fi pairing', () => {
  const SHOWN = { ok: true, offer_id: 'o1', code: '123-456', image: 'data:image/png;base64,AA', countdown: '2:00',
    address: '192.168.60.26:47821', hint: 'Phone and PC must be on the same Wi-Fi.', notice: '', size: 252, modules: 63 };

  it('keeps the QR at its crisp size beside the address and hint', async () => {
    api({ sync_qr_show: vi.fn().mockResolvedValue(SHOWN), sync_firewall_status: vi.fn().mockResolvedValue({ ok: true, supported: false }) });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    const img = await screen.findByAltText('Pairing QR code');
    expect(img).toHaveAttribute('width', '252');
    expect(img).toHaveAttribute('height', '252');
    expect(img.style.width).toBe('252px');
    const where = screen.getByLabelText('Where to connect');
    expect(img.parentElement).toBe(where.parentElement); // one row: QR and text side by side (wraps when narrow)
    expect(within(where).getByLabelText("This PC's address")).toHaveTextContent('192.168.60.26:47821');
    expect(within(where).getByText('Phone and PC must be on the same Wi-Fi.')).toBeInTheDocument();
  });

  it('shows the address in large text and the firewall button', async () => {
    const a = api({
      sync_qr_show: vi.fn().mockResolvedValue(SHOWN),
      sync_qr_close: vi.fn().mockResolvedValue({ ok: true }),
      sync_firewall_status: vi.fn().mockResolvedValue({ ok: true, supported: true, allowed: false, can_allow: true, profile: 'Private', advice: '' }),
      sync_firewall_allow: vi.fn().mockResolvedValue({ ok: true, supported: true, allowed: true, profile: 'Private', advice: '', message: 'Allowed.' }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    expect(await screen.findByLabelText("This PC's address")).toHaveTextContent('192.168.60.26:47821');
    expect(screen.getByText('Phone and PC must be on the same Wi-Fi.')).toBeInTheDocument();
    expect(await screen.findByText('Network profile: Private')).toBeInTheDocument();
    expect(a.sync_firewall_allow).not.toHaveBeenCalled(); // never without the button
    await fireEvent.click(screen.getByRole('button', { name: 'Allow through Windows Firewall' }));
    await waitFor(() => expect(a.sync_firewall_allow).toHaveBeenCalled());
    expect(await screen.findByText('Windows Firewall allows LocalGateKeys on this network.')).toBeInTheDocument();
  });

  it('steps the QR down by whole pixels per module in a narrow window', async () => {
    window.innerWidth = 300; // 60% is 180px: 63 modules x 2px = 126px, never a fractional module
    api({ sync_qr_show: vi.fn().mockResolvedValue(SHOWN), sync_firewall_status: vi.fn().mockResolvedValue({ ok: true, supported: false }) });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    const img = await screen.findByAltText('Pairing QR code');
    expect(img).toHaveAttribute('width', '126');
    window.innerWidth = 1024;
  });

  it('explains instead of offering the button on a Public network', async () => {
    const a = api({
      sync_qr_show: vi.fn().mockResolvedValue(SHOWN),
      sync_firewall_status: vi.fn().mockResolvedValue({ ok: true, supported: true, allowed: false, can_allow: false, profile: 'Public',
        advice: 'Windows treats this network as Public; set it to Private in Windows Settings › Network & internet.' }),
      sync_firewall_allow: vi.fn(),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    expect(await screen.findByText(/Windows treats this network as Public/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Allow through Windows Firewall' })).not.toBeInTheDocument();
    expect(a.sync_firewall_allow).not.toHaveBeenCalled();
  });

  it('preselects the gateway LAN over a saved VirtualBox address (the owner\'s PC)', async () => {
    api({
      sync_qr_show: vi.fn().mockResolvedValue({ ok: true, choose_address: true, current: '192.168.60.26:47821', message: 'Choose.',
        addresses: [{ value: '192.168.60.26:47821', label: '192.168.60.26 (Ethernet)' }, { value: '192.168.56.1:47821', label: '192.168.56.1 (saved)' }] }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    expect(await screen.findByLabelText('192.168.60.26 (Ethernet)')).toBeChecked();
    expect(screen.getByLabelText('192.168.56.1 (saved)')).not.toBeChecked();
  });

  it('preselects a saved address that is offered for keeping', async () => {
    api({
      sync_qr_show: vi.fn().mockResolvedValue({ ok: true, choose_address: true, current: '192.168.137.1:47821', message: 'Keep it?',
        addresses: [{ value: '192.168.137.1:47821', label: '192.168.137.1 (saved)' }, { value: '192.168.1.9:47821', label: '192.168.1.9 (Wi-Fi)' }] }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    expect(await screen.findByLabelText('192.168.137.1 (saved)')).toBeChecked();
    expect(screen.getByLabelText('192.168.1.9 (Wi-Fi)')).not.toBeChecked();
  });

  it('hides the firewall button off Windows', async () => {
    api({
      sync_qr_show: vi.fn().mockResolvedValue(SHOWN),
      sync_firewall_status: vi.fn().mockResolvedValue({ ok: true, supported: false }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    await screen.findByText('Code: 123-456');
    expect(screen.queryByRole('button', { name: 'Allow through Windows Firewall' })).not.toBeInTheDocument();
  });

  it('shows the reason instead of a QR when nothing listens', async () => {
    api({ sync_qr_show: vi.fn().mockResolvedValue({ ok: false, error: { code: 'listen_failed', message: 'Wi-Fi sync could not start listening on 192.168.56.1:47821.' } }) });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('192.168.56.1:47821');
    expect(screen.queryByAltText('Pairing QR code')).not.toBeInTheDocument();
  });

  it('asks for the address when there are several, saves it and then shows the code', async () => {
    const show = vi.fn()
      .mockResolvedValueOnce({ ok: true, choose_address: true, current: '10.0.0.7:47821', message: 'Choose the address.',
        addresses: [{ value: '192.168.60.26:47821', label: '192.168.60.26 (Ethernet)' }, { value: '192.168.1.9:47821', label: '192.168.1.9 (Wi-Fi)' }] })
      .mockResolvedValueOnce(SHOWN);
    const a = api({
      sync_qr_show: show,
      sync_wifi_enable: vi.fn().mockResolvedValue({ ...VIEW }),
      sync_firewall_status: vi.fn().mockResolvedValue({ ok: true, supported: false }),
    });
    render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    await fireEvent.click(await screen.findByLabelText('192.168.1.9 (Wi-Fi)'));
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(a.sync_wifi_enable).toHaveBeenCalledWith('192.168.1.9:47821'));
    expect(await screen.findByText('Code: 123-456')).toBeInTheDocument();
  });
});

describe('SyncPage unmount', () => {
  it('cancels an open pairing code', async () => {
    const a = api({
      sync_qr_show: vi.fn().mockResolvedValue({ ok: true, offer_id: 'o9', code: '1', image: 'data:image/png;base64,AA', countdown: '2:00' }),
      sync_qr_close: vi.fn().mockResolvedValue({ ok: true }),
    });
    const { unmount } = render(SyncPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show pairing code' }));
    await screen.findByText('Code: 1');
    unmount();
    await waitFor(() => expect(a.sync_qr_close).toHaveBeenCalledWith('o9'));
  });
});
