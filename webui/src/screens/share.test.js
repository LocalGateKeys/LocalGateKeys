import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import ShareSheet from '../components/ShareSheet.svelte';
import IncomingSheet from '../components/IncomingSheet.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const REF = { source: 'credential', id: 'e1', kind: 'web' };

describe('ShareSheet', () => {
  it('shows the six words, saves a file and shows a QR code', async () => {
    const api = fakeApi({
      share_start: vi.fn().mockResolvedValue({ ok: true, handle: 'h1', code: 'maple river onion seven lamp quote',
        title: 'Alpha', size: 900, qr: true, qr_limit: 2048, expires_hours: 24 }),
      share_save_file: vi.fn().mockResolvedValue({ ok: true, path: 'C:/x.lgkshare', status: 'Saved.' }),
      share_qr: vi.fn().mockResolvedValue({ ok: true, image: 'data:image/png;base64,AAAA' }),
      share_cancel: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(ShareSheet, { item: REF, onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Create share' }));
    expect(await screen.findByText('maple river onion seven lamp quote')).toBeInTheDocument();
    expect(api.share_start).toHaveBeenCalledWith(REF);
    await fireEvent.click(screen.getByRole('button', { name: 'Save as file…' }));
    await waitFor(() => expect(api.share_save_file).toHaveBeenCalledWith('h1'));
    await fireEvent.click(screen.getByRole('button', { name: 'Show QR code' }));
    expect(await screen.findByAltText('QR code holding the encrypted item')).toBeInTheDocument();
  });

  it('falls back to a file when the item is too large for QR', async () => {
    fakeApi({
      share_start: vi.fn().mockResolvedValue({ ok: true, handle: 'h2', code: 'a b c d e f', title: 'Big', size: 5000,
        qr: false, qr_limit: 2048, expires_hours: 24 }),
      share_cancel: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(ShareSheet, { item: REF, onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Create share' }));
    expect(await screen.findByText(/Too large for a QR code/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show QR code' })).toBeNull();
  });
});

describe('IncomingSheet', () => {
  it('opens a file, previews with masked values and saves', async () => {
    const row = { id: 'p1', sender: "Alex's iPhone", hours_left: 24 };
    const api = fakeApi({
      share_incoming: vi.fn().mockResolvedValue({ ok: true, incoming: [] }),
      share_receive_file: vi.fn().mockResolvedValue({ ok: true, id: 'p1', sender: row.sender, incoming: [row] }),
      share_preview: vi.fn().mockResolvedValue({ ok: true, id: 'p1', sender: row.sender, kind: 'wifi', title: 'Home Wi-Fi',
        duplicate: false, passkey_warning: false, fields: [{ name: 'Password', value: 'secret-pw', secret: true }] }),
      share_save: vi.fn().mockResolvedValue({ ok: true, status: 'Saved to your vault.' }),
    });
    const onchanged = vi.fn();
    render(IncomingSheet, { onclose: vi.fn(), onchanged });
    await fireEvent.click(screen.getByRole('button', { name: 'Open a shared item…' }));
    expect(await screen.findByText("Alex's iPhone shared an item with you")).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Six-word code'), { target: { value: 'a b c d e f' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    expect(await screen.findByText('wifi · Home Wi-Fi')).toBeInTheDocument();
    expect(screen.queryByText('secret-pw')).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Reveal' }));
    expect(screen.getByText('secret-pw')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Save to vault' }));
    await waitFor(() => expect(api.share_save).toHaveBeenCalledWith('p1', 'a b c d e f', 'keep'));
    await waitFor(() => expect(onchanged).toHaveBeenCalled());
  });

  it('receives a package from pasted QR text', async () => {
    const row = { id: 'p3', sender: 'Pixel', hours_left: 24 };
    const api = fakeApi({
      share_incoming: vi.fn().mockResolvedValue({ ok: true, incoming: [] }),
      share_receive_text: vi.fn().mockResolvedValue({ ok: true, id: 'p3', sender: 'Pixel', incoming: [row] }),
    });
    render(IncomingSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Paste a QR code…' }));
    await fireEvent.input(screen.getByLabelText('QR code text'), { target: { value: ' {"format":"localgatekeys-share"} ' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Receive' }));
    await waitFor(() => expect(api.share_receive_text).toHaveBeenCalledWith('{"format":"localgatekeys-share"}'));
    expect(await screen.findByText('Pixel shared an item with you')).toBeInTheDocument();
  });

  it('rejects a waiting item from the list', async () => {
    const api = fakeApi({
      share_incoming: vi.fn().mockResolvedValue({ ok: true, incoming: [{ id: 'p2', sender: 'PC', hours_left: 3 }] }),
      share_reject: vi.fn().mockResolvedValue({ ok: true, status: 'Deleted.', incoming: [] }),
    });
    render(IncomingSheet, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(api.share_reject).toHaveBeenCalledWith('p2'));
    expect(await screen.findByText('Nothing is waiting.')).toBeInTheDocument();
  });
});
