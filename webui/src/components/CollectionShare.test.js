import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import CollectionShare from './CollectionShare.svelte';
import WorkspacePages from './WorkspacePages.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const BASE = { ok: true, collection: { id: 'c1', name: 'Family' }, pro: true, pro_text: 'Shared collections need Pro.',
  help: 'Everyone keeps their own vault.', owner_loss: 'If that PC is lost, nobody can change who is in.' };
const UNSHARED = { ...BASE, shared: false, intro: 'Share this collection.', mode_hint: 'This choice is fixed once shared.', status: null };
const OWNER = {
  ...BASE, shared: true, role: 'owner', is_owner: true, mode: 'read', mode_text: 'Members can only view',
  mode_hint: 'This choice is fixed once shared.', folder: 'C:\\OneDrive\\Family',
  members: [
    { id: 'd-own', name: 'Anna', state: 'owner', state_text: 'Shared it', is_self: true, removable: false },
    { id: 'd-ben', name: 'Ben', state: 'member', state_text: 'Member', is_self: false, removable: true },
    { id: 'd-cy', name: 'Cy', state: 'pending', state_text: 'Waiting for approval', is_self: false, removable: true },
  ],
  pending: [{ id: 'd-cy', name: 'Cy' }], removed: [{ name: 'Dee', at: 1 }], status: null,
};

function passwordInputs() {
  return [...document.querySelectorAll('input[type="password"]')];
}

describe('Share a collection', () => {
  it('shares through a chosen folder with the password typed twice and the edit choice', async () => {
    const api = fakeApi({
      collection_share_members: vi.fn().mockResolvedValue(UNSHARED),
      collection_share_choose_folder: vi.fn().mockResolvedValue({ ok: true, token: 'tok', path: 'C:\\OneDrive\\Family' }),
      collection_share_create: vi.fn().mockResolvedValue({ ...OWNER, message: 'Family is shared.' }),
    });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    expect(await screen.findByText('This choice is fixed once shared.')).toBeInTheDocument();
    expect(screen.getByText(/If that PC is lost/)).toBeInTheDocument();
    const share = screen.getByRole('button', { name: 'Share collection' });
    expect(share).toBeDisabled();
    await fireEvent.click(screen.getByRole('button', { name: 'Choose folder' }));
    expect(await screen.findByText('C:\\OneDrive\\Family')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Your name for the others'), { target: { value: 'Anna' } });
    const [pw, again] = passwordInputs();
    await fireEvent.input(pw, { target: { value: 'correct horse battery 7!' } });
    await fireEvent.input(again, { target: { value: 'correct horse battery 7!' } });
    await fireEvent.click(screen.getByLabelText('Members can edit'));
    await fireEvent.click(share);
    await waitFor(() => expect(api.collection_share_create)
      .toHaveBeenCalledWith('c1', 'tok', 'correct horse battery 7!', 'correct horse battery 7!', true, 'Anna'));
    expect(await screen.findByText('Members can only view')).toBeInTheDocument();
    // The passwords are gone from the page once the call returns.
    expect(document.body.innerHTML).not.toContain('correct horse battery 7!');
  });

  it('clears the password after a refusal too', async () => {
    fakeApi({
      collection_share_members: vi.fn().mockResolvedValue(UNSHARED),
      collection_share_choose_folder: vi.fn().mockResolvedValue({ ok: true, token: 'tok', path: 'C:\\F' }),
      collection_share_create: vi.fn().mockResolvedValue({ ok: false, error: { code: 'pro_required', message: 'Shared collections need Pro.' } }),
    });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Choose folder' }));
    await screen.findByText('C:\\F');
    const [pw, again] = passwordInputs();
    await fireEvent.input(pw, { target: { value: 'secret share pw 1!' } });
    await fireEvent.input(again, { target: { value: 'secret share pw 1!' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Share collection' }));
    await waitFor(() => expect(passwordInputs().every((i) => i.value === '')).toBe(true));
  });
});

describe('Members', () => {
  it('shows who shared it, who is in, who waits and who was removed, and fixes the mode', async () => {
    fakeApi({ collection_share_members: vi.fn().mockResolvedValue(OWNER) });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    const people = await screen.findByRole('list', { name: 'People' });
    expect(within(people).getByText('Shared it')).toBeInTheDocument();
    expect(within(people).getByText('Member')).toBeInTheDocument();
    expect(within(people).getByText('Waiting for approval')).toBeInTheDocument();
    expect(screen.getByText('Dee')).toBeInTheDocument();
    expect(screen.getByText('Members can only view')).toBeInTheDocument();
    expect(screen.getByText('This choice is fixed once shared.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Stop sharing' })).toBeInTheDocument();
  });

  it('warns when the collection is shared from two of your devices', async () => {
    fakeApi({ collection_share_members: vi.fn().mockResolvedValue({ ...OWNER, twice: 'Shared from two of your devices.' }) });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    expect(await screen.findByRole('alert')).toHaveTextContent('Shared from two of your devices.');
  });

  it('offers Forget share link, not a new share, for a collection another of your devices shares', async () => {
    const LINKED = { ...UNSHARED, linked: { text: 'Another of your devices shares this collection.', forget_hint: 'If that device is gone, forget the link.' } };
    const api = fakeApi({
      collection_share_members: vi.fn().mockResolvedValue(LINKED),
      collection_share_forget_link: vi.fn().mockResolvedValue({ ...UNSHARED, linked: null, message: 'Forgotten.' }),
    });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    expect(await screen.findByText('Another of your devices shares this collection.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Share collection' })).not.toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Forget share link' }));
    await waitFor(() => expect(api.collection_share_forget_link).toHaveBeenCalledWith('c1'));
    expect(await screen.findByRole('button', { name: 'Share collection' })).toBeInTheDocument();
  });

  it('lets in only the waiting people the owner ticks, by name', async () => {
    const api = fakeApi({
      collection_share_members: vi.fn().mockResolvedValue(OWNER),
      collection_share_approve: vi.fn().mockResolvedValue({ ...OWNER, pending: [], message: 'Let in: Cy.' }),
    });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    const letIn = await screen.findByRole('button', { name: 'Let them in' });
    expect(letIn).toBeDisabled();
    await fireEvent.click(screen.getByRole('checkbox', { name: 'Cy' }));
    await fireEvent.click(letIn);
    await waitFor(() => expect(api.collection_share_approve).toHaveBeenCalledWith('c1', ['d-cy']));
  });

  it('removes someone with a new share password and says why it is needed', async () => {
    const api = fakeApi({
      collection_share_members: vi.fn().mockResolvedValue(OWNER),
      collection_share_remove_member: vi.fn().mockResolvedValue({ ...OWNER, members: OWNER.members.slice(0, 1), message: 'Ben was removed.' }),
    });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    const people = await screen.findByRole('list', { name: 'People' });
    await fireEvent.click(within(within(people).getByText('Ben').closest('.row')).getByRole('button', { name: 'Remove' }));
    expect(screen.getByText(/Ben knows the current share password/)).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('New share password'), { target: { value: 'a brand new phrase 42?' } });
    await fireEvent.input(screen.getByLabelText('New share password again'), { target: { value: 'a brand new phrase 42?' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Remove Ben' }));
    await waitFor(() => expect(api.collection_share_remove_member)
      .toHaveBeenCalledWith('c1', 'd-ben', 'a brand new phrase 42?', 'a brand new phrase 42?'));
    await waitFor(() => expect(screen.queryByText('Ben')).not.toBeInTheDocument());
  });

  it('offers the owner of an older share the upgrade with the share password typed twice', async () => {
    const upgrade = { title: 'Make this share safer', text: 'Only the people you let in can open the items.' };
    const api = fakeApi({
      collection_share_members: vi.fn().mockResolvedValue({ ...OWNER, upgrade }),
      collection_share_upgrade: vi.fn().mockResolvedValue({ ...OWNER, upgrade: null, message: 'Share upgraded.' }),
    });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    const form = await screen.findByRole('form', { name: 'Make this share safer' });
    expect(within(form).getByText(/Only the people you let in/)).toBeInTheDocument();
    const button = within(form).getByRole('button', { name: 'Upgrade share' });
    expect(button).toBeDisabled();
    const [pw, again] = within(form).getAllByLabelText(/Share password/);
    await fireEvent.input(pw, { target: { value: 'maple river onion seven' } });
    await fireEvent.input(again, { target: { value: 'maple river onion seven' } });
    await fireEvent.click(button);
    await waitFor(() => expect(api.collection_share_upgrade)
      .toHaveBeenCalledWith('c1', 'maple river onion seven', 'maple river onion seven'));
    await waitFor(() => expect(screen.queryByRole('form', { name: 'Make this share safer' })).not.toBeInTheDocument());
    expect(document.body.innerHTML).not.toContain('maple river onion seven');
  });

  it('shows no upgrade to a member or for a current share', async () => {
    fakeApi({ collection_share_members: vi.fn().mockResolvedValue({ ...OWNER, upgrade: null }) });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    await screen.findByRole('list', { name: 'People' });
    expect(screen.queryByText('Upgrade share')).not.toBeInTheDocument();
  });

  it('shows a merged keyring as information and a lost join with Join again', async () => {
    const api = fakeApi({
      collection_share_members: vi.fn()
        .mockResolvedValueOnce({ ...OWNER, status: { kind: 'keyring-merged', severity: 'info', text: 'Someone joined meanwhile.' } }),
      collection_share_rejoin: vi.fn().mockResolvedValue({ ...OWNER, status: null }),
    });
    const { unmount } = render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    expect(await screen.findByRole('status')).toHaveTextContent('Someone joined meanwhile.');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    unmount();
    api.collection_share_members.mockResolvedValueOnce({ ...OWNER, is_owner: false, role: 'member',
      status: { kind: 'superseded', severity: 'warning', text: 'Join again with the share password.', action: 'rejoin' } });
    render(CollectionShare, { collectionId: 'c1', onclose: vi.fn() });
    expect(await screen.findByRole('alert')).toHaveTextContent('Join again with the share password.');
    await fireEvent.input(passwordInputs()[0], { target: { value: 'correct horse battery 7!' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Join again' }));
    await waitFor(() => expect(api.collection_share_rejoin).toHaveBeenCalledWith('c1', 'correct horse battery 7!', ''));
  });
});

describe('Join a shared collection', () => {
  it('joins from the Collections page through a folder and a password', async () => {
    const api = fakeApi({
      collections_list: vi.fn().mockResolvedValue({ ok: true, collections: [{ id: 'c0', name: 'Travel', description: '', archived: false }] }),
      collection_share_choose_folder: vi.fn().mockResolvedValue({ ok: true, token: 'tok', path: 'C:\\OneDrive\\Family' }),
      collection_share_join: vi.fn().mockResolvedValue({ ...OWNER, role: 'member', is_owner: false, collection_id: 'c1', message: 'You joined Family.' }),
      collection_share_members: vi.fn().mockResolvedValue({ ...OWNER, role: 'member', is_owner: false }),
    });
    render(WorkspacePages, { kind: 'collections', onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Join a shared collection' }));
    const sheet = await screen.findByRole('dialog', { name: 'Join a shared collection' });
    await fireEvent.click(within(sheet).getByRole('button', { name: 'Choose folder' }));
    await within(sheet).findByText('C:\\OneDrive\\Family');
    await fireEvent.input(passwordInputs()[0], { target: { value: 'correct horse battery 7!' } });
    await fireEvent.click(within(sheet).getByRole('button', { name: 'Join' }));
    await waitFor(() => expect(api.collection_share_join).toHaveBeenCalledWith('tok', 'correct horse battery 7!', ''));
    expect(await screen.findByRole('dialog', { name: 'Share “Family”' })).toBeInTheDocument();
    expect(api.collections_list.mock.calls.length).toBeGreaterThan(1); // the list shows the new collection
  });

  it('opens the Share section from a collection row', async () => {
    fakeApi({
      collections_list: vi.fn().mockResolvedValue({ ok: true, collections: [{ id: 'c1', name: 'Family', description: '', archived: false }] }),
      collection_share_members: vi.fn().mockResolvedValue(UNSHARED),
    });
    render(WorkspacePages, { kind: 'collections', onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Share' }));
    expect(await screen.findByRole('dialog', { name: 'Share “Family”' })).toBeInTheDocument();
  });
});
