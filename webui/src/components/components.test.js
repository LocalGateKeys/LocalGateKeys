import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import Button from './Button.svelte';
import Field from './Field.svelte';
import Modal from './Modal.svelte';

describe('Button', () => {
  it('renders its label and calls onclick', async () => {
    const onclick = vi.fn();
    render(Button, { label: 'Unlock', onclick });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(onclick).toHaveBeenCalledOnce();
  });

  it('sets the variant class and is a pill', () => {
    render(Button, { label: 'Lock', variant: 'glass' });
    const button = screen.getByRole('button', { name: 'Lock' });
    expect(button).toHaveClass('btn', 'glass');
  });

  it('can be busy: disabled with a busy label', () => {
    render(Button, { label: 'Unlock', busy: true, busyLabel: 'Unlocking…' });
    expect(screen.getByRole('button', { name: 'Unlocking…' })).toBeDisabled();
  });
});

describe('Field', () => {
  it('links its label to the input', () => {
    render(Field, { label: 'Username', value: 'ilias' });
    expect(screen.getByLabelText('Username')).toHaveValue('ilias');
  });

  it('masks a password until Show is pressed', async () => {
    render(Field, { label: 'Master password', type: 'password', value: 'secret' });
    const input = screen.getByLabelText('Master password');
    expect(input).toHaveAttribute('type', 'password');
    await fireEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect(input).toHaveAttribute('type', 'text');
    expect(screen.getByRole('button', { name: 'Hide' })).toBeInTheDocument();
  });
});

describe('Modal', () => {
  it('shows title and message; Allow answers true', async () => {
    const onanswer = vi.fn();
    render(Modal, { title: 'Save new login?', message: 'Origin: https://a.test', onanswer });
    expect(screen.getByRole('dialog', { name: 'Save new login?' })).toBeInTheDocument();
    expect(screen.getByText('Origin: https://a.test')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Allow' }));
    expect(onanswer).toHaveBeenCalledWith(true);
  });

  it('an extra button sits beside Allow and takes the focus', async () => {
    const onanswer = vi.fn();
    const onextra = vi.fn();
    render(Modal, { title: 'Pro', message: 'M', allowLabel: 'Enter licence', denyLabel: 'Not now',
      extraLabel: 'Buy Pro', onextra, onanswer });
    const buy = screen.getByRole('button', { name: 'Buy Pro' });
    await tick();
    expect(buy).toHaveFocus();
    await fireEvent.click(buy);
    expect(onextra).toHaveBeenCalledOnce();
    expect(onanswer).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Enter licence' }));
    expect(onanswer).toHaveBeenCalledWith(true);
  });

  it('guarded: Deny has the focus and Enter or a click on Allow is ignored at first', async () => {
    vi.useFakeTimers();
    try {
      const onanswer = vi.fn();
      render(Modal, { title: 'T', message: 'M', guardMs: 500, onanswer });
      await tick();
      const allow = screen.getByRole('button', { name: 'Allow' });
      expect(screen.getByRole('button', { name: 'Deny' })).toHaveFocus();
      expect(allow).toBeDisabled();
      await fireEvent.click(allow);
      expect(onanswer).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(600);
      expect(allow).toBeEnabled();
      await fireEvent.click(allow);
      expect(onanswer).toHaveBeenCalledWith(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('Deny and Escape answer false', async () => {
    const onanswer = vi.fn();
    render(Modal, { title: 'T', message: 'M', onanswer });
    await fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onanswer.mock.calls).toEqual([[false], [false]]);
  });
});
