/**
 * Shared focus handling for every modal dialog and sheet: `use:dialog` or `use:dialog={{ onescape }}`.
 * - Tab and Shift+Tab stay inside the topmost dialog (keyboard and screen-reader users cannot wander into the
 *   list or sidebar behind the scrim).
 * - On open, focus goes to the first editable field (else the first control) unless the dialog already focused
 *   something inside itself.
 * - On close, focus returns to the element that opened the dialog.
 * - With `onescape`, Esc closes the topmost dialog (only for dialogs that do not handle Esc themselves).
 */
const stack = [];

const FOCUSABLE = 'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';
const FIELDS = 'input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([readonly]), textarea:not([readonly]), select';

function usable(el) {
  return !el.disabled && !el.closest('[inert]') && !el.closest('[hidden]') && el.getAttribute('aria-hidden') !== 'true';
}

export function focusablesIn(node) {
  return [...node.querySelectorAll(FOCUSABLE)].filter(usable);
}

export function dialog(node, options = {}) {
  let opts = options ?? {};
  const opener = document.activeElement;
  const entry = { node };
  stack.push(entry);
  const top = () => stack[stack.length - 1] === entry;

  function onkeydown(event) {
    if (!top()) return;
    if (event.key === 'Escape' && opts.onescape && !event.defaultPrevented) {
      event.preventDefault();
      opts.onescape();
      return;
    }
    if (event.key !== 'Tab') return;
    const items = focusablesIn(node);
    if (!items.length) { event.preventDefault(); node.focus?.(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (!node.contains(active)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
    else if (event.shiftKey && (active === first || active === node)) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && active === last) { event.preventDefault(); first.focus(); }
  }

  const timer = setTimeout(() => {
    const active = document.activeElement;
    if (node.contains(active) && active !== node) return; // the dialog chose its own first focus
    const target = [...node.querySelectorAll(FIELDS)].find(usable) ?? focusablesIn(node)[0];
    if (target) target.focus();
    else if (!node.contains(active)) {
      if (!node.hasAttribute('tabindex')) node.setAttribute('tabindex', '-1');
      node.focus();
    }
  }, 0);

  document.addEventListener('keydown', onkeydown);
  return {
    update(next) { opts = next ?? {}; },
    destroy() {
      clearTimeout(timer);
      document.removeEventListener('keydown', onkeydown);
      const at = stack.indexOf(entry);
      if (at >= 0) stack.splice(at, 1);
      const active = document.activeElement;
      const lost = !active || active === document.body || node.contains(active) || !active.isConnected;
      if (lost && opener?.isConnected && typeof opener.focus === 'function') opener.focus();
    },
  };
}
