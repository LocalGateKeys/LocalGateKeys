/** Printing a page that exists only while the system print dialog is open (the emergency kit, the shard sheet).
 *  The page is moved under <body> so `@media print` can hide everything else; it prints after two animation
 *  frames (laid out and painted) and reports `ondone` on `afterprint`, or after a long fallback timer because
 *  some hosts return from print() before the dialog closes.
 *  Every printable page's root carries the shared class `print-portal`, and its print CSS hides only
 *  `body > :not(.print-portal)`: a rule naming its own class would also hide the other pages' portals
 *  (component CSS applies whether or not the component is mounted), so they would print blank. */

export const PRINT_PORTAL_CLASS = 'print-portal';

export const PRINT_FALLBACK_MS = 5 * 60 * 1000;

/** Svelte action: move the node under <body>; it is removed again on unmount. */
export function portal(node) {
  document.body.appendChild(node);
  return { destroy() { node.remove(); } };
}

/** Open the print dialog once the page is painted; returns the cleanup for `onMount`. */
export function printWhenPainted(ondone) {
  let finished = false;
  let timer = 0;
  let frame = 0;
  const finish = () => {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    cancelAnimationFrame(frame);
    window.removeEventListener('afterprint', finish);
    ondone?.();
  };
  window.addEventListener('afterprint', finish);
  frame = requestAnimationFrame(() => {
    frame = requestAnimationFrame(() => {
      try {
        window.print();
        if (!finished) timer = setTimeout(finish, PRINT_FALLBACK_MS);
      } catch {
        finish(); // no dialog available: nothing to print
      }
    });
  });
  return () => {
    finished = true;
    clearTimeout(timer);
    cancelAnimationFrame(frame);
    window.removeEventListener('afterprint', finish);
  };
}
