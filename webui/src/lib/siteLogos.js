// Item tiles: the bundled site logo for a login's origin, else a glyph for the
// item's kind. The logo set is built by scripts/build_site_logos.mjs and ships
// with the app; nothing is fetched.
import data from '../../../src/localvault/assets/site_logos.json';

/** The logo for an origin ({ slug, title, hex, path, light }) or null. A host
 *  matches a listed domain or any subdomain of it, never a lookalike
 *  (google.com.example.net has no logo). */
export function logoFor(origin, set = data) {
  let host;
  try { host = new URL(origin).hostname.toLowerCase().replace(/\.$/, ''); } catch { return null; }
  const labels = host.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const slug = set.domains[labels.slice(i).join('.')];
    const logo = slug && set.logos[slug];
    if (logo) return { slug, ...logo, light: isLight(logo.hex) };
  }
  return null;
}

/** True when a brand colour is light enough to need a dark glyph. */
export function isLight(hex) {
  const n = parseInt(hex.slice(1), 16);
  return (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255 > 0.7;
}

// 24x24 line glyphs (stroke, no fill), one per kind. Same meaning as the iPhone
// list's SF Symbols (ios/App/Vault/VaultListView.swift).
const G = {
  globe: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3',
  desktop: 'M3 5h18v11H3zM9 20h6M12 16v4',
  note: 'M6 3h9l4 4v14H6zM15 3v4h4M9 12h7M9 16h5',
  card: 'M3 6h18v12H3zM3 10h18M7 15h4',
  person: 'M4 5h16v14H4zM9.5 12a2 2 0 1 0 0-4a2 2 0 1 0 0 4M6.5 16c.6-1.6 1.6-2.4 3-2.4s2.4.8 3 2.4M14.5 9.5h3M14.5 13h3',
  bookmark: 'M7 3h10v18l-5-4l-5 4z',
  wifi: 'M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01',
  key: 'M8 15a4 4 0 1 0 0-8a4 4 0 1 0 0 8M11.5 11H21M18 11v3M15 11v2',
  bank: 'M3 9l9-5l9 5M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18',
  passkey: 'M9 11a3.5 3.5 0 1 0 0-7a3.5 3.5 0 1 0 0 7M3 20c.8-3.4 3-5.2 6-5.2c1.4 0 2.6.4 3.6 1.1M17.5 15a2 2 0 1 0 0-4a2 2 0 1 0 0 4M17.5 15v6M17.5 18.5h2',
  receipt: 'M6 3h12v18l-2-1.5l-2 1.5l-2-1.5l-2 1.5l-2-1.5L6 21zM9 8h6M9 12h6M9 16h3',
  shield: 'M12 3l7 3v6c0 4.2-2.9 7.6-7 9c-4.1-1.4-7-4.8-7-9V6zM9 12l2 2l4-4',
  repeat: 'M4 11V9a3 3 0 0 1 3-3h12l-3-3M20 13v2a3 3 0 0 1-3 3H5l3 3',
  doc: 'M6 3h9l4 4v14H6zM15 3v4h4',
};
const KIND = {
  web: ['globe', 'link'], desktop: ['desktop', 'link'], note: ['note', 'warning'], card: ['card', 'success'],
  bank_account: ['bank', 'success'], identity: ['person', 'identity'], bookmark: ['bookmark', 'link'],
  wifi: ['wifi', 'link'], ssh_key: ['key', 'link'], api_key: ['key', 'link'], passkey: ['passkey', 'link'],
  license: ['key', 'link'], purchase: ['receipt', 'success'], warranty: ['shield', 'link'],
  subscription: ['repeat', 'link'], document: ['doc', 'link'],
};

/** { path, tint } for a kind; tint names a CSS colour token. */
export function glyphFor(kind) {
  const [name, tint] = KIND[kind] ?? ['doc', 'link'];
  return { path: G[name], tint };
}
