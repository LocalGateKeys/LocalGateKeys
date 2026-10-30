// Sidebar icons: 24x24 line drawings (stroke = currentColor), chosen by what the entry does or shows,
// never by its label (labels can be renamed or translated). Each value is a list of SVG elements.

const p = (d) => ({ tag: 'path', d });
const c = (cx, cy, r) => ({ tag: 'circle', cx, cy, r });
const r = (x, y, w, h, rx = 2) => ({ tag: 'rect', x, y, width: w, height: h, rx });

export const ICONS = {
  all: [r(3, 3, 7, 7), r(14, 3, 7, 7), r(3, 14, 7, 7), r(14, 14, 7, 7)],
  favorite: [p('M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8L3.5 9.7l5.9-.9z')],
  recent: [c(12, 12, 8.5), p('M12 7.5V12l3 2')],
  web: [c(12, 12, 8.5), p('M3.5 12h17'), p('M12 3.5c2.5 2.6 3.5 5.4 3.5 8.5s-1 5.9-3.5 8.5c-2.5-2.6-3.5-5.4-3.5-8.5s1-5.9 3.5-8.5z')],
  desktop: [r(3, 4, 18, 12), p('M8 20h8'), p('M12 16v4')],
  card: [r(2.5, 5.5, 19, 13), p('M2.5 10h19'), p('M6 15h4')],
  bank_account: [p('M3 9.5L12 4l9 5.5'), p('M4 20h16'), p('M6 10.5v7'), p('M10 10.5v7'), p('M14 10.5v7'), p('M18 10.5v7')],
  identity: [r(2.5, 5, 19, 14), c(8.5, 11, 2.2), p('M5.5 16.5c.6-1.6 1.7-2.4 3-2.4s2.4.8 3 2.4'), p('M14 10h4.5'), p('M14 13.5h3')],
  note: [p('M5 3.5h10l4 4v13H5z'), p('M15 3.5v4h4'), p('M8.5 12h7'), p('M8.5 15.5h5')],
  document: [p('M6 3.5h8l4 4v13H6z'), p('M14 3.5v4h4')],
  ssh_key: [r(3, 4.5, 18, 15), p('M7 10l2.5 2L7 14'), p('M11.5 15h5')],
  api_key: [p('M9 7l-5 5 5 5'), p('M15 7l5 5-5 5')],
  wifi: [p('M2.5 9a14 14 0 0 1 19 0'), p('M5.5 12.5a9.5 9.5 0 0 1 13 0'), p('M8.7 16a4.6 4.6 0 0 1 6.6 0'), c(12, 19.2, 0.6)],
  license: [c(12, 9, 5), p('M8.8 13l-1.3 7.5L12 18l4.5 2.5-1.3-7.5')],
  purchase: [p('M5 8h14l-1 12H6z'), p('M9 8V6.5a3 3 0 0 1 6 0V8')],
  warranty: [p('M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z'), p('M8.8 12.2l2.2 2.2 4.2-4.4')],
  subscription: [p('M19.5 9A8 8 0 0 0 5 7.2'), p('M4.5 3.5v4h4'), p('M4.5 15A8 8 0 0 0 19 16.8'), p('M19.5 20.5v-4h-4')],
  bookmark: [p('M6.5 3.5h11v17L12 16.5l-5.5 4z')],
  passkey: [c(8, 8, 3.5), p('M3 20c.4-3.6 2.4-5.5 5-5.5 1.3 0 2.4.4 3.3 1.2'), c(16.5, 13.5, 2.5), p('M16.5 16v5'), p('M16.5 18.5h2')],
  collection: [p('M3 6.5a1.5 1.5 0 0 1 1.5-1.5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18z')],
  view: [p('M3.5 5h17l-6.5 7.5V19l-4 1.5v-8z')],
  security: [p('M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z')],
  reminders: [p('M6.5 16V11a5.5 5.5 0 0 1 11 0v5l1.5 2H5z'), p('M10 20.5a2.2 2.2 0 0 0 4 0')],
  sync: [p('M19.5 9A8 8 0 0 0 5 7.2'), p('M4.5 3.5v4h4'), p('M4.5 15A8 8 0 0 0 19 16.8'), p('M19.5 20.5v-4h-4'), c(12, 12, 1.2)],
  connections: [r(2.5, 5, 13, 9), p('M5.5 17.5h7'), r(17, 8, 4.5, 11, 1.2), p('M19.2 16.5h.1')],
  licence: [r(3, 5, 18, 14), c(9, 12, 2.5), p('M13.5 10.5h4'), p('M13.5 13.5h3')],
  import_export: [p('M8 4v13'), p('M4.5 13.5L8 17l3.5-3.5'), p('M16 20V7'), p('M12.5 10.5L16 7l3.5 3.5')],
  scan_qr: [p('M4 8V4h4'), p('M16 4h4v4'), p('M20 16v4h-4'), p('M8 20H4v-4'), r(8, 8, 3, 3, 0.5), r(13, 8, 3, 3, 0.5), r(8, 13, 3, 3, 0.5), p('M13.5 13.5h2.5v2.5')],
  activity: [p('M3 12h4l2.5-6 5 12 2.5-6h4')],
  trash: [p('M4 6.5h16'), p('M9.5 6.5V4.5h5v2'), p('M6 6.5l1 13.5h10l1-13.5'), p('M10 10.5v6'), p('M14 10.5v6')],
  settings: [p('M18.71 10L21.26 10.41L21.26 13.59L18.71 14L18.16 15.33L19.68 17.43L17.43 19.68L15.33 18.16L14 18.71'
    + 'L13.59 21.26L10.41 21.26L10 18.71L8.67 18.16L6.57 19.68L4.32 17.43L5.84 15.33L5.29 14L2.74 13.59L2.74 10.41'
    + 'L5.29 10L5.84 8.67L4.32 6.57L6.57 4.32L8.67 5.84L10 5.29L10.41 2.74L13.59 2.74L14 5.29L15.33 5.84L17.43 4.32'
    + 'L19.68 6.57L18.16 8.67Z'), c(12, 12, 3)],
};

const ACTIONS = {
  security_health_clicked: 'security',
  reminders_clicked: 'reminders',
  sync_clicked: 'sync',
  connections_clicked: 'connections',
  licence_clicked: 'licence',
  import_export_clicked: 'import_export',
  scan_qr_clicked: 'scan_qr',
  activity_clicked: 'activity',
  trash_clicked: 'trash',
  settings_clicked: 'settings',
};

/** The icon key for a sidebar entry, or null when none fits (the entry then shows its first letter). */
export function navIconKey(entry) {
  if (!entry) return null;
  if (entry.action) return ACTIONS[entry.action] ?? null;
  const token = entry.token;
  if (token === null || token === undefined) return 'all';
  if (token.startsWith('collection:')) return 'collection';
  if (token.startsWith('view:')) return 'view';
  return Object.hasOwn(ICONS, token) ? token : null;
}
