// The demo vault the screenshot harness shows. Everything here is fictional: example.com
// addresses, a test card number, made-up passwords and well-known public demo TOTP secrets.
// Ids of the logins match the recorded health payloads in snapshots.js.

export const PROFILE = { id: 'demo-personal', name: 'Personal', color: '#2b6fe0' };
export const OTHER_PROFILES = [{ id: 'demo-work', name: 'Work', color: '#1f7a6c' }];

export const COLLECTIONS = [
  { id: 'work', name: 'Work' },
  { id: 'finance', name: 'Money' },
];

const DAY = 86400;

/** Website logins (source "credential", kind "web"). age: days since the last change. */
export const LOGINS = [
  { id: 'github', title: 'GitHub', username: 'alex-morgan-dev', origin: 'https://github.com', favorite: true,
    password: 'Vq7#mT2!pLx9@wRz4$Kd', totp: 'JBSWY3DPEHPK3PXP', age: 12, collection: 'work', tags: ['work', 'dev'],
    notes: 'Recovery codes are saved below. Personal access tokens rotate every 90 days.', recovery: 8 },
  { id: 'google', title: 'Google', username: 'alex.morgan@example.com', origin: 'https://accounts.google.com', favorite: true,
    password: 'hollow-Raven-quartz-61-tide', totp: 'KRSXG5CTMVRXEZLUKN2XAZLSOQ', age: 40, tags: ['email'],
    notes: 'Main account. Backup phone ends in 0142.', recovery: 10 },
  { id: 'netflix', title: 'Netflix', username: 'alex.morgan@example.com', origin: 'https://www.netflix.com',
    password: '9fK!c2Lr#Wq8zT6m', age: 95, tags: ['streaming'], notes: 'Standard plan, shared with the household.' },
  { id: 'dropbox', title: 'Dropbox', username: 'alex.morgan@example.com', origin: 'https://www.dropbox.com',
    password: 'p4R$e8Nw!x2Ub7Qj', totp: 'MFRGGZDFMZTWQ2LKNNWG23TPOA', age: 61, notes: '' },
  { id: 'paypal', title: 'PayPal', username: 'alex.morgan@example.com', origin: 'https://www.paypal.com', favorite: true,
    password: 'Gx3@uV9!rK6#tM1w', totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY', age: 20, collection: 'finance', tags: ['money'], notes: '' },
  { id: 'spotify', title: 'Spotify', username: 'alexmorgan.music', origin: 'https://accounts.spotify.com',
    password: 'Lantern-Purple-88', age: 150, tags: ['streaming'], notes: '' },
  { id: 'steam', title: 'Steam', username: 'quiet_otter_42', origin: 'https://store.steampowered.com',
    password: 'zH7#nQ2@kW9!fB4x', totp: 'ONSWG4TFOQYTEMZUGU3DOOBZHA', age: 33, tags: ['games'], notes: '' },
  { id: 'discord', title: 'Discord', username: 'alex.morgan@example.com', origin: 'https://discord.com',
    password: 'Lantern-Purple-88', age: 210, tags: ['games'], notes: '' },
  { id: 'reddit', title: 'Reddit', username: 'quiet_otter_42', origin: 'https://www.reddit.com',
    password: 'otter123', age: 300, notes: '' },
  { id: 'notion', title: 'Notion', username: 'alex.morgan@example.com', origin: 'https://www.notion.so',
    password: 'Wm8!tC3#yP6@qL2v', totp: 'NBSWY3DPO5XXE3DEEBQWY3DQNA', age: 8, collection: 'work', tags: ['work'], notes: '' },
  { id: 'figma', title: 'Figma', username: 'alex.morgan@example.com', origin: 'https://www.figma.com',
    password: 'eB5$kR9!mX2#wN7s', age: 70, collection: 'work', tags: ['work'], notes: '' },
  { id: 'airbnb', title: 'Airbnb', username: 'alex.morgan@example.com', origin: 'https://www.airbnb.com',
    password: 'fT6@hJ1!pZ8#cV3q', age: 420, tags: ['travel'], notes: '' },
  { id: 'proton', title: 'Proton Mail', username: 'alex.morgan@proton.example', origin: 'https://account.proton.me',
    password: 'violet-orbit-cactus-91-ember', totp: 'IFBEGRCFIZDUQSKKJNGE2TSPKA', age: 5, tags: ['email'], notes: '' },
];

/** Typed items (source "typed"). fields: the detail rows typed_detail returns, in schema order. */
export const TYPED = [
  { id: 'card-visa', kind: 'card', title: 'Visa Debit', target: 'Visa', age: 3, collection: 'finance', favorite: false,
    fields: [
      { name: 'cardholder', label: 'Cardholder', value: 'Alex Morgan', protected: false, present: true },
      { name: 'number', label: 'Card number', value: null, protected: true, present: true },
      { name: 'expiry', label: 'Expiry', value: '08/29', protected: false, present: true },
      { name: 'cvv', label: 'CVV', value: null, protected: true, present: true },
      { name: 'pin', label: 'PIN', value: null, protected: true, present: false },
      { name: 'notes', label: 'Notes', value: 'Contactless limit raised for travel.', protected: false, present: true },
    ],
    secrets: { number: '4242 4242 4242 4242', cvv: '123' } },
  { id: 'identity-alex', kind: 'identity', title: 'Alex Morgan', target: '', age: 54, favorite: false,
    fields: [
      { name: 'address', label: 'Address', value: '221 Example Street, Apt 4', protected: false, present: true },
      { name: 'city', label: 'City', value: 'Springfield', protected: false, present: true },
      { name: 'country', label: 'Country', value: 'United States', protected: false, present: true },
      { name: 'email', label: 'Email', value: 'alex.morgan@example.com', protected: false, present: true },
      { name: 'name', label: 'Full name', value: 'Alex Morgan', protected: false, present: true },
      { name: 'phone', label: 'Phone', value: '+1 555 0142', protected: false, present: true },
      { name: 'postal_code', label: 'Postal code', value: '01234', protected: false, present: true },
    ] },
  { id: 'note-router', kind: 'note', title: 'Router admin notes', target: '', age: 17, favorite: false,
    fields: [
      { name: 'body', label: 'Note body', value: null, protected: true, present: true },
    ],
    secrets: { body: 'Admin page: http://192.168.1.1\nFirmware updated October 2026.\nGuest network turns off at midnight.' } },
  { id: 'passkey-github', kind: 'passkey', title: 'GitHub passkey', target: 'github.com', age: 26, collection: 'work', favorite: false,
    fields: [
      { name: 'rp_name', label: 'Site name', value: 'GitHub', protected: false, present: true },
      { name: 'relying_party_id', label: 'Relying party id', value: 'github.com', protected: false, present: true },
      { name: 'user_name', label: 'Account', value: 'alex-morgan-dev', protected: false, present: true },
      { name: 'private_key', label: 'Private key', value: null, protected: true, present: true },
      { name: 'algorithm', label: 'Algorithm', value: 'ES256', protected: false, present: true },
      { name: 'created', label: 'Created', value: '2026-09-26', protected: false, present: true },
    ],
    secrets: { private_key: '-----BEGIN PRIVATE KEY-----\n(demo key, not real)\n-----END PRIVATE KEY-----' } },
  { id: 'wifi-home', kind: 'wifi', title: 'Home Wi-Fi', target: 'Morgan-Home-5G', age: 88, favorite: false,
    fields: [
      { name: 'ssid', label: 'Network name', value: 'Morgan-Home-5G', protected: false, present: true },
      { name: 'password', label: 'Password', value: null, protected: true, present: true },
      { name: 'security', label: 'Security type', value: 'wpa3', protected: false, present: true },
      { name: 'hidden', label: 'Hidden network', value: false, protected: false, present: true },
    ],
    secrets: { password: 'quiet-maple-harbor-27' } },
];

/** Typed kinds in sidebar order with their plural labels (shell/nav.py). */
export const TYPE_NAV = [
  ['web', 'Logins', 'row.websiteGlobe'],
  ['identity', 'Identities', 'row.identity'],
  ['note', 'Secure notes', 'row.note'],
  ['passkey', 'Passkeys', 'nav.tools'],
  ['card', 'Cards', 'nav.tools'],
  ['wifi', 'Wi-Fi', 'nav.tools'],
];

export const KIND_LABELS = {
  web: 'Website login', desktop: 'Desktop login', card: 'Payment card', identity: 'Identity', note: 'Note',
  passkey: 'Passkey', wifi: 'Wi-Fi network',
};

/** Items with a reminder in the next 30 days (the "Expiring" chip). */
export const EXPIRING = ['netflix', 'card-visa'];

export const WORDS = ['amber', 'bridge', 'cactus', 'delta', 'ember', 'falcon', 'garnet', 'harbor', 'island', 'juniper',
  'kettle', 'lantern', 'meadow', 'nickel', 'orbit', 'pepper', 'quartz', 'raven', 'saddle', 'timber', 'umbra', 'velvet',
  'willow', 'yonder', 'zephyr', 'copper', 'marble', 'thistle', 'canyon', 'mosaic'];

export const ageSeconds = (days) => days * DAY;
