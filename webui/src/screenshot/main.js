// Screenshot harness entry (dev-only, served by `npm run screens`): installs the demo bridge, then
// mounts the real root component exactly as src/main.js / src/popup.js do. The URL picks the screen:
//   ?screen=home|item|edit|generator|palette|new|quick|trash|unlock|security|health|settings|sync|licence
//   &id=<item id> (item, edit)   &filter=<health filter> (health)   &section=<key> (settings)
//   ?popup=unlock|fill|passkey   the small fill popup instead of the main window
//   &theme=dark|light|system (default dark)   &glass=on keeps the page transparent like the real window
import { mount } from 'svelte';
import '../styles/tokens.css';
import '../styles/glass.css';
import App from '../App.svelte';
import PopupApp from '../PopupApp.svelte';
import { LOGINS, TYPED } from './demoData.js';
import { createMockApi, emit } from './mockApi.js';

const params = new URLSearchParams(window.location.search);
const screen = params.get('screen') ?? 'home';
const popup = params.get('popup');
const theme = params.get('theme') ?? 'dark';

// A browser has no Mica behind the page: use the app's own opaque fallback (glass.css, data-glass="off").
if (params.get('glass') !== 'on') document.documentElement.dataset.glass = 'off';

const unlocked = popup ? popup !== 'unlock' : screen !== 'unlock';
window.pywebview = { api: createMockApi({ unlocked, appearance: theme }) };

/** Resolve with the first element matching `test` once it renders (or null after a few seconds). */
function waitFor(test, timeout = 5000) {
  return new Promise((resolve) => {
    const start = performance.now();
    const tick = () => {
      const found = test();
      if (found) resolve(found);
      else if (performance.now() - start > timeout) {
        console.warn('[screenshot harness] element not found for', screen);
        resolve(null);
      } else setTimeout(tick, 50); // not requestAnimationFrame: it pauses in a hidden or background tab
    };
    tick();
  });
}

const byText = (selector, text) => () => [...document.querySelectorAll(selector)].find((el) => el.textContent.trim() === text);

function itemRow(id) {
  const item = [...LOGINS, ...TYPED].find((i) => i.id === id) ?? LOGINS[0];
  return () => [...document.querySelectorAll('[role="option"]')]
    .find((row) => row.querySelector('.title')?.textContent.replace(/^★ /, '') === item.title);
}

// Pages Home opens itself from Python's "navigate" event: start there through the app's own hand-over
// (Home reads lgk.afterUnlock when it mounts).
const ROUTES = {
  security: { route: 'security' },
  health: { route: 'health', params: { filter: params.get('filter') } },
  settings: { route: 'settings', params: { section: params.get('section') } },
  sync: { route: 'sync' },
  licence: { route: 'licence' },
  new: { route: 'new-item' },
  quick: { route: 'quick-access' },
  reminders: { route: 'reminders' },
};
if (!popup && ROUTES[screen]) sessionStorage.setItem('lgk.afterUnlock', JSON.stringify(ROUTES[screen]));

if (popup) {
  // src/popup.js paints the popup opaque the same way.
  document.documentElement.dataset.glass = 'off';
  mount(PopupApp, { target: document.getElementById('app') });
  if (popup === 'fill') {
    setTimeout(() => emit('modal.request', {
      id: 'demo-choose', kind: 'choose', surface: 'popup', title: 'Choose account for this app', message: '',
      options: [
        { id: 'steam', label: 'Steam', detail: 'quiet_otter_42' },
        { id: 'steam-2', label: 'Steam (family)', detail: 'morgan.family.games' },
      ],
    }), 50);
  } else if (popup === 'passkey') {
    setTimeout(() => emit('modal.request', {
      id: 'demo-passkey', kind: 'passkey', surface: 'popup', mode: 'get',
      accounts: [{ item_id: 'passkey-github', title: 'GitHub passkey', user_name: 'alex-morgan-dev' }],
      text: { title: 'Sign in with a passkey?', body: 'Site: github.com\nPage: https://github.com\nProfile: Personal\nAccount: GitHub passkey',
        approve_label: 'Sign in', browser_label: 'Use browser or another device', cancel_label: 'Cancel' },
    }), 50);
  }
} else {
  mount(App, { target: document.getElementById('app') });
  if (screen === 'item' || screen === 'edit') {
    waitFor(itemRow(params.get('id') ?? 'github')).then((row) => {
      row?.click();
      if (screen === 'edit') row?.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
    });
  } else if (screen === 'generator') {
    waitFor(byText('button', 'Open the password generator')).then((button) => button?.click());
  } else if (screen === 'trash') {
    // Put two items in the trash first so the page has rows.
    (async () => {
      await window.pywebview.api.item_trash({ source: 'credential', id: 'figma', kind: 'web' });
      await window.pywebview.api.item_trash({ source: 'typed', id: 'wifi-home', kind: 'wifi' });
      (await waitFor(byText('.sidebar button', 'Trash')))?.click();
    })();
  } else if (screen === 'palette') {
    waitFor(() => document.querySelector('[role="option"]')).then(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }));
    });
  }
}
