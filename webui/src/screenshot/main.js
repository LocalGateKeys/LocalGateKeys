// Screenshot harness entry (dev-only, served by `npm run screens`): installs the demo bridge, then
// mounts the real root component exactly as src/main.js / src/popup.js do. The URL picks the screen:
//   ?screen=home|item|edit|generator|palette|new|scan|quick|trash|unlock|security|health|settings|sync|licence|connections
//   &lang=de|en-XA|... the webui's own strings in that language
//   &id=<item id> (item, edit)   &filter=<health filter> (health)   &section=<key> (settings)
//   ?popup=unlock|fill|passkey   the small fill popup instead of the main window
//   Feature pack (branch feature-pack), each opens straight on the new screen:
//     ?screen=developer                      Developer page: SSH agent running, keys, command line access with allowed items
//     ?screen=developer&git=on               ... with the "Use for Git signing" change preview open
//     ?screen=secretscan                     Developer page with the plain-secrets scan run (4 findings, no values shown)
//     ?screen=secretscan&rewrite=on          ... and the "Use references" preview for an imported .env file
//     ?screen=item&id=note-trip&reveal=on    Markdown note (headings, bold, lists, checklist, code, link); &formatting=off
//                                            shows the raw text (the "Show formatting" switch)
//     ?screen=item&id=wifi-home              Wi-Fi item with its "Show QR" dialog open (&qr=off leaves just the button)
//     ?screen=item&id=api-deploy&reveal=on   API key that is a JWT: revealed with the decoded token block
//     ?screen=item&id=ssh-laptop             SSH key item
//     ?screen=generator&mode=answer          password generator on the Answer tab (also mode=passphrase)
//     ?screen=recovery                       Backup & restore page with the "Print emergency kit" row
//     ?screen=kit                            the printed emergency kit itself, shown on screen (print styles applied)
//     ?screen=unlocking                      Unlocking page: key file + YubiKey set, remember, Windows Hello
//     ?screen=settings&section=unlocking     Settings > Unlocking
//     ?screen=unlock&factors=on              unlock screen asking for a key file (picker, remembered name) and a YubiKey
//     ?screen=unlock&factors=on&touch=on     ... with "Touch your YubiKey" and Cancel
//     ?screen=security                       Security check with the Not HTTPS, Passkey available and Plain secrets rows
//     ?screen=health&filter=http|passkey     health list on the new Not HTTPS / Passkey available filters
//   &rate=on   a Store build: the Settings "Rate" row, and the one-time rating prompt on home
//   &theme=dark|light|system (default dark)   &glass=on keeps the page transparent like the real window
import { mount } from 'svelte';
import '../styles/tokens.css';
import '../styles/glass.css';
import App from '../App.svelte';
import PopupApp from '../PopupApp.svelte';
import { LOGINS, TYPED } from './demoData.js';
import { createMockApi, emit } from './mockApi.js';
import { loadLocale } from '../lib/i18n.svelte.js';

const params = new URLSearchParams(window.location.search);
const screen = params.get('screen') ?? 'home';
const popup = params.get('popup');
const theme = params.get('theme') ?? 'dark';

// A browser has no Mica behind the page: use the app's own opaque fallback (glass.css, data-glass="off").
if (params.get('glass') !== 'on') document.documentElement.dataset.glass = 'off';

const unlocked = popup ? popup !== 'unlock' : screen !== 'unlock';
const factors = params.get('factors') === 'on' || screen === 'unlocking';
window.pywebview = { api: createMockApi({ unlocked, appearance: theme, factors }) };
if (params.get('formatting') === 'off') window.pywebview.api.notes_formatting_set(false);
// The generator remembers its tab in the mock; the URL picks it.
if (screen === 'generator' && params.get('mode')) window.pywebview.api.generator_generate({ mode: params.get('mode') });
// The emergency kit prints itself; keep it on the page instead (print styles are applied below).
if (screen === 'kit') window.print = () => {};
// &lang=de|en-XA|...: the webui's own strings in that language (texts Python sends stay in the mock's English).
const CATALOGS = import.meta.glob('../../../src/localvault/assets/i18n/*.json', { import: 'default' });
if (params.get('lang')) {
  const loader = CATALOGS[`../../../src/localvault/assets/i18n/${params.get('lang')}.json`];
  if (loader) {
    const base = window.pywebview.api;
    window.pywebview.api = new Proxy({}, { get: (_target, name) => (name === 'i18n_bundle'
      ? async () => ({ ok: true, lang: params.get('lang'), messages: await loader() }) : base[name]) });
  }
}
if (params.get('rate') === 'on') {
  const base = window.pywebview.api;
  const extra = {};
  window.pywebview.api = new Proxy({}, { get: (_target, name) => extra[name] ?? base[name] });
  const settingsPage = base.settings_page;
  extra.rating_prompt = async () => ({ ok: true, due: screen === 'home', title: 'Enjoying LocalGateKeys?', text: (
    'A rating on the Microsoft Store helps other people find LocalGateKeys.\n\nRate it now? This opens the '
    + 'Microsoft Store app. LocalGateKeys sends nothing, and won\'t ask again.') });
  extra.settings_page = async () => {
    const page = await settingsPage();
    for (const section of page.sections ?? []) {
      const at = section.rows.findIndex((row) => row.route === 'updates');
      if (at >= 0) section.rows.splice(at + 1, 0, { type: 'button', title: 'Rate LocalGateKeys',
        description: 'Tell others what you think on the Microsoft Store', label: 'Rate', route: 'rate', params: {}, primary: false });
    }
    return page;
  };
}

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
  scan: { route: 'scan-qr' },
  quick: { route: 'quick-access' },
  reminders: { route: 'reminders' },
  developer: { route: 'developer' },
  connections: { route: 'connections' },
  secretscan: { route: 'developer' },
  recovery: { route: 'recovery', params: { initial: params.get('initial') } },
  kit: { route: 'recovery' },
  unlocking: { route: 'hello' },
};
if (!popup && ROUTES[screen]) sessionStorage.setItem('lgk.afterUnlock', JSON.stringify(ROUTES[screen]));

if (params.get('lang')) await loadLocale();

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
      if (screen === 'item' && params.get('reveal') === 'on') {
        // Reveal each protected field (typed_reveal, which also returns the decoded JWT block).
        waitFor(() => document.querySelector('.text-btn')).then(() => {
          document.querySelectorAll('.text-btn').forEach((button) => button.click());
        });
      }
      if (screen === 'item' && params.get('qr') !== 'off') {
        waitFor(() => [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Show QR'))
          .then((button) => button?.click());
      }
    });
  } else if (screen === 'generator') {
    waitFor(byText('button', 'Generator')).then((button) => button?.click());
  } else if (screen === 'developer' && params.get('git') === 'on') {
    waitFor(byText('button', 'Use for Git signing')).then((button) => button?.click());
  } else if (screen === 'secretscan') {
    (async () => {
      (await waitFor(byText('button', 'Scan…')))?.click();
      (await waitFor(byText('button', 'Scan')))?.click();
      await waitFor(() => document.querySelector('[role="dialog"] .group .row'), 8000);
      if (params.get('rewrite') === 'on') (await waitFor(byText('button', 'Use references')))?.click();
    })();
  } else if (screen === 'kit') {
    (async () => {
      (await waitFor(byText('button', 'Print emergency kit…')))?.click();
      await waitFor(() => document.querySelector('.kit-portal article'));
      // The kit's layout lives in @media print rules: copy them to the screen so the kit shows as it prints.
      const rules = [];
      for (const sheet of document.styleSheets) {
        let list;
        try { list = sheet.cssRules; } catch { continue; }
        for (const rule of list) if (rule.media?.mediaText === 'print') for (const inner of rule.cssRules) rules.push(inner.cssText);
      }
      const style = document.createElement('style');
      style.textContent = `${rules.join(' ')} html, body { background: #fff !important; }`;
      document.head.append(style);
    })();
  } else if (screen === 'unlock' && params.get('touch') === 'on') {
    setTimeout(() => emit('factors.touch', { waiting: true }), 300);
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
