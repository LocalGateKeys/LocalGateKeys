import { mount } from 'svelte';
import './styles/tokens.css';
import './styles/glass.css';
import { loadLocale } from './lib/i18n.svelte.js';
import PopupApp from './PopupApp.svelte';

// The popup has no Windows glass backdrop: paint an opaque background so nothing shows through.
document.documentElement.dataset.glass = 'off';

await loadLocale();

export default mount(PopupApp, { target: document.getElementById('app') });
