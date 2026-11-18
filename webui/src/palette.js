import { mount } from 'svelte';
import './styles/tokens.css';
import './styles/glass.css';
import { loadLocale } from './lib/i18n.svelte.js';
import PaletteApp from './PaletteApp.svelte';

// The palette has no Windows glass backdrop: paint an opaque background so nothing shows through.
document.documentElement.dataset.glass = 'off';

await loadLocale();

export default mount(PaletteApp, { target: document.getElementById('app') });
