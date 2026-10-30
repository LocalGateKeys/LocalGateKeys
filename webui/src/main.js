import { mount } from 'svelte';
import './styles/tokens.css';
import './styles/glass.css';
import { loadLocale } from './lib/i18n.svelte.js';
import App from './App.svelte';

await loadLocale();

export default mount(App, { target: document.getElementById('app') });
