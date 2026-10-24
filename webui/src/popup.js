import { mount } from 'svelte';
import './styles/tokens.css';
import './styles/glass.css';
import PopupApp from './PopupApp.svelte';

// The popup has no Windows glass backdrop: paint an opaque background so nothing shows through.
document.documentElement.dataset.glass = 'off';

export default mount(PopupApp, { target: document.getElementById('app') });
