import { mount } from 'svelte';
import './styles/tokens.css';
import './styles/glass.css';
import App from './App.svelte';

export default mount(App, { target: document.getElementById('app') });
