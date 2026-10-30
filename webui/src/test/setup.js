import '@testing-library/jest-dom/vitest';
import { setMessages } from '../lib/i18n.svelte.js';
import enCatalog from '../../../src/localvault/assets/i18n/en.json';

setMessages('en', enCatalog);
