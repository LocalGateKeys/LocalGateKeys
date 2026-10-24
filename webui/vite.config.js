import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// The build is loaded from disk by the WebView2 host: relative paths, no
// inline scripts (the CSP in index.html allows only 'self' scripts).
export default defineConfig({
  base: './',
  plugins: [svelte(), svelteTesting()],
  // The site-logo set lives with the Python assets (one copy for desktop and iOS).
  server: { fs: { allow: ['.', '../src/localvault/assets/site_logos.json', '../src/localvault/assets/localgatekeys_mark.png'] } },
  build: {
    outDir: '../src/localvault/assets/ui',
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    // Two pages: the main window and the small popup a fill uses (unlock, choose an account).
    rollupOptions: { input: { main: 'index.html', popup: 'popup.html' } },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.test.js'],
  },
});
