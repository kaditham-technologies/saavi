import { defineConfig } from 'vite';
import { version } from './package.json';

export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(version) },
  // Tauri expects a fixed port and fails if it is taken.
  server: { port: 5173, strictPort: true },
  build: {
    target: 'es2022',
    rollupOptions: {
      output: {
        // Keep OpenPGP.js (LGPL) as its own replaceable file rather than
        // inlining it into Saavi's MIT code — see THIRD-PARTY-NOTICES.md.
        manualChunks: (id) => (id.includes('/node_modules/openpgp/') ? 'openpgp' : undefined),
      },
    },
  },
});
