import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'

// Static output only — the bundle is embedded into the siphon-api binary via
// rust-embed, so there is no Node runtime in production. `base` is relative so
// the same build serves from `/` or from a sub-path without a rebuild.
export default defineConfig({
  base: './',
  plugins: [
    tanstackRouter({ target: 'react', autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  // The API is reached under `/api`, never at the origin root.
  //
  // This is not cosmetic. siphon-api serves `POST /scan`, and the console has a
  // `/scan` *route* — served from the same origin once the bundle is embedded
  // in the binary, those are the same path, separated only by HTTP method. That
  // is a collision waiting to be tripped by a preflight, a redirect, or a
  // reverse proxy that normalises methods. Prefixing the API removes it, and it
  // matches how the stack is already deployed (`/ui/` + `/api/` behind Nginx).
  server: {
    proxy: {
      '/api': {
        target: process.env.SIPHON_API ?? 'http://127.0.0.1:8080',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false },
})
