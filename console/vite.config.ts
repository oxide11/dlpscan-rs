import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'

// Static output only — no Node runtime in production. The bundle is served by
// the nginx front door today (deploy/nginx/Dockerfile) and is ready to be
// embedded into the siphon-api binary via rust-embed.
export default defineConfig({
  // Absolute, not './'. The console is served at the origin root and its
  // routes are real paths, so a relative base would resolve assets against
  // `/findings` rather than `/` and 404 on every deep link or refresh.
  base: '/',
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
