import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Served by the Attack Service at /static/learn/. Fonts and images are never inlined: the Academy CSP only allows 'self'.
export default defineConfig({
  base: '/static/learn/',
  plugins: [react(), tailwindcss()],
  build: { outDir: 'dist', sourcemap: false, assetsInlineLimit: 0, cssCodeSplit: false },
})
