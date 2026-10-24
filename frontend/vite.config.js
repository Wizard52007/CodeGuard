import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// The FastAPI backend. Override with CODEGUARD_API_TARGET when it runs elsewhere.
const apiTarget = process.env.CODEGUARD_API_TARGET || 'http://127.0.0.1:8000'

// Same-origin proxy so the browser needs no CORS configuration.
const proxy = {
  '^/(health|evaluate|demo)(/|$)': {
    target: apiTarget,
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  build: { chunkSizeWarningLimit: 4000 },
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/setup.js'],
    css: false,
    restoreMocks: true,
  },
})
