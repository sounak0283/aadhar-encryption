import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Fixed port, not "whatever's free" — the backend's FRONTEND_ORIGIN (CORS
    // allowlist) has to match this exactly. strictPort means a second `npm run
    // dev` fails loudly instead of silently drifting to 5174/5175/etc., which
    // is what caused the CORS mismatches in the first place.
    port: 5173,
    strictPort: true,
  },
})
