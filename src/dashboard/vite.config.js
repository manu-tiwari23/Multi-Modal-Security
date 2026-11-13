import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    allowedHosts: [
      'powdered-duffel-citrus.ngrok-free.dev',
      '.ngrok-free.dev',
      '.ngrok.app',
      '.ngrok-free.app',
    ],
    proxy: {
      '/api': {
        target: process.env.MMS_API_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
