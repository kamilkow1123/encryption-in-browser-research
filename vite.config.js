import {resolve} from 'path'
import {defineConfig} from 'vite'

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        'open-pgp': resolve(__dirname, 'examples/open-pgp.html'),
        'web-crypto-api': resolve(__dirname, 'examples/web-crypto-api.html'),
        forge: resolve(__dirname, 'examples/forge.html'),
      },
    },
  },
})
