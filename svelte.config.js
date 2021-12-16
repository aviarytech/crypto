import adapter from '@sveltejs/adapter-auto';
import preprocess from 'svelte-preprocess';
import path from 'path';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	// Consult https://github.com/sveltejs/svelte-preprocess
	// for more information about preprocessors
	preprocess: preprocess(),

	kit: {
		adapter: adapter(),
		package: {
			exports: (file) => file.includes('index.ts')
		},
		// hydrate the <div id="svelte"> element in src/app.html
		target: '#svelte',
		vite: {
			resolve: {
				alias: { '@aviarytech/crypto': path.resolve('src/lib') }
			},
			optimizeDeps: {
				include: [
					'@stablelib/ed25519',
					'@stablelib/x25519',
					'@stablelib/xchacha20poly1305',
					'buffer/index.js',
					'b58',
					'@stablelib/aes-kw',
					'jsonld',
					'noble-secp256k1'
				]
			}
		}
	}
};

export default config;
