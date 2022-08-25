import { sveltekit } from '@sveltejs/kit/vite';
import path from 'path';

/** @type {import('vite').UserConfig} */
const config = {
	plugins: [sveltekit()],
	resolve: {
		alias: {
			$lib: path.resolve('./src/lib')
		}
	},
	optimizeDeps: {
		include: [
			'@stablelib/ed25519',
			'@stablelib/x25519',
			'@stablelib/random',
			'@stablelib/xchacha20poly1305',
			'buffer/index.js',
			'b58',
			'@stablelib/aes-kw',
			'jsonld',
			'noble-secp256k1'
		]
	}
};

export default config;
