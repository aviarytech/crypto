import adapter from '@sveltejs/adapter-auto';
import preprocess from 'svelte-preprocess';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: preprocess(),

	kit: {
		adapter: adapter()
		// package: {
		// 	exports: (file) => file.includes('index.ts')
		// }
		// vite: {
		// 	optimizeDeps: {
		// 		include: [
		// 			'@stablelib/ed25519',
		// 			'@stablelib/x25519',
		// 			'@stablelib/xchacha20poly1305',
		// 			'buffer/index.js',
		// 			'b58',
		// 			'@stablelib/aes-kw',
		// 			'jsonld',
		// 			'noble-secp256k1'
		// 		]
		// 	}
		// }
	}
};

export default config;
