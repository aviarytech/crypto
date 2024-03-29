import adapter from '@sveltejs/adapter-auto';
import preprocess from 'svelte-preprocess';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: preprocess(),

	kit: {
		adapter: adapter(),
		alias: {
			buffer: 'buffer/'
		},
		// package: {
		// 	exports: (file) => file.includes('index.ts')
		// }
		// vite: {
		// 	optimizeDeps: {
		// 		include: [
		// 			'@stablelib/ed25519',
		// 			'@stablelib/x25519',
		// 			'@stablelib/xchacha20poly1305',
		// 			'buffer',
		// 			'b58',
		// 			'@stablelib/aes-kw',
		// 			'jsonld',
		// 		]
		// 	}
		// }
	}
};

export default config;
