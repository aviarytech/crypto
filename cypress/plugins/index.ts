import path from 'path';
import webpackPreprocessor from '@cypress/webpack-preprocessor';
import { startDevServer } from '@cypress/webpack-dev-server';

module.exports = (on) => {
	let options = webpackPreprocessor.defaultOptions;
	options.webpackOptions.module.rules.push({
		test: /\.js$/,
		resolve: {
			fullySpecified: false
		}
	});
	options.webpackOptions.module.rules.push({
		test: /\.ts?$/,
		use: 'ts-loader',
		resolve: {
			fullySpecified: false
		},
		exclude: /node_modules/
	});
	options.webpackOptions.resolve = {
		extensions: ['.js', '.jsx', '.ts', '.tsx']
		// alias: {
		// 	'@aviarytech/crypto': path.resolve('./src/lib')
		// }
	};
	// let outputOptions = {};
	// Object.defineProperty(options.webpackOptions, 'output', {
	// 	get: () => {
	// 		return { ...outputOptions, publicPath: '/' };
	// 	},
	// 	set: function (x) {
	// 		outputOptions = x;
	// 	}
	// });
	on('file:preprocessor', webpackPreprocessor(options));
	on('dev-server:start', (options) => {
		return startDevServer({
			options,
			webpackConfig: options.webpackConfig
		});
	});
};
