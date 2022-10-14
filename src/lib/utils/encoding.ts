import b58 from 'b58';
import { Buffer } from 'buffer/index.js';

export const base64 = {
	encode: (unencoded: any): string => {
		return Buffer.from(unencoded || '').toString('base64');
	},
	decode: (encoded: any): Uint8Array => {
		return new Uint8Array(Buffer.from(encoded || '', 'base64').buffer);
	}
};

export const utf8 = {
	encode: (unencoded: string): Uint8Array => {
		return new TextEncoder().encode(unencoded)
	},
	decode: (encoded: Uint8Array): string => {
		return new TextDecoder().decode(encoded);
	} 
}

export const base64url = {
	encode: (unencoded: any): string => {
		var encoded = base64.encode(unencoded);
		return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
	},
	decode: (encoded: any): Uint8Array => {
		encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');
		while (encoded.length % 4) encoded += '=';
		return base64.decode(encoded);
	}
};

export const base58 = {
	encode: (unencoded: Uint8Array): string => {
		return b58.encode(unencoded);
	},
	decode: (encoded: string): Uint8Array => {
		try {
			return b58.decode(encoded);
		} catch (e) {
			console.error(e);
		}
	}
};
