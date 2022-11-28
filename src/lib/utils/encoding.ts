// @ts-ignore
import b58 from 'b58';
import { base58btc } from "multiformats/bases/base58"
import { Buffer } from 'buffer/index.js';

// multibase base58-btc header
export const MULTIBASE_BASE58BTC_HEADER = 'z';
// multicodec ed25519-pub header as varint
export const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01]);
// multicodec ed25519-priv header as varint
export const MULTICODEC_ED25519_PRIV_HEADER = new Uint8Array([0x80, 0x26]);
// multicodec x25519-pub header as varint
export const MULTICODEC_X25519_PUB_HEADER = new Uint8Array([0xec, 0x01]);
// multicodec x25519-priv header as varint
export const MULTICODEC_X25519_PRIV_HEADER = new Uint8Array([0x82, 0x26]);

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
		return b58.decode(encoded);
	}
};

export const multibase = {
	encode: (header: Uint8Array, val: Uint8Array): string => {
		const mcBytes = new Uint8Array(header.length + val.length);
		mcBytes.set(header)
		mcBytes.set(val, header.length)
		return MULTIBASE_BASE58BTC_HEADER + base58btc.encode(val)
	},
	decode: (header: Uint8Array, val: string): Uint8Array => {
		const mcValue = base58.decode(val.substring(1))
		for (let i = 0; i < header.length; i++) {
			if (mcValue[i] !== header[i]) {
				throw new Error('Multibase value does not have expected header.')
			}
		}
		return mcValue.slice(header.length)
	}
}
