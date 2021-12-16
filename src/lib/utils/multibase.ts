import {
	SECP256K1_MULTICODEC_IDENTIFIER,
	ED25519_MULTICODEC_IDENTIFIER,
	VARIABLE_INTEGER_TRAILING_BYTE
} from '$lib/constants.js';
import { base58 } from '$lib/utils/encoding.js';

export const getMultibaseFingerprintFromPublicKeyBytes = (
	publicKey: Uint8Array,
	identifier = ED25519_MULTICODEC_IDENTIFIER | SECP256K1_MULTICODEC_IDENTIFIER
): string => {
	const buffer = new Uint8Array(2 + publicKey.length);
	buffer[0] = identifier;
	buffer[1] = VARIABLE_INTEGER_TRAILING_BYTE;
	buffer.set(publicKey, 2);
	return `z${base58.encode(buffer)}`;
};
