import { AESKW } from '@stablelib/aes-kw';
import { X25519KeyAgreementKey2019 } from '$lib/keypairs/X25519KeyAgreementKey2019.js';
import { base64url } from '$lib/utils/encoding.js';
import { deriveKey } from '$lib/JWE/ecdhkdf.js';
import { Buffer } from 'buffer/index.js';

export interface CreateKekOptions {
	keyData: Uint8Array;
}

export interface WrapKeyOptions {
	unwrappedKey: Uint8Array;
}

export interface UnwrapKeyOptions {
	wrappedKey: string; //base64url
}

export class KeyEncryptionKey {
	public aeskw: AESKW;
	public algorithm: any;

	static createKek = async ({ keyData }: CreateKekOptions) => {
		return new KeyEncryptionKey(keyData);
	};

	constructor(key: Uint8Array) {
		if (key.length !== 32) {
			throw new Error('key must be 32 bytes');
		}
		this.aeskw = new AESKW(key);
		this.algorithm = { name: 'A256KW' };
	}

	/**
	 * Wraps a cryptographic key.
	 *
	 * @param {object} options - The options to use.
	 * @param {Uint8Array} options.unwrappedKey - The key material as a
	 *   `Uint8Array`.
	 *
	 * @returns {string} - The base64url-encoded wrapped key bytes.
	 */
	wrapKey({ unwrappedKey }: WrapKeyOptions): string {
		const wrappedKey = this.aeskw.wrapKey(unwrappedKey);
		return base64url.encode(Buffer.from(wrappedKey));
	}

	/**
	 * Unwraps a cryptographic key.
	 *
	 * @param {object} options - The options to use.
	 * @param {string} options.wrappedKey - The wrapped key material as a
	 *   base64url-encoded string.
	 *
	 * @returns {Uint8Array} - Resolves to the key bytes or null if
	 *   the unwrapping fails because the key does not match.
	 */
	unwrapKey({ wrappedKey }: UnwrapKeyOptions): Uint8Array | null {
		const _wrappedKey = base64url.decode(wrappedKey);
		try {
			return this.aeskw.unwrapKey(_wrappedKey);
		} catch (e) {
			// decryption failed
			console.error(e);
			return null;
		}
	}

	static fromStaticPeer = (KeyPair: any) => {
		return async ({ ephemeralKeyPair, staticPublicKey }: any) => {
			if (!staticPublicKey) throw new Error("no staticPublicKey found")
			if (!(
				staticPublicKey.type === 'X25519KeyAgreementKey2019' ||
				staticPublicKey.type === 'X25519KeyAgreementKey2020' ||
				staticPublicKey.type === 'JsonWebKey2020'
			)) {
				throw new Error(
					`"staticPublicKey.type" must be "X25519KeyAgreementKey2019", "X25519KeyAgreementKey2020" or "JsonWebKey2020".`
					);
			}
			const epkPair =
				ephemeralKeyPair.keypair.type === 'JsonWebKey2020'
				? await X25519KeyAgreementKey2019.fromJWK(ephemeralKeyPair.keypair)
				: await KeyPair.from(ephemeralKeyPair.keypair);
						
			// "Party U Info"
			let producerInfo: Uint8Array = epkPair.publicKey;

			// "Party V Info"
			const consumerInfo = Buffer.from(staticPublicKey.id);
			const secret = await epkPair.deriveSecret({
				publicKey: staticPublicKey
			} as any);

			const keyData = await deriveKey({ secret, producerInfo, consumerInfo });
			return {
				kek: await KeyEncryptionKey.createKek({ keyData }),
				epk: ephemeralKeyPair.epk,
				apu: base64url.encode(producerInfo),
				apv: base64url.encode(consumerInfo as any)
			};
		};
	};

	static fromEphemeralPeer = (KeyPairClass: any) => {
		return async ({ keyAgreementKey, epk, apu, apv }: any) => {
			if (!(epk && typeof epk === 'object')) {
				throw new TypeError('"epk" must be an object.');
			}
			// convert to LD key for Web KMS
			const ephemeralPublicKey = {
				type: 'JsonWebKey2020',
				publicKeyJwk: epk,
				id: '#ephemeral',
				controller: '#ephemeral'
			};

			const epkPair = await X25519KeyAgreementKey2019.fromJWK(ephemeralPublicKey);
			// "Party U Info"
			let producerInfo: Uint8Array = apu ? base64url.decode(apu) : base64url.decode(epk.x)

			// "Party V Info"
			const consumerInfo = apv ? base64url.decode(apv) : Buffer.from(keyAgreementKey.id);

			const secret = await keyAgreementKey.deriveSecret({
				publicKey: epkPair
			} as any);
			const keyData = await deriveKey({ secret, producerInfo, consumerInfo });
			return {
				kek: await KeyEncryptionKey.createKek({ keyData })
			};
		};
	};
}
