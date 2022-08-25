
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base58, base64url } from '$lib/utils/encoding.js';
import { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase.js';
import * as ed25519 from '@stablelib/ed25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { JsonWebKey, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';

export interface Ed25519VerificationKey2018 extends BaseKeyPair {
	id: string;
	type: 'Ed25519VerificationKey2018';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
}

@staticImplements<BaseKeyPairStatic>()
export class Ed25519KeyPair implements Ed25519VerificationKey2018 {
	id: string;
	type: 'Ed25519VerificationKey2018';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

	signer = (privateKey: Uint8Array) => {
		return {
			async sign({ data }) {
				return ed25519.sign(privateKey, data);
			}
		};
	};

	verifier = (publicKey: Uint8Array) => {
		return {
			async verify({ data, signature }): Promise<boolean> {
				let verified = false;
				try {
					verified = ed25519.verify(publicKey, data, signature);
				} catch (e) {
					// console.error('An error occurred when verifying signature: ', e);
				}
				return verified;
			}
		};
	};

	constructor(id: string, controller: string, publicKeyBase58: string, privateKeyBase58?: string) {
		this.type = 'Ed25519VerificationKey2018';
		this.id = id;
		this.controller = controller;
		this.publicKeyBase58 = publicKeyBase58;
		this.privateKeyBase58 = privateKeyBase58;
		this.publicKey = base58.decode(publicKeyBase58);
		if (privateKeyBase58) {
			this.privateKey = base58.decode(privateKeyBase58);
		}
	}

	static generate = async () => {
		const key = ed25519.generateKeyPair();

		const fingerprint = getMultibaseFingerprintFromPublicKeyBytes(key.publicKey);

		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new Ed25519KeyPair(
			id,
			controller,
			base58.encode(key.publicKey),
			base58.encode(key.secretKey)
		);
	};

	static from = async (k: Ed25519KeyPair, options: {}) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = k.publicKeyBase58;
		if (k.privateKeyBase58) {
			privateKeyBase58 = k.privateKeyBase58;
		}
		return new Ed25519KeyPair(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk) {
			privateKeyBase58 = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new Ed25519KeyPair(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	async export(
		options: {
			privateKey?: boolean;
			type: 'JsonWebKey2020';
		} = {
			privateKey: false,
			type: 'JsonWebKey2020'
		}
	): Promise<JsonWebKey> {
		return new JsonWebKey(
			this.id,
			this.controller,
			{
				kty: 'OKP',
				crv: 'Ed25519',
				x: base64url.encode(this.publicKey)
			},
			options.privateKey
				? {
						kty: 'OKP',
						crv: 'Ed25519',
						x: base64url.encode(this.publicKey),
						d: base64url.encode(this.privateKey)
				  }
				: undefined
		);
	}
}
