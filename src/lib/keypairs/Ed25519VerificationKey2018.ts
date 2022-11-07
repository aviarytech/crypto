
import type { BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base58, base64url, multibase } from '$lib/utils/encoding.js';
import * as ed25519 from '@stablelib/ed25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import type { Ed25519VerificationKey2020 } from './Ed25519VerificationKey2020';


@staticImplements<BaseKeyPairStatic>()
export class Ed25519VerificationKey2018 implements Ed25519VerificationKey2018 {
	id: string;
	type: 'Ed25519VerificationKey2018';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

	signer = (privateKey: Uint8Array) => {
		return {
			async sign({ data }: { data: Uint8Array }) {
				return ed25519.sign(privateKey, data);
			}
		};
	};

	verifier = (publicKey: Uint8Array) => {
		return {
			async verify({ data, signature }: { data: Uint8Array, signature: Uint8Array }): Promise<boolean> {
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

		const pub = base58.encode(key.publicKey);

		const controller = `did:key:${pub}`;
		const id = `${controller}#${pub}`;

		return new Ed25519VerificationKey2018(
			id,
			controller,
			base58.encode(key.publicKey),
			base58.encode(key.secretKey)
		);
	};

	static from = async (k: Ed25519VerificationKey2018, options: {}) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = k.publicKeyBase58;
		if (k.privateKeyBase58) {
			privateKeyBase58 = k.privateKeyBase58;
		}
		return new Ed25519VerificationKey2018(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	static fromMultibase = async (k: Ed25519VerificationKey2020) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = multibase.toBase58(k.publicKeyMultibase)
		if (k.privateKeyMultibase) {
			privateKeyBase58 = multibase.toBase58(k.privateKeyMultibase)
		}
		return new Ed25519VerificationKey2018(
			k.id ?? `#${publicKeyBase58.slice(0, 8)}`,
			k.controller ?? `#${publicKeyBase58.slice(0, 8)}`,
			publicKeyBase58,
			privateKeyBase58
		);
	}

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKeyBase58, privateKeyBase58;
		if (!k.publicKeyJwk.x)
		throw new Error('Public Key Not found')
		publicKeyBase58 = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKeyBase58 = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new Ed25519VerificationKey2018(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	async export(
		options: {
			privateKey?: boolean;
			type: 'JsonWebKey2020';
		} = {
			privateKey: false,
			type: 'JsonWebKey2020'
		}
	): Promise<JsonWebKeyPair> {
		return new JsonWebKeyPair(
			this.id,
			this.controller,
			{
				kty: 'OKP',
				crv: 'Ed25519',
				x: base64url.encode(this.publicKey)
			},
			options.privateKey && this.privateKey
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
