import * as x25519 from '@stablelib/x25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase.js';
import { base58, base64url } from '$lib/utils/encoding.js';
import { JsonWebKey, JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';

export interface X25519KeyAgreementKey2019 extends BaseKeyPair {
	id: string;
	type: 'X25519KeyAgreementKey2019';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
}
@staticImplements<BaseKeyPairStatic>()
export class X25519KeyPair implements X25519KeyAgreementKey2019 {
	id: string;
	type: 'X25519KeyAgreementKey2019';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

	constructor(id: string, controller: string, publicKeyBase58: string, privateKeyBase58?: string) {
		this.type = 'X25519KeyAgreementKey2019';
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
		const key = x25519.generateKeyPair();

		const fingerprint = getMultibaseFingerprintFromPublicKeyBytes(key.publicKey);

		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new X25519KeyPair(
			id,
			controller,
			base58.encode(key.publicKey),
			base58.encode(key.secretKey)
		);
	};

	static from = async (k: X25519KeyPair, options: {}) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = k.publicKeyBase58;
		if (k.privateKeyBase58) {
			privateKeyBase58 = k.privateKeyBase58;
		}
		return new X25519KeyPair(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKeyBase58: string, privateKeyBase58: string;
		publicKeyBase58 = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk) {
			privateKeyBase58 = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new X25519KeyPair(k.id, k.controller, publicKeyBase58, privateKeyBase58);
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
				crv: 'X25519',
				x: base64url.encode(this.publicKey)
			},
			options.privateKey
				? {
						kty: 'OKP',
						crv: 'X25519',
						x: base64url.encode(this.publicKey),
						d: base64url.encode(this.privateKey)
				  }
				: undefined
		);
	}

	async deriveSecret({ publicKey }: { publicKey: X25519KeyAgreementKey2019 }) {
		const remote = new X25519KeyPair(
			publicKey.id,
			publicKey.controller,
			publicKey.publicKeyBase58,
			this.privateKeyBase58
		);
		if (!this.privateKey) {
			throw new Error('No private key available for deriveSecret');
		}
		const scalarMultipleResult = x25519.sharedKey(this.privateKey, remote.publicKey, true);
		return scalarMultipleResult;
	}
}
