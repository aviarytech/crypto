import * as x25519 from '@stablelib/x25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase.js';
import { base64url } from '$lib/utils/encoding.js';
import { base58btc as base58 } from 'multiformats/bases/base58';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';

@staticImplements<BaseKeyPairStatic>()
export class X25519KeyAgreementKey2020 implements BaseKeyPair {
	id: string;
	type: 'X25519KeyAgreementKey2020';
	controller: string;
	publicKeyMultibase: string;
	privateKeyMultibase?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

	constructor(id: string, controller: string, publicKeyMultibase: string, privateKeyMultibase?: string) {
		this.type = 'X25519KeyAgreementKey2020';
		this.id = id;
		this.controller = controller;
		this.publicKeyMultibase = publicKeyMultibase;
		this.privateKeyMultibase = privateKeyMultibase;
		this.publicKey = base58.decode(publicKeyMultibase);
		if (privateKeyMultibase) {
			this.privateKey = base58.decode(privateKeyMultibase);
		}
	}

	static generate = async () => {
		const key = x25519.generateKeyPair();

		const fingerprint = getMultibaseFingerprintFromPublicKeyBytes(key.publicKey);

		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new X25519KeyAgreementKey2020(
			id,
			controller,
			base58.encode(key.publicKey),
			base58.encode(key.secretKey)
		);
	};

	static from = async (k: X25519KeyAgreementKey2020, options: {}) => {
		let publicKeyMultibase, privateKeyMultibase;
		publicKeyMultibase = k.publicKeyMultibase;
		if (k.privateKeyMultibase) {
			privateKeyMultibase = k.privateKeyMultibase;
		}
		return new X25519KeyAgreementKey2020(k.id, k.controller, publicKeyMultibase, privateKeyMultibase);
	};

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKey, privateKey;
		if (!k.publicKeyJwk.x)
			throw new Error('Public Key Not found')
		publicKey = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKey = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new X25519KeyAgreementKey2020(k.id, k.controller, publicKey, privateKey);
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
				crv: 'X25519',
				x: base64url.encode(this.publicKey)
			},
			options.privateKey && this.privateKey
				? {
						kty: 'OKP',
						crv: 'X25519',
						x: base64url.encode(this.publicKey),
						d: base64url.encode(this.privateKey)
				  }
				: undefined
		);
	}

	async deriveSecret({ publicKey }: { publicKey: X25519KeyAgreementKey2020 }) {
		const remote = new X25519KeyAgreementKey2020(
			publicKey.id,
			publicKey.controller,
			publicKey.publicKeyMultibase,
			this.privateKeyMultibase
		);
		if (!this.privateKey) {
			throw new Error('No private key available for deriveSecret');
		}
		const scalarMultipleResult = x25519.sharedKey(this.privateKey, remote.publicKey, true);
		return scalarMultipleResult;
	}
}
