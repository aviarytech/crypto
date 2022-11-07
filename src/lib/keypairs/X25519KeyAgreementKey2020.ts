import * as x25519 from '@stablelib/x25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase.js';
import { base64url, multibase } from '$lib/utils/encoding.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import type { X25519KeyAgreementKey2019 } from './X25519KeyAgreementKey2019';

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
		this.publicKey = multibase.decode(publicKeyMultibase);
		if (privateKeyMultibase) {
			this.privateKey = multibase.decode(privateKeyMultibase);
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
			multibase.encode(key.publicKey),
			multibase.encode(key.secretKey)
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

	static fromBase58 = async (k: X25519KeyAgreementKey2019) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = multibase.fromBase58(k.publicKeyBase58)
		if (k.privateKeyBase58) {
			privateKeyBase58 = multibase.fromBase58(k.privateKeyBase58)
		}
		return new X25519KeyAgreementKey2020(
			k.id ?? `#${publicKeyBase58.slice(0, 8)}`,
			k.controller ?? `#${publicKeyBase58.slice(0, 8)}`,
			publicKeyBase58,
			privateKeyBase58
		);
	}

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKey, privateKey;
		if (!k.publicKeyJwk.x)
			throw new Error('Public Key Not found')
		publicKey = multibase.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKey = multibase.encode(base64url.decode(k.privateKeyJwk.d));
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

	async deriveSecret({ publicKey }: { publicKey: JsonWebKeyPair | X25519KeyAgreementKey2019 | X25519KeyAgreementKey2020 }) {
		let remote;
		if (publicKey.type === 'JsonWebKey2020') {
			remote = await X25519KeyAgreementKey2020.fromJWK(publicKey)
		} else if (publicKey.type === 'X25519KeyAgreementKey2019') {
			remote = await X25519KeyAgreementKey2020.fromBase58(publicKey)
		} else {
			remote = new X25519KeyAgreementKey2020(
				publicKey.id,
				publicKey.controller,
				publicKey.publicKeyMultibase,
				this.privateKeyMultibase
			)
		}
		if (!remote.publicKey) {
			throw new Error('No public key available for deriveSecret')
		}
		if (!this.privateKey) {
			throw new Error('No private key available for deriveSecret');
		}
		return x25519.sharedKey(this.privateKey, remote.publicKey, true);
	}
}
