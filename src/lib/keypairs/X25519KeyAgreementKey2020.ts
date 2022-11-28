import * as x25519 from '@stablelib/x25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base58, base64url, multibase, MULTICODEC_ED25519_PUB_HEADER, MULTICODEC_X25519_PRIV_HEADER, MULTICODEC_X25519_PUB_HEADER } from '$lib/utils/encoding.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import type { X25519KeyAgreementKey2019 } from '$lib/keypairs/X25519KeyAgreementKey2019.js';

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
		this.publicKey = multibase.decode(MULTICODEC_X25519_PUB_HEADER, publicKeyMultibase);
		if (privateKeyMultibase) {
			this.privateKey = multibase.decode(MULTICODEC_X25519_PRIV_HEADER, privateKeyMultibase);
		}
	}

	static generate = async () => {
		const key = x25519.generateKeyPair();

		const fingerprint = multibase.encode(MULTICODEC_ED25519_PUB_HEADER, key.publicKey)

		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new X25519KeyAgreementKey2020(
			id,
			controller,
			multibase.encode(MULTICODEC_X25519_PUB_HEADER, key.publicKey),
			multibase.encode(MULTICODEC_X25519_PRIV_HEADER, key.secretKey)
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
		let publicKeyMultibase, privateKeyMultibase;
		publicKeyMultibase = multibase.encode(MULTICODEC_X25519_PUB_HEADER, base58.decode(k.publicKeyBase58))
		if (k.privateKeyBase58) {
			privateKeyMultibase = multibase.encode(MULTICODEC_X25519_PRIV_HEADER, base58.decode(k.privateKeyBase58))
		}
		return new X25519KeyAgreementKey2020(
			k.id ?? `#${publicKeyMultibase.slice(0, 8)}`,
			k.controller ?? `#${publicKeyMultibase.slice(0, 8)}`,
			publicKeyMultibase,
			privateKeyMultibase
		);
	}

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKey, privateKey;
		if (!k.publicKeyJwk.x)
			throw new Error('Public Key Not found')
		publicKey = multibase.encode(MULTICODEC_X25519_PUB_HEADER, base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKey = multibase.encode(MULTICODEC_X25519_PRIV_HEADER, base64url.decode(k.privateKeyJwk.d));
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
