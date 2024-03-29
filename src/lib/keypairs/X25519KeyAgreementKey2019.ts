import * as x25519 from '@stablelib/x25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base58, base64url, multibase, MULTICODEC_X25519_PRIV_HEADER, MULTICODEC_X25519_PUB_HEADER } from '$lib/utils/encoding.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import type { X25519KeyAgreementKey2020 } from '$lib/keypairs/X25519KeyAgreementKey2020.js';

@staticImplements<BaseKeyPairStatic>()
export class X25519KeyAgreementKey2019 implements BaseKeyPair {
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

		const fingerprint = multibase.encode(MULTICODEC_X25519_PUB_HEADER, key.publicKey)

		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new X25519KeyAgreementKey2019(
			id,
			controller,
			base58.encode(key.publicKey),
			base58.encode(key.secretKey)
		);
	};

	static from = async (k: X25519KeyAgreementKey2019, options: {}) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = k.publicKeyBase58;
		if (k.privateKeyBase58) {
			privateKeyBase58 = k.privateKeyBase58;
		}
		return new X25519KeyAgreementKey2019(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKeyBase58: string, privateKeyBase58: string;
		publicKeyBase58 = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKeyBase58 = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new X25519KeyAgreementKey2019(k.id, k.controller, publicKeyBase58, privateKeyBase58!);
	};

	static fromMultibase = async (options: {id?: string, controller?: string, publicKeyMultibase: string, privateKeyMultibase?: string}) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = base58.encode(multibase.decode(MULTICODEC_X25519_PUB_HEADER, options.publicKeyMultibase))

		if (options.privateKeyMultibase) {
			privateKeyBase58 = base58.encode(multibase.decode(MULTICODEC_X25519_PRIV_HEADER, options.privateKeyMultibase))
		}
		return new X25519KeyAgreementKey2019(
			options.id ?? `#${publicKeyBase58.slice(0, 8)}`,
			options.controller ?? `#${publicKeyBase58.slice(0, 8)}`,
			publicKeyBase58,
			privateKeyBase58
		);
	}

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

	async deriveSecret({ publicKey }: { publicKey: JsonWebKeyPair | X25519KeyAgreementKey2019 | X25519KeyAgreementKey2020 }) {
		let remote;
		if (publicKey.type === 'JsonWebKey2020') {
			remote = await X25519KeyAgreementKey2019.fromJWK(publicKey)
		} else if (publicKey.type === 'X25519KeyAgreementKey2020') {
			remote = await X25519KeyAgreementKey2019.fromMultibase(publicKey)

		} else {
			remote = new X25519KeyAgreementKey2019(
				publicKey.id,
				publicKey.controller,
				publicKey.publicKeyBase58,
				this.privateKeyBase58
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
