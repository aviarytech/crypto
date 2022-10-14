
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base64url } from '$lib/utils/encoding.js';
import { base58btc as base58 } from "multiformats/bases/base58"
import * as ed25519 from '@stablelib/ed25519';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';


@staticImplements<BaseKeyPairStatic>()
export class Ed25519VerificationKey2020 implements BaseKeyPair {
	id: string;
	type: 'Ed25519VerificationKey2020';
	controller: string;
	publicKeyMultibase: string;
	privateKeyMultibase?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

	signer = (privateKey: Uint8Array) => {
		return {
			async sign({ data }: {data: Uint8Array}) {
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

	constructor(id: string, controller: string, publicKeyMultibase: string, privateKeyMultibase?: string) {
		this.type = 'Ed25519VerificationKey2020';
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
		const key = ed25519.generateKeyPair();

		// const fingerprint = getMultibaseFingerprintFromPublicKeyBytes(key.publicKey);
		const pub = base58.encode(key.publicKey);
		const priv = base58.encode(key.secretKey);

		const controller = `did:key:${pub}`;
		const id = `${controller}#${pub}`;

		return new Ed25519VerificationKey2020(
			id,
			controller,
			pub,
			priv
		);
	};

	static from = async (k: Ed25519VerificationKey2020, options: {}) => {
		let publicKeyMultibase, privateKeyMultibase;
		publicKeyMultibase = k.publicKeyMultibase;
		if (k.privateKeyMultibase) {
			privateKeyMultibase = k.privateKeyMultibase;
		}
		return new Ed25519VerificationKey2020(k.id, k.controller, publicKeyMultibase, privateKeyMultibase);
	};

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKey, privateKey;
		if (!k.publicKeyJwk.x)
			throw new Error('Public Key Not found')
		publicKey = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKey = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new Ed25519VerificationKey2020(k.id, k.controller, publicKey, privateKey);
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
