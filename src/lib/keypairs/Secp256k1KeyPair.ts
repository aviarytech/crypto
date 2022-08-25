import * as secp from '@noble/secp256k1';
import { Buffer } from 'buffer/index.js';

import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { sha256Uint8Array } from '$lib/utils/sha256.js';
import { base58, base64url } from '$lib/utils/encoding.js';
import { SECP256K1_MULTICODEC_IDENTIFIER } from '$lib/constants.js';
import { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase.js';
import { JsonWebKey, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';

export interface EcdsaSecp256k1VerificationKey2019 extends BaseKeyPair {
	id: string;
	type: string;
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
}

@staticImplements<BaseKeyPairStatic>()
export class EcdsaSecp256k1KeyPair implements EcdsaSecp256k1VerificationKey2019 {
	id: string;
	type: 'EcdsaSecp256k1VerificationKey2019';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

	JWA = 'ES256K';

	async sign({ data }: { data: Uint8Array }): Promise<Uint8Array> {
		try {
			return await secp.sign(sha256Uint8Array(data), this.privateKey, {
				der: false
			});
		} catch (e) {
			console.error('An error occurred when signing: ', e);
			return null;
		}
	}

	async verify({ data, signature }: { data: Uint8Array; signature: Uint8Array }): Promise<boolean> {
		try {
			const sig =
				signature.length === 64
					? secp.Signature.fromCompact(signature)
					: secp.Signature.fromDER(signature);
			return secp.verify(sig, sha256Uint8Array(data), this.publicKey);
		} catch (e) {
			console.error('An error occurred when verifying signature: ', e);
			return false;
		}
	}

	constructor(id: string, controller: string, publicKeyBase58: string, privateKeyBase58?: string) {
		this.type = 'EcdsaSecp256k1VerificationKey2019';
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
		const privKey = secp.utils.randomPrivateKey();
		const pubKey = secp.getPublicKey(privKey);
		const fingerprint = getMultibaseFingerprintFromPublicKeyBytes(
			pubKey,
			SECP256K1_MULTICODEC_IDENTIFIER
		);
		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new EcdsaSecp256k1KeyPair(id, controller, base58.encode(pubKey), base58.encode(privKey));
	};

	static from = async (k: EcdsaSecp256k1VerificationKey2019, options?: {}) => {
		return new EcdsaSecp256k1KeyPair(k.id, k.controller, k.publicKeyBase58, k.privateKeyBase58);
	};

	static fromJWK = async (k: JsonWebKey) => {
		const { x, y } = k.publicKeyJwk;
		const xInt = Buffer.from(x, 'base64').toString('hex');
		const yInt = Buffer.from(y, 'base64').toString('hex');
		const point = new secp.Point(BigInt('0x' + xInt), BigInt('0x' + yInt));
		const pubKey = point.toRawBytes();
		if (k.privateKeyJwk) {
			const { d } = k.privateKeyJwk;
			const privKey = d ? Buffer.from(d, 'base64') : null;
			return new EcdsaSecp256k1KeyPair(
				k.id,
				k.controller,
				base58.encode(pubKey),
				base58.encode(privKey)
			);
		}
		return new EcdsaSecp256k1KeyPair(k.id, k.controller, base58.encode(pubKey));
	};

	async export(
		options: {
			privateKey?: boolean;
			type: 'JsonWebKey2020';
		} = {
			privateKey: false,
			type: 'JsonWebKey2020'
		}
	): Promise<JsonWebKey2020> {
		const bytes = secp.Point.fromHex(this.publicKey).toRawBytes();
		const x = bytes.slice(1, 33);
		const y = bytes.slice(33);
		if (!options.privateKey) {
			return {
				...new JsonWebKey(this.id, this.controller, {
					kty: 'EC',
					crv: 'secp256k1',
					x: base64url.encode(x),
					y: base64url.encode(y)
				})
			};
		}
		return {
			...new JsonWebKey(
				this.id,
				this.controller,
				{
					kty: 'EC',
					crv: 'secp256k1',
					x: base64url.encode(x),
					y: base64url.encode(y)
				},
				{
					kty: 'EC',
					crv: 'secp256k1',
					x: base64url.encode(x),
					y: base64url.encode(y),
					d: base64url.encode(this.privateKey)
				}
			)
		};
	}
}
