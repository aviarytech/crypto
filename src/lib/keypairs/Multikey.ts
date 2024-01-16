import * as secp from '@noble/secp256k1';
import { HDKey } from "@scure/bip32"
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { sha256Uint8Array } from '$lib/utils/sha256.js';
import { base58, base64url, multibase, MULTICODEC_SECP256K1_PUB_HEADER } from '$lib/utils/encoding.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import { Buffer } from 'buffer/index.js';

export interface IMultikey extends BaseKeyPair {
	id: string;
	type: string;
	controller: string;
	publicKeyMultibase: string;
	privateKeyMultibase?: string;
}

@staticImplements<BaseKeyPairStatic>()
export class Multikey implements IMultikey {
	ALG = 'ES256K';
	JWA = 'ES256K';
	algorithm = 'secp256k1';
	SUITE_TYPE = 'Multikey';

	id: string;
	type: 'Multikey';
	controller: string;
	publicKeyMultibase: string;
	privateKeyMultibase?: string;
	publicKey: Uint8Array;
	privateKey?: Uint8Array;

  constructor(id: string, controller: string, publicKeyMultibase: string, privateKeyMultibase?: string) {
		this.type = 'Multikey';
		this.id = id;
		this.controller = controller;
		this.publicKeyMultibase = publicKeyMultibase;
		this.privateKeyMultibase = privateKeyMultibase;
		this.publicKey = base58.decode(publicKeyMultibase);
    this.publicKey = multibase.decodeAny(publicKeyMultibase);
		if (privateKeyMultibase) {
			this.privateKey = base58.decode(privateKeyMultibase);
		}
	}

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

	static generate = async () => {
		const privKey = secp.utils.randomPrivateKey();
		const pubKey = secp.getPublicKey(privKey);
		const fingerprint = multibase.encode(MULTICODEC_SECP256K1_PUB_HEADER, pubKey)
		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new EcdsaSecp256k1KeyPair(id, controller, base58.encode(pubKey), base58.encode(privKey));
	};

	static from = async (k: EcdsaSecp256k1VerificationKey2019, options?: {}) => {
		return new EcdsaSecp256k1KeyPair(k.id, k.controller, k.publicKeyBase58, k.privateKeyBase58);
	};

	static fromXpub = async (xpub: string) => {
		const hd = HDKey.fromExtendedKey(xpub);
		if (hd.publicKey) {
			const fingerprint = multibase.encode(MULTICODEC_SECP256K1_PUB_HEADER, hd.publicKey)
			const controller = `did:key:${fingerprint}`;
			const id = `${controller}#${fingerprint}`;
			return new EcdsaSecp256k1KeyPair(id, controller, base58.encode(hd.publicKey));
		}
		return null;
	}

	static fromJWK = async (k: JsonWebKeyPair) => {
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
				...new JsonWebKeyPair(this.id, this.controller, {
					kty: 'EC',
					crv: 'secp256k1',
					x: base64url.encode(x),
					y: base64url.encode(y)
				})
			};
		}
		return {
			...new JsonWebKeyPair(
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
