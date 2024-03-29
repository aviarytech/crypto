
import { LinkedDataProof } from '$lib/LDP/proof.js';
import type { DocumentLoader } from '$lib/interfaces.js';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import { MULTICODEC_ED25519_PRIV_HEADER, MULTICODEC_ED25519_PUB_HEADER, base58, base64url, multibase } from '$lib/utils/encoding.js';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { createVerifyData } from '$lib/utils/vcs.js';
import * as ed25519 from '@stablelib/ed25519';
import { HDKey } from 'micro-ed25519-hdkey';
import { Buffer } from 'buffer/index.js';

export class Ed25519Signature2020LinkedDataProof extends LinkedDataProof {
	public proofValue: string | undefined;

	constructor(
		type: string,
		proofPurpose: string,
		verificationMethod: string,
		created: string,
		proofValue?: string,
		challenge?: string,
		domain?: string
	) {
		super(type, proofPurpose, verificationMethod, challenge, domain, created);
		if (proofValue) {
			this.proofValue = proofValue;
		}
	}

	toJSON() {
		let val: any = {
			type: this.type,
			proofPurpose: this.proofPurpose,
			verificationMethod: this.verificationMethod,
			created: this.created
		};
		if (this.proofValue) {
			val.proofValue = this.proofValue;
		}
		if (this.challenge) {
			val.challenge = this.challenge;
		}
		if (this.domain) {
			val.domain = this.domain;
		}
		return val;
	}
}

// TODO
// export const getNextKey = (hd: HDKey, path: string, nextLevel = false) => {
// 	if (nextLevel) {
// 		return hd.derive(path + "/0'");
// 	}
// 	let levels = path.split('/')
// 	levels[levels.length-1].replace(/\d+/, (val) => (parseInt(val)+1).toString())
// 	return hd.derive(levels.join('/'))
// }

export const deriveKeyFromSeed = (seed: string, path: string) => {
	const hd = HDKey.fromMasterSeed(seed);
	return deriveKeyFromHd(hd, path);
}
export const deriveKeyFromHd = (hd: HDKey, path: string) => {
	return hd.derive(path);
}

@staticImplements<BaseKeyPairStatic>()
export class Ed25519VerificationKey2020 implements BaseKeyPair {
	ALG = 'EdDSA'
	algorithm = 'Ed25519';
	SUITE_TYPE = 'Ed25519Signature2020'


	id: string;
	type: 'Ed25519VerificationKey2020';
	controller: string;
	publicKeyMultibase: string;
	privateKeyMultibase?: string;
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
				verified = ed25519.verify(publicKey, data, signature);
				return verified;
			}
		};
	};
	sign?: ({ data }: { data: Uint8Array }) => Promise<Uint8Array>;
	verify?: ({ data, signature }: { data: Uint8Array; signature: Uint8Array }) => Promise<boolean>;

	constructor(id: string, controller: string, publicKeyMultibase: string, privateKeyMultibase?: string) {
		this.type = 'Ed25519VerificationKey2020';
		this.id = id;
		this.controller = controller;
		this.publicKeyMultibase = publicKeyMultibase;
		this.privateKeyMultibase = privateKeyMultibase;
		this.publicKey = multibase.decode(MULTICODEC_ED25519_PUB_HEADER, publicKeyMultibase);
		if (privateKeyMultibase) {
			this.privateKey = multibase.decode(MULTICODEC_ED25519_PRIV_HEADER, privateKeyMultibase);
			this.sign = this.signer(this.privateKey).sign
		}
		this.verify = this.verifier(this.publicKey).verify
	}

	static generate = async () => {
		const key = ed25519.generateKeyPair();

		const fingerprint = multibase.encode(MULTICODEC_ED25519_PUB_HEADER, key.publicKey)

		const pub = multibase.encode(MULTICODEC_ED25519_PUB_HEADER, key.publicKey);
		const priv = multibase.encode(MULTICODEC_ED25519_PRIV_HEADER, key.secretKey);

		const controller = `did:key:${fingerprint}`;
		const id = `${controller}#${fingerprint}`;

		return new Ed25519VerificationKey2020(
			id,
			controller,
			pub,
			priv
		);
	};

	static from = async (options: { id?: string, controller?: string, publicKeyMultibase: string, privateKeyMultibase?: string }) => {
		return new Ed25519VerificationKey2020(
			options.id ?? `#${options.publicKeyMultibase.slice(1, 7)}`,
			options.controller ?? `#${options.publicKeyMultibase.slice(1, 7)}`,
			options.publicKeyMultibase,
			options.privateKeyMultibase
		);
	};

	static fromHD = (hd: HDKey) => {
		const publicKeyMultibase = multibase.encode(MULTICODEC_ED25519_PUB_HEADER, hd.publicKeyRaw)
		// TODO mayb 32 byte key is wrong should be 33?
		console.log(hd.publicKey.length)
		return new Ed25519VerificationKey2020(
			`did:key:${publicKeyMultibase}#${publicKeyMultibase}`,
			`did:key:${publicKeyMultibase}`,
			publicKeyMultibase,
			multibase.encode(MULTICODEC_ED25519_PRIV_HEADER, new Uint8Array(Buffer.concat([hd.chainCode, hd.privateKey,])))
		)
	}

	static fromBase58 = async (options: { id?: string, controller?: string, publicKeyBase58: string, privateKeyBase58?: string }) => {
		let publicKeyMultibase, privateKeyMultibase;
		publicKeyMultibase = multibase.encode(MULTICODEC_ED25519_PUB_HEADER, base58.decode(options.publicKeyBase58))
		if (options.privateKeyBase58) {
			privateKeyMultibase = multibase.encode(MULTICODEC_ED25519_PRIV_HEADER, base58.decode(options.privateKeyBase58))
		}
		return new Ed25519VerificationKey2020(
			options.id ?? `#${publicKeyMultibase.slice(0, 8)}`,
			options.controller ?? `#${publicKeyMultibase.slice(0, 8)}`,
			publicKeyMultibase,
			privateKeyMultibase
		);
	}

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

	async createProof(
		document: any,
		purpose: string,
		documentLoader: DocumentLoader,
		options?: { domain?: string, challenge?: string }
	): Promise<Ed25519Signature2020LinkedDataProof> {
		if (!this.privateKey) {
			throw new Error("No privateKey, Can't create proof");
		}
		const date = new Date().toISOString();
		const proof = new Ed25519Signature2020LinkedDataProof(
			this.SUITE_TYPE, purpose, this.id, date.slice(0, date.length - 5) + 'Z',
			undefined, options?.challenge, options?.domain
		)

		// create data to sign
		const verifyData = await createVerifyData({
			document,
			proof: { '@context': document['@context'], ...proof.toJSON() },
			documentLoader
		});

		const sig = await this.sign!({ data: verifyData });

		proof.proofValue = multibase.encode(new Uint8Array([]), sig)

		return proof.toJSON()
	}

	async verifyProof(
		documentProof: Ed25519Signature2020LinkedDataProof,
		document: any,
		documentLoader: DocumentLoader
	) {
		const { proof, ...doc } = document;
		console.log(documentProof)
		if (!documentProof.toJSON) {
			documentProof = new Ed25519Signature2020LinkedDataProof(documentProof.type,
				documentProof.proofPurpose, documentProof.verificationMethod, documentProof.created,
				documentProof.proofValue, documentProof.challenge, documentProof.domain)
		}
		try {
			const verifyData = await createVerifyData({
				document: doc,
				proof: { '@context': doc['@context'], ...documentProof.toJSON() },
				documentLoader
			})
			const verified = await this.verify!({
				data: Uint8Array.from(verifyData),
				signature: Uint8Array.from(multibase.decode(new Uint8Array([]), documentProof.proofValue ?? ''))
			});
			if (!verified) {
				throw new Error('Invalid signature.');
			}

			const purposeValid = documentProof.validate();

			if (!purposeValid) {
				throw new Error('Proof verified but not valid');
			}

			return { verified: true };
		} catch (error: any) {
			return { verified: false, errors: [error.message] };
		}
	}
}
