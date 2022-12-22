
import * as ed25519 from '@stablelib/ed25519';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base64url, multibase, base58, MULTICODEC_ED25519_PUB_HEADER, MULTICODEC_ED25519_PRIV_HEADER } from '$lib/utils/encoding.js';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import { LinkedDataProof } from '$lib/LDP/proof.js';
import { Buffer } from 'buffer/index.js';
import type { DocumentLoader } from '$lib/interfaces.js';
import { createVerifyData } from '$lib/utils/vcs.js';

export class Ed25519Signature2020LinkedDataProof extends LinkedDataProof {
	public jws: string;

	constructor(
		type: string,
		proofPurpose: string,
		verificationMethod: string,
		created: string,
		jws?: string,
		challenge?: string,
		domain?: string
	) {
		super(type, proofPurpose, verificationMethod, challenge, domain, created);
		this.jws = jws;
	}

	toJSON() {
		let val: any = {
			type: this.type,
			proofPurpose: this.proofPurpose,
			verificationMethod: this.verificationMethod,
			created: this.created
		};
		if (this.jws) {
			val.jws = this.jws;
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

@staticImplements<BaseKeyPairStatic>()
export class Ed25519VerificationKey2020 implements BaseKeyPair {
	ALG = 'EdDSA'

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

	static from = async (options: {id?: string, controller?: string, publicKeyMultibase: string, privateKeyMultibase?: string}) => {
		return new Ed25519VerificationKey2020(
			options.id ?? `#${options.publicKeyMultibase.slice(1, 7)}`,
			options.controller ?? `#${options.publicKeyMultibase.slice(1, 7)}`,
			options.publicKeyMultibase,
			options.privateKeyMultibase
		);
	};
	
	static fromBase58 = async (options: {id?: string, controller?: string, publicKeyBase58: string, privateKeyBase58?: string}) => {
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
		let proof = new Ed25519Signature2020LinkedDataProof(
			this.type, purpose, this.id, null, null, options ? options.challenge : null, options? options.domain : null
		)

		// create data to sign
		const verifyData = await createVerifyData({
			document,
			proof: { '@context': document['@context'], ...proof },
			documentLoader
		});

		const sig = await this.sign!({ data: verifyData });
		
		proof.jws = (
			base64url.encode(Buffer.from(JSON.stringify({ b64: false, crit: ['b64'], alg: this.ALG }))) +
			'..' +
			base64url.encode(sig)
		);

		return proof.toJSON()
	}
}
