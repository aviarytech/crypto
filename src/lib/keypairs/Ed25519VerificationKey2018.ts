
import * as ed25519 from '@stablelib/ed25519';
import type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
import { base58, base64url, multibase, MULTICODEC_ED25519_PRIV_HEADER, MULTICODEC_ED25519_PUB_HEADER } from '$lib/utils/encoding.js';
import { staticImplements } from '$lib/utils/staticImplements.js';
import { JsonWebKeyPair, type JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
import type { Ed25519VerificationKey2020 } from '$lib/keypairs/Ed25519VerificationKey2020.js';
import { LinkedDataProof } from '$lib/LDP/proof.js';
import type { DocumentLoader } from '$lib/interfaces.js';
import { createVerifyData } from '$lib/utils/vcs.js';

export class Ed25519Signature2018LinkedDataProof extends LinkedDataProof {
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
export class Ed25519VerificationKey2018 implements BaseKeyPair {
	ALG = 'EdDSA';
	algorithm = 'Ed25519';
	SUITE_TYPE = 'Ed25519Signature2018'

	id: string;
	type: 'Ed25519VerificationKey2018';
	controller: string;
	publicKeyBase58: string;
	privateKeyBase58?: string;
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
				try {
					verified = ed25519.verify(publicKey, data, signature);
				} catch (e) {
					// console.error('An error occurred when verifying signature: ', e);
				}
				return verified;
			}
		};
	};
	sign?: ({ data }: { data: Uint8Array; }) => Promise<Uint8Array>;
	verify: ({ data, signature }: { data: Uint8Array; signature: Uint8Array; }) => Promise<boolean>;

	constructor(id: string, controller: string, publicKeyBase58: string, privateKeyBase58?: string) {
		this.type = 'Ed25519VerificationKey2018';
		this.id = id;
		this.controller = controller;
		this.publicKeyBase58 = publicKeyBase58;
		this.privateKeyBase58 = privateKeyBase58;
		this.publicKey = base58.decode(publicKeyBase58);
		if (privateKeyBase58) {
			this.privateKey = base58.decode(privateKeyBase58);
			this.sign = this.signer(this.privateKey).sign
		}
		this.verify = this.verifier(this.publicKey).verify
	}

	static generate = async () => {
		const key = ed25519.generateKeyPair();
		const multibasePub = multibase.encode(MULTICODEC_ED25519_PUB_HEADER, key.publicKey)
		const controller = `did:key:${multibasePub}`;
		const id = `${controller}#${multibasePub}`;

		return new Ed25519VerificationKey2018(
			id,
			controller,
			base58.encode(key.publicKey),
			base58.encode(key.secretKey)
		);
	};

	static from = async (k: Ed25519VerificationKey2018, options: {}) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = k.publicKeyBase58;
		if (k.privateKeyBase58) {
			privateKeyBase58 = k.privateKeyBase58;
		}
		return new Ed25519VerificationKey2018(k.id, k.controller, publicKeyBase58, privateKeyBase58);
	};

	static fromMultibase = async (k: Ed25519VerificationKey2020) => {
		let publicKeyBase58, privateKeyBase58;
		publicKeyBase58 = base58.encode(multibase.decode(MULTICODEC_ED25519_PUB_HEADER, k.publicKeyMultibase))
		if (k.privateKeyMultibase) {
			privateKeyBase58 = base58.encode(multibase.decode(MULTICODEC_ED25519_PRIV_HEADER, k.privateKeyMultibase))
		}
		return new Ed25519VerificationKey2018(
			k.id ?? `#${publicKeyBase58.slice(0, 8)}`,
			k.controller ?? `#${publicKeyBase58.slice(0, 8)}`,
			publicKeyBase58,
			privateKeyBase58
		);
	}

	static fromJWK = async (k: JsonWebKey2020) => {
		let publicKeyBase58, privateKeyBase58;
		if (!k.publicKeyJwk.x)
		throw new Error('Public Key Not found')
		publicKeyBase58 = base58.encode(base64url.decode(k.publicKeyJwk.x));
		if (k.privateKeyJwk && k.privateKeyJwk.d) {
			privateKeyBase58 = base58.encode(base64url.decode(k.privateKeyJwk.d));
		}
		return new Ed25519VerificationKey2018(k.id, k.controller, publicKeyBase58, privateKeyBase58);
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
	): Promise<Ed25519Signature2018LinkedDataProof> {
		if (!this.privateKey) {
			throw new Error("No privateKey, Can't create proof");
		}
		let proof = new Ed25519Signature2018LinkedDataProof(
			this.SUITE_TYPE, purpose, this.id, null, null, options ? options.challenge : null, options? options.domain : null
		)

		// create data to sign
		const verifyData = await createVerifyData({
			document,
			proof: { '@context': document['@context'], ...proof },
			documentLoader
		});

		const sig = await this.sign!({ data: verifyData });
		
		proof.jws = (
			base64url.encode(Buffer.from(JSON.stringify({ alg: this.ALG, b64: false, crit: ['b64'] }))) +
			'..' +
			base64url.encode(sig)
		);

		return proof.toJSON()
	}
}
