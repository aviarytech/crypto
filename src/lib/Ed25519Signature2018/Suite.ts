import jsonld from 'jsonld';
import { Buffer } from 'buffer/index.js';
import type { DocumentLoader } from '$lib/interfaces.js';
import { LinkedDataProof } from '$lib/LDP/proof.js';
import { JsonWebKey } from '$lib/keypairs/JsonWebKey2020.js';
import { sha256buffer } from '$lib/utils/sha256.js';
import { base64url } from '$lib/utils/encoding.js';
import type { Ed25519KeyPair } from '$lib/keypairs/Ed25519VerificationKey2018';

export { createJWSSigner } from '$lib/JWS/createSigner.js';
export { createJWSVerifier } from '$lib/JWS/createVerifier.js';

export interface ISuite {
	key?: Ed25519KeyPair;
	getVerificationMethod: (options: any) => Promise<Ed25519KeyPair>;
	deriveProof?: (options: any) => Promise<any>;
}

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

export class Ed25519Signature2018Suite {
	public key: JsonWebKey;
	public date: string;
	public type: string = 'Ed25519Signature2018';
	public context: string = 'https://www.w3.org/2018/credentials/v1';
	public verificationMethod?: string;
	public useNativeCanonize: boolean = false;

	constructor(options: { key: JsonWebKey; date?: string }) {
		this.date = options.date;
		if (options.key) {
			this.key = options.key;
			this.verificationMethod = this.key.id;
		}
	}

	async getVerificationMethod({ proof, documentLoader }: any) {
		let { verificationMethod } = proof;
		if (typeof verificationMethod === 'object') {
			verificationMethod = verificationMethod.id;
		}
		if (!verificationMethod) {
			throw new Error('No verification method found in proof');
		}

		const { document } = await documentLoader(verificationMethod);
		const result = document.verificationMethod.find((v) => v.id === verificationMethod);
		if (!result || !result.controller) {
			throw new Error(`Verification method ${verificationMethod} not found.`);
		}

		return JsonWebKey.fromJWK(result);
	}

	async canonize(input: any, { documentLoader, expansionMap, skipExpansion }: any) {
		return await jsonld.canonize(input, {
			algorithm: 'URDNA2015',
			format: 'application/n-quads',
			documentLoader,
			expansionMap,
			skipExpansion,
			useNative: this.useNativeCanonize
		});
	}

	async canonizeProof(proof: any, { documentLoader, expansionMap }: any) {
		// `jws`,`signatureValue`,`proofValue` must not be included in the proof
		const { jws, ...rest } = proof;
		return await this.canonize(rest, {
			documentLoader,
			expansionMap,
			skipExpansion: false
		});
	}

	async createVerifyData({ document, proof, documentLoader, expansionMap }: any) {
		// concatenate hash of c14n proof options and hash of c14n document
		const c14nProofOptions = await this.canonizeProof(proof, {
			documentLoader,
			expansionMap
		});
		const c14nDocument = await this.canonize(document, {
			documentLoader,
			expansionMap
		});
		return Buffer.concat([sha256buffer(c14nProofOptions), sha256buffer(c14nDocument)]);
	}

	async createProof(
		document: any,
		purpose: string,
		documentLoader: DocumentLoader,
		options?: { domain?: string; challenge?: string }
	): Promise<Ed25519Signature2018LinkedDataProof> {
		if (!this.verificationMethod) {
			throw new Error("No verificationMethod, Can't create proof");
		}
		let proof = new Ed25519Signature2018LinkedDataProof(
			this.type,
			purpose,
			this.verificationMethod,
			null,
			null,
			options ? options.challenge : null,
			options ? options.domain : null
		);

		// create data to sign
		const verifyData = await this.createVerifyData({
			document,
			proof: { '@context': document['@context'], ...proof },
			documentLoader
		});

		// sign data
		const sig = await this.sign(verifyData);
		proof.jws = sig;

		return proof.toJSON();
	}

	async sign(verifyData: Uint8Array): Promise<string> {
		try {
			const key = await this.key.exportAsLD({ privateKey: true });
			const detachedJws = await key.sign({ data: verifyData });
			return (
				base64url.encode(Buffer.from(JSON.stringify({ b64: false, crit: ['b64'], alg: key.JWA }))) +
				'..' +
				base64url.encode(detachedJws)
			);
		} catch (e) {
			console.error('Failed to sign.', e);
			throw e;
		}
	}

	async verify(verifyData: Uint8Array, verificationMethod: JsonWebKey, proof: { jws: string }) {
		try {
			const key = await verificationMethod.exportAsLD({ privateKey: false });
			const [header, _, signature] = proof.jws.split('.');
			const headerData = JSON.parse(Buffer.from(base64url.decode(header)).toString('utf-8'));
			if (!headerData.crit.includes('b64') || headerData.b64) {
				throw new TypeError("'b64' JWS header param must be false and in crit");
			}
			if (headerData.alg !== key.JWA) {
				throw new TypeError(`JWA alg mismatch: received ${headerData.alg}, expected ${key.JWA}`);
			}

			return key.verify({
				data: verifyData,
				signature: base64url.decode(signature)
			});
		} catch (e) {
			console.error(e);
			return false;
		}
	}

	async verifyProof(
		proof: Ed25519Signature2018LinkedDataProof,
		document: any,
		documentLoader: DocumentLoader,
		options: { expansionMap?: any; compactProof?: any } = {}
	) {
		const { expansionMap, compactProof } = options;

		try {
			const verifyData = await this.createVerifyData({
				document,
				proof: { '@context': document['@context'], ...proof },
				documentLoader,
				expansionMap,
				compactProof
			});

			// fetch verification method
			const verificationMethod = await this.getVerificationMethod({
				proof,
				document,
				documentLoader,
				expansionMap,
				instance: true
			});

			// verify signature on data
			const verified = await this.verify(verifyData, verificationMethod, proof);
			if (!verified) {
				console.error('proof: ', proof);
				throw new Error('Invalid signature.');
			}

			// ensure proof was performed for a valid purpose
			const jwsProof = new Ed25519Signature2018LinkedDataProof(
				proof.type,
				proof.proofPurpose,
				proof.verificationMethod,
				proof.created,
				proof.jws
			);

			const purposeValid = jwsProof.validate();

			if (!purposeValid) {
				throw new Error('Proof purpose not valid');
			}

			return { verified: true };
		} catch (error) {
			return { verified: false, error: error.message };
		}
	}
}
