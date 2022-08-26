import type { IJWK } from "$lib";
import { createJWSSigner } from "$lib/JWS/createSigner.js";
import { createJWSVerifier } from "$lib/JWS/createVerifier.js";
import type { BaseKeyPair } from "$lib/keypairs/BaseKeyPair.js";
import { Ed25519KeyPair } from "$lib/keypairs/Ed25519VerificationKey2018.js";
import { EcdsaSecp256k1KeyPair } from "$lib/keypairs/Secp256k1KeyPair.js";
import { X25519KeyPair } from "$lib/keypairs/X25519KeyAgreementKey2019.js";


const applyJwa = async (k: any, options?: any) => {
	// attach verifier w/ jwa
	const verifier = await getVerifier(k, options);

	k.verifier = () => verifier as any;

	// attach encrypter w/ jwa
	const encrypter = await getEncrypter(k, options);
	k.encrypter = () => encrypter as any;

	if (k.privateKey) {
		// attach signer w/ jwa
		const signer = await getSigner(k, options);
		k.signer = () => signer as any;

		//attach decrypter w/ jwa
		const decrypter = await getDecrypter(k, options);
		k.decrypter = () => decrypter as any;
	}
	return k;
};

const useJwa = async (k: any, options?: any) => {
	k.useJwa = async (options?: any) => {
		return applyJwa(k, options);
	};
	return applyJwa(k, options);
};

const getKeyPairForKtyAndCrv = (kty: string, crv: string) => {
	if (kty === 'OKP') {
		if (crv === 'Ed25519') {
			return Ed25519KeyPair;
		}
		if (crv === 'X25519') {
			return X25519KeyPair;
		}
	}
	if (kty === 'EC') {
		if (crv === 'secp256k1') {
			return EcdsaSecp256k1KeyPair;
		}

		// if (crv === "BLS12381_G2") {
		//   return Bls12381G2KeyPair;
		// }
	}
	throw new Error(`getKeyPairForKtyAndCrv does not support: ${kty} and ${crv}`);
};

const getKeyPairForType = (k: any) => {
	if (k.type === 'JsonWebKey2020') {
		return getKeyPairForKtyAndCrv(k.publicKeyJwk.kty, k.publicKeyJwk.crv);
	}
	if (k.type === 'Ed25519VerificationKey2018') {
		return Ed25519KeyPair;
	}
	// if (k.type === "EcdsaSecp256k1VerificationKey2019") {
	//   return Secp256k1KeyPair;
	// }
	// if (k.type === "Bls12381G2Key2020") {
	//   return Bls12381G2KeyPair;
	// }
	if (k.type === 'X25519KeyAgreementKey2019') {
		return X25519KeyPair;
	}

	throw new Error('getKeyPairForType does not support type: ' + k.type);
};

const getVerifier = async (k: any, options = { detached: true }) => {
	const { publicKeyJwk } = await k.export({ type: 'JsonWebKey2020' });
	if (publicKeyJwk) {
		const { kty, crv } = publicKeyJwk;

		if (kty === 'OKP') {
			if (crv === 'Ed25519') {
				return createJWSVerifier(k.verifier(k.publicKey), 'EdDSA', options);
			}
		}

		if (kty === 'EC') {
			if (crv === 'secp256k1') {
				return createJWSVerifier(k.verifier(k.publicKey), 'ES256K', options);
			}

			if (crv === 'P-256') {
				return createJWSVerifier(k.verifier(k.publicKey), 'ES256', options);
			}
			if (crv === 'P-384') {
				return createJWSVerifier(k.verifier(k.publicKey), 'ES384', options);
			}
			if (crv === 'P-521') {
				return createJWSVerifier(k.verifier(k.publicKey), 'ES512', options);
			}

			if (crv === 'BLS12381_G2') {
				throw new Error('BLS12381_G2 has no registered JWA');
			}
		}
	}
	console.log(`getVerifier does not support ${JSON.stringify(publicKeyJwk, null, 2)}`);
	return () => {};
};

const getSigner = (k: any, options = { detached: true }) => {
	const { publicKeyJwk } = k;
	if (publicKeyJwk) {
		const { kty, crv } = publicKeyJwk;

		if (kty === 'OKP') {
			if (crv === 'Ed25519') {
				return createJWSSigner(k.signer(k.privateKey), 'EdDSA', options);
			}
		}
		if (kty === 'EC') {
			if (crv === 'secp256k1') {
				return createJWSSigner(k.signer(k.privateKey), 'ES256K', options);
			}
			if (crv === 'BLS12381_G2') {
				throw new Error('BLS12381_G2 has no registered JWA');
			}
			if (crv === 'P-256') {
				return createJWSSigner(k.signer(k.privateKey), 'ES256', options);
			}
			if (crv === 'P-384') {
				return createJWSSigner(k.signer(k.privateKey), 'ES384', options);
			}
			if (crv === 'P-521') {
				return createJWSSigner(k.signer(k.privateKey), 'ES512', options);
			}
		}
	}
	console.log(`getSigner does not support ${JSON.stringify(publicKeyJwk, null, 2)}`);
	return () => {};
};

const getEncrypter = async (k: JsonWebKeyPair, options = { flattened: false }) => {
	const { publicKeyJwk } = await k.export();
};

const getDecrypter = async (k: JsonWebKeyPair, options = { flattened: false }) => {
	const { privateKeyJwk } = await k.export();
};

export interface JsonWebKey2020 extends BaseKeyPair {
	id: string;
	type: string;
	controller: string;
	publicKeyJwk: IJWK;
	privateKeyJwk?: IJWK;
	export: (options: {privateKey?: boolean}) => Promise<JsonWebKeyPair>
	exportAsLD: (options: {privateKey?: boolean}) => Promise<BaseKeyPair>
}

export class JsonWebKeyPair implements JsonWebKey2020 {
	id: string;
	type: 'JsonWebKey2020';
	controller: string;
	publicKeyJwk: IJWK;
	privateKeyJwk?: IJWK;

	constructor(id: string, controller: string, publicKeyJwk: IJWK, privateKeyJwk?: IJWK) {
		this.type = 'JsonWebKey2020';
		this.id = id;
		this.controller = controller;
		this.publicKeyJwk = publicKeyJwk;
		if (privateKeyJwk) {
			this.privateKeyJwk = privateKeyJwk;
		}
	}

	static from = async (k: BaseKeyPair, options: any = { detached: true }) => {
		const KeyPair = getKeyPairForType(k);
		const key = await KeyPair.from(k as any, {});
		let { detached, header } = options;
		if (detached === undefined) {
			detached = true;
		}
		return useJwa(key, { detached, header });
	};

	static fromJWK = async (k: JsonWebKey2020) => {
		return new JsonWebKeyPair(k.id, k.controller, k.publicKeyJwk, k.privateKeyJwk);
	};

	static generate = async (options: any = { kty: 'OKP', crv: 'Ed25519', detached: true }) => {
		const KeyPair = getKeyPairForKtyAndCrv(options.kty, options.crv);
		return await KeyPair.generate();
	};

	/**
	 * Export as a JsonWebKeyPair (might not be necessary?)
	 */
	async export(
		options: {
			privateKey?: boolean;
		} = {
			privateKey: false
		}
	): Promise<JsonWebKeyPair> {
		return new JsonWebKeyPair(
			this.id,
			this.controller,
			this.publicKeyJwk,
			options.privateKey ? this.privateKeyJwk : undefined
		);
	}

	/**
	 * export as the Linked Data non JWK variant
	 */
	async exportAsLD(
		options: {
			privateKey?: boolean;
		} = {
			privateKey: false
		}
	): Promise<BaseKeyPair> {
		const keyPairClass = getKeyPairForKtyAndCrv(this.publicKeyJwk.kty, this.publicKeyJwk.crv);
		const jwk = await this.export(options);
		return await keyPairClass.fromJWK(jwk);
	}
}
