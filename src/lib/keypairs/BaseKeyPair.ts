import type { Ed25519KeyPair } from '$lib/keypairs/Ed25519VerificationKey2018.js';
import type { EcdsaSecp256k1VerificationKey2019 } from '$lib/keypairs/Secp256k1KeyPair.js';
import type { X25519KeyPair } from '$lib/keypairs/X25519KeyAgreementKey2019.js';
import type { JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';

export interface BaseKeyPairStatic {
	from(
		k: X25519KeyPair | Ed25519KeyPair | EcdsaSecp256k1VerificationKey2019,
		options: { detached: boolean }
	): Promise<BaseKeyPair>;
	fromJWK(k: JsonWebKey2020): Promise<BaseKeyPair>;
	generate(options: {
		kty?: string;
		crv?: string;
		detached?: boolean;
		secureRandom?: () => Uint8Array;
	}): Promise<BaseKeyPair>;
}

export interface BaseKeyPair {
	id: string;
	type: string;
	controller: string;
	JWA?: string;

	signer: (privateKey: Uint8Array) => { sign: ({ data }: { data: Uint8Array }) => {} };
	sign: ({ data }: { data: Uint8Array }) => Promise<Uint8Array>;

	verifier?: (publicKey: Uint8Array) => {
		verify: ({ data, signature }: { data: Uint8Array; signature: Uint8Array }) => Promise<boolean>;
	};
	verify: ({ data, signature }: { data: Uint8Array; signature: Uint8Array }) => Promise<boolean>;
}
