export type {
	Header,
	IJWE,
	IJWK,
	IJWS,
	ProofVerificationResult,
	DocumentLoader,
	LinkedDataSuite
} from '$lib/interfaces.js';
export { JsonWebEncryptionSuite } from '$lib/JWE/Suite.js';
export {
	JsonWebSignature2020Suite,
	JsonWebSignature2020LinkedDataProof,
	createJWSSigner,
	createJWSVerifier
} from '$lib/JWS/Suite.js';

export type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair.js';
export { JsonWebKey } from '$lib/keypairs/JsonWebKey2020.js';
export type { JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020.js';
export { Ed25519KeyPair } from '$lib/keypairs/Ed25519VerificationKey2018.js';
export { X25519KeyPair } from '$lib/keypairs/X25519KeyAgreementKey2019.js';
export type { EcdsaSecp256k1VerificationKey2019 } from '$lib/keypairs/Secp256k1KeyPair.js';

export { EcdsaSecp256k1KeyPair } from '$lib/keypairs/Secp256k1KeyPair.js';

export { LinkedDataProof } from '$lib/LDP/proof.js';

export { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase.js';
export { base64, base64url, base58 } from '$lib/utils/encoding.js';
export { sha256buffer, sha256Uint8Array, stringToUint8Array } from '$lib/utils/sha256.js';
export * from '$lib/constants.js';
