export type {
	Header,
	IJWE,
	IJWK,
	IJWS,
	ProofVerificationResult,
	DocumentLoader,
	LinkedDataSuite
} from '$lib/interfaces';
export { JsonWebEncryptionSuite } from '$lib/JWE/Suite';
export {
	JsonWebSignature2020Suite,
	JsonWebSignature2020LinkedDataProof,
	createJWSSigner,
	createJWSVerifier
} from '$lib/JWS/Suite';

export type { BaseKeyPair, BaseKeyPairStatic } from '$lib/keypairs/BaseKeyPair';
export { JsonWebKey } from '$lib/keypairs/JsonWebKey2020';
export type { JsonWebKey2020 } from '$lib/keypairs/JsonWebKey2020';
export { Ed25519KeyPair } from '$lib/keypairs/Ed25519VerificationKey2018';
export { X25519KeyPair } from '$lib/keypairs/X25519KeyAgreementKey2019';
export type { EcdsaSecp256k1VerificationKey2019 } from '$lib/keypairs/Secp256k1KeyPair';

export { EcdsaSecp256k1KeyPair } from '$lib/keypairs/Secp256k1KeyPair';

export { LinkedDataProof } from '$lib/LDP/proof';

export { getMultibaseFingerprintFromPublicKeyBytes } from '$lib/utils/multibase';
export { base64, base64url, base58 } from '$lib/utils/encoding';
export { sha256buffer, sha256Uint8Array, stringToUint8Array } from '$lib/utils/sha256';
export * from '$lib/constants';
