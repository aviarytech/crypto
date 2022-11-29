import { Ed25519VerificationKey2020 } from '$lib/keypairs/Ed25519VerificationKey2020';
import { base64url, multibase, MULTICODEC_ED25519_PRIV_HEADER, MULTICODEC_ED25519_PUB_HEADER } from '$lib/utils/encoding';

import { describe, expect, test } from 'vitest';

describe('Ed25519VerificationKey2020', () => {
	test('fromBase58', async () => {
		const key = 'ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7';
		
		const keypair = Ed25519VerificationKey2020.fromBase58({publicKeyBase58: key})
	})
	test('resolves as JWK', async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');

		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.privateKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(multibase.decode(MULTICODEC_ED25519_PUB_HEADER, ed25519.publicKeyMultibase)),
			d: base64url.encode(multibase.decode(MULTICODEC_ED25519_PRIV_HEADER, ed25519.privateKeyMultibase))
		});
	});

	test.only('w/o private key resolves as JWK', async () => {
		let ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');
		delete ed25519['privateKeyMultibase'];

		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.publicKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(multibase.decode(MULTICODEC_ED25519_PUB_HEADER, ed25519.publicKeyMultibase))
		});
	});

	test('can generate', async () => {
		const key = await Ed25519VerificationKey2020.generate()
		expect(key).toHaveProperty('publicKey')
		expect(key).toHaveProperty('privateKey')
	})
});
