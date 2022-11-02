import { Ed25519VerificationKey2020 } from '$lib/keypairs/Ed25519VerificationKey2020';
import { base64url } from '$lib/utils/encoding';
import { base58btc as base58 } from 'multiformats/bases/base58';

import { describe, expect, test } from 'vitest';

describe('Ed25519VerificationKey2020', () => {
	test('fromBase58', async () => {
		const key = 'ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7';
		
		const keypair = Ed25519VerificationKey2020.fromBase58({publicKeyBase58: key})
		console.log((await keypair).publicKeyMultibase)
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
			x: base64url.encode(base58.decode(ed25519.publicKeyMultibase)),
			d: base64url.encode(base58.decode(ed25519.privateKeyMultibase))
		});
	});

	test('w/o private key resolves as JWK', async () => {
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
			x: base64url.encode(base58.decode(ed25519.publicKeyMultibase))
		});
	});
});
