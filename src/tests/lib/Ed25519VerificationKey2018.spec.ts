import { Ed25519VerificationKey2018 } from '$lib/keypairs/Ed25519VerificationKey2018';
import { base58, base64url } from '$lib/utils/encoding';
import { describe, expect, test } from 'vitest';

describe('Ed25519VerificationKey2018', () => {
	test('resolves as JWK', async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2018.json');

		const key = new Ed25519VerificationKey2018(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyBase58,
			ed25519.privateKeyBase58
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.privateKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(ed25519.publicKeyBase58)),
			d: base64url.encode(base58.decode(ed25519.privateKeyBase58))
		});
	});

	test('w/o private key resolves as JWK', async () => {
		let ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2018.json');
		delete ed25519['privateKeyBase58'];

		const key = new Ed25519VerificationKey2018(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyBase58,
			ed25519.privateKeyBase58
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.publicKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(ed25519.publicKeyBase58))
		});
	});
});
